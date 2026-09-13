"""代码切片器（slicer）—— 为 LLM 研判构造精炼函数级上下文。

按 Finding 来源工具的粒度规则提取上下文（函数体集合）：

- **CodeQL 产出**：提取"数据流每一步所在函数的完整体"。
  CodeQL 是全局数据流引擎，告警位置在 sink；SARIF 未携带完整 codeFlow 时，
  我们以 AST 做**同一文件内的函数级近似回溯**：
  sink 所在函数（步骤0） + 该函数体内直接调用的同文件函数（下游传播步）
  + 调用 sink 函数的同文件调用方（上游来源步）。
- **Semgrep 产出**：提取"目标函数 + 直接调用者"（Semgrep 为模式匹配，
  命中点即目标函数；直接调用者用于确认该函数是否真的被外部/入口调用）。

硬性上限（对三种来源统一强制）：
- 单函数正文不超过 ``MAX_FUNC_LINES``（100 行）
- 数据流/调用步骤不超过 ``MAX_STEPS``（8 步）
- 拼装后总上下文不超过 ``MAX_CONTEXT_TOKENS``（3000 token，按 ~4 字符/token 估算）
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from models import Finding, ToolName
from modules.context_enrichment.ast_extractor import parse_source

logger = logging.getLogger("opensoft_detect.context_enrichment.slicer")

#: 硬性上限
MAX_FUNC_LINES: int = 100
MAX_STEPS: int = 8
MAX_CONTEXT_TOKENS: int = 3000
#: 中文/注释平均 ~4 字符近似 1 token 的估算用字符上限
_CHARS_PER_TOKEN: int = 4

#: 截断标记（提示 LLM 此处省略了代码行）
_TRUNC_MARK = "\n# ... (上下文超限，代码被截断) ...\n"


def est_tokens(text: str) -> int:
    """按字符数估算 token 数（中文/代码平均 ~4 字符 ≈ 1 token）。

    :param text: 文本。
    :return: 估算 token 数（至少 1）。
    """
    return max(1, (len(text) + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN)


@dataclass
class CodeContext:
    """一次切片的结果（供写入 metadata.code_context 与 LLM prompt）。"""

    entries: list[dict] = field(default_factory=list)   # [{role,file,func,lines,text}]
    text: str = ""                                       # 拼装后的纯文本
    tokens: int = 0                                      # est_tokens(text)
    steps: int = 0                                       # 实际纳入的步骤数（<= MAX_STEPS）
    truncated: bool = False                              # 是否发生过超限截断

    def to_dict(self) -> dict:
        """转为 JSON 友好字典。

        :return: 字典。
        """
        return {"entries": self.entries, "text": self.text,
                "tokens": self.tokens, "steps": self.steps,
                "truncated": self.truncated}


@dataclass
class _FuncInfo:
    """同一文件内的一个函数/方法定义（含正文字符串）。"""

    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualname: str          # 方法形如 Class.method
    start: int             # 定义起始行
    end: int               # 定义结束行
    text: str              # 正文字符串（已按 MAX_FUNC_LINES 截断）


class CodeSlicer:
    """按 Finding 来源做函数级切片。"""

    def __init__(self, max_func_lines: int = MAX_FUNC_LINES,
                 max_steps: int = MAX_STEPS,
                 max_context_tokens: int = MAX_CONTEXT_TOKENS,
                 search_roots: Optional[list[Path]] = None) -> None:
        """构造切片器。

        :param max_func_lines: 单函数正文行数上限。
        :param max_steps: 步骤数上限。
        :param max_context_tokens: 总 token 上限。
        :param search_roots: 跨文件查找被调函数（守卫/消毒等）的搜索根目录。
        """
        self.max_func_lines: int = max_func_lines
        self.max_steps: int = max_steps
        self.max_tokens: int = max_context_tokens
        self.search_roots: list[Path] = list(search_roots or [])
        self._cross_cache: dict[str, Optional[str]] = {}

    # ------------------------------------------------------------------
    def build_context(self, finding: Finding) -> CodeContext:
        """为单个 Finding 生成代码上下文（含全部硬性上限约束）。

        :param finding: 待富化的 Finding。
        :return: CodeContext（source 缺失/解析失败时为空文本）。
        """
        empty = CodeContext()
        if finding.location is None or not finding.file_path:
            return empty
        path = Path(finding.file_path)
        if not path.is_file():
            logger.warning("切片跳过：源文件不存在 %s", path)
            return empty
        lines: Optional[list[str]] = _read_lines(path)
        if lines is None:
            return empty
        tree = parse_source(path)
        if tree is None:
            return empty

        funcs: list[_FuncInfo] = self._collect_funcs(tree, lines)
        sink_line: int = finding.location.start_line
        enclosing = _enclosing(funcs, sink_line)
        if enclosing is None:
            # 兜底：命中点不在函数内（如模块级代码），给出命中行附近窗口
            return self._window_context(finding, lines)

        # 依据工具粒度选择步骤
        steps: list[_FuncInfo]
        if finding.tool == ToolName.CODEQL:
            steps = self._plan_codeql_steps(enclosing, funcs)
        else:  # Semgrep / 其它：目标函数 + 直接调用者
            steps = self._plan_caller_steps(enclosing, funcs)

        return self._assemble(steps, finding)

    # ---- 步骤规划 ----
    def _plan_codeql_steps(self, sink_func: _FuncInfo,
                           funcs: list[_FuncInfo]) -> list[_FuncInfo]:
        """CodeQL 粒度：sink 函数 + 体内被调(下游) + 调用方(上游)。

        步骤上限 MAX_STEPS，顺序：sink -> 被调传播函数 -> 调用方来源函数。

        :param sink_func: sink 所在函数。
        :param funcs: 同文件函数集合。
        :return: 步骤函数列表。
        """
        sink_node = sink_func.node
        # 下游传播步：sink 函数体内直接调用的、同文件内定义的函数
        called_names: set[str] = self._called_def_names(sink_node)
        local_tails = {f.qualname.rsplit(".", 1)[-1] for f in funcs}
        ordered: list[_FuncInfo] = [sink_func]
        for f in funcs:
            if f is not sink_func and f.qualname.rsplit(".", 1)[-1] in called_names:
                ordered.append(f)
        # **跨文件**被调函数（常见为守卫/消毒函数，如 is_path_inside）：
        # LLM 研判'是否已防护'高度依赖能否看到它们，优先纳入。
        for name in sorted(called_names):
            if name in local_tails:
                continue
            cross = self._find_cross_file_func(name)
            if cross is not None:
                ordered.append(cross)
        # 上游来源步：调用 sink 函数的同文件函数
        ordered.extend(c for c in _callers_of(sink_func.qualname, funcs, self.max_func_lines)
                       if c is not sink_func)
        return ordered[:self.max_steps]

    def _find_cross_file_func(self, name: str) -> Optional[_FuncInfo]:
        """在 search_roots 下找 ``def <name>(`` 的函数体（带缓存）。

        :param name: 函数名。
        :return: 伪 _FuncInfo（node 为 None，仅供拼装文本）；未找到返回 None。
        """
        if name in self._cross_cache:
            txt = self._cross_cache[name]
        else:
            txt = None
            for root in self.search_roots:
                if not root.is_dir():
                    continue
                for p in root.rglob("*.py"):
                    posix = p.as_posix()
                    if any(seg in posix for seg in ("venv", "node_modules", ".git", "__pycache__")):
                        continue
                    try:
                        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    except OSError:
                        continue
                    for i, ln in enumerate(lines):
                        if ln.lstrip().startswith(f"def {name}("):
                            seg = lines[i:i + self.max_func_lines]
                            txt = "\n".join(seg)
                            break
                    if txt:
                        break
                if txt:
                    break
            self._cross_cache[name] = txt
        if not txt:
            return None
        info = _FuncInfo(node=None, qualname=name, start=0, end=0, text=txt)  # type: ignore[arg-type]
        return info

    def _plan_caller_steps(self, target: _FuncInfo,
                           funcs: list[_FuncInfo]) -> list[_FuncInfo]:
        """Semgrep 粒度：目标函数 + 直接调用者（步骤上限 MAX_STEPS）。"""
        ordered: list[_FuncInfo] = [target]
        ordered.extend(c for c in _callers_of(target.qualname, funcs, self.max_func_lines)
                       if c is not target)
        return ordered[:self.max_steps]

    # ---- 组装与上限 ----
    def _assemble(self, steps: list[_FuncInfo], finding: Finding) -> CodeContext:
        """把步骤函数拼装为最终上下文，并强制 token/行数上限。

        :param steps: 步骤函数（已受行数截断）。
        :param finding: 来源 Finding（用于日志）。
        :return: CodeContext。
        """
        ctx = CodeContext()
        ctx.steps = len(steps)
        parts: list[str] = []
        for idx, func in enumerate(steps):
            sep = (f"\n# ---- 步骤{idx}: {func.qualname} "
                   f"[{Path(finding.file_path).name}:{func.start}-{func.end}] ----")
            header_ctx = {
                "role": "sink_function" if idx == 0 else f"step_{idx}",
                "file": finding.file_path,
                "func": func.qualname,
                "lines": [func.start, func.end],
            }
            parts.append(sep + "\n" + func.text)
            entry = dict(header_ctx, text=func.text)
            # 边拼边算 token，超出即停止追加后续步骤
            if est_tokens("\n".join(parts)) > self.max_tokens:
                parts.pop()
                ctx.truncated = True
                logger.info("Finding %s 上下文超过 %d token，已裁剪后续步骤。",
                            finding.id, self.max_tokens)
                break
            ctx.entries.append(entry)

        text = "\n".join(parts).strip()
        # 最后兜底：单段仍超限则硬截断文本
        if text and est_tokens(text) > self.max_tokens:
            cap_chars: int = self.max_tokens * _CHARS_PER_TOKEN
            text = text[:cap_chars] + _TRUNC_MARK
            ctx.truncated = True
        ctx.text = text
        ctx.tokens = est_tokens(text)
        return ctx

    def _window_context(self, finding: Finding, lines: list[str]) -> CodeContext:
        """命中点不在任何函数内时的兜底：给 sink 行前后共 ~20 行窗口。"""
        start: int = max(0, finding.location.start_line - 6)
        win: list[str] = lines[start:finding.location.start_line + 14]
        text = "\n".join(win)
        if est_tokens(text) > self.max_tokens:
            text = text[:self.max_tokens * _CHARS_PER_TOKEN] + _TRUNC_MARK
        ctx = CodeContext(entries=[{"role": "module_level", "file": finding.file_path,
                                    "func": "<module>",
                                    "lines": [start + 1, start + len(win)],
                                    "text": text}],
                          text=text, tokens=est_tokens(text), steps=1)
        return ctx

    # ---- 工具函数 ----
    def _collect_funcs(self, tree: ast.Module, lines: list[str]) -> list[_FuncInfo]:
        """收集文件内全部函数/方法（含类内方法），正文按行上限截断。

        :param tree: 模块 AST。
        :param lines: 源文件行列表（1-based 索引：行号 = 下标+1）。
        :return: 函数信息列表。
        """
        out: list[_FuncInfo] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            start: int = node.lineno
            end: int = getattr(node, "end_lineno", start) or start
            body: list[str] = lines[start - 1:min(end, start - 1 + self.max_func_lines)]
            if end - start + 1 > self.max_func_lines:
                body.append(_TRUNC_MARK)
            qualname: str = _qualname(node, tree)
            out.append(_FuncInfo(node=node, qualname=qualname,
                                 start=start, end=end, text="\n".join(body)))
        return out

    def _called_def_names(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        """返回函数体内直接调用的名字集合（近似：Call 的目标名）。"""
        names: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                f = sub.func
                if isinstance(f, ast.Name):
                    names.add(f.id)
                elif isinstance(f, ast.Attribute):
                    names.add(f.attr)
        return names


def _qualname(node: ast.FunctionDef | ast.AsyncFunctionDef, tree: Optional[ast.Module]) -> str:
    """拼出函数限定名（方法含类名前缀；tree 提供时按类内成员归属判断）。"""
    name: str = node.name
    if tree is None:
        return name
    for parent in ast.walk(tree):
        if isinstance(parent, ast.ClassDef):
            for child in parent.body:
                if child is node:
                    return f"{parent.name}.{name}"
    return name


def _read_lines(path: Path) -> Optional[list[str]]:
    """宽容读取源文件为行列表（utf-8 -> gbk 降级）。"""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            text = path.read_text(encoding=enc)
            return text.splitlines()
        except (OSError, UnicodeDecodeError):
            continue
    return None


def _enclosing(funcs: list[_FuncInfo], line_no: int) -> Optional[_FuncInfo]:
    """返回包含 line_no 且区间最小的函数（含嵌套时取最内层）。"""
    hit: Optional[_FuncInfo] = None
    for f in funcs:
        if f.start <= line_no <= f.end:
            if hit is None or (f.end - f.start) < (hit.end - hit.start):
                hit = f
    return hit


def _callers_of(qualname: str, funcs: list[_FuncInfo],
                max_lines: int) -> list[_FuncInfo]:
    """找出在同一文件内"直接调用" qualname 的函数（调用方）。

    判定依据：调用方函数体内出现对该限定名末段（方法名/函数名）的调用。

    :param qualname: 目标函数限定名（如 handle.upload）。
    :param funcs: 同文件函数集合。
    :param max_lines: 行上限（与正文截断一致）。
    :return: 调用方函数列表（按文件顺序）。
    """
    tail: str = qualname.rsplit(".", 1)[-1]
    callers: list[_FuncInfo] = []
    for f in funcs:
        if f.qualname == qualname:
            continue
        names: set[str] = set()
        for sub in ast.walk(f.node):
            if isinstance(sub, ast.Call):
                fn = sub.func
                if isinstance(fn, ast.Name):
                    names.add(fn.id)
                elif isinstance(fn, ast.Attribute):
                    names.add(fn.attr)
        if tail in names:
            callers.append(f)
    return callers


def build_context_for_finding(finding: Finding,
                              search_roots: Optional[list[Path]] = None) -> CodeContext:
    """便捷入口：为 Finding 生成 CodeContext（可指定跨文件搜索根）。

    :param finding: 待富化 Finding。
    :param search_roots: 跨文件查找被调函数（守卫/消毒）的搜索根。
    :return: CodeContext。
    """
    return CodeSlicer(search_roots=search_roots).build_context(finding)
