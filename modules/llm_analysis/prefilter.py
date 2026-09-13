"""LLM 前置预过滤（prefilter）。

在把 Finding 送进大模型之前，先用**低成本确定性规则**滤掉明显误报，节省调用：

1. **测试文件中的 Finding**：路径/文件名命中 test/spec 特征；
2. **注释 / 文档字符串里的"代码"**：命中位置所在行是注释，或整段命中都是注释，
   或命中落在模块/函数文档字符串内部（用 ast 判断）—— 这类静态工具偶发误报；
3. **已知安全模式的代码**：例如参数化查询 ``cursor.execute(sql, params)``、
   ``(sql, (a, b))``、ORM 传参等 —— 明显不构成注入。

被过滤的条目给出可读 reason，写入 metadata 并汇总落盘，保证可审计、可调参。
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from config import Config
from models import Finding

logger = logging.getLogger("opensoft_detect.llm_analysis.prefilter")

#: 命中即视为测试文件的路径关键字（目录段或文件名）
_TEST_PATH_KEYWORDS: tuple[str, ...] = (
    "test", "tests", "testing", "spec", "specs", "test_data", "conftest",
)

#: 命中即视为 SQL/注入类规则的特征（用于决定是否启用"安全模式"检查）
_SQLISH_RULE_HINTS: tuple[str, ...] = (
    "sql", "sqli", "injection", "execute", "cursor", "queryset",
)


@dataclass
class DropReport:
    """一条预过滤丢弃记录。"""

    finding_id: str
    rule_id: str
    file_path: str
    reason: str

    def to_dict(self) -> dict:
        """转为字典。"""
        return {"finding_id": self.finding_id, "rule_id": self.rule_id,
                "file_path": self.file_path, "reason": self.reason}


class Prefilter:
    """规则驱动的 LLM 前置过滤器。"""

    def __init__(self, config: Config) -> None:
        """构造过滤器。

        :param config: 全局配置。
        """
        self.config: Config = config
        # 被测工程根目录：判定"测试文件"只对该目录以下生效，
        # 避免把"工程外部的目录名（如测试集目录 test/）"误判成被测工程自己的测试。
        self._root = config.target.resolve() if config.target else None
        # 行级源码缓存（文件 -> 行列表），避免重复读盘
        self._lines_cache: dict[str, list[str]] = {}

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], list[DropReport]]:
        """逐条预过滤。

        :param findings: 待过滤的 Finding。
        :return: (保留列表, 丢弃报告列表)。
        """
        kept: list[Finding] = []
        dropped: list[DropReport] = []
        for finding in findings:
            reason: Optional[str] = self._drop_reason(finding)
            if reason is not None:
                dropped.append(DropReport(
                    finding_id=finding.id, rule_id=finding.rule_id,
                    file_path=finding.file_path, reason=reason))
                finding.metadata["prefilter"] = {"dropped": True, "reason": reason}
                logger.info("预过滤丢弃 %s：%s", finding.id, reason)
            else:
                finding.metadata.setdefault("prefilter", {})["dropped"] = False
                kept.append(finding)
        return kept, dropped

    # ------------------------------------------------------------------
    def _drop_reason(self, finding: Finding) -> Optional[str]:
        """返回命中丢弃规则的原因；未命中返回 None。"""
        if self._in_test_file(finding.file_path):
            return "位于测试文件中（路径含 test/spec 特征）"
        if self._in_comment(finding):
            return "命中位置在注释或文档字符串内"
        if self._has_strong_sanitizer(finding):
            return "已知安全模式：使用了消毒/规范化函数"
        if self._is_safe_sql_pattern(finding):
            return "已知安全模式：参数化查询 / ORM 参数绑定"
        return None

    #: 强消毒/规范化函数（出现即高度可能是已防护，直接确定性过滤，省一次 LLM 调用）
    _SANITIZERS: tuple[str, ...] = (
        "secure_filename", "shlex.quote", "html.escape", "literal_eval",
        "is_relative_to", "os.path.commonpath", "is_path_inside",
    )

    def _has_strong_sanitizer(self, finding: Finding) -> bool:
        """命中行/snippet 是否直接使用强消毒函数。

        :param finding: Finding。
        :return: True 表示确定性判为已防护。
        """
        snippet: str = (finding.location.snippet if finding.location else "") or ""
        if not snippet and finding.location:
            lines = self._file_lines(finding.file_path)
            if lines and 1 <= finding.location.start_line <= len(lines):
                snippet = lines[finding.location.start_line - 1]
        low = snippet.lower()
        return any(s in low for s in self._SANITIZERS)

    # ---- 1) 测试文件 ----
    def _in_test_file(self, file_path: str) -> bool:
        """判断文件是否属于**被测工程自身**的测试文件。

        只检查 target 根目录以下路径片段里的 test/spec 关键字；
        文件在 target 之外时（如被扫描工程位于某个测试集目录内），退化为
        仅按文件名启发式判断，避免把外部目录名误判为测试。

        :param file_path: 文件绝对路径。
        :return: True 表示属于测试文件。
        """
        if not file_path:
            return False
        p = Path(file_path).resolve()
        if self._root is not None:
            try:
                rel = p.relative_to(self._root)
                parts = [seg.lower() for seg in rel.parts]
            except ValueError:
                parts = [p.name.lower()]      # 在 target 之外：只看文件名
        else:
            parts = [seg.lower() for seg in p.parts]
        name: str = parts[-1] if parts else ""
        for kw in _TEST_PATH_KEYWORDS:
            if kw in parts:
                return True
        # 文件名 test_*.py / *_test.py / conftest.py（无论是否在 target 内均生效）
        if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
            return True
        return False

    # ---- 2) 注释 / 文档字符串 ----
    def _in_comment(self, finding: Finding) -> bool:
        """判断命中位置是否落在注释或 docstring 中。"""
        if finding.location is None:
            return False
        lines = self._file_lines(finding.file_path)
        line_no: int = finding.location.start_line
        if lines is None or not (1 <= line_no <= len(lines)):
            return False
        # 2a) 该行本身是注释
        if lines[line_no - 1].lstrip().startswith("#"):
            return True
        # 2b) snippet 全部是注释行（某些规则把整段注释当代码）
        snippet: str = (finding.location.snippet or "").strip()
        if snippet:
            code_lines = [ln for ln in snippet.splitlines() if ln.strip()]
            if code_lines and all(ln.lstrip().startswith("#") for ln in code_lines):
                return True
        # 2c) 命中点在字符串常量内部（docstring 等）
        return self._inside_string_literal(finding.file_path, line_no)

    def _inside_string_literal(self, file_path: str, line_no: int) -> bool:
        """用 ast 判断 line_no 是否落在某字符串常量（含文档字符串）行区间内。"""
        tree = self._parse_ast(file_path)
        if tree is None:
            return False
        for node in ast.walk(tree):
            # 字符串字面量可能出现在任何表达式里；直接检测 Constant(str)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s, e = getattr(node, "lineno", 0), getattr(node, "end_lineno", 0)
                if s and e and s <= line_no <= e:
                    return True
        return False

    # ---- 3) 已知安全模式 ----
    def _is_safe_sql_pattern(self, finding: Finding) -> bool:
        """判断是否参数化查询等已知安全模式。

        仅当规则/消息疑似 SQL 注入类时检查；命中 ``.execute(sql, 参数)`` 且参数
        是独立绑定（元组/列表/命名参数）或 ``%s``/``?`` 占位符 + 分离参数，
        视为参数化查询 -> 安全。
        """
        if not (finding.rule_id or "").lower() and not finding.message:
            return False
        blob: str = f"{finding.rule_id} {finding.rule_name} {finding.message}".lower()
        if not any(h in blob for h in _SQLISH_RULE_HINTS):
            return False
        snippet: str = (finding.location.snippet if finding.location else "") or ""
        if not snippet:
            lines = self._file_lines(finding.file_path)
            if lines and finding.location and 1 <= finding.location.start_line <= len(lines):
                snippet = lines[finding.location.start_line - 1]
        # 参数化模式：execute(sql, <独立参数>) 且参数不是拼接串
        if re.search(r"\.\s*execute\s*\(\s*[^,)]+,\s*(?:[\[\(]|(?:params|args|values)\b)", snippet):
            return True
        # execute 带 %s / ? 占位符且第二参为变量
        if re.search(r"\.\s*(?:execute|executemany)\s*\(\s*['\"][^'\"]*%(?:s|\(.+?\))s[^'\"]*['\"]\s*,\s*[A-Za-z_]", snippet):
            return True
        return False

    # ---- 源码读取缓存 ----
    def _file_lines(self, file_path: str) -> Optional[list[str]]:
        """带缓存地读取文件为行列表。"""
        if not file_path:
            return None
        if file_path not in self._lines_cache:
            try:
                p = Path(file_path)
                self._lines_cache[file_path] = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._lines_cache[file_path] = []
        return self._lines_cache[file_path] or None

    def _parse_ast(self, file_path: str) -> Optional[ast.Module]:
        """带缓存解析 AST（失败缓存 None）。"""
        key = f"ast:{file_path}"
        if key not in self._lines_cache:
            lines = self._file_lines(file_path)
            tree: Optional[ast.Module] = None
            if lines is not None:
                try:
                    tree = ast.parse("\n".join(lines), filename=file_path)
                except SyntaxError:
                    tree = None
            self._lines_cache[key] = tree
        return self._lines_cache[key]
