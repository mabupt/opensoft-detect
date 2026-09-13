"""统一数据模型模块（全项目共享）。

本模块定义 OpenSoft Detect 流水线（模块 0-5）中所有环节共用的核心数据结构，
是整个系统各模块之间传递数据的"公共契约"：

- 各类枚举：置信度分级、严重程度、漏洞状态、工具来源等
- 位置 / 污点路径 / 路由信息等辅助结构
- 统一的 :class:`Finding` 漏洞数据类（含置信度分级字段）

约定：任何模块在产出漏洞信息时，都应以 :class:`Finding` 作为最小交换单元，
通过 ``json`` 序列化在模块间传递（见各模块 runner 的落盘文件）。

设计说明（后续填充业务逻辑时遵循）：
- ``confidence`` 字段是贯穿全流程的**综合置信度**：初始来自静态工具给出的等级，
  经 LLM 误报研判与动态验证后逐级修正，最终写入报告。
- ``status`` 记录漏洞当前所处的判定阶段，方便跟踪误报研判闭环。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 枚举定义
# ---------------------------------------------------------------------------

class ConfidenceLevel(str, Enum):
    """置信度分级。

    用于静态发现结果的分级以及最终报告的置信度展示。
    全流程中由不同模块负责升降级：
    静态工具原始产出 -> LLM 误报研判 -> 动态验证确认。
    """

    HIGH = "high"          # 高置信度：存在明显污点路径 / 已被动态验证确认
    MEDIUM = "medium"      # 中置信度：污点路径不完全，需人工复核
    LOW = "low"            # 低置信度：线索不足，疑似误报


class Severity(str, Enum):
    """漏洞严重程度分级（对齐 CVSS 的分级习惯）。"""

    CRITICAL = "critical"  # 严重
    HIGH = "high"          # 高危
    MEDIUM = "medium"      # 中危
    LOW = "low"            # 低危
    INFO = "info"          # 信息


class ToolName(str, Enum):
    """漏洞来源工具（统一 findings 里的 ``tool`` 字段取值）。"""

    SEMGREP = "semgrep"
    CODEQL = "codeql"
    PIP_AUDIT = "pip_audit"
    LLM = "llm"            # LLM 补充研判阶段新增的发现（很少用）
    DYNAMIC = "dynamic"    # 动态验证新增的运行时发现


class VulnerabilityStatus(str, Enum):
    """漏洞状态（沿生命周期流转）。

    流转示意：:

        NEW
          -> UNDER_REVIEW      （进入 LLM 误报研判）
             -> FALSE_POSITIVE （研判为误报，流出）
             -> CONFIRMED      （研判为真实漏洞）
                -> DYNAMIC_CONFIRMED （动态验证命中）
                -> FIX_SUGGESTED     （已生成修复建议）
    """

    NEW = "new"                              # 新发现，尚未研判
    UNDER_REVIEW = "under_review"            # LLM 误报研判中
    TRUE_POSITIVE = "true_positive"          # 判定为真实漏洞（高可信）
    FALSE_POSITIVE = "false_positive"        # 判定为误报
    UNVERIFIED = "unverified"                # 无法确认，待人工复核
    DYNAMIC_CONFIRMED = "dynamic_confirmed"  # 已被动态验证实锤
    FIX_SUGGESTED = "fix_suggested"          # 已生成修复建议/补丁


# ---------------------------------------------------------------------------
# 位置与路径结构
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Location:
    """源代码位置（1 起始的行/列，与主流 LSP 约定一致）。"""

    file_path: str   # 源码文件绝对路径（对目标工程为相对路径亦可，统一由 manifest 决定）
    start_line: int  # 起始行号（从 1 开始）
    end_line: int    # 结束行号（从 1 开始，含）
    start_col: int = 1   # 起始列号
    end_col: int = 1     # 结束列号
    snippet: str = ""    # 该位置对应的代码片段（便于 LLM 上下文与报告展示）


@dataclass
class TaintStep:
    """污点传播路径中的一步。

    node_type 描述该步在污点链中的角色，常见取值：``source`` / ``propagator`` /
    ``sanitizer`` / ``sink``。语义上对应双轨检测（轨道 B）中污点标记的传播轨迹。
    """

    node_type: str                    # source / propagator / sanitizer / sink
    location: Location                # 该步所在代码位置
    variable: str = ""                # 关联的变量名或表达式描述
    description: str = ""             # 该步行为描述（如"来自 request.args['id']"）


@dataclass
class RouteInfo:
    """由 AST 提取的 HTTP 路由与参数信息（模块 2 context_enrichment 产出）。

    用于判断一个 Finding 是否可达（是否挂在某个对外路由上），
    这是 LLM 误报研判与动态验证的重要上下文。
    """

    path: str                    # 路由路径模板，如 /api/users/<int:uid>
    http_methods: list[str]      # 允许的 HTTP 方法，如 ["GET", "POST"]
    handler_file: str            # 处理函数所在文件
    handler_function: str        # 处理函数名（含类名时形如 Class.method）
    parameters: list[str] = field(default_factory=list)   # 路由/请求参数名列表
    framework: str = ""          # 框架名，如 flask / fastapi / django
    entry_location: Optional[Location] = None             # 处理函数在文件中的位置


@dataclass
class FixSuggestion:
    """修复建议（模块 5 报告阶段展示 / --fix-suggest 触发生成）。

    diff 字段保存对目标文件可应用的补丁文本（unified diff 或整文件替换片段），
    便于报告直接渲染"修复 Diff"。
    """

    summary: str = ""                      # 修复思路一句话概述
    diff: str = ""                         # 修复补丁（unified diff 文本）
    references: list[str] = field(default_factory=list)  # 参考链接（CWE/官方文档等）


# ---------------------------------------------------------------------------
# 统一漏洞对象
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """统一的漏洞发现数据类。

    这是全系统最重要的数据结构，0-5 各模块围绕它进行增补与流转：
    模块 1 静态分析产出原始 :class:`Finding`，
    模块 2 补充污点路径与路由可达性，
    模块 3 修正状态与置信度并回填 Qdrant 闭环，
    模块 4 追加动态验证结论，
    模块 5 汇总渲染进报告。
    """

    # --- 基础标识 ---
    id: str                                   # 唯一标识，如 "SEMGREP-PY002-astrbot/api.py-12"
    tool: ToolName                            # 来源工具（见 ToolName）
    rule_id: str                              # 规则/查询 ID，如 "python.lang.security.audit.eval"
    rule_name: str = ""                       # 规则名（人类可读）
    rule_url: str = ""                        # 规则文档链接（可为空）

    # --- 描述 ---
    severity: Severity = Severity.MEDIUM      # 严重程度
    message: str = ""                         # 发现的自然语言描述
    cwe_ids: list[str] = field(default_factory=list)      # 关联 CWE，如 ["CWE-78"]
    attack_techniques: list[str] = field(default_factory=list)  # 关联 ATT&CK，如 ["T1059"]

    # --- 位置与证据 ---
    file_path: str = ""                       # 主告警所在文件（冗余存储便于过滤/排序）
    location: Optional[Location] = None       # 主告警位置
    taint_flow: list[TaintStep] = field(default_factory=list)   # 污点传播路径（模块 2 填充）
    related_routes: list[RouteInfo] = field(default_factory=list)  # 可达路由（模块 2 填充）

    # --- 研判状态（模块 3 / 4 更新）---
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM   # 综合置信度（全程逐级修正）
    status: VulnerabilityStatus = VulnerabilityStatus.NEW  # 当前生命周期状态
    llm_verdict_reason: str = ""              # LLM 误报研判给出的推理文本
    fix_suggestion: Optional[FixSuggestion] = None         # 修复建议（--fix-suggest）

    # --- 原始与元数据 ---
    raw: dict[str, Any] = field(default_factory=dict)              # 工具原始告警（保底不丢信息）
    metadata: dict[str, Any] = field(default_factory=dict)         # 扩展元数据（探针结果等）
    created_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    # ------------------------------------------------------------------
    # 工具方法（跨模块 JSON 交换的核心实现）
    # ------------------------------------------------------------------

    def dedupe_key(self) -> str:
        """返回去重键：同一 (tool, file, rule, start_line) 视为同一告警。

        :return: 形如 ``tool|file_path|rule_id|start_line`` 的字符串。
        """
        start_line: int = self.location.start_line if self.location else 0
        return f"{self.tool.value}|{self.file_path}|{self.rule_id}|{start_line}"

    def to_dict(self) -> dict[str, Any]:
        """将本对象序列化为 JSON 友好的 dict（供落盘与跨模块传递）。

        所有 Enum 字段转为其 ``value`` 字符串；嵌套结构（Location / TaintStep /
        RouteInfo / FixSuggestion）一并递归序列化。

        :return: 可被 json.dumps 直接处理的字典。
        """
        return {
            "id": self.id,
            "tool": self.tool.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_url": self.rule_url,
            "severity": self.severity.value,
            "message": self.message,
            "cwe_ids": list(self.cwe_ids),
            "attack_techniques": list(self.attack_techniques),
            "file_path": self.file_path,
            "location": _loc_to_dict(self.location) if self.location else None,
            "taint_flow": [_ts_to_dict(s) for s in self.taint_flow],
            "related_routes": [_route_to_dict(r) for r in self.related_routes],
            "confidence": self.confidence.value,
            "status": self.status.value,
            "llm_verdict_reason": self.llm_verdict_reason,
            "fix_suggestion": _fix_to_dict(self.fix_suggestion) if self.fix_suggestion else None,
            "raw": self.raw,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """从 :meth:`to_dict` 产出的字典反序列化重建对象。

        对缺失/非法字段做宽容处理（枚举解析失败回落到默认值），
        保证读取历史产物或部分损坏文件时不至于整体崩溃。

        :param data: JSON 反序列化得到的字典。
        :return: 还原的 Finding 对象。
        """
        d: dict[str, Any] = data if isinstance(data, dict) else {}
        taint_flow_raw = d.get("taint_flow") or []
        routes_raw = d.get("related_routes") or []
        return cls(
            id=str(d.get("id", "")),
            tool=_coerce_enum(ToolName, d.get("tool"), ToolName.SEMGREP),
            rule_id=str(d.get("rule_id", "")),
            rule_name=str(d.get("rule_name", "")),
            rule_url=str(d.get("rule_url", "")),
            severity=_coerce_enum(Severity, d.get("severity"), Severity.MEDIUM),
            message=str(d.get("message", "")),
            cwe_ids=[str(c) for c in (d.get("cwe_ids") or [])],
            attack_techniques=[str(t) for t in (d.get("attack_techniques") or [])],
            file_path=str(d.get("file_path", "")),
            location=_loc_from_dict(d.get("location")),
            taint_flow=[_ts_from_dict(s) for s in taint_flow_raw if isinstance(s, dict)],
            related_routes=[_route_from_dict(r) for r in routes_raw if isinstance(r, dict)],
            confidence=_coerce_enum(ConfidenceLevel, d.get("confidence"), ConfidenceLevel.MEDIUM),
            status=_coerce_enum(VulnerabilityStatus, d.get("status"), VulnerabilityStatus.NEW),
            llm_verdict_reason=str(d.get("llm_verdict_reason", "")),
            fix_suggestion=_fix_from_dict(d.get("fix_suggestion")),
            raw=dict(d.get("raw") or {}),
            metadata=dict(d.get("metadata") or {}),
            created_at=str(d.get("created_at") or datetime.now().isoformat(timespec="seconds")),
        )

    def matches_query(self, query: str) -> bool:
        """判断本 Finding 是否命中过滤关键词（文件/规则/消息模糊匹配）。

        命中范围：file_path、rule_id、rule_name、message、各 CWE 编号。
        查询忽略大小写。

        :param query: 用户过滤关键词。
        :return: 命中返回 True。
        """
        q: str = (query or "").strip().lower()
        if not q:
            return True
        haystack: str = " | ".join([
            self.file_path, self.rule_id, self.rule_name, self.message,
            " ".join(self.cwe_ids),
        ]).lower()
        return q in haystack


# ---------------------------------------------------------------------------
# 嵌套结构的序列化 / 反序列化辅助函数
# ---------------------------------------------------------------------------

def _coerce_enum(enum_cls: type, value: Any, default: Any) -> Any:
    """宽容地把字符串/枚举值转为枚举成员；失败回落 default。

    :param enum_cls: Enum 类。
    :param value: 原始值。
    :param default: 解析失败时的默认枚举。
    :return: 枚举成员。
    """
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError:
            return default
    return default


def _loc_to_dict(loc: Location) -> dict[str, Any]:
    """Location -> dict。"""
    return {
        "file_path": loc.file_path, "start_line": loc.start_line, "end_line": loc.end_line,
        "start_col": loc.start_col, "end_col": loc.end_col, "snippet": loc.snippet,
    }


def _loc_from_dict(raw: Any) -> Optional[Location]:
    """dict -> Location（宽容处理缺失字段）。"""
    if not isinstance(raw, dict):
        return None
    return Location(
        file_path=str(raw.get("file_path", "")),
        start_line=int(raw.get("start_line", 0)),
        end_line=int(raw.get("end_line", 0)),
        start_col=int(raw.get("start_col", 1)),
        end_col=int(raw.get("end_col", 1)),
        snippet=str(raw.get("snippet", "")),
    )


def _ts_to_dict(step: TaintStep) -> dict[str, Any]:
    """TaintStep -> dict。"""
    return {
        "node_type": step.node_type,
        "location": _loc_to_dict(step.location) if step.location else None,
        "variable": step.variable,
        "description": step.description,
    }


def _ts_from_dict(raw: Any) -> TaintStep:
    """dict -> TaintStep。"""
    d: dict[str, Any] = raw if isinstance(raw, dict) else {}
    return TaintStep(
        node_type=str(d.get("node_type", "")),
        location=_loc_from_dict(d.get("location")) or Location("", 0, 0),
        variable=str(d.get("variable", "")),
        description=str(d.get("description", "")),
    )


def _route_to_dict(route: RouteInfo) -> dict[str, Any]:
    """RouteInfo -> dict。"""
    return {
        "path": route.path,
        "http_methods": list(route.http_methods),
        "handler_file": route.handler_file,
        "handler_function": route.handler_function,
        "parameters": list(route.parameters),
        "framework": route.framework,
        "entry_location": _loc_to_dict(route.entry_location) if route.entry_location else None,
    }


def _route_from_dict(raw: Any) -> RouteInfo:
    """dict -> RouteInfo。"""
    d: dict[str, Any] = raw if isinstance(raw, dict) else {}
    return RouteInfo(
        path=str(d.get("path", "")),
        http_methods=[str(m) for m in (d.get("http_methods") or [])],
        handler_file=str(d.get("handler_file", "")),
        handler_function=str(d.get("handler_function", "")),
        parameters=[str(p) for p in (d.get("parameters") or [])],
        framework=str(d.get("framework", "")),
        entry_location=_loc_from_dict(d.get("entry_location")),
    )


def _fix_to_dict(fix: FixSuggestion) -> dict[str, Any]:
    """FixSuggestion -> dict。"""
    return {
        "summary": fix.summary,
        "diff": fix.diff,
        "references": list(fix.references),
    }


def _fix_from_dict(raw: Any) -> Optional[FixSuggestion]:
    """dict -> FixSuggestion。"""
    if not isinstance(raw, dict):
        return None
    return FixSuggestion(
        summary=str(raw.get("summary", "")),
        diff=str(raw.get("diff", "")),
        references=[str(r) for r in (raw.get("references") or [])],
    )
