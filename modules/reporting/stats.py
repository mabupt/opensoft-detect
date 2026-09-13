"""报告统计（stats）。

四级置信度分级与误报率指标。分级规则（模块5 口径）：

- **confirmed**        ：动态验证双轨均触发（verdict==confirmed 或 DYNAMIC_CONFIRMED）
- **high_suspicious**  ：LLM 研判 true_positive 但未做动态验证
- **possible**         ：LLM uncertain / 仅轨道A触发(retry_poc) / 未研判(NEW)
- **excluded**         ：LLM false_positive / 动态 rejected / 预过滤排除
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from models import Finding, Severity, ToolName, VulnerabilityStatus

#: 四级置信度（顺序即展示顺序）
CONFIDENCE_LEVELS: tuple[str, ...] = ("confirmed", "high_suspicious", "possible", "excluded")

#: 各置信度短名
CONFIDENCE_LABELS: dict[str, str] = {
    "confirmed": "已确认（动态双轨）",
    "high_suspicious": "高度可疑（LLM 判真，未动态验证）",
    "possible": "可能（不确定/仅轨道A）",
    "excluded": "排除（误报）",
}


def classify_confidence(finding: Finding) -> str:
    """把 Finding 归入四级置信度之一。

    证据来源平等对待（不只看 LLM）：
    1. 动态实证（双轨/策略/DAST）→ confirmed；
    2. LLM 判真 → high_suspicious；
    3. **静态结论**：未经 LLM 研判（缺 Key/跳过）但来源为 CodeQL/Semgrep 且
       严重度 high/critical → high_suspicious，并标 ``static_only``（静态结论本身有价值）；
    4. 其余 → possible（待复核）。

    :param finding: 待分类 Finding。
    :return: confirmed / high_suspicious / possible / excluded。
    """
    dynamic = finding.metadata.get("dynamic") or {}
    prefilter = finding.metadata.get("prefilter") or {}
    llm = finding.metadata.get("llm") or {}
    # excluded：预过滤丢弃 或 LLM/动态判误报
    if prefilter.get("dropped") or finding.status == VulnerabilityStatus.FALSE_POSITIVE:
        return "excluded"
    if dynamic.get("verdict") in ("confirmed",) \
            or finding.status == VulnerabilityStatus.DYNAMIC_CONFIRMED:
        return "confirmed"
    if finding.status == VulnerabilityStatus.TRUE_POSITIVE:
        return "high_suspicious"
    # 静态结论（无 LLM 参与也成立）
    judged: bool = bool(llm) and not llm.get("skipped")
    if not judged and finding.tool in (ToolName.CODEQL, ToolName.SEMGREP) \
            and finding.severity in (Severity.CRITICAL, Severity.HIGH):
        finding.metadata["static_only"] = True
        return "high_suspicious"
    # 其余（uncertain/unverified/new）以及仅轨道A(retry_poc) -> possible
    return "possible"


def confidence_distribution(findings: Iterable[Finding]) -> dict[str, int]:
    """按四级置信度统计。

    :param findings: Finding 集合。
    :return: {level: count}。
    """
    counts: dict[str, int] = {k: 0 for k in CONFIDENCE_LEVELS}
    for f in findings:
        counts[classify_confidence(f)] += 1
    return counts


def compute_fp_rate(findings: Iterable[Finding],
                    dropped_count: int = 0) -> dict[str, Any]:
    """误报率统计。

    口径（写入报告的 assumptions）：
    - TP = confirmed + high_suspicious（被判为真实）
    - FP = excluded（LLM 误报 + 动态 rejected + 预过滤排除）
    - false_positive_rate = FP / (TP + FP)；无判定样本时为 0 并置 unrated=True

    :param findings: 已过滤后进入研判的 Finding。
    :param dropped_count: 预过滤丢弃数（并入 FP）。
    :return: 统计字典。
    """
    dist = confidence_distribution(findings)
    tp: int = dist["confirmed"] + dist["high_suspicious"]
    fp: int = dist["excluded"] + dropped_count
    total: int = tp + fp
    rate: float = 0.0
    if total:
        rate = round(fp / total, 4)
    return {
        "total_findings": total,
        "true_positives": tp,
        "false_positives": fp,
        "false_positive_rate": rate,
        "by_engine": _fp_rate_by_engine(findings),
        "unrated": (total == 0),
    }


def _fp_rate_by_engine(findings: Iterable[Finding]) -> dict[str, dict[str, Any]]:
    """分引擎误报率。

    为什么需要：整体误报率的分母常被**依赖漏洞**（客观 CVE，几乎恒为 TP）主导——
    实测 pygoat 里依赖类占 88.5%，于是"多判 1 条代码误报"就足以让整体比率变动
    0.26 个百分点，指标失去区分度。分引擎统计才看得出各检测能力的真实表现。

    :param findings: 报告内的 Finding 列表。
    :return: {引擎名: {total, true_positives, false_positives, false_positive_rate}}。
    """
    items = list(findings)
    out: dict[str, dict[str, Any]] = {}
    for tool in sorted({getattr(f.tool, "value", str(f.tool)) for f in items}):
        subset = [f for f in items if getattr(f.tool, "value", str(f.tool)) == tool]
        dist = confidence_distribution(subset)
        tp = dist["confirmed"] + dist["high_suspicious"]
        fp = dist["excluded"]
        total = tp + fp
        out[tool] = {
            "total": total,
            "true_positives": tp,
            "false_positives": fp,
            "false_positive_rate": round(fp / total, 4) if total else 0.0,
        }
    return out


def summarize(findings: Iterable[Finding],
              dropped_count: int = 0,
              severity: Optional[dict[str, int]] = None,
              tool: Optional[dict[str, int]] = None) -> dict[str, Any]:
    """汇总成报告 statistics 段。

    :param findings: 进入研判/报告的 Finding。
    :param dropped_count: 预过滤丢弃数。
    :param severity: 严重程度分布（可选覆盖）。
    :param tool: 来源工具分布（可选覆盖）。
    :return: 统计字典。
    """
    from collections import Counter

    dist = confidence_distribution(findings)
    fp = compute_fp_rate(findings, dropped_count)
    sev = severity or dict(Counter(f.severity.value for f in findings))
    tools = tool or dict(Counter(f.tool.value for f in findings))
    return {
        "total_reported": len(findings) + dropped_count,
        "confidence_distribution": dist,
        "confidence_labels": CONFIDENCE_LABELS,
        "severity_distribution": sev,
        "tool_distribution": tools,
        "fp_rate": fp,
        "assumptions": (
            "TP = confirmed + high_suspicious；FP = excluded（LLM 误报 + 动态 rejected "
            "+ 预过滤排除）；false_positive_rate = FP/(TP+FP)。"
        ),
    }
