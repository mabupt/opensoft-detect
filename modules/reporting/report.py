"""报告聚合与组装（report）。

把各模块产物汇总为一份最终 report 结构，供 JSON/HTML reporter 消费：

- **多文件聚合**：findings / enriched / verdicts / test_results 四阶段 JSON 按
  finding id 合并（后阶段覆盖前阶段），任一缺失容忍；
- **四级置信度分组**（见 reporting/stats.classify_confidence）；
- **CWE-ATT&CK 关联**（enrichment）；
- **修复 Diff**：仅当 ``--fix-suggest`` 且 verdict==true_positive 且
  test_status==confirmed 时，调用 LLM 生成 unified diff，并做**事实校验**
  （diff 内路径/行号必须与实际代码匹配，校验失败即丢弃该修复）；
- **误报率统计**（stats.compute_fp_rate）。
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import Config
from models import Finding, FixSuggestion, VulnerabilityStatus
from modules.reporting.enrichment import map_cwe_to_attack, technique_name
from modules.reporting.stats import classify_confidence, summarize

logger = logging.getLogger("opensoft_detect.reporting")

#: unified diff 的 hunk 头（@@ -old,? +new,? @@）
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


# ---------------------------------------------------------------------------
# 多文件聚合
# ---------------------------------------------------------------------------

def aggregate_findings(stage_paths: list[Path]) -> list[Finding]:
    """按 finding id 合并多阶段 JSON（后阶段覆盖前阶段）。

    :param stage_paths: 各阶段 JSON 路径（不存在的自动忽略）。
    :return: 合并后的 Finding 列表。
    """
    merged: dict[str, Finding] = {}
    for path in stage_paths:
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("聚合跳过不可读文件 %s：%s", path, exc)
            continue
        items = raw.get("findings") if isinstance(raw, dict) else raw
        for item in items or []:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            f = Finding.from_dict(item)
            merged[f.id] = f            # 后写的阶段覆盖先写的
    return list(merged.values())


def load_dropped(path: Path) -> list[dict[str, Any]]:
    """读取预过滤丢弃记录列表（模块3 产物）。

    :param path: prefilter_dropped.json 路径。
    :return: 记录列表。
    """
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return list(raw.get("records") or [])
    except (OSError, json.JSONDecodeError):
        return []


# ---------------------------------------------------------------------------
# 修复 Diff 事实校验
# ---------------------------------------------------------------------------

def validate_unified_diff(diff: str, target_file: str) -> tuple[bool, str]:
    """事实验证 unified diff：路径/行号必须与磁盘代码一致。

    规则：
    1. diff 非空；
    2. hunk 头可解析，且每个 hunk 的行号落在实际文件行数范围内（容差 append）；
    3. 目标文件存在。

    :param diff: unified diff 文本。
    :param target_file: 目标文件绝对路径。
    :return: (是否有效, 无效原因)。
    """
    if not diff or not diff.strip():
        return False, "diff 为空"
    path = Path(target_file)
    if not path.is_file():
        return False, f"目标文件不存在：{target_file}"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return False, f"读取目标文件失败：{exc}"
    n_lines = len(lines)
    hunks = [ln for ln in diff.splitlines() if ln.startswith("@@")]
    if not hunks:
        return False, "diff 中缺少 hunk 头（@@ 行）"
    for hunk in hunks:
        m = _HUNK_RE.match(hunk)
        if not m:
            return False, f"无法解析 hunk 头：{hunk[:60]}"
        old_start = int(m.group(1))
        if not (1 <= old_start <= n_lines + 1):
            return False, f"行号越界 old_start={old_start}（文件 {n_lines} 行）"
    return True, ""


def generate_fix_for_confirmed(finding: Finding, config: Config) -> Optional[FixSuggestion]:
    """仅对 confirmed 且 test_status==confirmed 的 Finding 生成修复建议。

    用模块3 的 LLM 客户端生成 unified diff，做事实校验；失败丢弃并留日志。

    :param finding: Finding。
    :param config: 全局配置。
    :return: 校验通过的 FixSuggestion；条件不满足或生成失败返回 None。
    """
    if finding.status not in (VulnerabilityStatus.DYNAMIC_CONFIRMED,) \
            and not (finding.metadata.get("dynamic") or {}).get("verdict") == "confirmed":
        return None
    if str((finding.metadata or {}).get("test_status", "")).lower() != "confirmed":
        return None
    from modules.llm_analysis.client import LLMClient
    client = LLMClient(config.llm)
    if not client.is_available():
        finding.metadata["fix"] = {"status": "skipped", "reason": "无 LLM API Key"}
        return None
    ctx: dict = finding.metadata.get("code_context") or {}
    system = ("# prompt_v=1.3-fix\n你是安全修复工程师。请给指定漏洞生成 unified diff 修复。"
              "diff 的行号必须与给出的实际文件一致。只输出 JSON："
              '{"summary": string, "diff": string, "references": [string]}')
    user = (f"rule={finding.rule_id}\n文件={finding.file_path}\n"
            f"sink 行={finding.location.start_line if finding.location else '?'}\n"
            f"代码上下文:\n```python\n{ctx.get('text') or '(无)'}\n```")
    try:
        resp = client.chat_json(system, user)
        diff = str(resp.get("diff") or "").strip()
        ok, reason = validate_unified_diff(diff, finding.file_path)
        if not ok:
            finding.metadata["fix"] = {"status": "discarded", "reason": reason}
            logger.warning("修复 Diff 校验失败已丢弃（%s）：%s", finding.id, reason)
            return None
        fix = FixSuggestion(
            summary=str(resp.get("summary", "")).strip(),
            diff=diff,
            references=[str(r) for r in (resp.get("references") or [])])
        finding.metadata["fix"] = {"status": "generated"}
        return fix
    except Exception as exc:  # noqa: BLE001
        finding.metadata["fix"] = {"status": "error", "reason": str(exc)}
        logger.warning("修复建议生成失败 %s：%s", finding.id, exc)
        return None


# ---------------------------------------------------------------------------
# 报告组装
# ---------------------------------------------------------------------------

class ReportAssembler:
    """把聚合后的 Finding 组装为最终 report 字典。"""

    def __init__(self, config: Config) -> None:
        """构造组装器。

        :param config: 全局配置。
        """
        self.config: Config = config

    def assemble(self, findings: list[Finding],
                 dropped: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
        """组装完整 report。

        :param findings: 聚合后 Finding。
        :param dropped: 预过滤丢弃记录。
        :return: report 字典。
        """
        dropped = dropped or []
        # 0) 预过滤丢弃回标：按 id 把对应 Finding 归为 FALSE_POSITIVE(excluded)，
        #    避免它们因"未进 verified 文件"而误落 possible；已回标的记录不计入 dropped 数
        matched_ids: set[str] = {d.get("finding_id") for d in dropped}
        left_dropped: list[dict[str, Any]] = [d for d in dropped
                                              if d.get("finding_id") not in {f.id for f in findings}]
        for f in findings:
            if f.id in matched_ids:
                f.status = VulnerabilityStatus.FALSE_POSITIVE
                f.metadata.setdefault("prefilter", {})["dropped"] = True

        # 1) 若开启修复建议，先为 confirmed 的生成修复
        if self.config.fix_suggest:
            for f in findings:
                if classify_confidence(f) == "confirmed":
                    fix = generate_fix_for_confirmed(f, self.config)
                    if fix is not None:
                        f.fix_suggestion = fix

        # 2) 统计（已回标的 dropped 不再重复计入 FP）
        statistics = summarize(findings, dropped_count=len(left_dropped))

        # 3) CWE-ATT&CK 关联
        matrix = {}
        for tech, cwes in sorted(_attack_matrix(findings).items()):
            matrix[tech] = {"name": technique_name(tech), "cwes": dict(sorted(cwes.items()))}

        # 4) 置信度分组 + 每条附 confidence/attacks
        groups: dict[str, list[dict[str, Any]]] = {k: [] for k in
                                                   ("confirmed", "high_suspicious", "possible", "excluded")}
        out_findings: list[dict[str, Any]] = []
        sources: dict[str, int] = {"dynamic_confirmed": 0, "llm_true_positive": 0,
                                   "static_only": 0, "needs_review": 0, "excluded": 0}
        for f in findings:
            level = classify_confidence(f)
            d = f.to_dict()
            d["report_confidence"] = level
            d["attack_techniques"] = map_cwe_to_attack(f.cwe_ids)
            # 三类证据并列展示（静态 / 动态 / LLM），不厚此薄彼
            llm_meta = f.metadata.get("llm") or {}
            d["evidence"] = {
                "static": {"tool": f.tool.value, "rule_id": f.rule_id,
                           "severity": f.severity.value, "cwe": list(f.cwe_ids)},
                "dynamic": f.metadata.get("dynamic"),
                "llm": {"verdict": f.status.value,
                        "reason": f.llm_verdict_reason,
                        "skipped": llm_meta.get("skipped"),
                        "prompt_version": llm_meta.get("prompt_version")},
                "guard_postfilter": f.metadata.get("guard_postfilter"),
            }
            groups[level].append(d)
            out_findings.append(d)
            # 证据来源统计
            if level == "excluded":
                sources["excluded"] += 1
            elif (f.metadata.get("dynamic") or {}).get("verdict") == "confirmed" \
                    or f.status == VulnerabilityStatus.DYNAMIC_CONFIRMED:
                sources["dynamic_confirmed"] += 1
            elif f.status == VulnerabilityStatus.TRUE_POSITIVE:
                sources["llm_true_positive"] += 1
            elif f.metadata.get("static_only"):
                sources["static_only"] += 1
            else:
                sources["needs_review"] += 1

        statistics["evidence_sources"] = sources
        return {
            "meta": self._build_meta(),
            "statistics": statistics,
            "cwe_attack_matrix": matrix,
            "confidence_groups": groups,
            "dropped_records": left_dropped,
            "findings": out_findings,
        }

    def _build_meta(self) -> dict[str, Any]:
        """构造报告 meta 段。"""
        return {
            "tool": "OpenSoft Detect",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target": str(self.config.target),
            "fix_suggest": self.config.fix_suggest,
            "skip_dynamic": self.config.skip_dynamic,
        }


def _attack_matrix(findings: list[Finding]) -> dict[str, dict[str, int]]:
    """(technique -> cwe -> count) 矩阵。"""
    matrix: dict[str, dict[str, int]] = {}
    for f in findings:
        for tech in map_cwe_to_attack(f.cwe_ids):
            row = matrix.setdefault(tech, {})
            for cid in f.cwe_ids:
                row[cid] = row.get(cid, 0) + 1
    return matrix
