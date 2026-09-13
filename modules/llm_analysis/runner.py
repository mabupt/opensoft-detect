"""模块3 编排入口（runner）。

对模块2 富化后的 Finding 执行：**预过滤 -> LLM 误报研判 -> 特征闭环**，
产出 ``output/verified_findings.json``。

流程：
1. 载入 enriched_findings.json；
2. Prefilter 过滤明显误报，丢弃清单落盘 ``output/prefilter_dropped.json``；
3. 构造 VulnerabilityKB 并确保特征集合存在（Qdrant 不可达则降级为空）；
4. 逐条调用 FalsePositiveJudge 研判（LLM 无 Key / 调用失败时对该条降级标记）；
5. 汇总落盘。

产物（verified_findings.json）结构：::

    {
      "version": "1.1",
      "generated_at": "...",
      "source": "<enriched 路径>",
      "dropped": N,
      "llm_available": true/false,
      "verdict_summary": {"true_positive": n, "false_positive": n, "unverified": n},
      "findings": [ Finding.to_dict() ... ]
    }
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import Config
from models import (ConfidenceLevel, Finding, ToolName, VulnerabilityStatus)
from modules.llm_analysis.client import LLMClient
from modules.llm_analysis.fp_judge import FalsePositiveJudge
from modules.llm_analysis.knowledge_base import VulnerabilityKB
from modules.llm_analysis.prefilter import DropReport, Prefilter

logger = logging.getLogger("opensoft_detect.llm_analysis")


def run(enriched_path: Path, config: Config) -> Path:
    """执行模块3 LLM 误报研判。

    :param enriched_path: 模块2 产出的 enriched_findings.json 路径。
    :param config: 全局配置（llm / qdrant / fix_suggest）。
    :return: verified_findings.json 绝对路径。
    """
    findings: list[Finding] = _load_findings(enriched_path)
    logger.info("载入 %d 条富化后 Finding 进入研判。", len(findings))

    # ---- 预过滤 ----
    prefilter = Prefilter(config)
    kept, dropped = prefilter.apply(findings)
    _save_dropped(dropped, config)
    logger.info("预过滤：保留 %d，丢弃 %d。", len(kept), len(dropped))
    if not kept:
        logger.warning("预过滤后无剩余 Finding，直接写空结果。")

    # ---- 知识库（降级容忍）----
    kb: Optional[VulnerabilityKB] = None
    try:
        kb = VulnerabilityKB(config.qdrant)
        kb.ensure_collection()
    except Exception as exc:  # noqa: BLE001
        logger.warning("漏洞知识库不可用，本轮不做特征闭环：%s", exc)
        kb = None

    # ---- LLM 研判 ----
    client = LLMClient(config.llm)
    llm_available: bool = client.is_available()
    if not llm_available:
        logger.warning("未配置 LLM API Key（ANTHROPIC_API_KEY/OPENAI_API_KEY），"
                       "本轮跳过 LLM 研判，仅保留预过滤结果。")
    judge = FalsePositiveJudge(client, kb=kb, fix_suggest=config.fix_suggest)

    routing: dict[str, int] = {"dependency_factual": 0, "policy_decidable": 0,
                               "llm": 0, "escalated": 0, "no_key": 0,
                               "endpoint_down": 0}
    escalation_model: str = os.environ.get("OPENSOFT_LLM_ESCALATION_MODEL", "").strip()
    consecutive_fail: int = 0
    endpoint_down: bool = False
    verified: list[Finding] = []
    for finding in kept:
        # 路由1：依赖漏洞（pip-audit/OSV）是事实性结论，不调 LLM
        if finding.tool == ToolName.PIP_AUDIT:
            finding.status = VulnerabilityStatus.TRUE_POSITIVE
            finding.confidence = ConfidenceLevel.HIGH
            finding.metadata.setdefault("llm", {})["skipped"] = "dependency-factual"
            routing["dependency_factual"] += 1
            verified.append(finding)
            continue
        # 路由2：规则明确类（弱哈希等）——策略可判，跳过 LLM（省调用，结论稳定）
        if _policy_decidable(finding):
            finding.status = VulnerabilityStatus.TRUE_POSITIVE
            finding.confidence = ConfidenceLevel.HIGH
            finding.metadata.setdefault("llm", {})["skipped"] = "policy-decidable"
            routing["policy_decidable"] += 1
            verified.append(finding)
            continue
        if not llm_available:
            finding.metadata.setdefault("llm", {})["skipped"] = "no_api_key"
            routing["no_key"] += 1
            verified.append(finding)
            continue
        # 端点熔断：连续失败达阈值即放弃本轮剩余 LLM 调用（避免"重试×条目数"放大耗时）
        if endpoint_down:
            finding.metadata.setdefault("llm", {})["skipped"] = "llm_endpoint_down"
            routing["endpoint_down"] += 1
            verified.append(finding)
            continue
        try:
            judge.judge(finding)
            consecutive_fail = 0
            routing["llm"] += 1
            # 路由3：仍不确定 → 若配置了升级模型，用它复核一次（分级调用，省钱）
            if escalation_model and finding.status == VulnerabilityStatus.UNVERIFIED:
                try:
                    from dataclasses import replace as _replace
                    esc_client = LLMClient(_replace(config.llm, model=escalation_model))
                    FalsePositiveJudge(esc_client, kb=kb,
                                       fix_suggest=config.fix_suggest).judge(finding)
                    routing["escalated"] += 1
                    logger.info("升级模型复核 %s -> %s", finding.id, finding.status.value)
                except Exception as exc2:  # noqa: BLE001
                    logger.warning("升级模型复核失败（保留原判定）：%s", exc2)
            logger.info("研判 %s -> %s (confidence=%s)", finding.id,
                        finding.status.value, finding.confidence.value)
        except Exception as exc:  # noqa: BLE001 - 单条研判失败降级
            finding.status = VulnerabilityStatus.UNVERIFIED
            finding.metadata.setdefault("llm", {})["error"] = str(exc)
            consecutive_fail += 1
            logger.error("研判 %s 失败（连续 %d 次），标记 unverified：%s",
                         finding.id, consecutive_fail, exc)
            if consecutive_fail >= 3:
                endpoint_down = True
                logger.warning("LLM 端点连续失败 %d 次，**熔断本轮剩余调用**"
                               "（避免重试放大耗时）。", consecutive_fail)
        verified.append(finding)

    summary: dict[str, int] = dict(Counter(f.status.value for f in verified))
    out_path: Path = config.paths.default_verdict_path
    payload: dict[str, Any] = {
        "version": "1.1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": str(enriched_path),
        "dropped": len(dropped),
        "llm_available": llm_available,
        "verdict_summary": summary,
        "llm_routing": routing,
        "findings": [f.to_dict() for f in verified],
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("研判完成写入：%s | verdict 分布 %s", out_path, summary)
    return out_path


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _policy_decidable(finding: Finding) -> bool:
    """规则明确、可由确定性策略判定的类别（弱哈希等），跳过 LLM。

    :param finding: 待路由 Finding。
    :return: True 表示走"策略直判"，不调用大模型。
    """
    blob = f"{finding.rule_id} {finding.rule_name} {finding.message} {' '.join(finding.cwe_ids)}".lower()
    hints = ("weak-sensitive-data-hashing", "weak-cryptographic-algorithm",
             "md5", "sha1", "cwe-327", "cwe-328", "cwe-916", "cwe-759", "cwe-760")
    return any(h in blob for h in hints)


def _load_findings(path: Path) -> list[Finding]:
    """宽容读取发现文件（wrapper 或裸列表）。"""
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.get("findings") if isinstance(raw, dict) else raw
    return [Finding.from_dict(x) for x in (items or []) if isinstance(x, dict)]


def _save_dropped(dropped: list[DropReport], config: Config) -> None:
    """把预过滤丢弃记录落盘（透明可审计）。"""
    out = config.paths.findings_dir / "prefilter_dropped.json"
    try:
        out.write_text(json.dumps(
            {"generated_at": datetime.now().isoformat(timespec="seconds"),
             "dropped": len(dropped),
             "records": [d.to_dict() for d in dropped]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("预过滤丢弃记录已写入：%s", out)
    except OSError as exc:
        logger.warning("写入预过滤丢弃记录失败：%s", exc)
