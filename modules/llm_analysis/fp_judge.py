"""误报研判器（FalsePositiveJudge）。

针对单条富化后的 Finding 构造结构化 Prompt 交给 :class:`LLMClient` 研判，
解析其 JSON 输出并把结论回写 Finding。

Prompt 组装内容（模块2 已在 metadata 就位）：
- ``code_context.text``：按工具粒度切好的代码上下文
- ``route_summary``：可达路由
- ``cwe_descriptions``：命中 CWE 的官方描述
- ``vector_hits``：安全知识库语义命中
- 可选：VulnerabilityKB 检索出的**历史确认相似案例**（score>0.85 才附加）

期望模型输出 JSON：::

    {
      "verdict": "true_positive" | "false_positive" | "uncertain",
      "confidence": "high" | "medium" | "low",
      "reason": "...",
      "cwe_ids": ["CWE-78"],
      "fix": {"summary": "...", "diff": "...", "references": []}   # 可选
    }
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from config import Config
from models import (ConfidenceLevel, Finding, FixSuggestion, VulnerabilityStatus)
from modules.llm_analysis.client import LLMClient
from modules.llm_analysis.knowledge_base import VulnerabilityKB

logger = logging.getLogger("opensoft_detect.llm_analysis.judge")

#: Prompt 版本号（嵌入 prompt 便于追踪与迭代）
PROMPT_VERSION: str = "1.4"

#: Few-shot 双例（真实案例）：一个真漏洞 + 一个"有守卫的误报"，
#: 让模型对"跨文件守卫"这种静态易误报的情形有一致判据（可用 use_few_shot=False 关闭做 A/B）。
FEW_SHOT_EXAMPLES: str = (
    "示例A（真漏洞）：`os.system('ping ' + request.GET.get('ip'))` —— 外部输入直达危险 sink，"
    "无任何校验 => {\"verdict\":\"true_positive\",\"reason\":\"外部输入直达 os.system，无消毒\"}\n"
    "示例B（误报）：`p=(base/filename).resolve()` + `if not is_path_inside(p, base): raise` "
    "后再 `FileResponse(p)` —— 已有路径包含性校验（守卫函数可能在其它文件）"
    " => {\"verdict\":\"false_positive\",\"reason\":\"已有校验，越界路径被拒绝\"}"
)

#: verdict 字符串 -> 生命周期状态
_VERDICT_MAP: dict[str, VulnerabilityStatus] = {
    "true_positive": VulnerabilityStatus.TRUE_POSITIVE,
    "false_positive": VulnerabilityStatus.FALSE_POSITIVE,
    "uncertain": VulnerabilityStatus.UNVERIFIED,
}

#: 置信度字符串 -> 枚举
_CONF_MAP: dict[str, ConfidenceLevel] = {
    "high": ConfidenceLevel.HIGH,
    "medium": ConfidenceLevel.MEDIUM,
    "low": ConfidenceLevel.LOW,
}

#: 守卫/消毒函数名特征（确定性后过滤用；不依赖 LLM 判断）
GUARD_HINTS: tuple[str, ...] = (
    "is_path_inside", "secure_filename", "html.escape", "escape(",
    "sanitize", "validate", "whitelist", "allowlist", "normalize",
    "is_relative_to", "commonpath", "literal_eval", "quote(",
    "parameterized", "shlex.quote", "os.path.realpath",
)


def detect_guard_in_context(code_text: str) -> list[str]:
    """在切片文本里找出命中的守卫/消毒函数名（确定性，供后过滤使用）。

    :param code_text: code_context 文本。
    :return: 命中的守卫特征列表（去重）。
    """
    if not code_text:
        return []
    low = code_text.lower()
    return [g for g in GUARD_HINTS if g.lower() in low]


class FalsePositiveJudge:
    """基于大模型的漏洞误报研判器。"""

    def __init__(self, client: LLMClient, kb: Optional[VulnerabilityKB] = None,
                 fix_suggest: bool = False, use_few_shot: bool = True) -> None:
        """构造研判器。

        :param client: LLM 客户端。
        :param kb: 漏洞知识库（提供历史相似案例先验）；可为空。
        :param fix_suggest: 是否要求同时给出修复建议。
        :param use_few_shot: 是否在 system prompt 注入 Few-shot 双例（A/B 评测可关）。
        """
        self.client: LLMClient = client
        self.kb: Optional[VulnerabilityKB] = kb
        self.fix_suggest: bool = fix_suggest
        self.use_few_shot: bool = use_few_shot

    # ------------------------------------------------------------------
    def judge(self, finding: Finding) -> Finding:
        """对单个 Finding 完成研判，返回更新后的对象。

        :param finding: 富化后的 Finding。
        :return: 更新研判状态后的 Finding。
        :raises RuntimeError: LLM 调用/解析失败（由调用方降级处理）。
        """
        # 1) 检索历史相似确认案例（score>0.85），构造先验
        prior_hits: list[dict[str, Any]] = []
        if self.kb is not None:
            try:
                prior_hits = self.kb.search_prior(finding)
            except Exception as exc:  # noqa: BLE001
                logger.warning("检索历史案例失败：%s", exc)
        if prior_hits:
            finding.metadata["kb_prior"] = [
                {"score": round(h["score"], 4),
                 "rule_id": h["payload"].get("rule_id"),
                 "pattern": h["payload"].get("code_pattern", "")[:120]}
                for h in prior_hits]

        # 2) 构造并调用
        system_prompt: str = self._build_system_prompt()
        user_prompt: str = self._build_user_prompt(finding, prior_hits)
        response: dict[str, Any] = self.client.chat_json(system_prompt, user_prompt)

        # 3) 解析并回写
        finding.status = self._map_status(response.get("verdict"))
        finding.confidence = self._map_confidence(response.get("confidence"))
        finding.llm_verdict_reason = str(response.get("reason", "")).strip()
        if isinstance(response.get("cwe_ids"), list):
            finding.cwe_ids = [str(c) for c in response["cwe_ids"]]
        if self.fix_suggest and isinstance(response.get("fix"), dict):
            fix = response["fix"]
            finding.fix_suggestion = FixSuggestion(
                summary=str(fix.get("summary", "")),
                diff=str(fix.get("diff", "")),
                references=[str(r) for r in (fix.get("references") or [])])
        finding.metadata["llm"] = {"prompt_version": PROMPT_VERSION,
                                   "judged_at": datetime.now().isoformat(timespec="seconds"),
                                   "fp_factors": list(response.get("fp_factors") or [])}

        # 3.5) 确定性守卫后过滤：切片里若出现针对输入的校验/消毒调用，
        #      即便 LLM 判 TP 也降级为"待复核"（治自定义消毒函数导致的 FP，
        #      如 chainlit 的 is_path_inside）。不依赖 LLM 稳定性。
        ctx_text: str = (finding.metadata.get("code_context") or {}).get("text", "")
        guards = detect_guard_in_context(ctx_text)
        if guards and finding.status == VulnerabilityStatus.TRUE_POSITIVE:
            finding.status = VulnerabilityStatus.UNVERIFIED
            finding.confidence = ConfidenceLevel.MEDIUM
            finding.metadata["guard_postfilter"] = {
                "downgraded": True, "guards": guards,
                "reason": "切片中存在校验/消毒调用，需人工确认是否有效防护",
            }
            logger.info("守卫后过滤：%s 由 TP 降级为待复核（命中 %s）",
                        finding.id, guards)

        # 4) 闭环入库：FP → 误报集合；TP → 仅动态确认后入漏洞集合
        if self.kb is not None:
            try:
                self.kb.store_adjudicated(finding)
            except Exception as exc:  # noqa: BLE001 - 入库失败不影响研判结果
                logger.warning("案例入库失败（忽略）：%s", exc)
        return finding

    # ------------------------------------------------------------------
    # Prompt 构造
    # ------------------------------------------------------------------
    def _build_system_prompt(self) -> str:
        """系统提示词：角色 + 输出 JSON schema 约束。

        :return: 系统提示词文本。
        """
        return (
            f"# prompt_v={PROMPT_VERSION}\n"
            "你是一名资深应用安全代码审计专家，负责对静态分析工具产出的漏洞告警做误报研判。\n"
            "请基于提供的代码切片、路由可达性与 CWE 描述，判断告警是否为真实可利用漏洞。\n"
            "只输出一个 JSON 对象（不要输出其它任何文字、解释或 markdown），结构如下：\n"
            "{\n"
            '  "verdict": "true_positive" | "false_positive" | "uncertain",\n'
            '  "confidence": "high" | "medium" | "low",\n'
            '  "fp_factors": ["若可能为误报，在此逐条列出理由（如：已有参数化/路径校验/不可达）"],\n'
            '  "reason": "简要中文推理",\n'
            '  "cwe_ids": ["CWE-xxx"],\n'
            '  "fix": {"summary": "修复思路", "diff": "可应用补丁(unified diff)", "references": []}\n'
            "}\n"
            "判定要点：外部输入确实流向危险函数且无消毒 => true_positive；"
            "存在消毒/参数化/不可达 => false_positive；证据不足 => uncertain。\n"
            "特别注意：切片中可能包含**跨文件被调函数**（如 is_path_inside / sanitize / "
            "validate / escape / normalize / resolve 后的边界校验）。请先找出所有"
            "针对该输入的校验或消毒调用；若已有有效防护（例如路径包含性校验、参数化查询、"
            "白名单），应判 false_positive。"
            + (f"\n\n{FEW_SHOT_EXAMPLES}" if self.use_few_shot else "")
        )

    def _build_user_prompt(self, finding: Finding,
                           prior_hits: list[dict[str, Any]]) -> str:
        """用户提示词：把告警与全部富化上下文拼进去。

        :param finding: 目标 Finding。
        :param prior_hits: 历史相似案例（可能为空）。
        :return: 用户提示词文本。
        """
        ctx: dict = finding.metadata.get("code_context") or {}
        route_sum: list = finding.metadata.get("route_summary") or []
        cwes: dict = finding.metadata.get("cwe_descriptions") or {}
        vhits: list = finding.metadata.get("vector_hits") or []
        cwe_desc_text: str = "\n".join(f"- {k}: {v}" for k, v in cwes.items()) or "(无)"
        vector_text: str = "\n".join(
            f"- ({h.get('source')}) {h.get('id')}: {h.get('name')}" for h in vhits) or "(无)"
        prior_text: str = VulnerabilityKB.prior_to_prompt(prior_hits)
        sink_line: str = f"{finding.file_path}:{finding.location.start_line}" \
            if finding.location else finding.file_path

        return (
            f"## 告警基本信息\n"
            f"- finding_id: {finding.id}\n"
            f"- 规则: {finding.rule_id} ({finding.rule_name or 'n/a'})\n"
            f"- 严重程度: {finding.severity.value} | 命中位置: {sink_line}\n"
            f"- 告警描述: {finding.message}\n"
            f"- 相关 CWE: {', '.join(finding.cwe_ids) or '(无)'}\n\n"
            f"## CWE 官方描述\n{cwe_desc_text}\n\n"
            f"## 路由可达性（若命中文件有路由）\n"
            f"{chr(10).join(route_sum) if route_sum else '(该文件未识别到路由)'}\n\n"
            f"## 知识库语义命中（供交叉验证）\n{vector_text}\n\n"
            f"## 代码上下文（切片）\n"
            f"```python\n{ctx.get('text') or '(未获取到代码上下文)'}\n```\n"
            + (f"\n## {prior_text}\n" if prior_text else "")
            + "\n请据此给出你的研判 JSON。"
        )

    # ------------------------------------------------------------------
    # 解析映射
    # ------------------------------------------------------------------
    @staticmethod
    def _map_status(text: Any) -> VulnerabilityStatus:
        """verdict 字符串 -> 状态枚举（未识别回落 UNVERIFIED）。"""
        return _VERDICT_MAP.get(str(text or "").strip().lower(),
                                VulnerabilityStatus.UNVERIFIED)

    @staticmethod
    def _map_confidence(text: Any) -> ConfidenceLevel:
        """置信度字符串 -> 枚举（未识别回落 MEDIUM）。"""
        return _CONF_MAP.get(str(text or "").strip().lower(),
                             ConfidenceLevel.MEDIUM)
