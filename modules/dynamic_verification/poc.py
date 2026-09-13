"""PoC 生成与重试（poc）。

在"轨道A 触发但轨道B 未触发"（污点标记在传播中被过滤）时，需要生成 / 调整 PoC。
流程遵循规格的 **"先分析再动手"**：

1. 让 LLM 先输出 ``analysis``（逐点分析各步过滤/消毒逻辑、标记会在哪里丢失），
   再输出 ``test_input``（对应 PoC 输入）；
2. 若一轮后轨道B 仍未命中，最多**重试 3 轮**，每轮把上一轮 analysis 与
   "标记丢失推测"反馈给 LLM 重新设计 test_input；
3. 兜底：若标记总是被过滤，则启用 ``source_inject=True`` —— 在 source 点
   （如 request.args.get）直接注入 :class:`track_b.TaintedString` 标记。

PoC 内容以 JSON 返回：``{"analysis": str, "test_input": str}``。
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from models import Finding
from modules.llm_analysis.client import LLMClient

logger = logging.getLogger("opensoft_detect.dynamic_verification.poc")

#: prompt 版本（与模块3 保持一致并单独递增以便追踪）
POC_PROMPT_VERSION: str = "0.2"
#: 重试上限
MAX_POC_RETRIES: int = 3


class PocGenerator:
    """基于 LLM 的 PoC 生成器（分析在前、输入在后）。"""

    def __init__(self, client: LLMClient, max_retries: int = MAX_POC_RETRIES) -> None:
        """构造生成器。

        :param client: LLM 客户端（可为不可用，届时退化为确定性空 PoC）。
        :param max_retries: 每 Finding 最多重试轮数。
        """
        self.client: LLMClient = client
        self.max_retries: int = max_retries

    def available(self) -> bool:
        """是否需要/能够用 LLM。

        :return: True 表示可用。
        """
        return self.client.is_available()

    # ------------------------------------------------------------------
    def generate(self, finding: Finding,
                 prev_analysis: str = "",
                 source_inject: bool = False) -> dict[str, str]:
        """为单个 Finding 生成一轮 PoC（analysis + test_input）。

        :param finding: 目标 Finding（含 code_context / route_summary）。
        :param prev_analysis: 上一轮 LLM 的分析（重试时用于指出标记丢失点）。
        :param source_inject: 是否启用 source 点直接注入标记的兜底。
        :return: {"analysis": "...", "test_input": "..."}；LLM 不可用时返回说明性空值。
        """
        if not self.client.is_available():
            return self._fallback_poc(finding, source_inject)
        system_prompt: str = self._system_prompt()
        user_prompt: str = self._user_prompt(finding, prev_analysis, source_inject)
        resp: dict[str, Any] = self.client.chat_json(system_prompt, user_prompt)
        return {
            "analysis": str(resp.get("analysis", "")),
            "test_input": str(resp.get("test_input", "")),
            "source_inject": source_inject,
        }

    def retry_loop(self, finding: Finding,
                   is_b_lost: Any) -> dict[str, str]:
        """按"轨道A 触发但轨道B 未触发"逐轮重试，最多 max_retries 轮。

        末尾轮启用 source 注入兜底。

        :param finding: 目标 Finding。
        :param is_b_lost: 判定对象/回调，若提供 callable 则每轮用它判断 B 是否仍丢。
        :return: 最后一次生成的 PoC（含轮次信息）。
        """
        last: dict[str, str] = {}
        prev: str = ""
        for round_no in range(1, self.max_retries + 1):
            inject: bool = (round_no == self.max_retries)   # 最后一轮用 source 注入兜底
            last = self.generate(finding, prev_analysis=prev, source_inject=inject)
            last["round"] = round_no
            logger.info("PoC 第 %d 轮完成（source_inject=%s）", round_no, inject)
            # 若调用方提供了"是否已不再丢 B"的判断且已解决，则提前退出
            if callable(is_b_lost):
                try:
                    if not is_b_lost():
                        break
                except Exception:  # noqa: BLE001
                    pass
            prev = last.get("analysis", "")
        return last

    # ------------------------------------------------------------------
    def _system_prompt(self) -> str:
        """系统提示：规定输出 JSON 且"先分析再动手"。"""
        return (
            f"# prompt_v={POC_PROMPT_VERSION}\n"
            "你是一名 Web 安全工程师，负责为已确认可动态执行的漏洞构造 Proof-of-Concept 输入。\n"
            "**必须遵循'先分析再动手'**：先逐点分析代码中各步是否存在过滤/消毒/类型转换\n"
            "（分析污点标记在哪一步会丢失），再给出最小化的 test_input。\n"
            "只输出 JSON：{\"analysis\": string, \"test_input\": string}，不要其它文字。"
        )

    def _user_prompt(self, finding: Finding, prev_analysis: str,
                     source_inject: bool) -> str:
        """用户提示：代码上下文 + 路由 + 上一轮分析（重试时）。"""
        ctx: dict = finding.metadata.get("code_context") or {}
        routes: list = finding.metadata.get("route_summary") or []
        lines = [
            f"## 告警\nrule={finding.rule_id}\nmessage={finding.message}\n"
            f"位置={finding.file_path}:{finding.location.start_line if finding.location else '?'}",
            "## 代码上下文\n```python\n%s\n```" % (ctx.get("text") or "(无)"),
            "## 可达路由\n" + ("\n".join(routes) if routes else "(无)"),
        ]
        if prev_analysis:
            lines.append("## 上一轮分析（标记可能在此丢失）\n" + prev_analysis)
        if source_inject:
            lines.append("## 指示\n污点标记经传递总是被清洗。请在构造 test_input 的同时说明"
                         "如何在 source 读取点直接注入带 __TAINT_ 标记的 TaintedString 兜底。")
        lines.append("请给出你的 JSON。")
        return "\n\n".join(lines)

    @staticmethod
    def _fallback_poc(finding: Finding, source_inject: bool) -> dict[str, str]:
        """LLM 不可用时的确定性兜底（不虚构细节）。"""
        return {
            "analysis": "LLM 不可用，无法生成针对性 PoC；需人工构造。",
            "test_input": "",
            "source_inject": source_inject,
        }
