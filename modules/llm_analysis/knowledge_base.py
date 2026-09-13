"""漏洞知识库闭环（knowledge_base）。

把"动态验证已确认"的漏洞沉淀为向量特征，并在 LLM 研判时检索最相似的**历史确认案例**
作参考，实现"越用越准"的闭环：

- **写入（仅在严格条件下）**：Finding 的研判为 true_positive 且动态验证
  ``metadata.test_status == "confirmed"``。特征 = :meth:`code_pattern`
  （sink 行 + 数据流签名），point id 用 code_pattern 的 **SHA-256 hash**，
  相同模式重复写入即覆盖（天然去重）。
- **检索**：研判前检索 Top3 相似确认案例，**相似度 > 0.85** 才被采纳进 Prompt
  （阈值常量 KB_SIMILARITY_THRESHOLD = 0.85）。
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import QdrantConfig
from models import Finding, VulnerabilityStatus
from modules.context_enrichment.vector_store import QdrantVectorStore

logger = logging.getLogger("opensoft_detect.llm_analysis.kb")

#: 检索相似历史确认案例的采纳阈值（高于此值才附进 Prompt）
KB_SIMILARITY_THRESHOLD: float = 0.85
#: 采纳的相似案例上限（Top-K）
KB_TOP_K: int = 3


class VulnerabilityKB:
    """基于 Qdrant 的漏洞/误报特征闭环存储。"""

    def __init__(self, qdrant_cfg: QdrantConfig,
                 vector_store: Optional[QdrantVectorStore] = None) -> None:
        """构造特征知识库。

        :param qdrant_cfg: Qdrant 配置。
        :param vector_store: 可注入向量库；None 内部自建。
        """
        self.qdrant_cfg: QdrantConfig = qdrant_cfg
        self.store: QdrantVectorStore = vector_store or QdrantVectorStore(qdrant_cfg)
        self.feature_collection: str = qdrant_cfg.vuln_feature_collection

    # ------------------------------------------------------------------
    def ensure_collection(self) -> None:
        """确保特征集合存在（dense 384）。"""
        self.store.ensure_collection(self.feature_collection, sparse=False)

    # ------------------------------------------------------------------
    # 特征构造
    # ------------------------------------------------------------------
    def code_pattern(self, finding: Finding) -> str:
        """从 Finding 提取可复现的 code_pattern（sink 行 + 数据流签名）。

        :param finding: 目标 Finding。
        :return: 规范化模式字符串。
        """
        sink_sig: str = self._sink_signature(finding)
        flow_sig: str = self._flow_signature(finding)
        cwes: str = ",".join(sorted(finding.cwe_ids)) or "-"
        return f"{finding.tool.value}|{finding.rule_id}|cwe:{cwes}|sink:{sink_sig}|flow:{flow_sig}"

    def _sink_signature(self, finding: Finding) -> str:
        """从 snippet/源码行提取 sink 行签名（去空白归一化）。"""
        snippet: str = (finding.location.snippet if finding.location else "") or ""
        if not snippet and finding.location and finding.file_path:
            try:
                lines = Path(finding.file_path).read_text(
                    encoding="utf-8", errors="replace").splitlines()
                ln = finding.location.start_line
                if 1 <= ln <= len(lines):
                    snippet = lines[ln - 1]
            except OSError:
                pass
        for line in snippet.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                # 归一化：压缩空白，保留首个括号调用片段
                s = " ".join(s.split())
                return s[:120]
        return (snippet.strip() or finding.message)[:120]

    def _flow_signature(self, finding: Finding) -> str:
        """从 taint_flow 中提取数据流签名（变量链，最多 8 个）。"""
        names: list[str] = []
        for step in finding.taint_flow[:8]:
            if step.variable:
                names.append(step.variable)
        return "->".join(names) or "-"

    # ------------------------------------------------------------------
    # 检索历史确认案例
    # ------------------------------------------------------------------
    def search_prior(self, finding: Finding,
                     top_k: int = KB_TOP_K) -> list[dict[str, Any]]:
        """检索最相似的历史案例（**含已确认漏洞 TP 与已判误报 FP**，>0.85 才返回）。

        同时查两个集合：``vuln_features``（历史 TP）与 ``fp_features``（历史 FP）。
        payload 里带 ``verdict``，供 Prompt 区分为"相似确认真漏洞"或"相似误报案例"，
        后者对抑制重复误报尤其有效。

        :param finding: 待研判 Finding。
        :param top_k: 每个集合返回条数上限。
        :return: [{"score","payload","kind"}]；无命中/向量库不可用时为空。
        """
        hits: list[dict[str, Any]] = []
        try:
            vector = self.store.embed_text(self._embed_text(finding))
            for coll, kind in ((self.feature_collection, "vuln"),
                               (self.qdrant_cfg.fp_feature_collection, "fp")):
                try:
                    got = self.store.search_vectors(
                        coll, vector, top_k=top_k, min_score=KB_SIMILARITY_THRESHOLD)
                except Exception:  # noqa: BLE001 - 集合不存在等，忽略该路
                    got = []
                for h in got:
                    h["kind"] = kind
                hits.extend(got)
        except Exception as exc:  # noqa: BLE001
            logger.warning("历史案例检索失败（忽略，不阻塞研判）：%s", exc)
            return []
        hits.sort(key=lambda x: x.get("score", 0.0), reverse=True)
        return hits[:top_k * 2]

    def _embed_text(self, finding: Finding) -> str:
        """向量化的文本：模式 + 规则名/消息摘要（更利于相似召回）。"""
        msg = (finding.rule_name or finding.message or "")[:200]
        return f"{self.code_pattern(finding)} {msg}"

    @staticmethod
    def prior_to_prompt(hits: list[dict[str, Any]]) -> str:
        """把检索到的历史案例转成 Prompt 参考文本（区分 TP / FP 先验）。

        :param hits: search_prior 结果。
        :return: 提示文本（无命中返回空串）。
        """
        if not hits:
            return ""
        lines: list[str] = ["以下是历史相似案例（供参考，注意区分真漏洞与已验证误报）："]
        for i, h in enumerate(hits, start=1):
            p = h["payload"]
            label = "历史确认漏洞" if h.get("kind") != "fp" else "历史判定误报"
            lines.append(
                f"案例{i}[{label}] (score={h['score']:.2f}) rule={p.get('rule_id')} "
                f"cwe={p.get('cwe_ids')} verdict={p.get('verdict')} "
                f"pattern={p.get('code_pattern', '')[:160]}")
        return "\n".join(lines)

    def store_fp(self, finding: Finding) -> Optional[str]:
        """把"已判误报"的案例写入 FP 集合（供后续相似告警参考，抑制重复 FP）。

        :param finding: 状态为 FALSE_POSITIVE 的 Finding。
        :return: 写入的 point_id；条件不满足返回 None。
        """
        if finding.status != VulnerabilityStatus.FALSE_POSITIVE:
            return None
        pattern = self.code_pattern(finding)
        # 加 verdict 前缀，避免与同 pattern 的 TP 点冲突
        digest = hashlib.sha256(("fp|" + pattern).encode()).hexdigest()
        point_id = str(uuid.UUID(digest[:32]))
        try:
            vector = self.store.embed_text(self._embed_text(finding))
            payload: dict[str, Any] = {
                "finding_id": finding.id, "rule_id": finding.rule_id,
                "cwe_ids": list(finding.cwe_ids), "verdict": "false_positive",
                "code_pattern": pattern, "source_file": finding.file_path,
                "reason": finding.llm_verdict_reason[:200],
                "stored_at": datetime.now().isoformat(timespec="seconds"),
            }
            self.store.upsert_point(self.qdrant_cfg.fp_feature_collection, point_id, vector, payload)
            logger.info("已把误报案例写入 FP 集合：%s（rule=%s）", point_id, finding.rule_id)
            return point_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("误报案例写入失败：%s", exc)
            return None

    def store_adjudicated(self, finding: Finding) -> Optional[str]:
        """按当前判定结果入库：FP → 误报集合；TP 需动态确认才入漏洞集合。

        :param finding: 已研判 Finding。
        :return: point_id 或 None。
        """
        if finding.status == VulnerabilityStatus.FALSE_POSITIVE:
            return self.store_fp(finding)
        return self.store_confirmed(finding)

    # ------------------------------------------------------------------
    # 写入确认案例
    # ------------------------------------------------------------------
    def store_confirmed(self, finding: Finding) -> Optional[str]:
        """把"动态验证已确认"的漏洞存入特征库。

        仅当：verdict 为 true_positive（TRUE_POSITIVE / DYNAMIC_CONFIRMED）
        且 ``metadata.test_status == "confirmed"``。point id = code_pattern 的 hash，
        重复写入同 id 即覆盖。

        :param finding: 已确认的 Finding。
        :return: 写入的 point_id；条件不满足返回 None。
        """
        if finding.status not in (VulnerabilityStatus.TRUE_POSITIVE,
                                  VulnerabilityStatus.DYNAMIC_CONFIRMED):
            return None
        if str((finding.metadata or {}).get("test_status", "")).lower() != "confirmed":
            return None

        pattern: str = self.code_pattern(finding)
        # Qdrant 只接受整数或 UUID point id：取 sha256 前 32 位十六进制格式化为 UUID，
        # 相同 code_pattern 稳定得到同一 id => 去重覆盖
        digest: str = hashlib.sha256(pattern.encode("utf-8")).hexdigest()
        point_id: str = str(uuid.UUID(digest[:32]))
        try:
            vector: list[float] = self.store.embed_text(self._embed_text(finding))
            payload: dict[str, Any] = {
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "cwe_ids": list(finding.cwe_ids),
                "verdict": finding.status.value,
                "test_status": "confirmed",
                "code_pattern": pattern,
                "source_file": finding.file_path,
                "sink_line": finding.location.start_line if finding.location else 0,
                "stored_at": datetime.now().isoformat(timespec="seconds"),
            }
            self.store.upsert_point(self.feature_collection, point_id, vector, payload)
            logger.info("已把确认案例写入特征库：%s（rule=%s）", point_id, finding.rule_id)
            return point_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("确认案例写入失败：%s", exc)
            return None
