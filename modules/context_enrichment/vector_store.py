"""Qdrant 向量库封装（QdrantVectorStore）。

模块2/3 共用的 Qdrant 客户端封装，能力分两类：

1. **安全知识检索（模块2 使用）**
   - :meth:`get_cwe_map`：启动时一次性预载全部 CWE 描述到内存字典（后续直接查）；
   - :meth:`search_text`：对代码切片文本向量化后在 ``security_knowledge`` 检索
     相似 CWE/ATT&CK/KEV 条目。

2. **漏洞知识库读写（模块3 闭环使用）**
   - :meth:`ensure_collection`：按需建集合；
   - :meth:`upsert_point`：按 point_id 写入（同一 id 天然去重覆盖）；
   - :meth:`search_vectors`：向量检索并返回 score 过滤后的命中。

向量化默认 fastembed（``BAAI/bge-small-en-v1.5`` 384 维），惰性加载；
可通过构造参数注入自定义 embedder。Qdrant 不可达时各方法抛出明确异常，
由调用方（runner）降级处理。
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Callable, Optional

from config import QdrantConfig

logger = logging.getLogger("opensoft_detect.context_enrichment.vector_store")

#: 文本向量化函数类型：text -> 向量
Embedder = Callable[[str], list[float]]

#: 嵌入模型加载（可能触发 HuggingFace 下载）的超时守护上限（秒）
EMBED_LOAD_TIMEOUT: int = 60

#: payload 中倾向文本化的字段（构建 CWE 描述时按序拼接；跳过超长列表）
_CWE_TEXT_FIELDS: tuple[str, ...] = (
    "name", "description", "abstraction", "likelihood_of_exploit",
)


class QdrantVectorStore:
    """Qdrant 集合操作封装（知识检索 + 特征存取共用）。"""

    def __init__(
        self,
        qdrant_cfg: QdrantConfig,
        embedder: Optional[Embedder] = None,
        collection: Optional[str] = None,
    ) -> None:
        """构造向量库客户端。

        :param qdrant_cfg: Qdrant 连接与模型配置。
        :param embedder: 注入的向量化函数；None 时惰性加载 fastembed。
        :param collection: 默认集合名；None 取 qdrant_cfg.collection_name。
        """
        self.cfg: QdrantConfig = qdrant_cfg
        self.embedder: Optional[Embedder] = embedder
        self.collection: str = collection or qdrant_cfg.collection_name
        self._client: Any = None
        self._embed_model: Any = None
        self._cwe_map: Optional[dict[str, str]] = None
        # 嵌入模型加载守护状态（后台线程加载，失败熔断，避免卡死主流程）
        self._embed_lock: threading.Lock = threading.Lock()
        self._embed_loaded: bool = False
        self._embed_failed: Optional[str] = None

    # ------------------------------------------------------------------
    # 连接与集合
    # ------------------------------------------------------------------
    @property
    def client(self) -> Any:
        """惰性创建并缓存 QdrantClient。

        :return: qdrant_client 实例。
        :raises RuntimeError: 连接失败（服务未启动）。
        """
        if self._client is None:
            try:
                from qdrant_client import QdrantClient
                self._client = QdrantClient(host=self.cfg.host, port=self.cfg.port)
                # 触发一次轻量请求，尽早暴露连接问题
                self._client.get_collections()
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError(f"Qdrant 连接失败 {self.cfg.host}:{self.cfg.port}: {exc}") from exc
        return self._client

    def ensure_collection(self, name: str, dim: int | None = None,
                          sparse: bool = False) -> None:
        """确保集合存在；缺失时按配置创建。

        知识主集合 ``security_knowledge`` 用 dense(384)+sparse('sparse')；
        知识库特征集合只用 dense 即可。

        :param name: 集合名。
        :param dim: dense 维度；None 取配置。
        :param sparse: 是否同时建命名 sparse 向量 'sparse'。
        """
        from qdrant_client import models

        dim = dim or self.cfg.embedding_dim
        client = self.client
        if client.collection_exists(name):
            return
        kwargs: dict[str, Any] = {
            "collection_name": name,
            "vectors_config": models.VectorParams(size=dim, distance=models.Distance.COSINE),
        }
        if sparse:
            kwargs["sparse_vectors_config"] = {"sparse": models.SparseVectorParams()}
        client.create_collection(**kwargs)
        logger.info("Qdrant 集合 %s 已创建（dim=%d, sparse=%s）", name, dim, sparse)

    # ------------------------------------------------------------------
    # 向量化（惰性 fastembed）
    # ------------------------------------------------------------------
    def embed_text(self, text: str) -> list[float]:
        """把文本转为 dense 向量。

        模型加载在后台线程进行并带超时守护：首次加载可能触发 HuggingFace 下载，
        若在 ``EMBED_LOAD_TIMEOUT`` 内未就绪则**熔断**并抛出 RuntimeError
        （调用方降级跳过向量化），后续调用立即失败，避免阻塞整条流水线。

        :param text: 输入文本。
        :return: 向量列表。
        :raises RuntimeError: 模型加载失败/超时或向量化失败。
        """
        if self.embedder is not None:
            return self.embedder(text)
        self._ensure_embed_model()
        if self._embed_model is None:
            raise RuntimeError(self._embed_failed or "嵌入模型不可用")
        try:
            vec = next(self._embed_model.embed([text[:2000]]))  # 限制长度防异常
            return [float(x) for x in vec]
        except Exception as exc:  # noqa: BLE001
            msg = f"向量化失败：{exc}"
            self._embed_failed = self._embed_failed or msg
            raise RuntimeError(msg) from exc

    # ---- 后台加载 + 超时熔断 ----
    def _ensure_embed_model(self) -> None:
        """确保嵌入模型已加载（后台线程，带超时）。

        结果三态：已加载(_embed_loaded=True) / 加载失败(_embed_failed 置值) /
        仍在加载：等待至 EMBED_LOAD_TIMEOUT 后熔断。
        """
        if self._embed_loaded or self._embed_failed:
            return
        with self._embed_lock:
            if self._embed_loaded or self._embed_failed:
                return
            if self._embed_model is None:
                threading.Thread(target=self._load_model_bg, daemon=True).start()
        # 等待加载完成 / 失败，最多 EMBED_LOAD_TIMEOUT 秒
        waited: float = 0.0
        while not self._embed_loaded and self._embed_failed is None:
            if waited >= EMBED_LOAD_TIMEOUT:
                self._embed_failed = (
                    f"嵌入模型加载超时（>{EMBED_LOAD_TIMEOUT}s，可能需联网下载 "
                    f"{self.cfg.embedding_model}）")
                logger.warning("嵌入模型加载超时，已熔断：%s", self.cfg.embedding_model)
                return
            import time
            time.sleep(1.0)
            waited += 1.0

    def _load_model_bg(self) -> None:
        """后台线程：真正加载 fastembed 模型。

        使用项目内持久缓存目录（cfg.embedding_cache_dir），模型已缓存时完全离线、
        秒级加载；未缓存且网络可达时才触发下载（可通过 ``HF_ENDPOINT`` 指定镜像）。
        """
        try:
            cache_dir = Path(self.cfg.embedding_cache_dir)
            cache_dir.mkdir(parents=True, exist_ok=True)
            from fastembed import TextEmbedding
            model = TextEmbedding(model_name=self.cfg.embedding_model,
                                  cache_dir=str(cache_dir))
            self._embed_model = model
            self._embed_loaded = True
            logger.info("嵌入模型加载完成：%s（cache=%s）", self.cfg.embedding_model, cache_dir)
        except Exception as exc:  # noqa: BLE001
            self._embed_failed = f"嵌入模型加载失败（{self.cfg.embedding_model}）：{exc}"
            # 向量检索是**可选增强**（缺 fastembed/模型即停用，流程继续），故不按 ERROR 报，
            # 否则换了 Python 环境后正常降级会被误读成故障。
            logger.warning("嵌入模型不可用，本轮跳过向量检索（%s）：%s",
                           self.cfg.embedding_model, exc)

    # ------------------------------------------------------------------
    # CWE 描述预载（模块2 启动时调用一次）
    # ------------------------------------------------------------------
    def get_cwe_map(self, force: bool = False) -> dict[str, str]:
        """返回 {CWE 编号: 描述文本} 映射（带进程内缓存）。

        通过过滤 scroll 一次性拉取全部 CWE 条目并缓存。

        :param force: 强制重载缓存。
        :return: CWE -> 描述。
        """
        if self._cwe_map is not None and not force:
            return self._cwe_map
        from qdrant_client import models
        cwe_map: dict[str, str] = {}
        try:
            client = self.client
            flt = models.Filter(must=[
                models.FieldCondition(key="source", match=models.MatchValue(value="CWE"))])
            pts = client.scroll(
                collection_name=self.collection,
                scroll_filter=flt, limit=2000, with_vectors=False,
            )[0]
            for p in pts:
                cid = (p.payload or {}).get("cwe_id")
                if cid:
                    cwe_map[cid] = _payload_to_text(p.payload or {})
        except Exception as exc:  # noqa: BLE001
            logger.warning("CWE 描述预载失败（将退化为空映射）：%s", exc)
        self._cwe_map = cwe_map
        logger.info("CWE 描述预载完成：%d 条", len(cwe_map))
        return cwe_map

    # ------------------------------------------------------------------
    # 知识检索（模块2）
    # ------------------------------------------------------------------
    def search_text(self, text: str, top_k: int | None = None,
                    min_score: float | None = None,
                    collection: str | None = None) -> list[dict[str, Any]]:
        """向量化文本后在知识集合检索相似条目。

        :param text: 查询文本（代码切片/描述）。
        :param top_k: 返回条数；None 取配置 top_k。
        :param min_score: 相似度阈值；低于则丢弃（None 用配置阈值）。
        :param collection: 目标集合；None 用默认知识集合。
        :return: [{"score": float, "payload": {...}}, ...]（按 score 降序）。
        """
        k = top_k or self.cfg.top_k
        thr: float = self.cfg.similarity_threshold if min_score is None else min_score
        vec = self.embed_text(text)
        res = self.client.query_points(
            collection_name=collection or self.collection,
            query=vec, limit=k * 3, with_payload=True,
        )
        hits: list[dict[str, Any]] = []
        for h in res.points:
            if h.score is not None and h.score >= thr:
                hits.append({"score": float(h.score), "payload": dict(h.payload or {})})
            if len(hits) >= k:
                break
        return hits

    # ------------------------------------------------------------------
    # 知识库（漏洞特征）读写原语（模块3）
    # ------------------------------------------------------------------
    def upsert_point(self, collection: str, point_id: str,
                     vector: list[float], payload: dict[str, Any]) -> str:
        """写入/覆盖一个向量点（point_id 相同即覆盖 = 去重）。

        :param collection: 目标集合。
        :param point_id: 点 ID（应使用 code_pattern 的 hash）。
        :param vector: dense 向量。
        :param payload: 附带元数据。
        :return: point_id。
        """
        from qdrant_client import models
        self.ensure_collection(collection, sparse=False)
        self.client.upsert(
            collection_name=collection,
            points=[models.PointStruct(id=point_id, vector=vector, payload=payload)],
            wait=True,
        )
        return point_id

    def search_vectors(self, collection: str, vector: list[float],
                       top_k: int = 3, min_score: float | None = None) -> list[dict[str, Any]]:
        """在指定集合中做 dense 检索，score 低于阈值（默认 0.85）的丢弃。

        :param collection: 目标集合。
        :param vector: 查询向量。
        :param top_k: 返回条数上限。
        :param min_score: 相似度阈值；None 用 0.85。
        :return: [{"score","payload"}...]（score 降序）。
        """
        thr: float = 0.85 if min_score is None else min_score
        res = self.client.query_points(
            collection_name=collection, query=vector, limit=top_k * 3, with_payload=True)
        out: list[dict[str, Any]] = []
        for h in res.points:
            if h.score is not None and h.score >= thr:
                out.append({"score": float(h.score), "payload": dict(h.payload or {})})
            if len(out) >= top_k:
                break
        return out

    def count_by_source(self, source: str) -> int:
        """统计指定 source 的条目数（验证/调试用）。

        :param source: source 值（CWE/ATTACK/KEV）。
        :return: 数量。
        """
        from qdrant_client import models
        return self.client.count(
            collection_name=self.collection,
            count_filter=models.Filter(must=[
                models.FieldCondition(key="source", match=models.MatchValue(value=source))]),
        ).count


def _payload_to_text(payload: dict[str, Any], max_len: int = 400) -> str:
    """把一条知识 payload 压成简短文本（name + 可用文本字段，截断）。

    :param payload: 点 payload。
    :param max_len: 结果最大长度。
    :return: 文本。
    """
    parts: list[str] = []
    for key in _CWE_TEXT_FIELDS:
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val.strip())
        elif isinstance(val, list) and key == "description":
            joined = " ".join(str(v) for v in val[:3])
            if joined:
                parts.append(joined[:200])
    text = " | ".join(dict.fromkeys(parts))  # 保序去重
    return text[:max_len]
