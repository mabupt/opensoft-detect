"""模块2 编排入口（runner）。

对模块1 产出的每个 Finding 做上下文富化，产出 ``output/enriched_findings.json``。

富化内容（可单条降级，不互相拖累）：
1. **代码切片**：按工具粒度提取函数体上下文（写入 metadata.code_context）；
2. **路由信息**：提取命中文件暴露的路由（Flask/FastAPI/Django），判断外部可达性
   （写入 finding.related_routes 与 metadata.route_summary）；
3. **CWE 描述**：启动时从 Qdrant 预载 CWE 描述映射，逐条补充
   （写入 metadata.cwe_descriptions）；
4. **向量知识支撑**：把切片向量化后在 security_knowledge 检索相似 CWE/ATT&CK/KEV
   条目（写入 metadata.vector_hits）。

Qdrant 不可达时步骤 3/4 整体降级（打一次 warning），切片与路由仍正常产出。
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import Config
from models import Finding, RouteInfo
from modules.context_enrichment.ast_extractor import RouteExtractor
from modules.context_enrichment.slicer import build_context_for_finding
from modules.context_enrichment.vector_store import QdrantVectorStore

logger = logging.getLogger("opensoft_detect.context_enrichment")


def run(findings_path: Path, manifest_path: Path, config: Config) -> Path:
    """执行模块2上下文富化。

    :param findings_path: 模块1 产出的 findings.json 路径。
    :param manifest_path: 模块0 清单路径（当前阶段仅用于解析目标根，可空传）。
    :param config: 全局配置。
    :return: enriched_findings.json 绝对路径。
    """
    findings: list[Finding] = _load_findings(findings_path)
    logger.info("载入 %d 条 Finding 开始富化。", len(findings))

    # ---- 准备 Qdrant（失败则整体降级，不影响切片/路由）----
    store: Optional[QdrantVectorStore] = None
    cwe_map: dict[str, str] = {}
    try:
        store = QdrantVectorStore(config.qdrant)
        store.ensure_collection(config.qdrant.collection_name, sparse=True)
        cwe_map = store.get_cwe_map()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Qdrant 不可用，本阶段跳过向量检索与 CWE 描述：%s", exc)

    # 路由提取器按文件缓存，避免重复解析
    route_extractor = RouteExtractor()
    route_cache: dict[str, list[RouteInfo]] = {}

    enriched: list[Finding] = []
    vector_ok: bool = store is not None   # 向量检索可用性（嵌入失败后整体降级，不再逐条报错）
    roots: list[Path] = [config.target] if config.target else []
    for finding in findings:
        finding.metadata.setdefault("enrichment", {})
        _enrich_code_context(finding, search_roots=roots)
        _enrich_routes(finding, route_extractor, route_cache)
        if store is not None:
            _enrich_cwe(finding, cwe_map)
            if vector_ok:
                try:
                    _enrich_vector_hits(finding, store, config)
                except Exception as exc:  # noqa: BLE001
                    vector_ok = False
                    logger.warning("向量检索整体降级（后续 Finding 跳过）：%s", exc)
                if store._embed_failed:
                    vector_ok = False
        enriched.append(finding)

    out_path: Path = config.paths.default_enriched_path
    payload: dict[str, Any] = {
        "version": "1.1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": str(findings_path),
        "total": len(enriched),
        "findings": [f.to_dict() for f in enriched],
    }
    out_path.write_text(
        __import__("json").dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("富化完成并写入：%s（%d 条）", out_path, len(enriched))
    return out_path


# ---------------------------------------------------------------------------
# 单条富化步骤
# ---------------------------------------------------------------------------

def _enrich_code_context(finding: Finding,
                         search_roots: Optional[list[Path]] = None) -> None:
    """代码切片：按工具粒度提取函数体上下文（含跨文件守卫/被调函数）。"""
    ctx = build_context_for_finding(finding, search_roots=search_roots)
    finding.metadata["code_context"] = ctx.to_dict()
    if ctx.steps == 0 and finding.location:
        logger.debug("Finding %s 未能切片（命中不在函数内或文件缺失）", finding.id)


def _enrich_routes(finding: Finding,
                   route_extractor: RouteExtractor,
                   cache: dict[str, list[RouteInfo]]) -> None:
    """路由信息：提取命中文件暴露的路由并写入 related_routes / route_summary。"""
    if not finding.file_path:
        return
    path = Path(finding.file_path)
    if path not in cache:
        try:
            cache[path] = route_extractor.extract_from_file(path) if path.is_file() else []
        except Exception as exc:  # noqa: BLE001
            logger.warning("路由提取失败 %s：%s", path, exc)
            cache[path] = []
    routes: list[RouteInfo] = cache[path]
    finding.related_routes = routes
    finding.metadata["route_summary"] = [
        f"{'|'.join(r.http_methods)} {r.path} -> {r.handler_function}"
        for r in routes
    ]


def _enrich_cwe(finding: Finding, cwe_map: dict[str, str]) -> None:
    """把命中 CWE 的描述文本补进 metadata（供 LLM prompt 使用）。"""
    descs: dict[str, str] = {}
    for cid in finding.cwe_ids:
        if cid in cwe_map:
            descs[cid] = cwe_map[cid]
    if descs:
        finding.metadata["cwe_descriptions"] = descs


def _enrich_vector_hits(finding: Finding, store: QdrantVectorStore, config: Config) -> None:
    """把切片/描述向量化后在知识库检索相似条目写入 metadata.vector_hits。"""
    code_text: str = (finding.metadata.get("code_context") or {}).get("text") or ""
    query: str = code_text[:800] or finding.message
    if not query.strip():
        finding.metadata["vector_hits"] = []
        return
    try:
        hits = store.search_text(query, top_k=config.qdrant.top_k)
        # 精简 payload，避免冗余塞爆 JSON
        slim = [{"score": round(h["score"], 4),
                 "source": h["payload"].get("source"),
                 "id": (h["payload"].get("source_id")
                        or h["payload"].get("cwe_id")
                        or h["payload"].get("attack_id")
                        or h["payload"].get("cve_id")),
                 "name": (h["payload"].get("name") or "")[:120]}
                for h in hits]
        finding.metadata["vector_hits"] = slim
    except Exception as exc:  # noqa: BLE001 - 单项检索失败降级为空
        logger.debug("Finding %s 向量检索失败：%s", finding.id, exc)
        finding.metadata["vector_hits"] = []
        finding.metadata.setdefault("qdrant_error", str(exc))


# ---------------------------------------------------------------------------
# 读取辅助
# ---------------------------------------------------------------------------

def _load_findings(path: Path) -> list[Finding]:
    """宽容读取任一阶段的发现文件（支持我们的 wrapper 结构或裸列表）。

    :param path: JSON 文件路径。
    :return: Finding 列表。
    """
    import json
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.get("findings") if isinstance(raw, dict) else raw
    items = items or []
    return [Finding.from_dict(x) for x in items if isinstance(x, dict)]
