"""从 sqlite 归档重建 Qdrant `security_knowledge` 知识集合。

背景：项目早期 ingest CWE/ATT&CK/KEV（共 4850 条）时，把待上传的
``qdrant_client.PointStruct`` 对象（含 dense+brm25 sparse 向量与 payload）
以 pickle 形式另存进了 ``qdrant_storage/collection/security_knowledge/storage.sqlite``
（自建的 sqlite 备份，并非 Qdrant 服务器目录）。本脚本把这些对象解包后
重新上传到正在运行的 Qdrant 服务，实现知识库无损重建。

用法：:

    rag_env\\Scripts\\python.exe scripts\\restore_qdrant_knowledge.py \
        --sqlite qdrant_storage/collection/security_knowledge/storage.sqlite \
        --host localhost --port 6333 \
        --collection security_knowledge --recreate

说明：
- 默认 ``--recreate``：若集合已存在则先删除再重建（保证无重复）。
- 集合配置固定为：默认无名字 Dense 384 维 Cosine + 命名 sparse ``sparse``，
  与归档中每个点的 vector 结构一致。
- 上传按 128 条一批，全部 wait=True，保证计数即时准确。
"""

from __future__ import annotations

import argparse
import logging
import pickle
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("restore_qdrant_knowledge")

#: 一批上传的点数
_BATCH_SIZE: int = 128


def iter_rows(sqlite_path: Path) -> Iterator[tuple[str, bytes]]:
    """只读逐行产出 (rowid, pickle_blob)。"""
    con = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    try:
        for rid, blob in con.execute("SELECT id, point FROM points"):
            yield str(rid), bytes(blob)
    finally:
        con.close()


def unpickle_point(blob: bytes):
    """把 pickled PointStruct 解包为 qdrant 点对象。

    :param blob: pickle 字节。
    :return: PointStruct（含 .id / .vector / .payload）。
    """
    return pickle.loads(blob)


def ensure_collection(client: Any, collection: str, recreate: bool) -> None:
    """按既定向量配置创建（或重建）集合。

    :param client: qdrant_client 实例。
    :param collection: 集合名。
    :param recreate: 已存在时先删除重建。
    """
    from qdrant_client import models

    exists = client.collection_exists(collection)
    if exists and recreate:
        logger.info("集合 %s 已存在，--recreate 开启：先删除再重建。", collection)
        client.delete_collection(collection)
        exists = False
    if not exists:
        client.create_collection(
            collection_name=collection,
            vectors_config=models.VectorParams(size=384, distance=models.Distance.COSINE),
            sparse_vectors_config={"sparse": models.SparseVectorParams()},
        )
        logger.info("集合 %s 已创建（dense 384/cosine + sparse 'sparse'）。", collection)


def restore(sqlite_path: Path, client: Any, collection: str,
            recreate: bool) -> int:
    """执行解包 + 批量上传。

    :return: 上传点数。
    """
    ensure_collection(client, collection, recreate)
    source_counter: dict[str, int] = {}
    uploaded: int = 0
    batch: list = []

    def _flush() -> None:
        nonlocal uploaded
        client.upsert(collection_name=collection, points=batch, wait=True)
        uploaded += len(batch)
        batch.clear()

    for rowid, blob in iter_rows(sqlite_path):
        try:
            pt = unpickle_point(blob)
        except Exception as exc:  # 单行损坏跳过并计数
            logger.warning("第 %s 行解包失败，已跳过：%s", rowid, exc)
            continue
        src: str = (pt.payload or {}).get("source") or "unknown"
        source_counter[src] = source_counter.get(src, 0) + 1
        batch.append(pt)
        if len(batch) >= _BATCH_SIZE:
            _flush()
    if batch:
        _flush()

    logger.info("上传完成，共 %d 条 | 按来源分布：%s", uploaded, source_counter)
    return uploaded


def main() -> int:
    """CLI 入口。"""
    parser = argparse.ArgumentParser(description="从 sqlite 归档重建 Qdrant 知识集合")
    parser.add_argument("--sqlite", type=Path, required=True,
                        help="归档 sqlite 文件（含 points 表，pickle 列名 point）")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=6333)
    parser.add_argument("--collection", default="security_knowledge")
    parser.add_argument("--recreate", action="store_true", default=True,
                        help="集合已存在时先删除重建（默认开启）")
    parser.add_argument("--no-recreate", dest="recreate", action="store_false")
    parser.set_defaults(recreate=True)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(levelname)s %(name)s | %(message)s")

    if not args.sqlite.is_file():
        logger.error("sqlite 归档不存在：%s", args.sqlite)
        return 1

    # qdrant_client 惰性导入（客户端存在性由安装保证）
    from qdrant_client import QdrantClient

    client = QdrantClient(host=args.host, port=args.port)
    logger.info("连接 Qdrant：%s:%s", args.host, args.port)
    uploaded = restore(args.sqlite, client, args.collection, args.recreate)
    # 最终校验
    info = client.get_collection(args.collection)
    logger.info("集合 points_count = %s（应等于上传数 %d）",
                info.points_count, uploaded)
    return 0 if uploaded else 2


if __name__ == "__main__":
    sys.exit(main())
