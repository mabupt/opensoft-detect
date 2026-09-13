# Qdrant RAG 数据库

集合名 `security_knowledge`，本地存储 `./qdrant_storage`，4850 条安全领域知识。

## 数据源

| 来源 | 记录数 |
|---|---|
| CWE v4.20 | 969 |
| ATT&CK Enterprise | 2,216 |
| KEV | 1,665 |

## 模型配置

- Dense: `BAAI/bge-small-en-v1.5`（384维，Cosine）
- Sparse: `Qdrant/bm25`

## 检索方式

1. **精确 ID 匹配**：从 query 中正则提取 `CWE-\d+`、`CVE-\d{4}-\d{4,7}`、`T\d{4}(?:\.\d{2,3})?`，作为 `FieldCondition` 过滤 `cwe_id`/`cve_id`/`attack_id` 字段
2. **混合检索**：无 ID 时走 Dense+Sparse 双路（BM25 作 prefetch，Dense 重排）
3. **融合策略**：有 ID 时先查精确命中，再用语义搜索补充 top_k

## Collection 字段

payload 包含：`cwe_id`、`cve_id`、`attack_id`（三选一或空）+ 描述文本