# OpenSoft Detect — 项目概览

## 项目定位

安全漏洞检测实验项目。已有 CodeQL + RAG 向量数据库（Qdrant）+ 测试集/靶场，用于检测 Python 项目中的安全漏洞。

## 目录结构

```
opensoft_detect/
├── codeql/                     CodeQL 工具链（Windows bundle，~4 万文件）
│   └── codeql-bundle-win64/    官方发布包，内含 codeql.exe、各语言 extractor 和 qlpacks
├── qdrant_storage/             Qdrant 本地向量数据库
│   ├── meta.json               集合元信息（collection: security_knowledge, 384维, Cosine）
│   ├── collection/             向量数据
│   └── .lock
├── qdrant.md                   Qdrant RAG 数据库文档
├── rag_env/                    Python venv（~8 千文件），fastembed + qdrant_client 等依赖
├── test/                       测试集
│   ├── real/                   真实 Python 项目（作为检测目标）
│   │   ├── AstrBot-3.5.12/     外层 + AstrBot-3.5.12/ 内层（同名嵌套）
│   │   ├── chainlit-2.9.3/     外层 + chainlit-2.9.3/ 内层（同名嵌套）
│   │   └── pyload/             含 pyload/ 和 pyload_ng-*.dist-info/ 两项
│   └── goat/                   靶场（故意含有漏洞的训练目标）
│       ├── dvpwa-master/       外层 + dvpwa-master/ 内层
│       └── pygoat-master/      外层 + pygoat-master/ 内层
```

## 关键信息速查

| 项 | 值 |
|---|---|
| RAG 集合名 | `security_knowledge` |
| Dense 模型 | `BAAI/bge-small-en-v1.5`（384维） |
| Sparse 模型 | `Qdrant/bm25` |
| 数据源 | CWE v4.20 (969) + ATT&CK Enterprise (2216) + KEV (1665) = 4850 条 |
| Python 依赖 | qdrant_client, fastembed, onnxruntime, numpy |

## 环境约束

- 无 .git，无 .gitignore
- Windows 环境（codeql 是 win64 bundle）
- 所有测试项目都存在外层目录 + 内层同名源码目录的嵌套