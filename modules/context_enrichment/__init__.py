"""模块2：上下文富化（context_enrichment）。

职责：为模块1 的每个 Finding 补足 LLM 误报研判（模块3）所需的上下文：

- 用 Python 原生 ast 提取 **路由/参数**（Flask / Django / FastAPI），
  判断告警是否外部可达 —— RouteExtractor / ParamExtractor；
- **代码切片**：按 Finding 来源工具给粒度（CodeQL=数据流各步所在函数体；
  Semgrep=目标函数+直接调用者），并强制 单函数<=100行 / 数据流<=8步 /
  总上下文<=3000 token 的上限 —— CodeSlicer；
- **Qdrant 客户端封装**：启动时预载 CWE 描述、知识检索（security_knowledge）、
  以及模块3 漏洞知识库的读写原语 —— QdrantVectorStore。

产物：``output/enriched_findings.json``（每个 Finding 的 metadata 增加
code_context / route_summary / cwe_descriptions / vector_hits）。

子模块拆分：::

    ast_extractor.py   RouteExtractor / ParamExtractor（ast 层面路由参数提取）
    slicer.py          CodeSlicer（函数级切片 + 粒度/上限约束）
    vector_store.py    QdrantVectorStore（CWE 预载 + 知识检索 + KB 读写原语）
    runner.py          本模块编排入口
"""
