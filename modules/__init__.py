"""OpenSoft Detect 功能模块包。

每个子模块对应流水线中的一个阶段，遵循统一约定：
- 子模块内的 ``runner.py`` 暴露顶层编排函数（通常命名为 ``run``），
  供 ``main.py`` 调用并返回本阶段产物的文件路径；
- 阶段之间通过 ``output/`` 下的 JSON 中间产物解耦传递，而非直接 import 调用，
  保证任一阶段都可单独运行 / 跳过 / 断点续跑。

子模块列表：:

    preprocess            模块0 文件遍历与过滤
    static_analysis       模块1 Semgrep / CodeQL / pip-audit
    context_enrichment    模块2 AST 提取 + 代码切片 + Qdrant 检索
    llm_analysis          模块3 大模型误报研判 + 特征闭环
    dynamic_verification  模块4 Import Hook + 双轨检测 + Docker 沙箱
    reporting             模块5 JSON / HTML 报告
"""
