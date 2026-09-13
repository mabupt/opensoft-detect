"""模块1：静态分析（static_analysis）。

职责：集成 **Semgrep**、**CodeQL** 与 **DepChecker(pip-audit)** 三类静态工具，
把它们异构的输出（SARIF / JSON）归一化为统一的
:class:`models.Finding` 列表，跨引擎去重后写出 ``output/findings.json``。

范围控制：三个引擎都基于模块0 产出的 file_manifest.json 的 ``scan_scope``
限定扫描对象（Semgrep 以 scan_scope 文件为显式目标；CodeQL 用自动生成的
codeql-config.yml 的 paths/paths-ignore；DepChecker 从 excluded 记录反查
依赖清单）。任一引擎缺失/失败时降级运行，不影响其它引擎。

子模块拆分：:

    base.py             分析器抽象基类（AnalyzerBase：is_available/run/post_process）
    parsers.py          工具输出 -> Finding 的归一化解析器 + 子进程执行工具
    semgrep_runner.py   Semgrep 集成（批量执行防参数超长）
    codeql_runner.py    CodeQL 集成（建库 -> 查询 -> SARIF 解析）
    dep_checker.py      DepChecker（pip-audit 依赖漏洞）
    orchestrator.py     调度多工具、失败隔离、合并去重并落盘
    runner.py           本模块编排入口
"""
