"""模块5：报告生成（reporting）。

职责：汇总全流程 Finding 生成可读/可审计的最终交付物：

- **CWE-ATT&CK 关联**：把每条 Finding 的 CWE 映射到对应 ATT&CK 攻击技术，
  支撑安全团队把"代码缺陷"翻译为"可利用的攻击路径"；
- **置信度分级**：按 ConfidenceLevel 分桶汇总展示；
- **修复 Diff**：--fix-suggest 开启时把 LLM 生成的修复补丁嵌入报告；
- **误报率统计**：结合研判结论（人工/LLM/动态）计算误报率与有效告警占比。

产物：
- ``output/reports/report.json`` —— 机器可读全量报告
- ``output/reports/report.html`` —— 人读的 HTML 报告（含修复 Diff、统计图表）

子模块拆分：::

    enrichment.py     CWE <-> ATT&CK 映射与关联计算
    stats.py          统计：置信度分布 / 误报率 / 严重程度分布
    json_reporter.py  JSON 报告写出
    html_reporter.py  HTML 报告渲染（Jinja2 模板）
    report.py         报告数据组装（把 findings+stats+映射 合成 report 结构）
    runner.py         本模块编排入口
"""
