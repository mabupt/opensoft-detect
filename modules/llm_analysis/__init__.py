"""模块3：大模型误报研判（llm_analysis）。

职责：对模块2 富化后的 Finding 做 **LLM 误报研判**，并维护
"漏洞特征入库 -> 相似命中复用"的 **Qdrant 闭环**。

- **预过滤**：送 LLM 前用确定性规则滤掉明显误报
  （测试文件 / 注释文档字符串内的代码 / 参数化查询等安全模式）—— prefilter.py；
- **研判**：构造含代码切片 + 路由信息 + CWE 描述 + 历史相似案例的 Prompt，
  要求模型以 **JSON**（verdict/confidence/reason）输出，按可靠性参数
  （temperature=0 / JSON mode / 30s 超时 / 最多重试 3 轮 / prompt 版本号）调用
  —— client.py + fp_judge.py；
- **闭环**：仅把"研判 true_positive 且动态验证 confirmed"的漏洞以
  code_pattern 特征 + SHA-256 hash 去重写入 Qdrant；研判前检索 Top3 相似
  历史确认案例，**相似度 > 0.85** 才作为先验附进 Prompt —— knowledge_base.py。

产物：``output/verified_findings.json`` 与 ``output/prefilter_dropped.json``。
"""
