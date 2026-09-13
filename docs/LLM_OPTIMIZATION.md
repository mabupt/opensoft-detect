# LLM 研判的工程化设计

模块3 的取费原则是"**确定性优先，LLM 兜底**"：凡是能确定性判定的（预过滤、守卫识别、策略 oracle、
缓存命中）都不调用模型；模型只处理含糊项，且**误报样本同样进入闭环**。以下为各项设计与其验证方式。

## 一、核心机制

| 机制 | 实现 | 价值 | 验证 |
|---|---|---|---|
| **判定缓存** | 按 `provider/model/system/user` 哈希缓存 JSON 结果（`output/.cache/llm_*.json`，TTL 30 天） | 重跑/回归不重复消耗额度，结果可复现 | 同 prompt 调两次 → 仅 1 次真实 API 调用，结果一致 |
| **误报闭环** | 判为误报的样本写入 `fp_features` 集合；研判前同时检索 TP/FP 先验，并在 Prompt 中标注"历史确认漏洞/历史判定误报" | 直接抑制重复误报（比只存 TP 更有效） | 存入 FP 后 `search_prior` 返回 `kind='fp'`，Prompt 文案正确 |
| **确定性强消毒过滤** | 命中行出现 `secure_filename` / `shlex.quote` / `html.escape` / `literal_eval` / `is_relative_to` / `commonpath` / `is_path_inside` → 预过滤直接判已防护 | 少一次模型调用，且不受模型波动影响 | snippet 含 `secure_filename` → 被丢弃 |
| **结构化自检输出** | 要求模型先给出 `fp_factors`（误报理由列表）再给 verdict；结果入库 `metadata.llm.fp_factors` | 推理过程可审计，便于人工复核与调参 | Prompt 已含该字段要求 |
| **Few-shot 双例** | `fp_judge.FEW_SHOT_EXAMPLES`：1 个真实 TP（命令注入）+ 1 个真实守卫误报（`is_path_inside`），prompt 版本 `1.4`；`use_few_shot=False` 可关闭以做 A/B | 提升守卫识别的一致性 | 关闭开关可对比两变体 |
| **模型路由** | ①依赖漏洞事实性放行；②规则明确类（如 weak-hash 策略）直判；③其余送模型；④可选升级模型复核 uncertain（环境变量 `OPENSOFT_LLM_ESCALATION_MODEL`） | 把调用量压到最低 | pyload 实测：12 条策略直判、0 次模型调用；统计写入产物 `llm_routing` |
| **端点熔断** | 连续失败 ≥3 次即放弃剩余调用并标记 `llm_endpoint_down` | 避免"重试 × 条目数"放大耗时 | 指向不可达端点实测：3 次后中断，全程 39.5s 结束 |

## 二、基础能力

预过滤（测试文件 / 注释与文档字符串 / 参数化查询）、**守卫后过滤**（切片出现校验或消毒调用即降级待复核）、
`# prompt_v` 版本标记、`temperature=0`、JSON mode、30s 超时、最多 3 轮重试、
知识库先验相似度阈值 0.85、依赖漏洞事实性放行（不调用模型）。

## 三、评测脚本

`scripts/prompt_ab.py`：以 chainlit 的 18 条人工标签为评测集，对比 baseline 与 few-shot 两个变体的
TP/FP 分布，带实时进度；由于结果缓存，重复条目不会重复消耗额度。

## 四、已知限制与后续方向

1. **一致性投票**：同一片段以"攻击者视角/修复者视角"两次研判，结论不一致则标待复核（成本 2×，
   可与缓存配合）。
2. **人工反馈回灌**：报告中标注 TP/FP 后写回 TP/FP 集合，形成"越用越准"的闭环；该接口目前尚未接入。
3. **成本与并发控制**：设置每轮 token 预算上限；批量研判并发化（需注意限流）。
4. **上下文压缩**：切片在"跨文件守卫"基础上进一步"按需注入"（先给摘要，模型请求时再展开某函数）。
