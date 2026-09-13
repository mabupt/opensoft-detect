# LLM 应用优化清单（亮点模块）

> 2026-09-12 · 本轮已落地 4 项（均有单测），另列后续高价值项与预期收益。

## 一、本轮已实现（已验证）

| # | 优化 | 价值 | 验证 |
|---|---|---|---|
| 1 | **判定缓存**：按 `provider/model/system/user` 哈希缓存 JSON 结果（`output/.cache/llm_*.json`，TTL 30 天） | 重跑/回归**不重复烧额度**、结果可复现、迭代快 | 同 prompt 调两次 → 只调 API 1 次，结果一致 |
| 2 | **FP 案例闭环**：判定为误报也写入 `fp_features` 集合；研判前同时检索 TP/FP 先验，Prompt 标注"历史确认漏洞/历史判定误报" | 直接**抑制重复误报**（比只存 TP 有效） | 存入 FP 后 `search_prior` 返回 `kind='fp'`，Prompt 文案正确 |
| 3 | **确定性强消毒过滤**：命中行出现 `secure_filename/shlex.quote/html.escape/literal_eval/is_relative_to/commonpath/is_path_inside` → 预过滤直接判已防护 | **少调一次 LLM**，且不受模型波动影响 | snippet 含 `secure_filename` → 被丢弃 |
| 4 | **结构化自检输出**：要求模型先给 `fp_factors`（列误报理由）再给 verdict；结果入库 `metadata.llm.fp_factors` | 推理可审计，便于人工复核与调参 | Prompt 已含该字段要求 |

## 二、已有能力（本轮之前）

预过滤（测试文件/注释文档串/参数化查询）、**守卫后过滤**（切片出现校验/消毒调用即降级待复核）、
`# prompt_v` 版本号、temperature=0 / JSON mode / 30s 超时 / 重试 3 轮、
KB 先验相似度阈值 0.85、依赖漏洞事实性放行（不调 LLM）。

## 二.5、本轮新增（2026-09-12 夜）

| 项 | 内容 | 验证 |
|---|---|---|
| **Few-shot 双例** | `fp_judge.FEW_SHOT_EXAMPLES`（真 TP 命令注入 + 真守卫 FP `is_path_inside`），prompt 版本 → **1.4**；`use_few_shot=False` 可关（供 A/B） | 导入检查通过 |
| **模型路由** | ①依赖漏洞 ②**规则明确类（weak-hash）→ 直判不调 LLM** ③其余送 LLM；④可选升级模型复核 uncertain（env `OPENSOFT_LLM_ESCALATION_MODEL`） | pyload 实测：**12 条策略直判**、0 LLM 调用；routing 统计写入产物 `llm_routing` |
| **端点熔断** | LLM 连续失败 ≥3 次 → **放弃本轮剩余调用**（标记 `llm_endpoint_down`），避免"重试×条目数"放大耗时 | 指向不可达端点实测：3 次后中断，全程 39.5s 结束（不再拖） |
| **Prompt A/B 脚本** | `scripts/prompt_ab.py`（chainlit 18 条人工标签；baseline vs few_shot；带实时进度） | 脚本就绪；**因智谱端点当前 read timeout 未跑完**，端点恢复后可直接重跑（有缓存，重复项不烧额度） |

## 三、建议的后续优化（按性价比）

1. **Few-shot 双例**：在 system prompt 放 1 个真实 TP 例（pygoat 命令注入）+ 1 个真实守卫 FP 例（chainlit is_path_inside）
   —— 成本≈0，预期显著提升守卫识别一致性。
2. **一致性投票（2 视角）**：同切片分别以"攻击者视角/修复者视角"两次调判，结论不一致 → 标"待复核"。
   成本 2×，换取更稳的 FP 抑制；可与缓存配合（两视角各自缓存）。
3. **模型路由**：规则明确类（weak_hash 策略、DAST 命中）**直接判定不调 LLM**；仅"含糊"条目送 LLM；
   预算允许时再用"flash 初审 → 强模型仅复核 uncertain/TP"分级调用。
4. **Prompt A/B 评测脚本**：用 chainlit（已人工判读 18 条）+ pygoat（10 个关键视图）作小评测集，
   对比不同 `prompt_v` 的 TP/FP/待复核分布 → 让优化有客观依据。
5. **人工反馈回灌**：报告里对 high_suspicious/待复核提供标注（TP/FP），经 `VulnerabilityKB.apply_review`
   写回 TP/FP 集合 —— 形成真正的"越用越准"。
6. **成本与并发工程**：每轮设 token 预算上限；findings 批量并发 N（注意限流）；超长切片再压（只留 sink 行±N 与守卫函数）。
7. **上下文压缩**：当前切片已含跨文件守卫；可进一步"按需注入"（先给摘要，模型请求再展开某函数），降 token。

## 四、一句话判断
现在的 LLM 用法是"**确定性优先、LLM 兜底**"：能确定判的（预过滤/守卫/策略/缓存）都不烧模型；
模型只处理含糊项，且**FP 也能进闭环**。上面 1/3/4 三项加起来成本很低，是下一步最划算的增强。
