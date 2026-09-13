# OpenSoft Detect — 能力 / 覆盖现状 与 建议路线图

> 速览一页版见 [REVIEW.md](REVIEW.md)；本文件为能力与路线细节。

> 生成：2026-09-06 · 本文件由会话实测结果汇总，均为真实可复现数据；标"待验证/建议"处为作者判断。
> 目标语料：`test/goat/pygoat-master`（人工设计的 Django 漏洞靶场，作为主基准）；`test/real/chainlit-2.9.3`（真实开源，作对照）；`test/goat/dvpwa-master` 为 PHP，**已排除**。

---

## 一、系统现状（6 模块 0→5 已全打通）

| 模块 | 能力 | 实测状态 |
|---|---|---|
| 0 预处理 | 硬/软排除 + 目录剪枝 → `file_manifest.json`（scan_scope/excluded/stats）；`--include-excluded`、`--scan-dirs` | ✅ 稳定 |
| 1 静态 | Semgrep（本地 5 规则含 taint）+ CodeQL（离线 code-scanning 套件，**建库失败自动回退全量**）+ DepChecker（pip-audit + **OSV 精确 pin 回退**）；跨引擎去重、单引擎降级 | ✅ pygoat 34 条；chainlit 27 条(codeql)；真实工程 codeql 曾建库失败已修复 |
| 2 富化 | AST 路由/参数（Flask/Django/FastAPI）、按工具粒度的函数级切片（上限 100 行/8 步/3000 token）、Qdrant 知识检索 + CWE 预载（969） | ✅ 嵌入模型离线缓存，检索/切片全通过 |
| 3 LLM 研判 | 预过滤（测试文件/docstring/参数化 SQL）、temperature=0+JSON mode+30s+重试3、prompt 版本号、四级置信度分类、KB 闭环(confirmed 写入、>0.85 先验) | ✅ GLM(flash) 真实调用；**无模型级 FP 出现（语料所致，见局限）** |
| 4 动态 | Import Hook 三层补丁（builtins/承载模块/已加载别名，含 PIL.ImageMath）+ 双轨检测（A/B + canary 内容水印）+ Flask test_client & Django RequestFactory 视图直调 + Docker 沙箱与降级 | ✅ 两种应用驱动都容器内实证；pygoat 部分视图 confirmed |
| 5 报告 | 多文件聚合、四级置信度、CWE-ATT&CK 矩阵、误报率口径、修复 Diff（confirmed 且事实校验）、JSON/HTML | ✅ |

## 二、基准结果（pygoat，最后可复现值）

| 指标 | 值 |
|---|---|
| 静态发现（去重） | 34（semgrep 8 + codeql ~code-scanning；pip-audit 见下） |
| 置信度 | **confirmed=4** · high_suspicious=19 · excluded=11 |
| 误报率口径 | TP=23（含 4 confirmed）/ FP=11（预过滤排除）→ 32.35% |
| 动态 confirmed | insec_des(Flask pickle.loads A585/B1) · cmd_lab(views431 os.system A146/B1) · cmd_lab2(views460 eval A4/B2)；a9_lab2(ImageMath)未过图像链路，诚实未标 |
| KB 闭环 | `vuln_features` = 4 条动态确认特征 |
| **依赖漏洞** | **289 条**（Django4.2/Pillow9.4/urllib3/cryptography…）→ `output/dependency_findings.json` |
| 真实项目对照 | chainlit 27 条 codeql；AstrBot/pyload 低信号（见局限） |

产物目录：`output/bench/pygoat/`（final_report.html/json、coverage.md、各阶段 json）、`output/dependency_findings.json`。

## 三、已知局限（如实，不粉饰）

1. **静态覆盖面是"选定类目"，非全量**：只扫 `.py`。XSS/模板注入（多在 HTML `|safe`）、越权/认证逻辑、跨文件复杂数据流，本质检测不到——这不是规则能"写全"的，是检测面问题。
2. **LLM 无模型级误报可判**：goat 全是真漏洞（连 docstring 示例都是真代码），flash 判 18/18、23/23 全 TP；误报目前主要由预过滤兜底（excluded=docstring/测试文件）。要看"LLM 筛 FP 降误报率"必须换带真 FP 的语料。且**仅 glm-4-flash 可用**（air/plus 该 key 余额不足，1113）。
3. **动态依赖"入口驱动"**：只支持自包含 Flask 与 Django 视图直调；`a9_lab2`(Pillow 图像链路)、SQL 类（DB/ORM 查询）尚未在沙箱内跑通；canary/source 注入是**尽力而为的污点兜底，非完整跨函数污点传播**。
4. **依赖审计精度**：OSV 条目常无 CVSS → 默认 medium（故 289 条全 medium，未夸大 severity）；大小写未归一（Django/django 重复计数）；只有"精确 pin 或已装环境"，动态解析的范围外依赖不在列。
5. **工程易用性**：跑新 target 会**覆盖 `output/` 同名文件**（无自动归档）；Qdrant 需 docker 容器运行；key/模型走环境变量；CodeQL 全量回退较慢。

## 四、运行方式速查（供复现）

```bash
# 依赖注入：LLM(智谱，仅 flash 可用；key 用自己的)
export OPENSOFT_LLM_PROVIDER=openai \
       OPENSOFT_LLM_API_BASE=https://open.bigmodel.cn/api/paas/v4 \
       OPENSOFT_LLM_MODEL=glm-4-flash \
       OPENAI_API_KEY=<你的key>
# Qdrant（如未起）docker start opensoft_qdrant
# 全流程：pygoat
python main.py --target test/goat/pygoat-master
# 依赖漏洞单独：python 调用 modules.static_analysis.dep_checker.DepChecker.run(manifest)
# 只看动态：Config(dynamic_attempts=True) 后跑 modules.dynamic_verification.runner.run
# 知识库恢复（如需重建）：python scripts/restore_qdrant_knowledge.py ...
```

## 五、建议路线图（作者按性价比排序，供你取舍）

### P0 — 让"结果可信、可复现、可迭代"（成本低、收益稳）
1. **依赖审计并入模块1/报告**：把 289 条依赖漏洞并入 `findings.json` 与 final_report（新增"依赖漏洞"分组，含包/版本/修复版本），模块3 已对其放行(TRUE_POSITIVE)，一次打通。
2. **运行归档 helper**：写 `scripts/run_bench.py <target> <名称>`，跑完自动把各阶段文件归档到 `output/bench/<名称>/` 并落 coverage——避免覆盖、便于多次对比（现状易互相覆盖）。
3. **回归验证脚本**：把 pygoat 的"关键视图必须命中"断言成可跑测试（cmd_lab/sql_lab/insec_des/a9_lab2/xxe/ssrf…），每次改规则/引擎跑一遍防回退。

### P1 — 深化动态与污点（动态是核心卖点，值得继续投）
4. **Django 视图直调补完**：处理 a9_lab2 的图像链路（POST 带真实图片/FILES）、给 sql_lab 起 sqlite+迁移后再直调、参数名从 urls/表单自动推断——目标把 confirmed 从 4 提到 10+。
5. **污点传播增强**：canary 内容水印已覆盖拼接清洗；再补 bytes/编码链路的传播包装与 `TaintedString.__add__` 保留，减少"仅轨道A"的 retry 比例。

### P2 — 静态广度与评测（成本高，按需做）
6. **HTML/XSS/模板检测**：作为独立 Analyzer（扫 templates `|safe`/JS 事件）补 .py 之外盲区。
7. **真实语料 + 人工/官方标签评测**：用 OWASP DevGuide/GitHub 对 pygoat 路由的漏洞定义做 ground truth（来源标注，绝不臆造），算精确率/召回率；再找一份带真 FP 的真实仓库测"LLM 降误报"。
8. **强模型**：智谱充值开通 air/plus 后复跑，对比 FP 判别力。

## 六.5、最新进展（2026-09-06 晚）与关键诊断

### 已落地
- **P0 全套**：依赖并入报告（pygoat 319 发现=285 依赖+34 代码）；`run_bench.py` 归档；`regression_pygoat.py`（10/10 过）。
- **动态两种模式**：RequestFactory 直调 + **真 HTTP**（同进程 WSGI+会话+免 CSRF+按视图函数定位路由打点，`config.dynamic_http=True` 启用）。
- 轨道B 增强：canary **精确相等 + 递归扫描**（覆盖 ORM 参数化路径），单测通过。
- pygoat HTTP 全量动态（含 AST 读点参数注入后）：`confirmed=8 条 finding`（**5 个唯一漏洞位**：cmd431 / cmd_lab2:460 / insec:36 / a9_lab2:588 / mitre:218），`retry_poc=15`。

### 关键诊断：为什么 confirmed 这么少？—— 链路归因（通用视角，不特化 pygoat）
预期链路：**入口/路由 → 参数名+类型 → LLM 构造 PoC → 执行 → 双轨确认**。逐环节检查：

| 环节 | 现状 | 是否瓶颈 |
|---|---|---|
| ① 入口/路由定位 | 只对 `path('x', views.f)` 直接注册生效；`include()`/跨模块/类视图漏 | 中（次要） |
| ② **参数名+类型解析** | ❌ 探针只发**通配参数包**（name/pass/function/val…），**没有解析每个视图实际读取哪个参数、什么类型** | **主瓶颈之一** |
| ③ **LLM PoC 生成** | ❌ `poc.py`（先 analysis 后 test_input）**存在但 runner 从未真正调用**去产出"精确到参数的 PoC" | **主瓶颈之一** |
| ④ 执行/双轨 | 真 HTTP 已能跑到视图（A 多>0），但 canary 未进 sink 实参 → B=0 | 结果受②③影响 |
| ⑤ 污点/懒执行语义 | canary 相等已补；ORM raw 懒执行等仍需真实迭代 | 次 |

**结论**：问题出在 **② 和 ③**——我们跳过了"把路由+参数+类型喂给 LLM 生成精确 PoC"，改用了"全路由盲发通配 canary"，导致 B 依赖参数名碰巧命中。这就是 confirmed 少、retry_poc 多的根因。

**已实现的通用修复（2026-09-06 晚）**：路由=Django `get_resolver()`/Flask `url_map` 运行时解析（含 include）；参数=A AST 读点扫描（`request.GET/POST.get('k')`）**再加 LLM 规划**：把 code_context+路由+读点喂给 GLM，返回"哪个参数填 canary、哪个是文件字段"（如 mitre code-injection→`{expression:__CAN__}`、weak-hash→`{username,password:__CAN__}`）→ 真 HTTP 打点。无 Key/失败自动回退 AST 通配。全程通用、无三方依赖。

**实测平台期**：加 AST 键后 confirmed 6→8；再叠加 LLM 参数规划后仍 **8/retry15 持平**。原因（如实）：剩余 retry_poc 中不少属**非"污点直达危险调用"的类别**——如 weak-sensitive-data-hashing（canary 经哈希后内容消失，B 按"内容到 sink"口径天然测不到）、clear-text-logging/懒查询等，需要**按漏洞类别定制的断言 oracle**（如"明文 password 变量进入弱算法/日志"），不是参数名/值问题。

## 六、作者的一句话判断
静态已"能用且有对照"，但**真正的差异化与剩余价值在动态实证与依赖审计**——建议资源优先 P0.1+P0.3（把结果做进正式报告并防回退），再上 P1 动态补完。P2 视你目标（论文/产品/内部工具）再定。
