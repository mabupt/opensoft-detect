# 真实项目评测（P2）— chainlit-2.9.3

> 目的：验证"在真实代码上是否真能检出、精度如何"。goat 语料全是真漏洞（无 FP），
> real 中 pyload/AstrBot 又近乎无信号，故选用**已有 CodeQL 命中的 chainlit** 做人工判读。

## 一、管道产出（bench: output/bench/chainlit/）
```
CodeQL 27 条（Semgrep 0，依赖审计无清单）
预过滤丢弃 10（docstring 3 + backend/tests 6 + 1）
LLM 研判 17 条 → 全 true_positive（初版）
报告：high_suspicious=17 / excluded=10，误报率 37%（口径=预过滤排除）
```

## 二、人工判读（逐条读真实代码，共 18 条保留项）

| # | 规则 | 位置 | 人工判定 | 依据 |
|---|---|---|---|---|
| 1-9 | py/path-injection | `server.py:267/272/273/285/290/291/303/308/309` | **FP** | 每个都先 `(base/filename).resolve()` 再 `is_path_inside(file,base)` 守卫；CodeQL 不识别自定义消毒函数 |
| 4,5 | py/path-injection | `markdown.py:45/54` | **FP** | 同样有 `is_path_inside` 守卫 |
| 2,3 | py/path-injection | `config.py:467/474` | **FP** | 路径来自配置(非请求) + 守卫 |
| 1 | py/path-injection | `_utils.py:8` | **FP** | 告警落在**守卫函数本身**上（规则误报） |
| 15,16 | py/cookie-injection | `auth/cookie.py:132/144` | **FP** | 写入的是**服务端生成**的 auth token，非用户输入 |
| 17 | py/cookie-injection | `server.py:769` | **TP** | `body.get("session_id")` 未校验即 `set_cookie`（cookie 注入） |
| 18 | py/samesite-none-cookie | `server.py:767` | **TP(低)** | 非本地时 `samesite="none"`，安全属性依赖条件分支 |

**人工统计：TP≈2 / FP≈16 → 真实精度约 11%。** 预过滤丢的 10 条（docstring/测试）判定**正确**。

## 三、发现的问题与已做的通用修复

**问题**：LLM 初版把 17 条几乎全判 TP——因为它**看不到跨文件的守卫函数**（切片只含同文件），
无法判断"是否已防护"。

**修复（通用，非特化）**：
1. **切片器补跨文件被调函数**（`slicer._find_cross_file_func`，按 `search_roots` 搜索 `def name(`），
   让 `is_path_inside` 这类守卫进入上下文；
2. **研判提示强调守卫/消毒**（fp_judge system prompt 增加"先找校验/消毒调用，有有效防护判 FP"）。

**效果（同一 chainlit）**：
```
LLM 判决：true_positive 17 → 13，false_positive 0 → 5
报告：high_suspicious 17→13，excluded 10→14
```
方向正确，但仍有 11 条被守卫保护的 path-injection 被判 TP（LLM 未完全利用守卫）。

**再叠加确定性守卫后过滤（不依赖 LLM）**：切片里出现 `is_path_inside` 等校验/消毒调用且 LLM 判 TP 时，
自动降级为 `unverified`（待复核）。chainlit 实测：
```
守卫命中覆盖 17/27；TP 降级 12 条
最终：true_positive 1 · false_positive 5 · unverified 12
报告：high_suspicious=1 · possible=12 · excluded=14
```
即：系统**不再把守卫保护的告警当 TP**——与人工判读（TP≈2/18）量级一致，可信度大幅提升。
（唯一 high_suspicious 是 `server.py:769` cookie 注入，与人工判定一致。）

## 四、结论与下一步（能真正提精度的）
1. **确定性后过滤（高性价比）**：切片中出现"对该输入的包含性/消毒调用"（如 `is_path_inside`、
   `sanitize*`、`escape*`、`validate*`）时，自动降级为需要复核（不直接给 TP）——不依赖 LLM 稳定性；
2. **来源区分**：把"值来源"（服务端生成 token vs 请求输入）纳入上下文，避免 cookie.py 类 FP；
3. **规则/查询取舍**：py/path-injection 在"自定义消毒"上系统性 FP，可在报告中对这类规则标注并优先人工；
4. **动态侧**：chainlit 是**服务端库**、非可直接跑的应用，动态未参与本次评测；下一步应选**可运行的真实应用**
   （候选：pyload 的 Web 界面）跑 DAST/动态，测"独立发现"的精度。

## 四.5、真实应用 pyload 评测（可运行的真实工程）

```
静态 38 条（CodeQL 37 + Semgrep 1）
报告：high_suspicious=3 · possible=15 · excluded=20
evidence_sources：llm_true_positive=3 · needs_review=15 · excluded=20
Top 规则：weak-sensitive-data-hashing 14 · path-injection 8 · stack-trace-exposure 4
          · weak-cryptographic-algorithm 3 · clear-text-storage 2 · sql-fstring-execute 1
```
- 判定为真实（LLM）：`py/weak-cryptographic-algorithm` @ `plugins/containers/RSDF.py:50`、
  `plugins/downloaders/MegaCoNz.py:110/120`（弱加密算法，客观可判）。
- `weak-sensitive-data-hashing`（14）多为**校验和/文件摘要**用途，非口令哈希 → 需人工复核（列 possible）。
- `path-injection`（8）与 chainlit 同理，多半有守卫 → 待复核。
- **动态未参与**：pyload Web UI 非 Flask/Django（bottle/CherryPy 系），我们现有入口驱动/DAST 不覆盖
  —— 这是当前动态层的**框架边界**（下一步：支持 bottle/CherryPy 或"用项目自身启动命令起服"的通用方案）。

**结论**：报告现在把 **静态 / LLM / 动态** 三类证据并列展示（每条 finding 有 `evidence.static/dynamic/llm`，
统计里有 `evidence_sources`）；无 LLM Key 时静态 high 结论仍独立成立（标 `static_only`）。

## 五、价值判断（如实）
- ✅ 管道在真实仓库**确实产出可解释的发现**，且我们通过**通用改进**把 LLM 的 FP 识别从 0 提到 5；
- ✅ 暴露出"自定义消毒函数导致静态 FP"这一真实痛点，并给出可落地对策；
- ⚠️ 当前精度（人工口径 ~11%）**不足以直接交付**，必须接确定性后过滤 + 人工复核；
- ⚠️ 动态能力尚未在真实可运行应用上验证（下一步 pyload）。
