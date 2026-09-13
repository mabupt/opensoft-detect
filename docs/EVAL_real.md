# 真实项目评测报告

对人工靶场（pygoat）之外的**真实开源工程**做检出与精度评测。靶场语料多为真漏洞（缺乏误报样本），
故选取有实际告警输出的真实仓库做人工判读。

## 一、chainlit-2.9.3（服务端库）

```
CodeQL 27 条（Semgrep 0；该工程无依赖清单）
预过滤丢弃 10（docstring 3 + backend/tests 6 + 1）
LLM 研判 17 条 → 初版全部 true_positive
```

### 人工判读（逐条核对真实代码，保留项 18 条）

| 规则 | 位置 | 人工判定 | 依据 |
|---|---|---|---|
| `py/path-injection` | `server.py:267/272/273/285/290/291/303/308/309` | FP | 均先 `(base/filename).resolve()` 再经 `is_path_inside(file, base)` 守卫；CodeQL 不识别自定义消毒函数 |
| `py/path-injection` | `markdown.py:45/54` | FP | 同上，有 `is_path_inside` 守卫 |
| `py/path-injection` | `config.py:467/474` | FP | 路径来自配置而非请求 + 守卫 |
| `py/path-injection` | `_utils.py:8` | FP | 告警落在**守卫函数自身**上（规则误报） |
| `py/cookie-injection` | `auth/cookie.py:132/144` | FP | 写入的是服务端生成的 auth token，非用户输入 |
| `py/cookie-injection` | `server.py:769` | **TP** | `body.get("session_id")` 未校验即 `set_cookie` |
| `py/samesite-none-cookie` | `server.py:767` | TP（低） | 非本地场景下 `samesite="none"`，安全属性依赖条件分支 |

**人工口径：TP ≈ 2 / FP ≈ 16，精度约 11%。** 预过滤丢弃的 10 条（docstring/测试文件）判定正确。

### 暴露的问题与通用修复

**问题**：初版 LLM 几乎全判 TP，因为它**看不到跨文件的守卫函数**（切片仅含同文件），无法判断"是否已防护"。

**修复（通用，非针对具体工程）**：
1. **切片器补跨文件被调函数**：`slicer._find_cross_file_func` 按搜索根查找 `def name(`，让
   `is_path_inside` 这类守卫函数进入上下文；
2. **研判提示强调守卫/消毒**：system prompt 要求"先找校验/消毒调用，有有效防护则判 FP"。

**效果**：LLM 判决 `true_positive 17 → 13`，`false_positive 0 → 5`。

### 再叠加确定性守卫后过滤（不依赖 LLM）

切片中出现 `is_path_inside` 等校验/消毒调用且 LLM 判 TP 时，自动降级为 `unverified`（待复核）：

```
守卫命中覆盖 17/27；TP 降级 12 条
最终：true_positive 1 · false_positive 5 · unverified 12
与人工判读（TP≈2/18）量级一致；唯一 high_suspicious 为 server.py:769 cookie 注入，与人工判定吻合
```

即：系统**不再把守卫保护的告警直接当 TP**，而是转人工复核，可信度显著提升。

## 二、pyload（可运行的真实应用）

```
静态 38 条（CodeQL 37 + Semgrep 1）
证据分布：llm_true_positive=3 · needs_review=15 · excluded=20
Top 规则：weak-sensitive-data-hashing 14 · path-injection 8 · stack-trace-exposure 4
          · weak-cryptographic-algorithm 3 · clear-text-storage 2 · sql-fstring-execute 1
```

- **判定为真实**：`py/weak-cryptographic-algorithm` @ `plugins/containers/RSDF.py:50`、
  `plugins/downloaders/MegaCoNz.py:110/120`（弱加密算法，客观可判）。
- `weak-sensitive-data-hashing`（14 条）多为校验和/文件摘要用途而非口令哈希 → 列待复核；
- `path-injection`（8 条）与 chainlit 同理，多半有守卫 → 待复核；
- **动态未参与**：pyload 的 Web 界面基于 bottle/CherryPy，不在当前入口驱动（Flask/Django/FastAPI）
  覆盖范围内——这是动态层的既有框架边界。

## 三、结论

- 管道在真实仓库**确实产出可解释的发现**，并通过通用改进把 LLM 的 FP 识别从 0 提升到 5；
- 暴露出"自定义消毒函数导致静态误报"这一真实痛点，并给出可落地的对策
  （跨文件切片 + 守卫提示 + 确定性后过滤）；
- 当前精度（人工口径约 11%）**不足以直接交付**，必须叠加确定性后过滤与人工复核；
- 报告将**静态 / LLM / 动态**三类证据并列展示（每条 finding 含 `evidence.static/dynamic/llm`，
  统计含 `evidence_sources`）；无 LLM Key 时静态高置信结论仍独立成立（标 `static_only`）。
