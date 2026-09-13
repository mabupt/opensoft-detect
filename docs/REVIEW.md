# OpenSoft Detect — 阶段性 Review（一页）

> 2026-09-13 更新 · 主语料 `test/goat/pygoat-master`（人工 Django 靶场）；`dvpwa` 为 PHP 已排除。
> 详细加固/事故记录见 [HARDENING.md](HARDENING.md)，真实评测见 [EVAL_real.md](EVAL_real.md)。
> 权威动态快照：`output/bench/pygoat_dynamic/dynamic_findings.json`。

## 目标
对 Python 项目做：静态发现 → 上下文富化 → LLM 误报研判 → **容器内动态实证** → 报告，
含第三方依赖漏洞与"动态确认"闭环（Qdrant 知识库存取）。

## 已交付（0→5 全通）
| 块 | 状态 |
|---|---|
| 0 预处理 / 1 静态 | ✅ CodeQL(离线套件+建库回退) · Semgrep(5 规则含 taint) · **DepChecker(pip-audit + OSV 精确 pin + dist-info/METADATA 派生)** |
| 2 富化 | ✅ 路由/参数(AST)、按工具粒度切片(100行/8步/3000token)、Qdrant 检索+CWE 预载 |
| 3 LLM | ✅ 预过滤、temp0/JSON/30s/重试3、四级置信度、KB 闭环(confirmed 写入、>0.85 先验)、Few-shot(1.4)、守卫后过滤、模型路由 |
| 4 动态 | ✅ 三层补丁 · 双轨 A/B + canary · Django(真 HTTP)/Flask/FastAPI · 路线级 DAST · **副本隔离沙箱** · Docker 降级链 |
| 5 报告 | ✅ 聚合、四级置信度、CWE-ATT&CK、修复 Diff(confirmed+事实校验)、JSON/HTML |

## 最新实测数字（pygoat，通用代码无特判）
- 静态 **320**（semgrep 8 · codeql 33 · pip_audit 279）
- LLM 研判：TP 305 · FP 17 · **误报率 5.28%**；路由 `dependency_factual` 直判占多数，LLM 调用约 19 次
- 动态：**confirmed 14**（11 code + 3 DAST：`missing-auth@/debug`、`reflected-xss@/xssL`、`@/xssL1`）·
  `retry_poc` 6 · 宿主语料零改动（探针跑在副本上）
- 回归断言 10/10；KB `vuln_features` 13 / `fp_features` 5

## 关键设计决策
1. **路由/参数**：Django 用框架运行时 `get_resolver()`、Flask `url_map`；参数=AST 读点先定键，
   再由 LLM 依据代码上下文判断"哪个参数流到 sink、怎么填"（`_llm_request_params`，失败回退 AST 通配）。
2. **依赖审计**：OSV 精确 pin 为主（无需安装/编译），pip-audit 为辅，均带本地缓存；
   无 requirements 的项目从 `dist-info/METADATA` 派生。
3. **动态用同进程 WSGI + 会话 + 免 CSRF 的真 HTTP**；RequestFactory 用于快速初筛。
4. **沙箱铁律**：探针一律跑在**被测工程副本**上并以相同容器内路径覆盖挂载——因为动态验证会
   真实触发"写文件"类漏洞（pygoat A9/A6 lab 曾把被测源码写成空文件，导致 confirmed 15→2）。

## 诚实边界（未解决）
- `retry_poc` 6 条多为"非污点直达型"（SQL raw 懒执行、clear-text-logging、部分 weak-hash）——
  参数已非瓶颈，需按漏洞类别的断言 oracle 才能动态化。
- 静态盲区：XSS/模板（在 HTML 非 .py）、越权逻辑、跨文件复杂流。
- LLM 仅 glm-4-flash 可用（强模型该 key 余额不足）；修复 Diff 只做格式/行号校验，语义需人工。
- **FastAPI 路径不再深挖**（用户决定）：其 DAST 探针可能跑满超时预算后止损，功能不崩但不快；
  可用 `--no-dast` 关闭。
- 历史 `output/bench/chainlit|pyload|pypi_upload_demo` 里的 dynamic 产物是 pygoat 残留
  （旧归档未校验归属），已加 `INVALID_ARCHIVE.txt` 标注，勿引用。

## 运行入口
- **一键基准（推荐）**：`python scripts/bench.py --target test/goat/pygoat-master --name pygoat --attempt-dynamic`
- 全流程：`python main.py --target <path> [--attempt-dynamic] [--no-dast] [--fix-suggest]`
- 回归：`python scripts/regression_pygoat.py output/findings.json`
- 知识库恢复：`python scripts/restore_qdrant_knowledge.py`
