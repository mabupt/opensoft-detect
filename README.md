# OpenSoft Detect

基于 **静态分析 + RAG 上下文富化 + LLM 误报研判 + 动态验证** 的 Python 项目安全漏洞检测系统。

对任意 Python 工程做端到端检测：文件过滤 → 多引擎静态发现 → 切片/路由/CWE 富化 →
LLM 误报研判（含知识库闭环）→ **容器内动态实证**（双轨污点检测 + 路线级 DAST）→
JSON/HTML 报告（四级置信度、CWE-ATT&CK 关联、修复 Diff）。

> 实测（人工靶场 pygoat，通用代码无特判）：静态 320 条 · LLM 研判 TP 305 / FP 17 ·
> **动态 confirmed 14**（含 3 条 DAST 独立发现）/ retry_poc 6。

## 系统架构（6 大模块）

```
main.py  ── 主控流程（CLI 解析 + 流水线调度）
│
├─ modules/preprocess          模块0  文件遍历与过滤 → file_manifest.json
├─ modules/static_analysis     模块1  Semgrep / CodeQL / pip-audit → findings.json
├─ modules/context_enrichment  模块2  AST 路由/参数提取 + 代码切片 + Qdrant 检索 → enriched_findings.json
├─ modules/llm_analysis        模块3  大模型误报研判 + 漏洞特征闭环(存取 Qdrant) → verified_findings.json
├─ modules/dynamic_verification 模块4  Import Hook 三层补丁 + 双轨检测 + Docker 沙箱 → dynamic_findings.json
└─ modules/reporting           模块5  JSON/HTML 报告（CWE-ATT&CK、置信度分级、修复 Diff、分引擎误报率）
```

产物统一写入 `output/`：`file_manifest.json` → `findings.json` → `enriched_findings.json`
→ `verified_findings.json` → `dynamic_findings.json` → `final_report.json` / `final_report.html`。

## 环境

| 项 | 值 |
|---|---|
| Python | 3.11+（**任意解释器**：代码无写死路径，缺依赖时逐级降级；开发环境见 `rag_env/`） |
| CodeQL | `codeql/codeql-bundle-win64/codeql/codeql.exe`（离线套件，仓库不含，需自行下载到该路径） |
| Qdrant | 容器 `opensoft_qdrant`（6333），集合 `security_knowledge`（384 维 bge 模型，缓存于 `models/fastembed_cache`） |
| Docker | 动态验证必需（不可用时自动降级为纯静态结论） |
| 依赖 | `pip install -r requirements.txt` + `semgrep` / `pip-audit` |

### 环境变量（LLM，可选；未配置时模块3 自动降级，静态结论独立成立）

```bash
export OPENSOFT_LLM_PROVIDER=openai                       # 或 anthropic
export OPENSOFT_LLM_API_BASE=https://api.example.com/v1    # OpenAI 兼容网关
export OPENSOFT_LLM_MODEL=<model-name>
export OPENAI_API_KEY=<your-key>                           # 切勿提交/写入产物
```

## 快速开始

```bash
# 缺省：0→4 静态链路 + 报告（不跑容器探针）
python main.py --target <项目路径>

# 含动态验证（容器探针；被测工程以副本挂载，不会改动宿主源码）
python main.py --target <项目路径> --attempt-dynamic

# 一键基准：全流程 + 归档 output/bench/<name>/ + 摘要
python scripts/bench.py --target <项目路径> --name <归档名> --attempt-dynamic

# 其它常用开关
--fix-suggest              为动态确认的漏洞生成修复 Diff（LLM，带事实校验）
--no-dast                  跳过路线级 DAST 扫描（与 Finding 无关、较耗时）
--include-excluded         软排除文件（tests/docs）也纳入扫描
--scan-dirs A B            只扫描指定子目录
--skip-enrich/--skip-llm/--skip-dynamic
```

## 安全与隔离（重要）

- **沙箱副本挂载**：动态探针跑在**被测工程副本**上并以相同容器内路径挂载。原因是动态验证会
  **真实触发**被测代码的漏洞，其中"写文件"类漏洞会覆盖源码（实测事故见
  [docs/HARDENING.md](docs/HARDENING.md) §五）。仓库外目标同理（挂载点 `/target`）。
- **密钥不回写产物**：`output/config_used.json` 对 `api_key` 等字段脱敏。
- 容器有硬超时与统一回收；探针日志流式输出，便于观察进度。

## 评测语料

`test/` 下的靶场（pygoat）与真实项目**不随仓库分发**（第三方版权 + 体积），
已在 `.gitignore` 中排除。复现评测请自行获取：

- pygoat：`https://github.com/adeyosemanputra/pygoat` → 放到 `test/goat/pygoat-master/`
- 真实项目：任意中小型 Python 工程（Flask/Django/FastAPI 有动态支持）

评测语料为第三方内容，未随仓库分发；本地复现时按上述方式获取即可。

## 状态流转

```
NEW → UNDER_REVIEW → TRUE_POSITIVE → DYNAMIC_CONFIRMED → FIX_SUGGESTED
                    ↘ FALSE_POSITIVE / UNVERIFIED
```

## 文档

- [docs/HARDENING.md](docs/HARDENING.md) — 通用性 / 稳定性 / 可靠性加固记录（含降级矩阵与事故复盘）
- [docs/EVAL_real.md](docs/EVAL_real.md) — 真实项目评测报告（chainlit / pyload 人工判读）
- [docs/LLM_OPTIMIZATION.md](docs/LLM_OPTIMIZATION.md) — LLM 研判的工程化设计（缓存 / 路由 / 熔断 / 闭环）
