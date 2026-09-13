# 工程加固记录：通用性 / 稳定性 / 可靠性

本文记录系统在通用性、稳定性、可靠性上的加固措施与已验证结论，含已修复缺陷的归因分析
（事故复盘保留原始技术细节，便于后续回归时对照）。

## 一、已修复缺陷

| # | 问题（风险） | 修复 |
|---|---|---|
| 1 | **容器泄漏**：探针执行/镜像供给在异常与提交失败路径不回收容器 | 统一 `try/finally` + `kill/remove(force=True)`（[sandbox.py](../modules/dynamic_verification/sandbox.py)、[provision.py](../modules/dynamic_verification/provision.py)） |
| 2 | **重型工程硬等**（超大依赖树逐条安装 >20 min） | **止损闸**：声明依赖 > `dynamic_provision_max_deps(80)` 直接跳过；构建超 `dynamic_provision_timeout(420s)` 自动 kill 并退回基础镜像 |
| 3 | **包装类破坏框架导入**（如 `subprocess.Popen` 被子类化时崩溃） | 承载表里**类只补 `__init__`**、保留类身份；originals 只登记非类可调用 |
| 4 | **缺包桩早于框架导入**（框架依赖被伪造成占位对象，类基异常） | 探针改为**先导入真实框架，再安装缺包桩** |
| 5 | `compile` 包装干扰模块导入期 | 从 `BUILTIN_SINKS` 移除 `compile`（保留 `eval`/`exec`/`open`） |
| 6 | 中断时打印堆栈、退出码不清晰 | 捕获 `KeyboardInterrupt` → 退出码 **130** |
| 7 | 旧 pin 依赖无法解析、计数随网络波动 | DepChecker 双通道（pip-audit → **OSV 精确 pin**）+ **本地内容哈希缓存**（TTL 7 天）；实测二次审计 162s→50s 且计数一致 |
| 8 | CodeQL 每次重跑建库（最慢一步） | DB 缓存：按 `target + scan_scope` 哈希复用；`codeql_cleanup_db=False` 默认保留 |
| 9 | 无 `py` launcher 时 CodeQL 建库失败 | 注入 `CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME`；并加"带 codescanning-config 失败 → 全量建库"回退 |

## 二、可靠性与降级保证

- **引擎互不影响**：Semgrep / CodeQL / DepChecker 任一失败只记入 `engine_results` 并继续；动态失败回退静态结论。
- **依赖来源通用**：`requirements*.txt` → `pyproject.toml` / `setup.py`（editable，失败则解析 PEP 621 / poetry 依赖逐条容错）
  → 已打包应用的 `*.dist-info/METADATA`（`Requires-Dist` 派生）。
- **LLM 可选**：无 Key 或调用失败时，静态结论独立成立（`static_only` 进入 high_suspicious），不静默丢弃。
- **外部服务可选**：Qdrant 不可达跳过向量检索；Docker 不可达则动态整体降级并记录 `skip_reason`；
  缺少 `jinja2` 时仅输出 JSON 报告，不中断流程。
- **有界行为**：所有子进程与网络调用均有超时；供给与探针有硬上限；重型工程按规则立即止损。
- **可复现**：中间产物与报告全部落 `output/`，`scripts/bench.py` 一键执行 + 归档 + 回归断言。

## 三、通用性矩阵

| 能力 | 支持范围 | 备注 |
|---|---|---|
| 静态分析（.py） | 任意 Python 工程 | CodeQL + Semgrep，规则见 `rules/semgrep/` |
| 依赖审计 | requirements / pyproject / dist-info | OSV 精确 pin + 本地缓存 |
| 动态 sink 探针 | **Flask / Django / FastAPI** | 五类 sink + 策略型（weak_hash） |
| 路线级 DAST | **Django**（缺鉴权 / 反射 XSS / 缺 CSRF）· **FastAPI**（反射 XSS） | 不依赖静态发现，独立产出 Finding |
| 沙箱供给 | requirements / pyproject / setup.py | 过重即止损；镜像按内容哈希缓存 |
| 解释器 | **任意 Python 3.11+** | 代码无写死解释器路径（详见 §六） |
| 暂不支持 | bottle / CherryPy 等小众框架、IDOR / 越权、存储型 XSS | 按需立项 |

## 四、残留风险（如实记录）

1. **canary / 策略判据是"尽力而为的污点分析"**，非完整跨函数污点；B 轨未命中 ≠ 无漏洞（标 `retry_poc` / 待复核）。
2. **守卫后过滤可能误降真阳性**——但只降级为"待复核"，不丢证据（`guard_postfilter` 记录在案）。
3. **OSV 缓存 TTL 7 天**：期间新增 CVE 不会更新（可删 `output/.cache/` 强制刷新）。
4. **重型工程被设计性跳过**；如需支持需上调阈值并接受长构建时间。
5. 真实项目精度仍受静态规则与模型判别力限制（见 [EVAL_real.md](EVAL_real.md)）。

## 五、事故复盘：探针写坏被测源码（confirmed 15 → 2）

**现象**：一轮动态验证后，Django 系候选全部 `app_unreachable` / `retry_poc`，confirmed 从 15 跌至 2。

**根因**：动态验证会**真实触发**被测代码的漏洞，而 pygoat 的 A9/A6 lab 本身就是"把提交内容写入源文件"的
漏洞（`apis.py` 把 `log_code` 写入 `playground/A9/main.py`、把 `code` 写入 `playground/A6/utility.py`）。
探针 POST 后**宿主源码被覆盖成载荷或空串** → `introduction.apis` 导入失败 → Django urlconf 仅剩 7 条路由、
回调退化为占位对象 → 所有 Django 路由返回 500 → 全部拿不到 B 轨证据。

**修复（通用，非特化）**：
1. **沙箱副本隔离**：`run_script(..., protect=[target])` 先把被测工程复制到 `output/sandbox/protect_<hash>/`，
   再以**相同容器内路径覆盖挂载**——探针的一切写入只落副本。实测副本内 `A9/main.py`、`A6/utility.py`
   被写成 0 字节，宿主文件保持完好；
2. **缺包桩 `_Any` 的全位置兼容**：作为基类时 `__mro_entries__` 返回**空元组**（返回 `object` 会引发 MRO 冲突）；
   `__instancecheck__` / `__subclasscheck__` 返回 True；继承 `BaseException`（支持 `except <missing>.Err`）；
   `__module__` / `__name__` 必须为 `str`（Django `lookup_str` 会做字符串拼接）；
3. **桩让位于迟到的 finder**：部分库（如 `six.moves`）在导入时才把 finder 追加到 `meta_path` 尾部；
   不让位会把 `urllib3` / `requests` 的惰性属性伪造成占位对象（曾导致 16 条 `app_unreachable`）；
4. **`from X import Y` 缺属性兜底**：`install_import_fallback()` 为已导入的真实模块补 PEP 562 `__getattr__` 并重试
   （IMPORT_FROM 阶段抛错不经过 `__import__`，只能这样兜底）；
5. **归档不再串名**：`run_bench.archive()` 只归档 `mtime >= 本次开始` 的产物并写 `STALE.txt`；
   对历史串名目录加 `INVALID_ARCHIVE.txt` 标注。

**修复后实测**：静态 320 → 动态 **confirmed 14**（11 code + 3 DAST）、`retry_poc` 6、宿主语料零改动。

## 六、换项目 / 换解释器的通用性复查

以"换成别的项目会怎样"为标准逐项验证，发现并修复 5 处**只在换环境时才暴露**的问题：

| # | 问题（换环境即踩） | 修复 |
|---|---|---|
| 1 | **容器内路径约定三方不一致**：探针按宿主绝对路径查找、sandbox 只挂 `/workspace`、provision 挂 `/proj` | 统一为 `container_root_for()`：仓库内 `/workspace/<rel>`、仓库外 `/target`，三处共用 |
| 2 | **仓库外目标无隔离**：`relative_to` 抛错被 `except: continue` 吞掉 → 探针直写用户真实工程 | 仓库外同样做副本并挂到 `/target`；副本创建失败**直接放弃该次探针** |
| 3 | **超大工程复制代价高** | 文件数 > `MAX_COPY_FILES(20000)` 时改用**只读挂载** |
| 4 | **已打包应用依赖审计恒为 0**：wheel 解包目录无 requirements，依赖仅在 `*.dist-info/METADATA` | `DepChecker._derive_from_metadata()` 抽取为 requirements 文本后复用原审计通道 |
| 5 | **缺 `jinja2` 会中断整个流程**：`reporting/runner.py` 无保护地构造 `HtmlReporter` | HTML 降级为"只出 JSON + 告警"，日志标注`（未生成）`；嵌入模型缺失由 ERROR 改 WARNING（可选能力不报故障） |

**解释器可移植性**：产品代码中**没有写死的解释器路径**——CodeQL 建库注入用 `sys.executable`
（自动跟随当前解释器）、容器内 pip 用 `sys.executable`、外部引擎（semgrep / pip-audit / codeql）走 PATH。

**验证（四种形态）**：
- **仓库外项目**（靶场副本置于仓库外目录）：Django 探针 `/cmd_lab` 200、`track_b=1`、7.2s，宿主语料零改动；
- **非靶场的真实 FastAPI 项目**：全流程 exit 0，依赖审计由 0 条变为命中 `CVE-2023-36464`；
- **0 候选目标**：动态阶段 30 秒内优雅空跑（无异常、无浪费），报告正常产出；
- **全新零依赖解释器**（`python -m venv` 空环境，第三方包 0 个）：全流程 **exit 0**，逐级降级且日志清晰
  —— Semgrep / CodeQL / pip-audit 走 PATH 照常工作，Qdrant 与 fastembed 缺失跳过向量检索，
  无 LLM Key 走 `static_only`，无 docker 模块动态降级，无 jinja2 仅输出 JSON 报告。

## 七、密钥与产物卫生

- **配置快照脱敏**：`ConfigLoader.dump()` 内置 `_redact()`，`api_key` / `token` / `secret` / `password`
  等字段一律写为 `***已配置（已脱敏）***`。配置快照会落到 `output/`，可能随报告一起分享，
  明文回写会导致凭证泄露；
- **运行时密钥只走环境变量**（`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`），不写入任何文件或产物；
- **仓库卫生**：`.gitignore` 排除 `output/`（产物）、`codeql/`（离线套件）、`rag_env/`（虚拟环境）、
  `qdrant_storage/`、`models/`（嵌入缓存）、`test/`（第三方语料）与工具本地配置。

## 八、快速自检

```bash
# 编译
python -m compileall -q main.py config.py modules scripts
# 冒烟：模块导入 + static_only 分级 + 守卫检测 + 缺包桩 + 策略 oracle
#      + dist-info 依赖解析 + 入口探测
```
