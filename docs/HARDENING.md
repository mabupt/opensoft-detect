# 通用性 / 稳定性 / 可靠性 加固报告

> 2026-09-12 · 本轮只做代码级审查与快速回归（不跑重型流程），全部改动已编译+冒烟通过。

## 一、本轮发现并修复的问题

| # | 问题（风险） | 修复 |
|---|---|---|
| 1 | **容器泄漏**：`run_script/供给构建`（原 run_python 死代码已移除） 在异常/提交失败路径不回收容器 | 统一 `try/finally` + `kill/remove(force=True)`（[sandbox.py](modules/dynamic_verification/sandbox.py)、[provision.py](modules/dynamic_verification/provision.py)） |
| 2 | **重型工程硬等**（chainlit 逐条装数百依赖 >20min） | 新增**止损闸**：声明依赖 > `dynamic_provision_max_deps(80)` 直接跳过；构建超 `dynamic_provision_timeout(420s)` 自动 kill 并退回基础镜像 |
| 3 | **包装类破坏框架导入**（`subprocess.Popen` 被子类化 → starlette/fastapi 导入崩） | 承载表里**类只补 `__init__`**、保留类身份；originals 只登记非类可调用 |
| 4 | **缺包桩早于框架导入**：框架依赖被伪造成 `_Any`，类基异常 | FastAPI 探针改为**先导入真实框架，再装缺包桩** |
| 5 | `compile` 包装干扰模块导入期 | 从 `BUILTIN_SINKS` 移除 `compile`（保留 eval/exec/open） |
| 6 | 用户中断打印堆栈、退出码不清晰 | `main` 捕获 `KeyboardInterrupt` → 退出码 **130** |
| 7 | 旧 pin 依赖无法解析 / 计数随网络波动 | DepChecker 双通道（pip-audit → **OSV 精确 pin**）+ **本地缓存**（OSV/pip-audit，按内容哈希，TTL 7 天）；实测二次审计 162s→50s，计数一致 |
| 8 | CodeQL 每次重跑建库（最慢一步） | DB 缓存：按 `target+scan_scope` 哈希复用；`codeql_cleanup_db=False` 默认保留 |
| 9 | Windows 无 `py` launcher 导致 CodeQL 建库失败 | 注入 `CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME`；并加"带 codescanning-config 失败 → 全量建库"回退 |

## 二、可靠性与降级保证（现状）

- **引擎互不影响**：Semgrep / CodeQL / DepChecker 任一失败只记 `engine_results` 并继续；动态失败回退静态结论。
- **依赖来源通用**：`requirements*.txt` → `pyproject.toml/setup.py`（editable，失败则解析 PEP621/poetry 逐条容错）→ 已打包应用的 `*.dist-info/METADATA`（探针自动补依赖）。
- **LLM 可选**：无 Key/失败时**静态结论独立成立**（`static_only` 进 high_suspicious），不静默丢弃。
- **外部服务可选**：Qdrant 不可达 → 跳过向量检索；Docker 不可达 → 动态整体降级并记 `skip_reason`。
- **有界行为**：所有子进程/网络调用都有超时；供给/探针有硬上限；重型工程按规则**立即止损**。
- **可复现**：中间产物与报告全部落 `output/`，`scripts/bench.py` 一键跑+归档+回归断言。

## 三、通用性矩阵

| 能力 | 支持 | 备注 |
|---|---|---|
| 静态（.py） | 任意 Python 工程 | CodeQL+Semgrep，规则见 `rules/semgrep/` |
| 依赖审计 | requirements / pyproject / 已装环境 | OSV 精确 pin + 本地缓存 |
| 动态 sink 探针 | **Flask / Django / FastAPI** | 五类 sink + 策略型（weak_hash） |
| 路线级 DAST | **Django**（缺鉴权/反射XSS/缺CSRF）· **FastAPI**（反射XSS） | 不依赖静态发现，独立产出 Finding |
| 沙箱供给 | requirements / pyproject / setup.py | 过重即止损；镜像按内容哈希缓存 |
| 不支持（明确） | bottle/CherryPy 等小众框架、IDOR/越权、XSS 存储型 | 按需再立项 |

## 四、残留风险（如实，未消除）

1. **canary/策略判据是"尽力而为的污点"**，非完整跨函数污点；B 未命中≠无漏洞（标 `retry_poc`/待复核）。
2. **守卫后过滤可能误降真阳性**——但只降级为"待复核"，不丢证据（`guard_postfilter` 记录在案）。
3. **OSV 缓存 TTL 7 天**：期间新增 CVE 不会更新（可删 `output/.cache/` 强制刷新）。
4. **重型工程被设计性跳过**（如 chainlit）；如需支持要上调阈值并接受长构建。
5. 真实项目评测精度仍受静态规则/模型判别力限制（见 [EVAL_real.md](EVAL_real.md)）。

## 五、2026-09-13 事故与修复（confirmed 15→2 的真实原因）

**现象**：跑完一轮动态验证后，Django 系全部 `app_unreachable`/`retry_poc`，confirmed 从 15 掉到 2。

**根因（不是 LLM/静态，也不是"镜像变弱"）**：动态验证会**真实触发**被测代码的漏洞，
而 pygoat 的 A9/A6 lab 本身就是"把提交内容写进源文件"的漏洞（`apis.py` 把 `log_code`
写进 `playground/A9/main.py`，写 `code` 写进 `playground/A6/utility.py`）。探针 POST 后
**宿主源码被覆盖成载荷/空串** → `introduction.apis` 导入失败 → Django urlconf 只剩 7 条
路由、回调成占位对象 → 所有 Django 路由 500 → 全部拿不到 B 轨证据。
被写坏的文件已按同目录 `archive.py`（`class Log`）与 `soln.py`（`check_vuln`）原样恢复。

**修复（通用，非特化）**：
1. **沙箱副本隔离**：`DockerExecutor.run_script(..., protect=[target])` 先把被测工程复制到
   `output/sandbox/protect_<hash>/`，再以**相同容器内路径覆盖挂载**——探针的一切写入只落副本
   （runner 三处调用已接入）。实测：副本内 `A9/main.py`/`A6/utility.py` 被写成 0 字节，
   宿主文件保持完好。
2. **缺包桩 `_Any` 的"任何位置都不炸"**：作为基类时 `__mro_entries__` 返回**空元组**
   （返回 `object` 会 MRO 冲突，如 PyYAML 缺 `_yaml`）；`__instancecheck__`/`__subclasscheck__`
   返回 True；继承 `BaseException`（供 `except <missing>.Err`）；`__module__/__name__` 必须是
   **str**（Django `lookup_str` 会拼接）。
3. **桩让位给迟到 finder**：six.moves 等库在导入时才把 finder 追加到 meta_path 尾部；
   不让位会把 `urllib3 1.26`/`requests` 的 lazy 属性伪造成占位对象（曾致 16 条 `app_unreachable`）。
4. **`from X import Y` 缺属性兜底**：`install_import_fallback()` 给已导入的真实模块补
   PEP 562 `__getattr__` 并重试（IMPORT_FROM 阶段抛错不经过 `__import__`，只能这样兜）。
5. **归档不再串名**：`run_bench.archive()` 只归档 `mtime >= 本次开始` 的产物并写 `STALE.txt`；
   已给历史串名目录（chainlit/pyload/pypi_upload_demo 的 dynamic 实为 pygoat 残留）加
   `INVALID_ARCHIVE.txt` 标注。

**修复后全流程实测**：静态 320 → 动态 **confirmed 14**（11 code + 3 DAST）、`retry_poc` 6、
误报率 5.28%，宿主语料零改动。

## 六、换项目 / 换解释器通用性复查（2026-09-13）

以"如果换成别的项目会怎样"为标准逐项验，发现并修掉 5 处**只在换环境时才暴露**的问题：

| # | 问题（换环境即踩） | 修复 |
|---|---|---|
| 1 | **容器内路径约定三方不一致**：探针按宿主绝对路径找目标、sandbox 只挂 `/workspace`、provision 挂 `/proj` | 统一为 `container_root_for()`：仓库内 `/workspace/<rel>`、仓库外 `/target`，sandbox/entry_driver/provision 共用 |
| 2 | **仓库外 target 无隔离**：`relative_to` 抛错被 `except: continue` 吞掉 → 探针直写用户真实工程 | 仓库外同样做副本并挂到 `/target`；副本创建失败**直接放弃该次探针**（宁可不验证也不写坏宿主） |
| 3 | **超大工程每次复制代价高** | 文件数 > `MAX_COPY_FILES(20000)` 时改用**只读挂载**（写操作失败但同样不污染宿主） |
| 4 | **已打包应用依赖审计恒为 0**：wheel 解包目录没有 requirements，依赖只在 `*.dist-info/METADATA` 的 `Requires-Dist` | `DepChecker._derive_from_metadata()` 抽取成 requirements 文本后复用原审计通道（跳过 `extra ==` 可选组、归一 `(>=1.0)`） |
| 5 | **换 Python 后缺 jinja2 会中断整个流程**：`reporting/runner.py` 无保护地构造 `HtmlReporter` | HTML 降级为"只出 JSON + 告警不中断"；日志标注 `（未生成）`；`vector_store` 嵌入缺失由 ERROR 改 WARNING（可选能力不报故障） |

**解释器可移植性**：产品代码中**没有任何写死的解释器路径**——CodeQL 建库注入用
`sys.executable`（自动跟随当前解释器）、容器内 pip 用 `sys.executable`、外部引擎走 PATH；
文档/脚本注释里的 `rag_env\Scripts\python.exe` 已统一改为通用 `python`。

**实测（四种形态）**：
- **仓库外项目**（pygoat 拷到 `D:/tmp/osd_outside`）：Django 探针 `/cmd_lab` 200、`track_b=1`、7.2s，仓库外语料零改动；
- **非 pygoat 的真实 FastAPI 项目**（`test/real_pypi/pypi-upload-demo-0.1.4`）：全流程 exit 0，依赖审计由 0 条变为命中 `CVE-2023-36464`；
- **0 候选目标**：动态阶段 30 秒内优雅空跑（无异常、无浪费），报告正常产出；
- **全新零依赖解释器**（`D:\tmp\freshpy`，Python 3.11.0，第三方包 0 个）：全流程 **exit 0**，
  逐级降级且日志清晰——Semgrep/CodeQL/pip-audit 走 PATH 照常、Qdrant 与 fastembed 缺失跳过向量检索、
  无 LLM Key 走 `static_only`、无 docker 模块动态降级、无 jinja2 只出 JSON 报告。

## 七、提交前安全清理（2026-09-13）

发布前扫描发现**两处明文密钥**（同一个 LLM key）：

| 位置 | 原因 | 处理 |
|---|---|---|
| `.claude/settings.json` / `settings.local.json` | 跑命令时生成的白名单条目把 `OPENAI_API_KEY=...` 原样记了进去 | 删除 5 条含密钥的条目；`.gitignore` 排除 `.claude/` |
| `output/config_used.json` | **配置快照把密钥原样落盘**（产品缺陷，产物一旦分享即泄露） | `ConfigLoader.dump()` 增加 `_redact()`：`api_key/token/secret/password` 等字段一律写成 `***已配置（已脱敏）***`；已落盘快照一并脱敏 |

`.gitignore` 同时排除：`codeql/`(1.2 GB 离线套件) · `output/`(3.4 GB 产物) ·
`rag_env/`(556 MB venv) · `qdrant_storage/` · `models/` · `test/`(第三方靶场语料，版权+体积)。

**操作建议**：该 key 曾以明文存在于本地文件与会话记录，发布前应在服务商后台**重置**。

## 八、快速自检（本轮跑过，全绿）

```bash
# 编译
python -m compileall -q main.py config.py modules scripts
# 冒烟：42 个模块导入 + static_only 分级 + 守卫检测 + 缺包桩 + 策略 oracle
#      + PyPI METADATA 依赖解析 + FastAPI 入口探测
```
