# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.1.0] - 2026-09-13

首个公开版本：完整 0→5 检测流水线。

### 新增

- **模块0 预处理**：文件遍历与硬/软过滤，产出含 `scan_scope` / `excluded` / `stats` 的
  `file_manifest.json`；支持 `--include-excluded`、`--scan-dirs`。
- **模块1 静态分析**：Semgrep（含 taint 规则集）、CodeQL（离线套件、建库缓存与失败回退）、
  pip-audit（+ OSV 精确 pin 回退、`dist-info/METADATA` 依赖派生、本地内容哈希缓存）；
  统一 `findings.json`，引擎相互隔离、单引擎失败不影响其余。
- **模块2 上下文富化**：AST 路由/参数提取（Django/Flask/FastAPI）、按工具粒度代码切片
  （单函数 ≤100 行、≤8 数据流步、≤3000 token，含跨文件被调函数）、Qdrant 向量检索与 CWE 预载。
- **模块3 LLM 研判**：确定性预过滤、`temperature=0` + JSON mode + 超时重试、误报知识库闭环
  （confirmed 回写 + Top3 先验）、few-shot、守卫后过滤、模型路由与端点熔断、判定缓存。
- **模块4 动态验证**：`sys.meta_path` 三层补丁、双轨判定（sink 调用记录 + canary 污点追踪）、
  类别化策略 oracle（如弱哈希断言）、Django（真 HTTP/RequestFactory）/Flask/FastAPI 探针、
  路线级 DAST（缺鉴权 / 反射 XSS / 缺 CSRF）、Docker 沙箱（副本隔离、超时回收、依赖自动供给与止损）。
- **模块5 报告**：四级置信度、CWE→ATT&CK 关联、修复 Diff（仅对动态确认项生成并做事实校验）、
  分引擎误报率、Jinja2 HTML 与机器可读 JSON 报告。
- **主控** `main.py`：0→5 串联、阶段跳过开关、配置快照留痕（密钥自动脱敏）、`KeyboardInterrupt` → 130。

### 安全

- 动态探针一律运行在**被测工程副本**上（含仓库外目标的 `/target` 挂载约定），避免真实漏洞利用写入宿主源码。
- 配置快照对 `api_key` / `token` / `secret` / `password` 等字段自动脱敏。
- 容器执行有硬超时、日志流式输出、异常路径统一回收。

### 已知限制

- 未检出 ≠ 无漏洞：`retry_poc` 类多为"非污点直达型"（SQL 懒执行、日志泄露等），需按类别的断言 oracle。
- CodeQL 对"自定义消毒函数"存在系统性误报，已用跨文件切片 + 守卫后过滤缓解，仍建议人工复核。
- 动态验证目前覆盖 Flask / Django / FastAPI；bottle、CherryPy 等不在范围内。
- 详见 [docs/HARDENING.md](docs/HARDENING.md) 与 [docs/EVAL_real.md](docs/EVAL_real.md)。
