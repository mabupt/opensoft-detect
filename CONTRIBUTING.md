# 贡献指南

感谢有兴趣参与改进。本项目是 Python 漏洞检测流水线（静态分析 → 上下文富化 → LLM 研判 →
容器内动态验证 → 报告），欢迎提交 Issue 与 PR。

## 开发环境

```bash
git clone https://github.com/mabupt/opensoft-detect.git
cd opensoft-detect
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 外部引擎（可选，缺失时对应能力自动降级）
pip install semgrep pip-audit
# CodeQL 为独立离线套件，按 README「环境」一节放到 codeql/codeql-bundle-win64/
```

## 提交前自检（必跑）

```bash
python -m compileall -q main.py config.py modules scripts
python scripts/smoke.py
```

`scripts/smoke.py` 覆盖模块导入与核心纯函数断言，且**不依赖**外部引擎/服务，应与 CI 保持一致。
若改动涉及动态验证，建议再跑一次全流程：

```bash
python main.py --target <本地靶场路径> --attempt-dynamic
```

## 代码约定

- Python 3.11+，全量类型注解，模块/函数/类均写中文 docstring（说明"为什么"而非复述签名）；
- 新能力默认**可降级**：外部引擎、Qdrant、Docker、LLM 任一不可用时不得让流程崩溃，
  应记录日志并继续（参见 [docs/HARDENING.md](docs/HARDENING.md) §二）；
- 动态验证相关改动**必须**保持沙箱隔离契约：探针只能写入被测工程的副本，绝不可写宿主源码；
- 不要提交密钥、产物（`output/`）、靶场语料（`test/`）与离线工具包（`codeql/`），
  这些已在 `.gitignore` 中排除。

## PR 流程

1. 从 `main` 切出分支（`feat/xxx`、`fix/xxx`）；
2. 保持改动聚焦，一个 PR 解决一件事，并说明**动机 + 验证方式**（贴出实际输出更有说服力）；
3. 若新增检测能力，请在 PR 描述中给出在真实样本上的实测数据（检出/误报），而非仅"已实现"；
4. CI 通过后由维护者合并。

## 报告问题

- Bug / 功能建议：走 Issue，附复现步骤、期望与实际行为、运行环境；
- 安全漏洞：**不要公开提 Issue**，见 [SECURITY.md](SECURITY.md)。
