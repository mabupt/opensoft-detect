# 早上提交清单（照做即可）

> 准备时间：2026-09-13 凌晨。仓库**已 `git init` + `git add -A`**，只剩你执行 `commit` / `push`。

## 第 0 步（必做，30 秒）：重置 API key

智谱后台 → API Keys → 把 `26bfd5...DIdt` 删掉/重置，换一把新的。
原因：它曾以明文出现在 `.claude/settings*.json`（命令白名单）与 `output/config_used.json`
（配置快照）。仓库里**已清理干净**（扫描 0 处），但凭据本身应作废。

新 key 只放在环境变量里，别写进任何文件：

```bash
export OPENSOFT_LLM_PROVIDER=openai
export OPENSOFT_LLM_API_BASE=https://open.bigmodel.cn/api/paas/v4
export OPENSOFT_LLM_MODEL=glm-4-flash
export OPENAI_API_KEY=<新 key>
```

## 第 1 步：复核提交内容（1 分钟）

```bash
cd /d/projct/opensoft_detect
git status --short | head          # 应只剩已暂存的 A 项，无未跟踪的大目录
git diff --cached --shortstat      # 预期：64 files changed, ~11.6k insertions
git diff --cached | grep -c "sk-"  # 若用 OpenAI 风格 key，应为 0（密钥检查）
```

如果昨晚之后又改过代码：`git add -A` 重新暂存。

## 第 2 步：提交并推送（你来）

```bash
git commit -m "feat: OpenSoft Detect — 静态分析 + RAG 富化 + LLM 研判 + 动态验证的 Python 漏洞检测流水线"
git branch -M main
git remote add origin <你的仓库地址>
git push -u origin main
```

推送时会用到 **PAT（Personal Access Token）**，不是登录密码。

## 第 3 步：可选——确认一遍能力（提交前后都可跑）

```bash
# 全流程（约 10 分钟，Docker 需在运行）
python main.py --target test/goat/pygoat-master --attempt-dynamic
```

**预期结果**（2026-09-13 实测）：

| 指标 | 期望值 |
|---|---|
| 静态发现 | 320（semgrep 8 · codeql 33 · pip_audit 279） |
| 动态 confirmed | **14**（11 code + 3 DAST：`/debug` 缺鉴权、`/xssL`、`/xssL1` 反射 XSS） |
| 报告误报率 | 整体 0.0528；**分引擎**：pip_audit 0% · dynamic 0% · semgrep 40% · codeql 53.6% |
| 宿主语料 | 零改动（探针跑副本） |

## 关于被排除的内容（`.gitignore`）

`codeql/`(1.2 GB 离线套件) · `output/`(3.4 GB 产物) · `rag_env/`(556 MB venv) ·
`qdrant_storage/` · `models/`(嵌入缓存) · `test/`(第三方靶场语料) · `.claude/` · `*.log`

**别人 clone 后如何跑起来**（README 已写明）：
1. `pip install -r requirements.txt`
2. 下载 CodeQL bundle 到 `codeql/codeql-bundle-win64/`（或设 `OPENSOFT_SKIP_CODEQL=1` 跳过该引擎）
3. 起 Qdrant：`docker run -d --name opensoft_qdrant -p 6333:6333 qdrant/qdrant`
4. 准备目标项目，`python main.py --target <路径>`

**若你想连靶场语料一起提交**：删掉 `.gitignore` 末尾的 `test/` 一行，再 `git add -A`
（注意 pygoat 是第三方项目，注意其许可证与出处标注）。

## 已知边界（如实写进报告，别当缺陷）

- `retry_poc` 6 条属"非污点直达型"（SQL raw 懒执行 / 日志泄露 / 部分弱哈希），需按类别的断言 oracle。
- codeql 代码类误报率 53.6%，集中在信息泄露类规则（`clear-text-logging` / `client-exposed-cookie`）。
- FastAPI 动态路径不再深挖（用户决定）：其 DAST 探针可能跑满超时预算后止损，可用 `--no-dast` 关闭。
- 强模型（glm-4-air/plus）该 key 余额不足，仅 glm-4-flash 可用。
