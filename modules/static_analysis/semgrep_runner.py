"""Semgrep 集成（semgrep_runner）。

以子进程方式调用 ``semgrep scan --json``。关键设计：

1. **扫描范围严格对齐模块0**：把 file_manifest.json 的 ``scan_scope`` 中的文件
   逐一作为目标文件传给 semgrep（而不是把整个工程目录丢给它），保证过滤结果
   与扫描结果一致；
2. **批量执行防参数超长**：Windows 命令行长度有限，按估计字符数把文件列表切成
   多个批次分别调用，最后合并结果；
3. **降级策略**：某一批次失败只记录日志、其余批次照跑；无本地规则时退化为
   ``--config auto``（联网 registry），失败则返回空列表并明确告警。

规则来源优先级：``ToolConfig.semgrep_rules_dir``（本地规则目录）> registry auto。
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from config import ToolConfig
from models import Finding, ToolName
from modules.preprocess.manifest import iter_scan_scope, load_manifest
from modules.static_analysis.base import AnalyzerBase
from modules.static_analysis.parsers import parse_semgrep_json, run_subprocess

logger = logging.getLogger("opensoft_detect.static_analysis.semgrep")

#: 单批次 argv 估算字符预算（Windows 命令行 ~32k，留 10k 余量）
_ARG_BUDGET: int = 20_000


class SemgrepRunner(AnalyzerBase):
    """基于 Semgrep 的静态分析器。"""

    tool: ToolName = ToolName.SEMGREP

    def is_available(self) -> bool:
        """检测 semgrep 是否在本机 PATH 中。

        :return: True 表示可运行。
        """
        if not shutil.which(self.tool_cfg.semgrep_bin):
            logger.warning("Semgrep 未安装（找不到可执行文件：%s），该引擎将被跳过。",
                           self.tool_cfg.semgrep_bin)
            return False
        return True

    def run(self, manifest_path: Path) -> list[Finding]:
        """按 scan_scope 批量执行 Semgrep 并合并归一化结果。

        :param manifest_path: file_manifest.json 路径。
        :return: Finding 列表；无目标/全部失败时为空。
        """
        try:
            manifest = load_manifest(manifest_path)
        except OSError as exc:
            logger.error("读取清单失败，Semgrep 跳过：%s", exc)
            return []

        targets: list[str] = [
            entry["path"] for entry in iter_scan_scope(manifest)
            if Path(entry.get("path", "")).is_file()
        ]
        if not targets:
            logger.warning("scan_scope 为空，Semgrep 无需扫描。")
            return []

        config_flags: list[str] = self._config_flags()
        base_cmd: list[str] = [
            self.tool_cfg.semgrep_bin, "scan",
            "--json", "--no-git-ignore", "--metrics=off", "--no-rewrite-rule-ids",
            *config_flags,
        ]

        findings: list[Finding] = []
        batches: list[list[str]] = self._split_batches(targets)
        logger.info("Semgrep 开始扫描：%d 个文件，切分为 %d 个批次。",
                    len(targets), len(batches))
        for i, batch in enumerate(batches, start=1):
            try:
                cmd: list[str] = [*base_cmd, *batch]
                code, out, err = run_subprocess(cmd, timeout=self.tool_cfg.semgrep_timeout)
                if code != 0:
                    logger.error("Semgrep 批次 %d 返回码 %d，stderr：%s",
                                 i, code, err[:800])
                if out.strip():
                    batch_findings = parse_semgrep_json(out)
                    findings.extend(batch_findings)
                    logger.info("Semgrep 批次 %d 解析出 %d 条发现。",
                                i, len(batch_findings))
            except Exception as exc:  # noqa: BLE001 - 单批次失败降级
                self.last_error = f"批次 {i} 失败: {exc}"
                logger.error("Semgrep 批次 %d 执行失败，已跳过该批次：%s", i, exc)
        return self.post_process(findings)

    # ---- 内部 ----
    def _config_flags(self) -> list[str]:
        """构造 --config 参数：本地规则目录优先，否则 auto（需联网）。

        :return: 命令行 flag 列表。
        """
        rules_dir = self.tool_cfg.semgrep_rules_dir
        if rules_dir.is_dir() and list(rules_dir.glob("*.y*ml")):
            logger.info("使用本地 Semgrep 规则目录：%s", rules_dir)
            return ["--config", str(rules_dir)]
        logger.warning(
            "未找到本地 Semgrep 规则目录（%s），退化为 --config auto "
            "（需要联网访问 registry；离线将失败并被降级处理）。", rules_dir)
        return ["--config", "auto"]

    def _split_batches(self, targets: list[str]) -> list[list[str]]:
        """按字符预算把文件列表切分为多个批次。

        逐文件累计估算长度，超过预算即开启新批次；单文件超预算时单独成批
        （宁可多批也不丢文件）。

        :param targets: 待扫描文件绝对路径列表。
        :return: 批次列表。
        """
        batches: list[list[str]] = []
        current: list[str] = []
        size: int = 0
        for t in targets:
            if current and size + len(t) > _ARG_BUDGET:
                batches.append(current)
                current, size = [], 0
            current.append(t)
            size += len(t) + 1
        if current:
            batches.append(current)
        return batches
