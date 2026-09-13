"""模块1 编排入口（runner）。

组合静态分析器的注册、调度、去重排序与落盘，供 main.py 调用。
"""

from __future__ import annotations

import logging
from pathlib import Path

from config import Config

logger = logging.getLogger("opensoft_detect.static_analysis")


def run(manifest_path: Path, config: Config) -> Path:
    """执行模块1静态分析，产出 ``output/findings.json``。

    流程：
    1. 构造 StaticOrchestrator（内置 Semgrep / CodeQL / DepChecker 三引擎）；
    2. analyze_all 依可用性运行各引擎并收集结果（单引擎失败自动降级）；
    3. 跨引擎去重、按严重程度排序；
    4. 与 engine_results 一起落盘。

    :param manifest_path: 模块0产出的 file_manifest.json 路径。
    :param config: 全局配置。
    :return: 统一 findings.json 绝对路径。
    """
    from modules.static_analysis.orchestrator import (StaticOrchestrator,
                                                      dedupe_findings,
                                                      sort_findings)

    orchestrator = StaticOrchestrator(config)
    raw_findings = orchestrator.analyze_all(manifest_path)
    merged = sort_findings(dedupe_findings(raw_findings))

    summary = {r["engine"]: r["status"] for r in orchestrator.engine_results}
    logger.info("引擎运行情况：%s | 去重后共 %d 条 Finding。",
                summary, len(merged))

    out_path: Path = config.paths.default_raw_findings_path
    saved: str = orchestrator.save_findings(merged, out_path)
    return Path(saved)
