"""模块5 编排入口（runner）。

聚合各阶段 JSON -> 组装 report -> 写出 ``output/final_report.json`` /
``output/final_report.html``。
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from config import Config
from modules.reporting.html_reporter import HtmlReporter
from modules.reporting.json_reporter import JsonReporter
from modules.reporting.report import ReportAssembler, aggregate_findings, load_dropped

logger = logging.getLogger("opensoft_detect.reporting")


def run(final_findings_path: Path, config: Config) -> tuple[Path, Path]:
    """执行模块5报告生成。

    :param final_findings_path: 模块4 产物（跳过动态时为模块3 产物）。
    :param config: 全局配置。
    :return: (final_report.json, final_report.html) 绝对路径。
    """
    # 聚合来源：依次为 findings -> enriched -> verified -> 最终文件（后覆盖先）
    stage_paths: list[Path] = [
        config.paths.default_raw_findings_path,
        config.paths.default_enriched_path,
        config.paths.default_verdict_path,
        Path(final_findings_path),
    ]
    # 去重保序
    unique: list[Path] = []
    for p in stage_paths:
        if p not in unique:
            unique.append(p)

    findings = aggregate_findings(unique)
    dropped_path: Path = config.paths.findings_dir / "prefilter_dropped.json"
    dropped: list[dict[str, Any]] = load_dropped(dropped_path)
    logger.info("报告聚合完成：%d 条 Finding（prefilter 丢弃 %d 条）",
                len(findings), len(dropped))

    assembler = ReportAssembler(config)
    report = assembler.assemble(findings, dropped=dropped)

    json_out: Path = config.paths.report_dir / "final_report.json"
    html_out: Path = config.paths.report_dir / "final_report.html"
    json_path = Path(JsonReporter().dump(report, json_out))
    # HTML 是附加产物（依赖 jinja2）：换 Python/新环境缺依赖时不能连累整条流程——
    # JSON 报告已落盘，这里降级为"无 HTML"并明确告警。
    try:
        html_path = Path(HtmlReporter().render(report, html_out))
    except Exception as exc:  # noqa: BLE001 - 缺 jinja2 等
        html_path = html_out
        logger.warning("HTML 报告生成失败（已保留 JSON 报告，不中断流程）：%s", exc)

    stats = report.get("statistics", {}).get("fp_rate", {})
    html_note = str(html_path) if html_path.exists() else f"{html_path}（未生成）"
    logger.info(
        "报告完成 | TP=%s FP=%s 误报率=%s | confidence=%s | json=%s html=%s",
        stats.get("true_positives"), stats.get("false_positives"),
        stats.get("false_positive_rate"),
        report.get("statistics", {}).get("confidence_distribution"),
        json_path, html_note,
    )
    return json_path, html_path
