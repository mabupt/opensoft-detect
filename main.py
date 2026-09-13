"""OpenSoft Detect —— 主控流程。

按顺序串联六个模块（0→1→2→3→4→5），各模块通过 ``output/`` 下的 JSON 传递数据：

    [模块0 preprocess] --file_manifest.json--> [模块1 static_analysis] --findings.json-->
    [模块2 context_enrichment] --enriched_findings.json--> [模块3 llm_analysis] --verified_findings.json-->
    [模块4 dynamic_verification] --dynamic_findings.json--> [模块5 reporting] --> final_report.{json,html}

每个模块执行前后打印进度日志；任一模块异常即中止并返回非零退出码。
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Optional, Sequence

from config import Config, ConfigLoader

logger = logging.getLogger("opensoft_detect")


# ---------------------------------------------------------------------------
# 命令行解析
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="opensoft_detect",
        description="Python 项目安全漏洞检测（静态分析 + RAG 富化 + LLM 研判 + 动态验证 + 报告）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target", type=Path, required=True, metavar="PATH",
        help="（必填）待扫描的目标项目目录。",
    )
    parser.add_argument(
        "--fix-suggest", action="store_true", default=False,
        help="生成修复建议：仅对 动态验证确认(confirmed) 的漏洞产出经校验的 unified diff。",
    )
    # ---- 模块0 选项 ----
    parser.add_argument("--include-excluded", action="store_true", default=False,
                        help="模块0：把软排除文件（tests/docs 等）也纳入扫描。")
    parser.add_argument("--scan-dirs", nargs="+", default=None, metavar="DIR",
                        help="模块0：只扫描 target 下指定的子目录。")
    # ---- 阶段跳过选项（用于单步调试/缺工具降级）----
    parser.add_argument("--skip-enrich", action="store_true", default=False,
                        help="跳过模块2 富化，改用已存在的 enriched_findings.json。")
    parser.add_argument("--skip-llm", action="store_true", default=False,
                        help="跳过模块3 LLM 研判（不调用大模型）。")
    parser.add_argument("--skip-dynamic", action="store_true", default=False,
                        help="跳过模块4 动态验证（无 Docker/入口驱动时开启）。")
    parser.add_argument("--attempt-dynamic", action="store_true", default=False,
                        help="启用模块4 真实动态验证（容器探针；默认关闭，仅做降级判定）。")
    parser.add_argument("--no-dast", action="store_true", default=False,
                        help="动态阶段跳过路线级 DAST 扫描（缺鉴权/反射XSS/缺CSRF；"
                             "该扫描与 Finding 无关、较耗时，按需关闭）。")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="日志级别。")
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """解析命令行参数。

    :param argv: 参数序列；None 时读 sys.argv。
    :return: 命名空间。
    """
    return build_arg_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# 各模块编排（单个函数一个模块，带进度日志）
# ---------------------------------------------------------------------------

def _write_config_snapshot(config: Config) -> None:
    """把本次运行配置写入 output/config_used.json。"""
    try:
        snap = config.paths.output_dir / "config_used.json"
        snap.write_text(json.dumps(ConfigLoader.dump(config), ensure_ascii=False, indent=2),
                        encoding="utf-8")
    except OSError as exc:
        logger.warning("写入配置快照失败：%s", exc)


def _run_preprocess(config: Config) -> Path:
    """模块0。"""
    from modules.preprocess.runner import run as run_preprocess
    logger.info("[1/6] 模块0 preprocess：遍历过滤 %s", config.target)
    out = run_preprocess(config)
    logger.info("[1/6] 模块0 完成 -> %s", out)
    return out


def _run_static_analysis(manifest_path: Path, config: Config) -> Path:
    """模块1。"""
    from modules.static_analysis.runner import run as run_static
    logger.info("[2/6] 模块1 static_analysis：Semgrep/CodeQL/pip-audit 基于 %s", manifest_path)
    out = run_static(manifest_path, config)
    logger.info("[2/6] 模块1 完成 -> %s", out)
    return out


def _run_context_enrichment(findings_path: Path, manifest_path: Path, config: Config) -> Path:
    """模块2。"""
    from modules.context_enrichment.runner import run as run_enrich
    logger.info("[3/6] 模块2 context_enrichment：切片/路由/Qdrant 检索 %s", findings_path)
    out = run_enrich(findings_path, manifest_path, config)
    logger.info("[3/6] 模块2 完成 -> %s", out)
    return out


def _run_llm_analysis(enriched_path: Path, config: Config) -> Path:
    """模块3。"""
    from modules.llm_analysis.runner import run as run_llm
    logger.info("[4/6] 模块3 llm_analysis：预过滤 + LLM 误报研判 %s", enriched_path)
    out = run_llm(enriched_path, config)
    logger.info("[4/6] 模块3 完成 -> %s", out)
    return out


def _run_dynamic_verification(verified_path: Path, manifest_path: Path, config: Config) -> Path:
    """模块4。"""
    from modules.dynamic_verification.runner import run as run_dynamic
    logger.info("[5/6] 模块4 dynamic_verification：Import Hook 双轨验证 %s", verified_path)
    out = run_dynamic(verified_path, manifest_path, config)
    logger.info("[5/6] 模块4 完成 -> %s", out)
    return out


def _run_reporting(final_path: Path, config: Config) -> tuple[Path, Path]:
    """模块5。"""
    from modules.reporting.runner import run as run_report
    logger.info("[6/6] 模块5 reporting：聚合 + 报告 %s", final_path)
    json_path, html_path = run_report(final_path, config)
    logger.info("[6/6] 模块5 完成 -> %s / %s", json_path, html_path)
    return json_path, html_path


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    """主入口：0→1→2→3→4→5 串联执行。

    :param argv: 命令行参数。
    :return: 0 成功；1 失败。
    """
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, (args.log_level or "INFO").upper(), logging.INFO),
                        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
    config: Config = ConfigLoader.load_from_args(args)
    ConfigLoader.ensure_dirs(config)
    _write_config_snapshot(config)
    logger.info("OpenSoft Detect 启动 | target=%s | fix_suggest=%s", config.target,
                config.fix_suggest)

    try:
        # ---- 模块0 ----
        manifest_path: Path = _run_preprocess(config)

        # ---- 模块1（静态分析：数据起点，不可跳过）----
        current: Path = _run_static_analysis(manifest_path, config)

        # ---- 模块2 ----
        if not args.skip_enrich:
            current = _run_context_enrichment(current, manifest_path, config)
        else:
            current = config.paths.default_enriched_path
            logger.warning("模块2 已跳过，复用 %s（若不存在后续将降级）", current)

        # ---- 模块3 ----
        if not args.skip_llm:
            current = _run_llm_analysis(current, config)
        else:
            logger.warning("模块3 已跳过（--skip-llm）。")

        # ---- 模块4 ----
        if not args.skip_dynamic:
            current = _run_dynamic_verification(current, manifest_path, config)
        else:
            logger.warning("模块4 已跳过（--skip-dynamic），无运行时验证结论。")

        # ---- 模块5 ----
        json_report, html_report = _run_reporting(current, config)

        logger.info("全流程完成。最终报告：\n  JSON=%s\n  HTML=%s", json_report, html_report)
        return 0
    except KeyboardInterrupt:  # 用户中断：优雅退出（不打印堆栈）
        logger.warning("已被用户中断。")
        return 130
    except Exception as exc:  # noqa: BLE001 - 顶层兜底：明确失败并返回非零
        logger.error("流水线失败：%s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
