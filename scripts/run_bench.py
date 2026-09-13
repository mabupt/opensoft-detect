"""一键跑某 target 的全流程并把产物归档到 output/bench/<name>/。

用法：:

    rag_env\\Scripts\\python.exe scripts\\run_bench.py \\
        --target test/goat/pygoat-master --name pygoat [--attempt-dynamic]

说明：
- 依赖 LLM（GLM）时请先在环境变量配置 OPENSOFT_LLM_* 与 OPENAI_API_KEY，
  否则模块3 自动降级为"只预过滤、不研判"；
- 默认模块4 动态 attempt=False（快速跳过，不产生误判）；加 --attempt-dynamic
  才会对可驱动应用做真实容器探针（较慢）；
- 归档文件：file_manifest/findings/enriched/verified/dynamic/prefilter_dropped/
  final_report.json/html。
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from collections import Counter
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s | %(message)s")
logger = logging.getLogger("run_bench")

_FILES = ["file_manifest.json", "findings.json", "enriched_findings.json",
          "verified_findings.json", "dynamic_findings.json",
          "prefilter_dropped.json", "final_report.json", "final_report.html"]


def run_stages(target: Path, attempt_dynamic: bool) -> tuple[Path, dict]:
    """执行 0→5，返回 (final_report_path, summary)。"""
    from config import Config
    cfg = Config(target=target.resolve(), dynamic_attempts=attempt_dynamic)

    from modules.preprocess.runner import run as pre
    from modules.static_analysis.runner import run as static
    from modules.context_enrichment.runner import run as enrich
    from modules.llm_analysis.runner import run as llm
    from modules.reporting.runner import run as report

    logger.info("--- 模块0 preprocess ---")
    man = pre(cfg)
    logger.info("--- 模块1 static ---")
    fin = static(man, cfg)
    logger.info("--- 模块2 enrich ---")
    enr = enrich(fin, man, cfg)
    logger.info("--- 模块3 llm ---")
    ver = llm(enr, cfg)
    # 模块4：仅当 --attempt-dynamic 时执行（此前遗漏，导致 bench 永远不跑动态——已修正）
    if attempt_dynamic:
        from modules.dynamic_verification.runner import run as dyn
        logger.info("--- 模块4 dynamic ---")
        ver = dyn(ver, man, cfg)
    else:
        logger.info("--- 模块4 dynamic 跳过（未加 --attempt-dynamic）---")
    logger.info("--- 模块5 report ---")
    j, h = report(ver, cfg)

    d = json.loads(Path(j).read_text(encoding="utf-8"))
    stats = d.get("statistics", {})
    summary = {
        "target": str(target),
        "static_total": len(d.get("findings", [])),
        "by_tool": dict(Counter(f.get("tool") for f in d.get("findings", []))),
        "confidence": stats.get("confidence_distribution"),
        "fp": stats.get("fp_rate"),
    }
    return Path(j), summary


def _repo_root(start: Path) -> Path:
    """向上找含 modules/ 目录的仓库根。"""
    cur = start
    while cur.parent != cur:
        if (cur / "modules").is_dir():
            return cur
        cur = cur.parent
    return cur


def archive(name: str, cfg_dir: Path, since: float = 0.0) -> Path:
    """把 output 下阶段文件归档到 bench/<name>。

    只归档**本次运行产出**的文件（``mtime >= since``）：否则上一轮 target 的残留
    会被当成这一轮的产物（实测出现过 bench/chainlit、bench/pyload 里存着 pygoat
    的结果这种串名，会直接误导汇报）。被跳过的过期文件记入 ``STALE.txt``。

    :param name: 归档名。
    :param cfg_dir: output 目录。
    :param since: 本次运行的起始时间戳（time.time()）。
    :return: 归档目录。
    """
    repo = _repo_root(cfg_dir)
    dest = repo / "output" / "bench" / name
    dest.mkdir(parents=True, exist_ok=True)
    copied: list[str] = []
    stale: list[str] = []
    for fn in _FILES:
        src = cfg_dir / fn
        if not src.is_file():
            continue
        if since and src.stat().st_mtime < since:
            stale.append(fn)
            logger.warning("跳过过期产物（不属于本次运行）：%s", fn)
            continue
        shutil.copy(src, dest / fn)
        copied.append(fn)
    (dest / "STALE.txt").unlink(missing_ok=True)
    if stale:
        (dest / "STALE.txt").write_text(
            "以下文件因早于本次运行而被跳过（避免旧 target 产物串名）：\n"
            + "\n".join(stale) + "\n", encoding="utf-8")
    logger.info("已归档 %d 个产物到 %s（跳过过期 %d 个）", len(copied), dest, len(stale))
    return dest


def main() -> int:
    """CLI 入口。"""
    ap = argparse.ArgumentParser(description="全流程跑 target 并归档")
    ap.add_argument("--target", type=Path, required=True)
    ap.add_argument("--name", default=None, help="归档名；默认用 target 末段")
    ap.add_argument("--attempt-dynamic", action="store_true", default=False,
                    help="启用模块4 真实容器探针")
    args = ap.parse_args()

    name = args.name or args.target.resolve().name
    import time as _time
    t0 = _time.time()
    final_json, summary = run_stages(args.target, args.attempt_dynamic)
    dest = archive(name, final_json.parent, since=t0)
    print("=== SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("archived:", dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
