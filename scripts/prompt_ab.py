"""Prompt A/B 评测：对比不同 prompt 版本在**已人工判读**数据集上的表现。

数据集：chainlit（18 条人工标签：TP=2 / FP=16，见 docs/EVAL_real.md）。
指标：
- ``tp_precision``：判为 true_positive 的条目中，人工标签为 tp 的比例（越高越好）；
- ``fp_recall``：人工标签为 fp 的条目中，被明确判为 false_positive 的比例；
- ``needs_review``：落为 unverified（待复核）的条数（不算错，但未收敛）。

用法：:

    python scripts/prompt_ab.py [--enriched 路径] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: 人工标签：(rule_id 关键字, 文件名, 行号) -> "tp" / "fp"（据 docs/EVAL_real.md 逐条判读）
LABELS: dict[tuple[str, str, int], str] = {
    ("path-injection", "server.py", 267): "fp", ("path-injection", "server.py", 272): "fp",
    ("path-injection", "server.py", 273): "fp", ("path-injection", "server.py", 285): "fp",
    ("path-injection", "server.py", 290): "fp", ("path-injection", "server.py", 291): "fp",
    ("path-injection", "server.py", 303): "fp", ("path-injection", "server.py", 308): "fp",
    ("path-injection", "server.py", 309): "fp",
    ("path-injection", "markdown.py", 45): "fp", ("path-injection", "markdown.py", 54): "fp",
    ("path-injection", "config.py", 467): "fp", ("path-injection", "config.py", 474): "fp",
    ("path-injection", "_utils.py", 8): "fp",
    ("cookie-injection", "cookie.py", 132): "fp", ("cookie-injection", "cookie.py", 144): "fp",
    ("cookie-injection", "server.py", 769): "tp",
    ("samesite-none-cookie", "server.py", 767): "tp",
}


def evaluate(enriched: Path, use_few_shot: bool, limit: int | None) -> dict:
    """跑一个 prompt 变体并统计指标。"""
    from config import Config
    from models import Finding, VulnerabilityStatus
    from modules.llm_analysis.client import LLMClient
    from modules.llm_analysis.fp_judge import FalsePositiveJudge

    cfg = Config()
    findings = [Finding.from_dict(x) for x in
                json.loads(enriched.read_text(encoding="utf-8"))["findings"]]
    if limit:
        findings = findings[:limit]
    judge = FalsePositiveJudge(LLMClient(cfg.llm), kb=None,
                               fix_suggest=False, use_few_shot=use_few_shot)
    tp_judged = tp_correct = fp_total = fp_judged = review = 0
    rows: list[dict] = []
    variant = "few_shot" if use_few_shot else "baseline"
    for idx, f in enumerate(findings, 1):
        print(f"[{variant}] {idx}/{len(findings)} {Path(f.file_path).name}:"
              f"{f.location.start_line if f.location else 0} ...", flush=True)
        line = f.location.start_line if f.location else 0
        name = Path(f.file_path).name
        label = next((v for (rk, fn, ln), v in LABELS.items()
                      if rk in f.rule_id and fn == name and ln == line), "?")
        try:
            judge.judge(f)
        except Exception as exc:  # noqa: BLE001 - 单条失败不影响评测
            rows.append({"id": f.id, "label": label, "status": f"error:{str(exc)[:60]}"})
            continue
        st = f.status.value
        rows.append({"id": f.id, "label": label, "status": st})
        if label == "fp":
            fp_total += 1
            if f.status == VulnerabilityStatus.FALSE_POSITIVE:
                fp_judged += 1
        if f.status == VulnerabilityStatus.TRUE_POSITIVE:
            tp_judged += 1
            if label == "tp":
                tp_correct += 1
        if f.status == VulnerabilityStatus.UNVERIFIED:
            review += 1
    return {
        "use_few_shot": use_few_shot, "total": len(findings),
        "tp_judged": tp_judged, "tp_correct": tp_correct,
        "tp_precision": round(tp_correct / tp_judged, 3) if tp_judged else None,
        "fp_total": fp_total, "fp_judged": fp_judged,
        "fp_recall": round(fp_judged / fp_total, 3) if fp_total else None,
        "needs_review": review, "rows": rows,
    }


def main() -> int:
    """CLI 入口。"""
    ap = argparse.ArgumentParser(description="Prompt A/B 评测（chainlit 人工标签）")
    ap.add_argument("--enriched", type=Path,
                    default=Path("output/bench/chainlit/enriched_findings.json"))
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    results = [evaluate(args.enriched, False, args.limit),
               evaluate(args.enriched, True, args.limit)]
    print(f"{'variant':<16}{'TP判定':<8}{'TP对':<6}{'精度':<8}{'FP应判':<8}{'FP判出':<8}{'FP召回':<8}{'待复核'}")
    for r in results:
        print(f"{('few_shot' if r['use_few_shot'] else 'baseline'):<16}"
              f"{r['tp_judged']:<8}{r['tp_correct']:<6}{str(r['tp_precision']):<8}"
              f"{r['fp_total']:<8}{r['fp_judged']:<8}{str(r['fp_recall']):<8}{r['needs_review']}")
    out = args.enriched.parent / "prompt_ab.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print("saved:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
