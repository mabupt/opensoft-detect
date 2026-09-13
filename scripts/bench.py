"""一键基准：全流程跑 target -> 归档 output/bench/<name>/ -> （pygoat）回归断言。

把 run_bench 的"跑+归档"与回归断言串成一个可重复命令：:

    rag_env\\Scripts\\python.exe scripts\\bench.py --target test/goat/pygoat-master --name pygoat

说明：
- 依赖 LLM（GLM）请先在环境变量配 OPENSOFT_LLM_* 与 OPENAI_API_KEY；缺 key 时
  模块3 自动降级为"只预过滤不研判"。
- 静态含 CodeQL 建库+分析、依赖审计（OSV 回退），完整跑一遍较慢（分钟级）。
- 目标路径含 "pygoat" 时自动对归档 findings 跑 regression_pygoat.py。
- 结果摘要写进 archive/bench.json。
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _run_regression(dest: Path, name: str) -> int:
    """对归档 findings 跑 pygoat 回归断言（非 pygoat 目标跳过）。

    :param dest: 归档目录。
    :param name: 目标名。
    :return: 回归退出码（未运行返回 0）。
    """
    if "pygoat" not in name.lower():
        print(f"[bench] {name} 非 pygoat，跳过回归断言。")
        return 0
    script = Path(__file__).resolve().parents[1] / "scripts" / "regression_pygoat.py"
    findings = dest / "findings.json"
    print("=== 回归断言 ===")
    proc = subprocess.run([sys.executable, str(script), str(findings)],
                          capture_output=True, text=True)
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode


def main() -> int:
    """CLI 入口。"""
    ap = argparse.ArgumentParser(description="全流程基准：跑+归档+回归")
    ap.add_argument("--target", type=Path, required=True, help="目标项目路径")
    ap.add_argument("--name", default=None, help="归档名；默认 target 末段")
    ap.add_argument("--attempt-dynamic", action="store_true", default=False,
                    help="启用模块4 真实容器探针（较慢）")
    args = ap.parse_args()

    from scripts.run_bench import archive, run_stages

    name = args.name or args.target.resolve().name
    print(f"[bench] 开始全流程基准：{args.target} (name={name})")
    final_json, summary = run_stages(args.target, args.attempt_dynamic)
    dest = archive(name, final_json.parent, since=t0)

    # 摘要落盘
    (dest / "bench.json").write_text(
        json.dumps({"bench": name, "target": str(args.target.resolve()),
                    "run_at": datetime.now().isoformat(timespec="seconds"),
                    "summary": summary}, ensure_ascii=False, indent=2),
        encoding="utf-8")

    print("=== SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("archived:", dest)

    rc = _run_regression(dest, name)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
