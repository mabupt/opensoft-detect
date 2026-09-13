"""pygoat 关键视图回归断言。

对 findings.json（含 codeql/semgrep/pip-audit 去重结果）断言"每个预期的关键漏洞视图
都必须至少命中一类检出规则"。防止改规则/引擎后对靶场召回回退。

用法：:

    rag_env\\Scripts\\python.exe scripts\\regression_pygoat.py [findings.json]

预期映射：视图函数名 -> 命中该函数的检出需要匹配的规则子串（任一即可）。
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

#: 关键意图漏洞视图 -> 期望命中规则的子串（任一命中即算通过）
#: 来源：introduction/urls.py 路由 + views.py 漏洞函数 + 实测检出规则
EXPECTED: dict[str, list[str]] = {
    "cmd_lab": ["command-line-injection", "request-to-dangerous"],
    "cmd_lab2": ["code-injection", "eval-usage", "request-to-dangerous"],
    "sql_lab": ["sql-injection"],
    "injection_sql_lab": ["sql-injection"],
    "insec_des_lab": ["unsafe-deserialization"],
    "a9_lab2": ["request-to-dangerous"],   # ImageMath.eval（规则补强后须命中）
    "xxe_parse": ["xxe"],
    "ssrf_lab": ["path-injection", "full-ssrf", "request-to-dangerous"],
    "a1_broken_access_lab_1": ["clear-text-logging"],
    "auth_lab_login": ["clear-text-logging", "client-exposed-cookie"],
}


def _views_func_map(views_path: Path) -> dict[str, tuple[int, int]]:
    """views.py 函数名 -> (start, end)。"""
    tree = ast.parse(views_path.read_text(encoding="utf-8"))
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef):
            out[n.name] = (n.lineno, getattr(n, "end_lineno", n.lineno))
    return out


def main() -> int:
    """断言入口。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", nargs="?", default="output/findings.json")
    ap.add_argument("--views", default="test/goat/pygoat-master/pygoat-master/introduction/views.py")
    args = ap.parse_args()

    raw = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    findings = raw.get("findings") if isinstance(raw, dict) else raw
    views = Path(args.views)
    fmap = _views_func_map(views)

    # 找出 views.py 内每个命中行所属函数 -> 命中规则集合
    func_rules: dict[str, set[str]] = {}
    for f in findings:
        fp = Path(f["file_path"])
        if fp.resolve() != views.resolve():
            continue
        line = f["location"]["start_line"]
        owner = None
        for name, (s, e) in fmap.items():
            if s <= line <= e and (owner is None
                                   or e - s < fmap[owner][1] - fmap[owner][0]):
                owner = name
        if owner:
            func_rules.setdefault(owner, set()).add(f["rule_id"])

    fails: list[str] = []
    for fn, needles in EXPECTED.items():
        rules = func_rules.get(fn, set())
        hit = any(any(nd in r for nd in needles) for r in rules)
        status = "PASS" if hit else "FAIL"
        print(f"  [{status}] {fn:<22} rules={sorted(rules)[:4]}")
        if not hit:
            fails.append(fn)

    if fails:
        print(f"\n回归失败（{len(fails)} 个关键视图未命中）：{fails}")
        return 1
    print(f"\n回归通过：{len(EXPECTED)} 个关键视图全部命中。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
