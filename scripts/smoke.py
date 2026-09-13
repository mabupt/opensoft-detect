"""冒烟自检：不依赖外部引擎/服务即可运行（供 CI 与本地快速回归）。

检查项：
1. 全部子模块可导入（本项目第三方依赖均为延迟导入，故无需安装即可通过）；
2. 关键纯函数行为正确（预过滤强消毒识别、守卫检测、置信度分级与误报率口径）。

用法：``python scripts/smoke.py``（失败返回非 0）。
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def check_imports() -> list[str]:
    """导入 modules 包下全部子模块。

    :return: 失败信息列表（空表示全部通过）。
    """
    import modules
    failures: list[str] = []
    names = [m.name for m in pkgutil.walk_packages(modules.__path__, "modules.")]
    for name in names:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - 冒烟需汇总全部失败
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    print(f"[smoke] 模块导入：{len(names)} 个，失败 {len(failures)}")
    return failures


def check_key_functions() -> list[str]:
    """校验不依赖外部服务的核心纯函数行为。

    :return: 失败信息列表（空表示全部通过）。
    """
    failures: list[str] = []

    def expect(cond: bool, msg: str) -> None:
        if not cond:
            failures.append(msg)

    # 1) 预过滤：命中行使用强消毒函数时应确定性判为已防护
    from config import Config
    from models import (Finding, Location, Severity, ToolName,
                        VulnerabilityStatus)
    from modules.llm_analysis.prefilter import Prefilter
    pre = Prefilter(Config())
    sanitized = Finding(id="smoke-1", tool=ToolName.CODEQL, rule_id="r", message="m",
                        file_path="a.py", severity=Severity.HIGH,
                        location=Location(file_path="a.py", start_line=1, end_line=1,
                                          snippet="p = secure_filename(name)"))
    expect(pre._has_strong_sanitizer(sanitized) is True,
           "预过滤未识别 secure_filename")

    # 2) 守卫检测：切片含包含性校验时应命中
    from modules.llm_analysis.fp_judge import detect_guard_in_context
    expect(bool(detect_guard_in_context("if is_path_inside(f, base): ...")) is True,
           "守卫检测未命中 is_path_inside")

    # 3) 误报率口径：FP/(TP+FP)，且含分引擎统计
    from modules.reporting.stats import compute_fp_rate

    def mk(status: VulnerabilityStatus, tool: ToolName) -> Finding:
        """构造带指定状态的 Finding（四级置信度由 status 推导）。"""
        loc = Location(file_path="a.py", start_line=1, end_line=1)
        f = Finding(id=f"{tool.value}-{status.value}", tool=tool, rule_id="r", message="m",
                    file_path="a.py", location=loc, severity=Severity.HIGH)
        f.status = status
        return f

    rated = [mk(VulnerabilityStatus.DYNAMIC_CONFIRMED, ToolName.CODEQL),   # -> confirmed
             mk(VulnerabilityStatus.FALSE_POSITIVE, ToolName.CODEQL),      # -> excluded
             mk(VulnerabilityStatus.TRUE_POSITIVE, ToolName.PIP_AUDIT)]    # -> high_suspicious
    fp = compute_fp_rate(rated)
    expect(fp["true_positives"] == 2 and fp["false_positives"] == 1,
           f"误报率口径异常：TP={fp['true_positives']} FP={fp['false_positives']}")
    expect(fp["false_positive_rate"] == round(1 / 3, 4),   # 统计口径保留 4 位小数
           f"误报率数值异常：{fp['false_positive_rate']}")
    expect(fp["by_engine"]["codeql"]["false_positive_rate"] == 0.5,
           "分引擎误报率异常")

    # 4) 配置快照必须脱敏（不得回写明文密钥）
    from config import ConfigLoader
    expect("api_key" in ConfigLoader._SECRET_KEYS, "密钥脱敏字段集缺失 api_key")
    redacted = {"llm": {"api_key": "sk-secret"}}
    ConfigLoader._redact(redacted)
    expect("sk-secret" not in str(redacted), "配置快照未脱敏")

    print(f"[smoke] 关键函数断言：{4 - len(failures)}/4 通过")
    return failures


def main() -> int:
    """入口：跑完全部检查并汇总。

    :return: 进程退出码（0=通过）。
    """
    failures = check_imports() + check_key_functions()
    if failures:
        print("\n[smoke] 失败项：")
        for item in failures:
            print("  -", item)
        return 1
    print("[smoke] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
