"""静态工具调度与聚合（orchestrator）。

顺序调度各 AnalyzerBase（Semgrep / CodeQL / DepChecker），实现：
1. **可用性预检**：工具未安装的引擎直接跳过并记入 engine_results；
2. **失败隔离**：单个引擎异常被捕获记录，不影响其它引擎（降级运行）；
3. **合并去重**：跨引擎/跨批次结果合并，先按精确键去重，再对同位置跨工具重叠
   做"留高"折叠；
4. **统一落盘**：把结果与 engine_results 一起写入 ``output/findings.json``。

findings.json 顶层结构：::

    {
      "version": "1.0",
      "generated_at": "...",
      "manifest": "<file_manifest.json 路径>",
      "engine_results": [{"engine": "semgrep", "status": "ok", "findings": 3}, ...],
      "total_findings": 5,
      "findings": [ Finding.to_dict(), ... ]
    }
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import Config
from models import Finding, Severity, ToolName
from modules.static_analysis.base import AnalyzerBase

logger = logging.getLogger("opensoft_detect.static_analysis")


#: 跨工具折叠时的工具优先级（值越小越优先保留）
_TOOL_PRIORITY: dict[str, int] = {
    "codeql": 0,
    "semgrep": 1,
    "pip_audit": 2,
    "dynamic": 3,
    "llm": 4,
}
#: 严重程度排序（值越大越严重，用于排序与折叠）
_SEV_ORDER: dict[str, int] = {
    Severity.CRITICAL.value: 5, Severity.HIGH.value: 4, Severity.MEDIUM.value: 3,
    Severity.LOW.value: 2, Severity.INFO.value: 1,
}


class StaticOrchestrator:
    """调度全部静态分析器并聚合结果。"""

    def __init__(self, config: Config,
                 analyzers: Optional[list[AnalyzerBase]] = None) -> None:
        """构造调度器。

        未显式传入 analyzers 时，运行时按 is_available() 预检决定启用哪些引擎。

        :param config: 全局配置。
        :param analyzers: 自定义分析器列表（测试可注入 mock）。
        """
        self.config: Config = config
        self.analyzers: list[AnalyzerBase] = list(analyzers or [])
        self.engine_results: list[dict[str, Any]] = []
        self.last_manifest_path: Optional[Path] = None

    def register(self, analyzer: AnalyzerBase) -> None:
        """注册单个分析器。

        :param analyzer: 分析器实例。
        """
        self.analyzers.append(analyzer)

    def _default_analyzers(self) -> list[AnalyzerBase]:
        """构造默认三引擎（懒导入避免循环依赖）。

        :return: 分析器实例列表。
        """
        from modules.static_analysis.codeql_runner import CodeQLRunner
        from modules.static_analysis.dep_checker import DepChecker
        from modules.static_analysis.semgrep_runner import SemgrepRunner

        return [
            SemgrepRunner(self.config.tools),
            CodeQLRunner(self.config.tools),
            DepChecker(self.config.tools),
        ]

    def analyze_all(self, manifest_path: Path) -> list[Finding]:
        """运行全部启用引擎并合并结果。

        引擎失败/不可用时只记录，不中断整体。

        :param manifest_path: file_manifest.json 路径。
        :return: 合并后的全部 Finding（未排序去重，交给调用方）。
        """
        self.last_manifest_path = manifest_path
        engines: list[AnalyzerBase] = self.analyzers or self._default_analyzers()
        all_findings: list[Finding] = []
        self.engine_results = []

        for engine in engines:
            record: dict[str, Any] = {"engine": engine.tool.value, "status": "ok",
                                      "reason": "", "findings": 0}
            if not engine.is_available():
                record["status"] = "skipped"
                record["reason"] = "工具未安装或规则/可执行文件缺失"
                self.engine_results.append(record)
                continue
            try:
                batch = engine.run(manifest_path)
                batch = engine.post_process(batch)
                all_findings.extend(batch)
                record["findings"] = len(batch)
                # 引擎内部做了降级（子步骤失败但未完全崩溃）时如实反映状态
                if engine.last_error:
                    record["status"] = "partial" if len(batch) else "error"
                    record["reason"] = engine.last_error
                    logger.warning("引擎 %s 运行中有失败（%s），已降级产出 %d 条。",
                                   engine.tool.value, engine.last_error, len(batch))
                else:
                    logger.info("引擎 %s 完成，产出 %d 条。", engine.tool.value, len(batch))
            except Exception as exc:  # noqa: BLE001 - 失败隔离，不中断其它引擎
                record["status"] = "error"
                record["reason"] = f"{type(exc).__name__}: {exc}"
                logger.error("引擎 %s 执行异常（已降级跳过）：%s", engine.tool.value, exc,
                             exc_info=True)
            finally:
                engine.last_error = None   # 复位，避免污染下次运行
            self.engine_results.append(record)
        return all_findings

    def save_findings(self, findings: list[Finding], out_path: Path) -> str:
        """把去重排序后的结果与 engine_results 一起落盘。

        :param findings: 待写出的 Finding。
        :param out_path: 输出文件路径。
        :return: 写入完成的绝对路径字符串。
        """
        out_path = out_path.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "version": "1.0",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "manifest": str(self.last_manifest_path) if self.last_manifest_path else "",
            "engine_results": self.engine_results,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        out_path.write_text(
            __import__("json").dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("统一 findings 已写入：%s（共 %d 条）", out_path, len(findings))
        return str(out_path)


# ---------------------------------------------------------------------------
# 去重 / 排序
# ---------------------------------------------------------------------------

def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """先按精确键去重，再对"同文件同行列"的跨工具重叠做留高折叠。

    第 2 步针对 Semgrep 与 CodeQL 常命中同一 sink 的现实：
    保留严重程度更高的；同级时按工具优先级（CodeQL > Semgrep）保留。

    :param findings: 原始 Finding 列表。
    :return: 去重后的列表。
    """
    # 1) 精确去重：同一 (tool,file,rule,line)
    by_key: dict[str, Finding] = {}
    for f in findings:
        k = f.dedupe_key()
        if k not in by_key:
            by_key[k] = f

    # 2) 位置重叠折叠：file + start_line + start_col
    #    只对代码类引擎(codeql/semgrep)生效——它们同位置多为同一 sink 的重复告警；
    #    pip_audit 依赖漏洞 location 是合成(第1行)，绝不能按位置折叠，只做精确去重。
    keep: list[Finding] = []
    folded: set[int] = set()  # id() 集合防重
    by_loc: dict[tuple, list[Finding]] = {}
    for f in by_key.values():
        if f.tool in (ToolName.CODEQL, ToolName.SEMGREP) and f.location is not None:
            loc_key = (f.file_path, f.location.start_line, f.location.start_col)
            by_loc.setdefault(loc_key, []).append(f)
        else:
            # 依赖漏洞 / 无位置发现：直接保留
            if id(f) not in folded:
                keep.append(f)
                folded.add(id(f))
    for group in by_loc.values():
        if len(group) == 1:
            keep.append(group[0])
            continue
        # 留高：severity 排序，其次工具优先级
        group.sort(key=lambda x: (-_SEV_ORDER.get(x.severity.value, 0),
                                  _TOOL_PRIORITY.get(x.tool.value, 9)))
        winner = group[0]
        if id(winner) not in folded:
            keep.append(winner)
            folded.add(id(winner))
    return keep


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """稳定排序：严重程度降序，其次文件路径字典序。

    :param findings: Finding 列表。
    :return: 排序后的新列表。
    """
    return sorted(
        findings,
        key=lambda f: (-_SEV_ORDER.get(f.severity.value, 0), f.file_path),
    )
