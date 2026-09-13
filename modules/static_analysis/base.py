"""分析器抽象基类。

为 Semgrep / CodeQL / DepChecker 定义统一的 :class:`AnalyzerBase` 接口，
使 orchestrator 可以无差别地调度、聚合各类分析器，并对"引擎缺失/调用失败"
做统一的降级处理。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from config import ToolConfig
from models import Finding, ToolName


class AnalyzerBase(ABC):
    """静态分析器统一接口。

    约定：
    - :meth:`is_available` 在调度前判定本机是否具备运行条件（工具未安装则直接跳过，
      并写入 engine_results 表明未运行原因）；
    - :meth:`run` 是真正执行分析的方法，**必须自行捕获并记录异常**，让单引擎
      失败不影响其它引擎（由 orchestrator 统一封装也可，这里两者都兜底）。
    """

    #: 工具标识（写入 Finding.tool）
    tool: ToolName = ToolName.SEMGREP

    def __init__(self, tool_cfg: ToolConfig) -> None:
        """构造分析器。

        :param tool_cfg: 全局 ToolConfig（可执行文件路径、超时、规则目录等）。
        """
        self.tool_cfg: ToolConfig = tool_cfg
        self.last_error: Optional[str] = None   # run() 内部降级失败时由子类记录，供 orchestrator 上报

    def is_available(self) -> bool:
        """当前环境是否具备运行本引擎的条件（工具存在/规则齐备）。

        子类应尽量做轻量探测（如 ``shutil.which``、文件存在性），避免启动重型进程。
        默认实现返回 True，供无前置条件的子类沿用。

        :return: True 表示可运行。
        """
        return True

    @abstractmethod
    def run(self, manifest_path: Path) -> list[Finding]:
        """基于清单运行本分析器，返回归一化的 Finding 列表。

        实现者应当：
        1. 只针对 manifest 的 ``scan_scope`` 做扫描（保证与模块0 过滤一致）；
        2. 内部 try/except 捕获子进程异常并 ``logger.error`` 记录后返回空列表
           （由 orchestrator 再做一次整体兜底）。

        :param manifest_path: 模块0产出的 file_manifest.json 路径。
        :return: 漏洞发现列表（引擎失败时返回空列表）。
        """
        raise NotImplementedError

    def post_process(self, findings: list[Finding]) -> list[Finding]:
        """统一的发现后处理钩子（默认透传，子类可覆写）。

        可在此修正置信度初值 / 过滤明显噪音。

        :param findings: run() 返回的原始发现。
        :return: 处理后的发现列表。
        """
        return findings
