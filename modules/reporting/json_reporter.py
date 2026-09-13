"""JSON 报告写出（json_reporter）。

把组装好的 report 字典序列化为机器可读的 ``output/final_report.json``。
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("opensoft_detect.reporting.json")


class JsonReporter:
    """将 report 字典落盘为 JSON。"""

    def __init__(self, pretty: bool = True, ensure_ascii: bool = False) -> None:
        """构造写出器。

        :param pretty: 是否缩进美化。
        :param ensure_ascii: 是否强制 ASCII。
        """
        self.pretty: bool = pretty
        self.ensure_ascii: bool = ensure_ascii

    def dump(self, report: dict[str, Any], out_path: Path) -> str:
        """写出 report。

        :param report: 报告字典。
        :param out_path: 输出 .json 路径。
        :return: 绝对路径字符串。
        """
        out_path = out_path.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(report, ensure_ascii=self.ensure_ascii,
                       indent=2 if self.pretty else None, default=self.default_encoder),
            encoding="utf-8")
        logger.info("final_report.json 已写入：%s", out_path)
        return str(out_path)

    @staticmethod
    def default_encoder(obj: Any) -> Any:
        """把 Path/Enum/dataclass 等转成可序列化表示。"""
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        raise TypeError(f"Type {type(obj).__name__} not serializable")

    @staticmethod
    def read(path: Path) -> dict[str, Any]:
        """读取报告 JSON。"""
        return json.loads(path.read_text(encoding="utf-8"))
