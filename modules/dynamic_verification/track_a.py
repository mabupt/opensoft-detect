"""轨道A：Sink 调用记录器（track_a）。

"轨道A"策略：**无差别记录**所有命中 sink 的函数调用——无论参数是否带污点。
价值在于：只要 sink 被执行即证明该代码路径可达，且当轨道B 因污点标记在
传播中被清洗而丢失时，轨道A 仍然给出"执行到危险点"的旁证，触发 PoC 重试。

记录统一缓冲在 :attr:`SinkCallTracker._sink_calls` 列表，进程结束由
runner 导出为 JSON，避免被测代码内 IO 干扰执行路径。
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Optional


class SinkCallTracker:
    """进程内 sink 调用缓冲器（轨道A）。"""

    def __init__(self, max_records: int = 50_000) -> None:
        """构造记录器。

        :param max_records: 缓冲上限，超限丢弃最旧记录。
        """
        self.max_records: int = max_records
        self._sink_calls: list[dict[str, Any]] = []
        self._lock: threading.Lock = threading.Lock()
        self.current_finding_id: str = ""   # 探针执行期间由 runner 设置，给调用打标

    def record_sink(self, sink_name: str, args: tuple[Any, ...],
                    kwargs: Optional[dict[str, Any]] = None,
                    module: str = "", line: int = 0) -> None:
        """追加一条 sink 调用事件（轨道A，无差别记录）。

        :param sink_name: sink 限定名（如 subprocess.Popen / eval）。
        :param args: 位置实参。
        :param kwargs: 关键字实参。
        :param module: 触发模块名（可由包装器补充）。
        :param line: 触发行号（可空）。
        """
        rec: dict[str, Any] = {
            "sink_name": sink_name,
            "finding_id": self.current_finding_id,
            "ts": time.time(),
            "module": module,
            "line": line,
            # 只保存参数 repr 前 200 字符，防超大对象爆内存
            "args_repr": _repr_limited((args, kwargs or {})),
        }
        with self._lock:
            self._sink_calls.append(rec)
            if len(self._sink_calls) > self.max_records:
                del self._sink_calls[: len(self._sink_calls) - self.max_records]

    def calls(self) -> list[dict[str, Any]]:
        """返回全部记录（拷贝）。"""
        with self._lock:
            return list(self._sink_calls)

    def calls_for(self, finding_id: str) -> list[dict[str, Any]]:
        """筛出关联某 Finding 的记录。

        :param finding_id: Finding ID。
        :return: 记录列表。
        """
        return [c for c in self.calls() if c["finding_id"] == finding_id]

    def call_count(self) -> int:
        """当前缓冲条数。"""
        return len(self._sink_calls)

    def reset(self) -> None:
        """清空缓冲（新一轮测试前调用）。"""
        with self._lock:
            self._sink_calls.clear()

    def export(self, out_path: Path) -> str:
        """把记录导出为 JSON 落盘。

        :param out_path: 输出文件路径。
        :return: 写入路径字符串。
        """
        import json
        out_path = out_path.resolve()
        out_path.write_text(
            json.dumps(self.calls(), ensure_ascii=False, indent=2), encoding="utf-8")
        return str(out_path)


def _repr_limited(obj: Any, limit: int = 200) -> str:
    """安全 repr 并截断。"""
    try:
        text = repr(obj)
    except Exception:  # noqa: BLE001
        return "<unrepr>"
    return text if len(text) <= limit else text[:limit] + "..."
