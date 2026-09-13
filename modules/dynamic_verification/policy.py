"""类别化断言 oracle（policy）。

与"污点双轨"正交的一层：某些漏洞类别**不是"脏数据到达危险调用"**的形状，
用 canary 永远测不到（例如弱哈希：明文经哈希后内容消失）。对这些类别，
在运行时直接断言"策略违规"更合适：

- **weak_hash**：调用了 md5/sha1（或 ``hashlib.new('md5')`` / ``pbkdf2_hmac('sha1')``）
  —— 命中即该类别的 vuln 成立（附加证据：入参是否来自请求/污点）。
- 预留扩展：明文日志（logging 收到 tainted 明文）、不安全随机、禁用校验等。

命中记为 hits，供 runner 归类为 confirmed（evidence.kind='policy'）。
通用实现，不针对特定项目。
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from modules.dynamic_verification.track_b import sink_args_tainted

logger = logging.getLogger("opensoft_detect.dynamic_verification.policy")

#: 视为弱的哈希算法
WEAK_HASH_ALGOS: frozenset[str] = frozenset({"md5", "sha1", "sha", "md2", "md4"})


class PolicyChecker:
    """策略断言收集器（按类别注册规则）。"""

    def __init__(self) -> None:
        """构造检查器。"""
        self._hits: list[dict[str, Any]] = []
        self._counter: int = 0

    # ------------------------------------------------------------------
    def check(self, sink_name: str, args: tuple[Any, ...],
              kwargs: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """在 sink 包装器里调用：按类别断言策略违规。

        :param sink_name: 被包装的函数名（md5/sha1/new/pbkdf2_hmac/…）。
        :param args: 位置实参。
        :param kwargs: 关键字实参。
        :return: 本次命中的记录列表。
        """
        out: list[dict[str, Any]] = []
        algo: Optional[str] = None
        if sink_name in ("md5", "sha1"):
            algo = sink_name
        elif sink_name in ("new", "pbkdf2_hmac") and args:
            algo = str(args[0]).strip().lower()
        if algo and algo in WEAK_HASH_ALGOS:
            out.append(self._record("weak_hash",
                                    f"使用弱哈希算法 {algo}",
                                    sink_name, args, kwargs, extra={"algorithm": algo}))
        self._hits.extend(out)
        return out

    def _record(self, policy: str, detail: str, sink_name: str,
                args: tuple[Any, ...], kwargs: Optional[dict[str, Any]],
                extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """构造一条策略违规记录。"""
        try:
            tainted = sink_args_tainted(args, kwargs)
        except Exception:  # noqa: BLE001
            tainted = []
        rec: dict[str, Any] = {
            "policy": policy,
            "detail": detail,
            "sink_name": sink_name,
            "tainted_input": bool(tainted),
            "seq": self._counter,
        }
        if extra:
            rec.update(extra)
        self._counter += 1
        return rec

    # ------------------------------------------------------------------
    def hits(self) -> list[dict[str, Any]]:
        """返回全部命中（拷贝）。"""
        return list(self._hits)

    def hit_count(self) -> int:
        """命中数。"""
        return len(self._hits)

    def reset(self) -> None:
        """清空（每轮探针前调用）。"""
        self._hits.clear()
        self._counter = 0
