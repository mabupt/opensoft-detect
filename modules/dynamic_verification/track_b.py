"""轨道B：污点标记检测（track_b）。

"轨道B"策略：**只有当 sink 参数携带污点标记时**才算漏洞实锤。
运行时污点分析（Dynamic Taint Analysis）在本模块落地为三件事：

1. **打标**：source（如 request.args.get 返回值）由 PoC/补丁包装器调用
   :func:`mark_tainted` 标记为污点值；
2. **传递中的识别**：sink 包装器在调用真实函数前，用 :func:`sink_args_tainted`
   检查每个实参是否带 ``__TAINT_`` 前缀的标记（见 :func:`is_tainted`）；
3. **判定物**：命中的实参记入 TaintChecker 的 ``_taint_hits`` 列表，
   供上层做 confirmed / retry_poc / rejected 三态判定。

标记载体：
- 可变对象/自定义类：进程内 id 注册表 + 允许打属性时写 ``__TAINT_<源>__`` 属性；
- 不可变 str：提供 :class:`TaintedString`（str 子类 + ``__TAINT_source__`` 属性，
  与普通 str 相等性/哈希一致），用于 source 点注入兜底。
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

logger = logging.getLogger("opensoft_detect.dynamic_verification.track_b")

#: 污点标记属性前缀（规格约定 __TAINT_xxx__）
TAINT_PREFIX: str = "__TAINT_"
#: str 子类上携带来源的固定属性名
_TAINT_ATTR: str = "__TAINT_source__"

#: 进程内 id 注册表（可变对象无法打属性时的兜底）
_taint_registry: dict[int, str] = {}
_registry_lock: threading.Lock = threading.Lock()


class TaintedString(str):
    """带污点来源标记的 str 子类。

    保留 str 的全部行为（哈希/相等/切片/join 都正常），仅额外携带来源标记，
    便于 source 注入兜底时仍然能通过 `== 'xxx'` 之类的正常代码路径。
    """

    __slots__ = (_TAINT_ATTR,)

    def __new__(cls, value: str, source: str = "") -> "TaintedString":
        """构造并打标。

        :param value: 字符串内容。
        :param source: 污点来源描述。
        """
        obj = str.__new__(cls, value)
        obj.__TAINT_source__ = source      # type: ignore[attr-defined]
        return obj


class TaintedBytes(bytes):
    """带污点来源标记的 bytes 子类。

    bytes 是可变槽位的 C 类型，不能声明非空 ``__slots__``，也不能动态打属性；
    因此来源记在类级 id 注册表（对象生命周期短暂，配合短促的 sink 调用足够）。
    """

    __slots__ = ()          # bytes 子类只允许空 slots

    #: id(TaintedBytes) -> source
    _sources: dict[int, str] = {}

    def __new__(cls, value: bytes, source: str = "") -> "TaintedBytes":
        """构造并登记来源。"""
        obj = bytes.__new__(cls, value)
        cls._sources[id(obj)] = source
        return obj

    @classmethod
    def source_of(cls, obj: "TaintedBytes") -> str:
        """查询来源。"""
        return cls._sources.get(id(obj), "tainted_bytes")


# ---------------------------------------------------------------------------
# 打标 / 检测（供 source/sink 包装器调用）
# ---------------------------------------------------------------------------

def mark_tainted(obj: Any, source: str = "source") -> Any:
    """给对象打污点标记，返回原对象（便于链式调用）。

    优先写入属性（自定义类）；str/bytes 走带标记子类；其它不可打属性对象走 id 注册表。

    :param obj: 目标对象。
    :param source: 来源描述。
    :return: 原对象（或带标记的 str/bytes 子类）。
    """
    if obj is None:
        return obj
    if isinstance(obj, TaintedString):
        obj.__TAINT_source__ = source       # type: ignore[attr-defined]
        return obj
    if isinstance(obj, TaintedBytes):
        return obj                          # 来源已在构造时登记，无需再打标
    if isinstance(obj, str):
        return TaintedString(obj, source)
    if isinstance(obj, bytes):
        return TaintedBytes(obj, source)
    if hasattr(obj, "__dict__") and not isinstance(obj, (int, float, tuple, frozenset)):
        try:
            setattr(obj, f"{TAINT_PREFIX}{_slug(source)}", True)
            return obj
        except (AttributeError, TypeError):
            pass
    with _registry_lock:
        _taint_registry[id(obj)] = source
    return obj


def is_tainted(obj: Any) -> bool:
    """判断对象是否携带污点标记（三种途径）。

    :param obj: 目标对象。
    :return: True 表示带污点。
    """
    if obj is None:
        return False
    # 1) str/bytes 子类标记属性
    if isinstance(obj, (TaintedString, TaintedBytes)):
        return True
    # 2) 允许打属性的对象上的 __TAINT_ 前缀属性
    try:
        if any(k.startswith(TAINT_PREFIX) for k in vars(obj)):
            return True
    except TypeError:
        pass
    # 3) id 注册表
    with _registry_lock:
        return id(obj) in _taint_registry


def taint_source_of(obj: Any) -> Optional[str]:
    """返回对象污点来源描述；无标记返回 None。"""
    if obj is None:
        return None
    if isinstance(obj, TaintedString):
        src: Optional[str] = getattr(obj, _TAINT_ATTR, None)
        return src or "tainted_value"
    if isinstance(obj, TaintedBytes):
        return TaintedBytes.source_of(obj)
    try:
        for k, v in vars(obj).items():
            if k.startswith(TAINT_PREFIX):
                return str(v) if v is not True else k[len(TAINT_PREFIX):]
    except TypeError:
        pass
    with _registry_lock:
        return _taint_registry.get(id(obj))


def sink_args_tainted(args: tuple[Any, ...],
                      kwargs: Optional[dict[str, Any]] = None) -> list[tuple[str, str]]:
    """扫描 sink 实参，返回所有带污点的 (位置描述, 来源)。

    这是轨道B 在 sink 入口的检测入口。

    :param args: 位置实参。
    :param kwargs: 关键字实参。
    :return: [("args[0]", "request.args.get('id'"), ...]。
    """
    hits: list[tuple[str, str]] = []
    for i, a in enumerate(args):
        if is_tainted(a):
            hits.append((f"args[{i}]", taint_source_of(a) or ""))
    for key, val in (kwargs or {}).items():
        if is_tainted(val):
            hits.append((f"kwargs[{key}]", taint_source_of(val) or ""))
    return hits


def _slug(text: str) -> str:
    """把来源文本转成可做属性名的短标识。"""
    return "".join(c for c in text if c.isalnum() or c == "_")[:40] or "src"


def reset_taint() -> None:
    """清空标记（新一轮测试前调用）。"""
    with _registry_lock:
        _taint_registry.clear()


def _iter_scalar(args: tuple[Any, ...],
                 kwargs: Optional[dict[str, Any]] = None):
    """递归产出实参里的字符串标量及其路径描述（含 tuple/list/dict 值）。

    :param args: 位置实参。
    :param kwargs: 关键字实参。
    :return: 生成 (路径描述, 字符串标量)，供 canary 相等/包含比对。
    """
    def walk(val: Any, pos: str) -> Any:
        if isinstance(val, bytes):
            yield pos, bytes(val).decode("utf-8", "ignore")
        elif isinstance(val, str):
            yield pos, val
        elif isinstance(val, (list, tuple, set)):
            for i, item in enumerate(val):
                yield from walk(item, f"{pos}[{i}]")
        elif isinstance(val, dict):
            for k, v in val.items():
                yield from walk(v, f"{pos}.{k}")

    for i, a in enumerate(args):
        yield from walk(a, f"args[{i}]")
    for k, v in (kwargs or {}).items():
        yield from walk(v, f"kwargs[{k}]")


class TaintChecker:
    """轨道B 检测器：记录所有"污点到达 sink"的命中。"""

    def __init__(self) -> None:
        """构造检测器。"""
        self._taint_hits: list[dict[str, Any]] = []
        self._counter: int = 0
        # 内容水印令牌集合：str 拼接/解码会丢失对象标记，但注入的随机令牌会以
        # 子串形式存活到 sink 参数里，可作为"数据流到达"的兜底判据
        self._canaries: set[str] = set()

    def add_canary(self, token: str) -> None:
        """注册一个内容水印令牌（探针在发送请求前调用）。

        :param token: 令牌文本（应具有唯一性）。
        """
        if token:
            self._canaries.add(token)

    def check_at_sink(self, sink_name: str, args: tuple[Any, ...],
                      kwargs: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """在 sink 入口执行轨道B 检查，命中则记录。

        命中来源两类：
        1. 对象级污点标记（TaintedString/TaintedBytes/注册表/属性）；
        2. **内容水印**：某 str/bytes 实参包含已注册 canary 令牌
           （应对拼接等使对象标记丢失的清洗场景）。

        :param sink_name: sink 限定名。
        :param args: 位置实参。
        :param kwargs: 关键字实参。
        :return: 本次命中的记录列表（未命中为空）。
        """
        hits: list[tuple[str, str]] = sink_args_tainted(args, kwargs)
        # 内容水印扫描：递归检查实参（含容器内元素）与令牌"相等或包含"
        if self._canaries:
            for token in self._canaries:
                for pos, leaf in _iter_scalar(args, kwargs):
                    if leaf == token:
                        hits.append((f"canary_equal:{pos}", token))
                    elif token in leaf:
                        hits.append((f"canary_sub:{pos}", token))

        records: list[dict[str, Any]] = []
        for pos, src in hits:
            rec: dict[str, Any] = {
                "sink_name": sink_name,
                "arg": pos,
                "source": src,
                "marker": f"{TAINT_PREFIX}{_slug(src)}__",
                "seq": self._counter,
            }
            self._counter += 1
            self._taint_hits.append(rec)
            records.append(rec)
        return records

    def hits(self) -> list[dict[str, Any]]:
        """返回已记录的全部轨道B 命中。

        :return: 命中列表（拷贝）。
        """
        return list(self._taint_hits)

    def hit_count(self) -> int:
        """轨道B 命中次数。"""
        return len(self._taint_hits)

    def reset(self) -> None:
        """清空命中（新一轮测试前调用）。"""
        self._taint_hits.clear()
        self._counter = 0
