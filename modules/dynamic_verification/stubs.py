"""通用缺包桩（stubs）。

动态探针常因目标应用依赖缺失（某第三方库未装/装不上）而导入失败、跑不起来。
本模块提供一个**宽容的 import 兜底**：在 ``sys.meta_path`` 末尾注册 Finder，
仅当所有正常 Finder 都失败时，为缺失模块伪造一个"任何属性都存在、可调用"
的占位模块，让应用能继续启动/加载。

定位与边界：
- 放在 meta_path **末尾**：真实模块优先，绝不遮蔽已装的库；
- 仅用于**动态测试沙箱**，不是生产特性；缺库行为可能与真实不一致，
  因此 findings 里会保留"stubbed 模块清单"以便人工判断可信度。
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec
from types import ModuleType
from typing import Any, Optional

#: 记录被伪造的模块名（供探针输出，提示结果可信度）
STUBBED: list[str] = []


class _Any(BaseException):
    """万能占位对象：任何属性/调用/迭代都返回自身（或空），**且在任何语法位置都不炸**。

    为什么继承 ``BaseException``：缺失依赖的占位符常被用在
    "异常类"位置（``except <missing>.Error:`` / ``raise``），而 Python 只接受
    ``BaseException`` 子类；同时它又常被用在"类型"位置（``class X(<missing>.Cls)``、
    ``isinstance(x, <missing>.Cls)``）。这些位置若抛 ``TypeError``，会把一个
    "缺个可选依赖"的小问题放大成应用完全起不来。

    因此这里把两类位置都兜住：
    - 类型位置：``__mro_entries__`` 退化到 ``(object,)``、``__instancecheck__`` /
      ``__subclasscheck__`` 一律返回 True；
    - 异常位置：本身即 ``BaseException`` 子类。

    实测踩坑（通用，非特化某库）：``urllib3 1.26`` 的 vendored ``six.moves``、
    ``requests.compat`` 的 ``import simplejson`` 回退分支，都会把占位对象绑到
    基类位置，未兜住时报 ``TypeError: __mro_entries__ must return a tuple``。
    """

    #: 必须是**字符串**：框架/标准库普遍做 f"{obj.__module__}.{obj.__name__}"
    #: （如 Django `lookup_str`、logging、inspect、pickle），返回占位对象会直接抛
    #: ``TypeError: can only concatenate str (not "_Any") to str``。
    __module__ = "opensoft_stub"
    __name__ = "stub"
    __qualname__ = "stub"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __call__(self, *args: Any, **kwargs: Any) -> "_Any":
        return _Any()

    def __getattr__(self, name: str) -> "_Any":
        return _Any()

    def __getitem__(self, item: Any) -> "_Any":
        """泛型下标（如 ``<missing>.Type[int]``）不炸。"""
        return _Any()

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return 0

    def __bool__(self) -> bool:
        return True

    def __str__(self) -> str:
        return ""

    # ---- 被误当"类型/类"使用时的退化钩子（否则抛 TypeError）----
    def __mro_entries__(self, bases: Any) -> tuple:
        """作为类基类时**整体丢弃**该基类（``class X(<missing>.Cls)`` 不炸）。

        必须返回空元组而不是 ``(object,)``：否则基类列表里插进一个 ``object``
        会破坏 MRO 线性化，例如 ``class CBaseLoader(CParser, BaseConstructor,
        BaseResolver)``（PyYAML 缺 ``_yaml`` C 扩展时）会报
        ``Cannot create a consistent method resolution order``。
        空元组是 CPython 明确支持的写法（等价于该基类不存在）。
        """
        return ()

    def __instancecheck__(self, instance: Any) -> bool:
        """``isinstance(x, <missing>.Cls)`` -> True。"""
        return True

    def __subclasscheck__(self, subclass: Any) -> bool:
        """``issubclass(X, <missing>.Cls)`` -> True。"""
        return True


class _StubLoader(Loader):
    """把缺失模块加载为带 ``__getattr__`` 的占位模块。"""

    def create_module(self, spec: ModuleSpec) -> Optional[ModuleType]:
        mod = ModuleType(spec.name)
        mod.__dict__["__all__"] = []

        def _getattr(name: str) -> Any:  # PEP 562 模块级 __getattr__
            return _Any()

        mod.__dict__["__getattr__"] = _getattr
        mod.__dict__["__path__"] = []          # 允许子模块导入
        STUBBED.append(spec.name)
        return mod

    def exec_module(self, module: ModuleType) -> None:
        return None


class PermissiveStubFinder(MetaPathFinder):
    """位于 meta_path 末尾的宽容 Finder。"""

    def find_spec(self, fullname: str, path=None, target=None) -> Optional[ModuleSpec]:
        """为走投无路的缺失模块返回占位 spec；有别的 finder 认领则让位。

        :param fullname: 模块全名。
        :param path: 父包路径。
        :param target: 目标模块。
        :return: 伪造的 ModuleSpec，或 None（让位/内部模块）。
        """
        # 顶层内部模块（本工程/标准前置）不伪造：交由导入系统报真实错误
        if fullname.split(".")[0] in ("modules", "__main__"):
            return None
        # 关键：排在我们**之后**的 finder 优先（见 _claimed_by_later_finder 的说明）
        if self._claimed_by_later_finder(fullname, path, target):
            return None
        return ModuleSpec(fullname, _StubLoader(), is_package=True)

    def _claimed_by_later_finder(self, fullname: str, path=None, target=None) -> bool:
        """是否有 meta_path 上排在本 finder 之后的其他 finder 能提供该模块。

        为什么需要："在 meta_path 末尾"并不等于"最后被询问"——有些库（如 six.moves、
        各类 lazy/namespace 加载器）是在**自己被导入时**才把自己的 finder
        ``append`` 到 ``sys.meta_path`` 尾部，于是排到了我们后面。若此时我们抢先伪造，
        这些库的 lazy 属性就会变成 ``_Any``：典型后果是
        ``class IncompleteRead(HTTPError, httplib_IncompleteRead)`` 抛
        ``TypeError: __mro_entries__ must return a tuple``（urllib3 1.26 + vendored six）。
        因此这里主动询问并让位，保证"真实实现优先"的语义。

        :param fullname: 模块全名。
        :param path: 父包路径。
        :param target: 目标模块。
        :return: True 表示应让位（不伪造）。
        """
        try:
            idx = sys.meta_path.index(self)
        except ValueError:
            return False
        for finder in sys.meta_path[idx + 1:]:
            if finder is self:
                continue
            try:
                spec_fn = getattr(finder, "find_spec", None)
                if spec_fn is not None:
                    if spec_fn(fullname, path, target) is not None:
                        return True
                    continue
                # legacy 协议（six 等）：find_module(fullname, path)
                mod_fn = getattr(finder, "find_module", None)
                if mod_fn is not None and mod_fn(fullname, path) is not None:
                    return True
            except Exception:  # noqa: BLE001 - 个别 finder 对陌生名字会抛错
                continue
        return False


_active: Optional[PermissiveStubFinder] = None


def install_attr_fallback_for(module: ModuleType) -> None:
    """给**真实模块**补 PEP 562 ``__getattr__``：缺失属性返回占位对象。

    场景（通用）：被测工程自身有导入瑕疵，例如 ``from .main import Log`` 而
    ``main.py`` 是空文件/被删/名字写错。这会抛 ``ImportError``，若发生在
    Django ``urls.py`` 之类的**导入链关键节点**上，会让整个应用起不来（所有路由 500），
    动态验证直接失效——一个"少个名字"的小瑕疵放大成"应用不可用"。

    沙箱内的取舍：宁可给占位对象也要把应用拉起来（被占位的名字记入 ``STUBBED``，
    供人工判断结果可信度）。模块自身的 ``__getattr__`` 优先，不覆盖。

    :param module: 目标模块（须为普通 Python 模块，可变 ``__dict__``）。
    """
    d = getattr(module, "__dict__", None)
    if not isinstance(d, dict):
        return
    if "__getattr__" in d or d.get("__opensoft_attr_fallback__"):
        return

    def _getattr(name: str) -> Any:  # PEP 562
        STUBBED.append(f"{getattr(module, '__name__', '?')}.{name}")
        return _Any()

    try:
        d["__getattr__"] = _getattr
        d["__opensoft_attr_fallback__"] = True
    except Exception:  # noqa: BLE001 - C 扩展模块等不可写
        return


def _resolve_abs_name(name: str, globals_: Any, level: int) -> Optional[str]:
    """把 ``__import__`` 的 (name, level) 解析为绝对模块名（含相对导入）。"""
    if not level:
        return name
    pkg = None
    if isinstance(globals_, dict):
        pkg = globals_.get("__package__") or globals_.get("__name__")
    try:
        return importlib.util.resolve_name("." * level + name, pkg)
    except Exception:  # noqa: BLE001
        return None


def install_import_fallback() -> None:
    """包装 ``builtins.__import__``：``from X import Y`` 失败时兜底重试（幂等）。

    只在**已经失败**的 from-import 上介入（正常导入零影响）：
    若 ``X`` 已在 ``sys.modules``（真实模块）而 ``Y`` 取不到，就给 ``X`` 装上
    缺属性占位（见 :func:`install_attr_fallback_for`）后重试一次。
    """
    global _import_fallback_installed, _orig_import
    if _import_fallback_installed:
        return
    import builtins as _builtins

    _orig_import = _builtins.__import__

    def _import(name: str, globals_: Any = None, locals_: Any = None,
                fromlist: Any = (), level: int = 0) -> Any:
        try:
            return _orig_import(name, globals_, locals_, fromlist, level)
        except ImportError:
            if not fromlist:
                raise
            abs_name = _resolve_abs_name(name, globals_, level) or name
            if abs_name.split(".")[0] in ("modules", "__main__"):
                raise
            mod = sys.modules.get(abs_name)
            if mod is None:
                raise
            install_attr_fallback_for(mod)
            return _orig_import(name, globals_, locals_, fromlist, level)

    _builtins.__import__ = _import
    _import_fallback_installed = True


_import_fallback_installed: bool = False
_orig_import: Any = None


def install_stub_finder() -> PermissiveStubFinder:
    """安装缺包兜底（幂等）：meta_path 末尾的宽容 Finder + from-import 缺属性兜底。

    :return: 已安装的 Finder 实例。
    """
    global _active
    if _active is None:
        _active = PermissiveStubFinder()
    # 始终置于末尾：重复调用时把自身挪回尾部（配合 _claimed_by_later_finder 双向兜底）
    if _active in sys.meta_path:
        sys.meta_path.remove(_active)
    sys.meta_path.append(_active)
    install_import_fallback()
    return _active
