"""Import Hook 三层补丁机制（import_hook）。

本模块在**被测代码 import 之前**把"危险函数"整体替换为打点包装器，
从而在不改写源码的前提下实现运行时打点。补丁分三层、互为兜底：

1. **_patch_builtins()**：直接替换 ``builtins`` 模块里的危险内建函数
   ``eval`` / ``exec`` / ``compile`` / ``open``；
2. **_patch_carriers()**：替换"承载型模块"（os/subprocess/pickle/shutil…）
   上的危险属性（os.system、subprocess.Popen 等）——动态属性访问也走包装器；
3. **_patch_already_loaded()**：扫描 ``sys.modules`` 已加载模块，凡持有上述
   危险函数**同对象引用**的属性（``from os import system`` 产生的别名）
   一并替换，作为兜底。

``SinkPatcherFinder`` 是实现 legacy import 协议的 Finder（``find_module`` /
``load_module``，并兼容 py3 的 ``find_spec``）：可选的第四层，用于对
``allowed_prefixes`` 下**晚加载**的目标模块在 exec 后做同样的属性打点。
实践中前三层已覆盖绝大多数动态调用点，Finder 作为协议与扩展保留。

**关键约束：``install()`` 必须在目标项目代码被 import 之前调用**
（runner / PoC 脚本的第一行即安装）。
"""

from __future__ import annotations

import builtins
import importlib
import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Optional, Sequence

from modules.dynamic_verification.track_a import SinkCallTracker
from modules.dynamic_verification.track_b import TaintChecker

logger = logging.getLogger("opensoft_detect.dynamic_verification.import_hook")

#: 需整体替换的危险内建函数
#: 注意：不含 compile —— 模块导入/类创建期高频调用，包装会干扰框架（如 starlette 类定义）
BUILTIN_SINKS: tuple[str, ...] = ("eval", "exec", "open")

#: 承载对象 -> 其上的危险属性。key 可为模块(或 类，如 sqlite3.Cursor)，
#: 支持点路径：import 首段后逐级 getattr。
CARRIER_SINKS: dict[str, tuple[str, ...]] = {
    "os": ("system", "popen", "spawn", "remove", "rmdir", "unlink"),
    "subprocess": ("run", "Popen", "call", "check_call", "check_output", "getoutput"),
    "pickle": ("loads", "load"),
    "shelve": ("open",),
    "shutil": ("rmtree", "move", "copy", "copy2"),
    # Pillow 表达式求值等同代码执行（pygoat a9_lab2: ImageMath.eval(request 可控 "function")）
    "PIL.ImageMath": ("eval",),
    # SQL：最底层 sqlite3 游标的 execute（Django/原生 raw 查询最终都到这里）
    "sqlite3.Cursor": ("execute", "executemany", "executescript"),
    # 哈希：弱算法类漏洞的"策略断言"入口（md5/sha1/new/pbkdf2_hmac）
    "hashlib": ("md5", "sha1", "sha256", "new", "pbkdf2_hmac"),
    # SSRF：把用户可控 URL 交给网络库
    "requests": ("get", "post", "put", "delete", "patch", "head", "request"),
    "urllib.request": ("urlopen",),
    "httpx": ("get", "post", "request"),
    # XXE / 不安全 XML 解析
    "xml.etree.ElementTree": ("fromstring", "parse", "XML", "iterparse"),
    "xml.dom.minidom": ("parse", "parseString"),
    "xml.sax": ("parse",),
    "lxml.etree": ("fromstring", "parse", "XML"),
    # SSTI / 模板注入
    "jinja2": ("Template",),
    "jinja2.Environment": ("from_string",),
    "flask": ("render_template_string",),
}

#: 默认启用的 sink 名集合（wrapper 只对其中成员做 A/B 打点；open 太噪默认不开）
DEFAULT_ENABLED_SINKS: frozenset[str] = frozenset(
    {"eval", "exec", "compile", "open",
     "system", "popen", "spawn", "remove", "rmdir", "unlink",
     "run", "Popen", "call", "check_call", "check_output", "getoutput",
     "loads", "load", "rmtree", "move", "copy", "copy2",
     "execute", "executemany", "executescript",
     "md5", "sha1", "sha256", "new", "pbkdf2_hmac",
     # SSRF / XXE / SSTI
     "get", "post", "put", "delete", "patch", "head", "request", "urlopen",
     "fromstring", "parse", "XML", "iterparse", "parseString",
     "Template", "from_string", "render_template_string"})


def sink_name_of(qualified: str) -> str:
    """由限定名取末段 sink 名（os.system -> system）。"""
    return qualified.rsplit(".", 1)[-1]


class SinkPatcherFinder:
    """运行时危险函数打点器（Import Hook + 全局替换）。

    设计要点：
    - 包装器对所有启用 sink 的调用先做**轨道A 无差别记录**，再做**轨道B
      污点检测**，最后调用原始函数（沙箱内执行是安全的）；
    - 同一原始函数对象只包装一次（wrapper 缓存），幂等可重入；
    - :meth:`uninstall` 恢复 builtins/承载模块原值并从 ``sys.meta_path`` 移除。
    """

    def __init__(
        self,
        tracker_a: SinkCallTracker,
        checker_b: TaintChecker,
        patch_root: Optional[Path] = None,
        allowed_prefixes: Sequence[str] = (),
        enabled_sinks: Optional[set[str]] = None,
        policy: Any = None,
    ) -> None:
        """构造打点器。

        :param tracker_a: 轨道A 记录器。
        :param checker_b: 轨道B 检测器。
        :param patch_root: 被测工程根（用于 find_spec 按文件归属判断，可选）。
        :param allowed_prefixes: 需要额外打点的顶层模块名前缀。
        :param enabled_sinks: 启用的 sink 名集合；None 用默认集。
        :param policy: 类别化断言 oracle（PolicyChecker）；None 则不做策略断言。
        """
        self.tracker_a: SinkCallTracker = tracker_a
        self.checker_b: TaintChecker = checker_b
        self.policy: Any = policy
        self.patch_root: Path = Path(patch_root).resolve() if patch_root else Path.cwd()
        self.allowed_prefixes: tuple[str, ...] = tuple(allowed_prefixes)
        self.enabled_sinks: set[str] = set(enabled_sinks) if enabled_sinks is not None \
            else set(DEFAULT_ENABLED_SINKS)

        self._originals: dict[int, tuple[str, Any]] = {}   # id(orig) -> (sink名, 原函数)
        self._wrapper_cache: dict[int, Any] = {}
        # 备份用于 uninstall 恢复
        self._builtin_backup: dict[str, Any] = {}
        self._carrier_backup: dict[str, dict[str, Any]] = {}
        self._installed: bool = False

    # ------------------------------------------------------------------
    # 安装 / 卸载
    # ------------------------------------------------------------------
    def install(self) -> None:
        """安装全部补丁。**必须在目标代码被 import 之前调用。**

        步骤：登记原函数 -> 打 builtins -> 打承载模块 -> 兜底扫描已加载模块
        -> 插入 ``sys.meta_path``。
        """
        if self._installed:
            return
        self._register_builtin_originals()
        self._register_carrier_originals()
        self._patch_builtins()          # 第一层：直接替换 builtins
        self._patch_carriers()          # 第二层：承载模块属性
        self._patch_already_loaded()    # 第三层：兜底扫描 sys.modules
        if not any(m is self for m in sys.meta_path):
            sys.meta_path.insert(0, self)   # 第四层：拦截晚加载目标模块
        self._installed = True
        logger.info("Import Hook 三层补丁已安装（sinks=%d）", len(self.enabled_sinks))

    def uninstall(self) -> None:
        """撤销补丁并恢复原状（进程收尾 / 回滚时调用）。"""
        # 恢复承载对象（模块属性 / 类 __init__）
        for key, attrs in self._carrier_backup.items():
            obj = self._resolve_carrier(key)
            if obj is None:
                continue
            for attr, orig in attrs.items():
                try:
                    if attr.endswith(".__init__"):
                        cls = getattr(obj, attr[: -len(".__init__")], None)
                        if cls is not None:
                            setattr(cls, "__init__", orig)
                    else:
                        setattr(obj, attr, orig)
                except Exception:  # noqa: BLE001
                    pass
        self._carrier_backup.clear()
        # 恢复 builtins
        for name, orig in self._builtin_backup.items():
            try:
                setattr(builtins, name, orig)
            except Exception:  # noqa: BLE001
                pass
        self._builtin_backup.clear()
        # 从 meta_path 移除
        sys.meta_path = [m for m in sys.meta_path if m is not self]
        self._installed = False
        self._wrapper_cache.clear()
        self._originals.clear()
        logger.info("Import Hook 已卸载")

    # ------------------------------------------------------------------
    # 原函数登记
    # ------------------------------------------------------------------
    def _register_builtin_originals(self) -> None:
        """把危险内建函数登记进原函数表。"""
        for name in BUILTIN_SINKS:
            obj = getattr(builtins, name, None)
            if callable(obj) and id(obj) not in self._originals:
                self._originals[id(obj)] = (name, obj)

    def _register_carrier_originals(self) -> None:
        """把承载对象(模块/类)的危险属性登记进原函数表（惰性 import/解析）。"""
        for key, attrs in CARRIER_SINKS.items():
            obj = self._resolve_carrier(key)
            if obj is None:
                logger.debug("承载对象 %s 不可用，跳过其打点", key)
                continue
            for attr in attrs:
                fn = getattr(obj, attr, None)
                # 只登记"函数/内建"为可替换原函数；类不做整体替换（避免破坏子类化，
                # 见 _patch_carriers 对类只补 __init__）
                if callable(fn) and not isinstance(fn, type) and id(fn) not in self._originals:
                    self._originals[id(fn)] = (attr, fn)

    @staticmethod
    def _resolve_carrier(key: str) -> Any:
        """把 'mod' 或 'mod.Cls' 解析成最终对象。

        :param key: 点路径（首段必须是 importable 模块）。
        :return: 目标对象；失败返回 None。
        """
        parts = key.split(".")
        try:
            obj: Any = importlib.import_module(parts[0])
        except Exception:  # noqa: BLE001
            return None
        for p in parts[1:]:
            obj = getattr(obj, p, None)
            if obj is None:
                return None
        return obj

    # ------------------------------------------------------------------
    # 三层打点
    # ------------------------------------------------------------------
    def _patch_builtins(self) -> None:
        """第一层：直接替换 builtins 中的 eval/exec/compile/open。"""
        for name in BUILTIN_SINKS:
            orig = getattr(builtins, name, None)
            if not callable(orig):
                continue
            if name not in self._builtin_backup:
                self._builtin_backup[name] = orig
            setattr(builtins, name, self._wrap(name, orig))

    def _patch_carriers(self) -> None:
        """第二层：替换承载对象（os/subprocess/sqlite3.Cursor/…）上的危险属性。"""
        for key, attrs in CARRIER_SINKS.items():
            obj = self._resolve_carrier(key)
            if obj is None:
                continue
            backup = self._carrier_backup.setdefault(key, {})
            for attr in attrs:
                orig = getattr(obj, attr, None)
                if not callable(orig):
                    continue
                try:
                    if isinstance(orig, type):
                        # 类：只补 __init__（保留类身份，避免破坏 isinstance/子类化，
                        # 如 subprocess.Popen 被框架继承）
                        init = orig.__init__
                        backup.setdefault(f"{attr}.__init__", init)
                        setattr(orig, "__init__", self._wrap(attr, init))
                    else:
                        backup.setdefault(attr, orig)
                        setattr(obj, attr, self._wrap(attr, orig))
                except (AttributeError, TypeError) as exc:
                    logger.debug("打点 %s.%s 失败：%s", key, attr, exc)

    def _patch_already_loaded(self) -> None:
        """第三层（兜底）：扫描 sys.modules，替换已绑定危险函数的模块属性。"""
        for mod_name, module in list(sys.modules.items()):
            if self._is_own_module(mod_name):
                continue
            try:
                self._patch_module_object(module, mod_name)
            except Exception:  # noqa: BLE001
                continue

    def _patch_module_object(self, module: Any, mod_name: str) -> None:
        """把模块内"值即危险原函数"的属性替换为包装器（identity 判断）。"""
        for attr, val in list(vars(module).items()):
            if not callable(val):
                continue
            entry = self._originals.get(id(val))
            if entry is not None:
                sink_name, _orig = entry
                try:
                    setattr(module, attr, self._wrap(sink_name, val))
                except (AttributeError, TypeError):
                    continue

    # ------------------------------------------------------------------
    # 包装器工厂
    # ------------------------------------------------------------------
    def _wrap(self, sink_name: str, orig: Any) -> Any:
        """为原函数构造打点包装器（同一原函数缓存一份）。

        :param sink_name: sink 名（system / Popen / eval ...）。
        :param orig: 原始可调用对象。
        :return: 包装函数。
        """
        cached = self._wrapper_cache.get(id(orig))
        if cached is not None:
            return cached
        tracker = self.tracker_a
        checker = self.checker_b
        policy_obj = self.policy
        enabled = self.enabled_sinks

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 未启用该 sink 时直通（open 等默认关闭以降低噪音）
            if sink_name in enabled:
                # 轨道A：无差别记录调用
                try:
                    tracker.record_sink(sink_name, args, kwargs)
                except Exception:  # noqa: BLE001
                    pass
                # 轨道B：污点检测
                try:
                    checker.check_at_sink(sink_name, args, kwargs)
                except Exception:  # noqa: BLE001
                    pass
                # 类别化断言 oracle（如 weak_hash：弱算法策略违规）
                if policy_obj is not None:
                    try:
                        policy_obj.check(sink_name, args, kwargs)
                    except Exception:  # noqa: BLE001
                        pass
            return orig(*args, **kwargs)

        # 尽量保留元信息（便于栈回溯可读）
        wrapper.__name__ = getattr(orig, "__name__", sink_name)
        wrapper.__qualname__ = getattr(orig, "__qualname__", sink_name)
        wrapper.__wrapped__ = orig          # type: ignore[attr-defined]
        wrapper.__opensoft_sink__ = sink_name  # type: ignore[attr-defined]
        self._wrapper_cache[id(orig)] = wrapper
        return wrapper

    def configure_sinks(self, sink_names: Optional[set[str]]) -> None:
        """按 Finding 重新限定启用的 sink 集合。

        :param sink_names: sink 名集合；None 恢复默认。
        """
        self.enabled_sinks = set(sink_names) if sink_names else set(DEFAULT_ENABLED_SINKS)

    # ------------------------------------------------------------------
    # Finder 协议（py2 legacy 风格 find_module / load_module + py3 find_spec）
    # ------------------------------------------------------------------
    def _is_target(self, fullname: str) -> bool:
        """是否属于需要拦截的目标模块（allowed_prefixes 或位于 patch_root 内）。"""
        if any(fullname == p or fullname.startswith(p + ".") for p in self.allowed_prefixes):
            return True
        # 按文件归属判断：需要解析路径，成本高；前缀判断为主，此处保守返回 False
        return False

    def find_module(self, fullname: str, path: Optional[str] = None) -> Any:
        """Legacy Finder 协议：命中目标返回 self，否则 None。

        :param fullname: 模块全名。
        :param path: 父包路径（可为 None）。
        :return: self / None。
        """
        return self if self._is_target(fullname) else None

    def load_module(self, fullname: str) -> ModuleType:
        """Legacy 加载器：加载模块后做属性打点（兜底）。"""
        module = importlib.import_module(fullname)
        self._patch_module_object(module, fullname)
        return module

    def find_spec(self, fullname: str, path=None, target: Optional[ModuleType] = None):
        """Python3 Finder 协议：对目标模块返回"exec 后打点"的 spec。

        非目标模块返回 None 交回正常 import。
        """
        if not self._is_target(fullname):
            return None
        try:
            spec = importlib.util.find_spec(fullname)   # noqa: PLC0415
        except Exception:  # noqa: BLE001
            return None
        if spec is None or spec.loader is None:
            return None
        loader = spec.loader

        class _PatchingLoader:
            """薄包装：exec_module 完成后对该模块属性打点。"""

            def __init__(self, underlying: Any, hook: "SinkPatcherFinder") -> None:
                self.underlying = underlying
                self._hook = hook

            def create_module(self, spec_: Any) -> Any:
                return self.underlying.create_module(spec_) \
                    if hasattr(self.underlying, "create_module") else None

            def exec_module(self, module: ModuleType) -> None:
                self.underlying.exec_module(module)
                try:
                    self._hook._patch_module_object(module, fullname)
                except Exception:  # noqa: BLE001
                    pass

            def __getattr__(self, item: str) -> Any:
                return getattr(self.underlying, item)

        spec.loader = _PatchingLoader(loader, self)  # type: ignore[assignment]
        return spec

    # ------------------------------------------------------------------
    @staticmethod
    def _is_own_module(fullname: str) -> bool:
        """跳过本系统自己的模块，避免把打点器自身也打了。"""
        return (fullname == "modules"
                or fullname.startswith("modules.")
                or fullname.startswith("opensoft")
                or fullname in ("__main__", "builtins"))


def install_default(tracker_a: SinkCallTracker, checker_b: TaintChecker,
                    enabled_sinks: Optional[set[str]] = None) -> SinkPatcherFinder:
    """便捷入口：构造并安装三层补丁。

    :param tracker_a: 轨道A 记录器。
    :param checker_b: 轨道B 检测器。
    :param enabled_sinks: 启用的 sink 集合。
    :return: 已安装的 finder。
    """
    finder = SinkPatcherFinder(tracker_a, checker_b, enabled_sinks=enabled_sinks)
    finder.install()
    return finder
