"""AST 路由与参数提取（RouteExtractor / ParamExtractor）。

基于 Python 原生 ``ast`` 对单个源码文件做静态结构分析，回答模块2 富化关心的
两个问题：
1. 该文件暴露了哪些 HTTP 路由（Flask / FastAPI / Django）？—— RouteExtractor
2. 路由处理函数接收哪些"外部可控"参数？—— ParamExtractor

这两个信息用于判断一个静态告警是否**外部可达**，是 LLM 误报研判（模块3）
与动态验证（模块4）做可达性判断的依据。

实现要点：
- 不依赖第三方 Web 框架运行时，全部用 ast 在源码层面识别：
  * Flask：``@app.route(path, methods=[...])`` / ``add_url_rule``
  * FastAPI：``@app.get/post/put/delete/...``
  * Django：``urlpatterns = [ path(...), re_path(...), url(...) ]``
- 产出结构复用 models.RouteInfo；不命中任何框架时返回空列表。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from models import Location, RouteInfo

#: Flask 可识别的 http 方法（用于 app.add_url_rule 的 methods 参数兜底）
_HTTP_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

#: FastAPI 装饰器 -> HTTP 方法
_FASTAPI_METHODS: dict[str, str] = {
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
    "patch": "PATCH", "head": "HEAD", "options": "OPTIONS",
}

#: 路由模板中抽取 {param} / <param> / <type:param> 的正则
_PARAM_RE = re.compile(r"[{<](?:[\w]+:)?([A-Za-z_][A-Za-z0-9_]*)[}>]")


def parse_source(file_path: Path) -> Optional[ast.Module]:
    """读取并解析源文件为 AST；语法错误/读取出错返回 None（调用方降级）。

    :param file_path: 目标源码文件。
    :return: 模块 AST 或 None。
    """
    try:
        text = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # 部分文件可能是 GBK 编码，宽容降级尝试
        try:
            text = file_path.read_text(encoding="gbk")
        except (OSError, UnicodeDecodeError):
            return None
    try:
        return ast.parse(text, filename=str(file_path))
    except SyntaxError:
        return None


def _route_path_params(path: str) -> list[str]:
    """从路由模板字符串抽取参数名（支持 {id} 与 <int:id> 两种写法）。

    :param path: 路由模板，如 "/api/users/{uid}"。
    :return: 参数名列表。
    """
    return _PARAM_RE.findall(path)


def _func_name(node: ast.AST) -> str:
    """取函数/类定义的名字或调用名，便于拼接 'Class.method'。"""
    return getattr(node, "name", getattr(node, "id", ""))


def _location_of(node: ast.AST, file_path: str) -> Location:
    """由 AST 节点位置构造 Location（含该行原文片段）。

    :param node: AST 节点。
    :param file_path: 文件绝对路径。
    :return: Location。
    """
    start: int = getattr(node, "lineno", 1)
    end: int = getattr(node, "end_lineno", start) or start
    return Location(file_path=file_path, start_line=start, end_line=end)


# ---------------------------------------------------------------------------
# RouteExtractor
# ---------------------------------------------------------------------------

class RouteExtractor:
    """从源码 AST 提取 Web 路由。

    采用"逐文件、按框架分派"的策略：先探测框架，再走对应提取分支，
    保证对三种框架各自最自然的语法都能覆盖。
    """

    def __init__(self, framework_hints: Optional[dict[str, str]] = None) -> None:
        """构造提取器。

        :param framework_hints: 可选 {文件路径: 框架名} 覆盖自动探测。
        """
        self.framework_hints: dict[str, str] = framework_hints or {}

    def extract_from_file(self, file_path: Path) -> list[RouteInfo]:
        """提取单个文件的路由列表。

        :param file_path: 目标源码文件。
        :return: RouteInfo 列表。
        """
        file_str = str(file_path)
        framework: str = self.framework_hints.get(file_str, "") or self.detect_framework(file_path)
        tree = parse_source(file_path)
        if tree is None:
            return []
        if framework == "flask":
            return self._extract_flask(tree, file_str)
        if framework == "fastapi":
            return self._extract_fastapi(tree, file_str)
        if framework == "django":
            return self._extract_django(tree, file_str)
        return []

    def detect_framework(self, file_path: Path) -> str:
        """按 import 语句启发式判断框架（flask / fastapi / django / ""）。

        :param file_path: 目标源码文件。
        :return: 框架名。
        """
        tree = parse_source(file_path)
        if tree is None:
            return ""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {node.module.split(".")[0]} if node.module else set()
            else:
                continue
            for n in names:
                if n == "flask":
                    return "flask"
                if n == "fastapi":
                    return "fastapi"
                if n == "django":
                    return "django"
        return ""

    # ---- Flask ----
    def _extract_flask(self, tree: ast.Module, file_str: str) -> list[RouteInfo]:
        routes: list[RouteInfo] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                route = self._flask_route_from_decorator(dec, node, file_str)
                if route is not None:
                    routes.append(route)
        # add_url_rule 显式注册（挂在模块级调用上）
        routes.extend(self._extract_flask_add_url_rule(tree, file_str))
        return routes

    def _flask_route_from_decorator(
        self,
        dec: ast.expr,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        file_str: str,
    ) -> Optional[RouteInfo]:
        """解析 Flask ``@app.route(path, methods=[...])`` 装饰器。"""
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "route"):
            return None
        if not dec.args or not isinstance(dec.args[0], ast.Constant) \
                or not isinstance(dec.args[0].value, str):
            return None
        path: str = dec.args[0].value
        methods: list[str] = []
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [elt.value for elt in kw.value.elts
                           if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
        methods = methods or ["GET"]
        return RouteInfo(
            path=path, http_methods=methods,
            handler_file=file_str, handler_function=func.name,
            parameters=_route_path_params(path)
            + [a.arg for a in func.args.args if a.arg not in {"self", "cls"}],
            framework="flask", entry_location=_location_of(func, file_str),
        )

    def _extract_flask_add_url_rule(self, tree: ast.Module, file_str: str) -> list[RouteInfo]:
        """解析 ``app.add_url_rule(rule, view_func=handler)``。"""
        out: list[RouteInfo] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) \
                    or node.func.attr != "add_url_rule":
                continue
            if not node.args:
                continue
            rule = node.args[0]
            if not isinstance(rule, ast.Constant) or not isinstance(rule.value, str):
                continue
            methods: list[str] = []
            handler: Optional[str] = None
            for kw in node.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [e.value for e in kw.value.elts
                               if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                elif kw.arg == "view_func" and isinstance(kw.value, ast.Name):
                    handler = kw.value.id
            if not handler:
                continue
            out.append(RouteInfo(
                path=rule.value, http_methods=methods or ["GET"],
                handler_file=file_str, handler_function=handler,
                parameters=_route_path_params(rule.value), framework="flask",
                entry_location=Location(file_str, rule.lineno, rule.end_lineno or rule.lineno),
            ))
        return out

    # ---- FastAPI ----
    def _extract_fastapi(self, tree: ast.Module, file_str: str) -> list[RouteInfo]:
        routes: list[RouteInfo] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                route = self._fastapi_route(dec, node, file_str)
                if route is not None:
                    routes.append(route)
        return routes

    def _fastapi_route(
        self,
        dec: ast.expr,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        file_str: str,
    ) -> Optional[RouteInfo]:
        """解析 FastAPI ``@app.get("/path")`` 等装饰器。"""
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            return None
        method: Optional[str] = _FASTAPI_METHODS.get(dec.func.attr)
        if method is None or not dec.args:
            return None
        path_node = dec.args[0]
        path: str = path_node.value if isinstance(path_node, ast.Constant) else ""
        if not path:
            return None
        return RouteInfo(
            path=path, http_methods=[method],
            handler_file=file_str, handler_function=func.name,
            parameters=_route_path_params(path)
            + [a.arg for a in func.args.args if a.arg not in {"self", "cls"}],
            framework="fastapi", entry_location=_location_of(func, file_str),
        )

    # ---- Django ----
    def _extract_django(self, tree: ast.Module, file_str: str) -> list[RouteInfo]:
        """解析 Django ``urlpatterns = [ path(...) / re_path(...) ]``。"""
        routes: list[RouteInfo] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not (isinstance(target, ast.Name) and target.id == "urlpatterns"):
                continue
            if not isinstance(node.value, (ast.List, ast.Tuple)):
                continue
            for item in node.value.elts:
                route = self._django_url_item(item, file_str)
                if route is not None:
                    routes.append(route)
        return routes

    def _django_url_item(self, item: ast.expr, file_str: str) -> Optional[RouteInfo]:
        """解析单个 urlpatterns 元素（path/re_path/url）。"""
        if not isinstance(item, ast.Call) or not isinstance(item.func, ast.Name):
            return None
        name = item.func.id
        if name not in {"path", "re_path", "url"}:
            return None
        if not item.args:
            return None
        first = item.args[0]
        path: str = first.value if isinstance(first, ast.Constant) else ""
        handler_name: str = ""
        # 处理函数形如 views.index（Attribute）或字符串 'views.index'
        if len(item.args) >= 2:
            h = item.args[1]
            if isinstance(h, ast.Attribute):
                handler_name = f"{_func_name(h.value)}.{h.attr}"
            elif isinstance(h, ast.Name):
                handler_name = h.id
            elif isinstance(h, ast.Constant) and isinstance(h.value, str):
                handler_name = h.value
        return RouteInfo(
            path=path, http_methods=["GET", "POST"],  # Django 不在 URL 层区分方法
            handler_file=file_str, handler_function=handler_name,
            parameters=_route_path_params(path), framework="django",
            entry_location=Location(file_str, item.lineno, item.end_lineno or item.lineno),
        )


# ---------------------------------------------------------------------------
# ParamExtractor
# ---------------------------------------------------------------------------

class ParamExtractor:
    """从处理函数/路由模板中提取"外部可控"的参数名。"""

    def __init__(self) -> None:
        """构造参数提取器。"""
        self._route = RouteExtractor()

    def from_route(self, route: RouteInfo) -> list[str]:
        """由 RouteInfo 直接给出参数（路由模板参数 + 签名参数）。

        :param route: 路由信息。
        :return: 参数名列表。
        """
        return list(route.parameters)

    def from_function(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        """提取函数中被视为"外部可控"的参数名。

        来源：
        1. 函数签名普通参数（排除 self/cls）；
        2. 函数体内对常见 request 对象取数的目标名（request.args.get('x') 等）。

        :param func: 函数定义节点。
        :return: 参数名列表。
        """
        params: list[str] = []
        seen: set[str] = set()

        def add(p: str) -> None:
            if p and p not in seen:
                seen.add(p)
                params.append(p)

        # 1) 位置/关键字参数
        for a in func.args.args:
            if a.arg not in {"self", "cls"}:
                add(a.arg)
        for a in func.args.kwonlyargs:
            if a.arg not in {"self", "cls"}:
                add(a.arg)
        # 2) 请求取值目标：request.args.get('k',...) / kwargs.get('k')
        for sub in ast.walk(func):
            if not isinstance(sub, ast.Call):
                continue
            targets = self._request_read_targets(sub)
            for t in targets:
                add(t)
        return params

    def _request_read_targets(self, call: ast.Call) -> list[str]:
        """识别一次 request 取值调用里显式给出的 key 名。"""
        keys: list[str] = []
        args: list[ast.expr] = list(call.args) + [k.value for k in call.keywords if not k.arg]
        for a in args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                keys.append(a.value)
            elif isinstance(a, ast.Name):
                keys.append(a.id)
        return keys

    def param_name_matches(self, finding_variable: str, params: Iterable[str]) -> bool:
        """判断某个（污点）变量名是否对应已登记的请求参数。

        :param finding_variable: 待比对变量名（可空）。
        :param params: 已提取参数名集合。
        :return: 命中返回 True。
        """
        if not finding_variable:
            return False
        return finding_variable in set(params)
