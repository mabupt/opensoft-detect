"""应用入口驱动（entry_driver）。

让模块4 能对真实 Web 应用做端到端动态探针：

- 对**自包含 Flask 应用**（``app = Flask(__name__)``，无外部 DB/服务）：
  在沙箱内 import 该应用并驱动其路由：
  1) **先 install() 三层补丁**，再 import 应用模块；
  2) 开启 **source 注入兜底**：包装 werkzeug ``MultiDict.get``，使视图读到的
     request 参数返回 :class:`TaintedString`（对应规格"标记总在传递被清洗时，
     在 source 点直接注入标记"的兜底）；
  3) 用 Flask ``test_client`` 逐个命中路由并携带污点载荷（含可触发反序列化
     sink 的 pickle 载荷），观察轨道A/轨道B；
  4) 结尾打印一行 JSON 双轨计数供宿主机解析。
- **Django / 依赖复杂的应用**：暂不内置驱动，返回 reason 交由 runner 降级。

双轨语义：A=真实 HTTP 路径确实执行到了 sink；B=source 注入的标记到达 sink。
双轨同真 => 外部输入确实流到危险 sink（confirmed 的判据）。
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from models import Finding
from modules.dynamic_verification.sandbox import (OUTSIDE_TARGET_MOUNT,
                                                  container_root_for)

logger = logging.getLogger("opensoft_detect.dynamic_verification.entry_driver")

#: Flask 应用标记（Flask(__name__) 或 Flask("name")）
_FLASK_MARKER = re.compile(r"Flask\(\s*")

#: 探针脚本模板（@@FILE@@ 会被替换为应用文件绝对路径；避免 f-string 大括号地狱）
_FLASK_PROBE_TEMPLATE = r'''import sys, base64, json, importlib.util

# ---- 0) 路径 + 先装三层补丁（早于 import 目标代码）----
WORKSPACE = "/workspace"
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()   # 缺包兜底：真实库缺失时伪造占位模块，保证应用能起来
from modules.dynamic_verification.import_hook import SinkPatcherFinder
from modules.dynamic_verification.track_a import SinkCallTracker
from modules.dynamic_verification.track_b import (TaintChecker, TaintedString,
                                                  TaintedBytes)
from modules.dynamic_verification.policy import PolicyChecker

ta, tb = SinkCallTracker(), TaintChecker()
pc = PolicyChecker()
finder = SinkPatcherFinder(ta, tb, policy=pc)
finder.install()

# 注册内容水印令牌（str 拼接会让对象标记丢失，令牌子串可存活到 sink）
tb.add_canary("__OSD_CANARY_7f3a__")

# ---- 1) source 注入兜底：request 取值返回 TaintedString ----
try:
    import werkzeug.datastructures as _wd
    _orig_get = _wd.MultiDict.get
    def _tainted_get(self, key, default=None, type=None):
        val = _orig_get(self, key, default=default, type=type)
        if isinstance(val, str):
            return TaintedString(val, source="request:" + str(key))
        return val
    _wd.MultiDict.get = _tainted_get
except Exception:
    pass

# ---- 1b) 传播层：base64 编解码保留污点标记（避免在解码处被清洗）----
try:
    import base64 as _b64
    _b64d = _b64.b64decode
    _b64e = _b64.b64encode
    def _prop_decode(s, *a, **kw):
        r = _b64d(s, *a, **kw)
        if isinstance(s, (TaintedString, TaintedBytes)):
            return TaintedBytes(r, source="base64.decode")
        return r
    def _prop_encode(s, *a, **kw):
        r = _b64e(s, *a, **kw)
        if isinstance(s, (TaintedString, TaintedBytes)):
            return TaintedString(r.decode("ascii"), source="base64.encode")
        return r
    _b64.b64decode = _prop_decode
    _b64.b64encode = _prop_encode
except Exception:
    pass

# ---- 2) import 目标应用模块 ----
_mod_path = @@FILE@@
_spec = importlib.util.spec_from_file_location("_probe_app", _mod_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["_probe_app"] = _mod          # 注册进 sys.modules，pickle 才能按名 import 到类
try:
    _spec.loader.exec_module(_mod)
except Exception as _e:
    print(json.dumps({"error": "import_failed", "detail": str(_e)[:400]}))
    sys.exit(0)

# ---- 3) 找 Flask 实例并驱动路由 ----
_app = getattr(_mod, "app", None)
out = {"track_a": 0, "track_b": 0, "routes_tried": 0}
if _app is None or not hasattr(_app, "test_client"):
    print(json.dumps({"error": "no_flask_app", "detail": "未找到 Flask app 实例"}))
    sys.exit(0)

_client = _app.test_client()
# 预构造载荷：若模块定义 User 之类，则给反序列化端点一个合法 pickle 载荷
_payload = None
try:
    import pickle as _pk
    _user_cls = getattr(_mod, "User", None)
    if _user_cls is not None:
        _payload = base64.b64encode(_pk.dumps(_user_cls("probe", False))).decode()
except Exception:
    pass

for _rule in _app.url_map.iter_rules():
    allowed = sorted(_rule.methods & {"GET", "POST"})
    if not allowed:
        continue
    _path = _rule.rule
    # 路径参数填值
    for _conv in list(_rule.arguments):
        _path = _path.replace("<int:" + _conv + ">", "1").replace("<" + _conv + ">", "x")
    for _m in allowed:
        try:
            if _m == "POST":
                _client.post(_path, data={"username": "probe",
                                          "serialized_data": _payload or "x",
                                          "comment": "x", "name": "x", "val": "x",
                                          "cmd": "__OSD_CANARY_7f3a__"})
            else:
                _client.get(_path, query_string={"id": "1", "name": "x", "cmd": "__OSD_CANARY_7f3a__",
                                                 "url": "http://127.0.0.1:1/"})
            out["routes_tried"] += 1
        except Exception:
            pass
    if tb.hit_count() > 0:
        break

out["track_a"] = ta.call_count()
out["track_b"] = tb.hit_count()
out["policy"] = pc.hit_count()
out["policy_samples"] = pc.hits()[:3]
print(json.dumps(out))
'''

#: Django 探针模板（@@SETTINGS@@ -> settings 模块名；@@ROOT@@ -> 容器内项目根）
_DJANGO_PROBE_TEMPLATE = r'''import sys, os, base64, json

WORKSPACE = "/workspace"
_ROOT = @@ROOT@@
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# 预构建镜像内的依赖桩目录（如 django_heroku no-op）
for _s in ("/tmp/stubs",):
    if _s not in sys.path and os.path.isdir(_s):
        sys.path.insert(0, _s)

from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()   # 缺包兜底：真实库缺失时伪造占位模块，保证应用能起来
from modules.dynamic_verification.import_hook import SinkPatcherFinder
from modules.dynamic_verification.track_a import SinkCallTracker
from modules.dynamic_verification.track_b import (TaintChecker, TaintedString,
                                                  TaintedBytes)
from modules.dynamic_verification.policy import PolicyChecker

ta, tb = SinkCallTracker(), TaintChecker()
pc = PolicyChecker()
finder = SinkPatcherFinder(ta, tb, policy=pc)
finder.install()

# 注册内容水印令牌（Django 场景同理）
tb.add_canary("__OSD_CANARY_7f3a__")

# source 注入 + base64 传播（同 Flask 探针）
try:
    import werkzeug.datastructures as _wd
    _o = _wd.MultiDict.get
    def _g(self, key, default=None, type=None):
        v = _o(self, key, default=default, type=type)
        return TaintedString(v, source="request:" + str(key)) if isinstance(v, str) else v
    _wd.MultiDict.get = _g
except Exception:
    pass
try:
    import base64 as _b64
    _bd = _b64.b64decode
    def _pd(s, *a, **kw):
        r = _bd(s, *a, **kw)
        return TaintedBytes(r, "b64") if isinstance(s, (TaintedString, TaintedBytes)) else r
    _b64.b64decode = _pd
except Exception:
    pass

# Django 初始化（settings 已在检测阶段定位）
os.environ.setdefault("DJANGO_SETTINGS_MODULE", @@SETTINGS@@)
try:
    import django
    django.setup()
    # test_client 用 testserver 主机名；工程 ALLOWED_HOSTS 未必包含，宽松追加
    from django.conf import settings as _dj_settings
    for _h in ("testserver", "localhost", "127.0.0.1"):
        if _h not in _dj_settings.ALLOWED_HOSTS:
            _dj_settings.ALLOWED_HOSTS.append(_h)
except Exception as _e:
    print(json.dumps({"error": "django_setup_failed", "detail": str(_e)[:500]}))
    sys.exit(0)

# Django 的 request.GET/POST 是 django.http.QueryDict，需单独包装
try:
    from django.http import QueryDict
    _oq = QueryDict.get
    def _qget(self, key, default=None):
        v = _oq(self, key, default=default)
        return TaintedString(v, source="request:" + str(key)) if isinstance(v, str) else v
    QueryDict.get = _qget
except Exception:
    pass

from django.urls import URLPattern, URLResolver
from django.test import Client
import re as _re

client = Client()
paths = []

def _walk(patterns, prefix=""):
    for p in patterns:
        if isinstance(p, URLResolver):
            _walk(getattr(p, "url_patterns", []), prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            full = prefix + str(p.pattern)
            full = _re.sub(r"<[^>]+>", "x", full)
            if not full.startswith("/"):
                full = "/" + full
            if full not in paths:
                paths.append(full)

try:
    from django.urls import get_resolver
    _walk(get_resolver().url_patterns)
except Exception as _e:
    print(json.dumps({"error": "url_walk_failed", "detail": str(_e)[:300]}))
    sys.exit(0)

out = {"track_a": 0, "track_b": 0, "routes_tried": 0}
for _path in paths:
    for _m in ("GET", "POST"):
        try:
            if _m == "GET":
                client.get(_path, {"cmd": "__OSD_CANARY_7f3a__", "name": "x", "id": "1",
                                   "url": "http://127.0.0.1:1/"})
            else:
                client.post(_path, {"username": "x", "cmd": "__OSD_CANARY_7f3a__", "name": "x",
                                    "comment": "x", "data": "x"})
            out["routes_tried"] += 1
        except Exception:
            pass
    if tb.hit_count() > 0:
        break

out["track_a"] = ta.call_count()
out["track_b"] = tb.hit_count()
out["policy"] = pc.hit_count()
out["policy_samples"] = pc.hits()[:3]
print(json.dumps(out))
'''


#: Django 真 HTTP 探针模板（同进程 WSGI 起服 + 会话 + 免 CSRF + 按视图路由打点）
#: 占位：@@ROOT@@(容器内工程根) / @@SETTINGS@@ / @@FUNC@@(视图函数名) / @@ROUTES@@(JSON 路径表)
_DJANGO_HTTP_PROBE_TEMPLATE = r'''import sys, os, json, io, base64, threading, time

WORKSPACE = "/workspace"
_ROOT = @@ROOT@@
for _p in (WORKSPACE, _ROOT, "/tmp/stubs"):
    if _p not in sys.path and os.path.isdir(_p):
        sys.path.insert(0, _p)

# 依赖桩（仅当真实包缺失时注入；避免覆盖真实库）
def _writepy(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)

import importlib.util as _iutil
if _iutil.find_spec("whitenoise") is None:
    _writepy("/tmp/stubs/whitenoise/__init__.py", "")
    _writepy("/tmp/stubs/whitenoise/middleware/__init__.py",
             "class WhiteNoiseMiddleware:\n    def __init__(self, get_response): self._gr = get_response\n    def __call__(self, request): return self._gr(request)\n")
    _writepy("/tmp/stubs/whitenoise/storage/__init__.py",
             "class CompressedManifestStaticFilesStorage:\n    pass\n")
    sys.path.insert(0, "/tmp/stubs")
if _iutil.find_spec("django_heroku") is None:
    _writepy("/tmp/stubs/django_heroku.py", "def settings(locals=None):\n    pass\n")
    sys.path.insert(0, "/tmp/stubs")

from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()   # 缺包兜底：真实库缺失时伪造占位模块，保证应用能起来
from modules.dynamic_verification.import_hook import SinkPatcherFinder
from modules.dynamic_verification.track_a import SinkCallTracker
from modules.dynamic_verification.track_b import TaintChecker, TaintedString
from modules.dynamic_verification.policy import PolicyChecker

ta, tb = SinkCallTracker(), TaintChecker()
tb.add_canary("__OSD_CANARY_7f3a__")
pc = PolicyChecker()

from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()   # 缺包兜底：保证应用能起来（幂等）

os.environ.setdefault("DJANGO_SETTINGS_MODULE", @@SETTINGS@@)
import django
django.setup()
from django.conf import settings as S
for _h in ("testserver", "localhost", "127.0.0.1", "0.0.0.0"):
    if _h not in S.ALLOWED_HOSTS:
        S.ALLOWED_HOSTS.append(_h)
# source 注入 + 关闭 CSRF（探针内免令牌）
from django.http import QueryDict
_oq = QueryDict.get
def _qget(self, key, default=None):
    v = _oq(self, key, default=default)
    return TaintedString(v, "req:" + str(key)) if isinstance(v, str) else v
QueryDict.get = _qget
try:
    import django.middleware.csrf as _csrf
    _csrf.CsrfViewMiddleware.process_view = lambda self, request, cb, ca, ck: None
except Exception:
    pass

SinkPatcherFinder(ta, tb, policy=pc).install()
from django.core.management import call_command
try:
    call_command("migrate", interactive=False, verbosity=0)
except Exception:
    pass

# 会话直连：造活跃用户 + 服务端 session cookie（含 _auth_user_hash 防止匿名化）
from django.contrib.auth import get_user_model
U = get_user_model()
u, _ = U.objects.get_or_create(username="probe_http", defaults={"is_active": True})
u.set_password("pw"); u.is_active = True; u.save()
from django.contrib.sessions.backends.db import SessionStore
_st = SessionStore()
_st["_auth_user_id"] = str(u.pk)
_st["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
_st["_auth_user_hash"] = u.get_session_auth_hash()
_st.create()

# 同进程 WSGI 服务器
from wsgiref.simple_server import make_server
from django.core.handlers.wsgi import WSGIHandler
_srv = make_server("127.0.0.1", 8000, WSGIHandler())
threading.Thread(target=_srv.serve_forever, daemon=True).start()
time.sleep(1.0)

import requests
_rs = requests.Session()
_rs.cookies.set("sessionid", _st.session_key)
_CAN = "__OSD_CANARY_7f3a__"
_PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==")

ROUTES = @@ROUTES@@
EXTRA = @@EXTRA@@
PARAMS = @@PARAMS@@
out = {"track_a": 0, "track_b": 0, "routes_tried": 0}
_anon = requests.Session()          # 匿名会话（无 sessionid），用于缺鉴权差分
_bypass = []
for _path in ROUTES:
    _data = {"name": _CAN, "pass": "x", "function": _CAN, "val": _CAN,
             "domain": _CAN, "os": "unix", "cmd": _CAN, "code": _CAN,
             "url": "http://127.0.0.1:1/" + _CAN, "xml": "<a>" + _CAN + "</a>",
             "template": _CAN, "q": _CAN}
    for _k in EXTRA:
        if _k not in _data:
            _data[_k] = _CAN
    for _k, _v in PARAMS.items():     # LLM 给出的精确参数覆盖通配值
        _data[_k] = _v
    # 缺鉴权差分：同一路由「已认证」vs「匿名」各请求一次，比较状态与响应体
    _url = "http://127.0.0.1:8000" + _path
    try:
        _ra = _rs.get(_url, params=_data, allow_redirects=False, timeout=8)
        _rb = _anon.get(_url, params=_data, allow_redirects=False, timeout=8)
        _same = (len(_ra.text) > 0 and _ra.status_code == 200
                 and _rb.status_code == 200 and _ra.text == _rb.text)
        _bypass.append({"route": _path, "auth_status": _ra.status_code,
                        "anon_status": _rb.status_code, "equal": bool(_same),
                        "auth_len": len(_ra.text), "anon_len": len(_rb.text)})
    except Exception:
        pass
    try:
        _rs.post(_url, data=_data,
                 files={"file": ("a.png", io.BytesIO(_PNG), "image/png")},
                 timeout=15)
    except Exception:
        pass
    out["routes_tried"] += 1
    if tb.hit_count() > 0 or pc.hit_count() > 0:
        break
out["track_a"] = ta.call_count()
out["track_b"] = tb.hit_count()
out["policy"] = pc.hit_count()
out["policy_samples"] = pc.hits()[:3]
out["auth_bypass"] = _bypass
print(json.dumps(out))
_srv.shutdown()
'''


#: 路线级 DAST 探针模板（缺鉴权）：枚举全部路由，匿名 vs 已认证差分。
#: 占位 @@ROOT@@ / @@SETTINGS@@
_DAST_PROBE_TEMPLATE = r'''import sys, os, json, threading, time

WORKSPACE = "/workspace"
_ROOT = @@ROOT@@
for _p in (WORKSPACE, _ROOT, "/tmp/stubs"):
    if _p not in sys.path and os.path.isdir(_p):
        sys.path.insert(0, _p)
def _writepy(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
import importlib.util as _iutil
if _iutil.find_spec("whitenoise") is None:
    _writepy("/tmp/stubs/whitenoise/__init__.py", "")
    _writepy("/tmp/stubs/whitenoise/middleware/__init__.py",
             "class WhiteNoiseMiddleware:\n    def __init__(self, get_response): self._gr = get_response\n    def __call__(self, request): return self._gr(request)\n")
    _writepy("/tmp/stubs/whitenoise/storage/__init__.py",
             "class CompressedManifestStaticFilesStorage:\n    pass\n")
    sys.path.insert(0, "/tmp/stubs")
if _iutil.find_spec("django_heroku") is None:
    _writepy("/tmp/stubs/django_heroku.py", "def settings(locals=None):\n    pass\n")
    sys.path.insert(0, "/tmp/stubs")

from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()   # 缺包兜底：保证应用能起来（幂等）

os.environ.setdefault("DJANGO_SETTINGS_MODULE", @@SETTINGS@@)
import django
django.setup()
from django.conf import settings as S
for _h in ("testserver", "localhost", "127.0.0.1", "0.0.0.0"):
    if _h not in S.ALLOWED_HOSTS:
        S.ALLOWED_HOSTS.append(_h)
try:
    import django.middleware.csrf as _csrf
    # 注意：DAST 需要保留 CSRF 中间件（缺 CSRF 检测依赖它）。
    pass
except Exception:
    pass
from django.core.management import call_command
try:
    call_command("migrate", interactive=False, verbosity=0)
except Exception:
    pass
from django.contrib.auth import get_user_model
U = get_user_model()
_u, _ = U.objects.get_or_create(username="probe_dast", defaults={"is_active": True})
_u.set_password("pw"); _u.is_active = True; _u.save()
from django.contrib.sessions.backends.db import SessionStore
_st = SessionStore()
_st["_auth_user_id"] = str(_u.pk)
_st["_auth_user_backend"] = "django.contrib.auth.backends.ModelBackend"
_st["_auth_user_hash"] = _u.get_session_auth_hash()
_st.create()

from wsgiref.simple_server import make_server
from django.core.handlers.wsgi import WSGIHandler
_srv = make_server("127.0.0.1", 8000, WSGIHandler())
threading.Thread(target=_srv.serve_forever, daemon=True).start()
time.sleep(1.2)

import requests
_auth = requests.Session(); _auth.cookies.set("sessionid", _st.session_key)
_anon = requests.Session()
BASE = "http://127.0.0.1:8000"

from django.urls import URLPattern, URLResolver, get_resolver
import re as _re
_paths = []
def _walk(patterns, prefix=""):
    for p in patterns:
        if isinstance(p, URLResolver):
            _walk(getattr(p, "url_patterns", []), prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            full = _re.sub(r"<[^>]+>", "x", prefix + str(p.pattern))
            if not full.startswith("/"):
                full = "/" + full
            if full not in _paths:
                _paths.append(full)
try:
    _walk(get_resolver().url_patterns)
except Exception:
    pass

# 公共外壳基线（匿名首页），用于排除"本来就公开"的页面
try:
    _base = _anon.get(BASE + "/", allow_redirects=False, timeout=8).text
except Exception:
    _base = ""
SKIP = ("login", "logout", "signup", "register", "static", "media", "admin",
        "favicon", "robots", "captcha", "password", "otp")
_hits = []
for _p in _paths:
    if any(s in _p.lower() for s in SKIP):
        continue
    try:
        _ra = _auth.get(BASE + _p, allow_redirects=False, timeout=8)
        _rb = _anon.get(BASE + _p, allow_redirects=False, timeout=8)
    except Exception:
        continue
    if (_ra.status_code == 200 and _rb.status_code == 200
            and _ra.text == _rb.text and len(_rb.text) >= 256
            and _rb.text.strip() != _base.strip()):
        _hits.append({"route": _p, "auth_status": _ra.status_code,
                      "anon_status": _rb.status_code, "len": len(_rb.text)})

# ---------- 反射型 XSS：带元字符标记，检查响应中"原样回显" ----------
import uuid as _uuid
_tag = "osdx" + _uuid.uuid4().hex[:8]
_raw = "<" + _tag + ">"
_payloads = ['"' + _raw, _raw]
_xss = []
for _p in _paths:
    if any(s in _p.lower() for s in ("static", "media", "favicon", "admin")):
        continue
    for _pl in _payloads:
        _params = {k: _pl for k in ("q", "name", "search", "msg", "comment",
                                    "text", "url", "id", "val", "content")}
        try:
            _r1 = _auth.get(BASE + _p, params=_params, timeout=8)
            _r2 = _auth.post(BASE + _p, data=_params, timeout=8)
        except Exception:
            continue
        for _m, _r in (("GET", _r1), ("POST", _r2)):
            _ct = (_r.headers.get("Content-Type") or "").lower()
            if "html" in _ct and _raw in _r.text:
                _xss.append({"route": _p, "method": _m, "marker": _raw,
                             "status": _r.status_code})
                break
        if _xss and _xss[-1]["route"] == _p:
            break

# ---------- 缺 CSRF：带会话、无/错 token 的 POST 是否被接受 ----------
import re as _re2
from urllib.parse import urljoin as _urljoin
_cands = []
for _p in _paths[:80]:
    if any(s in _p.lower() for s in ("static", "media", "favicon")):
        continue
    try:
        _pg = _auth.get(BASE + _p, timeout=8)
    except Exception:
        continue
    if "html" not in (_pg.headers.get("Content-Type") or "").lower():
        continue
    for _f in _re2.finditer(r"<form[^>]*method=[\"']?post[\"']?[^>]*>", _pg.text, _re2.I):
        _tag_txt = _f.group(0)
        _m = _re2.search(r"action=[\"']([^\"']*)[\"']", _tag_txt, _re2.I)
        _action = _urljoin(BASE + _p, _m.group(1)) if _m else (BASE + _p)
        _path2 = _action.replace(BASE, "") or "/"
        if _path2 not in _cands:
            _cands.append(_path2)
if not _cands:
    _cands = [_p for _p in _paths[:30] if not any(
        s in _p.lower() for s in ("login", "logout", "signup", "register", "static", "admin"))]
_csrf = []
for _p in _cands:
    try:
        _no = _auth.post(BASE + _p, data={"name": "x", "id": "1"}, timeout=8)
    except Exception:
        continue
    if _no.status_code in (403, 405):
        continue
    if _no.status_code in (200, 301, 302):
        _csrf.append({"route": _p, "status_no_token": _no.status_code})

print(json.dumps({"dast_missing_auth": _hits[:50], "dast_xss": _xss[:50],
                  "dast_csrf": _csrf[:50]}))
_srv.shutdown()
'''


def _find_fastapi_app_file(file_path: Path) -> Optional[Path]:
    """定位定义 ``FastAPI(...)`` 实例的文件（自身/同目录树/上层）。

    :param file_path: 触发检测的源码文件。
    :return: 含 FastAPI 实例的文件路径或 None。
    """
    def _has(p: Path) -> bool:
        try:
            return "FastAPI(" in p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False

    if _has(file_path):
        return file_path
    # 同目录树搜索（浅层优先）
    cands = [p for p in file_path.parent.rglob("*.py")
             if "venv" not in p.as_posix() and "node_modules" not in p.as_posix()
             and "__pycache__" not in p.as_posix()]
    cands.sort(key=lambda p: len(p.relative_to(file_path.parent).parts))
    for p in cands:
        if _has(p):
            return p
    # 向上层搜索
    cur = file_path.parent
    for _ in range(4):
        cur = cur.parent
        if cur.parent == cur:
            break
        for p in cur.glob("*.py"):
            if _has(p):
                return p
    return None


def detect_project_entry_fastapi(target: Path) -> Optional[dict[str, Any]]:
    """由目标目录探测 FastAPI 应用入口（app_file/root）。

    :param target: 目标工程目录。
    :return: {root, app_file} 或 None。
    """
    cands = [p for p in target.rglob("*.py")
             if "venv" not in p.as_posix() and "node_modules" not in p.as_posix()]
    cands.sort(key=lambda p: len(p.relative_to(target).parts))
    for p in cands:
        try:
            if "FastAPI(" in p.read_text(encoding="utf-8", errors="ignore"):
                return {"root": str(p.parent), "app_file": str(p)}
        except OSError:
            continue
    return None


#: FastAPI 探针模板（TestClient 同进程；@@ROOT@@ @@APPFILE@@ @@PARAMS@@）
_FASTAPI_PROBE_TEMPLATE = r'''import sys, os, json, io, base64, importlib.util

WORKSPACE = "/workspace"; _ROOT = @@ROOT@@
for _p in (WORKSPACE, _ROOT, "/tmp/stubs"):
    if _p not in sys.path and os.path.isdir(_p):
        sys.path.insert(0, _p)
from modules.dynamic_verification.import_hook import SinkPatcherFinder
from modules.dynamic_verification.track_a import SinkCallTracker
from modules.dynamic_verification.track_b import TaintChecker, TaintedString
from modules.dynamic_verification.policy import PolicyChecker
# 先导入真实框架（避免缺包桩把框架依赖伪造成占位对象），再装桩/补丁
from fastapi.testclient import TestClient
from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()
ta, tb, pc = SinkCallTracker(), TaintChecker(), PolicyChecker()
tb.add_canary("__OSD_CANARY_7f3a__")
SinkPatcherFinder(ta, tb, policy=pc).install()

_spec = importlib.util.spec_from_file_location("_probe_app", @@APPFILE@@)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["_probe_app"] = _mod
try:
    _spec.loader.exec_module(_mod)
except Exception as _e:
    print(json.dumps({"error": "import_failed", "detail": str(_e)[:400]})); sys.exit(0)

_app = None
for _v in list(vars(_mod).values()):
    if _v.__class__.__name__ == "FastAPI":
        _app = _v; break
if _app is None:
    _app = getattr(_mod, "app", None)
if _app is None:
    print(json.dumps({"error": "no_fastapi_app", "detail": "未找到 FastAPI 实例"})); sys.exit(0)

_client = TestClient(_app, raise_server_exceptions=False)
_CAN = "__OSD_CANARY_7f3a__"
PARAMS = @@PARAMS@@
_bag = {"q": _CAN, "name": _CAN, "cmd": _CAN, "url": _CAN, "id": "1",
        "val": _CAN, "msg": _CAN, "text": _CAN}
_bag.update(PARAMS or {})
out = {"track_a": 0, "track_b": 0, "policy": 0, "policy_samples": [],
       "routes_tried": 0, "auth_bypass": []}
for _r in _app.routes:
    _methods = sorted(getattr(_r, "methods", None) or [])
    _path = getattr(_r, "path", "")
    if not _methods or not _path:
        continue
    for _conv in list(getattr(_r, "param_convertors", {}) or {}):
        _path = _path.replace("{" + _conv + "}", "x")
    for _m in [m for m in _methods if m in ("GET", "POST", "PUT", "DELETE", "PATCH")]:
        try:
            if _m == "GET":
                _client.request(_m, _path, params=_bag)
            else:
                _client.request(_m, _path, json=_bag)
            out["routes_tried"] += 1
        except Exception:
            pass
        if tb.hit_count() > 0 or pc.hit_count() > 0:
            break
out["track_a"] = ta.call_count(); out["track_b"] = tb.hit_count()
out["policy"] = pc.hit_count(); out["policy_samples"] = pc.hits()[:3]
print(json.dumps(out))
'''

#: FastAPI DAST（反射 XSS）模板：@@ROOT@@ @@APPFILE@@
_FASTAPI_DAST_TEMPLATE = r'''import sys, os, json, importlib.util, uuid

WORKSPACE = "/workspace"; _ROOT = @@ROOT@@
for _p in (WORKSPACE, _ROOT, "/tmp/stubs"):
    if _p not in sys.path and os.path.isdir(_p):
        sys.path.insert(0, _p)
from fastapi.testclient import TestClient   # 先导入真实框架，再装缺包桩
from modules.dynamic_verification.stubs import install_stub_finder
install_stub_finder()
_spec = importlib.util.spec_from_file_location("_probe_app", @@APPFILE@@)
_mod = importlib.util.module_from_spec(_spec); sys.modules["_probe_app"] = _mod
try:
    _spec.loader.exec_module(_mod)
except Exception as _e:
    print(json.dumps({"dast_missing_auth": [], "dast_xss": [], "dast_csrf": []})); sys.exit(0)
_app = None
for _v in list(vars(_mod).values()):
    if _v.__class__.__name__ == "FastAPI":
        _app = _v; break
if _app is None:
    _app = getattr(_mod, "app", None)
_hits = []
if _app is not None:
    from fastapi.testclient import TestClient
    _c = TestClient(_app, raise_server_exceptions=False)
    _tag = "osdx" + uuid.uuid4().hex[:8]; _raw = "<" + _tag + ">"
    for _r in _app.routes:
        _methods = sorted(getattr(_r, "methods", None) or [])
        _path = getattr(_r, "path", "")
        if "GET" not in _methods or not _path:
            continue
        for _conv in list(getattr(_r, "param_convertors", {}) or {}):
            _path = _path.replace("{" + _conv + "}", "x")
        _params = {k: _raw for k in ("q", "name", "search", "msg", "comment", "text", "id", "val")}
        try:
            _resp = _c.get(_path, params=_params)
        except Exception:
            continue
        if "html" in (_resp.headers.get("content-type") or "").lower() and _raw in _resp.text:
            _hits.append({"route": _path, "method": "GET", "marker": _raw,
                          "status": _resp.status_code})
print(json.dumps({"dast_missing_auth": [], "dast_xss": _hits[:50], "dast_csrf": []}))
'''


def _request_keys_in_func(file_path: Path, func: str) -> list[str]:
    """AST 扫指定函数体内读取的 request 键（GET/POST/FILES/form/args.get('k') 与 []）。

    :param file_path: 源码文件。
    :param func: 函数名。
    :return: 键名列表（保序去重）。
    """
    import ast as _ast
    try:
        tree = _ast.parse(file_path.read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, OSError):
        return []
    node = next((n for n in _ast.walk(tree)
                 if isinstance(n, _ast.FunctionDef) and n.name == func), None)
    if node is None:
        return []
    keys: list[str] = []
    seen: set[str] = set()

    def _is_request(sub: _ast.AST) -> bool:
        # request.GET / request.POST / request.FILES / request.form / request.args / request.query_params
        if isinstance(sub, _ast.Attribute) and isinstance(sub.value, _ast.Name):
            return sub.value.id == "request"
        return False

    for n in _ast.walk(node):
        if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute):
            base = n.func
            # request.GET.get('k') / request.POST.get('k') …
            if base.attr in ("get",) and _is_request(base.value):
                for a in n.args:
                    if isinstance(a, _ast.Constant) and isinstance(a.value, str):
                        if a.value not in seen:
                            seen.add(a.value); keys.append(a.value)
            # request.get_json() 之类标记为 body 读取
        elif isinstance(n, _ast.Subscript) and isinstance(n.value, _ast.Attribute):
            if _is_request(n.value) and isinstance(n.slice, _ast.Constant) and isinstance(n.slice.value, str):
                k = n.slice.value
                if k not in seen:
                    seen.add(k); keys.append(k)
    return keys


def _view_func_for_finding(finding: Finding) -> Optional[str]:
    """由 Finding 行号定位所在视图函数名（AST 最小包围函数）。

    :param finding: Finding。
    :return: 函数名或 None。
    """
    import ast as _ast
    p = Path(finding.file_path)
    if not p.is_file():
        return None
    try:
        tree = _ast.parse(p.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return None
    line = finding.location.start_line
    cand = None
    for n in _ast.walk(tree):
        if isinstance(n, _ast.FunctionDef) and n.lineno <= line <= (getattr(n, "end_lineno", n.lineno) or n.lineno):
            if cand is None or (n.end_lineno - n.lineno) < (cand.end_lineno - cand.lineno):
                cand = n
    return cand.name if cand else None


def _routes_for_func(project_root: Path, func: str) -> list[str]:
    """在工程 Python 源码里找 ``path('路由', ...视图.func)`` 匹配 func 的路由。

    :param project_root: 工程根。
    :param func: 视图函数名。
    :return: 路由路径列表（去重）。
    """
    out: list[str] = []
    pat = re.compile(r"path\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)\.%s\b" % re.escape(func))
    for p in project_root.rglob("*.py"):
        if "venv" in p.as_posix() or "node_modules" in p.as_posix():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in pat.finditer(text):
            route = m.group(1)
            if not route.startswith("/"):
                route = "/" + route
            if route not in out:
                out.append(route)
    return out


def _find_django_project(file_path: Path, max_up: int = 4) -> Optional[Path]:
    """从 Finding 文件向上找 Django 工程根。

    `manage.py` 所在目录视为工程根（最强信号）；否则退化为最近的含 settings.py
    目录（供无 manage.py 的极简工程使用）。

    :param file_path: 视图文件绝对路径。
    :param max_up: 最多向上级数。
    :return: 工程根目录或 None。
    """
    manage_root: Optional[Path] = None
    settings_root: Optional[Path] = None
    cur = file_path.parent
    for _ in range(max_up):
        if manage_root is None and (cur / "manage.py").is_file():
            manage_root = cur
        if settings_root is None and (cur / "settings.py").is_file():
            settings_root = cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return manage_root or settings_root


def detect_project_entry(target: Path) -> Optional[dict[str, Any]]:
    """由目标目录探测 Django 工程入口（root + settings 模块），供 DAST 扫描用。

    :param target: 目标工程目录。
    :return: {root, settings} 或 None（找不到 manage.py/settings.py）。
    """
    target = target.resolve()
    if not target.exists():
        return None
    probe: Optional[Path] = None
    if (target / "manage.py").is_file():
        probe = target / "manage.py"
    else:
        # 取任一层级最浅的 manage.py / settings.py 作为线索
        cands = list(target.rglob("manage.py")) or list(target.rglob("settings.py"))
        cands = [p for p in cands if "venv" not in p.as_posix() and "__pycache__" not in p.as_posix()]
        if not cands:
            return None
        cands.sort(key=lambda p: len(p.relative_to(target).parts))
        probe = cands[0]
    root = _find_django_project(probe) if probe.name != "manage.py" else probe.parent
    if root is None:
        return None
    settings = _settings_module(root)
    if not settings:
        return None
    return {"root": str(root), "settings": settings}


def _settings_module(project_root: Path) -> Optional[str]:
    """定位 settings.py 并给出模块名（相对 project_root 去扩展名）。"""
    hits = [p for p in project_root.rglob("settings.py")
            if "venv" not in p.as_posix() and "__pycache__" not in p.as_posix()]
    # 取层级最浅的（最外层 settings 通常是主配置）
    hits.sort(key=lambda p: len(p.relative_to(project_root).parts))
    if not hits:
        return None
    rel = hits[0].relative_to(project_root).with_suffix("")
    return ".".join(rel.parts)


class EntryDriver:
    """判断候选应用类型并构造探针脚本。"""

    def detect(self, finding: Finding) -> dict[str, Any]:
        """探测 Finding 所在文件能否作为 Flask/Django 应用驱动。

        :param finding: 候选 Finding。
        :return: {kind: 'flask'|'django'|'unsupported', reason?, file_path?, root?, settings?}。
        """
        file_path = Path(finding.file_path)
        if not file_path.is_file():
            return {"kind": "unsupported", "reason": "源文件不存在"}
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return {"kind": "unsupported", "reason": f"读取失败 {exc}"}

        # Flask 优先
        if "from flask import" in text and _FLASK_MARKER.search(text):
            return {"kind": "flask", "file_path": str(file_path.resolve())}

        # FastAPI / Starlette（装饰器 + APIRouter 风格）
        if "fastapi" in text or "APIRouter(" in text:
            app_file = _find_fastapi_app_file(file_path)
            if app_file is not None:
                return {"kind": "fastapi", "file_path": str(file_path.resolve()),
                        "root": str(app_file.parent.resolve()), "app_file": str(app_file.resolve())}

        # Django：文件在含 settings.py/manage.py 的项目树内
        proj = _find_django_project(file_path)
        if proj is not None:
            settings_mod = _settings_module(proj)
            if settings_mod:
                return {"kind": "django", "file_path": str(file_path.resolve()),
                        "root": str(proj.resolve()), "settings": settings_mod}
        return {"kind": "unsupported",
                "reason": "既非自包含 Flask 应用，也非可定位 settings.py 的 Django 视图"
                          "（可能依赖过重或入口不在本项目内）"}

    def build_probe_script(self, finding: Finding, workspace_root: Path,
                           target_root: Optional[Path] = None) -> str:
        """为 Flask 候选生成探针脚本源码。

        :param finding: Flask 候选 Finding。
        :param workspace_root: 仓库根（挂载为容器 /workspace）；据此把宿主绝对路径
            换算为容器内路径。
        :return: 脚本源码。
        """
        container_path: str = self._to_container(Path(finding.file_path), workspace_root,
                                                 target_root)
        return _FLASK_PROBE_TEMPLATE.replace("@@FILE@@", json.dumps(container_path))

    def build_django_probe(self, finding: Finding, workspace_root: Path,
                           entry: dict[str, Any]) -> str:
        """为 Django 候选生成探针脚本源码。

        :param finding: Django 候选 Finding。
        :param workspace_root: 仓库根（挂载为 /workspace）。
        :param entry: detect() 返回的 django 条目（含 root/settings）。
        :return: 脚本源码。
        """
        root_abs = Path(entry["root"])
        cont_root: str = container_root_for(root_abs, workspace_root)
        settings: str = str(entry["settings"])
        return (_DJANGO_PROBE_TEMPLATE
                .replace("@@ROOT@@", json.dumps(cont_root))
                .replace("@@SETTINGS@@", json.dumps(settings)))

    def build_django_http_probe(self, finding: Finding, workspace_root: Path,
                                entry: dict[str, Any],
                                extra_keys: Optional[list[str]] = None,
                                params: Optional[dict[str, str]] = None) -> str:
        """为 Django 候选生成"真 HTTP"探针脚本源码。

        探针内：依赖桩(缺包才注入) -> django.setup + 免 CSRF -> 三层补丁 -> migrate
        -> 会话直连(活跃用户+session cookie+_auth_user_hash) -> 同进程 WSGI 起服
        -> 对 "该 Finding 视图函数对应路由" 逐个 GET/POST 携带 canary 载荷。

        参数定位（通用，不特化 pygoat）：
        - 用 AST 扫该视图函数读取的 request 键（extra_keys），避免只靠通配参数包；
        - 路由用 hosts 侧直接注册匹配 + 探针内可退化为全 resolver 枚举。

        :param finding: Django 候选 Finding。
        :param workspace_root: 仓库根（挂载为 /workspace）。
        :param entry: detect() 的 django 条目（root/settings）。
        :param extra_keys: 额外请求键（来自视图函数读取点）。
        :param params: LLM/静态给出的精确参数 {key: value}（覆盖通配值，可含 canary）。
        :return: 脚本源码。
        """
        root_abs = Path(entry["root"])
        cont_root: str = container_root_for(root_abs, workspace_root)
        func: Optional[str] = _view_func_for_finding(finding)
        routes: list[str] = _routes_for_func(root_abs, func) if func else []
        if not routes and finding.file_path:
            # 兜底：至少探测 '/'（可能有跨文件的 include 注册）
            routes = ["/"]
        extra: list[str] = list(extra_keys or [])
        if func and finding.file_path:
            # AST 读点键并入载荷（去重、去通配包已含项由模板处理）
            for k in _request_keys_in_func(Path(finding.file_path), func):
                if k not in extra:
                    extra.append(k)
        settings: str = str(entry["settings"])
        param_json: dict[str, str] = {str(k): str(v) for k, v in (params or {}).items()}
        return (_DJANGO_HTTP_PROBE_TEMPLATE
                .replace("@@ROOT@@", json.dumps(cont_root))
                .replace("@@SETTINGS@@", json.dumps(settings))
                .replace("@@ROUTES@@", json.dumps(routes))
                .replace("@@EXTRA@@", json.dumps(extra))
                .replace("@@PARAMS@@", json.dumps(param_json)))

    def build_dast_probe(self, entry: dict[str, Any], workspace_root: Path) -> str:
        """生成"缺鉴权"路线级 DAST 探针脚本（与 findings 无关）。

        :param entry: detect() 的 django 条目（root/settings）。
        :param workspace_root: 仓库根（挂载为 /workspace）。
        :return: 脚本源码。
        """
        root_abs = Path(entry["root"])
        cont_root: str = container_root_for(root_abs, workspace_root)
        return (_DAST_PROBE_TEMPLATE
                .replace("@@ROOT@@", json.dumps(cont_root))
                .replace("@@SETTINGS@@", json.dumps(str(entry["settings"]))))

    @staticmethod
    def _to_container(path: Path, workspace_root: Path,
                      target_root: Optional[Path] = None) -> str:
        """宿主路径 -> 容器内路径。

        约定：位于仓库内 -> ``/workspace/<相对路径>``；仓库**外**的目标工程 ->
        ``/target/<相对 target 根的路径>``（与 sandbox 挂载点、provision 一致）。
        旧实现在仓库外会返回宿主绝对路径（容器内不存在）导致探针必失败。

        :param path: 宿主路径。
        :param workspace_root: 仓库根（挂载为 /workspace）。
        :param target_root: 被测工程根（仓库外时用于换算 /target 下的相对路径）。
        :return: 容器内路径。
        """
        p = Path(path).resolve()
        try:
            return "/workspace/" + p.relative_to(Path(workspace_root).resolve()).as_posix()
        except ValueError:
            pass
        if target_root is not None:
            try:
                return (OUTSIDE_TARGET_MOUNT + "/"
                        + p.relative_to(Path(target_root).resolve()).as_posix())
            except ValueError:
                pass
        return OUTSIDE_TARGET_MOUNT + "/" + p.name

    def build_fastapi_probe(self, finding: Finding, workspace_root: Path,
                            entry: dict[str, Any],
                            params: Optional[dict[str, str]] = None) -> str:
        """生成 FastAPI 探针（TestClient 同进程，sink 双轨/策略计数）。

        :param finding: 候选 Finding（暂不强依赖其位置，按应用全路由探测）。
        :param workspace_root: 仓库根。
        :param entry: detect() 的 fastapi 条目（root/app_file）。
        :param params: LLM/静态给出的精确参数。
        :return: 脚本源码。
        """
        cont_app = self._to_container(Path(entry["app_file"]), workspace_root, entry.get("root"))
        cont_root = container_root_for(Path(entry["root"]), workspace_root)
        return (_FASTAPI_PROBE_TEMPLATE
                .replace("@@ROOT@@", json.dumps(cont_root))
                .replace("@@APPFILE@@", json.dumps(cont_app))
                .replace("@@PARAMS@@", json.dumps({str(k): str(v) for k, v in (params or {}).items()})))

    def build_fastapi_dast(self, entry: dict[str, Any], workspace_root: Path) -> str:
        """生成 FastAPI DAST（反射 XSS）探针。

        :param entry: detect() 的 fastapi 条目。
        :param workspace_root: 仓库根。
        :return: 脚本源码。
        """
        cont_app = self._to_container(Path(entry["app_file"]), workspace_root, entry.get("root"))
        cont_root = container_root_for(Path(entry["root"]), workspace_root)
        return (_FASTAPI_DAST_TEMPLATE
                .replace("@@ROOT@@", json.dumps(cont_root))
                .replace("@@APPFILE@@", json.dumps(cont_app)))

    @staticmethod
    def parse_dast_full(stdout: str) -> dict[str, list[dict[str, Any]]]:
        """解析 DAST 探针输出（三类：缺鉴权 / 反射 XSS / 缺 CSRF）。

        :param stdout: 容器输出。
        :return: {"missing_auth":[...], "xss":[...], "csrf":[...]}。
        """
        for line in reversed((stdout or "").strip().splitlines()):
            if line.lstrip().startswith("{"):
                try:
                    data = json.loads(line)
                    return {
                        "missing_auth": list(data.get("dast_missing_auth") or []),
                        "xss": list(data.get("dast_xss") or []),
                        "csrf": list(data.get("dast_csrf") or []),
                    }
                except json.JSONDecodeError:
                    continue
        return {"missing_auth": [], "xss": [], "csrf": []}

    @staticmethod
    def parse_dast_result(stdout: str) -> list[dict[str, Any]]:
        """解析 DAST 探针输出中的"缺鉴权"路由列表（兼容旧调用）。

        :param stdout: 容器输出。
        :return: 可疑路由列表。
        """
        return EntryDriver.parse_dast_full(stdout)["missing_auth"]

    @staticmethod
    def parse_result(stdout: str) -> Optional[dict[str, Any]]:
        """从探针 stdout 解析最后一行 JSON。

        :param stdout: 容器 stdout。
        :return: dict 或 None。
        """
        lines = [ln for ln in (stdout or "").strip().splitlines() if ln.lstrip().startswith("{")]
        if not lines:
            return None
        try:
            return json.loads(lines[-1])
        except json.JSONDecodeError:
            return None
