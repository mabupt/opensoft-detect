"""依赖漏洞检查器（DepChecker）—— 基于 pip-audit + OSV 精确 pin。

对目标工程里的依赖清单（requirements*.txt / Pipfile.lock / poetry.lock）找漏洞：

- **主通道**：host ``pip-audit -r <file> --format json``（需能解析/可装 wheels）；
- **回退通道（OSV 精确 pin）**：当 pip-audit 因旧 pin 无对应平台 wheel、需源码
  编译而解析失败时，直接按 ``name==version`` 精确版本查 OSV 数据库
  （api.osv.dev/querybatch），无需安装/容器，对 2021 年代旧 pin 最可靠。

设计要点：
- 清单位置不从 scan_scope 找（.py 之外的清单在模块0 记 unsupported_ext），改从
  manifest.excluded 反查；多个清单分别审计合并；
- 任一通道失败都不影响其它引擎（明确日志降级）。
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Optional

from config import ToolConfig
from models import (ConfidenceLevel, Finding, Location, Severity, ToolName,
                    VulnerabilityStatus)
from modules.preprocess.manifest import load_manifest
from modules.static_analysis.base import AnalyzerBase
from modules.static_analysis.parsers import make_id, parse_pip_audit_json, run_subprocess

logger = logging.getLogger("opensoft_detect.static_analysis.dep")

#: pip-audit 支持的依赖清单文件名特征
_CANDIDATE_SUFFIXES: tuple[str, ...] = (".txt", ".lock")
_CANDIDATE_EXACT: frozenset[str] = frozenset({"Pipfile.lock", "poetry.lock"})


class DepChecker(AnalyzerBase):
    """基于 pip-audit 的依赖漏洞分析器。"""

    tool: ToolName = ToolName.PIP_AUDIT

    def is_available(self) -> bool:
        """检测 pip-audit 是否在本机 PATH 中。

        :return: True 表示可运行。
        """
        if not shutil.which(self.tool_cfg.pip_audit_bin):
            logger.warning("pip-audit 未安装（找不到可执行文件：%s），该引擎将被跳过。",
                           self.tool_cfg.pip_audit_bin)
            return False
        return True

    def run(self, manifest_path: Path) -> list[Finding]:
        """定位依赖清单并对每个清单做 pip-audit，合并全部结果。

        :param manifest_path: file_manifest.json 路径。
        :return: 依赖漏洞 Finding 列表。
        """
        try:
            manifest = load_manifest(manifest_path)
        except OSError as exc:
            logger.error("读取清单失败，DepChecker 跳过：%s", exc)
            return []

        dep_files: list[Path] = self._locate_dep_files(manifest)
        if not dep_files:
            # 通用兜底：PyPI 已打包应用（wheel 解包目录）常无 requirements，依赖声明
            # 只在 *.dist-info/METADATA 的 Requires-Dist 里。抽取成 requirements 文本
            # 后复用同一条审计通道（否则这类项目依赖审计恒为 0 条）。
            derived = self._derive_from_metadata(Path(manifest.get("target") or "."),
                                                 manifest_path.parent)
            if derived is not None:
                dep_files = [derived]
        if not dep_files:
            logger.warning("未在目标工程中发现 requirements/Pipfile/poetry/dist-info "
                           "依赖清单，DepChecker 无内容可审计。")
            return []

        findings: list[Finding] = []
        min_ord = SeverityLevelOrder(self.tool_cfg.pip_audit_severity_min)
        for dep_file in dep_files:
            try:
                one = self._audit_one(dep_file)
                # 依据配置的最低严重程度过滤
                kept = [f for f in one if min_ord.allow(f.severity)]
                findings.extend(kept)
                logger.info("pip-audit 审计 %s：%d 条（>=%s）",
                            dep_file.name, len(kept), min_ord.name)
            except Exception as exc:  # noqa: BLE001 - 单清单失败降级
                self.last_error = f"审计 {dep_file.name} 失败: {exc}"
                logger.error("pip-audit 审计 %s 失败（已跳过该清单）：%s",
                             dep_file, exc)
        return self.post_process(findings)

    # ---- 内部 ----
    def _locate_dep_files(self, manifest: dict) -> list[Path]:
        """从 manifest.excluded 中反查候选依赖清单文件。

        requirements*.txt / 任意 .lock 结尾且名字命中，或精确命中 Pipfile.lock /
        poetry.lock。

        :param manifest: 清单字典。
        :return: 命中的清单绝对路径列表。
        """
        found: dict[str, Path] = {}
        for rec in manifest.get("excluded") or []:
            if rec.get("kind") != "file":
                continue
            name = Path(rec.get("rel_path") or "").name
            if name in _CANDIDATE_EXACT or (
                name.lower().endswith(".txt") and name.lower().startswith("requirements")
            ) or name == "poetry.lock" or name == "Pipfile.lock":
                p = Path(rec.get("path") or "")
                if p.is_file():
                    found[str(p)] = p
        return list(found.values())

    def _derive_from_metadata(self, target: Path, out_dir: Path) -> Optional[Path]:
        """从 ``*.dist-info/METADATA`` 的 Requires-Dist 派生 requirements 文件。

        适用：wheel 解包/已安装的 PyPI 应用（无 requirements/pyproject）。
        解析规则（保守）：只取声明行；跳过带 ``extra ==`` 的可选依赖组；
        ``foo (>=1.0)`` -> ``foo>=1.0``；丢掉 ``;`` 之后的环境 marker。

        :param target: 目标工程根。
        :param out_dir: 产物目录（派生文件写到其 .cache 下）。
        :return: 派生出的 requirements 文件路径；无内容返回 None。
        """
        specs: list[str] = []
        seen: set[str] = set()
        try:
            metas = list(Path(target).rglob("*.dist-info/METADATA"))[:50]
        except OSError:
            return None
        for meta in metas:
            try:
                text = meta.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in text.splitlines():
                if not line.startswith("Requires-Dist:"):
                    continue
                spec = line.split(":", 1)[1].strip()
                if "extra ==" in spec:
                    continue
                spec = spec.split(";")[0].strip()
                spec = re.sub(r"\(([^)]*)\)", r"\1", spec)
                spec = spec.strip()
                if spec and spec not in seen:
                    seen.add(spec)
                    specs.append(spec)
        if not specs:
            return None
        cache = Path(out_dir) / ".cache"
        try:
            cache.mkdir(parents=True, exist_ok=True)
            out = cache / "derived_requirements.txt"
            out.write_text("\n".join(specs) + "\n", encoding="utf-8")
        except OSError as exc:
            logger.warning("派生 requirements 写入失败：%s", exc)
            return None
        logger.info("无 requirements 清单，已从 %d 个 dist-info/METADATA 派生 %d 条依赖"
                    "（Requires-Dist）用于审计。", len(metas), len(specs))
        return out

    def _audit_one(self, dep_file: Path) -> list[Finding]:
        """对单个依赖清单审计：优先 pip-audit，解析失败回退 OSV 精确 pin。

        :param dep_file: 依赖清单绝对路径。
        :return: Finding 列表（任一通道成功即返回其结果；都失败抛错）。
        :raises RuntimeError: 两通道均失败。
        """
        # 主通道：host pip-audit
        try:
            return self._audit_via_pip_audit(dep_file)
        except Exception as exc:  # noqa: BLE001 - 旧 pin 无法解析/构建时回退
            logger.warning("pip-audit 通道失败（%s），改用 OSV 精确 pin 审计 %s",
                           exc, dep_file.name)
        # 回退通道：OSV 精确版本查询（无需安装/容器）
        return self._audit_via_osv(dep_file)

    def _audit_via_pip_audit(self, dep_file: Path) -> list[Finding]:
        """host 上执行 pip-audit 并解析。

        :param dep_file: 依赖清单。
        :return: Finding 列表。
        :raises RuntimeError: 子进程失败或输出无法解析。
        """
        # 结果缓存（按清单内容哈希 + TTL）：pip-audit 解析慢且有网络依赖
        cache_file = _json_cache_path("pipaudit", dep_file.read_bytes())
        cached = _json_cache_load(cache_file)
        if cached is not None:
            logger.info("pip-audit 命中本地缓存：%s", dep_file.name)
            return parse_pip_audit_json(cached, dep_file=str(dep_file))
        cmd = [
            self.tool_cfg.pip_audit_bin, "-r", str(dep_file),
            "--format", "json",
            "--progress-spinner", "off",
        ]
        code, out, err = run_subprocess(cmd, timeout=300)
        # pip-audit 检出漏洞时退出码为 1（0=无漏洞），两者都算命令成功
        if code not in (0, 1):
            raise RuntimeError(f"pip-audit 返回码 {code}: {err[:800]}")
        try:
            raw = json.loads(out)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"pip-audit 输出不是合法 JSON: {exc}") from exc
        _json_cache_save(cache_file, raw)
        return parse_pip_audit_json(raw, dep_file=str(dep_file))

    def _audit_via_osv(self, dep_file: Path) -> list[Finding]:
        """按 requirements 里的 ``name==version`` 精确 pin 查 OSV 数据库。

        :param dep_file: 依赖清单。
        :return: Finding 列表。
        :raises RuntimeError: 无 pin 可查 / 网络失败。
        """
        pins: list[tuple[str, str]] = parse_pins(dep_file)
        if not pins:
            raise RuntimeError(f"{dep_file} 中没有可解析的 == pin")
        # 本地缓存（内容哈希 + TTL），避免每轮依赖网络、保证计数稳定可复现
        cache_file = _osv_cache_path(pins)
        cached = _osv_cache_load(cache_file)
        if cached is not None:
            logger.info("OSV 命中本地缓存：%s（%d pin）", cache_file.name, len(pins))
            batched = cached
        else:
            # 一次 querybatch 批量查询全部 pin，避免逐 pin 网络往返
            batched = osv_query_batch(pins)
            _osv_cache_save(cache_file, batched)
        findings: list[Finding] = []
        for name, version, vulns in batched:
            for v in vulns:
                findings.append(_finding_from_osv(v, name, version, str(dep_file)))
        logger.info("OSV 审计 %s：%d 个精确 pin -> %d 条漏洞",
                    dep_file.name, len(pins), len(findings))
        return findings


class SeverityLevelOrder:
    """严重程度"阈值"封装：用于按最低级别过滤依赖漏洞。"""

    _ORDER: dict[str, int] = {
        Severity.CRITICAL.value: 4,
        Severity.HIGH.value: 3,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 1,
        Severity.INFO.value: 0,
    }

    def __init__(self, min_level: str) -> None:
        """构造阈值。

        :param min_level: 最低级别名（low/medium/high/critical），非法回落 low。
        """
        self.name: str = min_level.strip().lower()
        self._floor: int = self._ORDER.get(self.name, 1)

    def allow(self, severity: Severity) -> bool:
        """判断严重程度是否达到/超过阈值。

        :param severity: 待判断严重程度。
        :return: True 表示应保留。
        """
        return self._ORDER.get(severity.value, 0) >= self._floor


# ---------------------------------------------------------------------------
# OSV 精确 pin 回退通道
# ---------------------------------------------------------------------------

#: requirements 里 ``name==version``（含 ===、可带注释尾）
_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:===|==)\s*([0-9][A-Za-z0-9_.\-]*)")
_OSV_ENDPOINT: str = "https://api.osv.dev/v1/querybatch"
#: OSV 本地缓存目录与 TTL（秒）
_OSV_CACHE_DIR: Path = Path(__file__).resolve().parents[2] / "output" / ".cache"
_OSV_CACHE_TTL: int = 7 * 24 * 3600


def _json_cache_path(prefix: str, key_bytes: bytes) -> Path:
    """通用 JSON 缓存路径（前缀 + 内容哈希）。

    :param prefix: 缓存类别前缀（如 pipaudit / osv）。
    :param key_bytes: 决定缓存键的字节（清单内容等）。
    :return: 缓存文件路径。
    """
    import hashlib as _h
    return _OSV_CACHE_DIR / f"{prefix}_{_h.sha256(key_bytes).hexdigest()[:16]}.json"


def _json_cache_load(path: Path) -> Optional[Any]:
    """读取未过期 JSON 缓存（无/过期/损坏返回 None）。"""
    import time as _t
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if _t.time() - float(data.get("ts", 0)) > _OSV_CACHE_TTL:
            return None
        return data.get("payload")
    except Exception:  # noqa: BLE001
        return None


def _json_cache_save(path: Path, payload: Any) -> None:
    """写入 JSON 缓存（失败忽略）。"""
    import time as _t
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"ts": _t.time(), "payload": payload},
                                   ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        logger.debug("缓存写入失败：%s", exc)


def _osv_cache_path(pins: list[tuple[str, str]]) -> Path:
    """由 pin 集合生成稳定缓存文件名（内容哈希）。

    :param pins: (name, version) 列表。
    :return: 缓存文件路径。
    """
    import hashlib as _h
    key = _h.sha256(json.dumps(sorted(pins)).encode()).hexdigest()[:16]
    return _OSV_CACHE_DIR / f"osv_{key}.json"


def _osv_cache_load(path: Path) -> Optional[list[tuple[str, str, list[dict]]]]:
    """读取未过期的 OSV 缓存；无/过期返回 None。"""
    import time as _t
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if _t.time() - float(data.get("ts", 0)) > _OSV_CACHE_TTL:
            return None
        return [(str(n), str(v), list(vs)) for n, v, vs in data.get("items", [])]
    except Exception:  # noqa: BLE001
        return None


def _osv_cache_save(path: Path, batched: list[tuple[str, str, list[dict]]]) -> None:
    """写入 OSV 缓存（失败忽略，不影响主流程）。"""
    import time as _t
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"ts": _t.time(), "items": batched},
                                   ensure_ascii=False), encoding="utf-8")
    except OSError as exc:  # noqa: PERF203
        logger.debug("OSV 缓存写入失败：%s", exc)


def parse_pins(dep_file: Path) -> list[tuple[str, str]]:
    """解析依赖清单为精确 (name, version) 列表。

    支持 requirements 文本与 poetry.lock / Pipfile.lock 的 JSON。
    两段式版本（如 django==4.2）视为该主版本首个补丁（4.2.0）后再查，
    使 OSV 命中更贴合 pip 实际安装。

    :param dep_file: 依赖清单。
    :return: [(name, version), ...]。
    """
    try:
        text = dep_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return []
        out: list[tuple[str, str]] = []
        # poetry.lock: {"package": [{"name","version"}]}
        for pkg in obj.get("package") or []:
            if pkg.get("name") and pkg.get("version"):
                out.append((pkg["name"], str(pkg["version"])))
        # Pipfile.lock: {"default": {name: {"version": "==1.2.3"}}, "develop": {...}}
        for section in ("default", "develop"):
            for name, meta in (obj.get(section) or {}).items():
                ver = str((meta or {}).get("version", ""))
                if ver.startswith("=="):
                    out.append((name, ver[2:]))
        return _normalize_pins(out)
    pins: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = _PIN_RE.match(line)
        if m:
            pins.append((m.group(1), m.group(2)))
    return _normalize_pins(pins)


def _normalize_pins(pins: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """把两段式版本补成三段（django==4.2 -> 4.2.0），去重保序。"""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for name, version in pins:
        ver = version
        if ver.count(".") == 1:
            ver = f"{ver}.0"
        key = (name.lower(), ver)
        if key in seen:
            continue
        seen.add(key)
        out.append((name, ver))
    return out


def osv_query_batch(pins: list[tuple[str, str]]) -> list[tuple[str, str, list[dict]]]:
    """一次 querybatch 查全部 pin，返回 [(name, version, vulns)] 对齐结果。

    :param pins: (name, version) 列表。
    :return: 与 pins 等长/对齐的 [(name, version, vulns)]。
    :raises RuntimeError: 网络/HTTP 失败。
    """
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v}
               for n, v in pins]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(_OSV_ENDPOINT, data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.load(resp)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"OSV querybatch 失败（{len(pins)} pin）：{exc}") from exc
    results = data.get("results") or []
    out: list[tuple[str, str, list[dict]]] = []
    for idx, (name, version) in enumerate(pins):
        res = results[idx] if idx < len(results) else {}
        out.append((name, version, res.get("vulns") or []))
    return out


def _finding_from_osv(vuln: dict, name: str, version: str, dep_file: str) -> Finding:
    """把一条 OSV 漏洞转成 Finding。

    :param vuln: OSV vulnerability 对象。
    :param name: 包名。
    :param version: 版本。
    :param dep_file: 依赖清单路径。
    :return: Finding。
    """
    vid: str = str(vuln.get("id") or "OSV-?")
    aliases: list[str] = [str(a) for a in (vuln.get("aliases") or [])]
    rule_id: str = next((a for a in aliases if a.upper().startswith("CVE-")), vid)
    summary: str = str(vuln.get("summary") or "")[:300]
    # 严重程度：取 severity 列表里最高的 CVSS 分数
    score: float = 0.0
    for sev in vuln.get("severity") or []:
        try:
            score = max(score, float(sev.get("score")))
        except (TypeError, ValueError):
            continue
    severity = _severity_from_score(score) if score else Severity.MEDIUM
    # 修复版本提示：affected[].ranges[].events 里 fixed 的并集
    fixes: list[str] = []
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed") and str(ev["fixed"]) not in fixes:
                    fixes.append(str(ev["fixed"]))
    message = (f"[{name}=={version}] {summary or vid}"
               + (f" (修复版本: {', '.join(fixes[:5])})" if fixes else ""))
    return Finding(
        id=make_id(ToolName.PIP_AUDIT, dep_file, rule_id),
        tool=ToolName.PIP_AUDIT,
        rule_id=rule_id,
        rule_name=f"dependency-{name}",
        severity=severity,
        message=message,
        cwe_ids=[],
        file_path=dep_file,
        location=Location(file_path=dep_file, start_line=1, end_line=1),
        confidence=ConfidenceLevel.HIGH,
        status=VulnerabilityStatus.NEW,
        raw=vuln,
        metadata={"package": name, "version": version,
                  "osv_id": vid, "aliases": aliases,
                  "fix_versions": fixes[:5],
                  "audit_source": "osv-exact-pin"},
    )


def _severity_from_score(score: float) -> Severity:
    """CVSS 分数 -> Severity。"""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
