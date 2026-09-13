"""工具输出归一化解析器（parsers）。

把三个静态工具异构的输出解析为统一的 :class:`models.Finding`：

- Semgrep：``--json`` 输出（results/errors 结构）
- CodeQL：SARIF 2.1.0
- pip-audit：``--format json`` 输出（新旧两种容器结构都兼容）

所有解析函数都做**宽容处理**：字段缺失回落到默认值、单个条目损坏跳过其余
照常解析，保证"一个坏结果不毁掉整批结果"。
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Iterable, Optional

from models import (ConfidenceLevel, Finding, Location, Severity, ToolName,
                    VulnerabilityStatus)

logger = logging.getLogger("opensoft_detect.static_analysis.parsers")

#: 从任意文本中抽取 CWE 编号
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# 通用辅助
# ---------------------------------------------------------------------------

def _cwe(cwe_ids: Iterable[str]) -> list[str]:
    """把任意来源的 CWE 表述统一为去重、大写编号列表。"""
    seen: set[str] = set()
    out: list[str] = []
    for item in cwe_ids:
        for m in _CWE_RE.findall(str(item)):
            norm = m.upper()
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
    return out


def make_id(tool: ToolName, file_path: str, rule_id: str, line: int = 0) -> str:
    """构造稳定、可读、可去重的 Finding.id。

    形如：``SEMGREP@path/to/file.py@rule.id@12``。

    :param tool: 来源工具。
    :param file_path: 文件绝对路径。
    :param rule_id: 规则 ID。
    :param line: 起始行号。
    :return: id 字符串。
    """
    return f"{tool.value.upper()}@{file_path}@{rule_id}@{line}"


def _safe_int(value: Any, default: int = 0) -> int:
    """宽容转 int。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _snippet_of(text: Any, max_len: int = 2000) -> str:
    """把 lines/snippet 文本截断到 max_len。"""
    return str(text or "")[:max_len]


# ---------------------------------------------------------------------------
# Semgrep JSON 解析
# ---------------------------------------------------------------------------

#: Semgrep severity -> 内部 Severity
_SEMGREP_SEV = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def parse_semgrep_json(text: str) -> list[Finding]:
    """解析 Semgrep ``--json`` 输出文本为 Finding 列表。

    Semgrep 结果结构：``results[]`` 每个含 check_id / path / start|end / extra
    （message / severity / metadata.cwe / lines / fix 等）。

    :param text: Semgrep 原始 stdout。
    :return: Finding 列表（无结果返回空列表）。
    :raises json.JSONDecodeError: 输出不是合法 JSON（由上层捕获降级）。
    """
    raw: dict[str, Any] = json.loads(text)
    results: list[dict[str, Any]] = raw.get("results") or []
    findings: list[Finding] = []

    # errors 段只做日志留痕，不中断结果解析
    for err in raw.get("errors") or []:
        logger.warning("Semgrep 报告错误: %s", err.get("message") or err)

    for res in results:
        try:
            extra: dict[str, Any] = res.get("extra") or {}
            metadata: dict[str, Any] = extra.get("metadata") or {}
            file_path: str = str(res.get("path") or "")
            start: dict[str, Any] = res.get("start") or {}
            end: dict[str, Any] = res.get("end") or start

            severity: Severity = _SEMGREP_SEV.get(
                str(extra.get("severity", "WARNING")).upper(), Severity.MEDIUM)
            rule_id: str = str(res.get("check_id") or "unknown")
            loc = Location(
                file_path=file_path,
                start_line=_safe_int(start.get("line"), 1),
                end_line=_safe_int(end.get("line"), start.get("line", 1)),
                start_col=_safe_int(start.get("col"), 1),
                end_col=_safe_int(end.get("col"), start.get("col", 1)),
                snippet=_snippet_of(extra.get("lines")),
            )
            findings.append(Finding(
                id=make_id(ToolName.SEMGREP, file_path, rule_id, loc.start_line),
                tool=ToolName.SEMGREP,
                rule_id=rule_id,
                rule_name=str(extra.get("message") or "")[:120],
                rule_url=str(metadata.get("source") or "") if metadata.get("source") else "",
                severity=severity,
                message=str(extra.get("message") or rule_id),
                cwe_ids=_cwe(metadata.get("cwe") or []),
                file_path=file_path,
                location=loc,
                confidence=ConfidenceLevel.MEDIUM,
                status=VulnerabilityStatus.NEW,
                raw=res,
                metadata={
                    "confidence": str(metadata.get("confidence", "")),
                    "tags": list(metadata.get("technology") or []),
                },
            ))
        except Exception:  # noqa: BLE001 - 单条损坏跳过，不影响整体
            logger.warning("解析 Semgrep 单条结果失败，已跳过", exc_info=True)
    return findings


# ---------------------------------------------------------------------------
# CodeQL SARIF 2.1.0 解析
# ---------------------------------------------------------------------------

#: SARIF level -> 内部 Severity
_SARIF_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _uri_to_path(uri: Any, target_root: Optional[Path]) -> str:
    """把 SARIF 的 artifactLocation.uri 转成本机绝对路径。

    CodeQL 在未加 ``--sarif-add-snippets`` 等选项时，uri 通常是相对 source-root
    的 POSIX 路径；若以 file:// 开头则剥掉 scheme；相对路径用 target_root 补齐。

    :param uri: SARIF uri（任意类型）。
    :param target_root: manifest target 根目录。
    :return: 归一化绝对路径字符串。
    """
    text: str = str(uri or "").replace("\\", "/")
    if text.startswith("file://"):
        text = text[len("file://"):]
    p = Path(text)
    if p.is_absolute():
        return str(p)
    if target_root is not None:
        return str(target_root / p)
    return text


def parse_codeql_sarif(raw: dict[str, Any], target_root: Optional[Path] = None) -> list[Finding]:
    """解析 CodeQL 的 SARIF 2.1.0 JSON 为 Finding 列表。

    支持 ``runs[0]`` 单 run；rules 与 results 通过 ruleIndex/ruleId 关联。
    位置信息取自 ``locations[0].physicalLocation.region``。

    :param raw: json.loads 后的 SARIF 字典。
    :param target_root: 目标工程根目录（用于把相对 uri 归一化为绝对路径）。
    :return: Finding 列表。
    """
    runs: list[dict[str, Any]] = raw.get("runs") or []
    if not runs:
        return []
    run: dict[str, Any] = runs[0]

    # 规则表：ruleIndex -> rule 元数据
    driver: dict[str, Any] = run.get("tool", {}).get("driver", {}) or {}
    rules: list[dict[str, Any]] = driver.get("rules") or []
    rule_meta: dict[int, dict[str, Any]] = {}
    for idx, rule in enumerate(rules):
        props = rule.get("properties") or {}
        desc = (rule.get("fullDescription") or {}).get("text") \
            or (rule.get("shortDescription") or {}).get("text") or ""
        rule_meta[idx] = {
            "id": str(rule.get("id") or ""),
            "name": str(rule.get("name") or ""),
            "message": str(desc),
            "tags": list(props.get("tags") or []),
            "level": str(((rule.get("defaultConfiguration") or {}).get("level")) or "warning"),
            "help": str(props.get("help", "") or ""),
        }

    findings: list[Finding] = []
    for res in run.get("results") or []:
        try:
            rid: str = str(res.get("ruleId") or "")
            rule = rule_meta.get(_safe_int(res.get("ruleIndex"), -1)) \
                or {"id": rid, "message": rid, "tags": [], "level": "warning"}
            level: str = str(res.get("level") or rule["level"]).lower()
            severity: Severity = _SARIF_LEVEL.get(level, Severity.MEDIUM)

            # 取第一个物理位置（多位置告警只取主位置）
            locs = res.get("locations") or []
            phys = (locs[0].get("physicalLocation") if locs else {}) or {}
            artifact = phys.get("artifactLocation") or {}
            region = phys.get("region") or {}
            file_path: str = _uri_to_path(artifact.get("uri"), target_root)

            start_line: int = _safe_int(region.get("startLine"), 1)
            loc = Location(
                file_path=file_path,
                start_line=start_line,
                end_line=_safe_int(region.get("endLine"), start_line),
                start_col=_safe_int(region.get("startColumn"), 1),
                end_col=_safe_int(region.get("endColumn"), 1),
                snippet=_snippet_of((region.get("snippet") or {}).get("text")),
            )

            message: str = str((res.get("message") or {}).get("text") or rule["message"])
            findings.append(Finding(
                id=make_id(ToolName.CODEQL, file_path, rid, start_line),
                tool=ToolName.CODEQL,
                rule_id=rid,
                rule_name=str(rule["name"]) if rule["name"] else rid,
                severity=severity,
                message=message,
                cwe_ids=_cwe(rule["tags"] + [rid]),
                file_path=file_path,
                location=loc,
                confidence=ConfidenceLevel.MEDIUM,
                status=VulnerabilityStatus.NEW,
                raw=res,
                metadata={"codeql_tags": rule["tags"]},
            ))
        except Exception:  # noqa: BLE001
            logger.warning("解析 CodeQL SARIF 单条结果失败，已跳过", exc_info=True)
    return findings


# ---------------------------------------------------------------------------
# pip-audit JSON 解析
# ---------------------------------------------------------------------------

def _severity_from_cvss(score: Any) -> Severity:
    """按 CVSS 分数映射严重程度。

    :param score: cvss 分值（可空/字符串）。
    :return: 对应 Severity。
    """
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def parse_pip_audit_json(raw: Any, dep_file: str = "") -> list[Finding]:
    """解析 pip-audit JSON 输出为 Finding 列表。

    兼容两种容器结构：
    - 新版对象：``{"dependencies": [{"name","version","vulns":[...]}]}``
    - 旧版数组：``[{"name","version","vulns":[...]}]``

    每个 vuln 含 id（PYSEC-*/CVE-*）、aliases、fix_versions、description 等。

    :param raw: pip-audit 输出（dict 或 list）。
    :param dep_file: 对应的依赖清单文件路径（作为 Finding.file_path 标注）。
    :return: Finding 列表。
    """
    deps: list[dict[str, Any]]
    if isinstance(raw, dict):
        deps = raw.get("dependencies") or []
    elif isinstance(raw, list):
        deps = raw
    else:
        return []

    findings: list[Finding] = []
    for dep in deps:
        try:
            name: str = str(dep.get("name") or "")
            version: str = str(dep.get("version") or "?")
            for vuln in dep.get("vulns") or []:
                aliases: list[str] = [str(a) for a in (vuln.get("aliases") or [])]
                vuln_id: str = str(vuln.get("id") or "")
                # 优先 CVE 编号做 rule_id（更可读），否则用 PYSEC
                rule_id: str = next((a for a in aliases if a.upper().startswith("CVE-")), vuln_id)
                cvss: Any = (vuln.get("cvss_v3") or {}).get("score") \
                    if isinstance(vuln.get("cvss_v3"), dict) else vuln.get("cvss")
                severity: Severity = _severity_from_cvss(cvss)
                cwes: list[str] = _cwe(aliases + [vuln_id])  # aliases 内可能有 CWE
                description: str = _snippet_of(vuln.get("description") or
                                               vuln.get("advisory") or vuln_id, 500)
                message = (f"[{name}=={version}] {description} "
                           f"(修复版本: {', '.join(vuln.get('fix_versions') or []) or '无'})")
                findings.append(Finding(
                    id=make_id(ToolName.PIP_AUDIT, dep_file, rule_id),
                    tool=ToolName.PIP_AUDIT,
                    rule_id=rule_id,
                    rule_name=f"dependency-{name}",
                    severity=severity,
                    message=message.strip(),
                    cwe_ids=cwes,
                    file_path=dep_file,
                    location=Location(file_path=dep_file, start_line=1, end_line=1),
                    confidence=ConfidenceLevel.HIGH,   # 依赖漏洞是事实性结论，初值给高
                    status=VulnerabilityStatus.NEW,
                    raw=dep,
                    metadata={"package": name, "version": version,
                              "fix_versions": list(vuln.get("fix_versions") or [])},
                ))
        except Exception:  # noqa: BLE001
            logger.warning("解析 pip-audit 单条依赖失败，已跳过", exc_info=True)
    return findings


# ---------------------------------------------------------------------------
# 外部工具子进程通用执行
# ---------------------------------------------------------------------------

def run_subprocess(cmd: list[str], timeout: int, cwd: Optional[Path] = None,
                   env: Optional[dict[str, str]] = None) -> tuple[int, str, str]:
    """以子进程方式执行外部工具并返回 (returncode, stdout, stderr)。

    统一在此封装 subprocess，所有模块1 引擎调用都走这里，便于集中：
    - 编码处理（Windows 下外部工具可能输出 GBK/UTF-8，宽容解码）
    - 超时转异常
    - 子进程非零退出不在此抛错（返回 returncode 由调用方判读并打日志）

    :param cmd: argv 命令。
    :param timeout: 超时秒数。
    :param cwd: 工作目录（可选）。
    :param env: 需要注入的额外环境变量（合并进 os.environ 后传给子进程）。
    :return: (returncode, stdout, stderr)。
    :raises RuntimeError: 启动失败 / 超时。
    """
    import subprocess
    proc_env: Optional[dict] = None
    if env:
        proc_env = dict(os.environ)
        proc_env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=proc_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"外部工具执行超时（>{timeout}s）: {' '.join(cmd[:3])}…") from None
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"外部工具启动失败: {exc}") from exc

    # 宽容解码：优先 UTF-8，失败降级本地编码
    def _decode(data: bytes) -> str:
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, AttributeError):
                continue
        return data.decode("utf-8", errors="replace")

    return proc.returncode, _decode(proc.stdout), _decode(proc.stderr)
