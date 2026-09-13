"""模块4 编排入口（runner）。

对模块3 研判后仍需确认的 Finding 做**动态验证**，产出
``output/dynamic_findings.json``。

流程：
1. 载入 verified_findings.json，筛出候选；
2. 判定部署 plan（compose / sqlite / non_db_only / unreachable）；
3. Docker 与镜像就绪（可拉取）后，逐候选尝试**应用入口驱动**：
   自包含 Flask 应用 -> 生成探针脚本进沙箱：先 install() 三层补丁再 import
   应用，开 source 注入兜底，用 test_client 命中路由并携带污点载荷；
4. 按**双轨判定**回写：
   - A+B 都触发 -> confirmed（status=DYNAMIC_CONFIRMED、test_status=confirmed、
     写 KB 闭环）
   - 仅 A -> retry_poc（标记被传递清洗，可走 poc.py 的 LLM 重试）
   - 均未触发 -> not_reproduced（**保守：不自动降级为误报**）
5. 无法驱动/跑不起来 -> 降级 skip_reason（app_unreachable / no_entry_driver 等）。
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from config import Config
from models import (ConfidenceLevel, Finding, Location, Severity, ToolName,
                    VulnerabilityStatus)
from modules.dynamic_verification.entry_driver import EntryDriver
from modules.dynamic_verification.poc import PocGenerator
from modules.dynamic_verification.sandbox import DockerExecutor, decide_deployment

logger = logging.getLogger("opensoft_detect.dynamic_verification")

#: DB 相关规则特征（non_db_only 时跳过数据库类漏洞）
_DB_HINTS: tuple[str, ...] = ("sql-", "sqlite", "sqli", "nosql", "database")

#: 探针 canary 令牌（与 entry_driver 模板里的常量保持一致）
_CANARY: str = "__OSD_CANARY_7f3a__"

#: 策略类别 -> 该类别 Finding 的特征（规则/消息/CWE 子串，用于相关性闸门）
_POLICY_RELEVANCE: dict[str, tuple[str, ...]] = {
    "weak_hash": ("weak", "hash", "md5", "sha1", "cwe-327", "cwe-328", "cwe-916",
                  "cwe-759", "cwe-760", "hashing"),
}


def _app_requires(target: Path, limit: int = 30) -> list[str]:
    """从目标内的 ``*.dist-info/METADATA`` 提取依赖名（PyPI 已打包应用通用）。

    用于 FastAPI 探针安装依赖：wheel 分发的工程常没有 requirements/pyproject，
    但 dist-info/METADATA 里带 ``Requires-Dist``。

    :param target: 目标目录。
    :param limit: 最多返回条数。
    :return: 依赖名（含版本约束）列表。
    """
    out: list[str] = []
    try:
        for md in target.rglob("*.dist-info/METADATA"):
            for line in md.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.startswith("Requires-Dist:"):
                    continue
                spec = line.split(":", 1)[1].strip()
                if ";" in spec:                      # 去掉环境标记
                    spec = spec.split(";", 1)[0].strip()
                name = spec.split("[", 1)[0].split(" ")[0].split("=", 1)[0].split("<", 1)[0] \
                    .split(">", 1)[0].split("~", 1)[0].strip()
                if name and name not in out:
                    out.append(name)
                if len(out) >= limit:
                    return out
    except OSError:
        pass
    return out


def _auth_relevant(finding: Finding) -> bool:
    """Finding 是否属于"鉴权/访问控制"类，适用于缺鉴权差分断言。

    :param finding: 当前 Finding。
    :return: True 表示可用缺鉴权证据。
    """
    blob = f"{finding.rule_id} {finding.rule_name} {finding.message} {' '.join(finding.cwe_ids)}".lower()
    hints = ("auth", "login", "access", "permission", "broken", "session", "otp",
             "cwe-287", "cwe-306", "cwe-862", "cwe-863", "cwe-284", "privilege")
    return any(h in blob for h in hints)


def _policy_relevant(finding: Finding, result: dict) -> bool:
    """策略命中是否与 Finding 类别匹配（避免跨类别误确认）。

    :param finding: 当前 Finding。
    :param result: 探针输出（含 policy_samples）。
    :return: True 表示该策略命中可用于本 Finding 的 confirmed 判定。
    """
    kinds = {str(s.get("policy")) for s in (result.get("policy_samples") or [])}
    if not kinds:
        kinds = {"weak_hash"}
    blob = f"{finding.rule_id} {finding.rule_name} {finding.message} {' '.join(finding.cwe_ids)}".lower()
    for kind in kinds:
        hints = _POLICY_RELEVANCE.get(kind)
        if hints and any(h in blob for h in hints):
            return True
    return False


def _llm_request_params(finding: Finding, config: Config) -> dict[str, str]:
    """让 LLM 依据代码上下文决定"哪个参数、什么值"能流到 sink。

    返回 {参数名: 值}，值中可用占位 __CAN__ 表示应注入 canary 令牌；
    无 Key/调用失败返回 {}（回退到 AST 通配参数）。

    :param finding: Django 候选 Finding。
    :param config: 全局配置。
    :return: 参数覆盖表。
    """
    try:
        from modules.llm_analysis.client import LLMClient
        client = LLMClient(config.llm)
        if not client.is_available():
            return {}
        ctx: dict = finding.metadata.get("code_context") or {}
        code: str = (ctx.get("text") or "")[:3000]
        route_hints: list = finding.metadata.get("route_summary") or []
        reads = sorted({str(k) for k in (finding.metadata.get("input_reads") or [])}) \
            if finding.metadata.get("input_reads") else []
        if not code:
            return {}
        system = (
            "# prompt_v=param.1\n你为 Web 漏洞动态验证设计请求参数。只输出 JSON，结构：\n"
            '{"params": {"<参数名>": "<值或 __CAN__>"}, "files": ["<文件字段名>"]}\n'
            "规则：把能到达 sink 的输入参数值设为 __CAN__；只需真正相关字段；"
            "需要上传文件的视图在 files 中给出字段名。不要输出其它文字。")
        user = (
            f"rule={finding.rule_id}\nsink 行={finding.location.start_line if finding.location else '?'}\n"
            f"候选路由={route_hints}\n已读参数={reads}\n"
            f"代码上下文：\n```python\n{code}\n```\n请给出请求参数设计。")
        resp = client.chat_json(system, user)
        params_raw = resp.get("params") or {}
        params: dict[str, str] = {}
        for k, v in list(params_raw.items())[:12]:
            val = str(v)
            if val.strip() == "__CAN__":
                val = _CANARY
            params[str(k)] = val
        return params
    except Exception as exc:  # noqa: BLE001 - LLM 失败回退 AST 通配
        logger.warning("LLM 参数规划失败，回退 AST 通配：%s", exc)
        return {}


def classify_dual_track(track_a_count: int, track_b_count: int,
                        policy_count: int = 0) -> str:
    """判定：confirmed / retry_poc / not_reproduced。

    判据（满足其一即 confirmed）：
    1. 双轨均触发（A>0 且 B>0）—— 污点直达型；
    2. **类别化策略断言命中**（policy>0）—— 策略型（如 weak_hash 用了弱算法），
       canary 口径测不到，由 PolicyChecker 直接断言。

    :param track_a_count: 轨道A sink 调用数。
    :param track_b_count: 轨道B 污点命中数。
    :param policy_count: 策略断言命中数。
    :return: 判定字符串。
    """
    if policy_count > 0:
        return "confirmed"
    if track_a_count > 0 and track_b_count > 0:
        return "confirmed"
    if track_a_count > 0:
        return "retry_poc"
    return "not_reproduced"


def run(verified_path: Path, manifest_path: Path, config: Config) -> Path:
    """执行模块4动态验证。

    :param verified_path: 模块3 产物路径。
    :param manifest_path: 模块0 清单路径。
    :param config: 全局配置。
    :return: dynamic_findings.json 绝对路径。
    """
    findings: list[Finding] = _load_findings(verified_path)
    manifest: dict[str, Any] = _load_manifest(manifest_path)
    logger.info("载入 %d 条 Finding 进入动态验证。", len(findings))

    executor = DockerExecutor(config.docker)
    docker_ok: bool = executor.available()
    plan: dict[str, Any] = decide_deployment(manifest, config.docker)
    attempt: bool = bool(getattr(config, "dynamic_attempts", False))

    # 自动供给：动态开启时，先确保"目标依赖已装"的项目镜像（缓存命中即复用）
    if attempt and docker_ok:
        try:
            from modules.dynamic_verification.provision import ensure_project_image
            tag = ensure_project_image(Path(manifest.get("target") or "."), config)
            if tag:
                config.docker.image = tag
                logger.info("动态使用自动供给镜像：%s", tag)
        except Exception as exc:  # noqa: BLE001 - 供给失败沿用原镜像
            logger.warning("自动供给失败（沿用原镜像）：%s", exc)

    # 镜像保障：开启真实探针且 Docker 可用时，缺镜像先尝试拉取一次
    image_ok: bool = False
    if docker_ok:
        image_ok = executor.image_available()
        if attempt and not image_ok:
            image_ok = executor.ensure_image()

    logger.info("部署计划 kind=%s | docker=%s | image=%s | attempt=%s | reason=%s",
                plan["kind"], docker_ok, image_ok, attempt, plan["reason"])

    from modules.llm_analysis.client import LLMClient
    poc = PocGenerator(LLMClient(config.llm))
    driver = EntryDriver()
    scratch: Path = config.paths.output_dir / ".probe_tmp"
    scratch.mkdir(parents=True, exist_ok=True)

    candidates: list[Finding] = select_candidates(findings)
    logger.info("候选 Finding：%d / %d", len(candidates), len(findings))

    confirmed_ids: list[str] = []
    for finding in candidates:
        dynamic = _handle_one(finding, executor, docker_ok, image_ok, plan, poc,
                              manifest, attempt, driver, scratch, config)
        finding.metadata["dynamic"] = dynamic
        if dynamic.get("verdict") == "confirmed":
            finding.status = VulnerabilityStatus.DYNAMIC_CONFIRMED
            finding.metadata["test_status"] = "confirmed"
            confirmed_ids.append(finding.id)
            logger.info("动态验证 confirmed：%s", finding.id)
        elif dynamic.get("verdict") == "retry_poc":
            logger.warning("动态验证 retry_poc（标记被清洗，可 LLM PoC 重试）：%s", finding.id)
        else:
            logger.info("动态验证 %s：%s（%s）", dynamic.get("verdict"), finding.id,
                        dynamic.get("skip_reason") or dynamic.get("detail", "")[:60])

    _store_confirmed_to_kb(config, findings, confirmed_ids)

    # 路线级 DAST 小扫描（不依赖静态发现）：目前只做"缺鉴权"，产新 Finding
    if attempt and bool(getattr(config, "dynamic_dast", True)) and docker_ok and image_ok:
        try:
            dast = _run_dast_scan(manifest, config, executor, scratch)
            if dast:
                findings.extend(dast)
                logger.info("DAST 缺鉴权扫描新增 %d 条 Finding。", len(dast))
        except Exception as exc:  # noqa: BLE001 - DAST 失败不影响主结果
            logger.warning("DAST 扫描失败（忽略）：%s", exc)

    out_path: Path = config.paths.default_dynamic_path
    summary: dict[str, int] = {}
    for f in findings:
        d = f.metadata.get("dynamic") or {}
        key = d.get("verdict", "not_tested")
        summary[key] = summary.get(key, 0) + 1
    payload: dict[str, Any] = {
        "version": "1.1",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": str(verified_path),
        "deploy_plan": plan,
        "docker_ok": docker_ok,
        "dynamic_summary": summary,
        "findings": [f.to_dict() for f in findings],
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("动态验证写入：%s | 结果分布 %s", out_path, summary)
    return out_path


# ---------------------------------------------------------------------------
# 单条处理
# ---------------------------------------------------------------------------

def _handle_one(finding: Finding,
                executor: DockerExecutor,
                docker_ok: bool,
                image_ok: bool,
                plan: dict[str, Any],
                poc: PocGenerator,
                manifest: dict[str, Any],
                attempt: bool,
                driver: EntryDriver,
                scratch: Path,
                config: Config) -> dict[str, Any]:
    """按降级优先级处理单个候选，返回 dynamic 记录。"""
    base = {"rule": finding.rule_id,
            "attempted_at": datetime.now().isoformat(timespec="seconds")}
    if not docker_ok:
        return {**base, "verdict": "skipped", "skip_reason": "docker_unavailable",
                "detail": "Docker daemon 不可达，无法动态执行"}
    if plan["kind"] == "unreachable":
        return {**base, "verdict": "skipped", "skip_reason": "app_unreachable",
                "detail": plan["reason"]}
    if plan.get("kind") == "non_db_only" and _is_db_like(finding):
        return {**base, "verdict": "skipped", "skip_reason": "db_unreachable",
                "detail": "数据库不可达，仅验证非数据库类漏洞，本 Finding 跳过"}
    if not image_ok:
        return {**base, "verdict": "skipped", "skip_reason": "sandbox_image_missing",
                "detail": f"沙箱镜像 {executor.cfg.image} 未就绪"}
    if not attempt:
        return {**base, "verdict": "skipped", "skip_reason": "no_entry_driver",
                "detail": "未启用 dynamic_attempts（config），不做泛化探针"}

    # 入口驱动探测（Flask / Django）
    entry = driver.detect(finding)
    kind: str = entry.get("kind", "unsupported")
    if kind not in ("flask", "django", "fastapi"):
        return {**base, "verdict": "skipped", "skip_reason": "app_unreachable",
                "detail": f"该 Finding 无可用入口驱动（{kind}）：{entry.get('reason')}"}

    http_mode: bool = bool(getattr(config, "dynamic_http", True))
    if kind == "fastapi":
        # FastAPI：TestClient 同进程驱动（httpx 走 ASGI），参数由 LLM/AST 给出
        script = driver.build_fastapi_probe(finding, config.paths.workspace_root, entry,
                                            params=_llm_request_params(finding, config))
        pip = ["fastapi", "httpx", "email-validator", "python-multipart"]
        # 目标若是 PyPI 已打包应用，从 dist-info/METADATA 补其自身依赖
        for dep in _app_requires(Path(entry.get("root") or config.target)):
            if dep.lower() not in {p.lower() for p in pip}:
                pip.append(dep)
        timeout = 300
    elif kind == "flask":
        script = driver.build_probe_script(finding, config.paths.workspace_root,
                                           config.target)
        pip: list[str] = ["flask"]
        timeout: int = 120
    elif http_mode:
        # 真 HTTP：同进程 WSGI 起服 + 会话 + 免 CSRF + 按视图路由打点（更真实）
        # 参数：先让 LLM 依据代码上下文给出"流到 sink 的参数与值"，失败回退 AST 通配
        llm_params: dict[str, str] = _llm_request_params(finding, config)
        script = driver.build_django_http_probe(finding, config.paths.workspace_root,
                                                entry, params=llm_params)
        pip = []                 # 目标依赖应在沙箱镜像中（如 opensoft/pygoat-django）
        timeout = 240
    else:
        script = driver.build_django_probe(finding, config.paths.workspace_root, entry)
        pip = ["django"]
        timeout = 120
    script_path = scratch / f"probe_{hashlib.sha256(finding.id.encode()).hexdigest()[:12]}.py"
    try:
        script_path.write_text(script, encoding="utf-8")
    except OSError as exc:
        return {**base, "verdict": "skipped", "skip_reason": "probe_write_failed",
                "detail": str(exc)}

    res = executor.run_script(config.paths.workspace_root, script_path,
                              pip_install=pip, timeout=timeout,
                              protect=[config.target])
    stdout = (res.stdout or "") + (res.stderr or "")
    result = EntryDriver.parse_result(stdout)

    if result is None:
        return {**base, "verdict": "skipped", "skip_reason": "app_unreachable",
                "detail": f"容器未输出探针报告：{stdout[-400:]}"}
    if "error" in result:
        return {**base, "verdict": "skipped", "skip_reason": "app_unreachable",
                "detail": f"{result.get('error')}: {result.get('detail', '')[-400:]}"}

    a = int(result.get("track_a", 0))
    b = int(result.get("track_b", 0))
    p = int(result.get("policy", 0))
    # 类别相关性闸门：策略命中只对"同类 Finding"计入 confirmed，
    # 避免某个探针里顺带触发其它类别的策略命中而误确认。
    policy_used: int = p if _policy_relevant(finding, result) else 0
    if p > 0 and policy_used == 0:
        logger.info("策略命中 %d 条与 Finding 类别不符，已忽略：%s", p, finding.rule_id)
    verdict = classify_dual_track(a, b, policy_used)
    # 缺鉴权差分：仅对"鉴权/访问控制"类 Finding 生效（避免把公开页面误判）
    bypass_samples = [
        e for e in (result.get("auth_bypass") or [])
        if e.get("equal") and e.get("anon_status") == 200
        and e.get("auth_status") == 200 and int(e.get("anon_len", 0)) > 0
    ]
    auth_hit: bool = bool(bypass_samples) and _auth_relevant(finding)
    if auth_hit and verdict != "confirmed":
        verdict = "confirmed"
    rec = {**base, "verdict": verdict, "track_a": a, "track_b": b,
           "policy": p, "policy_used": policy_used,
           "auth_bypass_hit": auth_hit,
           "routes_tried": result.get("routes_tried", 0)}
    if policy_used > 0:
        rec["policy_samples"] = result.get("policy_samples") or []
    if auth_hit:
        rec["auth_bypass_samples"] = bypass_samples[:3]
    if verdict == "retry_poc":
        gen = poc.retry_loop(finding, is_b_lost=lambda: False)
        rec["poc"] = {"rounds": gen.get("round"), "source_inject": gen.get("source_inject", False)}
    return rec


# ---------------------------------------------------------------------------
# 候选筛选 / KB 闭环
# ---------------------------------------------------------------------------

def select_candidates(findings: list[Finding]) -> list[Finding]:
    """筛出值得动态验证的候选。"""
    out: list[Finding] = []
    for f in findings:
        if f.tool == ToolName.PIP_AUDIT:
            continue
        if f.status in (VulnerabilityStatus.FALSE_POSITIVE,
                        VulnerabilityStatus.FIX_SUGGESTED,
                        VulnerabilityStatus.DYNAMIC_CONFIRMED):
            continue
        if not f.file_path or not f.location:
            continue
        out.append(f)
    return out


def _is_db_like(finding: Finding) -> bool:
    """是否数据库类漏洞。"""
    blob: str = f"{finding.rule_id} {finding.message}".lower()
    return any(h in blob for h in _DB_HINTS)


def _store_confirmed_to_kb(config: Config, findings: list[Finding],
                           confirmed_ids: list[str]) -> None:
    """把 confirmed 结果写入 KB 特征库。"""
    if not confirmed_ids:
        return
    try:
        from modules.llm_analysis.knowledge_base import VulnerabilityKB
        kb = VulnerabilityKB(config.qdrant)
        kb.ensure_collection()
        for f in findings:
            if f.id in confirmed_ids:
                kb.store_confirmed(f)
    except Exception as exc:  # noqa: BLE001
        logger.warning("写入 KB 闭环失败（不影响动态结果）：%s", exc)


# ---------------------------------------------------------------------------
# IO 辅助
# ---------------------------------------------------------------------------

def _run_dast_scan(manifest: dict[str, Any], config: Config,
                   executor: DockerExecutor, scratch: Path) -> list[Finding]:
    """路线级 DAST 缺鉴权扫描：枚举路由做 匿名 vs 已认证 差分，产出新 Finding。

    :param manifest: file_manifest.json。
    :param config: 全局配置。
    :param executor: Docker 执行器。
    :param scratch: 探针脚本目录。
    :return: 新增 Finding 列表。
    """
    from modules.dynamic_verification.entry_driver import (EntryDriver,
                                                           detect_project_entry)
    target = Path(manifest.get("target") or ".").resolve()
    entry = detect_project_entry(target)
    driver = EntryDriver()
    if entry is None:
        # 非 Django：尝试 FastAPI（DAST 目前只做反射 XSS）
        from modules.dynamic_verification.entry_driver import detect_project_entry_fastapi
        fe = detect_project_entry_fastapi(target)
        if fe is None:
            logger.info("DAST：未定位到 Django/FastAPI 工程入口，跳过。")
            return []
        script = driver.build_fastapi_dast(fe, config.paths.workspace_root)
        sp = scratch / "dast_fastapi.py"
        sp.write_text(script, encoding="utf-8")
        pip_list = ["fastapi", "httpx"]
        for dep in _app_requires(target):
            if dep.lower() not in {p.lower() for p in pip_list}:
                pip_list.append(dep)
        res = executor.run_script(config.paths.workspace_root, sp,
                                  pip_install=pip_list, timeout=300,
                                  protect=[config.target])
        data = driver.parse_dast_full((res.stdout or "") + (res.stderr or ""))
        out_f: list[Finding] = []
        for h in data["xss"]:
            route = str(h.get("route") or "")
            if route:
                out_f.append(Finding(
                    id=f"DAST@dast/reflected-xss@{route}", tool=ToolName.DYNAMIC,
                    rule_id="dast/reflected-xss", rule_name="Reflected XSS (DAST)",
                    severity=Severity.HIGH,
                    message=(f"FastAPI 路由 {route}（{h.get('method')}）将带 HTML 元字符的"
                             f"输入原样回显（marker={h.get('marker')}），存在反射型 XSS（CWE-79）。"),
                    cwe_ids=["CWE-79"], file_path=str(target) + route,
                    location=Location(file_path=str(target) + route, start_line=1, end_line=1),
                    confidence=ConfidenceLevel.HIGH,
                    status=VulnerabilityStatus.DYNAMIC_CONFIRMED,
                    metadata={"test_status": "confirmed",
                              "dynamic": {"verdict": "confirmed",
                                          "evidence": "dast/reflected-xss",
                                          "route": route, "method": h.get("method")}}))
        return out_f
    script = driver.build_dast_probe(entry, config.paths.workspace_root)
    sp = scratch / "dast_scan.py"
    sp.write_text(script, encoding="utf-8")
    res = executor.run_script(config.paths.workspace_root, sp, pip_install=[],
                              timeout=420, protect=[config.target])
    data = driver.parse_dast_full((res.stdout or "") + (res.stderr or ""))
    out: list[Finding] = []

    def _mk(rule: str, name: str, cwe: str, sev: Severity, route: str,
            message: str, extra: dict[str, Any]) -> Finding:
        """构造一条 DAST 新 Finding。"""
        sink = f"{rule}@{route}"
        return Finding(
            id=f"DAST@{sink}",
            tool=ToolName.DYNAMIC,
            rule_id=rule,
            rule_name=name,
            severity=sev,
            message=message,
            cwe_ids=[cwe],
            file_path=str(target) + route,
            location=Location(file_path=str(target) + route, start_line=1, end_line=1),
            confidence=ConfidenceLevel.HIGH,
            status=VulnerabilityStatus.DYNAMIC_CONFIRMED,
            metadata={"test_status": "confirmed",
                      "dynamic": {"verdict": "confirmed", "evidence": rule,
                                  "route": route, **extra}},
        )

    for h in data["missing_auth"]:
        route = str(h.get("route") or "")
        if route:
            out.append(_mk("dast/missing-auth", "Missing Authentication (DAST)",
                           "CWE-306", Severity.HIGH, route,
                           (f"路由 {route} 匿名即可访问，且响应体与已认证完全一致"
                            f"（anon={h.get('anon_status')} auth={h.get('auth_status')}，"
                            f"len={h.get('len')}），疑似缺失鉴权（CWE-306）。"),
                           {"anon_status": h.get("anon_status"),
                            "auth_status": h.get("auth_status"), "len": h.get("len")}))
    for h in data["xss"]:
        route = str(h.get("route") or "")
        if route:
            out.append(_mk("dast/reflected-xss", "Reflected XSS (DAST)",
                           "CWE-79", Severity.HIGH, route,
                           (f"路由 {route}（{h.get('method')}）将带 HTML 元字符的输入"
                            f"原样回显（marker={h.get('marker')}），存在反射型 XSS（CWE-79）。"),
                           {"method": h.get("method"), "marker": h.get("marker"),
                            "status": h.get("status")}))
    for h in data["csrf"]:
        route = str(h.get("route") or "")
        if route:
            out.append(_mk("dast/missing-csrf", "Missing CSRF Protection (DAST)",
                           "CWE-352", Severity.MEDIUM, route,
                           (f"路由 {route} 接受『无 CSRF token』的 POST（status="
                            f"{h.get('status_no_token')}），疑似缺失 CSRF 防护（CWE-352）。"),
                           {"status_no_token": h.get("status_no_token")}))
    return out


def _load_findings(path: Path) -> list[Finding]:
    """宽容读取发现文件。"""
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.get("findings") if isinstance(raw, dict) else raw
    return [Finding.from_dict(x) for x in (items or []) if isinstance(x, dict)]


def _load_manifest(path: Path) -> dict[str, Any]:
    """读取清单。"""
    return json.loads(path.read_text(encoding="utf-8"))
