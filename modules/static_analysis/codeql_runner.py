"""CodeQL 集成（codeql_runner）。

以子进程方式调用本机 CodeQL CLI（Windows bundle），流程：
1. 依据 manifest 的 scan_scope 生成 ``codeql-config.yml``（paths / paths-ignore），
   把扫描范围限定在模块0 过滤后的目录上；
2. ``codeql database create --language=python`` 建立数据库（Python 为解释型，
   建库即 import 抽取，无需 build 命令）；
3. ``codeql database analyze --format=sarif-latest`` 运行查询套件并输出 SARIF；
4. 解析 SARIF（parsers.parse_codeql_sarif）为 Finding，随后删除中间数据库。

任何一步失败都记录明确日志并返回空列表（不影响其它引擎）。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import ToolConfig
from models import Finding, ToolName
from modules.preprocess.manifest import (load_manifest, scan_scope_dirname_groups)
from modules.static_analysis.base import AnalyzerBase
from modules.static_analysis.parsers import parse_codeql_sarif, run_subprocess

logger = logging.getLogger("opensoft_detect.static_analysis.codeql")


class CodeQLRunner(AnalyzerBase):
    """基于 CodeQL 的静态分析器。"""

    tool: ToolName = ToolName.CODEQL

    def is_available(self) -> bool:
        """检测 CodeQL CLI 可执行文件与查询套件是否存在。

        支持 ``OPENSOFT_SKIP_CODEQL=1`` 显式跳过（轻量/快速冒烟时用，避免建库+跑套件的分钟级开销）。

        :return: True 表示可运行。
        """
        import os as _os
        if _os.environ.get("OPENSOFT_SKIP_CODEQL", "").strip() in ("1", "true", "yes"):
            logger.info("OPENSOFT_SKIP_CODEQL=1，按配置跳过 CodeQL 引擎。")
            return False
        exe = self.tool_cfg.codeql_bin
        if not Path(exe).is_file():
            logger.warning("CodeQL 可执行文件不存在：%s，该引擎将被跳过。", exe)
            return False
        suite = self.tool_cfg.codeql_query_suite
        if not Path(suite).is_file():
            logger.warning("CodeQL 查询套件不存在：%s，该引擎将被跳过。", suite)
            return False
        return True

    def run(self, manifest_path: Path) -> list[Finding]:
        """执行 建库 -> 分析 -> 解析 全流程。

        :param manifest_path: file_manifest.json 路径。
        :return: Finding 列表；任一步失败时返回空列表。
        """
        try:
            manifest = load_manifest(manifest_path)
        except OSError as exc:
            logger.error("读取清单失败，CodeQL 跳过：%s", exc)
            return []
        scan_count: int = len(manifest.get("scan_scope") or [])
        if scan_count == 0:
            logger.warning("scan_scope 为空，CodeQL 无需分析。")
            return []

        target_root = Path(manifest["target"])
        if not target_root.is_dir():
            logger.warning("manifest.target 不是有效目录（%s），CodeQL 跳过。", target_root)
            return []

        db_dir = self._prepare_db_dir(manifest)
        reused: bool = (db_dir / "codeql-database.yml").is_file()
        findings: list[Finding] = []
        try:
            if reused:
                logger.info("复用 CodeQL 缓存数据库：%s", db_dir)
            else:
                # 生成限定扫描范围的 codeql-config.yml（部分真实工程会使 autobuild
                # 失败，见 _create_database 的自动回退）
                config_path = self._write_scope_config(manifest)
                self._create_database(target_root, db_dir, config_path)
            sarif_path = self._run_queries(db_dir)
            if sarif_path is not None:
                raw: dict[str, Any] = json.loads(sarif_path.read_text(encoding="utf-8"))
                findings = parse_codeql_sarif(raw, target_root=target_root)
                logger.info("CodeQL 解析出 %d 条发现。", len(findings))
        except Exception as exc:  # noqa: BLE001 - 引擎失败降级
            self.last_error = str(exc)
            logger.error("CodeQL 分析失败（已降级跳过）：%s", exc, exc_info=True)
        finally:
            if self.tool_cfg.codeql_cleanup_db:
                self._cleanup_db(db_dir)
        return self.post_process(findings)

    # ---- 子步骤 ----
    def _prepare_db_dir(self, manifest: dict[str, Any]) -> Path:
        """按 manifest 内容哈希生成稳定的数据库缓存目录（扫描集变则换 key）。

        :param manifest: file_manifest.json。
        :return: 数据库目录（已创建）。
        """
        import hashlib as _h
        key_src = str(manifest.get("target", "")) + "|" + "|".join(
            sorted(str(e.get("path", "")) for e in (manifest.get("scan_scope") or [])))
        key = _h.sha256(key_src.encode()).hexdigest()[:12]
        db_dir = self.tool_cfg.codeql_database_dir / f"cache_{key}"
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir

    def _write_scope_config(self, manifest: dict[str, Any]) -> Path:
        """依据 scan_scope 与 excluded 生成 codeql-config.yml。

        - ``paths``：scan_scope 覆盖的顶层目录（根级文件存在时含 "."）；
        - ``paths-ignore``：被模块0 排除、且位于上述目录之下的子树/文件，
          避免 CodeQL 把排除文件扫进来。

        :param manifest: 清单字典。
        :return: 配置文件路径。
        """
        paths: list[str] = scan_scope_dirname_groups(manifest)
        ignore: list[str] = []
        for rec in manifest.get("excluded") or []:
            rel: str = rec.get("rel_path") or ""
            if not rel or rel == ".":
                continue
            ignore.append(f"{rel}/**" if rec.get("kind") == "dir" else rel)

        lines = ["# 由 OpenSoft Detect 自动生成：限定 CodeQL 扫描范围\n", "paths:\n"]
        lines += [f"  - {p}\n" for p in paths]
        lines.append("paths-ignore:\n")
        # 统一加引号以防 YAML 特殊字符
        lines += [f'  - "{i}"\n' for i in ignore]

        cfg = self.tool_cfg.codeql_config_path
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("".join(lines), encoding="utf-8")
        logger.info("已生成 CodeQL 范围配置：%s（paths=%s, paths-ignore=%d）",
                    cfg, paths, len(ignore))
        return cfg

    def _create_database(self, target_root: Path, db_dir: Path, config_path: Path) -> None:
        """执行 ``codeql database create``，带"无 codescanning-config 回退"。

        实测：部分真实工程在带 ``--codescanning-config``（自动生成的 paths/
        paths-ignore）时 autobuild 会异常退出；去掉该配置即可成功建库。
        因此首次失败先清掉半成品库、改用全量建库重试一次。

        :param target_root: 目标工程根目录。
        :param db_dir: 数据库输出目录。
        :param config_path: codeql-config.yml 路径。
        :raises RuntimeError: 两次尝试均失败。
        """
        try:
            self._run_create_cmd(target_root, db_dir, [config_path])
        except RuntimeError:
            logger.warning("带 codescanning-config 建库失败，已回退为全量建库（重试一次）：%s",
                           config_path)
            import shutil as _shutil
            _shutil.rmtree(db_dir, ignore_errors=True)   # 清掉半成品
            self._run_create_cmd(target_root, db_dir, [])
        logger.info("CodeQL 数据库已创建：%s", db_dir)

    def _run_create_cmd(self, target_root: Path, db_dir: Path,
                        config_args: list[Path]) -> None:
        """构造并执行一次 database create。

        :param target_root: 目标工程根。
        :param db_dir: 数据库目录。
        :param config_args: 为 [config_path] 或 []（无 config）。
        :raises RuntimeError: 该次建库失败。
        """
        cmd: list[str] = [
            str(self.tool_cfg.codeql_bin), "database", "create",
            str(db_dir), "--language=python",
            "--source-root", str(target_root),
            "--overwrite", "--quiet",
        ]
        if config_args:
            cmd += ["--codescanning-config", str(config_args[0])]
        code, out, err = run_subprocess(cmd, timeout=self.tool_cfg.codeql_timeout,
                                        env=self._python_env())
        if code != 0:
            raise RuntimeError(f"codeql database create 失败 (rc={code}): {err[:1200] or out[:800]}")

    def _run_queries(self, db_dir: Path) -> Optional[Path]:
        """执行 ``codeql database analyze``，返回 SARIF 文件路径。

        :param db_dir: 数据库目录。
        :return: SARIF 文件路径；分析失败返回 None。
        :raises RuntimeError: analyze 失败。
        """
        sarif_out = db_dir / "results.sarif"
        suite = str(self.tool_cfg.codeql_query_suite)
        cmd = [
            str(self.tool_cfg.codeql_bin), "database", "analyze",
            str(db_dir),
            suite,
            "--format=sarif-latest",
            "--output", str(sarif_out),
            "--quiet",
        ]
        code, out, err = run_subprocess(cmd, timeout=self.tool_cfg.codeql_timeout,
                                        env=self._python_env())
        if code != 0:
            raise RuntimeError(f"codeql database analyze 失败 (rc={code}): {err[:1200] or out[:800]}")
        logger.info("CodeQL SARIF 结果：%s", sarif_out)
        return sarif_out

    @staticmethod
    def _python_env() -> dict[str, str]:
        """构造需要传给 CodeQL 子进程的额外环境变量。

        关键：Windows 上若未安装 ``py`` launcher，CodeQL 的 Python 建库会直接失败。
        通过设置 extractor 选项 ``python_executable_name``（环境变量形式
        ``CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME``）让 CodeQL
        使用我们指定的 Python 解释器，从而绕过对 ``py`` launcher 的依赖。

        :return: 待合并进子进程环境变量的字典。
        """
        python_exe: Optional[str] = sys.executable or shutil.which("python")
        if not python_exe:
            return {}
        return {"CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME": python_exe}

    @staticmethod
    def _cleanup_db(db_dir: Path) -> None:
        """删除本次运行产生的中间数据库目录。

        :param db_dir: 数据库目录。
        """
        import shutil as _shutil
        try:
            _shutil.rmtree(db_dir, ignore_errors=True)
        except OSError:
            pass
