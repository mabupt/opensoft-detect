"""Docker 沙箱执行与部署降级决策（sandbox）。

模块4 的动态验证必须在隔离环境运行（被测代码可能真实触发命令执行/文件删除），
统一封装为两层：

1. :class:`DockerExecutor`：基于 Docker SDK 创建一次性隔离容器，
   挂载被测工程与探针脚本，捕获 stdout/stderr/退出码并回收；
2. 部署降级决策 :func:`decide_deployment`：按规格的优先级判定被测工程能以
   何种方式跑起来，产出 plan 供 runner 选择执行策略。

降级策略（按优先级，逐级退让）：
   自带 docker-compose.yml -> 直接用 compose；
   使用 SQLite（零配置）-> 直接在沙箱里跑；
   数据库连不上 -> 只验证非数据库类漏洞（XSS/路径穿越），跳过 DB 类；
   应用完全跑不起来 -> 退化为纯静态结果，标注 skip_reason="app_unreachable"。
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from config import DockerConfig

logger = logging.getLogger("opensoft_detect.dynamic_verification.sandbox")

#: 副本文件数上限：超过则改用**只读**挂载（复制大工程代价高；只读同样不会污染宿主）
MAX_COPY_FILES: int = 20000

#: 仓库**外**目标在容器内的挂载点。
#: 约定：目标在仓库内 -> ``/workspace/<相对路径>``；在仓库外 -> ``/target``。
#: 该约定由 sandbox（挂载）、entry_driver（探针里的路径）、provision（构建镜像）
#: 三方共享，避免"探针按 A 路径找、挂载在 B 路径"这类只在换项目时才暴露的错位。
OUTSIDE_TARGET_MOUNT: str = "/target"


def container_root_for(target: Path, mount_root: Path) -> str:
    """返回目标工程在容器内的根路径（仓库内 -> /workspace/<rel>，仓库外 -> /target）。

    :param target: 被测工程根（宿主路径）。
    :param mount_root: 挂载为 /workspace 的宿主目录（通常是仓库根）。
    :return: 容器内路径。
    """
    try:
        rel = Path(target).resolve().relative_to(Path(mount_root).resolve())
        return "/workspace/" + rel.as_posix()
    except ValueError:
        return OUTSIDE_TARGET_MOUNT


@dataclass
class SandboxResult:
    """一次沙箱/本地运行的汇总结果。"""

    success: bool
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    runtime_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """转字典（截断超长输出）。"""
        return {
            "success": self.success, "exit_code": self.exit_code,
            "stdout": self.stdout[-4000:], "stderr": self.stderr[-4000:],
            "timed_out": self.timed_out, "runtime_seconds": round(self.runtime_seconds, 2),
        }


# ---------------------------------------------------------------------------
# DockerExecutor
# ---------------------------------------------------------------------------

class DockerExecutor:
    """基于 docker SDK 的一次性隔离执行器。"""

    def __init__(self, docker_cfg: DockerConfig) -> None:
        """构造执行器。

        :param docker_cfg: Docker 参数（镜像/网络/资源上限/超时）。
        """
        self.cfg: DockerConfig = docker_cfg
        self._client: Any = None

    # ---- 可用性 ----
    def available(self) -> bool:
        """Docker daemon 是否可达（并缓存客户端）。

        :return: True 表示可用。
        """
        try:
            if self._client is None:
                import docker
                # 长超时：pip 安装/静默期可能导致日志流长时间无输出（默认 60s 会误判超时）
                self._client = docker.from_env(timeout=600)
            self._client.ping()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Docker 不可用：%s", exc)
            return False

    # ---- 一次性容器运行 ----
    def image_available(self, image: Optional[str] = None) -> bool:
        """镜像是否已在本地（避免无网时触发 pull 卡死）。

        :param image: 镜像名。
        :return: True 表示本地已有。
        """
        img = image or self.cfg.image
        try:
            if not self.available():
                return False
            self._client.images.get(img)
            return True
        except Exception:  # noqa: BLE001
            return False

    def ensure_image(self, image: Optional[str] = None) -> bool:
        """确保镜像存在；缺失时从远端拉取。

        :param image: 镜像名。
        :return: True 表示就绪。
        """
        img = image or self.cfg.image
        if self.image_available(img):
            return True
        try:
            if not self.available():
                return False
            logger.info("拉取沙箱镜像：%s ...", img)
            self._client.images.pull(img)
            logger.info("沙箱镜像就绪：%s", img)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("拉取沙箱镜像失败：%s", exc)
            return False

    # ---- 跑"探针文件"（可选先 pip 装依赖）----
    @staticmethod
    def _count_files(path: Path) -> int:
        """快速统计目录内文件数（用于判断是否值得做副本）。"""
        import os as _os
        n = 0
        try:
            for _root, dirs, files in _os.walk(path):
                dirs[:] = [d for d in dirs
                           if d not in ("__pycache__", ".git", "node_modules", "venv", ".venv")]
                n += len(files)
                if n > MAX_COPY_FILES:
                    return n
        except OSError:
            return 0
        return n

    def _protected_copy(self, path: Path) -> Optional[Path]:
        """为被测工程做沙箱专用副本（隔离写入）。

        为什么必须：动态验证会**真实触发**被测代码里的漏洞，而部分漏洞的利用后果
        就是写文件（例如"把提交的代码写入 xx.py"这类 lab/后台管理接口）。若直接
        挂载宿主工程，跑一次动态就会把被测源码覆盖，污染语料并让后续运行退化。
        这里复制一份、以相同容器内路径覆盖挂载，探针的所有写入都落到副本。

        :param path: 宿主上的被测工程目录（须为绝对路径）。
        :return: 副本目录；失败返回 None（调用方回退为直接挂载）。
        """
        import hashlib
        import shutil
        tag = hashlib.sha256(str(path).encode()).hexdigest()[:12]
        dest = Path(self.cfg.volumes_mount_dir) / f"protect_{tag}"
        try:
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            shutil.copytree(path, dest, ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", ".git", "node_modules", "venv", ".venv"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("保护性副本创建失败（回退直接挂载原目录）：%s", exc)
            return None
        return dest

    def run_script(self, mount_root: Path, script_path: Path,
                   pip_install: Optional[list[str]] = None,
                   image: Optional[str] = None,
                   timeout: Optional[int] = None,
                   protect: Optional[list[Path]] = None) -> SandboxResult:
        """把脚本文件挂载进容器并以 python 执行（允许预装依赖）。

        挂载 mount_root 到 /workspace，脚本以相对路径定位；有 pip_install 时
        临时放开网络用于安装（沙箱其余网络仍禁用）。

        :param mount_root: 需挂载的工作目录（应为仓库根，含 modules/ 与被测工程）。
        :param script_path: 宿主机上探针脚本的绝对路径（须位于 mount_root 下）。
        :param pip_install: 需要预装到沙箱的包列表。
        :param image: 镜像。
        :param timeout: 超时秒数。
        :param protect: 需以"副本"形式挂载的目录（被测工程），避免探针写入污染宿主。
        :return: SandboxResult。
        """
        if not self.available():
            return SandboxResult(success=False, stderr="docker unavailable")
        img = image or self.cfg.image
        if not self.image_available(img):
            return SandboxResult(success=False, stderr=f"镜像未就绪：{img}")
        import time
        rel = script_path.resolve().relative_to(mount_root.resolve()).as_posix()
        in_script = f"/workspace/{rel}"
        parts: list[str] = []
        if pip_install:
            # 依赖安装加短超时/少重试：网络慢时快速失败（探针会以"缺框架"报错），
            # 而不是把整个探针预算（数百秒）耗在等待上。
            parts.append("python -m pip install -q --no-cache-dir --timeout 30 --retries 1 "
                         + " ".join(pip_install))
        # 路径加引号：被测工程目录名可能含空格/中文（Windows/共享盘常见），
        # 不加引号会被 shell 拆词导致探针根本起不来。
        parts.append('python "' + in_script + '"')
        shell_cmd = " && ".join(parts)
        t0 = time.time()
        try:
            import docker.types as dt
            mounts = [dt.Mount("/workspace", str(mount_root.resolve()), type="bind")]
            # 被测工程改用副本覆盖挂载：探针里的漏洞利用写入只落到副本
            for p in (protect or []):
                pr = Path(p).resolve()
                try:
                    rel = pr.relative_to(mount_root.resolve())
                    cont_target = f"/workspace/{rel.as_posix()}"
                except ValueError:
                    # 仓库外目标：挂到约定挂载点，与 entry_driver/provision 一致
                    cont_target = OUTSIDE_TARGET_MOUNT
                # 超大工程：复制代价高，改用只读挂载（写操作会失败，但同样不会污染宿主）
                if self._count_files(pr) > MAX_COPY_FILES:
                    logger.warning("目标文件数超过 %d，改用**只读**挂载（探针内的写操作会失败）：%s",
                                   MAX_COPY_FILES, pr)
                    mounts.append(dt.Mount(cont_target, str(pr), type="bind", read_only=True))
                    continue
                copy_dir = self._protected_copy(pr)
                if copy_dir is None:
                    # 隔离失败就不跑：探针可能真实利用"写文件"类漏洞，宁可不做动态验证，
                    # 也不能让写入落到宿主工程（曾把被测源码写成空文件的事故）。
                    return SandboxResult(
                        success=False,
                        stderr=f"保护性副本创建失败，放弃本次探针（避免污染宿主工程）：{pr}",
                        runtime_seconds=time.time() - t0)
                mounts.append(dt.Mount(cont_target, str(copy_dir), type="bind"))
            container = self._client.containers.run(
                img,
                ["/bin/sh", "-c", shell_cmd],
                mounts=mounts,
                # 需 pip 装依赖时开放网络；否则禁网
                network_disabled=not bool(pip_install),
                mem_limit=self.cfg.memory_limit,
                nano_cpus=int(self.cfg.cpu_limit * 1e9),
                detach=True,
                working_dir="/workspace",
            )
            removed = False
            timed_out = False
            exit_code = -1
            # 日志用**独立线程流式读取**：既不阻塞主线程（超时照样生效），又能把探针
            # 进度实时打进主日志——否则探针一旦卡住，300s 内一片空白，既看不到卡在哪，
            # 也让人误以为整个流程死了。
            log_chunks: list[str] = []

            def _pump_logs() -> None:
                try:
                    for chunk in container.logs(stream=True, follow=True):
                        text = (chunk or b"").decode("utf-8", "replace")
                        log_chunks.append(text)
                        for line in text.splitlines():
                            if line.strip():
                                logger.info("[sandbox] %s", line[:300])
                except Exception:  # noqa: BLE001 - 容器结束/被 kill 即退出
                    return

            pump = threading.Thread(target=_pump_logs, daemon=True)
            pump.start()
            try:
                exit_code = int(container.wait(
                    timeout=timeout or self.cfg.timeout_seconds).get("StatusCode", -1))
            except Exception as exc:  # noqa: BLE001 - 读超时/容器异常
                timed_out = True
                logger.warning("容器执行超时（上限 %ss），强制终止：%s",
                               timeout or self.cfg.timeout_seconds, exc)
                try:
                    container.kill()
                except Exception:  # noqa: BLE001
                    pass
            pump.join(timeout=5)          # 容器已结束/被杀，读线程应很快退出
            logs = "".join(log_chunks).encode("utf-8")
            # 可靠性：无论成功/超时/异常，容器都要回收（避免泄漏）
            if self.cfg.cleanup_after_run and not removed:
                try:
                    container.kill()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    container.remove(force=True)
                    removed = True
                except Exception:  # noqa: BLE001
                    pass
            text = (logs or b"").decode("utf-8", "replace")
            if timed_out:
                return SandboxResult(
                    success=False, timed_out=True, exit_code=exit_code, stdout=text,
                    stderr=f"容器执行超时（上限 {timeout or self.cfg.timeout_seconds}s），已强制终止",
                    runtime_seconds=time.time() - t0)
            return SandboxResult(success=(exit_code == 0), exit_code=exit_code,
                                 stdout=text, stderr="",
                                 runtime_seconds=time.time() - t0)
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(success=False, stderr=str(exc),
                                 runtime_seconds=time.time() - t0)


# ---------------------------------------------------------------------------
# 部署降级决策
# ---------------------------------------------------------------------------

def decide_deployment(manifest: dict[str, Any],
                      docker_cfg: DockerConfig) -> dict[str, Any]:
    """按规格优先级判定被测工程的可运行方式，返回 plan。

    plan.kind ∈ {"compose", "sqlite", "non_db_only", "unreachable"}。

    :param manifest: file_manifest.json。
    :param docker_cfg: Docker 配置。
    :return: plan 字典（kind/reason/db_based/docker_compose 等）。
    """
    root = Path(manifest.get("target") or ".").resolve()
    db_based: bool = _uses_sqlite(root)
    compose_file = _find_compose(root)
    unreachable_reason = _entry_unreachable_reason(root)

    if compose_file:
        return {"kind": "compose", "reason": f"发现 {compose_file}，直接使用 compose",
                "db_based": db_based, "docker_compose": str(compose_file)}
    if db_based:
        # SQLite 零配置：可在沙箱直接跑（网络禁用不影响本地 sqlite）
        return {"kind": "sqlite", "reason": "检测到 SQLite，零配置直接沙箱运行",
                "db_based": True}
    # 无 DB / 需要外部 DB 的应用：能确定无外部 DB 时按非 DB 处理
    if not unreachable_reason:
        return {"kind": "sqlite", "reason": "无 compose、非 SQLite，按轻量应用尝试",
                "db_based": False}
    return {"kind": "unreachable", "reason": unreachable_reason,
            "db_based": db_based}


def _uses_sqlite(root: Path) -> bool:
    """启发式判断工程是否使用 SQLite（settings 含 sqlite / 存在 .sqlite3 文件）。

    :param root: 工程根。
    :return: True 表示用 SQLite。
    """
    text_needles = ("sqlite3", "dj_database_url", "ENGINE", "django.db.backends.sqlite3")
    for p in _limited_py_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")[:200_000].lower()
        except OSError:
            continue
        if "sqlite" in text and ("engine" in text or "sqlite3" in text):
            return True
    return any(p.suffix in (".sqlite3", ".db", ".sqlite") for p in root.rglob("*")
               if p.is_file() and len(p.name) < 40)


def _find_compose(root: Path) -> Optional[Path]:
    """找 docker-compose(.yml/.yaml)。"""
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = root / name
        if p.is_file():
            return p
    return None


def _entry_unreachable_reason(root: Path) -> str:
    """粗略判断应用入口是否可能跑起来；无法判断时返回空串（视为可尝试）。"""
    has_manage = (root / "manage.py").is_file()
    has_requirements = (root / "requirements.txt").is_file()
    # 有 Django manage.py 但无 requirements 时大概率装不出依赖
    if has_manage and not has_requirements and not (root / "Pipfile.lock").is_file():
        return "应用具备入口但缺少依赖清单（requirements 等），沙箱内难以就绪"
    return ""


def _limited_py_files(root: Path, limit: int = 300) -> list[Path]:
    """返回工程内前 limit 个 .py 文件（浅遍历，避免深入依赖目录）。"""
    out: list[Path] = []
    try:
        for p in root.rglob("*.py"):
            rel = p.relative_to(root).as_posix()
            if any(seg in ("venv", ".venv", "node_modules", "__pycache__", "tests", "migrations")
                   for seg in Path(rel).parts):
                continue
            out.append(p)
            if len(out) >= limit:
                break
    except OSError:
        pass
    return out
