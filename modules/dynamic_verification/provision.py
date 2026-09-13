"""沙箱自动供给（provision）。

让动态验证对"任意 Python Web 工程"可用：自动发现依赖清单 → 在容器里安装
（部分失败也容忍，见 scripts/_provision_install.py）→ 提交为可复用镜像，缓存命中则跳过。

通用做法（不针对任何具体工程/包）：
- 清单发现：requirements*.txt（浅层优先）；无清单则退回基础镜像并在探测期 pip 装框架；
- 镜像标签：`opensoft/proj-<hash>`，hash 由目标路径 + 依赖清单内容决定 → 内容不变即复用；
- 失败降级：构建失败返回 None，调用方沿用原镜像/降级路径。
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

from config import Config
from modules.dynamic_verification.sandbox import OUTSIDE_TARGET_MOUNT

logger = logging.getLogger("opensoft_detect.dynamic_verification.provision")

#: 基础镜像（与 DockerConfig.image 默认一致）
_BASE_IMAGE: str = "python:3.11-slim"


def detect_requirements(target: Path) -> Optional[Path]:
    """在目标工程里找依赖清单（requirements*.txt，浅层优先）。

    :param target: 目标工程目录。
    :return: 清单路径或 None。
    """
    target = target.resolve()
    if not target.is_dir():
        return None
    exact = target / "requirements.txt"
    if exact.is_file():
        return exact
    cands = [p for p in target.rglob("requirements*.txt")
             if "venv" not in p.as_posix() and "node_modules" not in p.as_posix()]
    if not cands:
        return None
    cands.sort(key=lambda p: len(p.relative_to(target).parts))
    return cands[0]


def detect_install_targets(target: Path) -> list[Path]:
    """发现可安装目标：requirements*.txt 优先；否则 pyproject/setup.py 所在目录。

    :param target: 目标工程目录。
    :return: 安装目标路径列表（requirements 文件或项目目录）。
    """
    target = target.resolve()
    if not target.is_dir():
        return []
    req = target / "requirements.txt"
    if req.is_file():
        return [req]
    reqs = [p for p in target.rglob("requirements*.txt")
            if "venv" not in p.as_posix() and "node_modules" not in p.as_posix()]
    if reqs:
        reqs.sort(key=lambda p: len(p.relative_to(target).parts))
        return [reqs[0]]
    # pyproject / setup.py 项目
    cands: list[Path] = []
    for name in ("pyproject.toml", "setup.py"):
        hits = [p for p in target.rglob(name)
                if "venv" not in p.as_posix() and "node_modules" not in p.as_posix()]
        cands.extend(hits)
    if not cands:
        return []
    cands.sort(key=lambda p: len(p.relative_to(target).parts))
    return [cands[0].parent]


def _dep_count(targets: list[Path]) -> int:
    """粗略统计安装目标的依赖条目数（用于"过重即止损"判断）。

    :param targets: requirements 文件或项目目录。
    :return: 依赖条目数（估算）。
    """
    count = 0
    for t in targets:
        try:
            if t.is_file():                       # requirements*
                count += sum(1 for ln in t.read_text(encoding="utf-8", errors="ignore").splitlines()
                             if ln.strip() and not ln.strip().startswith(("#", "-")))
            elif t.is_dir():                      # pyproject 项目
                py = t / "pyproject.toml"
                if py.is_file():
                    try:
                        import tomllib
                        data = tomllib.loads(py.read_text(encoding="utf-8", errors="ignore"))
                        count += len((data.get("project") or {}).get("dependencies") or [])
                        for grp in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
                            count += len(grp or [])
                        poetry = ((data.get("tool") or {}).get("poetry") or {})
                        count += max(0, len(poetry.get("dependencies") or {}) - 1)
                    except Exception:  # noqa: BLE001
                        count += 1
                else:
                    count += 1
        except OSError:
            continue
    return count


def image_tag_for(target: Path, targets: Optional[list[Path]] = None) -> str:
    """由目标路径 + 安装目标内容生成稳定镜像标签（内容变则标签变）。

    :param target: 目标工程目录。
    :param targets: 安装目标（requirements 文件或项目目录）。
    :return: 镜像标签（含 :latest）。
    """
    h = hashlib.sha256(str(target.resolve()).encode())
    for t in (targets or []):
        if t.is_file():
            h.update(t.read_bytes())
        elif t.is_dir():
            for name in ("pyproject.toml", "setup.py", "requirements.txt"):
                f = t / name
                if f.is_file():
                    h.update(f.read_bytes())
            h.update(str(t).encode())
    return f"opensoft/proj-{h.hexdigest()[:10]}:latest"


def ensure_project_image(target: Path, config: Config) -> Optional[str]:
    """确保"已装依赖"的项目镜像存在；缺失则构建（安装依赖）并提交。

    :param target: 目标工程目录。
    :param config: 全局配置（用其 docker 配置）。
    :return: 可用镜像标签；构建失败返回 None。
    """
    try:
        import docker
        import docker.types as dt
    except Exception as exc:  # noqa: BLE001
        logger.warning("docker SDK 不可用：%s", exc)
        return None

    targets = detect_install_targets(target)
    tag = image_tag_for(target, targets)
    try:
        client = docker.from_env(timeout=600)
        client.ping()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Docker 不可达，无法自动供给：%s", exc)
        return None

    # 命中缓存直接复用
    try:
        client.images.get(tag)
        logger.info("复用已供给镜像：%s", tag)
        return tag
    except Exception:  # noqa: BLE001
        pass

    if not targets:
        logger.info("目标无 requirements/pyproject/setup.py，跳过自动供给（沿用基础镜像）。")
        return None

    # 止损闸 1：依赖条目过多（如 chainlit 这类重工程）直接放弃，别浪费时间
    dep_count = _dep_count(targets)
    max_deps = int(getattr(config, "dynamic_provision_max_deps", 80))
    if dep_count > max_deps:
        logger.warning("目标依赖约 %d 条 > 上限 %d，判定为重型工程，跳过自动供给"
                       "（避免长时间构建；如需可用 --provision-force 或调高配置）。",
                       dep_count, max_deps)
        return None

    repo = Path(__file__).resolve().parents[2]
    # 目标在仓库内则整体挂载仓库；否则额外挂载目标到 /proj
    inside = True
    try:
        target.resolve().relative_to(repo)
    except ValueError:
        inside = False
    mounts = [dt.Mount("/workspace", str(repo), type="bind")]
    if not inside:
        mounts.append(dt.Mount(OUTSIDE_TARGET_MOUNT, str(target.resolve()), type="bind"))

    def _container_path(p: Path) -> str:
        if inside:
            return "/workspace/" + p.resolve().relative_to(repo).as_posix()
        return (OUTSIDE_TARGET_MOUNT + "/"
                        + p.resolve().relative_to(target.resolve()).as_posix())

    # 逐项加引号：依赖清单/工程目录名可能含空格（通用性，Windows 常见）
    args = " ".join('"' + _container_path(t) + '"' for t in targets)
    workdir = "/workspace" if inside else OUTSIDE_TARGET_MOUNT
    logger.info("构建项目镜像 %s（安装 %s，允许部分失败）...", tag,
                ", ".join(t.name for t in targets))
    cmd = f"python /workspace/scripts/_provision_install.py {args} && echo PROVISION_DONE"
    try:
        c = client.containers.run(_BASE_IMAGE, ["/bin/sh", "-c", cmd],
                                  mounts=mounts, detach=True, working_dir=workdir,
                                  mem_limit="2g")
        out = b""
        try:
            for chunk in c.logs(stream=True, follow=True):
                out += chunk
        except Exception:  # noqa: BLE001
            pass
        # 止损闸 2：构建超时立即中止（不强等，避免浪费时间）
        timeout_s = int(getattr(config, "dynamic_provision_timeout", 420))
        try:
            rc = c.wait(timeout=timeout_s).get("StatusCode", -1)
        except Exception:  # noqa: BLE001 - 超时/异常
            logger.warning("自动供给超过 %ds 仍未完成，中止并退回基础镜像（避免浪费时间）。",
                           timeout_s)
            try:
                c.kill()
                c.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
            return None
        text = out.decode("utf-8", "replace")
        if rc != 0 or "PROVISION_DONE" not in text:
            logger.warning("项目镜像构建未完成（rc=%s），退回基础镜像。尾部：%s",
                           rc, text[-300:])
            c.remove(force=True)
            return None
        c.commit(repository=tag.split(":")[0], tag="latest")
        c.remove(force=True)
        logger.info("项目镜像就绪：%s", tag)
        return tag
    except Exception as exc:  # noqa: BLE001
        logger.warning("自动供给异常（忽略，退回基础镜像）：%s", exc)
        # 可靠性：异常路径也要回收容器（若已创建）；未创建时 NameError 被内层吞掉
        try:
            c.remove(force=True)          # type: ignore[possibly-undefined]
        except Exception:  # noqa: BLE001
            pass
        return None
