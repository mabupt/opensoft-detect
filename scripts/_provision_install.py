"""容器内"安装目标依赖"助手（自动供给通用版）。

支持三类目标（不针对任何具体工程）：
1. ``requirements*.txt``：整体装，失败则逐行容错（见同名逻辑）；
2. 含 ``pyproject.toml`` / ``setup.py`` 的**目录**：先 ``pip install -e <dir>``，
   失败则解析声明依赖逐条容错安装；
3. 直接给 ``pyproject.toml`` 文件：按第 2 类处理其所在目录。

始终以 0 退出（部分成功也可），由上层判断镜像可用性。

用法：``python _provision_install.py <path> [<path> ...]``
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _pip(args: list[str]) -> int:
    """执行 pip（静默、不交互）。"""
    return subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--no-input", *args],
                          check=False).returncode


def _tolerant_lines(specs: list[str], label: str) -> None:
    """逐条安装；失败的**再用 --no-deps 重试一次**（常见于依赖约束冲突），仍失败才跳过。"""
    ok = fail = 0
    for spec in specs:
        if not spec or spec.startswith(("-", "git+", "http://", "https://")):
            continue
        if _pip([spec]) == 0:
            ok += 1
            continue
        # 关键改进：带依赖解析失败时，退化为 --no-deps 单装（保证模块本体存在，供 import）
        if _pip(["--no-deps", spec]) == 0:
            ok += 1
            print(f"[provision]   以 --no-deps 安装成功：{spec}")
            continue
        fail += 1
        print(f"[provision]   跳过失败依赖：{spec}")
    print(f"[provision] {label} 逐条结果：成功 {ok}，跳过 {fail}")


def install_requirements(req: Path) -> None:
    """安装 requirements 文件（整体优先，失败逐行）。"""
    if _pip(["-r", str(req)]) == 0:
        print(f"[provision] requirements 安装成功：{req}")
        return
    print(f"[provision] requirements 整体失败，逐行容错：{req}")
    lines = [ln.split("#", 1)[0].strip()
             for ln in req.read_text(encoding="utf-8", errors="ignore").splitlines()]
    _tolerant_lines([ln for ln in lines if ln], req.name)


def _deps_from_pyproject(py: Path) -> list[str]:
    """从 pyproject 提取声明依赖（PEP 621 project.dependencies / poetry 依赖）。"""
    import tomllib  # py3.11
    try:
        data = tomllib.loads(py.read_text(encoding="utf-8", errors="ignore"))
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    proj = data.get("project") or {}
    for d in proj.get("dependencies") or []:
        out.append(str(d))
    for grp in (proj.get("optional-dependencies") or {}).values():
        out.extend(str(d) for d in (grp or []))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            out.append(f"{name}{spec}" if spec and spec[0] in "<>=~!^" else name)
        elif isinstance(spec, dict):
            ver = str(spec.get("version") or "")
            out.append(f"{name}{ver}" if ver else name)
    return out


def install_project_dir(directory: Path, py: Path | None = None) -> None:
    """安装项目目录：editable 优先，失败则解析声明依赖逐条装。"""
    if _pip(["-e", str(directory)]) == 0:
        print(f"[provision] 项目 editable 安装成功：{directory}")
        return
    print(f"[provision] editable 失败，改解析声明依赖：{directory}")
    deps = _deps_from_pyproject(py) if py and py.is_file() else []
    if not deps:
        print("[provision]   未解析到依赖（或为 setup.py 项目），尝试 setuptools 安装")
        _pip([str(directory)])
        return
    _tolerant_lines(deps, directory.name)


def main() -> int:
    """入口：按路径类型分派安装。"""
    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.is_file() and p.name.startswith("requirements"):
            install_requirements(p)
        elif p.is_file() and p.name == "pyproject.toml":
            install_project_dir(p.parent, p)
        elif p.is_dir():
            py = p / "pyproject.toml"
            if py.is_file() or (p / "setup.py").is_file():
                install_project_dir(p, py if py.is_file() else None)
            else:
                print(f"[provision] 目录无可安装声明，跳过：{p}")
        else:
            print(f"[provision] 未知目标，跳过：{p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
