"""源码文件元信息工具（scanner）。

模块0 中负责两类"轻量"工作，供 filter/manifest 复用：
- 语言识别（文件后缀 -> 语言名）
- 文件元信息采集（行数、内容 SHA-256、相对路径）

真正带剪枝的目录遍历与分类逻辑在 :mod:`modules.preprocess.filter` 的
:class:`FileFilter` 中实现；本模块不重复造轮子，只提供无状态纯函数。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

#: 文件后缀 -> 语言名映射（当前聚焦 Python，可按需扩展）
EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    # ... 后续按需扩展
}


def detect_language(path: Path) -> Optional[str]:
    """根据文件后缀返回语言名；未知后缀返回 None。

    :param path: 待判断文件路径。
    :return: 语言名（如 ``"python"``）；无法识别返回 None。
    """
    ext: str = path.suffix.lower()
    if ext not in EXTENSION_LANGUAGE_MAP:
        # 处理复合后缀（如 ``.py.tmpl`` 不是常规场景），这里直接给 None 即可
        return None
    return EXTENSION_LANGUAGE_MAP[ext]


def count_lines(path: Path) -> int:
    """统计文本文件行数。

    逐块读取避免一次性把大文件读进内存；解码失败（二进制被误判）返回 0。

    :param path: 目标文件。
    :return: 行数；读取异常返回 0。
    """
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def sha256_hex(path: Path) -> str:
    """计算文件内容 SHA-256 指纹（十六进制小写），供去重/缓存。

    :param path: 目标文件。
    :return: 64 位哈希字符串；读取异常返回空串。
    """
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 256), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def rel_posix(path: Path, base: Path) -> str:
    """返回 path 相对 base 的路径，分隔符统一为正斜杠（跨平台稳定）。

    若 path 不在 base 之下（不应发生），退化为返回 path 文件名。

    :param path: 文件/目录绝对路径。
    :param base: 参照根目录。
    :return: POSIX 风格的相对路径字符串。
    """
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name


def file_entry(path: Path, base: Path) -> dict:
    """生成单个待扫描文件的清单条目（含语言、大小、行数、指纹）。

    :param path: 待扫描文件绝对路径。
    :param base: manifest 的根目录（target）。
    :return: 清单条目字典。
    """
    lang: Optional[str] = detect_language(path)
    return {
        "path": str(path.resolve()),
        "rel_path": rel_posix(path, base),
        "language": lang or "unknown",
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "line_count": count_lines(path),
        "sha256": sha256_hex(path),
    }
