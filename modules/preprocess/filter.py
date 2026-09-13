"""路径过滤器（filter）—— 模块0 核心逻辑。

实现规则驱动的文件分类与目录剪枝遍历：

- **硬排除（hard）**：无论任何参数都排除。典型为缓存/依赖/二进制产物
  （``__pycache__``、``node_modules``、``.venv`` 等目录；``.pyc``、``.so``、
  ``.png`` 等扩展名）。
- **软排除（soft）**：默认排除，但 ``--include-excluded`` 时纳入扫描。
  典型为测试/文档/迁移/模板（``tests/``、``migrations/``、``docs/``、
  ``conftest.py``、``Dockerfile``、``docker-compose*.yml`` 等）。
- **不支持扩展名**：既非源码又非上述排除规则的常规文件（如 README.md），
  也不进入 scan_scope，单列为 ``unsupported_ext`` 排除记录，保证
  "看到过 = 已扫描 + 已排除" 的统计自洽。

遍历时对"整目录排除"做**剪枝**（不进子目录），避免在大体积的依赖目录
（node_modules / venv）内空耗 IO；被剪掉的目录在 excluded 里只记一条。

设计说明：分类函数返回 ``Optional[(category, reason)]``，``category``
取值 hard_dir / soft_dir / hard_ext / hard_file / soft_file；
文件若什么都不命中则由调用方决定是否按源码后缀纳入。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

from modules.preprocess.scanner import rel_posix

logger = logging.getLogger("opensoft_detect.preprocess")


# ---------------------------------------------------------------------------
# 排除规则常量（硬 / 软）
# ---------------------------------------------------------------------------

#: 硬排除目录名（精确匹配，大小写不敏感）
HARD_DIR_NAMES: frozenset[str] = frozenset({
    "__pycache__", ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", "vendor", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".pytype", ".coverage", "htmlcov", ".eggs", "site-packages",
})

#: 硬排除文件名（精确匹配，大小写不敏感）
HARD_FILE_NAMES: frozenset[str] = frozenset({
    ".ds_store", "thumbs.db",
})

#: 硬排除扩展名（大小写不敏感；均为不可解析的二进制/产物）
HARD_EXTENSIONS: frozenset[str] = frozenset({
    ".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".jar", ".war", ".whl",
    ".sqlite3", ".sqlite", ".db", ".bin", ".pdf", ".class", ".node",
})

#: 软排除目录名（--include-excluded 时纳入）
SOFT_DIR_NAMES: frozenset[str] = frozenset({
    "tests", "migrations", "alembic", "docs", "doc", "fixtures",
    "static", "assets", "templates",
})

#: 软排除文件名（精确匹配；Dockerfile 等按名字）
SOFT_FILE_NAMES: frozenset[str] = frozenset({
    "conftest.py", "setup.py", "dockerfile", "setup.cfg",
})

#: 软排除文件名 glob（docker-compose*.yml / *.yaml）
SOFT_FILE_GLOBS: frozenset[str] = frozenset({
    "docker-compose*.yml", "docker-compose*.yaml",
})


# ---------------------------------------------------------------------------
# 排除记录与扫描结果
# ---------------------------------------------------------------------------

@dataclass
class ExcludeRecord:
    """一条"被排除"的记录（整目录或单文件）。"""

    abs_path: Path          # 绝对路径
    rel_path: str           # 相对 target 的 POSIX 路径
    kind: str               # "dir" | "file"
    category: str           # hard_dir / soft_dir / hard_ext / hard_file / soft_file / unsupported_ext
    reason: str             # 人类可读原因（含命中的规则关键字）

    def to_dict(self) -> dict:
        """转为 JSON 友好的字典。

        :return: 记录字典。
        """
        return {
            "path": str(self.abs_path),
            "rel_path": self.rel_path,
            "kind": self.kind,
            "category": self.category,
            "reason": self.reason,
        }


@dataclass
class ScanResult:
    """一次扫描的结果（供 manifest 组装）。"""

    target: Path                             # 扫描根目标
    scanned_files: list[Path] = field(default_factory=list)   # 待扫描源码文件（绝对路径）
    excluded: list[ExcludeRecord] = field(default_factory=list)  # 全部排除记录
    include_excluded: bool = False           # 本次是否纳入软排除
    scan_dirs: list[str] = field(default_factory=list)         # 限定扫描的子目录（可空=全量）

    # ---- 统计辅助 ----
    @property
    def scanned_count(self) -> int:
        """待扫描文件数。"""
        return len(self.scanned_files)

    @property
    def excluded_count(self) -> int:
        """排除记录条数。"""
        return len(self.excluded)

    def category_counts(self) -> dict[str, int]:
        """按 category 统计排除记录数。

        :return: {category: count}。
        """
        counts: dict[str, int] = {}
        for rec in self.excluded:
            counts[rec.category] = counts.get(rec.category, 0) + 1
        return counts

    def excluded_dir_count(self) -> int:
        """排除的整目录数量。"""
        return sum(1 for r in self.excluded if r.kind == "dir")


# ---------------------------------------------------------------------------
# FileFilter：规则 + 剪枝遍历
# ---------------------------------------------------------------------------

class FileFilter:
    """按硬/软规则把目标目录分类为"待扫描"与"排除"，并做目录剪枝。"""

    def __init__(
        self,
        include_excluded: bool = False,
        scan_dirs: Optional[list[str]] = None,
        source_extensions: Optional[list[str]] = None,
    ) -> None:
        """构造过滤器。

        :param include_excluded: True 时软排除的目录/文件也纳入扫描。
        :param scan_dirs: 只扫描 target 下的这些子目录；None/空 表示全量。
        :param source_extensions: 视为源码的后缀白名单（决定哪些文件进 scan_scope）。
        """
        self.include_excluded: bool = include_excluded
        self.scan_dirs: list[str] = list(scan_dirs) if scan_dirs else []
        self.source_extensions: set[str] = set(source_extensions or [".py", ".pyw"])
        self._dirs_visited: int = 0

    # ---- 规则查询 ----
    def dir_category(self, dirname: str) -> Optional[str]:
        """返回目录命中规则：hard_dir / soft_dir / None。

        :param dirname: 目录名。
        :return: 命中类别或 None。
        """
        name = dirname.lower()
        if name in HARD_DIR_NAMES:
            return "hard_dir"
        if name in SOFT_DIR_NAMES:
            return "soft_dir"
        return None

    def file_category(self, filename: str) -> Optional[tuple[str, str]]:
        """返回文件命中的排除类别与原因；None 表示未命中任何排除规则。

        判定顺序：硬文件名 -> 硬扩展名 -> 软文件名/glob。

        :param filename: 文件名。
        :return: (category, reason)；未命中返回 None。
        """
        name = filename.lower()
        if name in HARD_FILE_NAMES:
            return "hard_file", f"硬排除文件: {filename}"
        ext = Path(filename).suffix.lower()
        if ext in HARD_EXTENSIONS:
            return "hard_ext", f"硬排除扩展名: {ext}"
        if name in SOFT_FILE_NAMES or any(fnmatch(name, g) for g in SOFT_FILE_GLOBS):
            return "soft_file", f"软排除文件: {filename}"
        return None

    # ---- 扫描 ----
    def scan(self, target: Path) -> ScanResult:
        """对 target 执行剪枝遍历并分类，返回 ScanResult。

        :param target: 待扫描目标（文件或目录）。
        :return: 扫描结果。
        :raises FileNotFoundError: target 不存在。
        """
        target = target.resolve()
        if not target.exists():
            raise FileNotFoundError(f"扫描目标不存在: {target}")

        result = ScanResult(target=target, include_excluded=self.include_excluded,
                            scan_dirs=list(self.scan_dirs))

        # 情况1：目标是单个文件 —— 直接分类，不做目录遍历
        if target.is_file():
            self._classify_file(target, target, result)
            return result

        # 情况2：目标是目录 —— 依据 scan_dirs 决定扫描根集合
        scan_roots: list[Path]
        if self.scan_dirs:
            scan_roots = []
            for d in self.scan_dirs:
                p = (target / d).resolve()
                if p.is_dir():
                    scan_roots.append(p)
                else:
                    logger.warning("--scan-dirs 指定的目录不存在，已跳过: %s", p)
            if not scan_roots:
                raise FileNotFoundError(
                    f"--scan-dirs 指定的目录在 {target} 下均不存在: {self.scan_dirs}"
                )
        else:
            scan_roots = [target]

        for root in scan_roots:
            self._walk_dir(root, target, result)
        return result

    def _walk_dir(self, root: Path, target: Path, result: ScanResult) -> None:
        """对一个扫描根目录做 os.walk 剪枝遍历。

        剪枝原理：对当前目录的每个子目录先判规则；命中硬排除（或软排除且未
        include_excluded）时记录一条 ExcludeRecord 并从 dirnames 中移除，
        os.walk 便不会进入该子树。

        :param root: 扫描起点目录。
        :param target: manifest 根目录（用于计算相对路径）。
        :param result: 累积结果容器。
        """
        for current, dirnames, filenames in os.walk(root):
            self._dirs_visited += 1
            current_dir = Path(current)

            # 先过滤子目录（原地修改 dirnames 实现剪枝）
            kept_dirs: list[str] = []
            for dirname in sorted(dirnames):
                category = self.dir_category(dirname)
                if category == "hard_dir":
                    self._record_excluded(current_dir / dirname, "dir", category,
                                          f"硬排除目录: {dirname}", target, result)
                elif category == "soft_dir" and not self.include_excluded:
                    self._record_excluded(current_dir / dirname, "dir", category,
                                          f"软排除目录: {dirname}（--include-excluded 可纳入）",
                                          target, result)
                else:
                    kept_dirs.append(dirname)  # 保留：继续下钻
            dirnames[:] = kept_dirs

            # 再分类当前目录下的文件
            for filename in sorted(filenames):
                self._classify_file(current_dir / filename, target, result)

    def _classify_file(self, file_path: Path, target: Path, result: ScanResult) -> None:
        """对单个文件做最终归属决策（扫描 / 各类排除）。

        决策逻辑：
        1. 命中软排除文件且 include_excluded=True 时，把它当普通文件继续走第 3 步
           （软排除只在默认关闭时生效）；
        2. 命中硬排除 -> excluded；
        3. 后缀命中源码白名单 -> scanned_files；
        4. 否则 -> 记录 unsupported_ext 排除（保证统计自洽）。

        :param file_path: 文件绝对路径。
        :param target: manifest 根目录。
        :param result: 累积结果容器。
        """
        name = file_path.name
        matched = self.file_category(name)

        if matched is not None:
            category, reason = matched
            if category == "soft_file" and self.include_excluded:
                pass  # 软排除被显式打开：不排除，按普通文件继续判断
            else:
                self._record_excluded(file_path, "file", category, reason, target, result)
                return

        # 未被排除或软排除被打开 -> 按源码后缀决定归属
        if file_path.suffix.lower() in self.source_extensions:
            result.scanned_files.append(file_path)
        else:
            self._record_excluded(file_path, "file", "unsupported_ext",
                                  f"非目标源码扩展名: {file_path.suffix or '(无)'}",
                                  target, result)

    @staticmethod
    def _record_excluded(path: Path, kind: str, category: str, reason: str,
                         target: Path, result: ScanResult) -> None:
        """便捷地追加一条排除记录。

        :param path: 被排除对象绝对路径。
        :param kind: "dir" 或 "file"。
        :param category: 排除类别。
        :param reason: 排除原因。
        :param target: manifest 根目录。
        :param result: 累积结果容器。
        """
        result.excluded.append(ExcludeRecord(
            abs_path=path,
            rel_path=rel_posix(path, target),
            kind=kind,
            category=category,
            reason=reason,
        ))
