"""模块0 编排入口（runner）。

把 FileFilter 扫描 -> ManifestBuilder 落盘串起来，供 main.py 单次调用。
返回 file_manifest.json 路径作为本阶段产物。
"""

from __future__ import annotations

import logging
from pathlib import Path

from config import Config
from modules.preprocess.filter import FileFilter
from modules.preprocess.manifest import ManifestBuilder

logger = logging.getLogger("opensoft_detect.preprocess")


def run(config: Config) -> Path:
    """执行模块0预处理，产出 ``output/file_manifest.json``。

    流程：
    1. 构造 :class:`FileFilter`（读取 config 的 include_excluded / scan_dirs）；
    2. ``FileFilter.scan(config.target)`` 遍历并按硬/软规则分类；
    3. ``ManifestBuilder.build_manifest + save`` 落盘到 config.paths.default_manifest_path。

    :param config: 全局配置。
    :return: 清单文件绝对路径。
    :raises FileNotFoundError: 目标不存在或 --scan-dirs 指定的目录均不存在。
    """
    f = FileFilter(
        include_excluded=config.include_excluded,
        scan_dirs=list(config.scan_dirs) or None,
        source_extensions=list(config.source_extensions),
    )
    result = f.scan(config.target)

    logger.info(
        "扫描完成：待扫描文件=%d | 排除目录=%d | 排除文件=%d | 分类=%s",
        result.scanned_count, result.excluded_dir_count(),
        result.excluded_count, result.category_counts(),
    )
    if result.scanned_count == 0:
        logger.warning("目标下未发现任何可扫描的源码文件，后续静态分析将为空。")

    manifest = ManifestBuilder().build_manifest(config.target, result)
    out_path: Path = config.paths.default_manifest_path
    saved: str = ManifestBuilder().save(manifest, out_path)
    return Path(saved)
