"""文件清单构建与读写（manifest）。

把模块0 过滤分类后的结果落盘为 ``output/file_manifest.json``。

顶层结构示意：::

    {
      "version": "1.0",
      "target": "D:/projct/opensoft_detect/test/goat/pygoat-master",
      "generated_at": "2026-09-06T15:30:00",
      "include_excluded": false,            # 本次是否纳入软排除
      "scan_dirs": [],                       # --scan-dirs 限定目录（空=全量）
      "scan_scope": [                        # 待静态扫描的源码文件
        {
          "path": ".../manage.py", "rel_path": "manage.py",
          "language": "python", "size_bytes": 2048,
          "line_count": 80, "sha256": "..."
        }
      ],
      "excluded": [                          # 排除记录（含分类原因）
        {"path": "...", "rel_path": "__pycache__", "kind": "dir",
         "category": "hard_dir", "reason": "硬排除目录: __pycache__"}
      ],
      "stats": {                             # 统计信息
        "scanned_files": 120,
        "excluded_dirs": 9, "excluded_files": 45,
        "excluded_by_category": {"hard_dir": 9, "unsupported_ext": 30, "soft_dir": 6}
      }
    }

模块1（static_analysis）只消费 ``scan_scope``，从而保证扫描范围与模块0 的
过滤结果严格一致。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from modules.preprocess.filter import ScanResult
from modules.preprocess.scanner import file_entry

logger = logging.getLogger("opensoft_detect.preprocess")

MANIFEST_VERSION: str = "1.0"


class ManifestBuilder:
    """把 ScanResult 汇总为清单字典并落盘。"""

    def build_manifest(self, target: Path, result: ScanResult) -> dict[str, Any]:
        """组装清单字典。

        :param target: 扫描根目标。
        :param result: FileFilter 的扫描结果。
        :return: file_manifest.json 对应的字典。
        """
        target = target.resolve()
        # scan_scope 有序去重；每个文件附带语言/大小/行数/指纹
        scan_entries: list[dict] = [file_entry(p, target) for p in sorted(set(result.scanned_files))]
        excluded_entries: list[dict] = [rec.to_dict() for rec in result.excluded]

        # 排除文件数 = 所有 kind=="file" 的排除记录（含 unsupported_ext）
        excluded_files: int = sum(1 for r in result.excluded if r.kind == "file")

        stats: dict[str, int] = {
            "scanned_files": len(scan_entries),
            "excluded_dirs": result.excluded_dir_count(),
            "excluded_files": excluded_files,
        }
        stats["excluded_by_category"] = {k: v for k, v in
                                         sorted(result.category_counts().items())}

        manifest: dict[str, Any] = {
            "version": MANIFEST_VERSION,
            "target": str(target),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "include_excluded": result.include_excluded,
            "scan_dirs": list(result.scan_dirs),
            "scan_scope": scan_entries,
            "excluded": excluded_entries,
            "stats": stats,
        }
        return manifest

    def save(self, manifest: dict[str, Any], out_path: Path) -> str:
        """将清单字典序列化写入 out_path（自动创建父目录）。

        :param manifest: 清单字典。
        :param out_path: 输出文件路径。
        :return: 写入完成的绝对路径字符串。
        """
        out_path = out_path.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("清单已写入：%s（scan_scope=%d 文件）",
                    out_path, len(manifest.get("scan_scope", [])))
        return str(out_path)


def load_manifest(path: Path) -> dict[str, Any]:
    """从磁盘读取 file_manifest.json 并解析为字典。

    :param path: 清单文件路径。
    :return: 清单字典。
    :raises FileNotFoundError: 文件不存在。
    """
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def iter_scan_scope(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """返回清单中 scan_scope 的条目列表（含 path/rel_path/language）。

    :param manifest: 清单字典。
    :return: 待扫描文件条目列表。
    """
    return list(manifest.get("scan_scope") or [])


def scan_scope_paths(manifest: dict[str, Any]) -> list[str]:
    """返回 scan_scope 中每个文件的绝对路径字符串。

    :param manifest: 清单字典。
    :return: 绝对路径列表。
    """
    return [entry["path"] for entry in iter_scan_scope(manifest) if entry.get("path")]


def scan_scope_dirname_groups(manifest: dict[str, Any]) -> list[str]:
    """按文件所在目录去重，返回"扫描文件覆盖的最短目录前缀集"。

    用于给 CodeQL 生成 codeql-config.yml 的 paths（顶层目录），以及给 Semgrep
    大文件量时做目录级定位。实现：取每个扫描文件 rel_path 的首段（根级文件用 "."）。

    :param manifest: 清单字典。
    :return: 去重后的目录前缀（POSIX 风格）列表。
    """
    prefixes: set[str] = set()
    for entry in iter_scan_scope(manifest):
        rel: str = entry.get("rel_path", "")
        if "/" in rel:
            prefixes.add(rel.split("/", 1)[0])
        else:
            prefixes.add(".")  # 根级文件
    return sorted(prefixes)
