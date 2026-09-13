"""全局配置模块。

集中管理 OpenSoft Detect 全部可配置项，并给出与当前工作环境一致的默认值：

- 目标路径 / 输出路径（中间 JSON 与最终报告统一放 ``output/``）
- 各静态工具的可执行文件与规则路径（Semgrep / CodeQL / pip-audit）
- Qdrant 向量库连接参数（集合 ``security_knowledge``，与 ./qdrant.md 一致）
- LLM 服务参数（默认 Anthropic，可通过环境变量注入 API Key）
- Docker 沙箱参数（模块4 动态验证用）
- 预处理过滤规则（硬排除 + 软排除，见 modules/preprocess/filter.py）

优先级约定：默认值 < 配置文件（可选）< 环境变量 < CLI 参数。

当前生效层：默认值 + CLI 参数（由 :class:`ConfigLoader.load_from_args` 合并）。
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

# 工作区根目录：以本文件所在目录为准（config.py 位于项目根）
WORKSPACE_ROOT: Path = Path(__file__).resolve().parent
# 中间数据与报告统一输出目录
OUTPUT_DIR: Path = WORKSPACE_ROOT / "output"


# ---------------------------------------------------------------------------
# 预处理过滤规则默认值（模块0）
# 完整规则见 modules/preprocess/filter.py；此处只提供"关闭/覆盖"用的开关。
# ---------------------------------------------------------------------------

#: 文件后缀白名单：静态分析只针对这几类源码（语义上与 filter 的 HARD/SOFT 无关）
DEFAULT_SOURCE_EXTENSIONS: list[str] = [".py", ".pyw"]


# ---------------------------------------------------------------------------
# 分段配置数据类
# ---------------------------------------------------------------------------

@dataclass
class PathsConfig:
    """全局路径配置（绝对路径，避免受运行时 cwd 影响）。

    约定：所有中间 JSON（file_manifest / findings / enriched / verified / dynamic）
    与最终报告统一放在 ``output/`` 目录下，便于清理与归档。
    """

    workspace_root: Path = WORKSPACE_ROOT      # 项目根目录
    output_dir: Path = OUTPUT_DIR              # 输出总目录

    manifest_dir: Path = OUTPUT_DIR            # 模块0 产物目录（= output 根）
    findings_dir: Path = OUTPUT_DIR            # 模块1/2/3/4 产物目录
    report_dir: Path = OUTPUT_DIR              # 模块5 报告目录

    # ---- 各阶段产物默认文件名 ----
    @property
    def default_manifest_path(self) -> Path:
        """模块0 默认清单路径（output/file_manifest.json）。"""
        return self.manifest_dir / "file_manifest.json"

    @property
    def default_raw_findings_path(self) -> Path:
        """模块1 默认统一发现路径（output/findings.json）。"""
        return self.findings_dir / "findings.json"

    @property
    def default_enriched_path(self) -> Path:
        """模块2 默认富化结果路径（output/enriched_findings.json）。"""
        return self.findings_dir / "enriched_findings.json"

    @property
    def default_verdict_path(self) -> Path:
        """模块3 默认研判结果路径（output/verified_findings.json）。"""
        return self.findings_dir / "verified_findings.json"

    @property
    def default_dynamic_path(self) -> Path:
        """模块4 默认动态验证结果路径（output/dynamic_findings.json）。"""
        return self.findings_dir / "dynamic_findings.json"


@dataclass
class QdrantConfig:
    """Qdrant 向量库连接与检索配置（与 ./qdrant.md 记录一致）。"""

    host: str = "localhost"
    port: int = 6333
    collection_name: str = "security_knowledge"              # 知识库主集合
    storage_path: Path = WORKSPACE_ROOT / "qdrant_storage"
    embedding_provider: str = "fastembed"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    # 嵌入模型本地持久缓存（项目内目录，避免 %TEMP% 被系统清理后每次重下）
    embedding_cache_dir: Path = WORKSPACE_ROOT / "models" / "fastembed_cache"
    embedding_dim: int = 384
    sparse_model: str = "Qdrant/bm25"
    top_k: int = 5
    similarity_threshold: float = 0.6

    # 漏洞特征闭环使用的专属集合（模块3）
    vuln_feature_collection: str = "vuln_features"
    fp_feature_collection: str = "fp_features"


@dataclass
class LLMConfig:
    """大模型调用配置（provider: anthropic / openai）。

    可靠性工程参数按模块3 约定固化：
    - ``temperature=0`` 消除随机性
    - 单次请求超时 30s
    - 失败最多重试 ``max_retries``(3) 轮
    """

    # provider: anthropic / openai(含兼容网关如智谱 bigmodel)。
    # 运行时通过环境变量覆盖默认值，避免把密钥/网关写进代码：
    #   OPENSOFT_LLM_PROVIDER / OPENSOFT_LLM_API_BASE / OPENSOFT_LLM_MODEL
    provider: str = field(default_factory=lambda: os.environ.get("OPENSOFT_LLM_PROVIDER", "anthropic"))
    api_base: str = field(default_factory=lambda: os.environ.get("OPENSOFT_LLM_API_BASE", ""))
    # 兼容两种 provider 的 Key 注入：anthropic 读 ANTHROPIC_API_KEY，openai 读 OPENAI_API_KEY
    api_key: str = field(default_factory=lambda: (
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY", "")))
    model: str = field(default_factory=lambda: os.environ.get("OPENSOFT_LLM_MODEL", "claude-sonnet-5"))
    temperature: float = 0.0
    max_tokens: int = 4096
    request_timeout: float = 30.0
    max_retries: int = 3
    json_mode: bool = True                     # 强制 JSON 结构化输出
    # 判定缓存：相同 (provider/model/system/user) 直接复用结果（省钱、可复现、回归不重复烧额度）
    cache_enabled: bool = True
    cache_ttl_days: int = 30


@dataclass
class ToolConfig:
    """静态工具（模块1）可执行文件与规则配置。

    路径默认值已对齐本机实际环境：
    - CodeQL 使用离线 Windows bundle，并直接指向其内置的
      ``python-code-scanning.qls`` 查询套件（无需联网下载包）。
    """

    semgrep_bin: str = "semgrep"
    # Semgrep 自定义规则目录：若目录为空则退化为 --config auto（需联网/登录 registry）
    semgrep_rules_dir: Path = WORKSPACE_ROOT / "rules" / "semgrep"
    semgrep_timeout: int = 300

    codeql_bin: Path = WORKSPACE_ROOT / "codeql" / "codeql-bundle-win64" / "codeql" / "codeql.exe"
    # 指向 bundle 内置离线 Python code-scanning 查询套件
    codeql_query_suite: Path = (
        WORKSPACE_ROOT / "codeql" / "codeql-bundle-win64" / "codeql" / "qlpacks"
        / "codeql" / "python-queries" / "1.8.9" / "codeql-suites" / "python-code-scanning.qls"
    )
    codeql_database_dir: Path = WORKSPACE_ROOT / "output" / "codeql-db"   # 中间数据库目录
    codeql_config_path: Path = WORKSPACE_ROOT / "output" / "codeql-config.yml"  # 生成的 paths 配置
    codeql_timeout: int = 900
    # 是否在分析后删除数据库：False=保留以复用（按 manifest 内容哈希缓存，扫描集变则失效）
    codeql_cleanup_db: bool = False

    pip_audit_bin: str = "pip-audit"
    # 依赖漏洞最低上报级别：medium（OSV 部分漏洞无 CVSS，默认按 medium 计）
    pip_audit_severity_min: str = "medium"


@dataclass
class DockerConfig:
    """动态验证（模块4）Docker 沙箱参数。"""

    image: str = "python:3.11-slim"
    network_mode: str = "none"
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    timeout_seconds: int = 60
    cleanup_after_run: bool = True
    volumes_mount_dir: Path = WORKSPACE_ROOT / "output" / "sandbox"


@dataclass
class Config:
    """全局配置聚合根。

    由 main.py 组装后按需把配置片段分发给各模块 runner。
    """

    target: Path = Path(".")             # 待扫描目标（模块0 输入）
    fix_suggest: bool = False            # 是否生成修复建议（--fix-suggest）
    skip_dynamic: bool = False           # 是否跳过动态验证（无 Docker 时置 True）
    skip_llm: bool = False               # 是否跳过 LLM 研判

    # ---- 模块0 专属开关 ----
    include_excluded: bool = False       # --include-excluded：把软排除文件也纳入扫描
    scan_dirs: list[str] = field(default_factory=list)   # --scan-dirs：只扫描指定的目录

    # ---- 模块4 专属开关 ----
    # 是否执行"尽力而为"的真实沙箱探针。目标工程需依赖齐全、具备可驱动入口
    # （+ 配置 LLM Key 生成 PoC）才有意义；默认关闭，避免把"能 import 但未触发"
    # 的模块误判为 rejected。关闭时相关 Finding 标注 skip_reason="no_entry_driver"。
    dynamic_attempts: bool = False

    # Django 候选的动态探针模式：True=真 HTTP（同进程 WSGI 起服+会话+免 CSRF，
    # 更真实但每候选需起服务+migrate）；False=RequestFactory 直调（更快）。
    # 仅当 dynamic_attempts=True 时生效。
    dynamic_http: bool = True

    # 路线级 DAST 小扫描（不依赖静态发现，直接产新 Finding）：
    # 目前实现"缺鉴权"（匿名 vs 已认证差分）；后续可加反射 XSS / 缺 CSRF。
    dynamic_dast: bool = True

    # 自动供给的"止损"防线：依赖条目过多 或 构建超时 → 立即放弃（不硬等）
    dynamic_provision_max_deps: int = 80     # 依赖条目上限（超过视为过重工程）
    dynamic_provision_timeout: int = 420     # 单次供给构建超时（秒）

    paths: PathsConfig = field(default_factory=PathsConfig)
    qdrant: QdrantConfig = field(default_factory=QdrantConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    tools: ToolConfig = field(default_factory=ToolConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)

    log_level: str = "INFO"
    source_extensions: list[str] = field(default_factory=lambda: list(DEFAULT_SOURCE_EXTENSIONS))


# ---------------------------------------------------------------------------
# 配置装载
# ---------------------------------------------------------------------------

class ConfigLoader:
    """把 CLI 参数 / 环境变量解析合并为 :class:`Config`。"""

    @staticmethod
    def ensure_dirs(config: Config) -> None:
        """确保所有输出目录存在（main.py 启动时调用一次）。"""
        for d in (config.paths.output_dir,
                  config.tools.codeql_database_dir,
                  config.docker.volumes_mount_dir):
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def load_from_args(cls, args: Any) -> Config:
        """根据 argparse 参数命名空间构造 :class:`Config`。

        :param args: main.py ``parse_args()`` 返回的对象。
        :return: 合并默认值与 CLI 参数后的全局配置。
        """
        return Config(
            target=Path(args.target).resolve() if args.target else Path(".").resolve(),
            fix_suggest=bool(getattr(args, "fix_suggest", False)),
            skip_dynamic=bool(getattr(args, "skip_dynamic", False)),
            skip_llm=bool(getattr(args, "skip_llm", False)),
            dynamic_attempts=bool(getattr(args, "attempt_dynamic", False)),
            dynamic_dast=not bool(getattr(args, "no_dast", False)),
            include_excluded=bool(getattr(args, "include_excluded", False)),
            scan_dirs=list(getattr(args, "scan_dirs", None) or []),
            log_level=getattr(args, "log_level", "INFO"),
        )

    @staticmethod
    def _plain(obj: Any) -> Any:
        """把嵌套 dataclass / Path 转成 JSON 友好的纯 dict/str。

        :param obj: 任意对象。
        :return: 可被 json.dumps 直接处理的表示。
        """
        if isinstance(obj, Path):
            return str(obj)
        if hasattr(obj, "__dataclass_fields__"):
            return {k: ConfigLoader._plain(v) for k, v in asdict(obj).items()}
        if isinstance(obj, dict):
            return {k: ConfigLoader._plain(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            return [ConfigLoader._plain(v) for v in obj]
        return obj

    #: 需要脱敏的键（配置快照会落到 output/，可能被随报告一起分享/提交）
    _SECRET_KEYS: frozenset[str] = frozenset({"api_key", "apikey", "token", "secret",
                                              "password", "access_key"})

    @classmethod
    def dump(cls, config: Config) -> dict[str, Any]:
        """把配置序列化为纯 dict（写入 output/config_used.json 留痕）。

        **密钥脱敏**：快照只保留"是否配置了密钥"，不回写明文——产物一旦被分享或
        误提交（实测发生过：key 出现在 output/config_used.json 与 .claude 白名单里）
        就会泄露凭证。

        :param config: 全局配置。
        :return: JSON 友好字典（密钥字段已脱敏）。
        """
        plain = cls._plain(config)
        cls._redact(plain)
        return plain

    @classmethod
    def _redact(cls, node: Any) -> None:
        """就地递归把密钥类字段替换为 ``***已配置***`` / 空标记。

        :param node: _plain 产出的 dict/list 结构。
        """
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if isinstance(v, str) and k.lower() in cls._SECRET_KEYS:
                    node[k] = "***已配置（已脱敏）***" if v else ""
                else:
                    cls._redact(v)
        elif isinstance(node, list):
            for item in node:
                cls._redact(item)
