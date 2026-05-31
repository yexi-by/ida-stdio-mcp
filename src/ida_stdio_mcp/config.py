"""读取项目配置。"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version as package_metadata_version
from pathlib import Path
from typing import TypeAlias, cast

from .errors import ConfigurationError

_PROJECT_DISTRIBUTION_NAME = "ida-stdio-mcp"

TomlScalar: TypeAlias = str | int | float | bool | None
TomlValue: TypeAlias = TomlScalar | list["TomlValue"] | dict[str, "TomlValue"]
TomlTable: TypeAlias = dict[str, TomlValue]


@dataclass(slots=True, frozen=True)
class LoggingConfig:
    """日志配置。"""

    level: str
    directory: Path


@dataclass(slots=True, frozen=True)
class ServerConfig:
    """服务协议配置。"""

    protocol_version: str
    server_name: str
    server_version: str
    default_input_path: str
    isolated_contexts: bool


@dataclass(slots=True, frozen=True)
class RuntimeWorkspaceConfig:
    """运行时副作用目录配置。"""

    directory: Path
    symbol_cache_directory: Path


@dataclass(slots=True, frozen=True)
class LimitConfig:
    """工具默认限制。"""

    default_page_size: int
    max_page_size: int
    max_search_hits: int
    max_callgraph_depth: int


@dataclass(slots=True, frozen=True)
class ExternalAnalyzerConfig:
    """外部分析器配置。"""

    name: str
    command: tuple[str, ...]
    timeout_sec: int


@dataclass(slots=True, frozen=True)
class AppConfig:
    """应用总配置。"""

    logging: LoggingConfig
    server: ServerConfig
    runtime_workspace: RuntimeWorkspaceConfig
    limits: LimitConfig
    external_analyzers: tuple[ExternalAnalyzerConfig, ...]
    root: Path


def package_version() -> str:
    """读取项目包元数据中的版本号。"""
    try:
        return package_metadata_version(_PROJECT_DISTRIBUTION_NAME)
    except PackageNotFoundError as exc:
        raise ConfigurationError(
            f"无法读取 {_PROJECT_DISTRIBUTION_NAME} 包版本；请通过 uv run 或安装包后启动服务"
        ) from exc


def _as_str(value: TomlValue, *, key: str, default: str) -> str:
    """读取可选字符串；字段缺失使用默认值，类型错误显式失败。"""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    raise ConfigurationError(f"{key} 必须是字符串")


def _as_bool(value: TomlValue, *, key: str, default: bool) -> bool:
    """读取可选布尔值；字段缺失使用默认值，类型错误显式失败。"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise ConfigurationError(f"{key} 必须是布尔值")


def _as_int(value: TomlValue, *, key: str, default: int) -> int:
    """读取可选整数；字段缺失使用默认值，类型错误显式失败。"""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{key} 必须是整数")
    return value


def _as_str_tuple(value: TomlValue) -> tuple[str, ...]:
    """把 TOML 字符串数组收窄成字符串元组。"""
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return ()
        result.append(item)
    return tuple(result)


def _require_table(raw: TomlTable, key: str) -> TomlTable:
    """读取一个必须存在的 TOML 表。"""
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigurationError(f"setting.toml 缺少 {key} 段")
    return cast(TomlTable, value)


def _reject_deprecated_keys(raw: TomlTable, *, section: str, keys: tuple[str, ...]) -> None:
    """禁止已移出配置文件的字段形成第二事实来源。"""
    for key in keys:
        if key in raw:
            raise ConfigurationError(f"{section}.{key} 已废弃；该值由项目包元数据统一提供")


def _resolve_path(root: Path, value: TomlValue, *, key: str, default: str) -> Path:
    """把配置中的路径解析为绝对路径。"""
    raw_text = _as_str(value, key=key, default=default).strip()
    path = Path(raw_text) if raw_text else Path(default)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _external_analyzers(raw: TomlTable) -> tuple[ExternalAnalyzerConfig, ...]:
    """读取外部分析器配置。"""
    value = raw.get("external_analyzers")
    if value is None:
        return ()
    if not isinstance(value, dict):
        raise ConfigurationError("external_analyzers 必须是 TOML 表")
    analyzers: list[ExternalAnalyzerConfig] = []
    for name, raw_item in sorted(value.items()):
        if not name.strip():
            raise ConfigurationError("external_analyzers 的名称不能为空")
        if not isinstance(raw_item, dict):
            raise ConfigurationError(f"external_analyzers.{name} 必须是 TOML 表")
        item = cast(TomlTable, raw_item)
        command = _as_str_tuple(item.get("command"))
        if not command:
            raise ConfigurationError(f"external_analyzers.{name}.command 必须是非空字符串数组")
        analyzers.append(
            ExternalAnalyzerConfig(
                name=name,
                command=command,
                timeout_sec=max(1, _as_int(item.get("timeout_sec"), key=f"external_analyzers.{name}.timeout_sec", default=120)),
            )
        )
    return tuple(analyzers)


def load_config(config_path: Path) -> AppConfig:
    """加载 `setting.toml`。"""
    if not config_path.exists():
        raise ConfigurationError(f"配置文件不存在：{config_path}")

    # tomllib 的类型声明较宽，这里把解析结果收窄到项目内部使用的 TOML 递归类型。
    raw = cast(TomlTable, tomllib.loads(config_path.read_text(encoding="utf-8")))
    root = config_path.parent.resolve()
    logging_raw = _require_table(raw, "logging")
    server_raw = _require_table(raw, "server")
    runtime_workspace_raw = _require_table(raw, "runtime_workspace")
    limits_raw = _require_table(raw, "limits")
    _reject_deprecated_keys(server_raw, section="server", keys=("server_version",))

    return AppConfig(
        logging=LoggingConfig(
            level=_as_str(logging_raw.get("level"), key="logging.level", default="INFO"),
            directory=_resolve_path(root, logging_raw.get("directory"), key="logging.directory", default="logs"),
        ),
        server=ServerConfig(
            protocol_version=_as_str(server_raw.get("protocol_version"), key="server.protocol_version", default="2025-06-18"),
            server_name=_as_str(server_raw.get("server_name"), key="server.server_name", default="ida-stdio-mcp"),
            server_version=package_version(),
            default_input_path=_as_str(server_raw.get("default_input_path"), key="server.default_input_path", default=""),
            isolated_contexts=_as_bool(server_raw.get("isolated_contexts"), key="server.isolated_contexts", default=False),
        ),
        runtime_workspace=RuntimeWorkspaceConfig(
            directory=_resolve_path(root, runtime_workspace_raw.get("directory"), key="runtime_workspace.directory", default=".runtime"),
            symbol_cache_directory=_resolve_path(
                root,
                runtime_workspace_raw.get("symbol_cache_directory"),
                key="runtime_workspace.symbol_cache_directory",
                default=".runtime/symbol-cache",
            ),
        ),
        limits=LimitConfig(
            default_page_size=_as_int(limits_raw.get("default_page_size"), key="limits.default_page_size", default=100),
            max_page_size=_as_int(limits_raw.get("max_page_size"), key="limits.max_page_size", default=1000),
            max_search_hits=_as_int(limits_raw.get("max_search_hits"), key="limits.max_search_hits", default=1000),
            max_callgraph_depth=_as_int(limits_raw.get("max_callgraph_depth"), key="limits.max_callgraph_depth", default=4),
        ),
        external_analyzers=_external_analyzers(raw),
        root=root,
    )
