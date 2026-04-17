"""读取项目配置。"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

from .errors import ConfigurationError

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


@dataclass(slots=True, frozen=True)
class FeatureGateConfig:
    """功能门控默认值。"""

    allow_unsafe: bool
    allow_debugger: bool


@dataclass(slots=True, frozen=True)
class LimitConfig:
    """工具默认限制。"""

    default_page_size: int
    max_page_size: int
    max_search_hits: int
    max_callgraph_depth: int


@dataclass(slots=True, frozen=True)
class DirectoryAnalysisConfig:
    """批处理默认配置。"""

    recursive: bool
    max_candidates: int
    max_deep_analysis: int
    include_extensions: tuple[str, ...]
    exclude_patterns: tuple[str, ...]
    prefer_managed: bool
    prefer_native: bool
    prefer_entry_binary: bool
    prefer_user_code: bool
    scoring_profile: str


@dataclass(slots=True, frozen=True)
class AppConfig:
    """应用总配置。"""

    logging: LoggingConfig
    server: ServerConfig
    feature_gates: FeatureGateConfig
    limits: LimitConfig
    directory_analysis: DirectoryAnalysisConfig
    root: Path


def _as_str(value: TomlValue, *, default: str) -> str:
    """把 TOML 标量安全转换成字符串。"""
    if isinstance(value, str):
        return value
    return default


def _as_bool(value: TomlValue, *, default: bool) -> bool:
    """把 TOML 标量安全转换成布尔值。"""
    if isinstance(value, bool):
        return value
    return default


def _as_int(value: TomlValue, *, default: int) -> int:
    """把 TOML 标量安全转换成整数。"""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    return default


def _require_table(raw: TomlTable, key: str) -> TomlTable:
    """读取一个必须存在的 TOML 表。"""
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigurationError(f"setting.toml 缺少 {key} 段")
    return cast(TomlTable, value)


def _to_str_tuple(value: TomlValue) -> tuple[str, ...]:
    """把 TOML 数组转换成字符串元组。"""
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def load_config(config_path: Path) -> AppConfig:
    """加载 `setting.toml`。"""
    if not config_path.exists():
        raise ConfigurationError(f"配置文件不存在：{config_path}")

    # tomllib 的类型声明较宽，这里把解析结果收窄到项目内部使用的 TOML 递归类型。
    raw = cast(TomlTable, tomllib.loads(config_path.read_text(encoding="utf-8")))
    root = config_path.parent.resolve()
    logging_raw = _require_table(raw, "logging")
    server_raw = _require_table(raw, "server")
    gates_raw = _require_table(raw, "feature_gates")
    limits_raw = _require_table(raw, "limits")
    directory_raw = _require_table(raw, "directory_analysis")

    return AppConfig(
        logging=LoggingConfig(
            level=_as_str(logging_raw.get("level", "INFO"), default="INFO"),
            directory=(root / _as_str(logging_raw.get("directory", "logs"), default="logs")).resolve(),
        ),
        server=ServerConfig(
            protocol_version=_as_str(server_raw.get("protocol_version", "2025-06-18"), default="2025-06-18"),
            server_name=_as_str(server_raw.get("server_name", "ida-stdio-mcp"), default="ida-stdio-mcp"),
            server_version=_as_str(server_raw.get("server_version", "0.2.0"), default="0.2.0"),
            default_input_path=_as_str(server_raw.get("default_input_path", ""), default=""),
        ),
        feature_gates=FeatureGateConfig(
            allow_unsafe=_as_bool(gates_raw.get("allow_unsafe", False), default=False),
            allow_debugger=_as_bool(gates_raw.get("allow_debugger", False), default=False),
        ),
        limits=LimitConfig(
            default_page_size=_as_int(limits_raw.get("default_page_size", 100), default=100),
            max_page_size=_as_int(limits_raw.get("max_page_size", 1000), default=1000),
            max_search_hits=_as_int(limits_raw.get("max_search_hits", 1000), default=1000),
            max_callgraph_depth=_as_int(limits_raw.get("max_callgraph_depth", 4), default=4),
        ),
        directory_analysis=DirectoryAnalysisConfig(
            recursive=_as_bool(directory_raw.get("recursive", True), default=True),
            max_candidates=_as_int(directory_raw.get("max_candidates", 20), default=20),
            max_deep_analysis=_as_int(directory_raw.get("max_deep_analysis", 5), default=5),
            include_extensions=tuple(item.lower() for item in _to_str_tuple(directory_raw.get("include_extensions", []))),
            exclude_patterns=_to_str_tuple(directory_raw.get("exclude_patterns", [])),
            prefer_managed=_as_bool(directory_raw.get("prefer_managed", False), default=False),
            prefer_native=_as_bool(directory_raw.get("prefer_native", False), default=False),
            prefer_entry_binary=_as_bool(directory_raw.get("prefer_entry_binary", True), default=True),
            prefer_user_code=_as_bool(directory_raw.get("prefer_user_code", True), default=True),
            scoring_profile=_as_str(directory_raw.get("scoring_profile", "default"), default="default"),
        ),
        root=root,
    )
