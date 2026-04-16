"""读取项目配置。"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError


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


@dataclass(slots=True, frozen=True)
class AppConfig:
    """应用总配置。"""

    logging: LoggingConfig
    server: ServerConfig
    feature_gates: FeatureGateConfig
    limits: LimitConfig
    directory_analysis: DirectoryAnalysisConfig
    root: Path


def _require_table(raw: dict[str, object], key: str) -> dict[str, object]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigurationError(f"setting.toml 缺少 {key} 段")
    return value


def _to_str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value)


def load_config(config_path: Path) -> AppConfig:
    """加载 `setting.toml`。"""
    if not config_path.exists():
        raise ConfigurationError(f"配置文件不存在：{config_path}")

    raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    root = config_path.parent.resolve()
    logging_raw = _require_table(raw, "logging")
    server_raw = _require_table(raw, "server")
    gates_raw = _require_table(raw, "feature_gates")
    limits_raw = _require_table(raw, "limits")
    directory_raw = _require_table(raw, "directory_analysis")

    return AppConfig(
        logging=LoggingConfig(
            level=str(logging_raw.get("level", "INFO")),
            directory=(root / str(logging_raw.get("directory", "logs"))).resolve(),
        ),
        server=ServerConfig(
            protocol_version=str(server_raw.get("protocol_version", "2025-06-18")),
            server_name=str(server_raw.get("server_name", "ida-stdio-mcp")),
            server_version=str(server_raw.get("server_version", "0.2.0")),
            default_input_path=str(server_raw.get("default_input_path", "")),
        ),
        feature_gates=FeatureGateConfig(
            allow_unsafe=bool(gates_raw.get("allow_unsafe", False)),
            allow_debugger=bool(gates_raw.get("allow_debugger", False)),
        ),
        limits=LimitConfig(
            default_page_size=int(limits_raw.get("default_page_size", 100)),
            max_page_size=int(limits_raw.get("max_page_size", 1000)),
            max_search_hits=int(limits_raw.get("max_search_hits", 1000)),
            max_callgraph_depth=int(limits_raw.get("max_callgraph_depth", 4)),
        ),
        directory_analysis=DirectoryAnalysisConfig(
            recursive=bool(directory_raw.get("recursive", True)),
            max_candidates=int(directory_raw.get("max_candidates", 20)),
            max_deep_analysis=int(directory_raw.get("max_deep_analysis", 5)),
            include_extensions=tuple(item.lower() for item in _to_str_tuple(directory_raw.get("include_extensions", []))),
            exclude_patterns=_to_str_tuple(directory_raw.get("exclude_patterns", [])),
        ),
        root=root,
    )
