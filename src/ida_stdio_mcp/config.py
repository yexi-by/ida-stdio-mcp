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
    directory_analysis: DirectoryAnalysisConfig
    root: Path


def load_config(config_path: Path) -> AppConfig:
    """加载 `setting.toml`。"""
    if not config_path.exists():
        raise ConfigurationError(f"配置文件不存在：{config_path}")

    raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    logging_raw = raw.get("logging")
    server_raw = raw.get("server")
    directory_raw = raw.get("directory_analysis")
    if not isinstance(logging_raw, dict) or not isinstance(server_raw, dict) or not isinstance(directory_raw, dict):
        raise ConfigurationError("setting.toml 缺少 logging/server/directory_analysis 段")

    root = config_path.parent
    return AppConfig(
        logging=LoggingConfig(
            level=str(logging_raw.get("level", "INFO")),
            directory=(root / str(logging_raw.get("directory", "logs"))).resolve(),
        ),
        server=ServerConfig(
            protocol_version=str(server_raw.get("protocol_version", "2025-06-18")),
            server_name=str(server_raw.get("server_name", "ida-stdio-mcp")),
            server_version=str(server_raw.get("server_version", "0.1.0")),
        ),
        directory_analysis=DirectoryAnalysisConfig(
            recursive=bool(directory_raw.get("recursive", True)),
            max_candidates=int(directory_raw.get("max_candidates", 20)),
            max_deep_analysis=int(directory_raw.get("max_deep_analysis", 5)),
            include_extensions=tuple(str(item).lower() for item in directory_raw.get("include_extensions", [])),
            exclude_patterns=tuple(str(item) for item in directory_raw.get("exclude_patterns", [])),
        ),
        root=root.resolve(),
    )
