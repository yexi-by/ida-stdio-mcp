"""应用主入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from loguru import logger

from .config import load_config
from .logging import configure_logging
from .runtime import HeadlessRuntime
from .stdio_server import ServerIdentity, StdioMcpServer
from .tools import build_registry


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="IDA Headless + stdio MCP 服务")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("setting.toml"),
        help="配置文件路径",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """启动服务。"""
    args = _parse_args(argv)
    config = load_config(args.config.resolve())
    log_path = configure_logging(config.logging)
    logger.info("启动参数：config={}, log_path={}", args.config, log_path)

    runtime = HeadlessRuntime()
    registry = build_registry(runtime, config)
    server = StdioMcpServer(
        registry=registry,
        identity=ServerIdentity(
            protocol_version=config.server.protocol_version,
            server_name=config.server.server_name,
            server_version=config.server.server_version,
        ),
    )
    try:
        return server.serve()
    finally:
        runtime.close_binary()
        logger.info("服务结束，最终已关闭数据库并完成清理")
