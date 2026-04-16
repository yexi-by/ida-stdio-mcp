"""日志初始化。"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from loguru import logger
from rich.console import Console

from .config import LoggingConfig

CONSOLE = Console(stderr=True, soft_wrap=True)


def configure_logging(config: LoggingConfig) -> Path:
    """配置终端与文件日志。"""
    config.directory.mkdir(parents=True, exist_ok=True)
    log_path = config.directory / f"ida-stdio-mcp-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

    logger.remove()
    logger.add(
        sys.stderr,
        level=config.level,
        colorize=True,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
    )
    logger.add(
        log_path,
        level="DEBUG",
        encoding="utf-8",
        enqueue=False,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
    )
    logger.info("日志系统已初始化，文件日志：{}", log_path)
    return log_path
