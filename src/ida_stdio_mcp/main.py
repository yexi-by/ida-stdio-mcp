"""应用主入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from loguru import logger

from .config import load_config
from .logging import configure_logging
from .runtime import HeadlessRuntime
from .stdio_server import ServerIdentity, StdioMcpServer


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="IDA Headless + 通用 stdio MCP 服务")
    parser.add_argument("input_path", nargs="?", type=Path, help="可选：启动后立即打开的样本路径")
    parser.add_argument("--config", type=Path, default=Path("setting.toml"), help="配置文件路径")
    parser.add_argument("--unsafe", action="store_true", help="启用危险写操作与 Python 执行工具")
    parser.add_argument("--debugger", action="store_true", help="启用调试器工具")
    parser.add_argument("--profile", type=Path, help="工具白名单 profile 文件")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """启动服务。"""
    args = _parse_args(argv)
    config = load_config(args.config.resolve())
    log_path = configure_logging(config.logging)

    runtime = HeadlessRuntime()
    ida_dir = runtime.require_ida_dir()

    # idapro 必须先于其它 ida_* 模块导入。
    import idapro

    idapro.enable_console_messages(False)

    from .service import build_service

    allow_unsafe = config.feature_gates.allow_unsafe or args.unsafe
    allow_debugger = config.feature_gates.allow_debugger or args.debugger
    profile_path = args.profile.resolve() if args.profile is not None else None

    logger.info(
        "启动参数：config={} log_path={} idadir={} unsafe={} debugger={} profile={}",
        args.config,
        log_path,
        ida_dir,
        allow_unsafe,
        allow_debugger,
        profile_path,
    )

    service = build_service(
        runtime,
        config,
        allow_unsafe=allow_unsafe,
        allow_debugger=allow_debugger,
        profile_path=profile_path,
    )

    startup_binary = args.input_path
    if startup_binary is None and config.server.default_input_path.strip():
        startup_binary = Path(config.server.default_input_path.strip())
    if startup_binary is not None:
        runtime.open_binary(startup_binary.resolve())
        logger.info("已在启动阶段打开样本：{}", startup_binary)

    server = StdioMcpServer(
        tools=service.tools,
        resources=service.resources,
        identity=ServerIdentity(
            protocol_version=config.server.protocol_version,
            server_name=config.server.server_name,
            server_version=config.server.server_version,
        ),
    )
    try:
        return server.serve()
    finally:
        runtime.shutdown()
        logger.info("服务结束，所有会话均已关闭")
