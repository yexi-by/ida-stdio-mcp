"""应用主入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from loguru import logger

from .config import load_config
from .ida_bootstrap import ensure_ida_environment, get_ida_runtime_info
from .logging import configure_logging
from .models import ToolSurface
from .runtime import HeadlessRuntime
from .runtime_workspace import configure_runtime_workspace
from .stdio_server import ServerIdentity, StdioMcpServer


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="IDA Headless + 通用 stdio MCP 服务")
    parser.add_argument("input_path", nargs="?", type=Path, help="可选：启动后立即打开的样本路径")
    parser.add_argument("--config", type=Path, default=Path("setting.toml"), help="配置文件路径")
    parser.add_argument("--unsafe", action="store_true", help="启用危险写操作与 Python 执行工具")
    parser.add_argument("--debugger", action="store_true", help="启用调试器工具")
    parser.add_argument("--isolated-contexts", action="store_true", help="按 context_id 隔离不同 agent/工作流的默认上下文")
    parser.add_argument("--tool-surface", choices=["slim", "full", "expert"], default="slim", help="工具暴露面：默认 slim 只暴露 AI 工作流入口")
    parser.add_argument("--profile", type=Path, help="工具白名单 profile 文件")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """启动服务。"""
    args = _parse_args(argv)
    config = load_config(args.config.resolve())
    log_path = configure_logging(config.logging)
    workspace_paths = configure_runtime_workspace(config.runtime_workspace)

    allow_unsafe = config.feature_gates.allow_unsafe or args.unsafe
    allow_debugger = config.feature_gates.allow_debugger or args.debugger
    isolated_contexts = config.feature_gates.isolated_contexts or args.isolated_contexts
    tool_surface: ToolSurface = args.tool_surface
    runtime = HeadlessRuntime(isolated_contexts=isolated_contexts)

    # idapro 必须先于其它 ida_* 模块导入。
    idapro_module = ensure_ida_environment()
    enable_console_messages = getattr(idapro_module, "enable_console_messages", None)
    if callable(enable_console_messages):
        enable_console_messages(False)

    from .service import build_service

    profile_path = args.profile.resolve() if args.profile is not None else None

    logger.info(
        "启动参数：config={} log_path={} ida_runtime={} unsafe={} debugger={} isolated_contexts={} tool_surface={} profile={}",
        args.config,
        log_path,
        get_ida_runtime_info().to_json(),
        allow_unsafe,
        allow_debugger,
        isolated_contexts,
        tool_surface,
        profile_path,
    )
    logger.info(
        "运行时目录：workspace={} symbol_cache={}",
        workspace_paths.directory,
        workspace_paths.symbol_cache_directory,
    )

    service = build_service(
        runtime,
        allow_unsafe=allow_unsafe,
        allow_debugger=allow_debugger,
        tool_surface=tool_surface,
        profile_path=profile_path,
    )

    startup_binary = args.input_path
    if startup_binary is None and config.server.default_input_path.strip():
        startup_binary = Path(config.server.default_input_path.strip())
    if startup_binary is not None:
        runtime.open_target(
            startup_binary.resolve(),
            context_id="startup" if isolated_contexts else None,
        )
        logger.info("已在启动阶段打开样本：{}", startup_binary)

    server = StdioMcpServer(
        tools=service.tools,
        resources=service.resources,
        prompts=service.prompts,
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
