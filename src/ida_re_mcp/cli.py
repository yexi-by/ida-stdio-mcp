"""ida-re-mcp 的最小命令行入口。"""

import argparse
import asyncio
import importlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal, Protocol, TextIO, cast

from ida_re_mcp.config import ConfigError, RuntimePathError
from ida_re_mcp.constants import PRODUCT_NAME
from ida_re_mcp.domain.base import JsonObject
from ida_re_mcp.supervisor.errors import SupervisorAlreadyRunningError

type CommandName = Literal["serve", "doctor", "gc"]


class ApplicationLike(Protocol):
    """CLI 与 Supervisor 应用对象之间的窄接口。"""

    async def serve(self) -> None: ...

    async def doctor(self) -> tuple[bool, JsonObject]: ...

    async def gc(self, *, apply: bool) -> JsonObject: ...

    async def aclose(self) -> None: ...


class ApplicationFactory(Protocol):
    def __call__(self, config_path: Path | None) -> ApplicationLike: ...


class _ApplicationType(Protocol):
    def open(self, config_path: Path | None) -> ApplicationLike: ...


@dataclass(frozen=True, slots=True)
class _Arguments:
    command: CommandName
    config_path: Path | None
    apply: bool


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PRODUCT_NAME,
        description="让 Codex 等 AI Agent 使用 IDA Pro 9.3+ 分析和修改程序",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="启动 MCP 服务，供 Agent 使用")
    serve.add_argument(
        "--config",
        type=Path,
        help="要读取的配置文件；本项目通常使用 config.toml",
    )
    serve.set_defaults(apply=False)

    doctor = subcommands.add_parser(
        "doctor",
        help="检查配置、数据目录、日志目录和 IDA 是否可以正常使用",
    )
    doctor.add_argument(
        "--config",
        type=Path,
        help="要读取的配置文件；本项目通常使用 config.toml",
    )
    doctor.set_defaults(apply=False)

    gc = subcommands.add_parser("gc", help="查看或清理不再使用的分析数据")
    gc.add_argument(
        "--config",
        type=Path,
        help="要读取的配置文件；本项目通常使用 config.toml",
    )
    mode = gc.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_false",
        dest="apply",
        help="只列出可以清理的数据，不删除文件",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        dest="apply",
        help="删除已经确认可以清理的数据",
    )
    return parser


def _parse_args(argv: Sequence[str] | None) -> _Arguments:
    namespace = _parser().parse_args(argv)
    command = cast(CommandName, namespace.command)
    config_path = cast(Path | None, namespace.config)
    apply = cast(bool, namespace.apply)
    return _Arguments(command=command, config_path=config_path, apply=apply)


def _default_application_factory(config_path: Path | None) -> ApplicationLike:
    module = importlib.import_module("ida_re_mcp.application")
    application_type = cast(_ApplicationType, module.Application)
    return application_type.open(config_path)


def _write_bytes(stream: BinaryIO, data: bytes) -> None:
    written = stream.write(data)
    if written != len(data):
        raise OSError(f"stdout 仅写入 {written}/{len(data)} 字节")
    stream.flush()


def _write_report(stream: BinaryIO, report: JsonObject) -> None:
    payload = (
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
    _write_bytes(stream, payload)


def _failure_message(error: Exception) -> str:
    """把命令行错误转换为不会泄漏内部实现细节的说明。"""

    if isinstance(error, (ConfigError, RuntimePathError)):
        detail = str(error).replace("\r", " ").replace("\n", " ")[:2_048]
        return f"配置无法使用：{detail}。请修改 config.toml 后重试。"
    if isinstance(error, SupervisorAlreadyRunningError):
        return "已有一个 ida-re-mcp 正在使用同一运行目录。请关闭重复启动的服务后重试。"
    return "命令没有完成。请先检查 config.toml；如果配置无误，请查看 logs 目录中的本次运行日志。"


async def _run(
    arguments: _Arguments,
    *,
    application_factory: ApplicationFactory,
    stdout: BinaryIO,
) -> int:
    application = application_factory(arguments.config_path)
    try:
        if arguments.command == "serve":
            await application.serve()
            return 0
        if arguments.command == "doctor":
            healthy, report = await application.doctor()
            _write_report(stdout, report)
            return 0 if healthy else 1
        report = await application.gc(apply=arguments.apply)
        _write_report(stdout, report)
        return 0
    finally:
        await application.aclose()


def main(
    argv: Sequence[str] | None = None,
    *,
    application_factory: ApplicationFactory = _default_application_factory,
    stdout: BinaryIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """解析命令并在单一 asyncio 生命周期内运行 Application。"""

    arguments = _parse_args(argv)
    binary_stdout = stdout if stdout is not None else cast(BinaryIO, sys.stdout.buffer)
    text_stderr = stderr if stderr is not None else sys.stderr
    try:
        return asyncio.run(
            _run(
                arguments,
                application_factory=application_factory,
                stdout=binary_stdout,
            )
        )
    except KeyboardInterrupt:
        text_stderr.write(f"{PRODUCT_NAME}：已中断\n")
        text_stderr.flush()
        return 130
    except Exception as exc:
        text_stderr.write(f"{PRODUCT_NAME}：{_failure_message(exc)}\n")
        text_stderr.flush()
        return 1
