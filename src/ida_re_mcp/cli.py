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

from ida_re_mcp.constants import PRODUCT_NAME
from ida_re_mcp.domain.base import JsonObject
from ida_re_mcp.protocol.stdio import LineProtocol, serve_stdio

type CommandName = Literal["serve", "doctor", "gc"]


class ApplicationLike(Protocol):
    """CLI 与 Supervisor 应用对象之间的窄接口。"""

    @property
    def protocol(self) -> LineProtocol: ...

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
        description="IDA Pro 9.3+ headless 逆向工程 MCP 服务",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="通过 current-only stdio 提供 MCP 服务")
    serve.add_argument("--config", type=Path, help="当前 schema 的 TOML 配置")
    serve.set_defaults(apply=False)

    doctor = subcommands.add_parser("doctor", help="检查运行目录与 IDA worker")
    doctor.add_argument("--config", type=Path, help="当前 schema 的 TOML 配置")
    doctor.set_defaults(apply=False)

    gc = subcommands.add_parser("gc", help="检查或执行不可变数据回收")
    gc.add_argument("--config", type=Path, help="当前 schema 的 TOML 配置")
    mode = gc.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_false", dest="apply", help="只报告可回收数据")
    mode.add_argument("--apply", action="store_true", dest="apply", help="执行安全回收")
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


async def _run(
    arguments: _Arguments,
    *,
    application_factory: ApplicationFactory,
    stdin: BinaryIO,
    stdout: BinaryIO,
    stderr: TextIO,
) -> int:
    application = application_factory(arguments.config_path)
    try:
        if arguments.command == "serve":
            await serve_stdio(
                application.protocol,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
            )
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
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """解析命令并在单一 asyncio 生命周期内运行 Application。"""

    arguments = _parse_args(argv)
    binary_stdin = stdin if stdin is not None else cast(BinaryIO, sys.stdin.buffer)
    binary_stdout = stdout if stdout is not None else cast(BinaryIO, sys.stdout.buffer)
    text_stderr = stderr if stderr is not None else sys.stderr
    try:
        return asyncio.run(
            _run(
                arguments,
                application_factory=application_factory,
                stdin=binary_stdin,
                stdout=binary_stdout,
                stderr=text_stderr,
            )
        )
    except KeyboardInterrupt:
        text_stderr.write(f"{PRODUCT_NAME}: 已中断\n")
        text_stderr.flush()
        return 130
    except Exception as exc:
        detail = str(exc).replace("\r", " ").replace("\n", " ")[:2_048]
        text_stderr.write(f"{PRODUCT_NAME}: {type(exc).__name__}: {detail}\n")
        text_stderr.flush()
        return 1
