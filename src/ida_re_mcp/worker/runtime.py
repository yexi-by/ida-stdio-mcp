"""worker 子进程运行时探测与 headless 服务入口。"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import os
import platform
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

from ida_re_mcp.worker._ida import require_ida
from ida_re_mcp.worker.errors import CapabilityError, WorkerError, WorkerInputError
from ida_re_mcp.worker.ipc import IpcEndpoint, WorkerHandler, serve_worker


def probe_runtime() -> dict[str, object]:
    """在候选 worker 解释器中探测 IDA 9.3、Python 3.13 与核心能力。"""

    result: dict[str, object] = {
        "available": False,
        "python": platform.python_version(),
        "python_ok": sys.version_info[:2] == (3, 13),
        "implementation": platform.python_implementation(),
    }
    try:
        importlib.import_module("idapro")
        api = require_ida(
            "ida_dbg",
            "ida_hexrays",
            "ida_ida",
            "ida_idd",
            "ida_kernwin",
            "ida_loader",
        )
        kernel_version = str(api.ida_kernwin.get_kernel_version())
        version_parts = tuple(int(part) for part in kernel_version.split(".")[:2])
        result.update(
            {
                "ida_kernel_version": kernel_version,
                "ida_ok": version_parts >= (9, 3),
                "headless": not bool(api.ida_kernwin.is_idaq()),
                "idb_path": str(api.ida_loader.get_path(api.ida_loader.PATH_TYPE_IDB)),
                "hexrays_available": bool(api.ida_hexrays.init_hexrays_plugin()),
                "debugger_api_available": True,
            }
        )
        result["available"] = (
            bool(result["python_ok"]) and bool(result["ida_ok"]) and bool(result["headless"])
        )
    except CapabilityError as exc:
        result["error"] = exc.as_dict()
    except Exception as exc:
        result["error"] = {
            "code": "runtime_probe_failed",
            "message": "IDA worker 运行时探测失败",
            "details": {"exception_type": type(exc).__name__},
        }
    return result


class _MutationHandler:
    def __init__(self) -> None:
        from ida_re_mcp.worker.mutation import MutationWorker
        from ida_re_mcp.worker.refine import RefineWorker

        self._worker = MutationWorker()
        self._refine_worker = RefineWorker()

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        if operation == "analysis.refine":
            return self._refine_worker.execute(operation, input)
        if operation != "mutation.apply":
            raise WorkerInputError("mutation worker 只接受 mutation.apply 或 analysis.refine")
        staging = input.get("staging_path")
        raw_operations = input.get("operations")
        if not isinstance(staging, str):
            raise WorkerInputError("staging_path 必须是字符串")
        if not isinstance(raw_operations, list):
            raise WorkerInputError("operations 必须是对象数组")
        candidates = cast(list[object], raw_operations)
        if any(not isinstance(item, Mapping) for item in candidates):
            raise WorkerInputError("operations 必须是对象数组")
        operations = cast(list[Mapping[str, object]], candidates)
        return self._worker.apply(Path(staging), operations)


class _IdaPro(Protocol):
    def open_database(
        self,
        file_name: str,
        run_auto_analysis: bool,
        args: str | None = None,
        enable_history: bool = False,
    ) -> int: ...

    def close_database(self, save: bool = True) -> None: ...


def _build_handler(arguments: argparse.Namespace) -> object:
    kind = cast(str, arguments.kind)
    checkout_value = cast(str | None, arguments.checkout)
    if kind == "bootstrap":
        from ida_re_mcp.worker.bootstrap import BootstrapWorker

        sample = cast(str | None, arguments.sample)
        if sample is None:
            raise WorkerInputError("bootstrap worker 需要 --sample")
        return BootstrapWorker(Path(sample))
    if checkout_value is None:
        raise WorkerInputError(f"{kind} worker 需要 --checkout")
    checkout = Path(checkout_value)
    if kind == "analysis":
        from ida_re_mcp.worker.analysis import AnalysisWorker

        return AnalysisWorker(checkout, revision=cast(str | None, arguments.revision))
    if kind == "mutation":
        return _MutationHandler()
    if kind == "expert":
        from ida_re_mcp.worker.expert import ExpertWorker

        return ExpertWorker()
    if kind == "debug":
        from ida_re_mcp.worker.debug import DebugWorker

        sample = cast(str | None, arguments.sample)
        if sample is None:
            raise WorkerInputError("debug worker 需要 --sample")
        return DebugWorker(
            checkout,
            Path(sample),
            allow_attach=bool(arguments.allow_attach),
        )
    raise AssertionError(kind)


def _serve(arguments: argparse.Namespace) -> int:
    secret_name = cast(str, arguments.authkey_env)
    encoded_secret = os.environ.pop(secret_name, None)
    if encoded_secret is None:
        raise WorkerError("ipc_auth_missing", "worker 认证密钥环境变量不存在")
    try:
        authkey = base64.b64decode(encoded_secret, validate=True)
    except ValueError as exc:
        raise WorkerError("ipc_auth_invalid", "worker 认证密钥不是有效 Base64") from exc
    if len(authkey) != 32:
        raise WorkerError("ipc_auth_invalid", "worker 认证密钥必须是 32 字节")
    endpoint = IpcEndpoint(
        cast(str, arguments.family),
        cast(str, arguments.address),
        authkey,
    )
    idapro = cast(_IdaPro, importlib.import_module("idapro"))
    kind = cast(str, arguments.kind)
    database_value = (
        cast(str | None, arguments.sample)
        if kind == "bootstrap"
        else cast(str | None, arguments.checkout)
    )
    if database_value is None:
        raise WorkerInputError(f"{kind} worker 缺少数据库输入路径")
    run_auto_analysis = kind in {"bootstrap", "analysis", "mutation", "expert"}
    opened = False
    try:
        result = idapro.open_database(database_value, run_auto_analysis=run_auto_analysis)
        if result != 0:
            raise WorkerError(
                "ida_open_failed",
                "IDALib 无法打开 worker 数据库输入",
                details={"ida_result": result, "kind": kind},
            )
        opened = True
        handler = _build_handler(arguments)
        serve_worker(endpoint, cast(WorkerHandler, handler))
        return 0
    finally:
        if opened:
            idapro.close_database(save=False)


def main(argv: Sequence[str] | None = None) -> int:
    """worker 子进程命令入口。"""

    parser = argparse.ArgumentParser(prog="python -m ida_re_mcp.worker")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("probe")
    serve = subparsers.add_parser("serve")
    serve.add_argument(
        "--kind",
        choices=("bootstrap", "analysis", "mutation", "debug", "expert"),
        required=True,
    )
    serve.add_argument("--family", choices=("AF_PIPE", "AF_UNIX"), required=True)
    serve.add_argument("--address", required=True)
    serve.add_argument("--authkey-env", required=True)
    serve.add_argument("--checkout")
    serve.add_argument("--revision")
    serve.add_argument("--sample")
    serve.add_argument("--allow-attach", action="store_true")
    arguments = parser.parse_args(list(argv) if argv is not None else None)
    if arguments.command == "probe":
        sys.stdout.write(
            json.dumps(
                probe_runtime(),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 0
    return _serve(arguments)
