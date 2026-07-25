# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""Windows x64 headless debugger 的终态、取消与强清理门禁。"""

from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
import threading
import time
import uuid
from ctypes import WinDLL
from ctypes.wintypes import BOOL, DWORD, HANDLE
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import Protocol, cast

import pytest

from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.ipc import IpcEndpoint, JsonObject, JsonValue, WorkerClient

_SYNCHRONIZE = 0x00100000
_PROCESS_TERMINATE = 0x0001
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x00000102


class _Kernel32(Protocol):
    def OpenProcess(self, access: int, inherit: bool, pid: int) -> HANDLE: ...

    def WaitForSingleObject(self, handle: HANDLE, milliseconds: int) -> int: ...

    def TerminateProcess(self, handle: HANDLE, exit_code: int) -> bool: ...

    def CloseHandle(self, handle: HANDLE) -> bool: ...


@dataclass(slots=True)
class _RunningWorker:
    process: subprocess.Popen[bytes]
    client: WorkerClient

    def close(self) -> None:
        self.client.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
            pytest.fail("worker 在 IPC 关闭后未退出")
        stdout = self.process.stdout.read() if self.process.stdout else b""
        if stdout:
            pytest.fail(f"worker stdout 被非协议内容污染: {stdout[:256]!r}")
        if self.process.returncode != 0:
            stderr = (self.process.stderr.read() if self.process.stderr else b"").decode(
                "utf-8",
                errors="replace",
            )
            pytest.fail(f"worker 异常退出: {stderr}")


def _start_worker(
    tmp_path: Path,
    environment: dict[str, str],
    kind: str,
    *,
    checkout: Path | None = None,
    sample: Path | None = None,
    allow_attach: bool = False,
) -> _RunningWorker:
    endpoint = IpcEndpoint.create(tmp_path)
    secret_name = f"IDA_RE_MCP_TEST_AUTH_{uuid.uuid4().hex.upper()}"
    child_environment = environment.copy()
    child_environment[secret_name] = base64.b64encode(endpoint.authkey).decode("ascii")
    command = [
        sys.executable,
        "-m",
        "ida_re_mcp.worker",
        "serve",
        "--kind",
        kind,
        "--family",
        endpoint.family,
        "--address",
        endpoint.address,
        "--authkey-env",
        secret_name,
    ]
    if checkout is not None:
        command.extend(("--checkout", str(checkout)))
    if sample is not None:
        command.extend(("--sample", str(sample)))
    if allow_attach:
        command.append("--allow-attach")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    client = WorkerClient(endpoint)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = (process.stderr.read() if process.stderr else b"").decode(
                "utf-8",
                errors="replace",
            )
            pytest.fail(f"worker 启动失败: {stderr}")
        try:
            client.connect()
            return _RunningWorker(process, client)
        except (OSError, EOFError):
            time.sleep(0.05)
    process.terminate()
    process.wait(timeout=10)
    pytest.fail("worker IPC 在 60 秒内未就绪")


def _bootstrap(
    tmp_path: Path,
    environment: dict[str, str],
    sample: Path,
) -> Path:
    checkout = tmp_path / f"{uuid.uuid4().hex}.i64"
    worker = _start_worker(tmp_path, environment, "bootstrap", sample=sample)
    try:
        result = worker.client.execute(
            "workspace.bootstrap",
            {"staging_path": str(checkout)},
        )
        assert result["saved"] is True
        assert result["input_sha256"] == _sha256(sample)
    finally:
        worker.close()
    return checkout


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _object(value: JsonValue, label: str) -> JsonObject:
    if not isinstance(value, dict):
        pytest.fail(f"{label} 不是 JSON 对象")
    return cast(JsonObject, value)


def _events_until(
    worker: _RunningWorker,
    cursor: int,
    kind: str,
    *,
    timeout_seconds: float = 30,
) -> tuple[JsonObject, JsonObject]:
    deadline = time.monotonic() + timeout_seconds
    latest = cursor
    while time.monotonic() < deadline:
        result = worker.client.execute(
            "debug.events",
            {"after_sequence": latest, "limit": 100, "wait_ms": 2_000},
        )
        latest_value = result["latest_sequence"]
        assert isinstance(latest_value, int)
        latest = latest_value
        raw_events = result["events"]
        assert isinstance(raw_events, list)
        for raw_event in raw_events:
            event = _object(raw_event, "debug event")
            if event.get("kind") == kind:
                return result, event
    pytest.fail(f"未在 {timeout_seconds} 秒内观察到 {kind}")


def _kernel32() -> _Kernel32:
    kernel32 = WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    kernel32.OpenProcess.restype = HANDLE
    kernel32.WaitForSingleObject.argtypes = [HANDLE, DWORD]
    kernel32.WaitForSingleObject.restype = DWORD
    kernel32.TerminateProcess.argtypes = [HANDLE, DWORD]
    kernel32.TerminateProcess.restype = BOOL
    kernel32.CloseHandle.argtypes = [HANDLE]
    kernel32.CloseHandle.restype = BOOL
    return cast(_Kernel32, kernel32)


def _pid_is_running(pid: int) -> bool:
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(_SYNCHRONIZE, False, pid)
    if not handle:
        return False
    try:
        result = int(kernel32.WaitForSingleObject(handle, 0))
        if result == _WAIT_TIMEOUT:
            return True
        if result == _WAIT_OBJECT_0:
            return False
        pytest.fail(f"WaitForSingleObject 返回未知状态: {result}")
    finally:
        kernel32.CloseHandle(handle)


def _wait_pid_exit(pid: int, timeout_seconds: float = 10) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _pid_is_running(pid):
            return
        time.sleep(0.05)
    pytest.fail(f"PID {pid} 未在 {timeout_seconds} 秒内退出")


def _terminate_pid(pid: int) -> None:
    kernel32 = _kernel32()
    handle = kernel32.OpenProcess(_PROCESS_TERMINATE | _SYNCHRONIZE, False, pid)
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 0xDE)
        kernel32.WaitForSingleObject(handle, 5_000)
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.ida
@pytest.mark.debugger
def test_module_rva_breakpoint_and_invalid_memory_are_real(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    sample = fixture_directory / "debug_target_x64.exe"
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    worker = _start_worker(
        tmp_path,
        ida_environment,
        "debug",
        checkout=checkout,
        sample=sample,
    )
    try:
        established = worker.client.execute(
            "debug.establish",
            {
                "mode": "launch",
                "target": str(sample),
                "arguments": [],
                "stop_on_entry": True,
                "timeout_ms": 30_000,
            },
        )
        stop_id = established["stop_id"]
        assert isinstance(stop_id, str)
        modules = worker.client.execute(
            "debug.inspect",
            {"view": "modules", "stop_id": stop_id},
        )
        raw_modules = modules["modules"]
        assert isinstance(raw_modules, list)
        target_modules = [
            _object(value, "module")
            for value in raw_modules
            if Path(str(_object(value, "module").get("name"))).name.casefold()
            == sample.name.casefold()
        ]
        assert len(target_modules) == 1
        module = target_modules[0]
        base = int(str(module["base"]), 16)
        assert base != 0x140000000
        size = module["size"]
        assert isinstance(size, int)

        added = worker.client.execute(
            "debug.breakpoints",
            {
                "action": "add",
                "location": {"module": sample.name, "rva": "0x1000"},
            },
        )
        breakpoint = _object(added["breakpoint"], "breakpoint")
        runtime_address = breakpoint["runtime_address"]
        assert runtime_address == f"0x{base + 0x1000:x}"
        assert breakpoint["active"] is True

        control = worker.client.execute(
            "debug.control",
            {
                "action": "continue",
                "stop_id": stop_id,
                "timeout_ms": 30_000,
            },
        )
        cursor = control["latest_sequence"]
        assert isinstance(cursor, int)
        stopped, event = _events_until(worker, cursor, "breakpoint")
        payload = _object(event["payload"], "breakpoint payload")
        assert payload["breakpoint_address"] == runtime_address
        hit_stop_id = stopped["stop_id"]
        assert isinstance(hit_stop_id, str)
        assert hit_stop_id != stop_id

        with pytest.raises(WorkerError) as stale:
            worker.client.execute(
                "debug.inspect",
                {"view": "registers", "stop_id": stop_id, "registers": ["RIP"]},
            )
        assert stale.value.code == "debug_state_conflict"

        with pytest.raises(WorkerError) as invalid_memory:
            worker.client.execute(
                "debug.inspect",
                {
                    "view": "memory",
                    "stop_id": hit_stop_id,
                    "address": {
                        "space": "runtime",
                        "module": sample.name,
                        "va": f"0x{base + size - 1:x}",
                        "stop_id": hit_stop_id,
                    },
                    "size": 2,
                },
            )
        assert invalid_memory.value.code == "address_unmapped"
        worker.client.execute(
            "debug.finish",
            {"action": "terminate", "timeout_ms": 30_000},
        )
    finally:
        worker.close()


@pytest.mark.ida
@pytest.mark.debugger
def test_natural_exit_is_observed_and_finish_is_idempotent(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    sample = fixture_directory / "debug_target_x64.exe"
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    worker = _start_worker(
        tmp_path,
        ida_environment,
        "debug",
        checkout=checkout,
        sample=sample,
    )
    try:
        established = worker.client.execute(
            "debug.establish",
            {
                "mode": "launch",
                "target": str(sample),
                "arguments": [],
                "stop_on_entry": True,
                "timeout_ms": 30_000,
            },
        )
        stop_id = established["stop_id"]
        assert isinstance(stop_id, str)
        control = worker.client.execute(
            "debug.control",
            {
                "action": "continue",
                "stop_id": stop_id,
                "timeout_ms": 30_000,
            },
        )
        cursor = control["latest_sequence"]
        assert isinstance(cursor, int)
        exited, event = _events_until(worker, cursor, "process_exited")
        assert exited["state"] == "exited"
        assert exited["stop_id"] is None
        payload = _object(event["payload"], "exit payload")
        assert payload["exit_code"] == 53

        finished = worker.client.execute(
            "debug.finish",
            {"action": "terminate", "timeout_ms": 30_000},
        )
        assert finished["state"] == "exited"
        assert finished["latest_sequence"] == exited["latest_sequence"]
    finally:
        worker.close()


@pytest.mark.ida
@pytest.mark.debugger
def test_attach_control_cancel_pause_and_detach_preserve_target(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    sample = fixture_directory / "debug_target_x64.exe"
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    target = subprocess.Popen(
        [str(sample), "--ida-re-hold"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    worker = _start_worker(
        tmp_path,
        ida_environment,
        "debug",
        checkout=checkout,
        sample=sample,
        allow_attach=True,
    )
    try:
        established = worker.client.execute(
            "debug.establish",
            {"mode": "attach", "pid": target.pid, "timeout_ms": 30_000},
        )
        assert established["state"] == "suspended"
        stop_id = established["stop_id"]
        assert isinstance(stop_id, str)

        request_id = f"cancel_{uuid.uuid4().hex}"
        outcomes: Queue[JsonObject | BaseException] = Queue(maxsize=1)

        def run_to_unreachable_address() -> None:
            try:
                outcomes.put(
                    worker.client.execute(
                        "debug.control",
                        {
                            "action": "run_to",
                            "stop_id": stop_id,
                            "address": {
                                "space": "runtime_module",
                                "module": sample.name,
                                "rva": "0x1040",
                            },
                            "timeout_ms": 30_000,
                        },
                        request_id=request_id,
                    )
                )
            except BaseException as exc:
                outcomes.put(exc)

        caller = threading.Thread(target=run_to_unreachable_address, daemon=True)
        caller.start()
        time.sleep(0.5)
        worker.client.cancel(request_id)
        caller.join(10)
        assert not caller.is_alive()
        cancelled = outcomes.get_nowait()
        if isinstance(cancelled, BaseException):
            raise cancelled
        assert cancelled["cancelled"] is True
        assert cancelled["state"] == "suspended"
        cancelled_stop_id = cancelled["stop_id"]
        assert isinstance(cancelled_stop_id, str)
        assert cancelled_stop_id != stop_id
        cancelled_event = _object(cancelled["event"], "cancelled control event")
        assert cancelled_event["kind"] == "process_suspended"

        continued = worker.client.execute(
            "debug.control",
            {
                "action": "continue",
                "stop_id": cancelled_stop_id,
                "timeout_ms": 30_000,
            },
        )
        assert continued["state"] == "running"

        paused = worker.client.execute(
            "debug.control",
            {"action": "pause", "timeout_ms": 30_000},
        )
        assert paused["state"] == "suspended"
        paused_stop_id = paused["stop_id"]
        assert isinstance(paused_stop_id, str)
        assert paused_stop_id != cancelled_stop_id
        paused_event = _object(paused["event"], "pause event")
        assert paused_event["kind"] == "process_suspended"

        detached = worker.client.execute(
            "debug.finish",
            {"action": "detach", "timeout_ms": 30_000},
        )
        assert detached["state"] == "detached"
        assert target.poll() is None
    finally:
        worker.close()
        if target.poll() is None:
            target.terminate()
            target.wait(timeout=5)


@pytest.mark.ida
@pytest.mark.debugger
def test_invalid_pid_and_worker_crash_cleanup(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    sample = fixture_directory / "debug_target_x64.exe"
    invalid_checkout = _bootstrap(tmp_path, ida_environment, sample)
    invalid_worker = _start_worker(
        tmp_path,
        ida_environment,
        "debug",
        checkout=invalid_checkout,
        sample=sample,
        allow_attach=True,
    )
    try:
        with pytest.raises(WorkerError) as invalid_pid:
            invalid_worker.client.execute(
                "debug.establish",
                {"mode": "attach", "pid": 0x7FFF_FFFF, "timeout_ms": 5_000},
            )
        assert invalid_pid.value.code == "debug_attach_failed"
    finally:
        invalid_worker.close()

    crash_checkout = _bootstrap(tmp_path, ida_environment, sample)
    crash_worker = _start_worker(
        tmp_path,
        ida_environment,
        "debug",
        checkout=crash_checkout,
        sample=sample,
    )
    target_pid: int | None = None
    try:
        established = crash_worker.client.execute(
            "debug.establish",
            {
                "mode": "launch",
                "target": str(sample),
                "arguments": [],
                "stop_on_entry": True,
                "timeout_ms": 30_000,
            },
        )
        owned_pid = established["owned_pid"]
        assert isinstance(owned_pid, int)
        target_pid = owned_pid
        assert _pid_is_running(target_pid)

        crash_worker.process.kill()
        crash_worker.process.wait(timeout=10)
        _wait_pid_exit(target_pid)
    finally:
        crash_worker.client.close()
        if crash_worker.process.poll() is None:
            crash_worker.process.kill()
            crash_worker.process.wait(timeout=5)
        if target_pid is not None and _pid_is_running(target_pid):
            _terminate_pid(target_pid)
