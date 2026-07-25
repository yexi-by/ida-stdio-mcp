import ast
import base64
import os
import subprocess
import sys
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from ida_re_mcp.supervisor.workers import (
    ProcessHandle,
    ProcessLaunch,
    WorkerKind,
    WorkerProcess,
    WorkerProcessError,
)
from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.ipc import IpcEndpoint, JsonObject, JsonValue


class _Process:
    pid = 4242

    def __init__(self, *, exit_code: int | None = None) -> None:
        self.exit_code = exit_code
        self.actions: list[str] = []

    def poll(self) -> int | None:
        return self.exit_code

    def wait(self, timeout: float | None = None) -> int:
        self.actions.append("wait")
        self.exit_code = 0 if self.exit_code is None else self.exit_code
        return self.exit_code

    def terminate(self) -> None:
        self.actions.append("terminate")
        self.exit_code = -15

    def kill(self) -> None:
        self.actions.append("kill")
        self.exit_code = -9


class _EscalatingProcess(_Process):
    def wait(self, timeout: float | None = None) -> int:
        self.actions.append("wait")
        if self.exit_code is None:
            raise subprocess.TimeoutExpired("worker", timeout or 0.0)
        return self.exit_code

    def terminate(self) -> None:
        self.actions.append("terminate")


class _Client:
    def __init__(self, *, connect_failures: int = 0) -> None:
        self.connect_failures = connect_failures
        self.connect_calls = 0
        self.close_calls = 0
        self.execute_calls = 0
        self.cancelled: list[str] = []
        self.events: list[str] = []

    def connect(self) -> None:
        self.events.append("connect")
        self.connect_calls += 1
        if self.connect_calls <= self.connect_failures:
            raise FileNotFoundError("pipe is not ready")

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        self.execute_calls += 1
        return {
            "call": self.execute_calls,
            "operation": operation,
            "request_id": request_id,
        }

    def cancel(self, request_id: str) -> None:
        self.cancelled.append(request_id)

    def close(self) -> None:
        self.events.append("client.close")
        self.close_calls += 1


class _BlockingClient(_Client):
    def __init__(self) -> None:
        super().__init__()
        self.released = threading.Event()

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        self.released.wait(timeout=5)
        raise WorkerError("ipc_disconnected", "connection closed")

    def close(self) -> None:
        super().close()
        self.released.set()


class _CrashedClient(_Client):
    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        raise WorkerError("ipc_disconnected", "connection lost")


class _Launcher:
    def __init__(self, process: ProcessHandle) -> None:
        self.process = process
        self.launches: list[ProcessLaunch] = []

    def __call__(
        self,
        launch: ProcessLaunch,
        *,
        stdout: BinaryIO,
        stderr: BinaryIO,
    ) -> ProcessHandle:
        self.launches.append(
            ProcessLaunch(
                command=launch.command,
                environment=dict(launch.environment),
                working_directory=launch.working_directory,
                creation_flags=launch.creation_flags,
            )
        )
        stdout.write(b"worker stdout\n")
        stderr.write(b"worker stderr\n")
        return self.process


def _endpoint(_directory: Path) -> IpcEndpoint:
    return IpcEndpoint("AF_PIPE", r"\\.\pipe\ida-re-mcp-test", b"k" * 32)


def _files(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    checkout = tmp_path / "data" / "database.i64"
    sample = tmp_path / "data" / "sample.exe"
    checkout.parent.mkdir()
    checkout.write_bytes(b"idb")
    sample.write_bytes(b"sample")
    working_tree = tmp_path / "repo"
    (working_tree / ".git").mkdir(parents=True)
    log_root = tmp_path / "logs"
    return checkout, sample, working_tree, log_root


def _launch(
    tmp_path: Path,
    *,
    kind: str = "analysis",
    process: ProcessHandle | None = None,
    client: _Client | None = None,
    environment: Mapping[str, str] | None = None,
) -> tuple[WorkerProcess, _Launcher, _Client]:
    checkout, sample, working_tree, log_root = _files(tmp_path)
    actual_process = process or _Process()
    actual_client = client or _Client()
    launcher = _Launcher(actual_process)
    kind_value = cast(WorkerKind, kind)
    if kind == "bootstrap":
        worker = WorkerProcess.launch(
            kind=kind_value,
            log_root=log_root,
            sample=sample,
            working_tree=working_tree,
            process_launcher=launcher,
            endpoint_factory=_endpoint,
            client_factory=lambda _endpoint_value: actual_client,
            sleeper=lambda _seconds: None,
            environment=environment,
        )
    elif kind == "debug":
        worker = WorkerProcess.launch(
            kind=kind_value,
            log_root=log_root,
            checkout=checkout,
            sample=sample,
            working_tree=working_tree,
            process_launcher=launcher,
            endpoint_factory=_endpoint,
            client_factory=lambda _endpoint_value: actual_client,
            sleeper=lambda _seconds: None,
            environment=environment,
        )
    else:
        worker = WorkerProcess.launch(
            kind=kind_value,
            log_root=log_root,
            checkout=checkout,
            working_tree=working_tree,
            process_launcher=launcher,
            endpoint_factory=_endpoint,
            client_factory=lambda _endpoint_value: actual_client,
            sleeper=lambda _seconds: None,
            environment=environment,
        )
    return worker, launcher, actual_client


@pytest.mark.parametrize("kind", ["bootstrap", "analysis", "mutation", "debug", "expert"])
def test_launch_uses_exact_current_worker_arguments_and_environment_auth(
    tmp_path: Path,
    kind: str,
) -> None:
    worker, launcher, _ = _launch(tmp_path, kind=kind)
    launch = launcher.launches[0]
    command = launch.command

    assert command[:4] == (sys.executable, "-m", "ida_re_mcp.worker", "serve")
    assert command[command.index("--kind") + 1] == kind
    auth_name = command[command.index("--authkey-env") + 1]
    assert auth_name.startswith("IDA_RE_MCP_WORKER_AUTH_")
    assert auth_name not in os.environ
    assert launch.environment[auth_name] == base64.b64encode(b"k" * 32).decode("ascii")
    assert launch.environment[auth_name] not in command

    if kind == "bootstrap":
        assert "--sample" in command
        assert "--checkout" not in command
    elif kind == "debug":
        assert "--sample" in command
        assert "--checkout" in command
    else:
        assert "--checkout" in command
        assert "--sample" not in command

    stdout_path = worker.stdout_log_path
    stderr_path = worker.stderr_log_path
    worker.close()
    assert stdout_path.read_bytes() == b"worker stdout\n"
    assert stderr_path.read_bytes() == b"worker stderr\n"
    assert stdout_path.parent == launch.working_directory
    assert stderr_path.parent == launch.working_directory


def test_connect_retries_without_restarting_process(tmp_path: Path) -> None:
    client = _Client(connect_failures=2)

    worker, launcher, actual_client = _launch(tmp_path, client=client)

    assert actual_client.connect_calls == 3
    assert len(launcher.launches) == 1
    worker.close()


def test_launch_applies_server_config_environment_to_worker(tmp_path: Path) -> None:
    worker, launcher, _ = _launch(
        tmp_path,
        environment={"IDADIR": "C:/Program Files/IDA Professional 9.3"},
    )

    assert launcher.launches[0].environment["IDADIR"] == ("C:/Program Files/IDA Professional 9.3")
    worker.close()


def test_connect_timeout_terminates_worker_and_maps_stable_code(tmp_path: Path) -> None:
    checkout, _, working_tree, log_root = _files(tmp_path)
    process = _Process()
    client = _Client(connect_failures=100)
    times = iter((0.0, 1.0))

    with pytest.raises(WorkerProcessError) as raised:
        WorkerProcess.launch(
            kind="analysis",
            checkout=checkout,
            log_root=log_root,
            working_tree=working_tree,
            connect_timeout_seconds=0.1,
            process_launcher=_Launcher(process),
            endpoint_factory=_endpoint,
            client_factory=lambda _endpoint_value: client,
            monotonic=lambda: next(times),
            sleeper=lambda _seconds: None,
        )

    assert raised.value.code == "worker_timeout"
    assert raised.value.details["reason"] == "FileNotFoundError"
    assert "terminate" in process.actions
    assert client.close_calls >= 1


def test_early_process_exit_maps_to_worker_crashed(tmp_path: Path) -> None:
    process = _Process(exit_code=17)
    client = _Client()

    with pytest.raises(WorkerProcessError) as raised:
        _launch(tmp_path, process=process, client=client)

    assert raised.value.code == "worker_crashed"
    assert raised.value.details["exit_code"] == 17
    assert client.close_calls >= 1


def test_operation_timeout_closes_ipc_and_terminates_worker(tmp_path: Path) -> None:
    process = _Process()
    client = _BlockingClient()
    worker, _, _ = _launch(tmp_path, process=process, client=client)

    with pytest.raises(WorkerProcessError) as raised:
        worker.execute("debug.control", {}, timeout_seconds=0.01)

    assert raised.value.code == "worker_timeout"
    assert worker.closed
    assert client.close_calls >= 1
    assert "terminate" in process.actions


def test_expert_timeout_uses_process_termination(tmp_path: Path) -> None:
    process = _Process()
    client = _BlockingClient()
    worker, _, _ = _launch(
        tmp_path,
        kind="expert",
        process=process,
        client=client,
    )

    with pytest.raises(WorkerProcessError) as raised:
        worker.execute(
            "expert.execute",
            {"staging_path": "unused", "code": "while True: pass"},
            timeout_seconds=0.01,
        )

    assert raised.value.code == "worker_timeout"
    assert worker.closed
    assert client.close_calls >= 1
    assert "terminate" in process.actions


def test_ipc_disconnect_maps_to_worker_crashed(tmp_path: Path) -> None:
    worker, _, _ = _launch(tmp_path, client=_CrashedClient())

    with pytest.raises(WorkerProcessError) as raised:
        worker.execute("program.overview", {})

    assert raised.value.code == "worker_crashed"
    assert worker.closed


def test_debug_worker_is_persistent_across_multiple_execute_calls(tmp_path: Path) -> None:
    worker, _, client = _launch(tmp_path, kind="debug")

    first = worker.execute("debug.events", {}, request_id="one")
    second = worker.execute("debug.inspect", {}, request_id="two")

    assert first["call"] == 1
    assert second["call"] == 2
    assert client.execute_calls == 2
    assert not worker.closed
    worker.close()


def test_close_sends_eof_before_terminate_and_kill(tmp_path: Path) -> None:
    process = _EscalatingProcess()
    client = _Client()
    worker, _, _ = _launch(tmp_path, process=process, client=client)

    worker.close()

    assert client.events[-1] == "client.close"
    assert process.actions == ["wait", "terminate", "wait", "kill", "wait"]


def test_log_root_inside_working_tree_is_rejected(tmp_path: Path) -> None:
    sample = tmp_path / "repo" / "sample.exe"
    (sample.parent / ".git").mkdir(parents=True)
    sample.write_bytes(b"sample")

    with pytest.raises(ValueError, match="日志目录不得位于工作树"):
        WorkerProcess.launch(
            kind="bootstrap",
            sample=sample,
            log_root=sample.parent / "logs",
            working_tree=sample.parent,
            process_launcher=_Launcher(_Process()),
            endpoint_factory=_endpoint,
            client_factory=lambda _endpoint_value: _Client(),
        )


def test_supervisor_worker_module_has_no_ida_runtime_import() -> None:
    source_path = Path(__file__).parents[2] / "src" / "ida_re_mcp" / "supervisor" / "workers.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.append(node.module)

    forbidden = [
        name
        for name in imported
        if name == "idapro" or (name.startswith("ida_") and not name.startswith("ida_re_mcp"))
    ]
    assert forbidden == []
