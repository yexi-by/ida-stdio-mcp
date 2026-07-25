from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ida_re_mcp.application import Application
from ida_re_mcp.config import RuntimePaths
from ida_re_mcp.supervisor.errors import SupervisorAlreadyRunningError
from ida_re_mcp.supervisor.operations import OperationState

_OWNER_PROBE = """
import os
from pathlib import Path
import sys
import time

from ida_re_mcp.application import Application
from ida_re_mcp.config import RuntimePaths

paths = RuntimePaths(
    data_root=Path(sys.argv[2]),
    log_root=Path(sys.argv[3]),
    workspace_root=Path(sys.argv[4]),
    artifact_root=Path(sys.argv[5]),
    checkout_root=Path(sys.argv[6]),
    temp_root=Path(sys.argv[7]),
)
application = Application.open(Path(sys.argv[1]), paths=paths)
operation = application.storage.operations.create("ownership_probe")
application.storage.operations.start(operation.operation_id)
Path(sys.argv[8]).write_text(operation.operation_id, encoding="ascii")
crash = Path(sys.argv[9])
deadline = time.monotonic() + 30
while not crash.is_file():
    if time.monotonic() >= deadline:
        raise TimeoutError("owner probe crash marker timed out")
    time.sleep(0.01)
os._exit(91)
"""


def _runtime_paths(tmp_path: Path) -> RuntimePaths:
    data_root = tmp_path / "data"
    return RuntimePaths(
        data_root=data_root,
        log_root=tmp_path / "logs",
        workspace_root=data_root / "workspaces",
        artifact_root=data_root / "artifacts",
        checkout_root=data_root / "checkouts",
        temp_root=data_root / "temp",
    ).ensure()


def _start_owner(
    config_path: Path,
    paths: RuntimePaths,
    *,
    ready: Path,
    crash: Path,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _OWNER_PROBE,
            str(config_path),
            str(paths.data_root),
            str(paths.log_root),
            str(paths.workspace_root),
            str(paths.artifact_root),
            str(paths.checkout_root),
            str(paths.temp_root),
            str(ready),
            str(crash),
        ],
        cwd=Path(__file__).resolve().parents[2],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def _wait_for_ready(ready: Path, process: subprocess.Popen[str]) -> str:
    deadline = time.monotonic() + 10
    while not ready.is_file():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                "owner probe 在取得 lease 前退出: "
                f"code={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            pytest.fail("等待 owner probe 超时")
        time.sleep(0.01)
    return ready.read_text(encoding="ascii")


def _finish_process(process: subprocess.Popen[str], crash: Path) -> tuple[str, str]:
    crash.touch(exist_ok=True)
    try:
        return process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.communicate(timeout=5)


class _FailingAsyncLock:
    async def aclose(self) -> None:
        raise RuntimeError("injected cleanup failure")


def test_application_aclose_releases_owner_lease_after_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _runtime_paths(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "2026-07-28"\n', encoding="utf-8")
    first = Application.open(config_path, paths=paths)
    monkeypatch.setattr(
        first,
        "_workspace_locks",
        {"injected": _FailingAsyncLock()},
    )

    with pytest.raises(RuntimeError, match="injected cleanup failure"):
        asyncio.run(first.aclose())

    second = Application.open(config_path, paths=paths)
    asyncio.run(second.aclose())


def test_application_owner_lease_precedes_operation_recovery_and_survives_crash(
    tmp_path: Path,
) -> None:
    paths = _runtime_paths(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "2026-07-28"\n', encoding="utf-8")
    ready = tmp_path / "owner.ready"
    crash = tmp_path / "owner.crash"
    process = _start_owner(config_path, paths, ready=ready, crash=crash)
    reopened: Application | None = None
    try:
        operation_id = _wait_for_ready(ready, process)
        record_path = paths.data_root / "operations" / f"{operation_id}.json"
        original_record = record_path.read_bytes()

        record_path.write_bytes(b"deliberately invalid while current owner is alive")
        started = time.monotonic()
        with pytest.raises(SupervisorAlreadyRunningError, match="Supervisor"):
            Application.open(config_path, paths=paths)
        assert time.monotonic() - started < 1
        assert record_path.read_bytes() == b"deliberately invalid while current owner is alive"
        record_path.write_bytes(original_record)

        stdout, stderr = _finish_process(process, crash)
        assert process.returncode == 91, (
            f"owner probe 未按预期崩溃: stdout={stdout!r}, stderr={stderr!r}"
        )

        reopened = Application.open(config_path, paths=paths)
        recovered = reopened.storage.operations.get(operation_id)
        assert recovered.state is OperationState.FAILED
        assert recovered.failure is not None
        assert recovered.failure.code == "worker_crashed"
    finally:
        if process.poll() is None:
            _finish_process(process, crash)
        if reopened is not None:
            asyncio.run(reopened.aclose())
