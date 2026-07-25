from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.application import Application
from ida_re_mcp.config import RuntimePaths
from ida_re_mcp.constants import OPERATION_RETENTION_SECONDS
from ida_re_mcp.supervisor._process_lock import exclusive_process_lease
from ida_re_mcp.supervisor.errors import OperationNotFoundError, SupervisorAlreadyRunningError
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


def _session_paths(tmp_path: Path, session_id: str) -> RuntimePaths:
    data_root = tmp_path / "data"
    session_root = data_root / "sessions" / session_id
    return RuntimePaths(
        data_root=data_root,
        log_root=tmp_path / "logs" / session_id,
        workspace_root=data_root / "workspaces",
        artifact_root=data_root / "artifacts",
        checkout_root=session_root / "checkouts",
        temp_root=session_root / "temp",
        session_root=session_root,
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
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
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


def test_application_aclose_releases_owner_lease_after_early_operation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        paths = _runtime_paths(tmp_path)
        config_path = tmp_path / "config.toml"
        config_path.write_text('schema_version = "1"\n', encoding="utf-8")
        first = Application.open(config_path, paths=paths)
        operation = first.storage.operations.create("ownership_probe")

        async def wait_forever() -> None:
            await asyncio.Future[None]()

        pending = asyncio.create_task(wait_forever())

        def fail_cancel(_operation_id: str) -> None:
            raise OSError("injected operation cleanup failure")

        monkeypatch.setattr(first.storage.operations, "cancel", fail_cancel)
        monkeypatch.setattr(
            first,
            "_operation_tasks",
            {operation.operation_id: pending},
        )

        with pytest.raises(OSError, match="injected operation cleanup failure"):
            await first.aclose()
        assert pending.cancelled()

        second = Application.open(config_path, paths=paths)
        await second.aclose()

    asyncio.run(scenario())


def test_distinct_mcp_sessions_share_revisions_but_isolate_session_state(
    tmp_path: Path,
) -> None:
    first_paths = _session_paths(tmp_path, "session_first")
    second_paths = _session_paths(tmp_path, "session_second")
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"shared sample")
    first = Application.open(config_path, paths=first_paths)
    second = Application.open(config_path, paths=second_paths)
    try:
        workspace = first.storage.workspaces.create(sample)
        operation = first.storage.operations.create(
            "session_probe",
            workspace_id=workspace.workspace_id,
        )

        assert second.storage.workspaces.get(workspace.workspace_id) == workspace
        with pytest.raises(OperationNotFoundError):
            second.storage.operations.get(operation.operation_id)
        assert first.storage.paths.operation_root != second.storage.paths.operation_root
        assert first.storage.paths.change_root != second.storage.paths.change_root
        assert first.storage.paths.checkout_root != second.storage.paths.checkout_root
        assert first.storage.paths.log_root != second.storage.paths.log_root
    finally:
        asyncio.run(first.aclose())
        asyncio.run(second.aclose())


def test_application_uses_shared_runtime_roots_from_server_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "shared" / "data"
    log_root = tmp_path / "shared" / "logs"
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "\n".join(
            (
                'schema_version = "1"',
                "",
                "[runtime]",
                f'data_root = "{data_root.as_posix()}"',
                f'log_root = "{log_root.as_posix()}"',
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("IDA_RE_MCP_DATA_ROOT", raising=False)
    monkeypatch.delenv("IDA_RE_MCP_LOG_ROOT", raising=False)

    application = Application.open(config_path)
    try:
        assert application.storage.paths.data_root == data_root.resolve()
        assert application.storage.paths.workspace_root == data_root.resolve() / "workspaces"
        assert application.storage.paths.session_data_root.parent == (
            data_root.resolve() / "sessions"
        )
        assert application.storage.paths.log_root.parent == log_root.resolve() / "sessions"
    finally:
        asyncio.run(application.aclose())


def test_gc_reclaims_only_expired_inactive_session_roots(tmp_path: Path) -> None:
    paths = _session_paths(tmp_path, "session_current")
    stale = paths.data_root / "sessions" / "session_stale"
    stale.mkdir(parents=True)
    payload = stale / "orphan.bin"
    payload.write_bytes(b"orphaned session")
    stale_log = paths.log_root.parent / stale.name
    stale_log.mkdir(parents=True)
    log_payload = stale_log / "worker.log"
    log_payload.write_text("orphaned log", encoding="ascii")
    old = time.time() - OPERATION_RETENTION_SECONDS - 60
    os.utime(payload, (old, old))
    os.utime(stale, (old, old))
    os.utime(log_payload, (old, old))
    os.utime(stale_log, (old, old))
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
    application = Application.open(config_path, paths=paths)
    try:
        preview = asyncio.run(application.gc(apply=False))
        preview_candidates = cast(dict[str, list[str]], preview["candidates"])
        assert str(stale) in preview_candidates["session"]
        assert str(stale_log) in preview_candidates["session"]
        assert stale.is_dir()
        stale_lease = paths.session_lease_root / "session_stale.lease.lock"
        assert stale_lease.is_file()

        applied = asyncio.run(application.gc(apply=True))
        applied_candidates = cast(dict[str, list[str]], applied["candidates"])
        assert str(stale) in applied_candidates["session"]
        assert not stale.exists()
        assert not stale_log.exists()
        assert not stale_lease.exists()
        assert paths.session_data_root.is_dir()
    finally:
        asyncio.run(application.aclose())


def test_gc_uses_latest_nested_session_activity(tmp_path: Path) -> None:
    paths = _session_paths(tmp_path, "session_current")
    candidate = paths.data_root / "sessions" / "session_recent_nested"
    operation_root = candidate / "operations"
    operation_root.mkdir(parents=True)
    operation = operation_root / "op_recent.json"
    operation.write_text("{}", encoding="ascii")
    old = time.time() - OPERATION_RETENTION_SECONDS - 60
    os.utime(candidate, (old, old))
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
    application = Application.open(config_path, paths=paths)
    try:
        preview = asyncio.run(application.gc(apply=False))
        candidates = cast(dict[str, list[str]], preview["candidates"])
        assert str(candidate) not in candidates["session"]
        assert candidate.is_dir()
    finally:
        asyncio.run(application.aclose())


def test_gc_skips_active_session_lease(tmp_path: Path) -> None:
    paths = _session_paths(tmp_path, "session_current")
    active = paths.data_root / "sessions" / "session_active"
    active.mkdir(parents=True)
    payload = active / "operation.json"
    payload.write_text("{}", encoding="ascii")
    old = time.time() - OPERATION_RETENTION_SECONDS - 60
    os.utime(payload, (old, old))
    os.utime(active, (old, old))
    lease = exclusive_process_lease(paths.session_lease_root / "session_active.lease.lock")
    assert lease.try_acquire()
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
    application = Application.open(config_path, paths=paths)
    try:
        applied = asyncio.run(application.gc(apply=True))
        assert applied["skipped_session_ids"] == ["session_active"]
        assert active.is_dir()
    finally:
        asyncio.run(application.aclose())
        lease.release()


def test_concurrent_gc_apply_claims_stale_session_once(tmp_path: Path) -> None:
    first_paths = _session_paths(tmp_path, "session_first")
    second_paths = _session_paths(tmp_path, "session_second")
    stale = first_paths.data_root / "sessions" / "session_stale"
    stale.mkdir(parents=True)
    payload = stale / "operation.json"
    payload.write_text("{}", encoding="ascii")
    old = time.time() - OPERATION_RETENTION_SECONDS - 60
    os.utime(payload, (old, old))
    os.utime(stale, (old, old))
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
    first = Application.open(config_path, paths=first_paths)
    second = Application.open(config_path, paths=second_paths)

    async def scenario() -> None:
        try:
            await asyncio.gather(first.gc(apply=True), second.gc(apply=True))
        finally:
            await asyncio.gather(first.aclose(), second.aclose())

    asyncio.run(scenario())
    assert not stale.exists()


def test_application_owner_lease_precedes_operation_recovery_and_survives_crash(
    tmp_path: Path,
) -> None:
    paths = _runtime_paths(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text('schema_version = "1"\n', encoding="utf-8")
    ready = tmp_path / "owner.ready"
    crash = tmp_path / "owner.crash"
    process = _start_owner(config_path, paths, ready=ready, crash=crash)
    reopened: Application | None = None
    try:
        operation_id = _wait_for_ready(ready, process)
        record_path = paths.data_root / "operations" / f"{operation_id}.json"
        original_record = record_path.read_bytes()

        record_path.write_bytes(b"deliberately invalid while active owner is alive")
        started = time.monotonic()
        with pytest.raises(SupervisorAlreadyRunningError, match="Supervisor"):
            Application.open(config_path, paths=paths)
        assert time.monotonic() - started < 1
        assert record_path.read_bytes() == b"deliberately invalid while active owner is alive"
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
