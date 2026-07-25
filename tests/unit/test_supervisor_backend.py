from __future__ import annotations

import asyncio
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.supervisor.backend import (
    DebugRequestCancelled,
    SubprocessIdaBackend,
)
from ida_re_mcp.supervisor.workers import WorkerProcess, WorkerProcessError
from ida_re_mcp.worker.ipc import JsonObject, JsonValue


class _BlockingWorker:
    def __init__(self, *, debug_result: JsonObject | None = None) -> None:
        self.started = threading.Event()
        self.released = threading.Event()
        self.debug_result = debug_result
        self.request_id: str | None = None
        self.cancelled_request_id: str | None = None
        self.aborted = False
        self.close_calls = 0

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
        request_id: str | None = None,
    ) -> JsonObject:
        del operation, input, timeout_seconds
        self.request_id = request_id
        self.started.set()
        assert self.released.wait(3)
        if self.aborted:
            raise WorkerProcessError("worker_crashed", "worker 已由调用方取消")
        assert self.debug_result is not None
        return self.debug_result

    def cancel(self, request_id: str) -> None:
        self.cancelled_request_id = request_id
        self.released.set()

    def abort(self) -> None:
        self.aborted = True
        self.released.set()

    def close(self) -> None:
        self.close_calls += 1


class _AbortRecordingWorker(WorkerProcess):
    def __init__(self) -> None:
        self.abort_calls = 0

    def abort(self) -> None:
        self.abort_calls += 1


def _replace_launch(
    monkeypatch: pytest.MonkeyPatch,
    worker: _BlockingWorker,
) -> None:
    def launch(*_args: object, **_kwargs: object) -> WorkerProcess:
        return cast(WorkerProcess, cast(object, worker))

    monkeypatch.setattr(WorkerProcess, "launch", launch)


def test_debug_cancellation_forwards_request_and_preserves_real_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingWorker(
            debug_result={
                "debug_session_id": "debug_123",
                "state": "suspended",
                "stop_id": "stop_456",
                "latest_sequence": 7,
                "cancelled": True,
            }
        )
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        debug = await backend.open_debug(
            checkout_path=tmp_path / "checkout.i64",
            sample_path=tmp_path / "sample.exe",
            revision="revision_123",
            allow_attach=False,
        )

        execution = asyncio.create_task(
            debug.execute("debug.control", {"action": "pause"}, timeout_seconds=5)
        )
        assert await asyncio.to_thread(worker.started.wait, 1)
        execution.cancel()

        with pytest.raises(DebugRequestCancelled) as cancelled:
            await execution
        assert cancelled.value.result == worker.debug_result
        assert worker.request_id
        assert worker.cancelled_request_id == worker.request_id
        assert not worker.aborted
        await debug.close()
        assert worker.close_calls == 1

    asyncio.run(scenario())


def test_analysis_cancellation_aborts_persistent_worker_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingWorker()
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")

        analysis = await backend.open_analysis(
            checkout_path=tmp_path / "checkout.i64",
            revision="revision_123",
        )
        execution = asyncio.create_task(
            analysis.execute(
                operation="program.overview",
                input={},
                timeout_seconds=5,
            )
        )
        assert await asyncio.to_thread(worker.started.wait, 1)
        execution.cancel()

        with pytest.raises(asyncio.CancelledError):
            await execution
        assert worker.aborted
        assert worker.cancelled_request_id is None
        await analysis.close()
        assert worker.close_calls == 1

    asyncio.run(scenario())


def test_launch_cancellation_aborts_worker_returned_by_launch_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        launch_started = threading.Event()
        release_launch = threading.Event()
        worker = _AbortRecordingWorker()

        def launch(*_args: object, **_kwargs: object) -> WorkerProcess:
            launch_started.set()
            assert release_launch.wait(3)
            return worker

        monkeypatch.setattr(WorkerProcess, "launch", launch)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        opening = asyncio.create_task(
            backend.open_analysis(
                checkout_path=tmp_path / "checkout.i64",
                revision="revision_123",
            )
        )
        assert await asyncio.to_thread(launch_started.wait, 1)

        opening.cancel()
        await asyncio.sleep(0)
        release_launch.set()

        with pytest.raises(asyncio.CancelledError):
            await opening
        assert worker.abort_calls == 1

    asyncio.run(scenario())
