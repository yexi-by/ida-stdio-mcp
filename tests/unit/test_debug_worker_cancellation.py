"""活动 worker 命令的 IPC cancellation 协作测试。"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path
from queue import Queue

import pytest

from ida_re_mcp.worker.ipc import IpcEndpoint, JsonObject, WorkerClient, serve_worker


class _CancellationProbe:
    def __init__(self) -> None:
        self.started = threading.Event()
        self._cancellation: threading.Event | None = None

    def bind_cancellation(self, cancellation: threading.Event | None) -> None:
        self._cancellation = cancellation

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        del operation, input
        cancellation = self._cancellation
        assert cancellation is not None
        self.started.set()
        assert cancellation.wait(3)
        return {"cancel_seen": True}


def test_ipc_binds_cancel_event_to_active_owner_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    endpoint = IpcEndpoint.create(tmp_path)
    ready = threading.Event()
    probe = _CancellationProbe()
    server = threading.Thread(
        target=serve_worker,
        args=(endpoint, probe),
        kwargs={"ready": ready.set},
        daemon=True,
    )
    server.start()
    assert ready.wait(3)
    client = WorkerClient(endpoint)
    results: Queue[JsonObject | BaseException] = Queue(maxsize=1)
    request_id = "debug_cancel_probe"

    def execute() -> None:
        try:
            results.put(client.execute("probe", {}, request_id=request_id))
        except BaseException as exc:
            results.put(exc)

    caller = threading.Thread(target=execute, daemon=True)
    caller.start()
    try:
        assert probe.started.wait(3)
        client.cancel(request_id)
        caller.join(3)
        assert not caller.is_alive()
        result = results.get_nowait()
        assert isinstance(result, dict)
        assert result == {"cancel_seen": True}
    finally:
        client.close()
    server.join(3)
    assert not server.is_alive()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
