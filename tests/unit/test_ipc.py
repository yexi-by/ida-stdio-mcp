"""worker IPC 只允许经过认证的 UTF-8 JSON 字节消息。"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from pathlib import Path

import pytest

from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.ipc import (
    IpcChannel,
    IpcEndpoint,
    WorkerClient,
    decode_message,
    encode_message,
    serve_worker,
)


class _RecordingConnection:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def send_bytes(self, buf: bytes, offset: int = 0, size: int | None = None) -> None:
        end = len(buf) if size is None else offset + size
        self.payloads.append(buf[offset:end])

    def recv_bytes(self, maxlength: int | None = None) -> bytes:
        del maxlength
        return self.payloads.pop(0)

    def send(self, _value: object) -> None:
        raise AssertionError("不得调用 pickle send")

    def recv(self) -> object:
        raise AssertionError("不得调用 pickle recv")

    def close(self) -> None:
        return None


class _EchoWorker:
    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        return {"operation": operation, "input": dict(input)}


def test_codec_is_deterministic_utf8_json() -> None:
    first = encode_message({"z": 1, "a": "逆向"})
    second = encode_message({"a": "逆向", "z": 1})
    assert first == second == b'{"a":"\xe9\x80\x86\xe5\x90\x91","z":1}'
    assert decode_message(first) == {"a": "逆向", "z": 1}


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":1,"a":2}',
        b"\xef\xbb\xbf{}",
        b"[]",
        b'{"value":NaN}',
        b"\xff",
    ],
)
def test_decoder_rejects_non_contract_json(payload: bytes) -> None:
    with pytest.raises(WorkerError) as captured:
        decode_message(payload)
    assert captured.value.code == "ipc_invalid_json"


def test_channel_uses_bytes_api_only() -> None:
    connection = _RecordingConnection()
    channel = IpcChannel(connection)
    channel.send({"kind": "probe"})
    assert channel.receive() == {"kind": "probe"}


def test_endpoint_uses_platform_local_transport(tmp_path: Path) -> None:
    endpoint = IpcEndpoint.create(tmp_path)
    assert len(endpoint.authkey) == 32
    if os.name == "nt":
        assert endpoint.family == "AF_PIPE"
        assert endpoint.address.startswith(r"\\.\pipe\ida-re-mcp-")
    else:
        assert endpoint.family == "AF_UNIX"
        assert Path(endpoint.address).parent == tmp_path
    assert "authkey" not in endpoint.public_dict()


def test_authenticated_server_round_trip(tmp_path: Path) -> None:
    endpoint = IpcEndpoint.create(tmp_path)
    ready = threading.Event()
    stopped = threading.Event()
    server = threading.Thread(
        target=serve_worker,
        args=(endpoint, _EchoWorker()),
        kwargs={"ready": ready.set, "stop_event": stopped},
        daemon=True,
    )
    server.start()
    assert ready.wait(3)
    client = WorkerClient(endpoint)
    try:
        assert client.execute("probe", {"value": 7}) == {
            "operation": "probe",
            "input": {"value": 7},
        }
    finally:
        client.close()
    server.join(3)
    assert not server.is_alive()


def test_worker_error_is_transported_without_traceback(tmp_path: Path) -> None:
    class FailingWorker:
        def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
            del operation, input
            raise WorkerError("expected_failure", "可公开错误", details={"stage": "test"})

    endpoint = IpcEndpoint.create(tmp_path)
    ready = threading.Event()
    server = threading.Thread(
        target=serve_worker,
        args=(endpoint, FailingWorker()),
        kwargs={"ready": ready.set},
        daemon=True,
    )
    server.start()
    assert ready.wait(3)
    client = WorkerClient(endpoint)
    try:
        with pytest.raises(WorkerError) as captured:
            client.execute("fail", {})
        assert captured.value.code == "expected_failure"
        assert captured.value.details == {"stage": "test"}
    finally:
        client.close()
    server.join(3)
    assert not server.is_alive()
