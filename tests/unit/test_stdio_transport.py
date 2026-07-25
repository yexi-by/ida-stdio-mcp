from __future__ import annotations

import asyncio
import io
import json
from typing import TYPE_CHECKING, cast

import pytest

import ida_re_mcp.protocol.stdio as stdio
from ida_re_mcp.protocol.stdio import (
    MAX_STDIO_INPUT_BYTES,
    serve_stdio,
)

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer


def _wire_result(request_id: object, result: object) -> bytes:
    return (
        json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "result": result},
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _decode_lines(stream: io.BytesIO) -> list[dict[str, object]]:
    messages: list[dict[str, object]] = []
    for line in stream.getvalue().splitlines():
        value: object = json.loads(line)
        assert isinstance(value, dict)
        messages.append(cast(dict[str, object], value))
    return messages


class _ConcurrentProtocol:
    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0
        self.seen: list[bytes] = []

    async def handle_line(self, line: bytes | str) -> bytes | None:
        assert isinstance(line, bytes)
        self.seen.append(line)
        request = json.loads(line)
        if "id" not in request:
            return None
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0.01)
            return _wire_result(request["id"], {"ok": True})
        finally:
            self.active -= 1


class _FixedProtocol:
    def __init__(self, response: bytes | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls = 0

    async def handle_line(self, line: bytes | str) -> bytes | None:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.response


class _CancellableProtocol:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.request_task: asyncio.Task[None] | None = None

    async def handle_line(self, line: bytes | str) -> bytes | None:
        assert isinstance(line, bytes)
        message: object = json.loads(line)
        assert isinstance(message, dict)
        if "id" in message:
            current = asyncio.current_task()
            assert current is not None
            self.request_task = current
            self.started.set()
            await asyncio.Event().wait()
            raise AssertionError("已取消请求不应继续执行")

        await self.started.wait()
        assert self.request_task is not None
        self.request_task.cancel()
        return None


class _PartialWriter(io.BytesIO):
    def __init__(self, max_write: int) -> None:
        super().__init__()
        self.max_write = max_write

    def write(self, data: ReadableBuffer) -> int:
        chunk = bytes(data)[: self.max_write]
        return super().write(chunk)


def _run(
    protocol: _CancellableProtocol | _ConcurrentProtocol | _FixedProtocol,
    data: bytes,
) -> tuple[io.BytesIO, io.StringIO]:
    stdout = io.BytesIO()
    stderr = io.StringIO()
    asyncio.run(
        serve_stdio(
            protocol,
            stdin=io.BytesIO(data),
            stdout=stdout,
            stderr=stderr,
        )
    )
    return stdout, stderr


def test_stdio_concurrently_dispatches_and_waits_at_eof() -> None:
    protocol = _ConcurrentProtocol()
    data = b"".join(
        [
            b'{"jsonrpc":"2.0","id":1}\n',
            b'{"jsonrpc":"2.0","method":"notification"}\n',
            b'{"jsonrpc":"2.0","id":2}\n',
        ]
    )

    stdout, stderr = _run(protocol, data)

    assert protocol.max_active >= 2
    assert {message["id"] for message in _decode_lines(stdout)} == {1, 2}
    assert stderr.getvalue() == ""


def test_stdio_rejects_one_oversized_line_and_continues() -> None:
    protocol = _FixedProtocol(response=_wire_result(7, {"ok": True}))
    oversized = b"x" * (MAX_STDIO_INPUT_BYTES + 1) + b"\n"

    stdout, stderr = _run(protocol, oversized + b'{"jsonrpc":"2.0","id":7}\n')

    messages = _decode_lines(stdout)
    assert len(messages) == 2
    errors = [
        cast(dict[str, object], message["error"])
        for message in messages
        if isinstance(message.get("error"), dict)
    ]
    assert any(error.get("code") == -32700 for error in errors)
    assert any(message.get("id") == 7 and "result" in message for message in messages)
    assert protocol.calls == 1
    assert stderr.getvalue() == ""


def test_stdio_accepts_exact_input_boundary() -> None:
    base = b'{"jsonrpc":"2.0","id":9}'
    line = base + (b" " * (MAX_STDIO_INPUT_BYTES - len(base))) + b"\n"
    protocol = _FixedProtocol(response=_wire_result(9, {}))

    stdout, _ = _run(protocol, line)

    assert protocol.calls == 1
    assert _decode_lines(stdout)[0]["id"] == 9


def test_stdio_replaces_oversized_result_with_internal_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(stdio, "MAX_STDIO_MESSAGE_BYTES", 512)
    base = b'{"jsonrpc":"2.0","id":"large","result":{}}'
    response = base + (b" " * (stdio.MAX_STDIO_MESSAGE_BYTES + 1 - len(base))) + b"\n"
    protocol = _FixedProtocol(response=response)

    stdout, stderr = _run(protocol, b'{"jsonrpc":"2.0","id":"large"}\n')

    message = _decode_lines(stdout)[0]
    assert message["id"] == "large"
    error = cast(dict[str, object], message["error"])
    assert error["code"] == -32603
    assert "协议响应超过" in stderr.getvalue()


def test_stdio_accepts_exact_output_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stdio, "MAX_STDIO_MESSAGE_BYTES", 512)
    base = b'{"jsonrpc":"2.0","id":4,"result":{}}'
    response = base + (b" " * (stdio.MAX_STDIO_MESSAGE_BYTES - len(base))) + b"\n"

    stdout, stderr = _run(_FixedProtocol(response=response), b'{"id":4}\n')

    assert stdout.getvalue() == response
    assert stderr.getvalue() == ""


def test_stdio_sanitizes_handler_exception_without_polluting_stdout() -> None:
    protocol = _FixedProtocol(error=RuntimeError("failure\nwith another line"))

    stdout, stderr = _run(protocol, b'{"jsonrpc":"2.0","id":23}\n')

    messages = _decode_lines(stdout)
    assert messages == [
        {
            "jsonrpc": "2.0",
            "id": 23,
            "error": {"code": -32603, "message": "Internal error"},
        }
    ]
    assert len(stdout.getvalue().splitlines()) == 1
    assert "failure with another line" in stderr.getvalue()


def test_stdio_notification_can_produce_no_output() -> None:
    stdout, stderr = _run(_FixedProtocol(response=None), b'{"jsonrpc":"2.0","method":"x"}\n')

    assert stdout.getvalue() == b""
    assert stderr.getvalue() == ""


def test_stdio_retries_partial_stdout_writes_until_response_is_complete() -> None:
    response = _wire_result("partial", {"ok": True})
    stdout = _PartialWriter(max_write=3)
    stderr = io.StringIO()

    asyncio.run(
        serve_stdio(
            _FixedProtocol(response=response),
            stdin=io.BytesIO(b'{"jsonrpc":"2.0","id":"partial"}\n'),
            stdout=stdout,
            stderr=stderr,
        )
    )

    assert stdout.getvalue() == response
    assert stderr.getvalue() == ""


def test_stdio_cancelled_request_produces_no_response_and_keeps_transport_clean() -> None:
    protocol = _CancellableProtocol()
    stdout, stderr = _run(
        protocol,
        (
            b'{"jsonrpc":"2.0","id":"request"}\n'
            b'{"jsonrpc":"2.0","method":"notifications/cancelled",'
            b'"params":{"requestId":"request"}}\n'
        ),
    )

    assert stdout.getvalue() == b""
    assert stderr.getvalue() == ""
