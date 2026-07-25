"""current-only MCP 的二进制 stdio 传输边界。"""

import asyncio
import json
from dataclasses import dataclass
from typing import BinaryIO, Final, Protocol, TextIO, cast

MAX_STDIO_INPUT_BYTES: Final = 8 * 1024 * 1024
# 工具的结构化 inline 结果仍由协议层限制为 32 KiB. resource 读取可由
# 最多 64 个 1 MiB 原始块组成, 加上 base64 与 JSON 开销后仍必须容纳于一行.
MAX_STDIO_MESSAGE_BYTES: Final = 96 * 1024 * 1024
_INTERNAL_ERROR: Final = -32603
_PARSE_ERROR: Final = -32700

type RequestId = int | str | None


class LineProtocol(Protocol):
    """stdio 所依赖的最小 current-only 协议接口。"""

    async def handle_line(self, line: bytes | str) -> bytes | None: ...


class StdioTransportError(RuntimeError):
    """stdio 本身无法继续可靠读写。"""


@dataclass(frozen=True, slots=True)
class _ReadResult:
    data: bytes
    oversized: bool


class _LockedWriter:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._lock = asyncio.Lock()

    async def write(self, data: bytes) -> None:
        async with self._lock:
            await asyncio.to_thread(self._write_all, data)

    def _write_all(self, data: bytes) -> None:
        view = memoryview(data)
        total = 0
        while total < len(view):
            written = self._stream.write(view[total:])
            if written <= 0:
                raise OSError(f"stdout 写入在 {total}/{len(view)} 字节处停止")
            total += written
        self._stream.flush()


def _read_one(stream: BinaryIO) -> _ReadResult | None:
    # 多读 3 字节; 才能同时区分上限、LF 与 CRLF。
    raw = stream.readline(MAX_STDIO_INPUT_BYTES + 3)
    if raw == b"":
        return None

    payload_end = len(raw)
    if raw.endswith(b"\n"):
        payload_end -= 1
        if payload_end > 0 and raw[payload_end - 1 : payload_end] == b"\r":
            payload_end -= 1
    oversized = payload_end > MAX_STDIO_INPUT_BYTES

    if oversized and not raw.endswith(b"\n"):
        while True:
            remainder = stream.readline(MAX_STDIO_INPUT_BYTES + 3)
            if remainder == b"" or remainder.endswith(b"\n"):
                break
    return _ReadResult(data=raw, oversized=oversized)


def _encode_error(request_id: RequestId, code: int, message: str) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            },
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _request_id(line: bytes) -> RequestId:
    try:
        value: object = json.loads(line.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    candidate = cast(dict[str, object], value).get("id")
    if isinstance(candidate, bool):
        return None
    if isinstance(candidate, (int, str)):
        return candidate
    return None


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"非有限 JSON 数值: {value}")


def _validate_response(response: bytes) -> bytes:
    if not response.endswith(b"\n") or response.endswith(b"\r\n"):
        raise ValueError("协议响应必须以单个 LF 结束")
    payload = response[:-1]
    if not payload or b"\n" in payload or b"\r" in payload:
        raise ValueError("协议响应必须是单行 JSON")
    if len(payload) > MAX_STDIO_MESSAGE_BYTES:
        raise ValueError("协议响应超过传输上限")
    try:
        value: object = json.loads(
            payload.decode("utf-8", errors="strict"),
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("协议响应不是严格 UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("协议响应不是 JSON-RPC 2.0 对象")
    message = cast(dict[str, object], value)
    if message.get("jsonrpc") != "2.0" or "id" not in message:
        raise ValueError("协议响应不是 JSON-RPC 2.0 对象")
    if ("result" in message) == ("error" in message):
        raise ValueError("协议响应必须且只能包含 result 或 error")
    return response


def _write_diagnostic(stderr: TextIO, message: str, error: Exception) -> None:
    detail = str(error).replace("\r", " ").replace("\n", " ")[:2_048]
    stderr.write(f"ida-re-mcp: {message}: {type(error).__name__}: {detail}\n")
    stderr.flush()


async def serve_stdio(
    protocol: LineProtocol,
    *,
    stdin: BinaryIO,
    stdout: BinaryIO,
    stderr: TextIO,
) -> None:
    """并发处理请求; 在 EOF 后等待所有响应完成并保持 stdout 纯净。"""

    writer = _LockedWriter(stdout)
    tasks: set[asyncio.Task[None]] = set()
    write_failures: list[Exception] = []

    async def write_response(response: bytes) -> None:
        try:
            await writer.write(response)
        except Exception as exc:
            _write_diagnostic(stderr, "stdout 写入失败", exc)
            write_failures.append(exc)

    async def process(line: bytes) -> None:
        try:
            response = await protocol.handle_line(line)
        except asyncio.CancelledError:
            # notifications/cancelled 表示调用方不再使用结果, 不得伪造错误响应。
            return
        except Exception as exc:
            _write_diagnostic(stderr, "请求处理失败", exc)
            response = _encode_error(_request_id(line), _INTERNAL_ERROR, "Internal error")
        if response is None:
            return
        try:
            prepared = _validate_response(response)
        except Exception as exc:
            _write_diagnostic(stderr, "拒绝非法协议响应", exc)
            prepared = _encode_error(_request_id(line), _INTERNAL_ERROR, "Internal error")
        await write_response(prepared)

    try:
        while not write_failures:
            item = await asyncio.to_thread(_read_one, stdin)
            if item is None:
                break
            if item.oversized:
                task = asyncio.create_task(
                    write_response(_encode_error(None, _PARSE_ERROR, "Parse error"))
                )
            else:
                task = asyncio.create_task(process(item.data))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        if tasks:
            await asyncio.gather(*tuple(tasks))
    except BaseException:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tuple(tasks), return_exceptions=True)
        raise

    if write_failures:
        raise StdioTransportError("stdout 无法完整写入协议响应") from write_failures[0]
