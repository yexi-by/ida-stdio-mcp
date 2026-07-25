"""经过认证的本机 worker IPC。

连接层使用 ``multiprocessing.connection`` 的 AF_PIPE/AF_UNIX 认证握手, 但应用
消息始终通过 ``send_bytes``/``recv_bytes`` 传输 UTF-8 JSON, 绝不调用会使用
pickle 的 ``send``/``recv``。
"""

from __future__ import annotations

import json
import os
import queue
import secrets
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from multiprocessing.connection import Client, Connection, Listener
from pathlib import Path
from typing import Protocol, cast

from ida_re_mcp.worker.errors import WorkerError

MAX_IPC_MESSAGE_BYTES = 8 * 1024 * 1024

JsonScalar = None | bool | int | float | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]


def _reject_constant(value: str) -> None:
    raise ValueError(f"JSON 不允许非有限数值: {value}")


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON 对象包含重复键: {key}")
        result[key] = value
    return result


def encode_message(message: Mapping[str, JsonValue]) -> bytes:
    """编码确定性的 UTF-8 JSON 消息。"""

    payload = json.dumps(
        dict(message),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_IPC_MESSAGE_BYTES:
        raise WorkerError(
            "ipc_message_too_large",
            "worker IPC 消息超过大小上限",
            details={"actual_bytes": len(payload), "limit_bytes": MAX_IPC_MESSAGE_BYTES},
        )
    return payload


def decode_message(payload: bytes) -> JsonObject:
    """解码单个 JSON 对象并拒绝重复键、BOM、非 UTF-8 和非有限数值。"""

    if len(payload) > MAX_IPC_MESSAGE_BYTES:
        raise WorkerError(
            "ipc_message_too_large",
            "worker IPC 消息超过大小上限",
            details={"actual_bytes": len(payload), "limit_bytes": MAX_IPC_MESSAGE_BYTES},
        )
    if payload.startswith(b"\xef\xbb\xbf"):
        raise WorkerError("ipc_invalid_json", "worker IPC JSON 不允许 UTF-8 BOM")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkerError(
            "ipc_invalid_json",
            "worker IPC 收到无效 UTF-8 JSON",
            details={"reason": str(exc)},
        ) from exc
    if not isinstance(value, dict):
        raise WorkerError("ipc_invalid_json", "worker IPC 顶层消息必须是 JSON 对象")
    candidate = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in candidate):
        raise WorkerError("ipc_invalid_json", "worker IPC 顶层消息必须使用字符串键")
    return cast(JsonObject, candidate)


@dataclass(frozen=True, slots=True)
class IpcEndpoint:
    """本机 IPC 地址与认证信息。"""

    family: str
    address: str
    authkey: bytes

    @classmethod
    def create(cls, directory: Path | None = None) -> IpcEndpoint:
        """创建仅供当前 worker 生命周期使用的随机端点。"""

        authkey = secrets.token_bytes(32)
        token = uuid.uuid4().hex
        if os.name == "nt":
            return cls("AF_PIPE", rf"\\.\pipe\ida-re-mcp-{token}", authkey)
        root = directory or Path(tempfile.gettempdir())
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        return cls("AF_UNIX", str(root / f"ida-re-mcp-{token}.sock"), authkey)

    def public_dict(self) -> dict[str, str]:
        """返回不泄露认证密钥的诊断信息。"""

        return {"family": self.family, "address": self.address}


class _ByteConnection(Protocol):
    def send_bytes(self, buf: bytes, offset: int = 0, size: int | None = None) -> None: ...

    def recv_bytes(self, maxlength: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class IpcChannel:
    """线程安全的 JSON 字节消息通道。"""

    def __init__(self, connection: _ByteConnection) -> None:
        self._connection = connection
        self._send_lock = threading.Lock()

    def send(self, message: Mapping[str, JsonValue]) -> None:
        payload = encode_message(message)
        with self._send_lock:
            self._connection.send_bytes(payload)

    def receive(self) -> JsonObject:
        try:
            payload = self._connection.recv_bytes(MAX_IPC_MESSAGE_BYTES + 1)
        except OSError as exc:
            raise WorkerError("ipc_disconnected", "worker IPC 连接已断开") from exc
        return decode_message(payload)

    def close(self) -> None:
        self._connection.close()


class WorkerHandler(Protocol):
    """serve_worker 可调度的最小 worker 接口。"""

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]: ...


class CancellationAwareWorkerHandler(Protocol):
    """由 owner 线程把当前命令的取消标志绑定到 handler。"""

    def bind_cancellation(self, cancellation: threading.Event | None) -> None: ...


class WorkerClient:
    """Supervisor 侧的同步 worker 客户端。"""

    def __init__(self, endpoint: IpcEndpoint) -> None:
        self._endpoint = endpoint
        self._channel: IpcChannel | None = None
        self._call_lock = threading.Lock()

    def connect(self) -> None:
        if self._channel is not None:
            return
        connection = Client(
            self._endpoint.address,
            family=self._endpoint.family,
            authkey=self._endpoint.authkey,
        )
        self._channel = IpcChannel(cast(Connection, connection))

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> JsonObject:
        """发送命令并等待相同 request id 的唯一回复。"""

        if not operation:
            raise ValueError("operation 不能为空")
        with self._call_lock:
            self.connect()
            channel = self._require_channel()
            command_id = request_id or uuid.uuid4().hex
            channel.send(
                {
                    "kind": "command",
                    "id": command_id,
                    "operation": operation,
                    "input": dict(input),
                }
            )
            while True:
                reply = channel.receive()
                if reply.get("kind") == "event":
                    continue
                if reply.get("kind") != "reply" or reply.get("id") != command_id:
                    raise WorkerError(
                        "ipc_protocol_error",
                        "worker 返回了无法关联的回复",
                    )
                if reply.get("ok") is True:
                    result = reply.get("result")
                    if not isinstance(result, dict):
                        raise WorkerError(
                            "ipc_protocol_error",
                            "worker 成功回复缺少 JSON 对象结果",
                        )
                    return cast(JsonObject, result)
                error = reply.get("error")
                if not isinstance(error, dict):
                    raise WorkerError("worker_failed", "worker 返回了无结构错误")
                code = error.get("code")
                message = error.get("message")
                details = error.get("details")
                raise WorkerError(
                    code if isinstance(code, str) else "worker_failed",
                    message if isinstance(message, str) else "worker 操作失败",
                    details=cast(dict[str, object], details) if isinstance(details, dict) else None,
                )

    def cancel(self, request_id: str) -> None:
        """异步请求取消; 取消只设置标志, 不直接调用任何 IDA API。"""

        self._require_channel().send({"kind": "cancel", "id": request_id})

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None

    def _require_channel(self) -> IpcChannel:
        if self._channel is None:
            raise WorkerError("ipc_not_connected", "worker IPC 尚未连接")
        return self._channel

    def __enter__(self) -> WorkerClient:
        self.connect()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


@dataclass(slots=True)
class _Command:
    command_id: str
    operation: str
    input: dict[str, object]
    cancel_requested: threading.Event


def _safe_error(exc: BaseException) -> dict[str, object]:
    if isinstance(exc, WorkerError):
        return exc.as_dict()
    return {
        "code": "worker_internal_error",
        "message": "worker 内部错误",
        "details": {"exception_type": type(exc).__name__},
    }


def serve_worker(
    endpoint: IpcEndpoint,
    handler: WorkerHandler,
    *,
    stop_event: threading.Event | None = None,
    ready: Callable[[], None] | None = None,
) -> None:
    """在调用线程调度命令, 在独立 reader 线程接收 IPC。

    调用线程即 worker owner 线程。reader 线程仅解析、排队及设置取消标志,
    从不调用 handler 或 IDA。
    """

    commands: queue.Queue[_Command | None] = queue.Queue()
    cancellations: dict[str, threading.Event] = {}
    stopped = stop_event or threading.Event()
    address_path = Path(endpoint.address) if endpoint.family == "AF_UNIX" else None
    listener = Listener(endpoint.address, family=endpoint.family, authkey=endpoint.authkey)
    if address_path is not None:
        try:
            os.chmod(address_path, 0o600)
        except OSError:
            listener.close()
            raise
    if ready is not None:
        ready()
    connection = listener.accept()
    channel = IpcChannel(cast(Connection, connection))

    def read_messages() -> None:
        try:
            while not stopped.is_set():
                message = channel.receive()
                kind = message.get("kind")
                command_id = message.get("id")
                if not isinstance(command_id, str) or not command_id:
                    raise WorkerError("ipc_protocol_error", "IPC 消息缺少有效 id")
                if kind == "cancel":
                    cancellation = cancellations.get(command_id)
                    if cancellation is not None:
                        cancellation.set()
                    continue
                if kind != "command":
                    raise WorkerError("ipc_protocol_error", "IPC 只接受 command 或 cancel")
                operation = message.get("operation")
                raw_input = message.get("input")
                if not isinstance(operation, str) or not isinstance(raw_input, dict):
                    raise WorkerError("ipc_protocol_error", "command 缺少 operation 或 input")
                cancellation = threading.Event()
                cancellations[command_id] = cancellation
                commands.put(
                    _Command(
                        command_id,
                        operation,
                        cast(dict[str, object], raw_input),
                        cancellation,
                    )
                )
        except (EOFError, OSError, WorkerError):
            stopped.set()
            commands.put(None)

    reader = threading.Thread(target=read_messages, name="ida-re-ipc-reader", daemon=True)
    reader.start()
    poll = getattr(handler, "poll", None)
    bind_cancellation = getattr(handler, "bind_cancellation", None)
    try:
        while not stopped.is_set():
            try:
                command = commands.get(timeout=0.05)
            except queue.Empty:
                if callable(poll):
                    poll()
                continue
            if command is None:
                break
            try:
                if command.cancel_requested.is_set():
                    raise WorkerError("cancelled", "操作在执行前已取消")
                if callable(bind_cancellation):
                    bind_cancellation(command.cancel_requested)
                result = handler.execute(command.operation, command.input)
                reply: dict[str, JsonValue] = {
                    "kind": "reply",
                    "id": command.command_id,
                    "ok": True,
                    "result": cast(JsonObject, result),
                }
            except BaseException as exc:
                reply = {
                    "kind": "reply",
                    "id": command.command_id,
                    "ok": False,
                    "error": cast(JsonObject, _safe_error(exc)),
                }
            finally:
                if callable(bind_cancellation):
                    bind_cancellation(None)
                cancellations.pop(command.command_id, None)
            channel.send(reply)
            if callable(poll):
                poll()
    finally:
        stopped.set()
        close = getattr(handler, "close", None)
        if callable(close):
            close()
        channel.close()
        listener.close()
        if address_path is not None:
            address_path.unlink(missing_ok=True)
        reader.join(timeout=1.0)


def wait_for_endpoint(endpoint: IpcEndpoint, timeout_seconds: float = 5.0) -> None:
    """仅用于进程启动编排: 等待 AF_UNIX socket 出现。"""

    if endpoint.family != "AF_UNIX":
        time.sleep(min(timeout_seconds, 0.05))
        return
    deadline = time.monotonic() + timeout_seconds
    path = Path(endpoint.address)
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise WorkerError(
        "ipc_start_timeout",
        "worker IPC 端点未在时限内出现",
        details={"timeout_seconds": timeout_seconds},
    )
