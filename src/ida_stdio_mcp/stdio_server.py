"""原生 stdio MCP 服务。"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from time import perf_counter
from typing import BinaryIO, Literal, cast

from loguru import logger

from .logging import (
    log_resource_read_exception,
    log_resource_read_finished,
    log_resource_read_started,
    log_tool_call_exception,
    log_tool_call_finished,
    log_tool_call_started,
)
from .models import JsonObject, JsonValue
from .result import build_error_info, build_result, normalize_json_object
from .tool_registry import ResourceRegistry, ToolRegistry

TransportFlavor = Literal["framed", "line_json"]


@dataclass(slots=True, frozen=True)
class ServerIdentity:
    """服务身份信息。"""

    protocol_version: str
    server_name: str
    server_version: str


class StdioMcpServer:
    """支持 tools 与 resources 的最小 stdio MCP 服务。"""

    def __init__(
        self,
        tools: ToolRegistry,
        resources: ResourceRegistry,
        identity: ServerIdentity,
    ) -> None:
        self._tools = tools
        self._resources = resources
        self._identity = identity
        self._transport_flavor: TransportFlavor | None = None

    def serve(self) -> int:
        """进入 stdio 主循环。"""
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        logger.info("stdio MCP 服务已启动")

        while True:
            try:
                request_text, transport_flavor = self._read_message(stdin, self._transport_flavor)
            except (BrokenPipeError, KeyboardInterrupt):
                break
            except ValueError as exc:
                logger.error("收到非法 MCP framing：{}", exc)
                self._write_message(
                    stdout,
                    self._error_response(None, -32600, str(exc)),
                    self._transport_flavor or "framed",
                )
                return 1
            if request_text is None:
                break
            if not request_text:
                continue
            self._transport_flavor = transport_flavor

            try:
                request_obj = cast(JsonObject, json.loads(request_text))
            except json.JSONDecodeError as exc:
                response = self._error_response(None, -32700, f"非法 JSON：{exc}")
                self._write_message(stdout, response, self._transport_flavor or "framed")
                continue

            response = self._dispatch(request_obj)
            if response is None:
                continue
            self._write_message(stdout, response, self._transport_flavor or "framed")

        logger.info("stdio MCP 服务已退出")
        return 0

    def dispatch_message(self, request_obj: JsonObject) -> JsonObject | None:
        """公开单条消息分发入口。

        这个方法主要服务于单元测试和未来可能的嵌入式宿主，
        避免测试代码直接依赖私有 `_dispatch`，同时也让协议层语义更清晰。
        """
        return self._dispatch(request_obj)

    @staticmethod
    def read_message(
        stream: BinaryIO,
        current_flavor: TransportFlavor | None = None,
    ) -> tuple[str | None, TransportFlavor]:
        """公开消息读取入口，便于测试 framing 兼容性。"""
        return StdioMcpServer._read_message(stream, current_flavor)

    @staticmethod
    def write_message(
        stream: BinaryIO,
        payload: JsonObject,
        transport_flavor: TransportFlavor = "framed",
    ) -> None:
        """公开消息写出入口，便于测试不同 transport flavor。"""
        StdioMcpServer._write_message(stream, payload, transport_flavor)

    def _dispatch(self, request_obj: JsonObject) -> JsonObject | None:
        method = request_obj.get("method")
        request_id = request_obj.get("id")
        if not isinstance(method, str):
            return self._error_response(request_id, -32600, "请求缺少 method")

        if method == "initialize":
            return self._ok_response(
                request_id,
                {
                    "protocolVersion": self._identity.protocol_version,
                    "capabilities": {
                        "tools": {},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {},
                    },
                    "serverInfo": {
                        "name": self._identity.server_name,
                        "version": self._identity.server_version,
                    },
                },
            )

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return self._ok_response(request_id, {})

        if method == "tools/list":
            return self._ok_response(
                request_id,
                {"tools": [cast(JsonValue, item) for item in self._tools.list_tools()]},
            )

        if method == "tools/call":
            params = request_obj.get("params")
            if not isinstance(params, dict):
                return self._error_response(request_id, -32602, "tools/call 缺少 params")
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                return self._error_response(request_id, -32602, "tools/call 参数格式错误")
            typed_arguments = cast(JsonObject, arguments)
            log_tool_call_started(tool_name, request_id, typed_arguments)
            started_at = perf_counter()
            try:
                result = self._tools.call(tool_name, typed_arguments)
            except Exception as exc:
                duration_ms = (perf_counter() - started_at) * 1000.0
                log_tool_call_exception(tool_name, request_id, typed_arguments, exc, duration_ms=duration_ms)
                return self._ok_response(
                    request_id,
                    cast(
                        JsonObject,
                        {
                        "content": [{"type": "text", "text": str(exc)}],
                        "structuredContent": {
                            "status": "error",
                            "source": tool_name,
                            "warnings": [],
                            "error": cast(
                                JsonObject,
                                build_error_info(
                                code="tool_execution_exception",
                                message=str(exc),
                                details={"tool": tool_name},
                                next_steps=["检查文件日志中的完整异常链", "确认当前数据库状态与工具前置条件"],
                                ),
                            ),
                            "data": None,
                        },
                        "isError": True,
                        },
                    ),
                )
            duration_ms = (perf_counter() - started_at) * 1000.0
            log_tool_call_finished(tool_name, request_id, typed_arguments, result, duration_ms=duration_ms)
            return self._ok_response(request_id, self._tools.format_tool_result(result))

        if method == "resources/list":
            return self._ok_response(
                request_id,
                {"resources": [cast(JsonValue, item) for item in self._resources.list_resources()]},
            )

        if method == "resources/templates/list":
            return self._ok_response(
                request_id,
                {"resourceTemplates": [cast(JsonValue, item) for item in self._resources.list_templates()]},
            )

        if method == "resources/read":
            params = request_obj.get("params")
            if not isinstance(params, dict):
                return self._error_response(request_id, -32602, "resources/read 缺少 params")
            uri = params.get("uri")
            if not isinstance(uri, str):
                return self._error_response(request_id, -32602, "resources/read 需要字符串 uri")
            typed_params = cast(JsonObject, params)
            log_resource_read_started(uri, request_id, typed_params)
            started_at = perf_counter()
            try:
                contents, is_error = self._resources.read(uri, typed_params)
            except Exception as exc:
                duration_ms = (perf_counter() - started_at) * 1000.0
                log_resource_read_exception(uri, request_id, typed_params, exc, duration_ms=duration_ms)
                payload = build_result(
                    status="error",
                    source=f"resource.read:{uri}",
                    data=None,
                    error=cast(
                        JsonObject,
                        build_error_info(
                        code="resource_read_failed",
                        message=str(exc),
                        details={"uri": uri},
                        next_steps=["检查资源 URI 是否存在", "必要时查看文件日志中的异常上下文"],
                        ),
                    ),
                )
                log_resource_read_finished(
                    uri,
                    request_id,
                    typed_params,
                    duration_ms=duration_ms,
                    is_error=True,
                    payload_summary=cast(JsonValue, payload),
                )
                return self._ok_response(
                    request_id,
                    cast(
                        JsonObject,
                        {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(payload, ensure_ascii=False),
                            }
                        ],
                        "isError": True,
                        },
                    ),
                )
            duration_ms = (perf_counter() - started_at) * 1000.0
            payload_summary: JsonValue = {}
            if contents:
                raw_text = contents[0]["text"]
                try:
                    payload_summary = cast(JsonValue, json.loads(raw_text))
                except json.JSONDecodeError:
                    payload_summary = raw_text
            log_resource_read_finished(
                uri,
                request_id,
                typed_params,
                duration_ms=duration_ms,
                is_error=is_error,
                payload_summary=payload_summary,
            )
            return self._ok_response(
                request_id,
                {"contents": [cast(JsonValue, item) for item in contents], "isError": is_error},
            )

        return self._error_response(request_id, -32601, f"未知方法：{method}")

    @staticmethod
    def _ok_response(request_id: JsonValue, result: JsonObject) -> JsonObject:
        return normalize_json_object({"jsonrpc": "2.0", "result": result, "id": request_id})

    @staticmethod
    def _error_response(request_id: JsonValue, code: int, message: str) -> JsonObject:
        return normalize_json_object(
            {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id,
            }
        )

    @staticmethod
    def _read_message(
        stream: BinaryIO,
        current_flavor: TransportFlavor | None = None,
    ) -> tuple[str | None, TransportFlavor]:
        """读取一条 stdio 消息，同时兼容 framing 与逐行 JSON 两种实现。"""
        if current_flavor == "line_json":
            return StdioMcpServer._read_line_json_message(stream), "line_json"
        if current_flavor == "framed":
            return StdioMcpServer._read_framed_message(stream), "framed"

        first_line = stream.readline()
        if not first_line:
            return None, "framed"

        stripped = first_line.strip()
        if not stripped:
            return StdioMcpServer._read_message(stream, None)

        if stripped.startswith((b"{", b"[")):
            return first_line.decode("utf-8").strip(), "line_json"

        return StdioMcpServer._read_framed_message(stream, first_line), "framed"

    @staticmethod
    def _read_line_json_message(stream: BinaryIO) -> str | None:
        """读取一条逐行 JSON 消息。"""
        while True:
            line = stream.readline()
            if not line:
                return None
            decoded = line.decode("utf-8").strip()
            if decoded:
                return decoded

    @staticmethod
    def _read_framed_message(stream: BinaryIO, first_line: bytes | None = None) -> str | None:
        """按 Content-Length framing 读取一条消息。"""
        headers: dict[str, str] = {}
        line = first_line
        while True:
            if line is None:
                line = stream.readline()
            if not line:
                return None
            if line in {b"\r\n", b"\n"}:
                break
            decoded = line.decode("utf-8").strip()
            if not decoded:
                break
            if ":" not in decoded:
                raise ValueError(f"非法 MCP 头：{decoded}")
            key, value = decoded.split(":", 1)
            headers[key.strip().lower()] = value.strip()
            line = None

        content_length_text = headers.get("content-length")
        if content_length_text is None:
            raise ValueError("MCP 消息缺少 Content-Length")
        content_length = int(content_length_text)
        payload = stream.read(content_length)
        if len(payload) != content_length:
            raise ValueError("MCP 消息体长度不足")
        return payload.decode("utf-8")

    @staticmethod
    def _write_message(
        stream: BinaryIO,
        payload: JsonObject,
        transport_flavor: TransportFlavor = "framed",
    ) -> None:
        """按指定 stdio 传输格式写出一条消息。"""
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if transport_flavor == "line_json":
            stream.write(encoded + b"\n")
            stream.flush()
            return
        header = f"Content-Length: {len(encoded)}\r\nContent-Type: application/json\r\n\r\n".encode("ascii")
        stream.write(header)
        stream.write(encoded)
        stream.flush()
