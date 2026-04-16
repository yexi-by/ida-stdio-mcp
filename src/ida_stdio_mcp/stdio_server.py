"""原生 stdio MCP 服务。"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import cast

from loguru import logger

from .models import JsonObject
from .tool_registry import ToolRegistry


@dataclass(slots=True, frozen=True)
class ServerIdentity:
    """服务身份信息。"""

    protocol_version: str
    server_name: str
    server_version: str


class StdioMcpServer:
    """最小可用的 stdio MCP 服务器。"""

    def __init__(self, registry: ToolRegistry, identity: ServerIdentity) -> None:
        self._registry = registry
        self._identity = identity

    def serve(self) -> int:
        """进入 stdio 主循环。"""
        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        logger.info("stdio MCP 服务已启动")

        while True:
            try:
                raw = stdin.readline()
            except (BrokenPipeError, KeyboardInterrupt):
                break
            if not raw:
                break

            request_text = raw.decode("utf-8").strip()
            if not request_text:
                continue

            try:
                request_obj = cast(JsonObject, json.loads(request_text))
            except json.JSONDecodeError as exc:
                response = self._error_response(None, -32700, f"非法 JSON：{exc}")
                stdout.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
                stdout.flush()
                continue

            response = self._dispatch(request_obj)
            if response is None:
                continue
            stdout.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            stdout.flush()

        logger.info("stdio MCP 服务已退出")
        return 0

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

        if method == "tools/list":
            return self._ok_response(request_id, {"tools": self._registry.list_tools()})

        if method == "tools/call":
            params = request_obj.get("params")
            if not isinstance(params, dict):
                return self._error_response(request_id, -32602, "tools/call 缺少 params")
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                return self._error_response(request_id, -32602, "tools/call 参数格式错误")
            try:
                result = self._registry.call(tool_name, cast(JsonObject, arguments))
            except Exception as exc:
                logger.exception("工具调用失败：{}", tool_name)
                return self._ok_response(
                    request_id,
                    {
                        "content": [{"type": "text", "text": str(exc)}],
                        "structuredContent": {
                            "status": "error",
                            "source": tool_name,
                            "warnings": [],
                            "error": str(exc),
                            "data": None,
                        },
                        "isError": True,
                    },
                )
            return self._ok_response(request_id, self._registry.format_tool_result(result))

        return self._error_response(request_id, -32601, f"未知方法：{method}")

    @staticmethod
    def _ok_response(request_id: object, result: JsonObject) -> JsonObject:
        return {"jsonrpc": "2.0", "result": result, "id": request_id}

    @staticmethod
    def _error_response(request_id: object, code: int, message: str) -> JsonObject:
        return {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": request_id,
        }
