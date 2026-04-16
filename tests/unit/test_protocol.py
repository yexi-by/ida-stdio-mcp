"""stdio 协议层单元测试。"""

from __future__ import annotations

import json
import unittest

from ida_stdio_mcp.models import JsonObject
from ida_stdio_mcp.result import build_result
from ida_stdio_mcp.stdio_server import ServerIdentity, StdioMcpServer
from ida_stdio_mcp.tool_registry import ToolRegistry, ToolSpec


class ProtocolTests(unittest.TestCase):
    """覆盖 initialize/tools/list/tools/call 的最小协议行为。"""

    def setUp(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="hello",
                description="返回问候。",
                input_schema={"type": "object", "properties": {}, "required": []},
                output_schema={"type": "object"},
                handler=lambda _arguments: build_result(
                    status="ok",
                    source="unit",
                    data={"message": "hello"},
                ),
            )
        )
        self.server = StdioMcpServer(
            registry=registry,
            identity=ServerIdentity(
                protocol_version="2025-06-18",
                server_name="ida-stdio-mcp",
                server_version="0.1.0",
            ),
        )

    def test_initialize(self) -> None:
        request: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        response = self.server._dispatch(request)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["result"]["serverInfo"]["name"], "ida-stdio-mcp")

    def test_tools_list(self) -> None:
        request: JsonObject = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        response = self.server._dispatch(request)
        self.assertIsNotNone(response)
        assert response is not None
        tools = response["result"]["tools"]
        self.assertEqual(len(tools), 1)
        self.assertEqual(tools[0]["name"], "hello")

    def test_tools_call(self) -> None:
        request: JsonObject = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "hello", "arguments": {}},
        }
        response = self.server._dispatch(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]["structuredContent"]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["message"], "hello")
        json.loads(response["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
