"""协议与门控单元测试。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from ida_stdio_mcp.config import load_config
from ida_stdio_mcp.service import build_service
from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.stdio_server import ServerIdentity, StdioMcpServer


class ProtocolTests(unittest.TestCase):
    """覆盖 initialize、tools/list、resources/list 与门控。"""

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[2]

    def test_build_service_hides_unsafe_and_debugger_by_default(self) -> None:
        config = load_config(self._repo_root() / "setting.toml")
        service = build_service(
            HeadlessRuntime(),
            config,
            allow_unsafe=False,
            allow_debugger=False,
            profile_path=None,
        )
        tool_names = [
            str(tool["name"])
            for tool in service.tools.list_tools()
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        ]
        self.assertIn("open_binary", tool_names)
        self.assertIn("survey_binary", tool_names)
        self.assertNotIn("set_comments", tool_names)
        self.assertNotIn("debug_start", tool_names)

    def test_health_uses_runtime_feature_gates_instead_of_static_config(self) -> None:
        config = load_config(self._repo_root() / "setting.toml")
        runtime = HeadlessRuntime()
        service = build_service(
            runtime,
            config,
            allow_unsafe=True,
            allow_debugger=True,
            profile_path=None,
        )
        server = StdioMcpServer(
            tools=service.tools,
            resources=service.resources,
            identity=ServerIdentity(
                protocol_version=config.server.protocol_version,
                server_name=config.server.server_name,
                server_version=config.server.server_version,
            ),
        )

        health = server._dispatch({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "health", "arguments": {}}})
        self.assertIsNotNone(health)
        assert health is not None
        structured = health["result"]["structuredContent"]
        self.assertIsInstance(structured, dict)
        assert isinstance(structured, dict)
        health_data = structured["data"]
        self.assertIsInstance(health_data, dict)
        assert isinstance(health_data, dict)
        feature_gates = health_data.get("feature_gates")
        self.assertIsInstance(feature_gates, dict)
        assert isinstance(feature_gates, dict)
        self.assertTrue(bool(feature_gates.get("unsafe")))
        self.assertTrue(bool(feature_gates.get("debugger")))

    def test_stdio_dispatch_supports_tools_and_resources(self) -> None:
        config = load_config(self._repo_root() / "setting.toml")
        service = build_service(
            HeadlessRuntime(),
            config,
            allow_unsafe=False,
            allow_debugger=False,
            profile_path=None,
        )
        server = StdioMcpServer(
            tools=service.tools,
            resources=service.resources,
            identity=ServerIdentity(
                protocol_version=config.server.protocol_version,
                server_name=config.server.server_name,
                server_version=config.server.server_version,
            ),
        )

        initialize = server._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIsNotNone(initialize)
        assert initialize is not None
        self.assertEqual(initialize["result"]["serverInfo"]["name"], "ida-stdio-mcp")

        tools = server._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        self.assertIsNotNone(tools)
        assert tools is not None
        self.assertGreater(len(tools["result"]["tools"]), 10)

        resources = server._dispatch({"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}})
        self.assertIsNotNone(resources)
        assert resources is not None
        resource_items = resources["result"]["resources"]
        self.assertIsInstance(resource_items, list)
        assert isinstance(resource_items, list)
        uris = [
            str(item["uri"])
            for item in resource_items
            if isinstance(item, dict) and isinstance(item.get("uri"), str)
        ]
        self.assertIn("ida://sessions", uris)
        self.assertIn("ida://idb/metadata", uris)
        self.assertIn("ida://idb/capabilities", uris)
        self.assertIn("ida://survey", uris)
        self.assertIn("ida://functions", uris)
        self.assertIn("ida://strings", uris)
        self.assertIn("ida://imports/categories", uris)
        self.assertIn("ida://callgraph/summary", uris)
        self.assertIn("ida://managed/summary", uris)
        self.assertIn("ida://managed/types", uris)
        self.assertIn("ida://managed/namespaces", uris)
        self.assertIn("ida://functions/profiles", uris)

        templates = server._dispatch({"jsonrpc": "2.0", "id": 4, "method": "resources/templates/list", "params": {}})
        self.assertIsNotNone(templates)
        assert templates is not None
        template_items = templates["result"]["resourceTemplates"]
        self.assertIsInstance(template_items, list)
        assert isinstance(template_items, list)
        self.assertGreater(len(template_items), 0)
        template_uris = [
            str(item["uriTemplate"])
            for item in template_items
            if isinstance(item, dict) and isinstance(item.get("uriTemplate"), str)
        ]
        self.assertIn("ida://function/{query}", template_uris)
        self.assertIn("ida://stack-frame/{addr}", template_uris)
        self.assertIn("ida://callgraph/{root}", template_uris)
        self.assertIn("ida://type/{name}", template_uris)
        self.assertIn("ida://data-flow/{addr}", template_uris)
        self.assertIn("ida://function-profile/{query}", template_uris)
        self.assertIn("ida://decompile/{query}", template_uris)
        self.assertIn("ida://basic-blocks/{addr}", template_uris)
        self.assertIn("ida://managed/method/{query}", template_uris)

        health = server._dispatch({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "health", "arguments": {}}})
        self.assertIsNotNone(health)
        assert health is not None
        self.assertEqual(health["result"]["structuredContent"]["status"], "ok")
        content_items = health["result"]["content"]
        self.assertIsInstance(content_items, list)
        assert isinstance(content_items, list)
        self.assertGreater(len(content_items), 0)
        first = content_items[0]
        self.assertIsInstance(first, dict)
        assert isinstance(first, dict)
        raw_text = first.get("text")
        self.assertIsInstance(raw_text, str)
        assert isinstance(raw_text, str)
        json.loads(raw_text)


if __name__ == "__main__":
    unittest.main()
