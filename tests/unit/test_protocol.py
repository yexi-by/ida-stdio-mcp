"""V2 协议与门控单元测试。"""

from __future__ import annotations

import json
import unittest
from io import BytesIO
from pathlib import Path
from typing import cast

from loguru import logger

from ida_stdio_mcp.config import load_config
from ida_stdio_mcp.models import JsonObject, JsonValue, ToolSurface
from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.service import build_service
from ida_stdio_mcp.stdio_server import ServerIdentity, StdioMcpServer

REMOVED_V1_TOOLS = {
    "describe_capabilities",
    "health",
    "warmup",
    "open_binary",
    "close_binary",
    "switch_binary",
    "list_binaries",
    "current_binary",
    "save_binary",
    "deactivate_binary",
    "analyze_directory",
    "survey_binary",
    "summarize_binary",
    "find_string_usage",
    "get_xrefs_to",
    "get_xrefs_to_field",
}
SLIM_TOOLS = {
    "get_workspace_state",
    "open_target",
    "triage_binary",
    "investigate_string",
    "explain_function",
    "trace_input_to_check",
    "decompile_function",
    "export_report",
    "save_workspace",
    "close_target",
}


def expect_object(value: JsonValue, *, name: str) -> JsonObject:
    """把 JSON 值收窄为对象。"""
    if not isinstance(value, dict):
        raise AssertionError(f"{name} 应为对象，实际为 {type(value).__name__}")
    return value


def expect_list(value: JsonValue, *, name: str) -> list[JsonValue]:
    """把 JSON 值收窄为数组。"""
    if not isinstance(value, list):
        raise AssertionError(f"{name} 应为数组，实际为 {type(value).__name__}")
    return value


def expect_string(value: JsonValue, *, name: str) -> str:
    """把 JSON 值收窄为字符串。"""
    if not isinstance(value, str):
        raise AssertionError(f"{name} 应为字符串，实际为 {type(value).__name__}")
    return value


def schema_properties(tool: JsonObject, *, name: str) -> JsonObject:
    """读取工具 inputSchema 的 properties。"""
    input_schema = expect_object(tool["inputSchema"], name=f"{name}.inputSchema")
    return expect_object(input_schema["properties"], name=f"{name}.inputSchema.properties")


class ProtocolTests(unittest.TestCase):
    """覆盖 V2 initialize、tools/list、prompts、resources 与门控。"""

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[2]

    def _service(self, *, tool_surface: ToolSurface = "slim", unsafe: bool = False, debugger: bool = False, isolated: bool = False) -> tuple[StdioMcpServer, list[JsonObject]]:
        """构造测试服务并返回工具列表。"""
        config = load_config(self._repo_root() / "setting.toml")
        service = build_service(
            HeadlessRuntime(isolated_contexts=isolated),
            allow_unsafe=unsafe,
            allow_debugger=debugger,
            tool_surface=tool_surface,
            profile_path=None,
        )
        server = StdioMcpServer(
            tools=service.tools,
            resources=service.resources,
            prompts=service.prompts,
            identity=ServerIdentity(
                protocol_version=config.server.protocol_version,
                server_name=config.server.server_name,
                server_version=config.server.server_version,
            ),
        )
        return server, service.tools.list_tools()

    @staticmethod
    def _tool_names(tools: list[JsonObject]) -> set[str]:
        """返回工具名集合。"""
        return {str(tool["name"]) for tool in tools if isinstance(tool.get("name"), str)}

    @staticmethod
    def _resource_payload(response: JsonObject) -> JsonObject:
        """读取 resources/read 的 JSON envelope。"""
        result = expect_object(response["result"], name="response.result")
        contents = expect_list(result["contents"], name="response.result.contents")
        first = expect_object(contents[0], name="response.result.contents[0]")
        raw_text = expect_string(first.get("text"), name="resource.text")
        payload = json.loads(raw_text)
        if not isinstance(payload, dict):
            raise AssertionError("资源文本解码后不是对象")
        return cast(JsonObject, payload)

    def test_default_surface_is_v2_slim_and_has_no_legacy_tools(self) -> None:
        """默认工具面只暴露 V2 高层入口。"""
        _, tools = self._service()
        tool_names = self._tool_names(tools)
        self.assertEqual(tool_names, SLIM_TOOLS)
        self.assertFalse(tool_names & REMOVED_V1_TOOLS)

    def test_full_and_expert_surfaces_do_not_reenable_legacy_tools(self) -> None:
        """full/expert 也不能把旧 MCP 工具面作为兼容层暴露回来。"""
        _, full_tools = self._service(tool_surface="full", unsafe=True, debugger=True)
        full_names = self._tool_names(full_tools)
        self.assertFalse(full_names & REMOVED_V1_TOOLS)
        self.assertIn("get_import_at", full_names)
        self.assertIn("microcode_summary", full_names)
        self.assertIn("microcode_def_use", full_names)
        self.assertNotIn("microcode_experiment", full_names)

        _, expert_tools = self._service(tool_surface="expert", unsafe=True, debugger=True)
        expert_names = self._tool_names(expert_tools)
        self.assertFalse(expert_names & REMOVED_V1_TOOLS)
        self.assertIn("microcode_experiment", expert_names)

    def test_initialize_and_prompts_are_real_capabilities(self) -> None:
        """initialize 声明 prompts 时必须能 list/get。"""
        server, _ = self._service(tool_surface="full")
        initialize = server.dispatch_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIsNotNone(initialize)
        assert initialize is not None
        initialize_result = expect_object(initialize["result"], name="initialize.result")
        capabilities = expect_object(initialize_result["capabilities"], name="initialize.capabilities")
        self.assertIn("prompts", capabilities)

        prompts = server.dispatch_message({"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}})
        self.assertIsNotNone(prompts)
        assert prompts is not None
        prompt_items = expect_list(expect_object(prompts["result"], name="prompts.result")["prompts"], name="prompts")
        prompt_names = {str(item["name"]) for item in prompt_items if isinstance(item, dict) and isinstance(item.get("name"), str)}
        self.assertIn("triage-native", prompt_names)
        self.assertIn("microcode-investigation", prompt_names)

        prompt = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "prompts/get",
                "params": {"name": "string-led-investigation", "arguments": {"pattern": "CreateFile"}},
            }
        )
        self.assertIsNotNone(prompt)
        assert prompt is not None
        messages = expect_list(expect_object(prompt["result"], name="prompt.result")["messages"], name="prompt.messages")
        first = expect_object(messages[0], name="prompt.messages[0]")
        content = expect_object(first["content"], name="prompt.content")
        self.assertIn("CreateFile", expect_string(content.get("text"), name="prompt.text"))

    def test_workspace_state_is_ai_recoverable_without_ida(self) -> None:
        """无 IDA 环境也应返回 V2 可修复状态，而不是回退 V1 健康检查。"""
        server, _ = self._service()
        response = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "get_workspace_state", "arguments": {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        structured = expect_object(expect_object(response["result"], name="workspace.result")["structuredContent"], name="workspace.structured")
        self.assertEqual(structured["status"], "ok")
        data = expect_object(structured["data"], name="workspace.data")
        self.assertEqual(data["sessions"], [])
        self.assertEqual(data["recommended_next_tools"], ["open_target"])
        self.assertIn("runtime_ready", data)

    def test_tool_schema_is_explicit_and_v2_entrypoints_have_expected_fields(self) -> None:
        """工具 schema 仍保持显式、稳定、无顶层组合关键字。"""
        _, tools = self._service(tool_surface="full", unsafe=True, debugger=True)
        by_name = {str(item["name"]): item for item in tools if isinstance(item.get("name"), str)}
        self.assertGreater(len(by_name), 40)
        self.assertFalse(set(by_name) & REMOVED_V1_TOOLS)

        for name, item in by_name.items():
            schema = expect_object(item.get("inputSchema"), name=f"{name}.inputSchema")
            self._assert_schema_is_explicit(schema, tool_name=name)
            self.assertIn("inputExample", item, msg=f"{name} 缺少最小输入示例")

        self.assertEqual(set(schema_properties(by_name["open_target"], name="open_target")), {"path", "run_auto_analysis", "session_id"})
        self.assertEqual(
            set(schema_properties(by_name["triage_binary"], name="triage_binary")),
            {"function_limit", "string_limit", "import_limit_per_category", "include_strings", "session_id"},
        )
        self.assertEqual(set(schema_properties(by_name["get_import_at"], name="get_import_at")), {"addr", "session_id"})
        self.assertEqual(set(schema_properties(by_name["microcode_summary"], name="microcode_summary")), {"addr", "query", "max_instructions", "session_id"})

    def test_invalid_arguments_return_machine_fixable_error(self) -> None:
        """底层工具参数错误仍返回统一机器可修复 envelope。"""
        server, _ = self._service(tool_surface="full")
        response = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "get_function", "arguments": {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        structured = expect_object(expect_object(response["result"], name="invalid.result")["structuredContent"], name="invalid.structured")
        self.assertEqual(structured["status"], "error")
        error = expect_object(structured["error"], name="invalid.error")
        self.assertEqual(error["code"], "invalid_arguments")
        details = expect_object(error["details"], name="invalid.details")
        self.assertEqual(details["tool"], "get_function")

    def test_resource_contract_is_uniform_and_global_resources_do_not_need_session(self) -> None:
        """资源 envelope 保持统一。"""
        server, _ = self._service(tool_surface="full")
        capability = server.dispatch_message({"jsonrpc": "2.0", "id": 6, "method": "resources/read", "params": {"uri": "ida://capability-matrix"}})
        self.assertIsNotNone(capability)
        assert capability is not None
        capability_payload = self._resource_payload(capability)
        self.assertEqual(capability_payload.get("status"), "ok")

        functions = server.dispatch_message({"jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": {"uri": "ida://functions"}})
        self.assertIsNotNone(functions)
        assert functions is not None
        functions_payload = self._resource_payload(functions)
        self.assertEqual(functions_payload.get("status"), "error")
        error = expect_object(functions_payload.get("error"), name="functions.error")
        self.assertEqual(error.get("code"), "session_required")

    def test_isolated_context_schema_uses_v2_names(self) -> None:
        """隔离模式只在 V2 工具上暴露 context_id。"""
        _, tools = self._service(tool_surface="full", isolated=True)
        by_name = {str(item["name"]): item for item in tools if isinstance(item.get("name"), str)}
        self.assertTrue(bool(by_name["open_target"]["requiresContext"]))
        self.assertTrue(bool(by_name["get_workspace_state"]["requiresContext"]))
        self.assertIn("context_id", schema_properties(by_name["open_target"], name="open_target"))
        self.assertIn("context_id", schema_properties(by_name["get_workspace_state"], name="get_workspace_state"))
        self.assertNotIn("open_binary", by_name)

    def test_stdio_message_framing_uses_content_length(self) -> None:
        """framed transport 使用 Content-Length。"""
        payload: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        stream = BytesIO(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
        request_text, flavor = StdioMcpServer.read_message(stream)
        self.assertEqual(request_text, encoded.decode("utf-8"))
        self.assertEqual(flavor, "framed")

        output = BytesIO()
        StdioMcpServer.write_message(output, {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
        blob = output.getvalue()
        self.assertIn(b"Content-Length:", blob)
        self.assertIn(b"Content-Type: application/json", blob)
        self.assertIn(b"\r\n\r\n", blob)

    def test_stdio_line_json_mode_is_supported(self) -> None:
        """逐行 JSON transport 仍可用。"""
        payload: JsonObject = {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}}
        encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        stream = BytesIO(encoded)
        request_text, flavor = StdioMcpServer.read_message(stream)
        self.assertEqual(request_text, encoded.decode("utf-8").strip())
        self.assertEqual(flavor, "line_json")

    def test_tool_and_resource_calls_are_written_to_debug_log(self) -> None:
        """日志测试使用 V2 工具名。"""
        server, _ = self._service(tool_surface="full")
        rendered_logs: list[str] = []
        sink_id = logger.add(
            rendered_logs.append,
            level="DEBUG",
            format="{level} | {message} | {extra[event]} | {extra[tool_name]} | {extra[resource_uri]} | {extra[status]} | {extra[details]}",
        )
        try:
            tool_response = server.dispatch_message(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {"name": "get_workspace_state", "arguments": {}},
                }
            )
            self.assertIsNotNone(tool_response)
            resource_response = server.dispatch_message(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "resources/read",
                    "params": {"uri": "ida://capability-matrix"},
                }
            )
            self.assertIsNotNone(resource_response)
        finally:
            logger.remove(sink_id)

        merged = "\n".join(rendered_logs)
        self.assertIn("工具调用开始：get_workspace_state", merged)
        self.assertIn("工具调用完成：get_workspace_state", merged)
        self.assertIn("资源读取开始：ida://capability-matrix", merged)
        self.assertIn("资源读取完成：ida://capability-matrix", merged)

    def _assert_schema_is_explicit(self, schema: JsonObject, *, tool_name: str) -> None:
        """递归校验 tool schema 已明确暴露参数。"""
        schema_type = schema.get("type")
        one_of = schema.get("oneOf")

        if schema_type == "object":
            properties = expect_object(schema.get("properties"), name=f"{tool_name}.properties")
            self.assertIn("additionalProperties", schema, msg=f"{tool_name} 的对象 schema 缺少 additionalProperties")
            self.assertFalse(bool(schema.get("additionalProperties")), msg=f"{tool_name} 的对象 schema 不应允许额外参数")
            if "." not in tool_name:
                for invalid_key in ("oneOf", "anyOf", "allOf", "enum", "not", "x-required-any-of"):
                    self.assertNotIn(invalid_key, schema, msg=f"{tool_name} 的顶层 schema 不应包含 {invalid_key}")
            for property_name, property_schema in properties.items():
                self.assertIsInstance(property_name, str)
                self.assertIsInstance(property_schema, dict, msg=f"{tool_name}.{property_name} schema 非对象")
                assert isinstance(property_schema, dict)
                self._assert_schema_is_explicit(property_schema, tool_name=f"{tool_name}.{property_name}")
            return

        if schema_type == "array":
            items = expect_object(schema.get("items"), name=f"{tool_name}.items")
            self._assert_schema_is_explicit(items, tool_name=f"{tool_name}[]")
            return

        if isinstance(one_of, list):
            self.assertGreater(len(one_of), 0, msg=f"{tool_name} 的 oneOf 为空")
            for index, option in enumerate(one_of):
                self.assertIsInstance(option, dict, msg=f"{tool_name}.oneOf[{index}] 非对象")
                assert isinstance(option, dict)
                self._assert_schema_is_explicit(cast(JsonObject, option), tool_name=f"{tool_name}.oneOf[{index}]")


if __name__ == "__main__":
    unittest.main()
