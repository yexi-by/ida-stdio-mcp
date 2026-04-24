"""协议与门控单元测试。"""

from __future__ import annotations

import json
import unittest
from io import BytesIO
from pathlib import Path
from typing import cast

from loguru import logger

from ida_stdio_mcp.config import load_config
from ida_stdio_mcp.models import JsonObject, JsonValue
from ida_stdio_mcp.service import build_service
from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.stdio_server import ServerIdentity, StdioMcpServer


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
    """覆盖 initialize、tools/list、resources/list 与门控。"""

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[2]

    @staticmethod
    def _resource_payload(response: JsonObject) -> JsonObject:
        result = expect_object(response["result"], name="response.result")
        contents = expect_list(result["contents"], name="response.result.contents")
        first = expect_object(contents[0], name="response.result.contents[0]")
        raw_text = expect_string(first.get("text"), name="resource.text")
        payload = json.loads(raw_text)
        if not isinstance(payload, dict):
            raise AssertionError("资源文本解码后不是对象")
        return cast(JsonObject, payload)

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
            if isinstance(tool.get("name"), str)
        ]
        self.assertIn("describe_capabilities", tool_names)
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

        health = server.dispatch_message({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "health", "arguments": {}}})
        self.assertIsNotNone(health)
        assert health is not None
        health_result = expect_object(health["result"], name="health.result")
        structured = expect_object(health_result["structuredContent"], name="health.structured")
        health_data = expect_object(structured["data"], name="health.data")
        feature_gates = expect_object(health_data.get("feature_gates"), name="health.feature_gates")
        self.assertTrue(bool(feature_gates.get("unsafe")))
        self.assertTrue(bool(feature_gates.get("debugger")))

    def test_describe_capabilities_returns_keyword_rich_overview(self) -> None:
        """能力总览工具应返回可检索、可导航的分类与任务摘要。"""
        config = load_config(self._repo_root() / "setting.toml")
        service = build_service(
            HeadlessRuntime(),
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

        response = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "describe_capabilities",
                    "arguments": {"focus": "反编译伪代码", "include_examples": True},
                },
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        response_result = expect_object(response["result"], name="describe.result")
        structured = expect_object(response_result["structuredContent"], name="describe.structured")
        self.assertEqual(structured["status"], "ok")
        data = expect_object(structured["data"], name="describe.data")
        summary = expect_string(data.get("summary"), name="describe.data.summary")
        self.assertIn("反编译伪代码", summary)
        self.assertIn("交叉引用", summary)
        self.assertIn("导出分析结果", summary)

        categories = expect_list(data.get("categories"), name="describe.data.categories")
        self.assertGreater(len(categories), 0)
        category_titles = [
            str(item.get("title"))
            for item in categories
            if isinstance(item, dict) and isinstance(item.get("title"), str)
        ]
        self.assertIn("上手入口与能力总览", category_titles)
        self.assertIn("函数、伪代码与调用关系", category_titles)

        tasks = expect_list(data.get("notable_tasks"), name="describe.data.notable_tasks")
        self.assertGreater(len(tasks), 0)
        task_titles = [
            str(item.get("title"))
            for item in tasks
            if isinstance(item, dict) and isinstance(item.get("title"), str)
        ]
        self.assertIn("读取反编译伪代码 / 高层表示", task_titles)

        entrypoints = expect_list(data.get("recommended_entrypoints"), name="describe.data.recommended_entrypoints")
        self.assertGreater(len(entrypoints), 0)
        by_name = {
            str(item["name"]): item
            for item in entrypoints
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
        self.assertIn("describe_capabilities", by_name)
        self.assertIn("summarize_binary", by_name)
        self.assertIn("decompile_function", by_name)
        self.assertIn("export_full_analysis", by_name)
        decompile_entry = expect_object(by_name["decompile_function"], name="describe.entrypoints.decompile_function")
        self.assertIn("input_example", decompile_entry)

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

        initialize = server.dispatch_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIsNotNone(initialize)
        assert initialize is not None
        initialize_result = expect_object(initialize["result"], name="initialize.result")
        server_info = expect_object(initialize_result["serverInfo"], name="initialize.serverInfo")
        self.assertEqual(server_info["name"], "ida-stdio-mcp")

        ping = server.dispatch_message({"jsonrpc": "2.0", "id": 99, "method": "ping", "params": {}})
        self.assertIsNotNone(ping)
        assert ping is not None
        self.assertEqual(ping["result"], {})

        tools = server.dispatch_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        self.assertIsNotNone(tools)
        assert tools is not None
        tools_result = expect_object(tools["result"], name="tools.list.result")
        tool_items = expect_list(tools_result["tools"], name="tools.list.tools")
        self.assertGreater(len(tool_items), 10)

        resources = server.dispatch_message({"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}})
        self.assertIsNotNone(resources)
        assert resources is not None
        resources_result = expect_object(resources["result"], name="resources.list.result")
        resource_items = expect_list(resources_result["resources"], name="resources.list.resources")
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
        self.assertIn("ida://capability-matrix", uris)
        self.assertIn("ida://docs/tools", uris)

        templates = server.dispatch_message({"jsonrpc": "2.0", "id": 4, "method": "resources/templates/list", "params": {}})
        self.assertIsNotNone(templates)
        assert templates is not None
        template_result = expect_object(templates["result"], name="resources.templates.result")
        template_items = expect_list(template_result["resourceTemplates"], name="resources.templates.items")
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
        self.assertIn("ida://docs/tool/{name}", template_uris)

        capability_resource = next(item for item in resource_items if isinstance(item, dict) and item.get("uri") == "ida://capability-matrix")
        self.assertEqual(capability_resource.get("scope"), "global")
        self.assertFalse(bool(capability_resource.get("requiresSession", True)))

        function_resource = next(item for item in resource_items if isinstance(item, dict) and item.get("uri") == "ida://functions")
        self.assertEqual(function_resource.get("scope"), "session")
        self.assertTrue(bool(function_resource.get("requiresSession", False)))

        health = server.dispatch_message({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "health", "arguments": {}}})
        self.assertIsNotNone(health)
        assert health is not None
        health_result = expect_object(health["result"], name="health.result")
        structured = expect_object(health_result["structuredContent"], name="health.structured")
        self.assertEqual(structured["status"], "ok")
        content_items = expect_list(health_result["content"], name="health.content")
        self.assertGreater(len(content_items), 0)
        first = expect_object(content_items[0], name="health.content[0]")
        raw_text = expect_string(first.get("text"), name="health.content[0].text")
        json.loads(raw_text)

    def test_resource_contract_is_uniform_and_capability_matrix_is_global(self) -> None:
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

        capability = server.dispatch_message({"jsonrpc": "2.0", "id": 31, "method": "resources/read", "params": {"uri": "ida://capability-matrix"}})
        self.assertIsNotNone(capability)
        assert capability is not None
        capability_payload = self._resource_payload(capability)
        self.assertEqual(capability_payload.get("status"), "ok")
        capability_data = capability_payload.get("data")
        self.assertIsInstance(capability_data, dict)
        assert isinstance(capability_data, dict)
        self.assertIn("service", capability_data)
        self.assertIn("resource_scopes", capability_data)

        functions = server.dispatch_message({"jsonrpc": "2.0", "id": 32, "method": "resources/read", "params": {"uri": "ida://functions"}})
        self.assertIsNotNone(functions)
        assert functions is not None
        functions_payload = self._resource_payload(functions)
        self.assertEqual(functions_payload.get("status"), "error")
        functions_error = functions_payload.get("error")
        self.assertIsInstance(functions_error, dict)
        assert isinstance(functions_error, dict)
        self.assertEqual(functions_error.get("code"), "session_required")
        function_details = functions_error.get("details")
        self.assertIsInstance(function_details, dict)
        assert isinstance(function_details, dict)
        self.assertTrue(bool(function_details.get("requires_session")))

    def test_deactivate_binary_without_session_is_explicit_error(self) -> None:
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

        response = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {"name": "deactivate_binary", "arguments": {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        response_result = expect_object(response["result"], name="deactivate.result")
        structured = expect_object(response_result["structuredContent"], name="deactivate.structured")
        self.assertEqual(structured.get("status"), "error")
        error = expect_object(structured.get("error"), name="deactivate.error")
        self.assertEqual(error.get("code"), "session_required")
        details = expect_object(error.get("details"), name="deactivate.details")
        self.assertTrue(bool(details.get("requires_session")))

    def test_current_binary_without_session_is_explicit_empty_state(self) -> None:
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

        response = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {"name": "current_binary", "arguments": {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        response_result = expect_object(response["result"], name="current.result")
        structured = expect_object(response_result["structuredContent"], name="current.structured")
        self.assertEqual(structured["status"], "ok")
        data = expect_object(structured["data"], name="current.data")
        self.assertIn("session", data)
        self.assertIsNone(data["session"])

    def test_all_tools_expose_explicit_input_schema(self) -> None:
        config = load_config(self._repo_root() / "setting.toml")
        service = build_service(
            HeadlessRuntime(),
            config,
            allow_unsafe=True,
            allow_debugger=True,
            profile_path=None,
        )
        tools = service.tools.list_tools()
        self.assertGreater(len(tools), 50)

        by_name: dict[str, JsonObject] = {}
        for item in tools:
            self.assertIsInstance(item, dict)
            assert isinstance(item, dict)
            raw_name = item.get("name")
            self.assertIsInstance(raw_name, str)
            assert isinstance(raw_name, str)
            by_name[raw_name] = item

            schema = expect_object(item.get("inputSchema"), name=f"{raw_name}.inputSchema")
            self._assert_schema_is_explicit(schema, tool_name=raw_name)
            self.assertIn("inputExample", item, msg=f"{raw_name} 缺少最小输入示例")

        self.assertEqual(
            set(schema_properties(by_name["describe_capabilities"], name="describe_capabilities").keys()),
            {"focus", "include_examples"},
        )
        self.assertFalse(bool(by_name["describe_capabilities"]["requiresSession"]))
        self.assertFalse(bool(by_name["describe_capabilities"]["requiresContext"]))
        self.assertEqual(
            by_name["describe_capabilities"]["inputExample"],
            {"focus": "反编译伪代码", "include_examples": True},
        )
        self.assertEqual(
            set(schema_properties(by_name["open_binary"], name="open_binary").keys()),
            {"path", "run_auto_analysis", "session_id"},
        )
        self.assertFalse(bool(by_name["current_binary"]["requiresSession"]))
        self.assertTrue(bool(by_name["warmup"]["requiresSession"]))
        self.assertTrue(bool(by_name["list_functions"]["requiresSession"]))
        self.assertEqual(by_name["warmup"]["inputExample"], {"session_id": "sess-001"})
        self.assertEqual(
            by_name["list_functions"]["inputExample"],
            {"session_id": "sess-001", "filter": "main", "count": 20},
        )
        self.assertIn("emptyStateBehavior", by_name["current_binary"])
        self.assertIn("preconditions", by_name["warmup"])
        self.assertEqual(
            set(schema_properties(by_name["get_function"], name="get_function").keys()),
            {"addr", "query", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["query_imports"], name="query_imports").keys()),
            {"module", "filter", "offset", "count", "limit", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["find_strings"], name="find_strings").keys()),
            {"pattern", "offset", "count", "limit", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["summarize_binary"], name="summarize_binary").keys()),
            {"function_limit", "string_limit", "import_limit_per_category", "include_strings", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["survey_binary"], name="survey_binary").keys()),
            {"include_strings", "string_limit", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["find_string_usage"], name="find_string_usage").keys()),
            {"pattern", "addr", "max_strings", "max_usages", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["export_full_analysis"], name="export_full_analysis").keys()),
            {"function_limit", "string_limit", "global_limit", "import_limit", "type_limit", "struct_limit", "include_decompile", "include_asm", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["trace_data_flow"], name="trace_data_flow").keys()),
            {"addr", "direction", "max_depth", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["analyze_component"], name="analyze_component").keys()),
            {"query", "max_depth", "include_asm", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["query_instructions"], name="query_instructions").keys()),
            {"pattern", "max_hits", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["read_ints"], name="read_ints").keys()),
            {"items", "session_id"},
        )
        self.assertEqual(
            set(schema_properties(by_name["debug_write_memory"], name="debug_write_memory").keys()),
            {"addr", "hex"},
        )
        input_example = by_name["open_binary"]["inputExample"]
        self.assertIsInstance(input_example, dict)
        assert isinstance(input_example, dict)
        self.assertIn("path", input_example)
        set_comments_input = expect_object(by_name["set_comments"]["inputSchema"], name="set_comments.inputSchema")
        set_comments_properties = expect_object(set_comments_input["properties"], name="set_comments.properties")
        set_comments_schema = expect_object(set_comments_properties["items"], name="set_comments.items")
        comment_item_schema = expect_object(set_comments_schema["items"], name="set_comments.items[]")
        self.assertEqual(
            set(expect_object(comment_item_schema["properties"], name="set_comments.items[].properties").keys()),
            {"addr", "comment", "repeatable"},
        )
        discovery_keywords: dict[str, tuple[str, ...]] = {
            "describe_capabilities": ("反编译伪代码", "交叉引用", "导出分析结果"),
            "summarize_binary": ("样本摘要", "binary summary", "关键字符串"),
            "decompile_function": ("反编译伪代码", "Hex-Rays"),
            "get_xrefs_to": ("交叉引用", "xref"),
            "list_strings": ("字符串",),
            "find_string_usage": ("字符串", "xref", "grep"),
            "read_struct": ("结构体", "UDT"),
            "query_types": ("类型", "函数原型"),
            "export_full_analysis": ("完整分析结果", "full analysis bundle"),
            "export_functions": ("导出函数分析结果", "AI"),
            "rename_symbols": ("重命名符号",),
            "patch_assembly": ("修改汇编", "补丁"),
            "patch_bytes": ("字节补丁", "十六进制"),
            "evaluate_python": ("IDAPython", "高级自定义分析"),
        }
        for tool_name, keywords in discovery_keywords.items():
            description = expect_string(by_name[tool_name].get("description"), name=f"{tool_name}.description")
            for keyword in keywords:
                self.assertIn(keyword, description, msg=f"{tool_name} 描述缺少关键词：{keyword}")

    def test_invalid_arguments_return_machine_fixable_error(self) -> None:
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

        response = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "get_function", "arguments": {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        response_result = expect_object(response["result"], name="invalid.result")
        structured = expect_object(response_result["structuredContent"], name="invalid.structured")
        self.assertEqual(structured["status"], "error")
        error = expect_object(structured["error"], name="invalid.error")
        self.assertEqual(error["code"], "invalid_arguments")
        details = expect_object(error["details"], name="invalid.details")
        self.assertEqual(details["tool"], "get_function")
        self.assertTrue(str(details["path"]).startswith("arguments"))

    def test_tool_and_resource_calls_are_written_to_debug_log(self) -> None:
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
                    "id": 61,
                    "method": "tools/call",
                    "params": {"name": "health", "arguments": {}},
                }
            )
            self.assertIsNotNone(tool_response)

            resource_response = server.dispatch_message(
                {
                    "jsonrpc": "2.0",
                    "id": 62,
                    "method": "resources/read",
                    "params": {"uri": "ida://capability-matrix"},
                }
            )
            self.assertIsNotNone(resource_response)
        finally:
            logger.remove(sink_id)

        merged = "\n".join(rendered_logs)
        self.assertIn("工具调用开始：health", merged)
        self.assertIn("工具调用完成：health", merged)
        self.assertIn("tool_call_start", merged)
        self.assertIn("tool_call_finish", merged)
        self.assertIn("资源读取开始：ida://capability-matrix", merged)
        self.assertIn("资源读取完成：ida://capability-matrix", merged)
        self.assertIn("resource_read_start", merged)
        self.assertIn("resource_read_finish", merged)

    def test_stdio_message_framing_uses_content_length(self) -> None:
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

    def test_stdio_line_json_mode_is_supported_for_cherry_studio(self) -> None:
        payload: JsonObject = {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}}
        encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        stream = BytesIO(encoded)
        request_text, flavor = StdioMcpServer.read_message(stream)
        self.assertEqual(request_text, encoded.decode("utf-8").strip())
        self.assertEqual(flavor, "line_json")

        output = BytesIO()
        StdioMcpServer.write_message(
            output,
            {"jsonrpc": "2.0", "id": 7, "result": {}},
            "line_json",
        )
        self.assertEqual(
            output.getvalue().decode("utf-8"),
            json.dumps({"jsonrpc": "2.0", "id": 7, "result": {}}, ensure_ascii=False) + "\n",
        )

    def test_isolated_context_mode_exposes_context_schema_and_resource_scope(self) -> None:
        config = load_config(self._repo_root() / "setting.toml")
        runtime = HeadlessRuntime(isolated_contexts=True)
        service = build_service(
            runtime,
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

        tools = service.tools.list_tools()
        by_name = {
            str(item["name"]): item
            for item in tools
            if isinstance(item.get("name"), str)
        }
        self.assertTrue(bool(by_name["open_binary"]["requiresContext"]))
        self.assertTrue(bool(by_name["list_binaries"]["requiresContext"]))
        self.assertFalse(bool(by_name["health"]["requiresContext"]))
        self.assertIn("context_id", schema_properties(by_name["open_binary"], name="open_binary"))
        self.assertIn("context_id", schema_properties(by_name["health"], name="health"))
        self.assertEqual(
            by_name["open_binary"]["inputExample"],
            {
                "path": "D:/samples/sample.exe",
                "run_auto_analysis": True,
                "session_id": "sess-001",
                "context_id": "agent-001",
            },
        )

        resources = service.resources.list_resources()
        by_uri = {
            str(item["uri"]): item
            for item in resources
            if isinstance(item.get("uri"), str)
        }
        sessions_resource = by_uri["ida://sessions"]
        self.assertEqual(sessions_resource.get("scope"), "context")
        self.assertFalse(bool(sessions_resource.get("requiresSession")))
        self.assertTrue(bool(sessions_resource.get("requiresContext")))
        functions_resource = by_uri["ida://functions"]
        self.assertEqual(functions_resource.get("scope"), "session")
        self.assertTrue(bool(functions_resource.get("requiresSession")))
        self.assertTrue(bool(functions_resource.get("requiresContext")))

        no_context = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 51,
                "method": "resources/read",
                "params": {"uri": "ida://sessions"},
            }
        )
        self.assertIsNotNone(no_context)
        assert no_context is not None
        no_context_payload = self._resource_payload(no_context)
        self.assertEqual(no_context_payload.get("status"), "error")
        no_context_error = expect_object(no_context_payload.get("error"), name="isolated.sessions.error")
        self.assertEqual(no_context_error.get("code"), "session_required")

        with_context = server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 52,
                "method": "resources/read",
                "params": {"uri": "ida://sessions", "context_id": "agent-1"},
            }
        )
        self.assertIsNotNone(with_context)
        assert with_context is not None
        with_context_payload = self._resource_payload(with_context)
        self.assertEqual(with_context_payload.get("status"), "ok")
        self.assertEqual(with_context_payload.get("data"), [])

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
            return


if __name__ == "__main__":
    unittest.main()
