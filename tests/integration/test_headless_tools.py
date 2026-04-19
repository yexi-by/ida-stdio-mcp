"""真实 idalib headless 集成测试。"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from typing import cast

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


def expect_optional_object(value: JsonValue, *, name: str) -> JsonObject:
    """把可空 JSON 值收窄为对象。"""
    if not isinstance(value, dict):
        raise AssertionError(f"{name} 应为对象，实际为 {type(value).__name__}")
    return value


class HeadlessToolTests(unittest.TestCase):
    """覆盖多会话、资源读取、目录分析与危险工具。"""

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[2]

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = cls._repo_root()
        cls.elf_fixture = Path(
            os.environ.get(
                "IDA_STDIO_MCP_TEST_BINARY",
                str(cls.repo_root / "tests" / "fixtures" / "crackme03.elf"),
            )
        ).resolve()
        cls.pe_fixture = (cls.repo_root / "tests" / "fixtures" / "minimal_pe.exe").resolve()
        cls.mixed_fixture = (cls.repo_root / "tests" / "fixtures" / "mixed").resolve()

    def setUp(self) -> None:
        self.config = load_config(self.repo_root / "setting.toml")
        self.runtime = HeadlessRuntime()
        self.service = build_service(
            self.runtime,
            self.config,
            allow_unsafe=True,
            allow_debugger=True,
            profile_path=None,
        )
        self.server = StdioMcpServer(
            tools=self.service.tools,
            resources=self.service.resources,
            identity=ServerIdentity(
                protocol_version=self.config.server.protocol_version,
                server_name=self.config.server.server_name,
                server_version=self.config.server.server_version,
            ),
        )

    def tearDown(self) -> None:
        self.runtime.shutdown()

    def _call_tool(self, name: str, arguments: JsonObject | None = None) -> JsonObject:
        response = self.server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        response_result = expect_object(response["result"], name="tool.result")
        return expect_object(response_result["structuredContent"], name="tool.structured")

    def _read_resource(self, uri: str, params: JsonObject | None = None) -> JsonObject:
        request_params: JsonObject = {"uri": uri}
        if params is not None:
            request_params.update(params)
        response = self.server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": request_params,
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        return expect_object(response["result"], name="resource.result")

    def test_multi_session_open_switch_close_and_resources(self) -> None:
        opened_elf = self._call_tool("open_binary", {"path": str(self.elf_fixture), "session_id": "elf"})
        self.assertEqual(opened_elf["status"], "ok")
        opened_pe = self._call_tool("open_binary", {"path": str(self.pe_fixture), "session_id": "pe"})
        self.assertEqual(opened_pe["status"], "ok")

        listing = self._call_tool("list_binaries")
        self.assertEqual(listing["status"], "ok")
        data = listing["data"]
        self.assertIsInstance(data, list)
        assert isinstance(data, list)
        session_ids = [
            str(item["session_id"])
            for item in data
            if isinstance(item, dict) and isinstance(item.get("session_id"), str)
        ]
        self.assertIn("elf", session_ids)
        self.assertIn("pe", session_ids)

        switched = self._call_tool("switch_binary", {"session_id": "elf"})
        self.assertEqual(switched["status"], "ok")

        current_resource = self._read_resource("ida://session/current")
        contents = expect_list(current_resource["contents"], name="current_resource.contents")
        self.assertGreater(len(contents), 0)
        first = expect_object(contents[0], name="current_resource.contents[0]")
        text = expect_string(first.get("text"), name="current_resource.contents[0].text")
        self.assertIn("elf", text)

        metadata = self._read_resource("ida://idb/metadata")
        self.assertFalse(bool(metadata.get("isError", False)))

        close_pe = self._call_tool("close_binary", {"session_id": "pe"})
        self.assertEqual(close_pe["status"], "ok")

    def test_core_read_tools_and_unsafe_write_tool(self) -> None:
        self._call_tool("open_binary", {"path": str(self.elf_fixture), "session_id": "elf-main"})

        survey = self._call_tool("survey_binary", {"session_id": "elf-main"})
        self.assertIn(survey["status"], ("ok", "degraded"))

        summary = self._call_tool("summarize_binary", {"session_id": "elf-main", "function_limit": 8, "string_limit": 8})
        self.assertEqual(summary["status"], "ok")
        summary_data = summary["data"]
        self.assertIsInstance(summary_data, dict)
        assert isinstance(summary_data, dict)
        self.assertIn("interesting_functions", summary_data)
        self.assertIn("interesting_strings", summary_data)
        self.assertIn("recommended_next_tools", summary_data)

        functions = self._call_tool("list_functions", {"filter": "main", "count": 20, "session_id": "elf-main"})
        self.assertEqual(functions["status"], "ok")

        single = self._call_tool("get_function", {"query": "main", "session_id": "elf-main"})
        self.assertEqual(single["status"], "ok")

        decompile = self._call_tool("decompile_function", {"addr": "main", "session_id": "elf-main"})
        self.assertIn(decompile["status"], ("ok", "degraded", "unsupported"))

        disasm = self._call_tool("disassemble_function", {"addr": "main", "session_id": "elf-main"})
        self.assertEqual(disasm["status"], "ok")

        strings_page = self._call_tool("list_strings", {"limit": 20, "session_id": "elf-main"})
        self.assertEqual(strings_page["status"], "ok")
        strings_data = strings_page["data"]
        self.assertIsInstance(strings_data, list)
        assert isinstance(strings_data, list)
        self.assertGreater(len(strings_data), 0)
        first_string = strings_data[0]
        self.assertIsInstance(first_string, dict)
        assert isinstance(first_string, dict)
        first_string_addr = first_string.get("addr")
        self.assertIsInstance(first_string_addr, str)
        assert isinstance(first_string_addr, str)

        string_usage = self._call_tool("find_string_usage", {"addr": first_string_addr, "max_usages": 20, "session_id": "elf-main"})
        self.assertEqual(string_usage["status"], "ok")
        string_usage_data = string_usage["data"]
        self.assertIsInstance(string_usage_data, dict)
        assert isinstance(string_usage_data, dict)
        self.assertIn("matches", string_usage_data)
        self.assertIn("usages", string_usage_data)
        self.assertIn("functions", string_usage_data)

        comment = self._call_tool(
            "set_comments",
            {
                "items": [{"addr": "main", "comment": "ida-stdio-mcp 集成测试注释", "repeatable": False}],
                "session_id": "elf-main",
            },
        )
        self.assertEqual(comment["status"], "ok")
        comment_data = comment["data"]
        self.assertIsInstance(comment_data, dict)
        assert isinstance(comment_data, dict)
        self.assertTrue(bool(comment_data.get("dirty")))
        self.assertEqual(comment_data.get("writeback_kind"), "comment")
        self.assertFalse(bool(comment_data.get("persistent_after_save")))

        saved = self._call_tool("save_binary", {"session_id": "elf-main"})
        self.assertEqual(saved["status"], "ok")
        saved_data = saved["data"]
        self.assertIsInstance(saved_data, dict)
        assert isinstance(saved_data, dict)
        self.assertFalse(bool(saved_data.get("dirty")))
        self.assertTrue(bool(saved_data.get("persistent_after_save")))

        capabilities = self._read_resource("ida://idb/capabilities")
        self.assertFalse(bool(capabilities.get("isError", False)))

        capability_matrix = self._read_resource("ida://capability-matrix")
        self.assertFalse(bool(capability_matrix.get("isError", False)))

        survey_resource = self._read_resource("ida://survey")
        self.assertFalse(bool(survey_resource.get("isError", False)))

        functions_resource = self._read_resource("ida://functions")
        self.assertFalse(bool(functions_resource.get("isError", False)))

        strings_resource = self._read_resource("ida://strings")
        self.assertFalse(bool(strings_resource.get("isError", False)))

        imports_categories = self._read_resource("ida://imports/categories")
        self.assertFalse(bool(imports_categories.get("isError", False)))

        callgraph_summary = self._read_resource("ida://callgraph/summary")
        self.assertFalse(bool(callgraph_summary.get("isError", False)))

        managed_summary = self._read_resource("ida://managed/summary")
        self.assertFalse(bool(managed_summary.get("isError", False)))

        managed_types = self._read_resource("ida://managed/types")
        self.assertFalse(bool(managed_types.get("isError", False)))

        managed_namespaces = self._read_resource("ida://managed/namespaces")
        self.assertFalse(bool(managed_namespaces.get("isError", False)))

        tool_docs = self._read_resource("ida://docs/tools")
        self.assertFalse(bool(tool_docs.get("isError", False)))

        function_profiles = self._read_resource("ida://functions/profiles")
        self.assertFalse(bool(function_profiles.get("isError", False)))

        function_resource = self._read_resource("ida://function/main")
        self.assertFalse(bool(function_resource.get("isError", False)))

        function_profile_resource = self._read_resource("ida://function-profile/main")
        self.assertFalse(bool(function_profile_resource.get("isError", False)))

        decompile_resource = self._read_resource("ida://decompile/main")
        self.assertFalse(bool(decompile_resource.get("isError", False)))

        basic_blocks_resource = self._read_resource("ida://basic-blocks/main")
        self.assertFalse(bool(basic_blocks_resource.get("isError", False)))

        stack_frame_resource = self._read_resource("ida://stack-frame/main")
        self.assertFalse(bool(stack_frame_resource.get("isError", False)))

        callgraph_resource = self._read_resource("ida://callgraph/main")
        self.assertFalse(bool(callgraph_resource.get("isError", False)))

        data_flow_resource = self._read_resource("ida://data-flow/main")
        self.assertFalse(bool(data_flow_resource.get("isError", False)))

        tool_doc_resource = self._read_resource("ida://docs/tool/get_function")
        self.assertFalse(bool(tool_doc_resource.get("isError", False)))

        exported_json = self._call_tool(
            "export_functions",
            {"items": ["main"], "format": "json", "session_id": "elf-main"},
        )
        self.assertEqual(exported_json["status"], "ok")
        exported_json_data = exported_json["data"]
        self.assertIsInstance(exported_json_data, list)
        assert isinstance(exported_json_data, list)
        self.assertGreater(len(exported_json_data), 0)
        first_export = exported_json_data[0]
        self.assertIsInstance(first_export, dict)
        assert isinstance(first_export, dict)
        self.assertEqual(first_export.get("format"), "json")
        json_functions = first_export.get("functions")
        self.assertIsInstance(json_functions, list)
        assert isinstance(json_functions, list)
        self.assertGreater(len(json_functions), 0)
        json_function = json_functions[0]
        self.assertIsInstance(json_function, dict)
        assert isinstance(json_function, dict)
        self.assertIn("asm", json_function)
        self.assertIn("code", json_function)
        self.assertIn("xrefs", json_function)
        self.assertIn("stack_frame", json_function)

        exported_header = self._call_tool(
            "export_functions",
            {"items": ["main"], "format": "c_header", "session_id": "elf-main"},
        )
        self.assertEqual(exported_header["status"], "ok")
        exported_header_data = exported_header["data"]
        self.assertIsInstance(exported_header_data, list)
        assert isinstance(exported_header_data, list)
        header_first = exported_header_data[0]
        self.assertIsInstance(header_first, dict)
        assert isinstance(header_first, dict)
        self.assertEqual(header_first.get("format"), "c_header")
        self.assertIsInstance(header_first.get("content"), str)

        exported_prototypes = self._call_tool(
            "export_functions",
            {"items": ["main"], "format": "prototypes", "session_id": "elf-main"},
        )
        self.assertEqual(exported_prototypes["status"], "ok")
        exported_prototypes_data = exported_prototypes["data"]
        self.assertIsInstance(exported_prototypes_data, list)
        assert isinstance(exported_prototypes_data, list)
        proto_first = exported_prototypes_data[0]
        self.assertIsInstance(proto_first, dict)
        assert isinstance(proto_first, dict)
        self.assertEqual(proto_first.get("format"), "prototypes")
        proto_functions = proto_first.get("functions")
        self.assertIsInstance(proto_functions, list)

        full_export = self._call_tool(
            "export_full_analysis",
            {"session_id": "elf-main", "function_limit": 5, "string_limit": 20, "include_asm": False},
        )
        self.assertEqual(full_export["status"], "ok")
        full_export_data = full_export["data"]
        self.assertIsInstance(full_export_data, dict)
        assert isinstance(full_export_data, dict)
        self.assertEqual(full_export_data.get("bundle_format"), "full_analysis_v1")
        self.assertIn("summary", full_export_data)
        self.assertIn("functions", full_export_data)
        self.assertIn("types", full_export_data)

    def test_extended_type_stack_patch_and_trace_tools(self) -> None:
        self._call_tool("open_binary", {"path": str(self.elf_fixture), "session_id": "elf-extended"})

        type_name = f"__Stage2Struct_{os.getpid()}__"
        stack_name = f"__stage2_stack_{os.getpid()}__"
        declaration = f"""
            struct {type_name} {{
                int field1;
                char field2;
            }};
        """

        declared = self._call_tool(
            "declare_types",
            {"items": [declaration], "session_id": "elf-extended"},
        )
        self.assertEqual(declared["status"], "ok")

        queried_types = self._call_tool(
            "query_types",
            {"filter": type_name, "session_id": "elf-extended"},
        )
        self.assertEqual(queried_types["status"], "ok")
        queried_type_rows = queried_types["data"]
        self.assertIsInstance(queried_type_rows, list)
        assert isinstance(queried_type_rows, list)
        self.assertTrue(
            any(isinstance(item, dict) and item.get("name") == type_name for item in queried_type_rows)
        )
        self.assertTrue(
            all(
                isinstance(item, dict)
                and type_name.lower()
                in (
                    f"{item.get('name', '')} {item.get('declaration_or_signature', '')}"
                ).lower()
                for item in queried_type_rows
            )
        )

        type_resource = self._read_resource(f"ida://type/{type_name}")
        self.assertFalse(bool(type_resource.get("isError", False)))

        struct_resource = self._call_tool(
            "read_struct",
            {"name": type_name, "session_id": "elf-extended"},
        )
        self.assertEqual(struct_resource["status"], "ok")

        inferred = self._call_tool(
            "infer_types",
            {"items": ["main"], "session_id": "elf-extended"},
        )
        self.assertEqual(inferred["status"], "ok")
        inferred_data = inferred["data"]
        self.assertIsInstance(inferred_data, dict)
        assert isinstance(inferred_data, dict)
        self.assertTrue(bool(inferred_data.get("dirty")))
        inferred_rows = inferred_data.get("result")
        self.assertIsInstance(inferred_rows, list)
        assert isinstance(inferred_rows, list)
        self.assertGreater(len(inferred_rows), 0)
        first_inferred = inferred_rows[0]
        self.assertIsInstance(first_inferred, dict)
        assert isinstance(first_inferred, dict)
        self.assertIsInstance(first_inferred.get("inferred_type"), str)
        self.assertIsInstance(first_inferred.get("method"), str)

        declared_stack = self._call_tool(
            "declare_stack_variables",
            {
                "items": [{"addr": "main", "name": stack_name, "offset": -8, "type": "int"}],
                "session_id": "elf-extended",
            },
        )
        self.assertEqual(declared_stack["status"], "ok")

        frame_after_create = self._call_tool(
            "get_stack_frame",
            {"addr": "main", "session_id": "elf-extended"},
        )
        self.assertEqual(frame_after_create["status"], "ok")
        frame_after_create_data = frame_after_create["data"]
        self.assertIsInstance(frame_after_create_data, dict)
        assert isinstance(frame_after_create_data, dict)
        created_members = frame_after_create_data.get("members")
        self.assertIsInstance(created_members, list)
        assert isinstance(created_members, list)
        self.assertTrue(
            any(isinstance(item, dict) and item.get("name") == stack_name for item in created_members)
        )

        deleted_stack = self._call_tool(
            "delete_stack_variables",
            {"items": [{"addr": "main", "name": stack_name}], "session_id": "elf-extended"},
        )
        self.assertEqual(deleted_stack["status"], "ok")

        frame_after_delete = self._call_tool(
            "get_stack_frame",
            {"addr": "main", "session_id": "elf-extended"},
        )
        self.assertEqual(frame_after_delete["status"], "ok")
        frame_after_delete_data = frame_after_delete["data"]
        self.assertIsInstance(frame_after_delete_data, dict)
        assert isinstance(frame_after_delete_data, dict)
        deleted_members = frame_after_delete_data.get("members")
        self.assertIsInstance(deleted_members, list)
        assert isinstance(deleted_members, list)
        self.assertFalse(
            any(isinstance(item, dict) and item.get("name") == stack_name for item in deleted_members)
        )

        original_bytes = self._call_tool(
            "read_bytes",
            {"addrs": ["0x125e"], "size": 2, "session_id": "elf-extended"},
        )
        self.assertEqual(original_bytes["status"], "ok")
        original_rows = original_bytes["data"]
        self.assertIsInstance(original_rows, list)
        assert isinstance(original_rows, list)
        first_bytes = original_rows[0]
        self.assertIsInstance(first_bytes, dict)
        assert isinstance(first_bytes, dict)
        original_hex = first_bytes.get("hex")
        self.assertIsInstance(original_hex, str)

        try:
            patched = self._call_tool(
                "patch_assembly",
                {
                    "items": [{"addr": "0x125e", "asm": "sub eax, eax"}],
                    "session_id": "elf-extended",
                },
            )
            self.assertEqual(patched["status"], "ok")

            changed_bytes = self._call_tool(
                "read_bytes",
                {"addrs": ["0x125e"], "size": 2, "session_id": "elf-extended"},
            )
            self.assertEqual(changed_bytes["status"], "ok")
            changed_rows = changed_bytes["data"]
            self.assertIsInstance(changed_rows, list)
            assert isinstance(changed_rows, list)
            changed_first = changed_rows[0]
            self.assertIsInstance(changed_first, dict)
            assert isinstance(changed_first, dict)
            self.assertEqual(changed_first.get("hex"), "29c0")

            decompile_after_patch = self._call_tool(
                "decompile_function",
                {"query": "main", "session_id": "elf-extended"},
            )
            self.assertIn(decompile_after_patch["status"], ("ok", "degraded", "unsupported"))
            decompile_after_patch_data = decompile_after_patch["data"]
            self.assertIsInstance(decompile_after_patch_data, dict)
            assert isinstance(decompile_after_patch_data, dict)
            if decompile_after_patch["status"] == "ok":
                decompile_text = decompile_after_patch_data.get("text")
                self.assertIsInstance(decompile_text, str)
                assert isinstance(decompile_text, str)
                self.assertNotEqual(decompile_text.strip(), "None")
        finally:
            self._call_tool(
                "patch_bytes",
                {
                    "items": [{"addr": "0x125e", "hex": original_hex}],
                    "session_id": "elf-extended",
                },
            )

        traced = self._call_tool(
            "trace_data_flow",
            {"addr": "main", "direction": "forward", "max_depth": 2, "session_id": "elf-extended"},
        )
        self.assertEqual(traced["status"], "ok")
        traced_data = traced["data"]
        self.assertIsInstance(traced_data, dict)
        assert isinstance(traced_data, dict)
        self.assertIsInstance(traced_data.get("nodes"), list)
        self.assertIsInstance(traced_data.get("edges"), list)
        self.assertIsInstance(traced_data.get("summary"), dict)
        traced_edges = traced_data.get("edges")
        self.assertIsInstance(traced_edges, list)
        assert isinstance(traced_edges, list)
        if traced_edges:
            first_edge = traced_edges[0]
            self.assertIsInstance(first_edge, dict)
            assert isinstance(first_edge, dict)
            self.assertIn("xref_type", first_edge)
            self.assertIn("edge_kind", first_edge)
            self.assertIn("source", first_edge)
            self.assertIn("resolution", first_edge)
        traced_summary = traced_data.get("summary")
        self.assertIsInstance(traced_summary, dict)
        assert isinstance(traced_summary, dict)
        self.assertIn("edge_kind_histogram", traced_summary)
        self.assertIn("xref_type_histogram", traced_summary)

        callgraph = self._call_tool(
            "build_callgraph",
            {"query": "main", "max_depth": 2, "session_id": "elf-extended"},
        )
        self.assertEqual(callgraph["status"], "ok")
        callgraph_data = callgraph["data"]
        self.assertIsInstance(callgraph_data, dict)
        assert isinstance(callgraph_data, dict)
        self.assertIn("external_targets", callgraph_data)

        component = self._call_tool(
            "analyze_component",
            {"query": "main", "max_depth": 2, "session_id": "elf-extended"},
        )
        self.assertEqual(component["status"], "ok")

    def test_debug_registers_all_threads_without_debuggee_is_cleanly_unsupported(self) -> None:
        result = self._call_tool("debug_registers_all_threads")
        self.assertEqual(result["status"], "unsupported")
        result_data = result["data"]
        self.assertIsInstance(result_data, dict)
        assert isinstance(result_data, dict)
        reason = result_data.get("reason")
        self.assertIsInstance(reason, str)
        assert isinstance(reason, str)
        self.assertNotIn("尚未实现", reason)
        warnings = result["warnings"]
        self.assertIsInstance(warnings, list)
        assert isinstance(warnings, list)
        self.assertFalse(any("暂未实现" in str(item) for item in warnings))

    def test_analyze_directory_restores_previous_session(self) -> None:
        self._call_tool("open_binary", {"path": str(self.elf_fixture), "session_id": "restore-target"})
        before = self._call_tool("current_binary")
        self.assertEqual(before["status"], "ok")

        analyzed = self._call_tool(
            "analyze_directory",
            {
                "path": str(self.mixed_fixture),
                "recursive": True,
                "max_candidates": 5,
                "max_deep_analysis": 2,
                "prefer_entry_binary": True,
                "prefer_user_code": True,
                "scoring_profile": "entry_only",
            },
        )
        self.assertIn(analyzed["status"], ("ok", "degraded"))
        summary = expect_object(analyzed["data"], name="analyze_directory.data")
        self.assertIn("summary", summary)
        summary_block = expect_object(summary["summary"], name="analyze_directory.summary")
        policy = expect_object(summary_block.get("policy"), name="analyze_directory.summary.policy")
        self.assertEqual(policy.get("scoring_profile"), "entry_only")

        after = self._call_tool("current_binary")
        self.assertEqual(after["status"], "ok")
        after_data = after["data"]
        self.assertIsInstance(after_data, dict)
        assert isinstance(after_data, dict)
        current_session = after_data.get("session")
        self.assertIsInstance(current_session, dict)
        assert isinstance(current_session, dict)
        self.assertEqual(current_session.get("session_id"), "restore-target")

    def test_query_imports_filter_works(self) -> None:
        self._call_tool("open_binary", {"path": str(self.pe_fixture), "session_id": "pe-imports"})
        imports_result = self._call_tool("list_imports", {"session_id": "pe-imports"})
        self.assertEqual(imports_result["status"], "ok")
        imports_data = imports_result["data"]
        self.assertIsInstance(imports_data, list)
        assert isinstance(imports_data, list)
        if not imports_data:
            self.skipTest("当前最小 PE fixture 不包含可枚举导入，跳过 query_imports 过滤验证")
        first_import = imports_data[0]
        self.assertIsInstance(first_import, dict)
        assert isinstance(first_import, dict)
        import_name = first_import.get("name")
        self.assertIsInstance(import_name, str)
        assert isinstance(import_name, str)

        filtered = self._call_tool("query_imports", {"filter": import_name, "session_id": "pe-imports"})
        self.assertEqual(filtered["status"], "ok")
        filtered_data = filtered["data"]
        self.assertIsInstance(filtered_data, list)
        assert isinstance(filtered_data, list)
        self.assertGreater(len(filtered_data), 0)
        self.assertTrue(
            all(isinstance(item, dict) and item.get("name") == import_name for item in filtered_data)
        )

    def test_isolated_contexts_keep_sessions_and_resources_separate(self) -> None:
        isolated_runtime = HeadlessRuntime(isolated_contexts=True)
        isolated_service = build_service(
            isolated_runtime,
            self.config,
            allow_unsafe=True,
            allow_debugger=True,
            profile_path=None,
        )
        isolated_server = StdioMcpServer(
            tools=isolated_service.tools,
            resources=isolated_service.resources,
            identity=ServerIdentity(
                protocol_version=self.config.server.protocol_version,
                server_name=self.config.server.server_name,
                server_version=self.config.server.server_version,
            ),
        )

        def call(name: str, arguments: JsonObject) -> JsonObject:
            response = isolated_server.dispatch_message(
                {
                    "jsonrpc": "2.0",
                    "id": 90,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )
            self.assertIsNotNone(response)
            assert response is not None
            response_result = expect_object(response["result"], name="isolated.tool.result")
            return expect_object(response_result["structuredContent"], name="isolated.tool.structured")

        def read(uri: str, params: JsonObject) -> JsonObject:
            response = isolated_server.dispatch_message(
                {
                    "jsonrpc": "2.0",
                    "id": 91,
                    "method": "resources/read",
                    "params": {"uri": uri, **params},
                }
            )
            self.assertIsNotNone(response)
            assert response is not None
            return expect_object(response["result"], name="isolated.resource.result")

        try:
            self.assertEqual(
                call(
                    "open_binary",
                    {"path": str(self.elf_fixture), "session_id": "agent1-elf", "context_id": "agent-1"},
                )["status"],
                "ok",
            )
            self.assertEqual(
                call(
                    "open_binary",
                    {"path": str(self.pe_fixture), "session_id": "agent1-pe", "context_id": "agent-1"},
                )["status"],
                "ok",
            )
            self.assertEqual(
                call(
                    "open_binary",
                    {"path": str(self.elf_fixture), "session_id": "agent2-elf", "context_id": "agent-2"},
                )["status"],
                "ok",
            )

            agent1_sessions = call("list_binaries", {"context_id": "agent-1"})
            self.assertEqual(agent1_sessions["status"], "ok")
            agent1_data = agent1_sessions["data"]
            self.assertIsInstance(agent1_data, list)
            assert isinstance(agent1_data, list)
            self.assertEqual(
                {str(item["session_id"]) for item in agent1_data if isinstance(item, dict)},
                {"agent1-elf", "agent1-pe"},
            )

            agent2_sessions = call("list_binaries", {"context_id": "agent-2"})
            self.assertEqual(agent2_sessions["status"], "ok")
            agent2_data = agent2_sessions["data"]
            self.assertIsInstance(agent2_data, list)
            assert isinstance(agent2_data, list)
            self.assertEqual(
                {str(item["session_id"]) for item in agent2_data if isinstance(item, dict)},
                {"agent2-elf"},
            )

            self.assertEqual(
                expect_optional_object(
                    expect_object(call("current_binary", {"context_id": "agent-1"})["data"], name="agent1.current")["session"],
                    name="agent1.current.session",
                )["session_id"],
                "agent1-pe",
            )
            self.assertEqual(
                expect_optional_object(
                    expect_object(call("current_binary", {"context_id": "agent-2"})["data"], name="agent2.current")["session"],
                    name="agent2.current.session",
                )["session_id"],
                "agent2-elf",
            )

            switched = call("switch_binary", {"session_id": "agent1-elf", "context_id": "agent-1"})
            self.assertEqual(switched["status"], "ok")
            self.assertEqual(
                expect_optional_object(
                    expect_object(call("current_binary", {"context_id": "agent-1"})["data"], name="agent1.current.after")["session"],
                    name="agent1.current.after.session",
                )["session_id"],
                "agent1-elf",
            )
            self.assertEqual(
                expect_optional_object(
                    expect_object(call("current_binary", {"context_id": "agent-2"})["data"], name="agent2.current.after")["session"],
                    name="agent2.current.after.session",
                )["session_id"],
                "agent2-elf",
            )

            forbidden = call("switch_binary", {"session_id": "agent2-elf", "context_id": "agent-1"})
            self.assertEqual(forbidden["status"], "error")
            forbidden_error = forbidden["error"]
            self.assertIsInstance(forbidden_error, dict)
            assert isinstance(forbidden_error, dict)
            self.assertEqual(forbidden_error.get("code"), "session_not_found")

            isolated_sessions_resource = read("ida://sessions", {"context_id": "agent-1"})
            contents = expect_list(isolated_sessions_resource["contents"], name="isolated.sessions.contents")
            first = expect_object(contents[0], name="isolated.sessions.contents[0]")
            decoded_payload = json.loads(expect_string(first.get("text"), name="isolated.sessions.text"))
            self.assertIsInstance(decoded_payload, dict)
            assert isinstance(decoded_payload, dict)
            payload = expect_object(cast(JsonObject, decoded_payload), name="isolated.sessions.payload")
            self.assertEqual(payload.get("status"), "ok")
            payload_data = payload.get("data")
            self.assertIsInstance(payload_data, list)
            assert isinstance(payload_data, list)
            self.assertEqual(
                {str(item["session_id"]) for item in payload_data if isinstance(item, dict)},
                {"agent1-elf", "agent1-pe"},
            )
        finally:
            isolated_runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
