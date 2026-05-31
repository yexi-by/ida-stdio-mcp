"""协议、工具面与服务能力单元测试。"""

from __future__ import annotations

import json
import unittest
from io import BytesIO
from pathlib import Path
from typing import cast
from unittest.mock import patch

from loguru import logger

from ida_stdio_mcp.config import load_config
from ida_stdio_mcp.models import JsonObject, JsonValue
from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.service import build_service
from ida_stdio_mcp.stdio_server import ServerIdentity, StdioMcpServer

EXCLUDED_PROTOCOL_TOOLS = {
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
WORKFLOW_TOOLS = {
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
REMOVED_PUBLIC_TOOLS = {
    "apply_types",
    "debug_registers_all_threads",
    "debug_registers_thread",
    "debug_general_registers",
    "debug_general_registers_thread",
    "debug_named_registers",
    "debug_named_registers_thread",
}


class _FalseSaveRuntime:
    """模拟底层保存返回 false 的运行时。"""

    @property
    def isolated_contexts(self) -> bool:
        """测试运行时不启用上下文隔离。"""
        return False

    def save_workspace(self, path: str = "", session_id: str | None = None, *, context_id: str | None = None) -> JsonObject:
        """模拟旧实现中会被包装成 ok 的保存失败 payload。"""
        return {
            "ok": False,
            "path": path,
            "session_id": session_id or "",
            "context_id": context_id or "",
            "error": "save_database returned false",
        }


class _WorkflowRuntime:
    """模拟有活动会话的运行时。"""

    def __init__(self) -> None:
        """初始化会话状态和调用记录。"""
        self.mark_writeback_calls: list[str] = []
        self.recorded_activities: list[str] = []
        self.session: JsonObject = {
            "session_id": "sess-001",
            "source_path": "<输入文件>",
            "working_idb_path": "<工作库>",
            "filename": "sample.exe",
            "created_at": "2026-06-01T00:00:00",
            "last_accessed": "2026-06-01T00:00:00",
            "is_analyzing": False,
            "metadata": {},
            "is_active": True,
            "is_current_context": True,
            "bound_contexts": 1,
            "dirty": False,
            "writeback_kind": None,
            "persistent_after_save": False,
            "saved_path": "<工作库>",
            "undo_supported": False,
            "last_active_tool": "",
            "recent_targets": [],
            "recommended_next_tools": [],
        }

    @property
    def isolated_contexts(self) -> bool:
        """测试运行时不启用上下文隔离。"""
        return False

    def activate_for_request(self, session_id: str | None = None, *, context_id: str | None = None) -> JsonObject:
        """返回当前会话。"""
        return self.session

    def current_target(self, *, context_id: str | None = None) -> JsonObject:
        """返回当前会话。"""
        return self.session

    def mark_writeback(self, *, writeback_kind: str, session_id: str | None = None, context_id: str | None = None) -> JsonObject:
        """记录写回标记调用。"""
        self.mark_writeback_calls.append(writeback_kind)
        self.session["dirty"] = True
        self.session["writeback_kind"] = writeback_kind
        return self.session

    def record_activity(self, tool_name: str, *, target: str = "", session_id: str | None = None, context_id: str | None = None) -> None:
        """记录活动调用。"""
        self.recorded_activities.append(tool_name)


class _DegradedExplainCore:
    """模拟 explain_function 的降级子结果。"""

    def get_function_profile(self, query: str, *, include_asm: bool = False) -> JsonObject:
        """返回函数画像。"""
        return {"addr": "0x401000", "name": query}

    def decompile_function(self, query: str) -> JsonObject:
        """返回降级反编译结果。"""
        return {
            "status": "degraded",
            "representation": "asm_fallback",
            "warnings": ["Hex-Rays 不可用，已降级"],
            "text": "ret",
        }

    def microcode_summary(self, query: str, *, max_instructions: int = 80) -> JsonObject:
        """返回不支持的 microcode 结果。"""
        return {
            "status": "unsupported",
            "data": None,
            "warnings": ["当前环境不可用 Hex-Rays，无法生成 microcode。"],
        }


class _DegradedTriageCore:
    """模拟 triage_binary 的降级摘要。"""

    @staticmethod
    def _summary_payload() -> JsonObject:
        """返回带状态的摘要 payload。"""
        return {
            "status": "degraded",
            "warnings": ["函数 0x401000 的调用关系摘要读取失败：模拟异常"],
            "summary": "局部摘要可用",
            "metadata": {},
            "statistics": {},
            "capabilities": {},
            "quality": {},
            "entrypoints": [],
            "interesting_functions": [],
            "interesting_strings": [],
            "string_index": {},
            "imports": {},
            "managed_summary": {},
            "recommended_queries": [],
            "recommended_next_tools": [],
            "opening_moves": [],
        }

    def binary_survey_snapshot(self, *, include_strings: bool = False, string_limit: int = 0) -> JsonObject:
        """返回资源读取使用的降级摘要。"""
        return self._summary_payload()

    def triage_binary_snapshot(
        self,
        *,
        function_limit: int = 12,
        string_limit: int = 12,
        import_limit_per_category: int = 6,
        include_strings: bool = False,
    ) -> JsonObject:
        """返回带状态的开局摘要。"""
        return self._summary_payload()


class _InferNoWriteCore:
    """模拟 infer_types 只读推断结果。"""

    def infer_types(self, items: list[str]) -> list[JsonObject]:
        """返回未实际写入的推断结果。"""
        return [
            {
                "addr": "0x401000",
                "inferred_type": "int main(void)",
                "method": "function_prototype",
                "confidence": "high",
                "applied": False,
            }
        ]


class _EnumMemberFailureCore:
    """模拟枚举成员写入失败。"""

    def upsert_enum(self, items: list[JsonObject]) -> list[JsonObject]:
        """抛出核心层枚举成员写入错误。"""
        raise RuntimeError("添加枚举成员失败：TestEnum.VALUE=1 error_code=1")


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
    """覆盖 initialize、tools/list、prompts、resources 与工具面。"""

    @staticmethod
    def _repo_root() -> Path:
        """返回仓库根目录。"""
        return Path(__file__).resolve().parents[2]

    def _service(self, *, tool_surface: str = "all", isolated: bool = False) -> tuple[StdioMcpServer, list[JsonObject]]:
        """构造测试服务并返回工具列表。"""
        config = load_config(self._repo_root() / "setting.toml")
        service = build_service(
            HeadlessRuntime(isolated_contexts=isolated),
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

    def test_default_surface_registers_all_core_capabilities(self) -> None:
        """默认工具面暴露全部核心能力。"""
        _, tools = self._service()
        tool_names = self._tool_names(tools)
        self.assertFalse(tool_names & EXCLUDED_PROTOCOL_TOOLS)
        self.assertGreater(len(tool_names), 40)
        self.assertTrue(WORKFLOW_TOOLS <= tool_names)
        self.assertIn("patch_bytes", tool_names)
        self.assertIn("patch_assembly", tool_names)
        self.assertIn("patch_diff", tool_names)
        self.assertIn("patch_history", tool_names)
        self.assertIn("rollback_patch", tool_names)
        self.assertIn("scan_dispatchers", tool_names)
        self.assertIn("run_external_analyzer", tool_names)
        self.assertIn("import_analysis_artifact", tool_names)
        self.assertIn("list_analysis_artifacts", tool_names)
        self.assertIn("correlate_analysis_artifact", tool_names)
        self.assertIn("evaluate_python", tool_names)
        self.assertIn("execute_python_file", tool_names)
        self.assertIn("export_full_analysis", tool_names)
        self.assertIn("microcode_experiment", tool_names)
        self.assertIn("debug_start", tool_names)
        self.assertIn("debug_launch", tool_names)
        self.assertIn("debug_attach", tool_names)
        self.assertIn("debug_step", tool_names)
        self.assertIn("debug_registers", tool_names)
        self.assertIn("debug_stack", tool_names)
        self.assertIn("debug_capture_calls", tool_names)
        self.assertIn("debug_export_timeline", tool_names)
        self.assertFalse(tool_names & REMOVED_PUBLIC_TOOLS)
        for tool in tools:
            self.assertNotIn("featureGate", tool)

    def test_workflow_surface_is_noise_reduction_only(self) -> None:
        """workflow 工具面只保留高层工作流入口。"""
        _, tools = self._service(tool_surface="workflow")
        tool_names = self._tool_names(tools)
        self.assertEqual(tool_names, WORKFLOW_TOOLS)
        self.assertFalse(tool_names & EXCLUDED_PROTOCOL_TOOLS)

    def test_tool_surface_alias_and_invalid_values_do_not_fail_open(self) -> None:
        """工具面旧别名和非法值不得静默暴露全部工具。"""
        _, tools = self._service(tool_surface="slim")
        self.assertEqual(self._tool_names(tools), WORKFLOW_TOOLS)

        with self.assertRaises(ValueError):
            self._service(tool_surface="typo")

        with self.assertRaises(ValueError):
            self._service(tool_surface="full")

    def test_initialize_and_prompts_are_real_capabilities(self) -> None:
        """initialize 声明 prompts 时必须能 list/get。"""
        server, _ = self._service()
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
        """无 IDA 环境也应返回可修复工作区状态。"""
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

    def test_tool_schema_is_explicit_and_workflow_entrypoints_have_expected_fields(self) -> None:
        """工具 schema 仍保持显式、稳定、无顶层组合关键字。"""
        _, tools = self._service()
        by_name = {str(item["name"]): item for item in tools if isinstance(item.get("name"), str)}
        self.assertGreater(len(by_name), 40)
        self.assertFalse(set(by_name) & EXCLUDED_PROTOCOL_TOOLS)

        for name, item in by_name.items():
            self.assertNotIn("featureGate", item, msg=f"{name} 不应包含旧工具面元数据")
            schema = expect_object(item.get("inputSchema"), name=f"{name}.inputSchema")
            self._assert_schema_is_explicit(schema, tool_name=name)
            self.assertIn("inputExample", item, msg=f"{name} 缺少最小输入示例")

        self.assertEqual(set(schema_properties(by_name["open_target"], name="open_target")), {"path", "run_auto_analysis", "session_id"})
        open_target_properties = schema_properties(by_name["open_target"], name="open_target")
        run_auto_analysis_schema = expect_object(open_target_properties["run_auto_analysis"], name="open_target.run_auto_analysis")
        self.assertIs(run_auto_analysis_schema["default"], False)
        input_example = expect_object(by_name["open_target"]["inputExample"], name="open_target.inputExample")
        self.assertIs(input_example["run_auto_analysis"], False)
        self.assertEqual(
            set(schema_properties(by_name["triage_binary"], name="triage_binary")),
            {"function_limit", "string_limit", "import_limit_per_category", "include_strings", "session_id"},
        )
        self.assertEqual(set(schema_properties(by_name["get_import_at"], name="get_import_at")), {"addr", "session_id"})
        self.assertEqual(
            set(schema_properties(by_name["export_full_analysis"], name="export_full_analysis")),
            {
                "function_limit",
                "string_limit",
                "global_limit",
                "import_limit",
                "type_limit",
                "struct_limit",
                "include_decompile",
                "include_asm",
                "session_id",
            },
        )
        self.assertEqual(set(schema_properties(by_name["microcode_summary"], name="microcode_summary")), {"addr", "query", "max_instructions", "session_id"})
        self.assertEqual(set(schema_properties(by_name["debug_registers"], name="debug_registers")), {"scope", "thread_id", "names", "group"})
        self.assertEqual(set(schema_properties(by_name["patch_diff"], name="patch_diff")), {"items", "session_id"})
        self.assertEqual(set(schema_properties(by_name["patch_history"], name="patch_history")), {"limit", "session_id"})
        self.assertEqual(set(schema_properties(by_name["rollback_patch"], name="rollback_patch")), {"ids", "session_id"})
        self.assertEqual(set(schema_properties(by_name["scan_dispatchers"], name="scan_dispatchers")), {"max_functions", "max_candidates", "session_id"})
        self.assertEqual(set(schema_properties(by_name["run_external_analyzer"], name="run_external_analyzer")), {"name", "input_path", "output_path", "timeout_sec"})
        self.assertEqual(set(schema_properties(by_name["import_analysis_artifact"], name="import_analysis_artifact")), {"path", "artifact_id"})
        self.assertEqual(set(schema_properties(by_name["list_analysis_artifacts"], name="list_analysis_artifacts")), set())
        self.assertEqual(set(schema_properties(by_name["correlate_analysis_artifact"], name="correlate_analysis_artifact")), {"artifact_id", "path", "max_items", "session_id"})
        self.assertEqual(set(schema_properties(by_name["debug_start"], name="debug_start")), {"path", "args", "cwd"})
        self.assertEqual(set(schema_properties(by_name["debug_launch"], name="debug_launch")), {"path", "args", "cwd", "use_request"})
        self.assertEqual(set(schema_properties(by_name["debug_attach"], name="debug_attach")), {"pid", "event_id", "use_request"})
        self.assertEqual(set(schema_properties(by_name["debug_step"], name="debug_step")), {"action"})
        self.assertEqual(set(schema_properties(by_name["debug_stack"], name="debug_stack")), {"size"})
        self.assertEqual(
            set(schema_properties(by_name["debug_capture_calls"], name="debug_capture_calls")),
            {"action", "addrs", "include_registers", "stack_bytes", "register_names"},
        )
        self.assertEqual(set(schema_properties(by_name["debug_export_timeline"], name="debug_export_timeline")), {"limit", "include_ida_trace", "path"})
        debug_start_example = expect_object(by_name["debug_start"]["inputExample"], name="debug_start.inputExample")
        self.assertEqual(set(debug_start_example), {"path", "args", "cwd"})

    def test_invalid_arguments_return_machine_fixable_error(self) -> None:
        """底层工具参数错误仍返回统一机器可修复 envelope。"""
        server, _ = self._service()
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

    def test_save_workspace_false_payload_is_not_reported_as_success(self) -> None:
        """保存失败 payload 不得被工作流入口包装成成功。"""
        service = build_service(cast(HeadlessRuntime, _FalseSaveRuntime()), tool_surface="workflow")
        result = service.tools.call("save_workspace", {})

        self.assertEqual(result["status"], "error")
        error = expect_object(result["error"], name="save.error")
        self.assertEqual(error["code"], "tool_execution_failed")
        self.assertIn("save_database returned false", expect_string(error["message"], name="save.error.message"))

    def test_explain_function_propagates_child_degraded_status(self) -> None:
        """工作流解释函数不得把内层降级包装成顶层成功。"""
        runtime = _WorkflowRuntime()
        service = build_service(cast(HeadlessRuntime, runtime), tool_surface="workflow")

        with patch("ida_stdio_mcp.service._new_core", return_value=_DegradedExplainCore()):
            result = service.tools.call("explain_function", {"query": "main", "include_microcode": True})

        self.assertEqual(result["status"], "degraded")
        self.assertIn("Hex-Rays 不可用，已降级", result["warnings"])
        self.assertIn("当前环境不可用 Hex-Rays，无法生成 microcode。", result["warnings"])
        data = expect_object(result["data"], name="explain.data")
        representation = expect_object(data["representation"], name="explain.representation")
        self.assertEqual(representation["status"], "degraded")
        microcode = expect_object(data["microcode"], name="explain.microcode")
        self.assertEqual(microcode["status"], "unsupported")

    def test_triage_binary_propagates_degraded_summary_status(self) -> None:
        """开局摘要的局部失败不得被工作流入口包装成顶层成功。"""
        runtime = _WorkflowRuntime()
        service = build_service(cast(HeadlessRuntime, runtime), tool_surface="workflow")

        with patch("ida_stdio_mcp.service._new_core", return_value=_DegradedTriageCore()):
            result = service.tools.call("triage_binary", {})

        self.assertEqual(result["status"], "degraded")
        self.assertIn("函数 0x401000 的调用关系摘要读取失败：模拟异常", result["warnings"])
        data = expect_object(result["data"], name="triage.data")
        summary = expect_object(data["summary"], name="triage.summary")
        self.assertEqual(summary["status"], "degraded")

    def test_statusful_resource_propagates_degraded_status(self) -> None:
        """资源读取不得把核心层降级结果包装成顶层成功。"""
        runtime = _WorkflowRuntime()
        service = build_service(cast(HeadlessRuntime, runtime), tool_surface="workflow")

        with patch("ida_stdio_mcp.service._new_core", return_value=_DegradedTriageCore()):
            contents, is_error = service.resources.read("ida://triage")

        self.assertFalse(is_error)
        raw_payload = json.loads(contents[0]["text"])
        self.assertIsInstance(raw_payload, dict)
        assert isinstance(raw_payload, dict)
        payload = cast(JsonObject, raw_payload)
        self.assertEqual(payload["status"], "degraded")
        warnings_value = payload.get("warnings")
        self.assertIsInstance(warnings_value, list)
        assert isinstance(warnings_value, list)
        warnings = [str(item) for item in warnings_value]
        self.assertIn("函数 0x401000 的调用关系摘要读取失败：模拟异常", warnings)

    def test_infer_types_without_applied_write_does_not_mark_session_dirty(self) -> None:
        """未实际应用类型的 infer_types 结果不得标记会话为 dirty。"""
        runtime = _WorkflowRuntime()
        service = build_service(cast(HeadlessRuntime, runtime), tool_surface="all")

        with patch("ida_stdio_mcp.service._new_core", return_value=_InferNoWriteCore()):
            result = service.tools.call("infer_types", {"items": ["main"]})

        self.assertEqual(result["status"], "ok")
        self.assertEqual(runtime.mark_writeback_calls, [])
        data = expect_object(result["data"], name="infer.data")
        self.assertFalse(bool(data["dirty"]))
        self.assertIsNone(data["writeback_kind"])
        rows = expect_list(data["result"], name="infer.result")
        row = expect_object(rows[0], name="infer.result[0]")
        self.assertFalse(bool(row["applied"]))

    def test_upsert_enum_member_failure_is_reported_as_error(self) -> None:
        """枚举成员写入失败不得被报告为成功写回。"""
        runtime = _WorkflowRuntime()
        service = build_service(cast(HeadlessRuntime, runtime), tool_surface="all")

        with patch("ida_stdio_mcp.service._new_core", return_value=_EnumMemberFailureCore()):
            result = service.tools.call("upsert_enum", {"items": [{"name": "TestEnum", "members": [{"name": "VALUE", "value": 1}]}]})

        self.assertEqual(result["status"], "error")
        self.assertEqual(runtime.mark_writeback_calls, [])
        error = expect_object(result["error"], name="enum.error")
        self.assertIn("添加枚举成员失败", expect_string(error["message"], name="enum.error.message"))

    def test_resource_contract_is_uniform_and_global_resources_do_not_need_session(self) -> None:
        """资源 envelope 保持统一。"""
        server, _ = self._service()
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
        """隔离模式只在会话工具上暴露 context_id。"""
        _, tools = self._service(isolated=True)
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
        """日志测试使用当前工作流工具名。"""
        server, _ = self._service()
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
