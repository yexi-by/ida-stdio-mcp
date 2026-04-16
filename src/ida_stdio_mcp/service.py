"""构建纯实现的 headless stdio 服务。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import AppConfig
from .directory_analysis import iter_candidate_files
from .ida_core import IdaCore, ToolEnvelope
from .models import JsonObject, JsonValue, ToolStatus
from .profile_loader import load_profile
from .result import build_result
from .runtime import HeadlessRuntime
from .tool_registry import ResourceRegistry, ResourceSpec, ToolRegistry, ToolSpec

COMMON_OUTPUT_SCHEMA: JsonObject = {
    "type": "object",
    "properties": {
        "status": {"type": "string"},
        "source": {"type": "string"},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "error": {"type": ["string", "null"]},
        "data": {},
    },
    "required": ["status", "source", "warnings", "error", "data"],
    "additionalProperties": False,
}

GENERIC_INPUT_SCHEMA: JsonObject = {
    "type": "object",
    "properties": {"session_id": {"type": "string"}},
    "additionalProperties": True,
}


@dataclass(slots=True, frozen=True)
class ServiceBundle:
    """服务构建结果。"""

    tools: ToolRegistry
    resources: ResourceRegistry


def _ensure_session(arguments: JsonObject, runtime: HeadlessRuntime) -> None:
    raw_session = arguments.get("session_id")
    session_id = raw_session if isinstance(raw_session, str) and raw_session else None
    runtime.activate_for_request(session_id)


def _normalize_tool_data(value: object) -> JsonValue:
    core = IdaCore()
    return core.jsonify(value)


def _unwrap_statusful(value: object) -> tuple[ToolStatus, JsonValue, list[str]]:
    if isinstance(value, dict) and {"status", "data", "warnings"} <= set(value.keys()):
        raw_status = value.get("status")
        raw_data = value.get("data")
        raw_warnings = value.get("warnings")
        status: ToolStatus = raw_status if isinstance(raw_status, str) else "error"  # type: ignore[assignment]
        warnings = [str(item) for item in raw_warnings] if isinstance(raw_warnings, list) else []
        return status, _normalize_tool_data(raw_data), warnings
    if isinstance(value, dict) and {"status", "representation", "warnings"} <= set(value.keys()):
        raw_status = value.get("status")
        raw_warnings = value.get("warnings")
        status = raw_status if isinstance(raw_status, str) else "error"  # type: ignore[assignment]
        warnings = [str(item) for item in raw_warnings] if isinstance(raw_warnings, list) else []
        return status, _normalize_tool_data(value), warnings
    return "ok", _normalize_tool_data(value), []


def _tool(
    registry: ToolRegistry,
    *,
    name: str,
    description: str,
    source: str,
    runtime: HeadlessRuntime,
    handler: Callable[[IdaCore, JsonObject], object],
    session_required: bool = True,
) -> None:
    def wrapped(arguments: JsonObject):
        try:
            if session_required:
                _ensure_session(arguments, runtime)
            core = IdaCore()
            raw = handler(core, arguments)
            status, data, warnings = _unwrap_statusful(raw)
            return build_result(status=status, source=source, data=data, warnings=warnings)
        except Exception as exc:
            return build_result(status="error", source=source, data=None, error=str(exc))

    registry.register(
        ToolSpec(
            name=name,
            description=description,
            input_schema=GENERIC_INPUT_SCHEMA,
            output_schema=COMMON_OUTPUT_SCHEMA,
            handler=wrapped,
        )
    )


def _management_tools(
    registry: ToolRegistry,
    runtime: HeadlessRuntime,
    config: AppConfig,
    *,
    allow_unsafe: bool,
    allow_debugger: bool,
) -> set[str]:
    protected = {
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
    }

    def health_handler(_: JsonObject):
        active: JsonValue = None
        health_data = {
            "runtime_ready": True,
            "idadir": str(runtime.require_ida_dir()),
            "binary_open": False,
            "active": None,
            "feature_gates": {
                "unsafe": allow_unsafe,
                "debugger": allow_debugger,
            },
        }
        try:
            active = _normalize_tool_data(runtime.current_binary())
            runtime.activate_for_request(None)
            core = IdaCore()
            payload = core.health()
            payload["active_session"] = active
            payload["feature_gates"] = {
                "unsafe": allow_unsafe,
                "debugger": allow_debugger,
            }
            health_data = payload
        except Exception:
            pass
        if active is not None:
            health_data["binary_open"] = True
            health_data["active"] = active
        return build_result(status="ok", source="runtime.health", data=_normalize_tool_data(health_data))

    def warmup_handler(arguments: JsonObject):
        _ensure_session(arguments, runtime)
        core = IdaCore()
        data = core.wait_auto_analysis()
        return build_result(status="ok", source="runtime.warmup", data=data)

    def open_binary_handler(arguments: JsonObject):
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str):
            return build_result(status="error", source="runtime.open_binary", data=None, error="path 必须是字符串")
        summary = runtime.open_binary(
            Path(raw_path),
            run_auto_analysis=bool(arguments.get("run_auto_analysis", True)),
            session_id=arguments.get("session_id") if isinstance(arguments.get("session_id"), str) else None,
        )
        return build_result(status="ok", source="runtime.open_binary", data=summary)

    def close_binary_handler(arguments: JsonObject):
        raw_session = arguments.get("session_id")
        session_id = raw_session if isinstance(raw_session, str) else None
        runtime.close_binary(session_id)
        return build_result(status="ok", source="runtime.close_binary", data={"closed": True, "session_id": session_id})

    def switch_binary_handler(arguments: JsonObject):
        raw_session = arguments.get("session_id")
        if not isinstance(raw_session, str):
            return build_result(status="error", source="runtime.switch_binary", data=None, error="session_id 必须是字符串")
        return build_result(status="ok", source="runtime.switch_binary", data=runtime.switch_binary(raw_session))

    def list_binaries_handler(_: JsonObject):
        return build_result(status="ok", source="runtime.list_binaries", data=runtime.list_binaries())

    def current_binary_handler(_: JsonObject):
        try:
            return build_result(status="ok", source="runtime.current_binary", data=runtime.current_binary())
        except Exception as exc:
            return build_result(status="degraded", source="runtime.current_binary", data=None, warnings=[str(exc)])

    def save_binary_handler(arguments: JsonObject):
        raw_session = arguments.get("session_id")
        session_id = raw_session if isinstance(raw_session, str) else None
        path = arguments.get("path") if isinstance(arguments.get("path"), str) else ""
        return build_result(status="ok", source="runtime.save_binary", data=runtime.save_binary(path=path, session_id=session_id))

    def deactivate_binary_handler(_: JsonObject):
        return build_result(status="ok", source="runtime.deactivate_binary", data={"deactivated": runtime.deactivate_binary()})

    def analyze_directory_handler(arguments: JsonObject):
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str):
            return build_result(status="error", source="directory_analysis", data=None, error="path 必须是字符串")
        root = Path(raw_path)
        if not root.exists():
            return build_result(status="error", source="directory_analysis", data=None, error=f"目录不存在：{root}")
        if not root.is_dir():
            return build_result(status="error", source="directory_analysis", data=None, error=f"不是目录：{root}")

        raw_include = arguments.get("include_extensions", config.directory_analysis.include_extensions)
        raw_exclude = arguments.get("exclude_patterns", config.directory_analysis.exclude_patterns)
        include_extensions = tuple(str(item).lower() for item in raw_include) if isinstance(raw_include, (list, tuple)) else config.directory_analysis.include_extensions
        exclude_patterns = tuple(str(item) for item in raw_exclude) if isinstance(raw_exclude, (list, tuple)) else config.directory_analysis.exclude_patterns
        recursive = bool(arguments.get("recursive", config.directory_analysis.recursive))
        max_candidates = int(arguments.get("max_candidates", config.directory_analysis.max_candidates))
        max_deep_analysis = int(arguments.get("max_deep_analysis", config.directory_analysis.max_deep_analysis))

        previous_session_id: str | None = None
        try:
            current = runtime.current_binary()
            previous_value = current.get("session_id")
            previous_session_id = previous_value if isinstance(previous_value, str) else None
        except Exception:
            previous_session_id = None

        candidates = iter_candidate_files(
            root,
            recursive=recursive,
            include_extensions=include_extensions,
            exclude_patterns=exclude_patterns,
        )
        selected = candidates[:max_candidates]
        analyzed: list[JsonValue] = []
        skipped: list[JsonValue] = []
        errors: list[JsonValue] = []

        for index, candidate in enumerate(selected):
            if index >= max_deep_analysis:
                skipped.append({"path": str(candidate.path), "reason": "超出 max_deep_analysis 限制", "score": candidate.score})
                continue
            temp_session_id = f"batch-{index:03d}"
            try:
                runtime.open_binary(candidate.path, session_id=temp_session_id)
                core = IdaCore()
                survey = core.survey_binary()
                try:
                    focus = core.analyze_function("main", include_asm=False)
                except Exception as exc:
                    focus = {"addr": "main", "error": str(exc)}
                analyzed.append(
                    {
                        "path": str(candidate.path),
                        "binary_kind": candidate.binary_kind,
                        "score": candidate.score,
                        "reasons": list(candidate.reasons),
                        "survey": _normalize_tool_data(survey),
                        "focus": _normalize_tool_data(focus),
                    }
                )
            except Exception as exc:
                errors.append({"path": str(candidate.path), "error": str(exc)})
            finally:
                try:
                    runtime.close_binary(temp_session_id)
                except Exception:
                    pass

        if previous_session_id is not None:
            try:
                runtime.switch_binary(previous_session_id)
            except Exception as exc:
                errors.append({"path": "<restore>", "error": f"恢复原会话失败：{exc}"})
        else:
            runtime.deactivate_binary()

        status: ToolStatus = "ok" if not errors else "degraded"
        warnings = ["部分样本分析失败，已降级返回"] if errors else []
        return build_result(
            status=status,
            source="directory_analysis",
            data={
                "summary": {
                    "root": str(root),
                    "candidate_count": len(candidates),
                    "selected_count": len(selected),
                    "analyzed_count": len(analyzed),
                    "skipped_count": len(skipped),
                    "error_count": len(errors),
                },
                "candidates": [
                    {
                        "path": str(item.path),
                        "binary_kind": item.binary_kind,
                        "score": item.score,
                        "size": item.size,
                        "sha256": item.sha256,
                        "reasons": list(item.reasons),
                    }
                    for item in candidates
                ],
                "selected": [str(item.path) for item in selected],
                "analyzed": analyzed,
                "skipped": skipped,
                "errors": errors,
            },
            warnings=warnings,
        )

    registry.register(ToolSpec("health", "返回运行时健康状态。", {"type": "object", "properties": {}, "additionalProperties": False}, COMMON_OUTPUT_SCHEMA, health_handler))
    registry.register(ToolSpec("warmup", "预热当前会话。", GENERIC_INPUT_SCHEMA, COMMON_OUTPUT_SCHEMA, warmup_handler))
    registry.register(ToolSpec("open_binary", "打开二进制并绑定当前会话。", {"type": "object", "properties": {"path": {"type": "string"}, "run_auto_analysis": {"type": "boolean"}, "session_id": {"type": "string"}}, "required": ["path"], "additionalProperties": False}, COMMON_OUTPUT_SCHEMA, open_binary_handler))
    registry.register(ToolSpec("close_binary", "关闭指定或当前会话。", GENERIC_INPUT_SCHEMA, COMMON_OUTPUT_SCHEMA, close_binary_handler))
    registry.register(ToolSpec("switch_binary", "切换当前默认会话。", {"type": "object", "properties": {"session_id": {"type": "string"}}, "required": ["session_id"], "additionalProperties": False}, COMMON_OUTPUT_SCHEMA, switch_binary_handler))
    registry.register(ToolSpec("list_binaries", "列出所有打开的会话。", {"type": "object", "properties": {}, "additionalProperties": False}, COMMON_OUTPUT_SCHEMA, list_binaries_handler))
    registry.register(ToolSpec("current_binary", "返回当前默认会话。", {"type": "object", "properties": {}, "additionalProperties": False}, COMMON_OUTPUT_SCHEMA, current_binary_handler))
    registry.register(ToolSpec("save_binary", "保存当前或指定会话对应的 IDB。", GENERIC_INPUT_SCHEMA, COMMON_OUTPUT_SCHEMA, save_binary_handler))
    registry.register(ToolSpec("deactivate_binary", "解除默认会话绑定。", {"type": "object", "properties": {}, "additionalProperties": False}, COMMON_OUTPUT_SCHEMA, deactivate_binary_handler))
    registry.register(ToolSpec("analyze_directory", "扫描目录、挑选候选二进制并做批量深度分析。", GENERIC_INPUT_SCHEMA, COMMON_OUTPUT_SCHEMA, analyze_directory_handler))
    return protected


def _register_read_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    _tool(registry, name="survey_binary", description="返回当前会话的二进制概览。", source="core.survey_binary", runtime=runtime, handler=lambda core, _: core.survey_binary())
    _tool(
        registry,
        name="list_functions",
        description="分页列出函数。",
        source="core.list_functions",
        runtime=runtime,
        handler=lambda core, arguments: core.list_functions(
            filter_text=_query_filter(arguments),
            offset=int(arguments.get("offset", 0)),
            limit=int(arguments.get("count", arguments.get("limit", 100))),
        ),
    )
    _tool(registry, name="get_function", description="返回单个函数详情以及 callers/callees。", source="core.get_function", runtime=runtime, handler=lambda core, arguments: core.get_function(_addr_or_query(arguments)))
    _tool(
        registry,
        name="get_function_profile",
        description="读取函数画像。",
        source="core.get_function_profile",
        runtime=runtime,
        handler=lambda core, arguments: core.get_function_profile(_addr_or_query(arguments), include_asm=bool(arguments.get("include_asm", True))),
    )
    _tool(
        registry,
        name="analyze_functions",
        description="批量分析多个函数。",
        source="core.analyze_functions",
        runtime=runtime,
        handler=lambda core, arguments: core.analyze_functions(_string_list(arguments, "queries")),
    )
    _tool(registry, name="decompile_function", description="返回函数的统一高层表示。", source="core.decompile_function", runtime=runtime, handler=lambda core, arguments: core.decompile_function(_addr_or_query(arguments)))
    _tool(registry, name="disassemble_function", description="返回函数反汇编。", source="core.disassemble_function", runtime=runtime, handler=lambda core, arguments: core.disassemble_function(_addr_or_query(arguments)))
    _tool(
        registry,
        name="list_globals",
        description="分页列出全局变量。",
        source="core.list_globals",
        runtime=runtime,
        handler=lambda core, arguments: core.list_globals(
            filter_text=str(arguments.get("filter", "")),
            offset=int(arguments.get("offset", 0)),
            limit=int(arguments.get("count", arguments.get("limit", 100))),
        ),
    )
    _tool(registry, name="list_imports", description="列出导入表。", source="core.list_imports", runtime=runtime, handler=lambda core, arguments: core.list_imports(offset=int(arguments.get("offset", 0)), limit=int(arguments.get("count", arguments.get("limit", 200)))))
    _tool(
        registry,
        name="query_imports",
        description="按条件查询导入表。",
        source="core.query_imports",
        runtime=runtime,
        handler=lambda core, arguments: core.query_imports(
            module=str(arguments.get("module", "")),
            name_filter=_import_name_filter(arguments),
            offset=int(arguments.get("offset", 0)),
            limit=int(arguments.get("count", arguments.get("limit", 200))),
        ),
    )
    _tool(registry, name="get_xrefs_to", description="读取目标地址的交叉引用。", source="core.get_xrefs_to", runtime=runtime, handler=lambda core, arguments: core.get_xrefs_to(_addr_or_query(arguments)))
    _tool(registry, name="query_xrefs", description="按条件查询交叉引用。", source="core.query_xrefs", runtime=runtime, handler=lambda core, arguments: core.query_xrefs(from_query=str(arguments.get("from_query", "")), to_query=str(arguments.get("to_query", "")), xref_type=str(arguments.get("type", ""))))
    _tool(registry, name="get_xrefs_to_field", description="读取结构字段交叉引用。", source="core.get_xrefs_to_field", runtime=runtime, handler=lambda core, arguments: core.get_xrefs_to_field(_require_string(arguments, "struct_name"), _require_string(arguments, "field_name")))
    _tool(registry, name="get_callers", description="读取函数调用者。", source="core.get_callers", runtime=runtime, handler=lambda core, arguments: core.get_callers(_addr_or_query(arguments)))
    _tool(registry, name="get_callees", description="读取函数调用目标。", source="core.get_callees", runtime=runtime, handler=lambda core, arguments: core.get_callees(_addr_or_query(arguments)))
    _tool(registry, name="get_basic_blocks", description="读取函数基本块。", source="core.get_basic_blocks", runtime=runtime, handler=lambda core, arguments: core.get_basic_blocks(_addr_or_query(arguments)))
    _tool(registry, name="list_strings", description="分页列出字符串。", source="core.list_strings", runtime=runtime, handler=lambda core, arguments: core.list_strings(offset=int(arguments.get("offset", 0)), limit=int(arguments.get("count", arguments.get("limit", 100)))))
    _tool(registry, name="find_strings", description="按子串搜索字符串。", source="core.find_strings", runtime=runtime, handler=lambda core, arguments: core.find_strings(_search_text(arguments), offset=int(arguments.get("offset", 0)), limit=int(arguments.get("count", arguments.get("limit", 100)))))
    _tool(registry, name="search_regex", description="对字符串做正则搜索。", source="core.search_regex", runtime=runtime, handler=lambda core, arguments: core.search_regex(_search_text(arguments), offset=int(arguments.get("offset", 0)), limit=int(arguments.get("count", arguments.get("limit", 100)))))
    _tool(registry, name="find_bytes", description="按字节模式搜索。", source="core.find_bytes", runtime=runtime, handler=lambda core, arguments: core.find_bytes(_require_string(arguments, "pattern"), max_hits=int(arguments.get("max_hits", 100))))
    _tool(registry, name="find_items", description="按高级条件搜索字符串/函数。", source="core.find_items", runtime=runtime, handler=lambda core, arguments: core.find_items(_search_text(arguments), max_hits=int(arguments.get("max_hits", 100))))
    _tool(registry, name="query_instructions", description="按指令模式查询。", source="core.query_instructions", runtime=runtime, handler=lambda core, arguments: core.query_instructions(_require_string(arguments, "mnemonic"), max_hits=int(arguments.get("max_hits", 100))))
    _tool(registry, name="read_bytes", description="读取内存字节。", source="core.read_bytes", runtime=runtime, handler=lambda core, arguments: core.read_bytes(_addr_list(arguments, "addrs"), size=int(arguments.get("size", 16))))
    _tool(registry, name="read_ints", description="读取整数。", source="core.read_ints", runtime=runtime, handler=lambda core, arguments: core.read_ints(_json_object_list(arguments, "queries")))
    _tool(registry, name="read_strings", description="读取字符串。", source="core.read_strings", runtime=runtime, handler=lambda core, arguments: core.read_strings(_addr_list(arguments, "addrs"), max_length=int(arguments.get("max_length", 512))))
    _tool(registry, name="read_global_values", description="读取全局变量值。", source="core.read_global_values", runtime=runtime, handler=lambda core, arguments: core.read_global_values(_addr_list(arguments, "addrs"), size=int(arguments.get("size", 8))))
    _tool(registry, name="get_stack_frame", description="读取函数栈帧。", source="core.get_stack_frame", runtime=runtime, handler=lambda core, arguments: core.get_stack_frame(_addr_or_query(arguments)))
    _tool(registry, name="read_struct", description="读取结构体字段定义。", source="core.read_struct", runtime=runtime, handler=lambda core, arguments: core.read_struct(_require_string(arguments, "name")))
    _tool(registry, name="search_structs", description="搜索结构体。", source="core.search_structs", runtime=runtime, handler=lambda core, arguments: core.search_structs(str(arguments.get("filter", ""))))
    _tool(registry, name="query_types", description="查询类型目录。", source="core.query_types", runtime=runtime, handler=lambda core, arguments: core.query_types(str(arguments.get("filter", ""))))
    _tool(registry, name="inspect_type", description="读取具体类型详情。", source="core.inspect_type", runtime=runtime, handler=lambda core, arguments: core.inspect_type(_require_string(arguments, "name")))
    _tool(
        registry,
        name="export_functions",
        description="导出函数。",
        source="core.export_functions",
        runtime=runtime,
        handler=lambda core, arguments: core.export_functions(
            queries=_optional_query_list(arguments),
            format_name=str(arguments.get("format", arguments.get("format_name", "json"))),
            limit=int(arguments.get("limit", 1000)),
        ),
    )
    _tool(registry, name="build_callgraph", description="构建调用图。", source="core.build_callgraph", runtime=runtime, handler=lambda core, arguments: core.build_callgraph(_root_queries(arguments), max_depth=int(arguments.get("max_depth", 3))))
    _tool(registry, name="analyze_function", description="做单函数综合分析。", source="core.analyze_function", runtime=runtime, handler=lambda core, arguments: core.analyze_function(_addr_or_query(arguments), include_asm=bool(arguments.get("include_asm", False))))
    _tool(registry, name="analyze_component", description="做组件级综合分析。", source="core.analyze_component", runtime=runtime, handler=lambda core, arguments: core.analyze_component(_require_string(arguments, "root_query"), max_depth=int(arguments.get("max_depth", 2)), include_asm=bool(arguments.get("include_asm", False))))
    _tool(
        registry,
        name="trace_data_flow",
        description="做数据流追踪。",
        source="core.trace_data_flow",
        runtime=runtime,
        handler=lambda core, arguments: core.trace_data_flow(
            _require_string(arguments, "addr"),
            direction=str(arguments.get("direction", "both")),
            max_depth=int(arguments.get("max_depth", 5)),
        ),
    )
    _tool(registry, name="convert_integer", description="做整数进制/字节转换。", source="core.convert_integer", runtime=runtime, handler=lambda core, arguments: core.convert_integer(_int_value(arguments.get("value")), width=int(arguments.get("width", 8)), signed=bool(arguments.get("signed", False))), session_required=False)


def _register_unsafe_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    _tool(registry, name="set_comments", description="设置注释。", source="core.set_comments", runtime=runtime, handler=lambda core, arguments: core.set_comments(_json_object_list(arguments, "items"), append=False))
    _tool(registry, name="append_comments", description="追加注释。", source="core.append_comments", runtime=runtime, handler=lambda core, arguments: core.set_comments(_json_object_list(arguments, "items"), append=True))
    _tool(registry, name="patch_assembly", description="按汇编语句打补丁。", source="core.patch_assembly", runtime=runtime, handler=lambda core, arguments: core.patch_assembly(_json_object_list(arguments, "items")))
    _tool(registry, name="rename_symbols", description="批量重命名符号。", source="core.rename_symbols", runtime=runtime, handler=lambda core, arguments: core.rename_symbols(_json_object_list(arguments, "items")))
    _tool(registry, name="define_function", description="定义函数。", source="core.define_function", runtime=runtime, handler=lambda core, arguments: core.define_function(_string_list(arguments, "addrs")))
    _tool(registry, name="define_code", description="把字节定义为代码。", source="core.define_code", runtime=runtime, handler=lambda core, arguments: core.define_code(_string_list(arguments, "addrs")))
    _tool(registry, name="undefine_items", description="取消定义。", source="core.undefine_items", runtime=runtime, handler=lambda core, arguments: core.undefine_items(_string_list(arguments, "addrs")))
    _tool(registry, name="declare_types", description="声明 C 类型。", source="core.declare_types", runtime=runtime, handler=lambda core, arguments: core.declare_types(_string_list(arguments, "declarations")))
    _tool(registry, name="upsert_enum", description="创建或更新枚举。", source="core.upsert_enum", runtime=runtime, handler=lambda core, arguments: core.upsert_enum(_json_object_list(arguments, "items")))
    _tool(registry, name="set_types", description="设置类型。", source="core.set_types", runtime=runtime, handler=lambda core, arguments: core.set_types(_json_object_list(arguments, "items")))
    _tool(registry, name="apply_types", description="批量应用类型。", source="core.apply_types", runtime=runtime, handler=lambda core, arguments: core.apply_types(_json_object_list(arguments, "items")))
    _tool(registry, name="infer_types", description="推断并写入类型。", source="core.infer_types", runtime=runtime, handler=lambda core, arguments: core.infer_types(_string_list(arguments, "queries")))
    _tool(registry, name="declare_stack_variables", description="声明栈变量。", source="core.declare_stack_variables", runtime=runtime, handler=lambda core, arguments: core.declare_stack_variables(_json_object_list(arguments, "items")))
    _tool(registry, name="delete_stack_variables", description="删除栈变量。", source="core.delete_stack_variables", runtime=runtime, handler=lambda core, arguments: core.delete_stack_variables(_json_object_list(arguments, "items")))
    _tool(registry, name="patch_bytes", description="直接写入字节补丁。", source="core.patch_bytes", runtime=runtime, handler=lambda core, arguments: core.patch_bytes(_json_object_list(arguments, "items")))
    _tool(registry, name="write_ints", description="写入整数。", source="core.write_ints", runtime=runtime, handler=lambda core, arguments: core.write_ints(_json_object_list(arguments, "items")))
    _tool(registry, name="evaluate_python", description="在 IDA 上下文执行 Python 代码。", source="core.evaluate_python", runtime=runtime, handler=lambda core, arguments: core.evaluate_python(_require_string(arguments, "code")), session_required=False)
    _tool(registry, name="execute_python_file", description="执行磁盘上的 Python 脚本。", source="core.execute_python_file", runtime=runtime, handler=lambda core, arguments: core.execute_python_file(_require_string(arguments, "path")), session_required=False)


def _register_debug_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    _tool(registry, name="debug_start", description="启动调试会话。", source="core.debug_start", runtime=runtime, handler=lambda core, arguments: core.debug_start(str(arguments.get("path", ""))), session_required=False)
    _tool(registry, name="debug_exit", description="退出调试会话。", source="core.debug_exit", runtime=runtime, handler=lambda core, arguments: core.debug_exit(), session_required=False)
    _tool(registry, name="debug_continue", description="继续执行。", source="core.debug_continue", runtime=runtime, handler=lambda core, arguments: core.debug_continue(), session_required=False)
    _tool(registry, name="debug_run_to", description="运行到指定地址。", source="core.debug_run_to", runtime=runtime, handler=lambda core, arguments: core.debug_run_to(_require_string(arguments, "addr")), session_required=False)
    _tool(registry, name="debug_step_into", description="单步进入。", source="core.debug_step_into", runtime=runtime, handler=lambda core, arguments: core.debug_step_into(), session_required=False)
    _tool(registry, name="debug_step_over", description="单步越过。", source="core.debug_step_over", runtime=runtime, handler=lambda core, arguments: core.debug_step_over(), session_required=False)
    _tool(registry, name="debug_list_breakpoints", description="列出断点。", source="core.debug_list_breakpoints", runtime=runtime, handler=lambda core, arguments: core.debug_breakpoints(), session_required=False)
    _tool(registry, name="debug_add_breakpoints", description="添加断点。", source="core.debug_add_breakpoints", runtime=runtime, handler=lambda core, arguments: core.debug_add_breakpoints(_string_list(arguments, "addrs")), session_required=False)
    _tool(registry, name="debug_delete_breakpoints", description="删除断点。", source="core.debug_delete_breakpoints", runtime=runtime, handler=lambda core, arguments: core.debug_delete_breakpoints(_string_list(arguments, "addrs")), session_required=False)
    _tool(registry, name="debug_toggle_breakpoints", description="启停断点。", source="core.debug_toggle_breakpoints", runtime=runtime, handler=lambda core, arguments: core.debug_toggle_breakpoints(_json_object_list(arguments, "items")), session_required=False)
    _tool(registry, name="debug_registers", description="读取当前线程全部寄存器。", source="core.debug_registers", runtime=runtime, handler=lambda core, arguments: core.debug_registers(), session_required=False)
    _tool(
        registry,
        name="debug_registers_all_threads",
        description="读取所有线程寄存器。",
        source="core.debug_registers_all_threads",
        runtime=runtime,
        handler=lambda core, arguments: core.debug_registers_all_threads(
            names=_string_list(arguments, "names") if isinstance(arguments.get("names"), list) else None
        ),
        session_required=False,
    )
    _tool(registry, name="debug_registers_thread", description="读取指定线程寄存器。", source="core.debug_registers_thread", runtime=runtime, handler=lambda core, arguments: core.debug_registers(thread_id=int(arguments.get("thread_id", 0))), session_required=False)
    _tool(registry, name="debug_general_registers", description="读取当前线程通用寄存器。", source="core.debug_general_registers", runtime=runtime, handler=lambda core, arguments: core.debug_registers(names=["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "rip", "rsp", "rbp"]), session_required=False)
    _tool(registry, name="debug_general_registers_thread", description="读取指定线程通用寄存器。", source="core.debug_general_registers_thread", runtime=runtime, handler=lambda core, arguments: core.debug_registers(thread_id=int(arguments.get("thread_id", 0)), names=["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "rip", "rsp", "rbp"]), session_required=False)
    _tool(registry, name="debug_named_registers", description="读取指定寄存器集合。", source="core.debug_named_registers", runtime=runtime, handler=lambda core, arguments: core.debug_registers(names=_string_list(arguments, "names")), session_required=False)
    _tool(registry, name="debug_named_registers_thread", description="读取指定线程的指定寄存器集合。", source="core.debug_named_registers_thread", runtime=runtime, handler=lambda core, arguments: core.debug_registers(thread_id=int(arguments.get("thread_id", 0)), names=_string_list(arguments, "names")), session_required=False)
    _tool(registry, name="debug_stacktrace", description="读取当前调用栈。", source="core.debug_stacktrace", runtime=runtime, handler=lambda core, arguments: core.debug_stacktrace(), session_required=False)
    _tool(registry, name="debug_read_memory", description="读取调试进程内存。", source="core.debug_read_memory", runtime=runtime, handler=lambda core, arguments: core.debug_read_memory(_require_string(arguments, "addr"), int(arguments.get("size", 16))), session_required=False)
    _tool(registry, name="debug_write_memory", description="写入调试进程内存。", source="core.debug_write_memory", runtime=runtime, handler=lambda core, arguments: core.debug_write_memory(_require_string(arguments, "addr"), _require_string(arguments, "hex")), session_required=False)


def _register_resources(resources: ResourceRegistry, runtime: HeadlessRuntime) -> None:
    def active_reader(reader: Callable[[IdaCore], JsonValue]) -> Callable[[dict[str, str]], JsonValue]:
        def wrapped(_: dict[str, str]) -> JsonValue:
            runtime.activate_for_request(None)
            return reader(IdaCore())

        return wrapped

    def template_reader(reader: Callable[[IdaCore, dict[str, str]], JsonValue]) -> Callable[[dict[str, str]], JsonValue]:
        def wrapped(params: dict[str, str]) -> JsonValue:
            runtime.activate_for_request(None)
            return reader(IdaCore(), params)

        return wrapped

    resources.register_static(ResourceSpec("ida://idb/metadata", "idb_metadata", "当前 IDB 元数据。", "application/json", active_reader(lambda core: core.idb_metadata())))
    resources.register_static(ResourceSpec("ida://idb/segments", "idb_segments", "当前 IDB 段信息。", "application/json", active_reader(lambda core: core.segments())))
    resources.register_static(ResourceSpec("ida://idb/entrypoints", "idb_entrypoints", "当前 IDB 入口点。", "application/json", active_reader(lambda core: core.entrypoints())))
    resources.register_static(ResourceSpec("ida://idb/capabilities", "idb_capabilities", "当前 IDB 能力矩阵。", "application/json", active_reader(lambda core: core.capabilities())))
    resources.register_static(ResourceSpec("ida://survey", "survey", "当前样本的综合概览。", "application/json", active_reader(lambda core: core.survey_binary())))
    resources.register_static(ResourceSpec("ida://types", "types", "当前类型目录。", "application/json", active_reader(lambda core: core.query_types())))
    resources.register_static(ResourceSpec("ida://structs", "structs", "当前结构体列表。", "application/json", active_reader(lambda core: core.search_structs())))
    resources.register_static(ResourceSpec("ida://functions", "functions", "当前函数列表。", "application/json", active_reader(lambda core: core.list_functions(limit=2000))))
    resources.register_static(ResourceSpec("ida://functions/profiles", "function_profiles", "当前函数画像摘要。", "application/json", active_reader(lambda core: [core.get_function_profile(str(item.get("addr")), include_asm=False) for item in core.list_functions(limit=200)])))
    resources.register_static(ResourceSpec("ida://globals", "globals", "当前全局符号列表。", "application/json", active_reader(lambda core: core.list_globals(limit=2000))))
    resources.register_static(ResourceSpec("ida://imports", "imports", "当前导入表。", "application/json", active_reader(lambda core: core.list_imports(limit=2000))))
    resources.register_static(ResourceSpec("ida://imports/categories", "imports_categories", "当前导入的分类视图。", "application/json", active_reader(lambda core: core.survey_binary()["imports_by_category"])))
    resources.register_static(ResourceSpec("ida://strings", "strings", "当前字符串列表。", "application/json", active_reader(lambda core: core.list_strings(limit=2000))))
    resources.register_static(ResourceSpec("ida://callgraph/summary", "callgraph_summary", "当前样本的调用图摘要。", "application/json", active_reader(lambda core: core.survey_binary()["call_graph_summary"])))
    resources.register_static(ResourceSpec("ida://managed/summary", "managed_summary", "托管/.NET 能力与符号级摘要。", "application/json", active_reader(lambda core: core.managed_summary())))
    resources.register_static(ResourceSpec("ida://managed/types", "managed_types", "托管/.NET 符号级类型目录。", "application/json", active_reader(lambda core: core.managed_types(limit=2000))))
    resources.register_static(ResourceSpec("ida://managed/namespaces", "managed_namespaces", "托管/.NET 命名空间统计。", "application/json", active_reader(lambda core: core.managed_summary()["top_namespaces"])))
    resources.register_static(ResourceSpec("ida://session/current", "session_current", "当前默认会话。", "application/json", lambda _params: _normalize_tool_data({"session": runtime.current_binary() if runtime.list_binaries() else None})))
    resources.register_static(ResourceSpec("ida://sessions", "sessions", "当前所有会话。", "application/json", lambda _params: _normalize_tool_data(runtime.list_binaries())))

    resources.register_template(
        uri_template="ida://struct/{name}",
        name="struct_name",
        description="读取指定结构体定义。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.read_struct(params["name"])),
    )
    resources.register_template(
        uri_template="ida://function/{query}",
        name="function_query",
        description="读取指定函数详情。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.get_function(params["query"])),
    )
    resources.register_template(
        uri_template="ida://function-profile/{query}",
        name="function_profile_query",
        description="读取指定函数画像。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.get_function_profile(params["query"], include_asm=False)),
    )
    resources.register_template(
        uri_template="ida://decompile/{query}",
        name="decompile_query",
        description="读取指定函数的高层表示。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.decompile_function(params["query"])),
    )
    resources.register_template(
        uri_template="ida://basic-blocks/{addr}",
        name="basic_blocks_addr",
        description="读取指定函数的基本块信息。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.get_basic_blocks(params["addr"])),
    )
    resources.register_template(
        uri_template="ida://stack-frame/{addr}",
        name="stack_frame",
        description="读取指定函数栈帧。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.get_stack_frame(params["addr"])),
    )
    resources.register_template(
        uri_template="ida://type/{name}",
        name="type_name",
        description="读取指定类型详情。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.inspect_type(params["name"])),
    )
    resources.register_template(
        uri_template="ida://import/{name}",
        name="import_name",
        description="读取指定导入符号。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.query_imports(name_filter=params["name"], limit=200)),
    )
    resources.register_template(
        uri_template="ida://export/{name}",
        name="export_name",
        description="读取指定导出符号。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: [item for item in core.entrypoints() if str(item.get("name", "")).lower() == params["name"].lower()]),
    )
    resources.register_template(
        uri_template="ida://xrefs/from/{addr}",
        name="xrefs_from",
        description="读取指定地址的向外 xref。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.get_xrefs_from(params["addr"])),
    )
    resources.register_template(
        uri_template="ida://callgraph/{root}",
        name="callgraph_root",
        description="读取指定根函数的调用图。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.build_callgraph([params["root"]], max_depth=3)),
    )
    resources.register_template(
        uri_template="ida://data-flow/{addr}",
        name="data_flow_addr",
        description="读取指定地址的增强版数据流追踪。",
        mime_type="application/json",
        handler=template_reader(lambda core, params: core.trace_data_flow(params["addr"], direction="both", max_depth=3)),
    )
    resources.register_template(
        uri_template="ida://managed/method/{query}",
        name="managed_method_query",
        description="读取指定托管方法的 managed 身份与高层表示。",
        mime_type="application/json",
        handler=template_reader(
            lambda core, params: {
                "identity": core.managed_method_identity(core.parse_address(params["query"])),
                "decompile": core.decompile_function(params["query"]),
            }
        ),
    )


def build_service(runtime: HeadlessRuntime, config: AppConfig, *, allow_unsafe: bool, allow_debugger: bool, profile_path: Path | None) -> ServiceBundle:
    """构建完整纯实现 headless 服务。"""
    tools = ToolRegistry()
    resources = ResourceRegistry()
    protected = _management_tools(tools, runtime, config, allow_unsafe=allow_unsafe, allow_debugger=allow_debugger)
    _register_read_tools(tools, runtime)
    if allow_unsafe:
        _register_unsafe_tools(tools, runtime)
    if allow_debugger:
        _register_debug_tools(tools, runtime)
    if profile_path is not None:
        whitelist = load_profile(profile_path)
        tools.apply_whitelist(whitelist, protected=protected)
    _register_resources(resources, runtime)
    return ServiceBundle(tools=tools, resources=resources)


def _require_string(arguments: JsonObject, key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串")
    return value


def _string_list(arguments: JsonObject, key: str) -> list[str]:
    value = arguments.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} 必须是字符串列表")
    result = [str(item) for item in value]
    return result


def _optional_query_list(arguments: JsonObject) -> list[str] | None:
    raw_queries = arguments.get("queries")
    if isinstance(raw_queries, list):
        return [str(item) for item in raw_queries]
    for key in ("query", "addr", "root"):
        value = arguments.get(key)
        if isinstance(value, str):
            return [value]
    return None


def _json_object_list(arguments: JsonObject, key: str) -> list[JsonObject]:
    value = arguments.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} 必须是对象列表")
    result: list[JsonObject] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{key} 内部元素必须是对象")
        result.append(item)
    return result


def _query_filter(arguments: JsonObject) -> str:
    raw_queries = arguments.get("queries")
    if isinstance(raw_queries, list) and raw_queries:
        first = raw_queries[0]
        if isinstance(first, dict):
            value = first.get("filter")
            if isinstance(value, str):
                return value
    raw_filter = arguments.get("filter")
    if isinstance(raw_filter, str):
        return raw_filter
    return ""


def _search_text(arguments: JsonObject) -> str:
    for key in ("pattern", "text", "query"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    raise ValueError("必须提供 pattern、text 或 query")


def _import_name_filter(arguments: JsonObject) -> str:
    for key in ("filter", "name_filter", "query", "name"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    return ""


def _addr_list(arguments: JsonObject, key: str) -> list[str]:
    value = arguments.get(key)
    if isinstance(value, list):
        return [str(item) for item in value]
    single = arguments.get("addr")
    if isinstance(single, str):
        return [single]
    raise ValueError(f"{key} 必须是地址列表，或提供单个 addr")


def _root_queries(arguments: JsonObject) -> list[str]:
    raw_roots = arguments.get("roots")
    if isinstance(raw_roots, list):
        return [str(item) for item in raw_roots]
    for key in ("root", "query", "addr"):
        value = arguments.get(key)
        if isinstance(value, str):
            return [value]
    raise ValueError("必须提供 roots，或提供 root/query/addr")


def _addr_or_query(arguments: JsonObject) -> str:
    for key in ("addr", "query"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    raise ValueError("必须提供 addr 或 query")


def _int_value(value: JsonValue) -> str | int:
    if isinstance(value, (str, int)):
        return value
    raise ValueError("value 必须是字符串或整数")
