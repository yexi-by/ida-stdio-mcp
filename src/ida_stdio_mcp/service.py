"""构建纯实现的 headless stdio 服务。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, cast

from .analysis_artifacts import import_analysis_artifact, list_analysis_artifacts, run_external_analyzer
from .config import ExternalAnalyzerConfig
from .errors import RuntimeNotReadyError, SessionNotFoundError, SessionRequiredError
from .models import BinarySummary, JsonObject, JsonValue, ToolResult, ToolStatus, ToolSurface
from .profile_loader import load_profile
from .prompts import PromptRegistry, build_prompt_registry
from .result import build_error_info, build_result, normalize_json_object
from .runtime import HeadlessRuntime
from .service_arguments import (
    addr_list as _addr_list,
    addr_or_query as _addr_or_query,
    bool_or_default as _bool_or_default,
    int_list as _int_list,
    int_or_default as _int_or_default,
    int_value as _int_value,
    json_object_list as _json_object_list,
    optional_query_list as _optional_query_list,
    query_filter as _query_filter,
    require_string as _require_string,
    root_queries as _root_queries,
    search_text as _search_text,
    string_list as _string_list,
    string_or_default as _string_or_default,
)
from .tool_registry import ResourceRegistry, ResourceSpec, ToolRegistry, ToolSpec

if TYPE_CHECKING:
    from .ida_core import IdaCore

COMMON_OUTPUT_SCHEMA: JsonObject = {
    "type": "object",
    "properties": {
        "status": {"type": "string"},
        "source": {"type": "string"},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "error": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "details": {"type": "object", "additionalProperties": True},
                        "next_steps": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["code", "message", "details", "next_steps"],
                    "additionalProperties": False,
                },
            ]
        },
        "data": {},
    },
    "required": ["status", "source", "warnings", "error", "data"],
    "additionalProperties": False,
}


def _string_schema(description: str, *, enum: list[str] | None = None) -> JsonObject:
    """构造字符串参数定义。"""
    schema: JsonObject = {"type": "string", "description": description}
    if enum is not None:
        schema["enum"] = [item for item in enum]
    return schema


def _integer_schema(description: str, *, minimum: int | None = None) -> JsonObject:
    """构造整数参数定义。"""
    schema: JsonObject = {"type": "integer", "description": description}
    if minimum is not None:
        schema["minimum"] = minimum
    return schema


def _boolean_schema(description: str, *, default: bool | None = None) -> JsonObject:
    """构造布尔参数定义。"""
    schema: JsonObject = {"type": "boolean", "description": description}
    if default is not None:
        schema["default"] = default
    return schema


def _array_schema(description: str, items: JsonObject, *, min_items: int | None = None) -> JsonObject:
    """构造数组参数定义。"""
    schema: JsonObject = {"type": "array", "description": description, "items": items}
    if min_items is not None:
        schema["minItems"] = min_items
    return schema


def _object_param_schema(
    description: str,
    properties: dict[str, JsonObject],
    *,
    required: tuple[str, ...] = (),
) -> JsonObject:
    """构造对象参数定义。"""
    return normalize_json_object(
        cast(
            JsonObject,
            {
                "type": "object",
                "description": description,
                "properties": cast(JsonValue, properties),
                "required": list(required),
                "additionalProperties": False,
            },
        )
    )


SESSION_ID_SCHEMA = _string_schema("可选。指定会话 ID；不传时默认作用于当前激活会话。")
CONTEXT_ID_SCHEMA = _string_schema("上下文 ID；启用 --isolated-contexts 时必须显式提供，用于隔离不同 agent 的默认会话。")
WORKFLOW_TOOL_NAMES = {
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
ADDR_OR_QUERY_PROPERTIES: dict[str, JsonObject] = {
    "addr": _string_schema("地址字符串，可写 0x 地址、十进制地址，或能解析到地址的符号名。"),
    "query": _string_schema("函数/符号查询文本；与 addr 二选一。"),
}
SEARCH_TEXT_PROPERTIES: dict[str, JsonObject] = {
    "pattern": _string_schema("搜索文本或模式。"),
}
PAGINATION_PROPERTIES: dict[str, JsonObject] = {
    "offset": _integer_schema("分页起始偏移。", minimum=0),
    "count": _integer_schema("返回数量；优先于 limit。", minimum=1),
    "limit": _integer_schema("返回数量上限。", minimum=1),
}
GENERAL_REGISTER_NAMES = ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "rip", "rsp", "rbp"]


def _tool_input_schema(
    *,
    properties: dict[str, JsonObject] | None = None,
    required: tuple[str, ...] = (),
    include_session: bool = False,
    include_context: bool = False,
    any_of: tuple[tuple[str, ...], ...] = (),
) -> JsonObject:
    """构造统一的 tool 输入 schema。

    公开 schema 固定使用“顶层 object + properties + required +
    additionalProperties=false”结构，便于 MCP 客户端和模型工具接口
    稳定读取字段。`any_of` 约束写入内部扩展字段，由服务端校验器
    在调用边界执行。
    """
    final_properties: JsonObject = {}
    if properties is not None:
        final_properties.update(deepcopy(properties))
    if include_session:
        final_properties["session_id"] = deepcopy(SESSION_ID_SCHEMA)
    if include_context:
        final_properties["context_id"] = deepcopy(CONTEXT_ID_SCHEMA)
    schema: JsonObject = {
        "type": "object",
        "properties": final_properties,
        "required": list(required),
        "additionalProperties": False,
    }
    if any_of:
        schema["x-required-any-of"] = [list(group) for group in any_of]
    return normalize_json_object(schema)


def _public_tool_schema(schema: JsonObject) -> JsonObject:
    """剥离仅供服务端内部校验使用的 schema 扩展字段。"""
    sanitized: JsonObject = {}
    for key, value in schema.items():
        if key.startswith("x-"):
            continue
        if isinstance(value, dict):
            sanitized[key] = _public_tool_schema(value)
            continue
        if isinstance(value, list):
            items: list[JsonValue] = []
            for item in value:
                if isinstance(item, dict):
                    items.append(_public_tool_schema(item))
                else:
                    items.append(item)
            sanitized[key] = items
            continue
        sanitized[key] = value
    return sanitized


def _mapped_error_info(
    *,
    name: str,
    source: str,
    exc: Exception,
    session_required: bool,
    context_required: bool,
) -> JsonObject:
    """把运行时异常映射为稳定、可恢复的结构化错误。"""
    if isinstance(exc, SessionRequiredError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="session_required",
            message=str(exc),
            details={
                "tool": name,
                "source": source,
                "requires_session": session_required,
                "requires_context": context_required,
            },
            next_steps=["先调用 open_target 打开样本", "或调用 get_workspace_state 查看当前会话", "若启用了隔离模式，请补充 context_id"],
        )))
    if isinstance(exc, SessionNotFoundError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="session_not_found",
            message=str(exc),
            details={
                "tool": name,
                "source": source,
                "requires_session": session_required,
                "requires_context": context_required,
            },
            next_steps=["先调用 get_workspace_state 查看当前有效会话", "再使用正确的 session_id 重新调用", "若启用了隔离模式，请确认 session_id 属于当前 context_id"],
        )))
    if isinstance(exc, FileNotFoundError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="path_not_found",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required, "requires_context": context_required},
            next_steps=["检查路径是否存在", "确认宿主进程对该路径有访问权限"],
        )))
    if isinstance(exc, NotADirectoryError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="path_not_directory",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required, "requires_context": context_required},
            next_steps=["改传目录路径", "或改用 open_target 打开单个文件"],
        )))
    if isinstance(exc, IsADirectoryError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="path_is_directory",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required, "requires_context": context_required},
            next_steps=["改传具体文件路径", "不要把目录路径传给只接受文件的工具"],
        )))
    if isinstance(exc, RuntimeNotReadyError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="runtime_not_ready",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required, "requires_context": context_required},
            next_steps=["检查 IDADIR 是否已设置且指向有效 IDA 安装目录"],
        )))
    if isinstance(exc, ValueError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="invalid_request",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required, "requires_context": context_required},
            next_steps=["按当前工具的 inputSchema 修正字段值或查询目标"],
        )))
    return normalize_json_object(cast(JsonObject, build_error_info(
        code="tool_execution_failed",
        message=str(exc),
        details={"tool": name, "source": source, "requires_session": session_required, "requires_context": context_required},
        next_steps=["检查当前数据库状态", "必要时查看文件日志中的异常上下文"],
    )))


def _error_result_from_exception(
    *,
    name: str,
    source: str,
    exc: Exception,
    session_required: bool,
    context_required: bool,
) -> ToolResult:
    """把异常转换成统一 tool/resource envelope。"""
    return build_result(
        status="error",
        source=source,
        data=None,
        error=_mapped_error_info(
            name=name,
            source=source,
            exc=exc,
            session_required=session_required,
            context_required=context_required,
        ),
    )


COMMENT_ITEM_SCHEMA = _object_param_schema(
    "单条注释编辑。",
    {
        "addr": _string_schema("目标地址。"),
        "comment": _string_schema("注释文本。"),
        "repeatable": _boolean_schema("是否写成 repeatable 注释。"),
    },
    required=("addr", "comment"),
)
RENAME_ITEM_SCHEMA = _object_param_schema(
    "单条符号重命名。",
    {"addr": _string_schema("目标地址。"), "name": _string_schema("新符号名。")},
    required=("addr", "name"),
)
PATCH_ASM_ITEM_SCHEMA = _object_param_schema(
    "单条汇编补丁。",
    {"addr": _string_schema("起始地址。"), "asm": _string_schema("汇编文本；可用分号分隔多条指令。")},
    required=("addr", "asm"),
)
PATCH_BYTES_ITEM_SCHEMA = _object_param_schema(
    "单条字节补丁。",
    {"addr": _string_schema("起始地址。"), "hex": _string_schema("十六进制字节串，不带 0x。")},
    required=("addr", "hex"),
)
WRITE_INT_ITEM_SCHEMA = _object_param_schema(
    "单条整数写入。",
    {
        "addr": _string_schema("目标地址。"),
        "value": _integer_schema("要写入的整数值。"),
        "size": _integer_schema("写入字节宽度，默认 4。", minimum=1),
        "signed": _boolean_schema("是否按有符号整数编码。"),
    },
    required=("addr", "value"),
)
READ_INT_QUERY_SCHEMA = _object_param_schema(
    "单条整数读取请求。",
    {
        "addr": _string_schema("目标地址。"),
        "size": _integer_schema("读取字节宽度，默认 4。", minimum=1),
        "signed": _boolean_schema("是否按有符号整数解释。"),
    },
    required=("addr",),
)
ENUM_MEMBER_SCHEMA = _object_param_schema(
    "枚举成员。",
    {"name": _string_schema("成员名。"), "value": _integer_schema("成员值。")},
    required=("name", "value"),
)
ENUM_ITEM_SCHEMA = _object_param_schema(
    "枚举定义。",
    {
        "name": _string_schema("枚举名。"),
        "members": _array_schema("成员列表。", ENUM_MEMBER_SCHEMA, min_items=1),
    },
    required=("name", "members"),
)
TYPE_ASSIGN_ITEM_SCHEMA = _object_param_schema(
    "单条类型赋值。",
    {"addr": _string_schema("目标地址。"), "type": _string_schema("C 风格类型声明。")},
    required=("addr", "type"),
)
STACK_VAR_DECLARE_ITEM_SCHEMA = _object_param_schema(
    "单条栈变量声明。",
    {
        "addr": _string_schema("函数地址或函数名。"),
        "name": _string_schema("栈变量名。"),
        "type": _string_schema("变量类型；推荐字段。"),
        "ty": _string_schema("type 的别名。"),
        "offset": {
            "description": "栈变量偏移；可为整数，也可为如 -0x20 的字符串。",
            "oneOf": [{"type": "integer"}, {"type": "string"}],
        },
    },
    required=("addr", "name", "offset"),
)
STACK_VAR_DELETE_ITEM_SCHEMA = _object_param_schema(
    "栈变量删除项。",
    {
        "addr": _string_schema("函数地址或名称。"),
        "name": _string_schema("栈变量名称。"),
        "offset": {
            "description": "可选的精确偏移；传入后会优先按偏移删除，避免名称重名或参数区/局部区混淆。",
            "oneOf": [{"type": "integer"}, {"type": "string"}],
        },
    },
    required=("addr",),
)
BREAKPOINT_TOGGLE_ITEM_SCHEMA = _object_param_schema(
    "单条断点启停请求。",
    {"addr": _string_schema("断点地址。"), "enabled": _boolean_schema("true 为启用，false 为禁用。")},
    required=("addr",),
)


@dataclass(slots=True, frozen=True)
class ServiceBundle:
    """服务构建结果。"""

    tools: ToolRegistry
    resources: ResourceRegistry
    prompts: PromptRegistry


def _ensure_session(arguments: JsonObject, runtime: HeadlessRuntime) -> None:
    """按请求参数激活会话，缺少会话时抛出结构化前置错误。"""
    raw_session = arguments.get("session_id")
    session_id = raw_session if isinstance(raw_session, str) and raw_session else None
    runtime.activate_for_request(session_id, context_id=_context_id(arguments))


def _context_id(arguments: JsonObject) -> str | None:
    """读取可选上下文 ID。"""
    raw_context = arguments.get("context_id")
    if raw_context is None:
        return None
    if not isinstance(raw_context, str):
        raise ValueError("context_id 必须是字符串")
    return raw_context or None


def _new_core() -> "IdaCore":
    """惰性创建 IDA 能力层对象，避免服务注册阶段强制加载 IDA。"""
    from .ida_core import IdaCore

    return IdaCore()


def _activity_target(arguments: JsonObject) -> str:
    """从工具参数中提取适合写入工作流状态的目标标识。"""
    for key in ("addr", "query", "pattern", "name", "path"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    items = arguments.get("items")
    if isinstance(items, list) and items:
        return f"items:{len(items)}"
    return ""


def _context_enabled_schema(runtime: HeadlessRuntime, schema: JsonObject, *, required: bool) -> JsonObject:
    """按运行模式把 context_id 暴露到公开 schema。"""
    if not runtime.isolated_contexts:
        return schema
    schema_copy = deepcopy(schema)
    properties = schema_copy.get("properties")
    if not isinstance(properties, dict):
        return schema_copy
    properties["context_id"] = deepcopy(CONTEXT_ID_SCHEMA)
    if required:
        required_fields = schema_copy.get("required")
        required_list: list[JsonValue] = [item for item in required_fields if isinstance(item, str)] if isinstance(required_fields, list) else []
        if "context_id" not in required_list:
            required_list.append("context_id")
        schema_copy["required"] = required_list
    return normalize_json_object(schema_copy)


def _with_context_preconditions(
    runtime: HeadlessRuntime,
    preconditions: tuple[str, ...],
    *,
    required: bool,
) -> tuple[str, ...]:
    """按运行模式补充上下文隔离前置条件。"""
    if not runtime.isolated_contexts or not required:
        return preconditions
    note = "启用 --isolated-contexts 后，必须显式提供 context_id。"
    if note in preconditions:
        return preconditions
    return (*preconditions, note)


def _with_context_example(
    runtime: HeadlessRuntime,
    input_example: JsonValue | None,
    *,
    required: bool,
) -> JsonValue | None:
    """按运行模式为示例补充 context_id。"""
    if not runtime.isolated_contexts or not required:
        return input_example
    context_value = "agent-001"
    if input_example is None:
        return {"context_id": context_value}
    if isinstance(input_example, dict):
        example = deepcopy(input_example)
        example.setdefault("context_id", context_value)
        return normalize_json_object(cast(JsonObject, example))
    return input_example


def _normalize_tool_data(value: object) -> JsonValue:
    """在协议边界把任意运行时值收窄为 JSON 值。

    本函数是协议层接收任意 `object` 的边界入口，用来承接 IDA 运行时
    与资源层回传的各类对象；入口处立即递归收窄，保证后续流程只处理
    可序列化的 JSON 值。
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        list_value = cast(list[object], value)
        return [_normalize_tool_data(item) for item in list_value]
    if isinstance(value, tuple):
        tuple_value = cast(tuple[object, ...], value)
        return [_normalize_tool_data(item) for item in tuple_value]
    if isinstance(value, dict):
        dict_value = cast(dict[object, object], value)
        return {str(key): _normalize_tool_data(item) for key, item in dict_value.items()}
    return str(value)


def _unwrap_statusful(value: object) -> tuple[ToolStatus, JsonValue, list[str]]:
    """识别核心层自带状态的结果并提取状态、数据与告警。"""
    if isinstance(value, dict):
        payload = cast(JsonObject, value)
        if {"status", "data", "warnings"} <= set(payload.keys()):
            raw_status = payload.get("status")
            raw_data = payload.get("data")
            raw_warnings = payload.get("warnings")
            status_value: ToolStatus = cast(ToolStatus, raw_status) if isinstance(raw_status, str) else "error"
            warnings = [str(item) for item in raw_warnings] if isinstance(raw_warnings, list) else []
            return status_value, _normalize_tool_data(raw_data), warnings
        if {"status", "representation", "warnings"} <= set(payload.keys()):
            raw_status = payload.get("status")
            raw_warnings = payload.get("warnings")
            representation_status: ToolStatus = cast(ToolStatus, raw_status) if isinstance(raw_status, str) else "error"
            warnings = [str(item) for item in raw_warnings] if isinstance(raw_warnings, list) else []
            return representation_status, _normalize_tool_data(cast(object, payload)), warnings
        if {"status", "warnings"} <= set(payload.keys()):
            raw_status = payload.get("status")
            raw_warnings = payload.get("warnings")
            payload_status: ToolStatus = cast(ToolStatus, raw_status) if isinstance(raw_status, str) else "error"
            warnings = [str(item) for item in raw_warnings] if isinstance(raw_warnings, list) else []
            return payload_status, _normalize_tool_data(cast(object, payload)), warnings
    return "ok", _normalize_tool_data(cast(object, value)), []


def _statusful_status(value: object) -> ToolStatus | None:
    """从子结果中读取统一状态。"""
    if not isinstance(value, dict):
        return None
    raw_status = cast(JsonObject, value).get("status")
    if raw_status in {"ok", "degraded", "unsupported", "error"}:
        return cast(ToolStatus, raw_status)
    return None


def _statusful_warnings(value: object) -> list[str]:
    """从子结果中读取告警列表。"""
    if not isinstance(value, dict):
        return []
    raw_warnings = cast(JsonObject, value).get("warnings")
    if not isinstance(raw_warnings, list):
        return []
    return [str(item) for item in raw_warnings]


def _combine_child_statuses(*values: object) -> tuple[ToolStatus, list[str]]:
    """把多个子结果状态合并成顶层状态和告警。"""
    statuses = [status for status in (_statusful_status(value) for value in values) if status is not None]
    warnings: list[str] = []
    for value in values:
        warnings.extend(_statusful_warnings(value))
    if "error" in statuses:
        return "error", warnings
    if "degraded" in statuses:
        return "degraded", warnings
    if "unsupported" in statuses:
        if any(status == "ok" for status in statuses):
            return "degraded", warnings
        return "unsupported", warnings
    return "ok", warnings


def _result_indicates_writeback(data: JsonValue) -> bool:
    """判断工具结果是否表示实际发生了写回。"""
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                return True
            applied = item.get("applied")
            if isinstance(applied, bool):
                if applied:
                    return True
                continue
            return True
        return False
    if isinstance(data, dict):
        applied = data.get("applied")
        if isinstance(applied, bool):
            return applied
    return True


def _with_writeback_state(data: JsonValue, session: BinarySummary) -> JsonObject:
    """把写回语义显式并入工具结果。"""
    return normalize_json_object(
        {
        "result": data,
        "dirty": bool(session.get("dirty", False)),
        "writeback_kind": session.get("writeback_kind"),
        "persistent_after_save": bool(session.get("persistent_after_save", False)),
        "saved_path": str(session.get("saved_path", "")),
        "undo_supported": bool(session.get("undo_supported", False)),
        }
    )


def _tool(
    registry: ToolRegistry,
    *,
    name: str,
    description: str,
    source: str,
    runtime: HeadlessRuntime,
    handler: Callable[[IdaCore, JsonObject], object],
    input_schema: JsonObject,
    session_required: bool = True,
    context_required: bool | None = None,
    writeback_kind: str | None = None,
    preconditions: tuple[str, ...] = (),
    empty_state_behavior: str = "",
    input_example: JsonValue | None = None,
) -> None:
    """注册一个绑定 IDA 能力层的工具并包裹会话、错误和写回语义。"""
    effective_context_required = runtime.isolated_contexts if context_required is None else context_required
    schema_with_context = _context_enabled_schema(runtime, input_schema, required=effective_context_required)
    effective_preconditions = _with_context_preconditions(
        runtime,
        preconditions,
        required=effective_context_required,
    )
    effective_input_example = _with_context_example(
        runtime,
        input_example,
        required=effective_context_required,
    )

    def wrapped(arguments: JsonObject) -> ToolResult:
        """执行单次工具调用并转换为统一工具结果。"""
        try:
            if session_required:
                _ensure_session(arguments, runtime)
            core = _new_core()
            raw = handler(core, arguments)
            status, data, warnings = _unwrap_statusful(raw)
            if writeback_kind is not None and status in {"ok", "degraded"}:
                if _result_indicates_writeback(data):
                    session = runtime.mark_writeback(
                        writeback_kind=writeback_kind,
                        session_id=_string_or_default(arguments, "session_id", "") or None,
                        context_id=_context_id(arguments),
                    )
                else:
                    session = runtime.current_target(context_id=_context_id(arguments))
                data = _with_writeback_state(data, session)
            if session_required and status in {"ok", "degraded"}:
                runtime.record_activity(
                    name,
                    target=_activity_target(arguments),
                    session_id=_string_or_default(arguments, "session_id", "") or None,
                    context_id=_context_id(arguments),
                )
            return build_result(status=status, source=source, data=data, warnings=warnings)
        except Exception as exc:
            return _error_result_from_exception(
                name=name,
                source=source,
                exc=exc,
                session_required=session_required,
                context_required=effective_context_required,
            )

    registry.register(
        ToolSpec(
            name=name,
            description=description,
            input_schema=_public_tool_schema(schema_with_context),
            output_schema=COMMON_OUTPUT_SCHEMA,
            handler=wrapped,
            validation_schema=schema_with_context,
            requires_session=session_required,
            requires_context=effective_context_required,
            preconditions=effective_preconditions,
            empty_state_behavior=empty_state_behavior,
            input_example=effective_input_example,
        )
    )


def _management_tools(
    registry: ToolRegistry,
    runtime: HeadlessRuntime,
) -> None:
    """注册不直接复用 `_tool` 包装器的工作流管理工具。"""
    context_required = runtime.isolated_contexts

    def register_management_tool(
        *,
        name: str,
        description: str,
        schema: JsonObject,
        handler: Callable[[JsonObject], ToolResult],
        requires_session: bool,
        requires_context: bool | None = None,
        preconditions: tuple[str, ...] = (),
        empty_state_behavior: str = "",
        input_example: JsonValue | None = None,
    ) -> None:
        """注册一个工作流管理工具并补齐上下文隔离元数据。"""
        effective_requires_context = context_required if requires_context is None else requires_context
        schema_with_context = _context_enabled_schema(
            runtime,
            schema,
            required=effective_requires_context,
        )
        registry.register(
            ToolSpec(
                name=name,
                description=description,
                input_schema=_public_tool_schema(schema_with_context),
                output_schema=COMMON_OUTPUT_SCHEMA,
                handler=handler,
                validation_schema=schema_with_context,
                requires_session=requires_session,
                requires_context=effective_requires_context,
                preconditions=_with_context_preconditions(
                    runtime,
                    preconditions,
                    required=effective_requires_context,
                ),
                empty_state_behavior=empty_state_behavior,
                input_example=_with_context_example(
                    runtime,
                    input_example,
                    required=effective_requires_context,
                ),
            )
        )

    def management_error_result(name: str, source: str, exc: Exception, *, session_required: bool, requires_context: bool) -> ToolResult:
        """把工作流管理工具异常转换为统一结果。"""
        return _error_result_from_exception(
            name=name,
            source=source,
            exc=exc,
            session_required=session_required,
            context_required=requires_context,
        )

    def get_workspace_state_handler(arguments: JsonObject) -> ToolResult:
        """处理工作区状态查询。"""
        try:
            return build_result(
                status="ok",
                source="workflow.get_workspace_state",
                data=_normalize_tool_data(runtime.workspace_state(context_id=_context_id(arguments))),
            )
        except Exception as exc:
            return management_error_result("get_workspace_state", "workflow.get_workspace_state", exc, session_required=False, requires_context=context_required)

    def runtime_health_handler(_arguments: JsonObject) -> ToolResult:
        """处理 IDA runtime health 查询。"""
        try:
            return build_result(
                status="ok",
                source="health.runtime",
                data=_normalize_tool_data(runtime.runtime_health()),
            )
        except Exception as exc:
            return management_error_result("runtime_health", "health.runtime", exc, session_required=False, requires_context=False)

    def get_capability_state_handler(arguments: JsonObject) -> ToolResult:
        """处理统一能力状态查询。"""
        try:
            return build_result(
                status="ok",
                source="health.capabilities",
                data=_normalize_tool_data(runtime.capability_snapshot(context_id=_context_id(arguments))),
            )
        except Exception as exc:
            return management_error_result("get_capability_state", "health.capabilities", exc, session_required=False, requires_context=context_required)

    def open_target_handler(arguments: JsonObject) -> ToolResult:
        """处理样本打开请求并返回绑定会话摘要。"""
        try:
            raw_path = _require_string(arguments, "path")
            summary = runtime.open_target(
                Path(raw_path),
                run_auto_analysis=_bool_or_default(arguments, "run_auto_analysis", False),
                loader=_string_or_default(arguments, "loader", ""),
                processor=_string_or_default(arguments, "processor", ""),
                plugin_options=tuple(_string_list(arguments, "plugin_options")) if "plugin_options" in arguments else None,
                session_id=_string_or_default(arguments, "session_id", "") or None,
                context_id=_context_id(arguments),
            )
            return build_result(status="ok", source="workflow.open_target", data=_normalize_tool_data(summary))
        except Exception as exc:
            return management_error_result("open_target", "workflow.open_target", exc, session_required=False, requires_context=context_required)

    def triage_binary_handler(arguments: JsonObject) -> ToolResult:
        """处理开局分析请求并记录工作流活动。"""
        try:
            _ensure_session(arguments, runtime)
            core = _new_core()
            summary = core.triage_binary_snapshot(
                function_limit=_int_or_default(arguments, "function_limit", 12),
                string_limit=_int_or_default(arguments, "string_limit", 12),
                import_limit_per_category=_int_or_default(arguments, "import_limit_per_category", 6),
                include_strings=_bool_or_default(arguments, "include_strings", False),
            )
            runtime.record_activity(
                "triage_binary",
                target="triage",
                session_id=_string_or_default(arguments, "session_id", "") or None,
                context_id=_context_id(arguments),
            )
            status, warnings = _combine_child_statuses(summary)
            return build_result(
                status=status,
                source="workflow.triage_binary",
                data=_normalize_tool_data(
                    {
                        "session": runtime.current_target(context_id=_context_id(arguments)),
                        "summary": summary,
                    }
                ),
                warnings=warnings,
            )
        except Exception as exc:
            return management_error_result("triage_binary", "workflow.triage_binary", exc, session_required=True, requires_context=context_required)

    def investigate_string_handler(arguments: JsonObject) -> ToolResult:
        """处理字符串牵引调查请求。"""
        try:
            _ensure_session(arguments, runtime)
            pattern = _string_or_default(arguments, "pattern", "")
            addr = _string_or_default(arguments, "addr", "")
            core = _new_core()
            usage = core.investigate_string(
                pattern=pattern,
                addr=addr,
                max_strings=_int_or_default(arguments, "max_strings", 20),
                max_usages=_int_or_default(arguments, "max_usages", 100),
            )
            runtime.record_activity(
                "investigate_string",
                target=pattern or addr,
                session_id=_string_or_default(arguments, "session_id", "") or None,
                context_id=_context_id(arguments),
            )
            return build_result(status="ok", source="workflow.investigate_string", data=_normalize_tool_data(usage))
        except Exception as exc:
            return management_error_result("investigate_string", "workflow.investigate_string", exc, session_required=True, requires_context=context_required)

    def explain_function_handler(arguments: JsonObject) -> ToolResult:
        """处理函数解释请求并聚合画像、反编译和可选 microcode。"""
        try:
            _ensure_session(arguments, runtime)
            query = _addr_or_query(arguments)
            core = _new_core()
            profile = core.get_function_profile(query, include_asm=_bool_or_default(arguments, "include_asm", False))
            representation = core.decompile_function(query)
            microcode: JsonValue = None
            if _bool_or_default(arguments, "include_microcode", False):
                microcode = core.microcode_summary(query, max_instructions=_int_or_default(arguments, "max_micro_instructions", 80))
            status, warnings = _combine_child_statuses(representation, microcode)
            runtime.record_activity(
                "explain_function",
                target=query,
                session_id=_string_or_default(arguments, "session_id", "") or None,
                context_id=_context_id(arguments),
            )
            return build_result(
                status=status,
                source="workflow.explain_function",
                data=_normalize_tool_data(
                    {
                        "profile": profile,
                        "representation": representation,
                        "microcode": microcode,
                        "recommended_next_tools": ["trace_input_to_check", "investigate_string", "export_report"],
                    }
                ),
                warnings=warnings,
            )
        except Exception as exc:
            return management_error_result("explain_function", "workflow.explain_function", exc, session_required=True, requires_context=context_required)

    def trace_input_to_check_handler(arguments: JsonObject) -> ToolResult:
        """处理输入到检查点的轻量追踪请求。"""
        try:
            _ensure_session(arguments, runtime)
            query = _require_string(arguments, "addr")
            core = _new_core()
            data_flow = core.trace_data_flow(
                query,
                direction=_string_or_default(arguments, "direction", "both"),
                max_depth=_int_or_default(arguments, "max_depth", 5),
            )
            runtime.record_activity(
                "trace_input_to_check",
                target=query,
                session_id=_string_or_default(arguments, "session_id", "") or None,
                context_id=_context_id(arguments),
            )
            return build_result(status="ok", source="workflow.trace_input_to_check", data=_normalize_tool_data(data_flow))
        except Exception as exc:
            return management_error_result("trace_input_to_check", "workflow.trace_input_to_check", exc, session_required=True, requires_context=context_required)

    def export_report_handler(arguments: JsonObject) -> ToolResult:
        """处理结构化报告导出请求。"""
        try:
            _ensure_session(arguments, runtime)
            core = _new_core()
            report = core.build_analysis_report(
                function_limit=_int_or_default(arguments, "function_limit", 120),
                string_limit=_int_or_default(arguments, "string_limit", 200),
                global_limit=_int_or_default(arguments, "global_limit", 120),
                import_limit=_int_or_default(arguments, "import_limit", 240),
                type_limit=_int_or_default(arguments, "type_limit", 120),
                struct_limit=_int_or_default(arguments, "struct_limit", 80),
                include_decompile=_bool_or_default(arguments, "include_decompile", False),
                include_asm=_bool_or_default(arguments, "include_asm", False),
            )
            runtime.record_activity(
                "export_report",
                target="report",
                session_id=_string_or_default(arguments, "session_id", "") or None,
                context_id=_context_id(arguments),
            )
            return build_result(
                status="ok",
                source="workflow.export_report",
                data=_normalize_tool_data(
                    {
                        "session": runtime.current_target(context_id=_context_id(arguments)),
                        "report": report,
                    }
                ),
            )
        except Exception as exc:
            return management_error_result("export_report", "workflow.export_report", exc, session_required=True, requires_context=context_required)

    def save_workspace_handler(arguments: JsonObject) -> ToolResult:
        """处理工作 IDB 保存或导出请求。"""
        try:
            session_id = _string_or_default(arguments, "session_id", "") or None
            path = _string_or_default(arguments, "path", "")
            saved = runtime.save_workspace(path=path, session_id=session_id, context_id=_context_id(arguments))
            if saved.get("ok") is False:
                error_text = saved.get("error")
                raise RuntimeError(str(error_text) if isinstance(error_text, str) and error_text else "保存工作 IDB 失败")
            return build_result(
                status="ok",
                source="workflow.save_workspace",
                data=_normalize_tool_data(saved),
            )
        except Exception as exc:
            return management_error_result("save_workspace", "workflow.save_workspace", exc, session_required=True, requires_context=context_required)

    def close_target_handler(arguments: JsonObject) -> ToolResult:
        """处理会话关闭请求。"""
        try:
            raw_session = arguments.get("session_id")
            session_id = raw_session if isinstance(raw_session, str) else None
            runtime.close_target(session_id, context_id=_context_id(arguments))
            return build_result(
                status="ok",
                source="workflow.close_target",
                data=_normalize_tool_data({"closed": True, "session_id": session_id}),
            )
        except Exception as exc:
            return management_error_result("close_target", "workflow.close_target", exc, session_required=True, requires_context=context_required)

    register_management_tool(
        name="get_workspace_state",
        description="工作区状态：返回 IDA 9.3+ 运行时、当前会话、工作 IDB、最近目标和推荐下一步；适合作为 AI 分析流程的第一步。",
        schema=_tool_input_schema(),
        handler=get_workspace_state_handler,
        requires_session=False,
        empty_state_behavior="无会话时返回 sessions=[] 与推荐 open_target，不视为错误。",
        input_example={},
    )
    register_management_tool(
        name="runtime_health",
        description="读取 IDA headless runtime 分层诊断，区分 idapro 包缺失、IDALIB 动态库加载失败、版本不足和可用状态。",
        schema=_tool_input_schema(),
        handler=runtime_health_handler,
        requires_session=False,
        requires_context=False,
        empty_state_behavior="不需要活动会话；用于排查 IDA runtime 初始化。",
        input_example={},
    )
    register_management_tool(
        name="get_capability_state",
        description="读取统一能力初始化快照，覆盖 IDA runtime、open_target、debugger、Hex-Rays、managed decompiler 和 external analyzer。",
        schema=_tool_input_schema(),
        handler=get_capability_state_handler,
        requires_session=False,
        empty_state_behavior="无会话时仍返回 runtime 与待初始化能力状态。",
        input_example={},
    )
    register_management_tool(
        name="open_target",
        description="打开样本：加载原始文件并创建 .runtime/sessions/<session_id>/working.i64 工作库；后续分析、写回和保存都作用于工作 IDB。",
        schema=_tool_input_schema(
            properties={
                "path": _string_schema("二进制文件路径。"),
                "run_auto_analysis": _boolean_schema(
                    "是否在打开后等待全库自动分析完成。默认 false；大型样本保持 false，后续工具按需做定点分析。",
                    default=False,
                ),
                "loader": _string_schema("可选。IDA loader 名称；映射为 headless -T 参数。"),
                "processor": _string_schema("可选。IDA processor 名称；映射为 headless -p 参数。"),
                "plugin_options": _array_schema(
                    "可选。IDA 插件选项列表；每项映射为 headless -O<plugin>:<options> 参数。",
                    _string_schema("单条插件选项，不含 -O 前缀。"),
                ),
            },
            required=("path",),
            include_session=True,
        ),
        handler=open_target_handler,
        requires_session=False,
        empty_state_behavior="无需现有会话；成功后返回绑定会话和工作 IDB 路径。",
        input_example={
            "path": "<输入文件>",
            "run_auto_analysis": False,
            "loader": "",
            "processor": "",
            "plugin_options": [],
            "session_id": "sess-001",
        },
    )
    register_management_tool(
        name="triage_binary",
        description="开局分析：返回样本摘要、入口点、关键函数、导入分类、字符串索引状态、托管质量等级和推荐下一步；默认不构建全量字符串索引。",
        schema=_tool_input_schema(
            properties={
                "function_limit": _integer_schema("返回多少个关键函数摘要。", minimum=1),
                "string_limit": _integer_schema("include_strings=true 时返回多少个关键字符串。", minimum=1),
                "import_limit_per_category": _integer_schema("每类导入最多展示多少条。", minimum=1),
                "include_strings": _boolean_schema("是否显式构建字符串索引。默认 false。"),
            },
            include_session=True,
        ),
        handler=triage_binary_handler,
        requires_session=True,
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        input_example={"session_id": "sess-001", "include_strings": False, "function_limit": 12},
    )
    register_management_tool(
        name="investigate_string",
        description="字符串牵引调查：输入字符串、URL、路径、错误文案或字符串地址，返回 string -> xref -> 所属函数的闭环线索。",
        schema=_tool_input_schema(
            properties={
                "pattern": _string_schema("要查的字符串内容、错误文案、URL、路径或协议字段。"),
                "addr": _string_schema("字符串地址；与 pattern 二选一。"),
                "max_strings": _integer_schema("最多展开多少条匹配字符串。", minimum=1),
                "max_usages": _integer_schema("最多返回多少条使用点。", minimum=1),
            },
            include_session=True,
            any_of=(("pattern",), ("addr",)),
        ),
        handler=investigate_string_handler,
        requires_session=True,
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        input_example={"session_id": "sess-001", "pattern": "error", "max_strings": 10, "max_usages": 40},
    )
    register_management_tool(
        name="explain_function",
        description="函数解释：一次返回函数画像、调用关系、字符串/常量、伪代码或托管 C# 表示；可选附带只读 microcode summary 线索。",
        schema=_tool_input_schema(
            properties={
                **ADDR_OR_QUERY_PROPERTIES,
                "include_asm": _boolean_schema("是否包含完整反汇编。默认 false。"),
                "include_microcode": _boolean_schema("是否附带只读 microcode summary。需要 Hex-Rays。"),
                "max_micro_instructions": _integer_schema("microcode summary 最多返回多少条指令。", minimum=1),
            },
            include_session=True,
            any_of=(("addr",), ("query",)),
        ),
        handler=explain_function_handler,
        requires_session=True,
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        input_example={"session_id": "sess-001", "query": "main", "include_asm": False},
    )
    register_management_tool(
        name="trace_input_to_check",
        description="输入到检查点追踪：围绕地址或函数做轻量数据流追踪，适合顺着输入、鉴权、路径、协议字段追到比较与分支。",
        schema=_tool_input_schema(
            properties={
                "addr": _string_schema("起始地址、函数名或符号名。"),
                "direction": _string_schema("追踪方向。", enum=["forward", "backward", "both"]),
                "max_depth": _integer_schema("最大追踪深度。", minimum=1),
            },
            required=("addr",),
            include_session=True,
        ),
        handler=trace_input_to_check_handler,
        requires_session=True,
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        input_example={"session_id": "sess-001", "addr": "main", "direction": "both", "max_depth": 4},
    )
    register_management_tool(
        name="export_report",
        description="报告导出：导出适合 AI 复盘的当前样本报告，包含元数据、入口、导入、字符串、类型、结构与函数摘要。",
        schema=_tool_input_schema(
            properties={
                "function_limit": _integer_schema("最多导出多少个函数。", minimum=1),
                "string_limit": _integer_schema("最多导出多少条字符串。", minimum=1),
                "global_limit": _integer_schema("最多导出多少个全局符号。", minimum=1),
                "import_limit": _integer_schema("最多导出多少条导入。", minimum=1),
                "type_limit": _integer_schema("最多导出多少条类型记录。", minimum=1),
                "struct_limit": _integer_schema("最多导出多少条结构体记录。", minimum=1),
                "include_decompile": _boolean_schema("函数导出中是否包含反编译伪代码。默认 false。"),
                "include_asm": _boolean_schema("函数导出中是否包含汇编文本。默认 false。"),
            },
            include_session=True,
        ),
        handler=export_report_handler,
        requires_session=True,
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        input_example={"session_id": "sess-001", "function_limit": 80, "include_decompile": False},
    )
    register_management_tool(
        name="save_workspace",
        description="保存工作区：默认保存当前 working.i64；显式传 path 时导出到用户指定路径。",
        schema=_tool_input_schema(
            properties={"path": _string_schema("可选导出路径；为空则保存当前工作 IDB。")},
            include_session=True,
        ),
        handler=save_workspace_handler,
        requires_session=False,
        preconditions=("若不传 session_id，则必须存在活动会话。",),
        input_example={"session_id": "sess-001"},
    )
    register_management_tool(
        name="close_target",
        description="关闭样本：关闭指定或当前会话，保留 .runtime/sessions 下的工作 IDB。",
        schema=_tool_input_schema(include_session=True),
        handler=close_target_handler,
        requires_session=False,
        preconditions=("若不传 session_id，则必须存在活动会话。",),
        input_example={"session_id": "sess-001"},
    )

def _register_read_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册只读分析、查询与导出工具。"""
    _tool(
        registry,
        name="list_functions",
        description="分页列函数、做函数名筛选并枚举目标函数；适合先看函数列表、入口函数和批量逆向目标。",
        source="core.list_functions",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "filter": _string_schema("函数名筛选文本。"),
                **PAGINATION_PROPERTIES,
            },
            include_session=True,
        ),
        handler=lambda core, arguments: core.list_functions(
            filter_text=_query_filter(arguments),
            offset=_int_or_default(arguments, "offset", 0),
            limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100)),
        ),
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        empty_state_behavior="无活动会话时返回 session_required。",
        input_example={"session_id": "sess-001", "filter": "main", "count": 20},
    )
    _tool(
        registry,
        name="get_function",
        description="返回单个函数详情以及 callers/callees；适合按函数名或地址定位目标函数并看调用关系。",
        source="core.get_function",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_function(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="get_function_profile",
        description="读取函数画像，聚合字符串、常量、calls/xrefs、基本块、注释等摘要；适合单函数分析。",
        source="core.get_function_profile",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={**ADDR_OR_QUERY_PROPERTIES, "include_asm": _boolean_schema("是否在结果中包含函数反汇编。")},
            include_session=True,
            any_of=(("addr",), ("query",)),
        ),
        handler=lambda core, arguments: core.get_function_profile(_addr_or_query(arguments), include_asm=_bool_or_default(arguments, "include_asm", True)),
    )
    _tool(
        registry,
        name="analyze_functions",
        description="批量分析多个函数，适合一次性拉取多个目标函数的画像摘要。",
        source="core.analyze_functions",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("函数地址/函数名列表。", _string_schema("函数地址或函数名。"), min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.analyze_functions(_string_list(arguments, "items")),
    )
    _tool(
        registry,
        name="decompile_function",
        description="读取反编译伪代码 / 高层表示：native 优先 Hex-Rays C 伪代码，托管/.NET 优先 C#；失败时降级为 IL 或汇编文本。",
        source="core.decompile_function",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.decompile_function(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="disassemble_function",
        description="读取函数汇编 / 反汇编文本，适合在没有伪代码时直接看指令级逻辑。",
        source="core.disassemble_function",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.disassemble_function(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="list_globals",
        description="分页列出全局变量。",
        source="core.list_globals",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"filter": _string_schema("全局变量名筛选文本。"), **PAGINATION_PROPERTIES},
            include_session=True,
        ),
        handler=lambda core, arguments: core.list_globals(
            filter_text=_string_or_default(arguments, "filter", ""),
            offset=_int_or_default(arguments, "offset", 0),
            limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100)),
        ),
    )
    _tool(
        registry,
        name="list_imports",
        description="列出导入表。",
        source="core.list_imports",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=PAGINATION_PROPERTIES, include_session=True),
        handler=lambda core, arguments: core.list_imports(offset=_int_or_default(arguments, "offset", 0), limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 200))),
    )
    _tool(
        registry,
        name="query_imports",
        description="按条件查询导入表。",
        source="core.query_imports",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "module": _string_schema("模块名筛选。"),
                "filter": _string_schema("导入名筛选。"),
                **PAGINATION_PROPERTIES,
            },
            include_session=True,
        ),
        handler=lambda core, arguments: core.query_imports(
            module=_string_or_default(arguments, "module", ""),
            filter_text=_string_or_default(arguments, "filter", ""),
            offset=_int_or_default(arguments, "offset", 0),
            limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 200)),
        ),
    )
    _tool(
        registry,
        name="get_import_at",
        description="IDA 9.3+ import-by-address：按地址解析导入项，并返回 module/name/ordinal 富化信息。",
        source="core.get_import_at",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addr": _string_schema("导入表地址、IAT thunk 或外部调用目标地址。")},
            required=("addr",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.get_import_at(_require_string(arguments, "addr")),
        input_example={"session_id": "sess-001", "addr": "0x401000"},
    )
    _tool(
        registry,
        name="query_xrefs",
        description="按条件查询交叉引用 / xref，支持 from/to 方向和类型过滤。",
        source="core.query_xrefs",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "query": _string_schema("要查询 xref 的地址、函数名或符号名。"),
                "direction": _string_schema("查询方向：from 表示从该地址向外看，to 表示看谁引用了该地址。", enum=["from", "to"]),
                "filter": _string_schema("xref 类型筛选，例如 Code_Near_Call。"),
            },
            required=("query",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.query_xrefs(
            query=_require_string(arguments, "query"),
            direction=_string_or_default(arguments, "direction", "to"),
            filter_text=_string_or_default(arguments, "filter", ""),
        ),
    )
    _tool(
        registry,
        name="get_callers",
        description="读取函数调用者，查看哪些函数会调用当前目标函数。",
        source="core.get_callers",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_callers(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="get_callees",
        description="读取函数调用目标，查看当前函数调用了哪些内部或外部目标。",
        source="core.get_callees",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_callees(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="get_basic_blocks",
        description="读取函数基本块与控制流边，适合做 CFG、复杂度和路径分析。",
        source="core.get_basic_blocks",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_basic_blocks(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="list_strings",
        description="分页列字符串，适合做字符串总览、字面量审计、提示词/路径/URL 摸排；首次调用会构建当前 working IDB 的受控字符串缓存，返回 data/cache/statistics。",
        source="core.list_strings",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=PAGINATION_PROPERTIES, include_session=True),
        handler=lambda core, arguments: core.list_strings(offset=_int_or_default(arguments, "offset", 0), limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100))),
    )
    _tool(
        registry,
        name="find_strings",
        description="按子串搜索字符串，快速查提示词、错误文案、URL、路径、协议字段；复用当前 working IDB 的字符串缓存并返回 cache 命中状态。",
        source="core.find_strings",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={**SEARCH_TEXT_PROPERTIES, **PAGINATION_PROPERTIES}, include_session=True, required=("pattern",)),
        handler=lambda core, arguments: core.find_strings(_search_text(arguments), offset=_int_or_default(arguments, "offset", 0), limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100))),
    )
    _tool(
        registry,
        name="search_regex",
        description="对字符串做正则搜索，适合批量查模式化字面量、路径、域名、格式串；复用当前 working IDB 的字符串缓存并返回 cache 命中状态。",
        source="core.search_regex",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={**SEARCH_TEXT_PROPERTIES, **PAGINATION_PROPERTIES}, include_session=True, required=("pattern",)),
        handler=lambda core, arguments: core.search_regex(_search_text(arguments), offset=_int_or_default(arguments, "offset", 0), limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100))),
    )
    _tool(
        registry,
        name="find_bytes",
        description="按字节模式搜索。",
        source="core.find_bytes",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"pattern": _string_schema("十六进制字节模式。"), "max_hits": _integer_schema("最大命中数。", minimum=1)},
            required=("pattern",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.find_bytes(_require_string(arguments, "pattern"), max_hits=_int_or_default(arguments, "max_hits", 100)),
    )
    _tool(
        registry,
        name="find_items",
        description="按高级条件搜索字符串/函数。",
        source="core.find_items",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={**SEARCH_TEXT_PROPERTIES, "max_hits": _integer_schema("最大命中数。", minimum=1)},
            include_session=True,
            required=("pattern",),
        ),
        handler=lambda core, arguments: core.find_items(_search_text(arguments), max_hits=_int_or_default(arguments, "max_hits", 100)),
    )
    _tool(
        registry,
        name="query_instructions",
        description="按指令模式查询。",
        source="core.query_instructions",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"pattern": _string_schema("指令助记符，例如 mov、call、jmp。"), "max_hits": _integer_schema("最大命中数。", minimum=1)},
            required=("pattern",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.query_instructions(_require_string(arguments, "pattern"), max_hits=_int_or_default(arguments, "max_hits", 100)),
    )
    _tool(
        registry,
        name="read_bytes",
        description="读取内存字节。",
        source="core.read_bytes",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "addrs": _array_schema("地址列表。", _string_schema("地址或符号名。"), min_items=1),
                "addr": _string_schema("单个地址；与 addrs 二选一。"),
                "size": _integer_schema("每个地址读取字节数。", minimum=1),
            },
            include_session=True,
            any_of=(("addrs",), ("addr",)),
        ),
        handler=lambda core, arguments: core.read_bytes(_addr_list(arguments, "addrs"), size=_int_or_default(arguments, "size", 16)),
    )
    _tool(
        registry,
        name="read_ints",
        description="读取整数。",
        source="core.read_ints",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("整数读取请求列表。", READ_INT_QUERY_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.read_ints(_json_object_list(arguments, "items")),
    )
    _tool(
        registry,
        name="read_strings",
        description="读取字符串。",
        source="core.read_strings",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "addrs": _array_schema("地址列表。", _string_schema("地址或符号名。"), min_items=1),
                "addr": _string_schema("单个地址；与 addrs 二选一。"),
                "max_length": _integer_schema("最大读取长度。", minimum=1),
            },
            include_session=True,
            any_of=(("addrs",), ("addr",)),
        ),
        handler=lambda core, arguments: core.read_strings(_addr_list(arguments, "addrs"), max_length=_int_or_default(arguments, "max_length", 512)),
    )
    _tool(
        registry,
        name="read_global_values",
        description="读取全局变量值。",
        source="core.read_global_values",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "addrs": _array_schema("地址列表。", _string_schema("全局变量地址或名称。"), min_items=1),
                "addr": _string_schema("单个地址；与 addrs 二选一。"),
                "size": _integer_schema("读取字节宽度。", minimum=1),
            },
            include_session=True,
            any_of=(("addrs",), ("addr",)),
        ),
        handler=lambda core, arguments: core.read_global_values(_addr_list(arguments, "addrs"), size=_int_or_default(arguments, "size", 8)),
    )
    _tool(
        registry,
        name="get_stack_frame",
        description="读取函数栈帧、局部变量槽位和成员布局。",
        source="core.get_stack_frame",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_stack_frame(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="read_struct",
        description="读取结构体字段定义，查看成员、偏移、大小；支持本地 UDT 与托管类型。",
        source="core.read_struct",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"name": _string_schema("结构体名、本地 UDT 名或托管类型名。")},
            required=("name",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.read_struct(_require_string(arguments, "name")),
    )
    _tool(
        registry,
        name="search_structs",
        description="搜索结构体，按结构体名筛选并查看成员数量。",
        source="core.search_structs",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={"filter": _string_schema("结构体名筛选文本。")}, include_session=True),
        handler=lambda core, arguments: core.search_structs(_string_or_default(arguments, "filter", "")),
    )
    _tool(
        registry,
        name="query_types",
        description="查询类型目录，列出本地类型/托管类型；适合查类型名、函数原型、UDT 和声明。",
        source="core.query_types",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={"filter": _string_schema("类型名筛选文本。")}, include_session=True),
        handler=lambda core, arguments: core.query_types(_string_or_default(arguments, "filter", "")),
    )
    _tool(
        registry,
        name="inspect_type",
        description="读取具体类型详情，查看类型声明、成员布局、字段定义与来源。",
        source="core.inspect_type",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"name": _string_schema("类型名。")},
            required=("name",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.inspect_type(_require_string(arguments, "name")),
    )
    _tool(
        registry,
        name="export_functions",
        description="导出函数分析结果；支持结构化 JSON、函数原型、近似头文件，适合批量复盘、报告和继续喂给 AI。",
        source="core.export_functions",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "items": _array_schema("要导出的函数列表；不传则按 limit 导出全部函数。", _string_schema("函数地址或函数名。")),
                "query": _string_schema("单个函数；items 的别名。"),
                "addr": _string_schema("单个函数地址；items 的别名。"),
                "format": _string_schema("导出格式。", enum=["json", "c_header", "prototypes"]),
                "format_name": _string_schema("导出格式别名。", enum=["json", "c_header", "prototypes"]),
                "limit": _integer_schema("最多导出多少个函数。", minimum=1),
            },
            include_session=True,
        ),
        handler=lambda core, arguments: core.export_functions(
            items=_optional_query_list(arguments),
            format_name=_string_or_default(arguments, "format", _string_or_default(arguments, "format_name", "json")),
            limit=_int_or_default(arguments, "limit", 1000),
        ),
    )
    _tool(
        registry,
        name="export_full_analysis",
        description="导出当前 IDB 的完整分析结果，包含 metadata、入口点、imports、globals、strings、types、structs、functions 等结构化内容。",
        source="core.export_full_analysis",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "function_limit": _integer_schema("最多导出多少个函数。", minimum=1),
                "string_limit": _integer_schema("最多导出多少条字符串。", minimum=1),
                "global_limit": _integer_schema("最多导出多少个全局符号。", minimum=1),
                "import_limit": _integer_schema("最多导出多少条导入。", minimum=1),
                "type_limit": _integer_schema("最多导出多少条类型目录记录。", minimum=1),
                "struct_limit": _integer_schema("最多导出多少条结构体记录。", minimum=1),
                "include_decompile": _boolean_schema("函数导出中是否包含反编译伪代码。"),
                "include_asm": _boolean_schema("函数导出中是否包含汇编文本。"),
            },
            include_session=True,
        ),
        handler=lambda core, arguments: core.export_full_analysis(
            function_limit=_int_or_default(arguments, "function_limit", 200),
            string_limit=_int_or_default(arguments, "string_limit", 500),
            global_limit=_int_or_default(arguments, "global_limit", 200),
            import_limit=_int_or_default(arguments, "import_limit", 500),
            type_limit=_int_or_default(arguments, "type_limit", 200),
            struct_limit=_int_or_default(arguments, "struct_limit", 100),
            include_decompile=_bool_or_default(arguments, "include_decompile", True),
            include_asm=_bool_or_default(arguments, "include_asm", False),
        ),
        input_example={"session_id": "sess-001", "function_limit": 100, "string_limit": 200, "include_asm": False},
    )
    _tool(
        registry,
        name="build_callgraph",
        description="构建调用图。",
        source="core.build_callgraph",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "items": _array_schema("根函数列表。", _string_schema("函数地址或函数名。"), min_items=1),
                "query": _string_schema("单个根函数查询；items 的别名。"),
                "addr": _string_schema("单个根函数地址；items 的别名。"),
                "max_depth": _integer_schema("最大展开深度。", minimum=1),
            },
            include_session=True,
            any_of=(("items",), ("query",), ("addr",)),
        ),
        handler=lambda core, arguments: core.build_callgraph(_root_queries(arguments), max_depth=_int_or_default(arguments, "max_depth", 3)),
    )
    _tool(
        registry,
        name="analyze_function",
        description="做单函数综合分析。",
        source="core.analyze_function",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={**ADDR_OR_QUERY_PROPERTIES, "include_asm": _boolean_schema("是否在分析结果中包含完整反汇编。")},
            include_session=True,
            any_of=(("addr",), ("query",)),
        ),
        handler=lambda core, arguments: core.analyze_function(_addr_or_query(arguments), include_asm=_bool_or_default(arguments, "include_asm", False)),
    )
    _tool(
        registry,
        name="analyze_component",
        description="做组件级综合分析。",
        source="core.analyze_component",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "query": _string_schema("组件根函数地址或函数名。"),
                "max_depth": _integer_schema("组件展开深度。", minimum=1),
                "include_asm": _boolean_schema("是否在结果中附带反汇编。"),
            },
            required=("query",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.analyze_component(_require_string(arguments, "query"), max_depth=_int_or_default(arguments, "max_depth", 2), include_asm=_bool_or_default(arguments, "include_asm", False)),
    )
    _tool(
        registry,
        name="trace_data_flow",
        description="做数据流追踪。",
        source="core.trace_data_flow",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "addr": _string_schema("起始地址或符号名。"),
                "direction": _string_schema("追踪方向。", enum=["forward", "backward", "both"]),
                "max_depth": _integer_schema("最大追踪深度。", minimum=1),
            },
            required=("addr",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.trace_data_flow(
            _require_string(arguments, "addr"),
            direction=_string_or_default(arguments, "direction", "both"),
            max_depth=_int_or_default(arguments, "max_depth", 5),
        ),
    )
    _tool(
        registry,
        name="microcode_summary",
        description="读取 Hex-Rays microcode 只读摘要，返回块、指令、defs/uses 线索；这是 experimental 线索工具，不修改数据库。",
        source="core.microcode_summary",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                **ADDR_OR_QUERY_PROPERTIES,
                "max_instructions": _integer_schema("最多返回多少条 microcode 指令。", minimum=1),
            },
            include_session=True,
            any_of=(("addr",), ("query",)),
        ),
        handler=lambda core, arguments: core.microcode_summary(
            _addr_or_query(arguments),
            max_instructions=_int_or_default(arguments, "max_instructions", 80),
        ),
        input_example={"session_id": "sess-001", "query": "main", "max_instructions": 80},
    )
    _tool(
        registry,
        name="microcode_def_use",
        description="读取 Hex-Rays microcode def-use 线索，适合辅助确认变量定义、使用和条件检查来源；不修改数据库。",
        source="core.microcode_def_use",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                **ADDR_OR_QUERY_PROPERTIES,
                "max_instructions": _integer_schema("最多扫描多少条 microcode 指令。", minimum=1),
            },
            include_session=True,
            any_of=(("addr",), ("query",)),
        ),
        handler=lambda core, arguments: core.microcode_def_use(
            _addr_or_query(arguments),
            max_instructions=_int_or_default(arguments, "max_instructions", 120),
        ),
        input_example={"session_id": "sess-001", "query": "main", "max_instructions": 120},
    )
    _tool(
        registry,
        name="convert_integer",
        description="做整数进制/字节转换。",
        source="core.convert_integer",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "value": {
                    "description": "要转换的整数，可传 Python 整数或如 0x41 的字符串。",
                    "oneOf": [{"type": "integer"}, {"type": "string"}],
                },
                "width": _integer_schema("按多少字节宽度输出。", minimum=1),
                "signed": _boolean_schema("是否按有符号整数处理。"),
            },
            required=("value",),
        ),
        handler=lambda core, arguments: core.convert_integer(_int_value(arguments.get("value")), width=_int_or_default(arguments, "width", 8), signed=_bool_or_default(arguments, "signed", False)),
        session_required=False,
    )


def _register_write_script_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册写回、脚本执行和 microcode 实验工具。"""
    _tool(
        registry,
        name="set_comments",
        description="设置注释，给地址、指令或函数补充中文/业务语义说明。",
        source="core.set_comments",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("注释项列表。", COMMENT_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.set_comments(_json_object_list(arguments, "items"), append=False),
        writeback_kind="comment",
    )
    _tool(
        registry,
        name="append_comments",
        description="追加注释，在保留原注释的前提下补充更多分析说明。",
        source="core.append_comments",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("注释项列表。", COMMENT_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.set_comments(_json_object_list(arguments, "items"), append=True),
        writeback_kind="comment_append",
    )
    _tool(
        registry,
        name="patch_assembly",
        description="修改汇编并打补丁：按汇编语句 assemble 后写回数据库，适合改指令逻辑或快速验证补丁。",
        source="core.patch_assembly",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("汇编补丁项列表。", PATCH_ASM_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.patch_assembly(_json_object_list(arguments, "items")),
        writeback_kind="patch_assembly",
    )
    _tool(
        registry,
        name="rename_symbols",
        description="批量重命名符号、函数、变量，提升数据库可读性并方便后续逆向分析。",
        source="core.rename_symbols",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("重命名项列表。", RENAME_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.rename_symbols(_json_object_list(arguments, "items")),
        writeback_kind="rename",
    )
    _tool(
        registry,
        name="define_function",
        description="定义函数。",
        source="core.define_function",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addrs": _array_schema("函数起始地址列表。", _string_schema("函数起始地址。"), min_items=1)},
            required=("addrs",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.define_function(_string_list(arguments, "addrs")),
        writeback_kind="define_function",
    )
    _tool(
        registry,
        name="define_code",
        description="把字节定义为代码。",
        source="core.define_code",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addrs": _array_schema("要强制定义为代码的地址列表。", _string_schema("目标地址。"), min_items=1)},
            required=("addrs",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.define_code(_string_list(arguments, "addrs")),
        writeback_kind="define_code",
    )
    _tool(
        registry,
        name="undefine_items",
        description="取消定义。",
        source="core.undefine_items",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addrs": _array_schema("要取消定义的地址列表。", _string_schema("目标地址。"), min_items=1)},
            required=("addrs",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.undefine_items(_string_list(arguments, "addrs")),
        writeback_kind="undefine",
    )
    _tool(
        registry,
        name="declare_types",
        description="声明 C 类型，把结构体、枚举、函数原型等声明写入本地类型库。",
        source="core.declare_types",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("C 声明列表。", _string_schema("单条 C 类型声明。"), min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.declare_types(_string_list(arguments, "items")),
        writeback_kind="declare_types",
    )
    _tool(
        registry,
        name="upsert_enum",
        description="创建或更新枚举。",
        source="core.upsert_enum",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("枚举定义列表。", ENUM_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.upsert_enum(_json_object_list(arguments, "items")),
        writeback_kind="enum",
    )
    _tool(
        registry,
        name="set_types",
        description="设置类型 / 函数原型 / 变量类型，适合批量修正签名和恢复类型信息。",
        source="core.set_types",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("类型赋值列表。", TYPE_ASSIGN_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.set_types(_json_object_list(arguments, "items")),
        writeback_kind="set_type",
    )
    _tool(
        registry,
        name="infer_types",
        description="推断并尽量写回类型，适合恢复函数原型、字符串指针、指针链和基础整数类型。",
        source="core.infer_types",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("待推断的地址/符号列表。", _string_schema("地址或符号名。"), min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.infer_types(_string_list(arguments, "items")),
        writeback_kind="infer_type",
    )
    _tool(
        registry,
        name="declare_stack_variables",
        description="声明栈变量。",
        source="core.declare_stack_variables",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("栈变量声明列表。", STACK_VAR_DECLARE_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.declare_stack_variables(_json_object_list(arguments, "items")),
        writeback_kind="stack_variable",
    )
    _tool(
        registry,
        name="delete_stack_variables",
        description="删除栈变量。",
        source="core.delete_stack_variables",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("栈变量删除列表。", STACK_VAR_DELETE_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.delete_stack_variables(_json_object_list(arguments, "items")),
        writeback_kind="stack_variable_delete",
    )
    _tool(
        registry,
        name="patch_bytes",
        description="直接写入字节补丁 / 十六进制补丁，适合做 opcode 级 patch 和快速回滚。",
        source="core.patch_bytes",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("字节补丁列表。", PATCH_BYTES_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.patch_bytes(_json_object_list(arguments, "items")),
        writeback_kind="patch_bytes",
    )
    _tool(
        registry,
        name="patch_diff",
        description="预览字节补丁差异，不写入 IDB；返回当前字节、目标字节和逐字节变化。",
        source="core.patch_diff",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("字节补丁预览列表。", PATCH_BYTES_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.patch_diff(_json_object_list(arguments, "items")),
    )
    _tool(
        registry,
        name="patch_history",
        description="读取当前 working IDB 的补丁历史，包含 patch_id、地址、写入前后字节和变化偏移。",
        source="core.patch_history",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"limit": _integer_schema("最多返回多少条历史记录。", minimum=1)},
            include_session=True,
        ),
        handler=lambda core, arguments: core.patch_history(limit=_int_or_default(arguments, "limit", 50)),
    )
    _tool(
        registry,
        name="rollback_patch",
        description="按 patch_id 回滚补丁历史；按传入顺序的逆序恢复原始字节。",
        source="core.rollback_patch",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"ids": _array_schema("要回滚的 patch_id 列表。", _integer_schema("patch_id。", minimum=1), min_items=1)},
            required=("ids",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.rollback_patch(_int_list(arguments, "ids")),
        writeback_kind="rollback_patch",
    )
    _tool(
        registry,
        name="write_ints",
        description="写入整数。",
        source="core.write_ints",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("整数写入列表。", WRITE_INT_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.write_ints(_json_object_list(arguments, "items")),
        writeback_kind="write_int",
    )
    _tool(
        registry,
        name="microcode_experiment",
        description="实验性 microcode mutation，用于局部 microcode 实验，不保证长期稳定。",
        source="core.microcode_experiment",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                **ADDR_OR_QUERY_PROPERTIES,
                "action": _string_schema("实验动作；当前支持 mark_chains_dirty。", enum=["mark_chains_dirty"]),
            },
            include_session=True,
            any_of=(("addr",), ("query",)),
        ),
        handler=lambda core, arguments: core.microcode_experiment(
            _addr_or_query(arguments),
            action=_string_or_default(arguments, "action", "mark_chains_dirty"),
        ),
        writeback_kind="microcode_experiment",
        input_example={"session_id": "sess-001", "query": "main", "action": "mark_chains_dirty"},
    )
    _tool(
        registry,
        name="evaluate_python",
        description="在当前或指定会话的 IDB 上执行 Python / IDAPython 代码；返回 stdout/stderr/result 的受控摘要，不回传完整局部变量。",
        source="core.evaluate_python",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "code": _string_schema("要执行的 Python 代码。"),
                "include_locals": _boolean_schema("是否返回局部变量可序列化摘要。默认 false；不会返回完整大对象。", default=False),
                "max_output_chars": _integer_schema("stdout/stderr 最大返回字符数；服务端仍有硬上限，避免拖垮 MCP 客户端。", minimum=1000),
            },
            required=("code",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.evaluate_python(
            _require_string(arguments, "code"),
            include_locals=_bool_or_default(arguments, "include_locals", False),
            max_output_chars=_int_or_default(arguments, "max_output_chars", 120_000),
        ),
        input_example={"session_id": "sess-001", "code": "import idautils\nresult = {'functions': len(list(idautils.Functions()))}"},
    )
    _tool(
        registry,
        name="execute_python_file",
        description="在当前或指定会话的 IDB 上执行磁盘 Python / IDAPython 脚本文件，适合复用现有分析脚本。",
        source="core.execute_python_file",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"path": _string_schema("Python 脚本文件路径。")},
            required=("path",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.execute_python_file(_require_string(arguments, "path")),
        input_example={"session_id": "sess-001", "path": "<脚本文件>"},
    )


def _register_artifact_tools(
    registry: ToolRegistry,
    runtime: HeadlessRuntime,
    *,
    external_analyzers: tuple[ExternalAnalyzerConfig, ...],
) -> None:
    """注册 dispatcher 扫描、外部分析器和 artifact 关联工具。"""

    def register_plain_tool(
        *,
        name: str,
        description: str,
        source: str,
        input_schema: JsonObject,
        handler: Callable[[JsonObject], object],
        input_example: JsonValue | None = None,
    ) -> None:
        """注册不需要 IDA core 的本地 artifact 工具。"""

        def wrapped(arguments: JsonObject) -> ToolResult:
            """执行本地 artifact 工具并转换为统一结果。"""
            try:
                raw = handler(arguments)
                status, data, warnings = _unwrap_statusful(raw)
                return build_result(status=status, source=source, data=data, warnings=warnings)
            except Exception as exc:
                return _error_result_from_exception(
                    name=name,
                    source=source,
                    exc=exc,
                    session_required=False,
                    context_required=False,
                )

        registry.register(
            ToolSpec(
                name=name,
                description=description,
                input_schema=_public_tool_schema(input_schema),
                output_schema=COMMON_OUTPUT_SCHEMA,
                handler=wrapped,
                validation_schema=input_schema,
                requires_session=False,
                requires_context=False,
                input_example=input_example,
            )
        )

    register_plain_tool(
        name="run_external_analyzer",
        description="执行 setting.toml 中配置的外部分析器，并把 JSON 输出导入 artifact 索引。",
        source="analysis_artifacts.run_external_analyzer",
        input_schema=_tool_input_schema(
            properties={
                "name": _string_schema("外部分析器配置名。"),
                "input_path": _string_schema("输入文件或目录路径。"),
                "output_path": _string_schema("可选。外部分析器 JSON 输出路径；为空时写入运行时目录。"),
                "timeout_sec": _integer_schema("可选。覆盖配置中的超时时间。", minimum=1),
            },
            required=("name", "input_path"),
        ),
        handler=lambda arguments: run_external_analyzer(
            external_analyzers,
            name=_require_string(arguments, "name"),
            input_path=_require_string(arguments, "input_path"),
            output_path=_string_or_default(arguments, "output_path", ""),
            timeout_sec=_int_or_default(arguments, "timeout_sec", 0) or None,
        ),
        input_example={"name": "custom-vm", "input_path": "<输入文件>", "output_path": "", "timeout_sec": 120},
    )
    register_plain_tool(
        name="import_analysis_artifact",
        description="导入外部 JSON 分析 artifact，供后续与当前 IDB 关联。",
        source="analysis_artifacts.import_analysis_artifact",
        input_schema=_tool_input_schema(
            properties={
                "path": _string_schema("JSON artifact 文件路径。"),
                "artifact_id": _string_schema("可选。自定义 artifact ID。"),
            },
            required=("path",),
        ),
        handler=lambda arguments: import_analysis_artifact(
            _require_string(arguments, "path"),
            artifact_id=_string_or_default(arguments, "artifact_id", ""),
        ),
        input_example={"path": "<分析结果.json>", "artifact_id": ""},
    )
    register_plain_tool(
        name="list_analysis_artifacts",
        description="列出已导入的外部分析 artifact。",
        source="analysis_artifacts.list_analysis_artifacts",
        input_schema=_tool_input_schema(),
        handler=lambda arguments: list_analysis_artifacts(),
        input_example={},
    )
    _tool(
        registry,
        name="scan_dispatchers",
        description="扫描通用间接分发器候选，包括 hash 常量、switch 元数据、跳转表和间接调用。",
        source="core.scan_dispatchers",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "max_functions": _integer_schema("最多扫描多少个函数。", minimum=1),
                "max_candidates": _integer_schema("最多返回多少个候选。", minimum=1),
            },
            include_session=True,
        ),
        handler=lambda core, arguments: core.scan_dispatchers(
            max_functions=_int_or_default(arguments, "max_functions", 300),
            max_candidates=_int_or_default(arguments, "max_candidates", 100),
        ),
        input_example={"session_id": "sess-001", "max_functions": 300, "max_candidates": 100},
    )
    _tool(
        registry,
        name="correlate_analysis_artifact",
        description="把外部 JSON artifact 与当前 IDB 的字符串、函数、地址、hash 常量和路径线索关联。",
        source="core.correlate_analysis_artifact",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "artifact_id": _string_schema("已导入 artifact ID；与 path 二选一。"),
                "path": _string_schema("JSON artifact 文件路径；与 artifact_id 二选一，未导入时自动导入。"),
                "max_items": _integer_schema("最多使用多少个实体做关联。", minimum=1),
            },
            include_session=True,
            any_of=(("artifact_id",), ("path",)),
        ),
        handler=lambda core, arguments: core.correlate_analysis_artifact(
            artifact_id=_string_or_default(arguments, "artifact_id", ""),
            path=_string_or_default(arguments, "path", ""),
            max_items=_int_or_default(arguments, "max_items", 100),
        ),
        input_example={"session_id": "sess-001", "artifact_id": "<artifact_id>", "max_items": 100},
    )


def _register_debug_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册 IDA 调试器相关工具。"""
    def debug_use_request(arguments: JsonObject) -> bool:
        """读取调试 request 队列策略；未传时使用配置默认值。"""
        return _bool_or_default(arguments, "use_request", runtime.debugger_launch_use_request_default())

    def debug_wait_ms(arguments: JsonObject) -> int:
        """读取调试启动/附加后的状态等待时间。"""
        return _int_or_default(arguments, "wait_for_suspend_ms", runtime.debugger_wait_for_suspend_ms())

    def debug_backend(arguments: JsonObject) -> str:
        """读取显式调试器后端覆盖。"""
        return _string_or_default(arguments, "backend", "")

    def debug_registers_handler(core: IdaCore, arguments: JsonObject) -> object:
        """按统一入口读取当前线程、指定线程或全部线程寄存器。"""
        names = _string_list(arguments, "names") if isinstance(arguments.get("names"), list) else None
        group = _string_or_default(arguments, "group", "all")
        if group == "general" and names is None:
            names = GENERAL_REGISTER_NAMES

        scope = _string_or_default(arguments, "scope", "current")
        if scope == "all_threads":
            return core.debug_register_snapshots(names=names)
        if scope == "thread":
            if not isinstance(arguments.get("thread_id"), int) or isinstance(arguments.get("thread_id"), bool):
                raise ValueError("scope=thread 时必须提供整数 thread_id")
            return core.debug_registers(thread_id=_int_or_default(arguments, "thread_id", 0), names=names)
        if isinstance(arguments.get("thread_id"), int) and not isinstance(arguments.get("thread_id"), bool):
            return core.debug_registers(thread_id=_int_or_default(arguments, "thread_id", 0), names=names)
        return core.debug_registers(names=names)

    _tool(
        registry,
        name="debug_health",
        description="检查 headless 调试器后端、加载候选、request 队列和当前进程状态。",
        source="core.debug_health",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "backend": _string_schema("可选。显式调试器后端模块名；为空时使用配置、环境变量或平台默认值。"),
                "load": _boolean_schema("是否主动尝试加载调试器后端。", default=True),
            }
        ),
        handler=lambda core, arguments: core.debug_health(
            backend=debug_backend(arguments),
            configured_candidates=runtime.debugger_backend_candidates(),
            load=_bool_or_default(arguments, "load", True),
        ),
        input_example={"backend": "", "load": True},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_start",
        description="启动调试会话。",
        source="core.debug_start",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "path": _string_schema("可选。要调试的目标程序路径；为空时尝试复用当前输入文件。"),
                "args": _string_schema("可选。传给调试目标的命令行参数字符串。"),
                "cwd": _string_schema("可选。调试目标启动目录；为空时使用目标程序所在目录。"),
                "backend": _string_schema("可选。显式调试器后端模块名；为空时使用配置、环境变量或平台默认值。"),
                "use_request": _boolean_schema("是否通过 IDA request 队列提交启动请求。默认来自 setting.toml。"),
                "wait_for_suspend_ms": _integer_schema("启动后等待进入可观测挂起状态的毫秒数。", minimum=0),
            }
        ),
        handler=lambda core, arguments: core.debug_start(
            _string_or_default(arguments, "path", ""),
            args=_string_or_default(arguments, "args", ""),
            cwd=_string_or_default(arguments, "cwd", ""),
            use_request=debug_use_request(arguments),
            backend=debug_backend(arguments),
            configured_candidates=runtime.debugger_backend_candidates(),
            wait_for_suspend_ms=debug_wait_ms(arguments),
        ),
        input_example={"path": "<输入文件>", "args": "", "cwd": "<输入目录>", "backend": "", "use_request": True, "wait_for_suspend_ms": 1500},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_launch",
        description="启动调试目标；可选择通过 IDA request 队列提交启动请求。",
        source="core.debug_launch",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "path": _string_schema("可选。要调试的目标程序路径；为空时尝试复用当前输入文件。"),
                "args": _string_schema("可选。传给调试目标的命令行参数字符串。"),
                "cwd": _string_schema("可选。调试目标启动目录；为空时使用目标程序所在目录。"),
                "backend": _string_schema("可选。显式调试器后端模块名；为空时使用配置、环境变量或平台默认值。"),
                "use_request": _boolean_schema("是否通过 IDA request 队列提交启动请求。默认来自 setting.toml。"),
                "wait_for_suspend_ms": _integer_schema("启动后等待进入可观测挂起状态的毫秒数。", minimum=0),
            }
        ),
        handler=lambda core, arguments: core.debug_launch(
            _string_or_default(arguments, "path", ""),
            args=_string_or_default(arguments, "args", ""),
            cwd=_string_or_default(arguments, "cwd", ""),
            use_request=debug_use_request(arguments),
            backend=debug_backend(arguments),
            configured_candidates=runtime.debugger_backend_candidates(),
            wait_for_suspend_ms=debug_wait_ms(arguments),
        ),
        input_example={"path": "<输入文件>", "args": "", "cwd": "<输入目录>", "backend": "", "use_request": True, "wait_for_suspend_ms": 1500},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_attach",
        description="附加到正在运行的进程。",
        source="core.debug_attach",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "pid": _integer_schema("目标进程 PID。", minimum=1),
                "event_id": _integer_schema("IDA attach event_id；默认 -1。"),
                "backend": _string_schema("可选。显式调试器后端模块名；为空时使用配置、环境变量或平台默认值。"),
                "use_request": _boolean_schema("是否通过 IDA request 队列提交 attach 请求。默认来自 setting.toml。"),
                "wait_for_suspend_ms": _integer_schema("附加后等待进入可观测挂起状态的毫秒数。", minimum=0),
            },
            required=("pid",),
        ),
        handler=lambda core, arguments: core.debug_attach(
            _int_or_default(arguments, "pid", 0),
            event_id=_int_or_default(arguments, "event_id", -1),
            use_request=debug_use_request(arguments),
            backend=debug_backend(arguments),
            configured_candidates=runtime.debugger_backend_candidates(),
            wait_for_suspend_ms=debug_wait_ms(arguments),
        ),
        input_example={"pid": 1234, "event_id": -1, "backend": "", "use_request": True, "wait_for_suspend_ms": 1500},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_exit",
        description="退出调试会话。",
        source="core.debug_exit",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_exit(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_continue",
        description="继续执行。",
        source="core.debug_continue",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_continue(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_run_to",
        description="运行到指定地址。",
        source="core.debug_run_to",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addr": _string_schema("断下来的目标地址。")},
            required=("addr",),
        ),
        handler=lambda core, arguments: core.debug_run_to(_require_string(arguments, "addr")),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_step_into",
        description="单步进入。",
        source="core.debug_step_into",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_step_into(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_step_over",
        description="单步越过。",
        source="core.debug_step_over",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_step_over(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_step",
        description="统一单步入口：into 进入、over 越过、out 运行到当前函数返回。",
        source="core.debug_step",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"action": _string_schema("单步动作。", enum=["into", "over", "out"])},
        ),
        handler=lambda core, arguments: core.debug_step(action=_string_or_default(arguments, "action", "into")),
        input_example={"action": "into"},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_list_breakpoints",
        description="列出断点。",
        source="core.debug_list_breakpoints",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_breakpoints(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_add_breakpoints",
        description="添加断点。",
        source="core.debug_add_breakpoints",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addrs": _array_schema("断点地址列表。", _string_schema("断点地址。"), min_items=1)},
            required=("addrs",),
        ),
        handler=lambda core, arguments: core.debug_add_breakpoints(_string_list(arguments, "addrs")),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_delete_breakpoints",
        description="删除断点。",
        source="core.debug_delete_breakpoints",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addrs": _array_schema("要删除的断点地址列表。", _string_schema("断点地址。"), min_items=1)},
            required=("addrs",),
        ),
        handler=lambda core, arguments: core.debug_delete_breakpoints(_string_list(arguments, "addrs")),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_toggle_breakpoints",
        description="启停断点。",
        source="core.debug_toggle_breakpoints",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("断点启停项列表。", BREAKPOINT_TOGGLE_ITEM_SCHEMA, min_items=1)},
            required=("items",),
        ),
        handler=lambda core, arguments: core.debug_toggle_breakpoints(_json_object_list(arguments, "items")),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_registers",
        description="读取调试寄存器；可按当前线程、指定线程、全部线程、寄存器名或通用寄存器组筛选。",
        source="core.debug_registers",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "scope": _string_schema("读取范围。current=当前线程，thread=指定线程，all_threads=所有线程。", enum=["current", "thread", "all_threads"]),
                "thread_id": _integer_schema("线程 ID。", minimum=0),
                "names": _array_schema("要读取的寄存器名列表。", _string_schema("寄存器名。"), min_items=1),
                "group": _string_schema("寄存器组筛选。all=不按组筛选，general=常用通用寄存器。", enum=["all", "general"]),
            },
        ),
        handler=debug_registers_handler,
        input_example={"scope": "all_threads", "group": "general"},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_stacktrace",
        description="读取当前调用栈。",
        source="core.debug_stacktrace",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_stacktrace(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_stack",
        description="读取当前线程栈顶内存。",
        source="core.debug_stack",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"size": _integer_schema("读取栈顶字节数。", minimum=1)},
        ),
        handler=lambda core, arguments: core.debug_stack(size=_int_or_default(arguments, "size", 128)),
        input_example={"size": 128},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_read_memory",
        description="读取调试进程内存。",
        source="core.debug_read_memory",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addr": _string_schema("目标地址。"), "size": _integer_schema("读取字节数。", minimum=1)},
            required=("addr",),
        ),
        handler=lambda core, arguments: core.debug_read_memory(_require_string(arguments, "addr"), _int_or_default(arguments, "size", 16)),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_write_memory",
        description="写入调试进程内存。",
        source="core.debug_write_memory",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"addr": _string_schema("目标地址。"), "hex": _string_schema("要写入的十六进制字节串。")},
            required=("addr", "hex"),
        ),
        handler=lambda core, arguments: core.debug_write_memory(_require_string(arguments, "addr"), _require_string(arguments, "hex")),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_capture_calls",
        description="配置基于断点命中的通用调用捕获，并把命中事件写入调试时间线。",
        source="core.debug_capture_calls",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "action": _string_schema("操作。enable=启用，disable=停用，list=列出，clear=清空。", enum=["enable", "disable", "list", "clear"]),
                "addrs": _array_schema("调用入口地址列表。", _string_schema("地址或符号名。"), min_items=1),
                "include_registers": _boolean_schema("命中时是否采样寄存器。", default=True),
                "stack_bytes": _integer_schema("命中时采样的栈顶字节数。", minimum=0),
                "register_names": _array_schema("命中时采样的寄存器名列表。", _string_schema("寄存器名。"), min_items=1),
            },
        ),
        handler=lambda core, arguments: core.debug_capture_calls(
            action=_string_or_default(arguments, "action", "list"),
            addrs=_string_list(arguments, "addrs") if isinstance(arguments.get("addrs"), list) else None,
            include_registers=_bool_or_default(arguments, "include_registers", True),
            stack_bytes=_int_or_default(arguments, "stack_bytes", 64),
            register_names=_string_list(arguments, "register_names") if isinstance(arguments.get("register_names"), list) else None,
        ),
        input_example={"action": "enable", "addrs": ["main"], "include_registers": True, "stack_bytes": 64},
        session_required=False,
    )
    _tool(
        registry,
        name="debug_export_timeline",
        description="导出调试事件时间线，包含 MCP 事件和可选 IDA trace buffer 摘要。",
        source="core.debug_export_timeline",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "limit": _integer_schema("最多导出的事件数量。", minimum=1),
                "include_ida_trace": _boolean_schema("是否同时读取 IDA trace buffer。", default=True),
                "path": _string_schema("可选。输出 JSON 文件路径；为空时写入运行时目录。"),
            },
        ),
        handler=lambda core, arguments: core.debug_export_timeline(
            limit=_int_or_default(arguments, "limit", 500),
            include_ida_trace=_bool_or_default(arguments, "include_ida_trace", True),
            path=_string_or_default(arguments, "path", ""),
        ),
        input_example={"limit": 500, "include_ida_trace": True, "path": ""},
        session_required=False,
    )


def _register_resources(
    resources: ResourceRegistry,
    runtime: HeadlessRuntime,
    tools: ToolRegistry,
) -> None:
    """注册 MCP resources 与 resource templates。"""
    session_requires_context = runtime.isolated_contexts
    session_scope = "session"
    context_scope = "context" if runtime.isolated_contexts else "global"

    def resource_payload(
        *,
        source: str,
        data: JsonValue,
        status: ToolStatus = "ok",
        warnings: list[str] | None = None,
        error: JsonObject | None = None,
    ) -> JsonObject:
        """构造资源读取使用的统一结果 envelope。"""
        return cast(JsonObject, build_result(status=status, source=source, data=data, warnings=warnings, error=error))

    def statusful_resource_payload(source: str, raw: object) -> JsonObject:
        """构造资源读取结果，并传播核心层自带的状态。"""
        status, data, warnings = _unwrap_statusful(raw)
        return resource_payload(source=source, status=status, data=data, warnings=warnings)

    def request_context_id(params: dict[str, str], *, required: bool) -> str | None:
        """从资源读取参数中提取上下文 ID。"""
        context_id = params.get("context_id")
        if context_id is None and required:
            raise SessionRequiredError("当前启用了 --isolated-contexts，资源读取必须显式提供 context_id")
        return context_id

    def global_reader(source: str, reader: Callable[[], object]) -> Callable[[dict[str, str]], JsonValue]:
        """把无参全局资源读取函数包装为统一 reader。"""
        def wrapped(_: dict[str, str]) -> JsonValue:
            """读取全局资源并把异常转换为资源 envelope。"""
            try:
                return _normalize_tool_data(statusful_resource_payload(source, reader()))
            except Exception as exc:
                return _normalize_tool_data(
                    _error_result_from_exception(
                        name=source,
                        source=source,
                        exc=exc,
                        session_required=False,
                        context_required=False,
                    )
                )

        return wrapped

    def global_param_reader(
        source: str,
        reader: Callable[[dict[str, str]], object],
    ) -> Callable[[dict[str, str]], JsonValue]:
        """把带参数的全局资源读取函数包装为统一 reader。"""
        def wrapped(params: dict[str, str]) -> JsonValue:
            """读取带参数的全局资源并包装结果。"""
            try:
                return _normalize_tool_data(statusful_resource_payload(source, reader(params)))
            except Exception as exc:
                return _normalize_tool_data(
                    _error_result_from_exception(
                        name=source,
                        source=source,
                        exc=exc,
                        session_required=False,
                        context_required=False,
                    )
                )

        return wrapped

    def global_template_reader(source: str, reader: Callable[[dict[str, str]], object]) -> Callable[[dict[str, str]], JsonValue]:
        """把全局模板资源读取函数包装为统一 reader。"""
        def wrapped(params: dict[str, str]) -> JsonValue:
            """读取全局模板资源并包装结果。"""
            try:
                return _normalize_tool_data(statusful_resource_payload(source, reader(params)))
            except Exception as exc:
                return _normalize_tool_data(
                    _error_result_from_exception(
                        name=source,
                        source=source,
                        exc=exc,
                        session_required=False,
                        context_required=False,
                    )
                )

        return wrapped

    def active_reader(source: str, reader: Callable[[IdaCore], object]) -> Callable[[dict[str, str]], JsonValue]:
        """把依赖当前 IDB 的资源读取函数包装为统一 reader。"""
        def wrapped(params: dict[str, str]) -> JsonValue:
            """激活当前会话后读取资源并包装结果。"""
            try:
                runtime.activate_for_request(None, context_id=request_context_id(params, required=session_requires_context))
                return _normalize_tool_data(statusful_resource_payload(source, reader(_new_core())))
            except Exception as exc:
                return _normalize_tool_data(
                    _error_result_from_exception(
                        name=source,
                        source=source,
                        exc=exc,
                        session_required=True,
                        context_required=session_requires_context,
                    )
                )

        return wrapped

    def template_reader(source: str, reader: Callable[[IdaCore, dict[str, str]], object]) -> Callable[[dict[str, str]], JsonValue]:
        """把依赖当前 IDB 的模板资源读取函数包装为统一 reader。"""
        def wrapped(params: dict[str, str]) -> JsonValue:
            """激活当前会话后读取模板资源并包装结果。"""
            try:
                runtime.activate_for_request(None, context_id=request_context_id(params, required=session_requires_context))
                return _normalize_tool_data(statusful_resource_payload(source, reader(_new_core(), params)))
            except Exception as exc:
                return _normalize_tool_data(
                    _error_result_from_exception(
                        name=source,
                        source=source,
                        exc=exc,
                        session_required=True,
                        context_required=session_requires_context,
                    )
                )

        return wrapped

    def context_reader(
        source: str,
        reader: Callable[[str | None], object],
    ) -> Callable[[dict[str, str]], JsonValue]:
        """把依赖上下文的资源读取函数包装为统一 reader。"""
        def wrapped(params: dict[str, str]) -> JsonValue:
            """读取上下文资源并包装结果。"""
            try:
                context_id = request_context_id(params, required=session_requires_context)
                return _normalize_tool_data(statusful_resource_payload(source, reader(context_id)))
            except Exception as exc:
                return _normalize_tool_data(
                    _error_result_from_exception(
                        name=source,
                        source=source,
                        exc=exc,
                        session_required=False,
                        context_required=session_requires_context,
                    )
                )

        return wrapped

    def current_session_resource(context_id: str | None) -> JsonObject:
        """返回当前上下文绑定的会话摘要。"""
        try:
            session: JsonValue = _normalize_tool_data(runtime.current_target(context_id=context_id))
        except SessionRequiredError:
            session = None
        return normalize_json_object({"session": session})

    def capability_matrix_document(params: dict[str, str]) -> JsonObject:
        """构造全局能力矩阵资源内容。"""
        context_id = request_context_id(params, required=False)
        current_session: JsonValue = None
        current_snapshot: JsonValue = None
        try:
            current_session = _normalize_tool_data(runtime.current_target(context_id=context_id))
            runtime.activate_for_request(None, context_id=context_id)
            current_snapshot = _new_core().capabilities()
        except Exception:
            current_session = None
            current_snapshot = None
        resource_scopes: JsonObject = {
            "global": [
                "ida://capability-matrix",
                "ida://docs/tools",
            ],
            session_scope: [
                "ida://idb/metadata",
                "ida://idb/segments",
                "ida://idb/entrypoints",
                "ida://idb/capabilities",
                "ida://triage",
                "ida://types",
                "ida://structs",
                "ida://functions",
                "ida://functions/profiles",
                "ida://globals",
                "ida://imports",
                "ida://imports/categories",
                "ida://strings",
                "ida://callgraph/summary",
                "ida://managed/summary",
                "ida://managed/types",
                "ida://managed/namespaces",
            ],
        }
        context_resources: list[JsonValue] = ["ida://session/current", "ida://sessions"]
        if runtime.isolated_contexts:
            resource_scopes[context_scope] = context_resources
        else:
            global_resources = cast(list[JsonValue], resource_scopes["global"])
            global_resources.extend(context_resources)
        return {
            "service": {
                "headless_only": True,
                "stdio_only": True,
                "multi_session": True,
                "runtime_modes": {"isolated_contexts": runtime.isolated_contexts},
            },
            "resource_scopes": resource_scopes,
            "context_requirements": {
                "isolated_contexts": runtime.isolated_contexts,
                "session_scoped_tools_require_context": runtime.isolated_contexts,
                "session_scoped_resources_require_context": runtime.isolated_contexts,
            },
            "requested_context": context_id,
            "current_session": current_session,
            "current_snapshot": current_snapshot,
        }

    resources.register_static(
        ResourceSpec(
            "ida://idb/metadata",
            "idb_metadata",
            "当前 IDB 元数据。",
            "application/json",
            active_reader("resource.idb_metadata", lambda core: core.idb_metadata()),
            requires_context=session_requires_context,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://idb/segments",
            "idb_segments",
            "当前 IDB 段信息。",
            "application/json",
            active_reader("resource.idb_segments", lambda core: core.segments()),
            requires_context=session_requires_context,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://idb/entrypoints",
            "idb_entrypoints",
            "当前 IDB 入口点。",
            "application/json",
            active_reader("resource.idb_entrypoints", lambda core: core.entrypoints()),
            requires_context=session_requires_context,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://idb/capabilities",
            "idb_capabilities",
            "当前活动会话的实时能力矩阵。",
            "application/json",
            active_reader("resource.idb_capabilities", lambda core: core.capabilities()),
            requires_context=session_requires_context,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://capability-matrix",
            "capability_matrix",
            "全局能力边界文档；即使当前没有活动会话也可读取。",
            "application/json",
            global_param_reader("resource.capability_matrix", capability_matrix_document),
            scope="global",
            requires_session=False,
        )
    )
    resources.register_static(ResourceSpec("ida://triage", "triage", "当前样本的开局分析概览。", "application/json", active_reader("resource.triage", lambda core: core.binary_survey_snapshot()), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://types", "types", "当前类型目录。", "application/json", active_reader("resource.types", lambda core: core.query_types()), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://structs", "structs", "当前结构体列表。", "application/json", active_reader("resource.structs", lambda core: core.search_structs()), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://functions", "functions", "当前函数列表。", "application/json", active_reader("resource.functions", lambda core: core.list_functions(limit=2000)), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://functions/profiles", "function_profiles", "当前函数画像摘要。", "application/json", active_reader("resource.function_profiles", lambda core: [core.get_function_profile(str(item.get("addr")), include_asm=False) for item in core.list_functions(limit=200)]), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://globals", "globals", "当前全局符号列表。", "application/json", active_reader("resource.globals", lambda core: core.list_globals(limit=2000)), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://imports", "imports", "当前导入表。", "application/json", active_reader("resource.imports", lambda core: core.list_imports(limit=2000)), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://imports/categories", "imports_categories", "当前导入的分类视图。", "application/json", active_reader("resource.imports_categories", lambda core: core.import_categories()), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://strings", "strings", "当前字符串列表。", "application/json", active_reader("resource.strings", lambda core: core.list_strings(limit=2000)), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://callgraph/summary", "callgraph_summary", "当前样本的调用图摘要。", "application/json", active_reader("resource.callgraph_summary", lambda core: core.callgraph_summary()), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://managed/summary", "managed_summary", "托管/.NET 能力与符号级摘要。", "application/json", active_reader("resource.managed_summary", lambda core: core.managed_summary()), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://managed/types", "managed_types", "托管/.NET 符号级类型目录。", "application/json", active_reader("resource.managed_types", lambda core: core.managed_types(limit=2000)), requires_context=session_requires_context))
    resources.register_static(ResourceSpec("ida://managed/namespaces", "managed_namespaces", "托管/.NET 命名空间统计。", "application/json", active_reader("resource.managed_namespaces", lambda core: core.managed_summary()["top_namespaces"]), requires_context=session_requires_context))
    resources.register_static(
        ResourceSpec(
            "ida://docs/tools",
            "tool_docs",
            "全部工具的 schema、自描述与调用文档。",
            "application/json",
            global_reader("resource.docs.tools", lambda: _normalize_tool_data(tools.list_tools())),
            scope="global",
            requires_session=False,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://session/current",
            "session_current",
            "当前默认会话；未绑定时返回 null。",
            "application/json",
            context_reader("resource.session_current", current_session_resource),
            scope=context_scope,
            requires_session=False,
            requires_context=session_requires_context,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://sessions",
            "sessions",
            "当前所有会话；即使为空也返回统一 envelope。",
            "application/json",
            context_reader("resource.sessions", lambda context_id: runtime.list_targets(context_id=context_id)),
            scope=context_scope,
            requires_session=False,
            requires_context=session_requires_context,
        )
    )

    resources.register_template(
        uri_template="ida://struct/{name}",
        name="struct_name",
        description="读取指定结构体定义。",
        mime_type="application/json",
        handler=template_reader("resource.struct_name", lambda core, params: core.read_struct(params["name"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://function/{query}",
        name="function_query",
        description="读取指定函数详情。",
        mime_type="application/json",
        handler=template_reader("resource.function_query", lambda core, params: core.get_function(params["query"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://function-profile/{query}",
        name="function_profile_query",
        description="读取指定函数画像。",
        mime_type="application/json",
        handler=template_reader("resource.function_profile_query", lambda core, params: core.get_function_profile(params["query"], include_asm=False)),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://decompile/{query}",
        name="decompile_query",
        description="读取指定函数的高层表示。",
        mime_type="application/json",
        handler=template_reader("resource.decompile_query", lambda core, params: core.decompile_function(params["query"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://basic-blocks/{addr}",
        name="basic_blocks_addr",
        description="读取指定函数的基本块信息。",
        mime_type="application/json",
        handler=template_reader("resource.basic_blocks_addr", lambda core, params: core.get_basic_blocks(params["addr"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://stack-frame/{addr}",
        name="stack_frame",
        description="读取指定函数栈帧。",
        mime_type="application/json",
        handler=template_reader("resource.stack_frame", lambda core, params: core.get_stack_frame(params["addr"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://type/{name}",
        name="type_name",
        description="读取指定类型详情。",
        mime_type="application/json",
        handler=template_reader("resource.type_name", lambda core, params: core.inspect_type(params["name"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://import/{name}",
        name="import_name",
        description="读取指定导入符号。",
        mime_type="application/json",
        handler=template_reader("resource.import_name", lambda core, params: core.query_imports(filter_text=params["name"], limit=200)),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://export/{name}",
        name="export_name",
        description="读取指定导出符号。",
        mime_type="application/json",
        handler=template_reader("resource.export_name", lambda core, params: [item for item in core.entrypoints() if str(item.get("name", "")).lower() == params["name"].lower()]),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://xrefs/from/{addr}",
        name="xrefs_from",
        description="读取指定地址的向外 xref。",
        mime_type="application/json",
        handler=template_reader("resource.xrefs_from", lambda core, params: core.get_xrefs_from(params["addr"])),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://callgraph/{root}",
        name="callgraph_root",
        description="读取指定根函数的调用图。",
        mime_type="application/json",
        handler=template_reader("resource.callgraph_root", lambda core, params: core.build_callgraph([params["root"]], max_depth=3)),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://data-flow/{addr}",
        name="data_flow_addr",
        description="读取指定地址的增强版数据流追踪。",
        mime_type="application/json",
        handler=template_reader("resource.data_flow_addr", lambda core, params: core.trace_data_flow(params["addr"], direction="both", max_depth=3)),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://managed/method/{query}",
        name="managed_method_query",
        description="读取指定托管方法的 managed 身份与高层表示。",
        mime_type="application/json",
        handler=template_reader(
            "resource.managed_method_query",
            lambda core, params: {
                "identity": core.managed_method_identity(core.parse_address(params["query"])),
                "decompile": core.decompile_function(params["query"]),
            },
        ),
        requires_context=session_requires_context,
    )
    resources.register_template(
        uri_template="ida://docs/tool/{name}",
        name="tool_doc_name",
        description="读取单个工具的 schema 与说明。",
        mime_type="application/json",
        handler=global_template_reader("resource.docs.tool", lambda params: _tool_doc_payload(tools, params["name"])),
        scope="global",
        requires_session=False,
    )


def build_service(
    runtime: HeadlessRuntime,
    *,
    tool_surface: ToolSurface | str = "all",
    profile_path: Path | None = None,
    external_analyzers: tuple[ExternalAnalyzerConfig, ...] = (),
) -> ServiceBundle:
    """构建完整纯实现 headless 服务。"""
    tools = ToolRegistry()
    resources = ResourceRegistry()
    prompts = build_prompt_registry()
    _management_tools(tools, runtime)
    _register_read_tools(tools, runtime)
    _register_write_script_tools(tools, runtime)
    _register_artifact_tools(tools, runtime, external_analyzers=external_analyzers)
    _register_debug_tools(tools, runtime)
    _apply_tool_surface(tools, tool_surface)
    if profile_path is not None:
        whitelist = load_profile(profile_path)
        tools.apply_whitelist(whitelist)
    _register_resources(resources, runtime, tools)
    return ServiceBundle(tools=tools, resources=resources, prompts=prompts)


def _apply_tool_surface(tools: ToolRegistry, tool_surface: ToolSurface | str) -> None:
    """按工具面裁剪注册表。"""
    if tool_surface in {"workflow", "slim"}:
        tools.apply_whitelist(WORKFLOW_TOOL_NAMES)
        return
    if tool_surface in {"full", "expert"}:
        raise ValueError(f"工具面 {tool_surface} 已移除，请使用 all 或 workflow")
    if tool_surface != "all":
        raise ValueError(f"未知工具面：{tool_surface}")
    registered = {
        str(item["name"])
        for item in tools.list_tools()
        if isinstance(item.get("name"), str)
    }
    tools.apply_whitelist(registered)


def _tool_doc_payload(tools: ToolRegistry, name: str) -> JsonObject:
    """读取单个工具的自描述文档。"""
    for item in tools.list_tools():
        tool_name = item.get("name")
        if isinstance(tool_name, str) and tool_name == name:
            return item
    raise KeyError(f"未知工具：{name}")
