"""构建纯实现的 headless stdio 服务。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, cast

from .config import AppConfig
from .directory_analysis import DirectoryAnalysisPolicy, detect_project_profile, iter_candidate_files
from .errors import RuntimeNotReadyError, SessionNotFoundError, SessionRequiredError
from .ida_core import IdaCore
from .models import BinarySummary, GateName, JsonObject, JsonValue, ToolResult, ToolStatus
from .profile_loader import load_profile
from .result import build_error_info, build_result, normalize_json_object
from .runtime import HeadlessRuntime
from .tool_registry import ResourceRegistry, ResourceSpec, ToolRegistry, ToolSpec

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


def _boolean_schema(description: str) -> JsonObject:
    """构造布尔参数定义。"""
    return {"type": "boolean", "description": description}


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


def _tool_input_schema(
    *,
    properties: dict[str, JsonObject] | None = None,
    required: tuple[str, ...] = (),
    include_session: bool = False,
    any_of: tuple[tuple[str, ...], ...] = (),
) -> JsonObject:
    """构造统一的 tool 输入 schema。

    这里刻意避免在顶层使用 anyOf/oneOf/allOf。
    原因不是 JSON Schema 本身不支持，而是 Codex、Claude Code、Cherry
    等主流 agent/client 在把 MCP tool 转成函数调用 schema 时，普遍只接受
    “顶层 object + properties + required + additionalProperties=false”这一子集。
    因此像“addr/query 二选一”这类约束，统一降级为自定义扩展字段，
    由服务端自己的校验器负责执行。
    """
    final_properties: JsonObject = {}
    if properties is not None:
        final_properties.update(deepcopy(properties))
    if include_session:
        final_properties["session_id"] = deepcopy(SESSION_ID_SCHEMA)
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
) -> JsonObject:
    """把运行时异常映射为稳定、可恢复的结构化错误。"""
    if isinstance(exc, SessionRequiredError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="session_required",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["先调用 open_binary 打开样本", "或调用 switch_binary 切换到已有会话"],
        )))
    if isinstance(exc, SessionNotFoundError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="session_not_found",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["先调用 list_binaries 查看当前有效会话", "再使用正确的 session_id 重新调用"],
        )))
    if isinstance(exc, FileNotFoundError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="path_not_found",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["检查路径是否存在", "确认宿主进程对该路径有访问权限"],
        )))
    if isinstance(exc, NotADirectoryError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="path_not_directory",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["改传目录路径", "或改用 open_binary 打开单个文件"],
        )))
    if isinstance(exc, IsADirectoryError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="path_is_directory",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["改传具体文件路径", "不要把目录路径传给只接受文件的工具"],
        )))
    if isinstance(exc, RuntimeNotReadyError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="runtime_not_ready",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["检查 IDADIR 是否已设置且指向有效 IDA 安装目录"],
        )))
    if isinstance(exc, ValueError):
        return normalize_json_object(cast(JsonObject, build_error_info(
            code="invalid_request",
            message=str(exc),
            details={"tool": name, "source": source, "requires_session": session_required},
            next_steps=["按当前工具的 inputSchema 修正字段值或查询目标"],
        )))
    return normalize_json_object(cast(JsonObject, build_error_info(
        code="tool_execution_failed",
        message=str(exc),
        details={"tool": name, "source": source, "requires_session": session_required},
        next_steps=["检查当前数据库状态", "必要时查看文件日志中的异常上下文"],
    )))


def _error_result_from_exception(
    *,
    name: str,
    source: str,
    exc: Exception,
    session_required: bool,
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
        "ty": _string_schema("兼容别名；等同于 type。"),
        "offset": {
            "description": "栈变量偏移；可为整数，也可为如 -0x20 的字符串。",
            "oneOf": [{"type": "integer"}, {"type": "string"}],
        },
    },
    required=("addr", "name", "offset"),
)
STACK_VAR_DELETE_ITEM_SCHEMA = _object_param_schema(
    "单条栈变量删除请求。",
    {"addr": _string_schema("函数地址或函数名。"), "name": _string_schema("栈变量名。")},
    required=("addr", "name"),
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


def _ensure_session(arguments: JsonObject, runtime: HeadlessRuntime) -> None:
    raw_session = arguments.get("session_id")
    session_id = raw_session if isinstance(raw_session, str) and raw_session else None
    runtime.activate_for_request(session_id)


def _normalize_tool_data(value: object) -> JsonValue:
    """在协议边界把任意运行时值收窄为 JSON 值。

    这里只保留一个 `object` 边界入口，用来承接 IDA 运行时与资源层回传的
    各类对象；后续立即通过 `IdaCore.jsonify` 收窄，禁止把宽泛类型继续下传。
    """
    core = IdaCore()
    return core.jsonify(value)


def _unwrap_statusful(value: object) -> tuple[ToolStatus, JsonValue, list[str]]:
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
    return "ok", _normalize_tool_data(cast(object, value)), []


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
    writeback_kind: str | None = None,
    feature_gate: GateName = "public",
    preconditions: tuple[str, ...] = (),
    empty_state_behavior: str = "",
    input_example: JsonValue | None = None,
) -> None:
    def wrapped(arguments: JsonObject) -> ToolResult:
        try:
            if session_required:
                _ensure_session(arguments, runtime)
            core = IdaCore()
            raw = handler(core, arguments)
            status, data, warnings = _unwrap_statusful(raw)
            if writeback_kind is not None and status in {"ok", "degraded"}:
                session = runtime.mark_writeback(
                    writeback_kind=writeback_kind,
                    session_id=_string_or_default(arguments, "session_id", "") or None,
                )
                data = _with_writeback_state(data, session)
            return build_result(status=status, source=source, data=data, warnings=warnings)
        except Exception as exc:
            return _error_result_from_exception(
                name=name,
                source=source,
                exc=exc,
                session_required=session_required,
            )

    registry.register(
        ToolSpec(
            name=name,
            description=description,
            input_schema=_public_tool_schema(input_schema),
            output_schema=COMMON_OUTPUT_SCHEMA,
            handler=wrapped,
            validation_schema=input_schema,
            requires_session=session_required,
            feature_gate=feature_gate,
            preconditions=preconditions,
            empty_state_behavior=empty_state_behavior,
            input_example=input_example,
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

    def management_error_result(name: str, source: str, exc: Exception, *, session_required: bool) -> ToolResult:
        return _error_result_from_exception(
            name=name,
            source=source,
            exc=exc,
            session_required=session_required,
        )

    def health_handler(_: JsonObject) -> ToolResult:
        active: JsonValue = None
        health_data: JsonObject = normalize_json_object(
            {
                "runtime_ready": True,
                "idadir": str(runtime.require_ida_dir()),
                "binary_open": False,
                "active": None,
                "feature_gates": {
                    "unsafe": allow_unsafe,
                    "debugger": allow_debugger,
                },
            }
        )
        try:
            active = _normalize_tool_data(runtime.current_binary())
            runtime.activate_for_request(None)
            core = IdaCore()
            payload = normalize_json_object(core.health())
            payload["active_session"] = active
            payload["feature_gates"] = normalize_json_object(
                {
                "unsafe": allow_unsafe,
                "debugger": allow_debugger,
                }
            )
            health_data = payload
        except Exception:
            pass
        if active is not None:
            health_data["binary_open"] = True
            health_data["active"] = active
        return build_result(status="ok", source="runtime.health", data=_normalize_tool_data(health_data))

    def warmup_handler(arguments: JsonObject) -> ToolResult:
        try:
            _ensure_session(arguments, runtime)
            core = IdaCore()
            data = core.wait_auto_analysis()
            return build_result(status="ok", source="runtime.warmup", data=data)
        except Exception as exc:
            return management_error_result("warmup", "runtime.warmup", exc, session_required=True)

    def open_binary_handler(arguments: JsonObject) -> ToolResult:
        try:
            raw_path = _require_string(arguments, "path")
            summary = runtime.open_binary(
                Path(raw_path),
                run_auto_analysis=_bool_or_default(arguments, "run_auto_analysis", True),
                session_id=_string_or_default(arguments, "session_id", "") or None,
            )
            return build_result(status="ok", source="runtime.open_binary", data=_normalize_tool_data(summary))
        except Exception as exc:
            return management_error_result("open_binary", "runtime.open_binary", exc, session_required=False)

    def close_binary_handler(arguments: JsonObject) -> ToolResult:
        try:
            raw_session = arguments.get("session_id")
            session_id = raw_session if isinstance(raw_session, str) else None
            runtime.close_binary(session_id)
            return build_result(
                status="ok",
                source="runtime.close_binary",
                data=_normalize_tool_data({"closed": True, "session_id": session_id}),
            )
        except Exception as exc:
            return management_error_result("close_binary", "runtime.close_binary", exc, session_required=True)

    def switch_binary_handler(arguments: JsonObject) -> ToolResult:
        try:
            raw_session = _require_string(arguments, "session_id")
            return build_result(status="ok", source="runtime.switch_binary", data=_normalize_tool_data(runtime.switch_binary(raw_session)))
        except Exception as exc:
            return management_error_result("switch_binary", "runtime.switch_binary", exc, session_required=False)

    def list_binaries_handler(_: JsonObject) -> ToolResult:
        return build_result(status="ok", source="runtime.list_binaries", data=_normalize_tool_data(runtime.list_binaries()))

    def current_binary_handler(_: JsonObject) -> ToolResult:
        try:
            return build_result(
                status="ok",
                source="runtime.current_binary",
                data=_normalize_tool_data({"session": runtime.current_binary()}),
            )
        except SessionRequiredError:
            return build_result(status="ok", source="runtime.current_binary", data=_normalize_tool_data({"session": None}))
        except Exception as exc:
            return management_error_result("current_binary", "runtime.current_binary", exc, session_required=False)

    def save_binary_handler(arguments: JsonObject) -> ToolResult:
        try:
            session_id = _string_or_default(arguments, "session_id", "") or None
            path = _string_or_default(arguments, "path", "")
            return build_result(
                status="ok",
                source="runtime.save_binary",
                data=_normalize_tool_data(runtime.save_binary(path=path, session_id=session_id)),
            )
        except Exception as exc:
            return management_error_result("save_binary", "runtime.save_binary", exc, session_required=True)

    def deactivate_binary_handler(_: JsonObject) -> ToolResult:
        try:
            return build_result(
                status="ok",
                source="runtime.deactivate_binary",
                data=_normalize_tool_data({"deactivated": runtime.deactivate_binary()}),
            )
        except Exception as exc:
            return management_error_result("deactivate_binary", "runtime.deactivate_binary", exc, session_required=True)

    def analyze_directory_handler(arguments: JsonObject) -> ToolResult:
        try:
            raw_path = _require_string(arguments, "path")
            root = Path(raw_path)
            if not root.exists():
                raise FileNotFoundError(f"目录不存在：{root}")
            if not root.is_dir():
                raise NotADirectoryError(f"不是目录：{root}")
            project_profile = detect_project_profile(root)

            raw_include = arguments.get("include_extensions", config.directory_analysis.include_extensions)
            raw_exclude = arguments.get("exclude_patterns", config.directory_analysis.exclude_patterns)
            include_extensions = tuple(str(item).lower() for item in raw_include) if isinstance(raw_include, (list, tuple)) else config.directory_analysis.include_extensions
            exclude_patterns = tuple(str(item) for item in raw_exclude) if isinstance(raw_exclude, (list, tuple)) else config.directory_analysis.exclude_patterns
            recursive = _bool_or_default(arguments, "recursive", config.directory_analysis.recursive)
            max_candidates = _int_or_default(arguments, "max_candidates", config.directory_analysis.max_candidates)
            max_deep_analysis = _int_or_default(arguments, "max_deep_analysis", config.directory_analysis.max_deep_analysis)
            policy = DirectoryAnalysisPolicy(
                prefer_managed=_bool_or_default(arguments, "prefer_managed", config.directory_analysis.prefer_managed),
                prefer_native=_bool_or_default(arguments, "prefer_native", config.directory_analysis.prefer_native),
                prefer_entry_binary=_bool_or_default(arguments, "prefer_entry_binary", config.directory_analysis.prefer_entry_binary),
                prefer_user_code=_bool_or_default(arguments, "prefer_user_code", config.directory_analysis.prefer_user_code),
                scoring_profile=_string_or_default(arguments, "scoring_profile", config.directory_analysis.scoring_profile),
            )

            previous_session_id: str | None = None
            try:
                current = runtime.current_binary()
                previous_session_id = current["session_id"]
            except Exception:
                previous_session_id = None

            candidates = iter_candidate_files(
                root,
                recursive=recursive,
                include_extensions=include_extensions,
                exclude_patterns=exclude_patterns,
                policy=policy,
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
                try:
                    runtime.deactivate_binary()
                except Exception:
                    pass

            status: ToolStatus = "ok" if not errors else "degraded"
            warnings = ["部分样本分析失败，已降级返回"] if errors else []
            return build_result(
                status=status,
                source="directory_analysis",
                data={
                    "summary": {
                        "root": str(root),
                        "project_profile": project_profile,
                        "policy": {
                            "prefer_managed": policy.prefer_managed,
                            "prefer_native": policy.prefer_native,
                            "prefer_entry_binary": policy.prefer_entry_binary,
                            "prefer_user_code": policy.prefer_user_code,
                            "scoring_profile": policy.scoring_profile,
                        },
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
        except Exception as exc:
            return management_error_result("analyze_directory", "directory_analysis", exc, session_required=False)

    registry.register(ToolSpec("health", "返回运行时健康状态。", _tool_input_schema(), COMMON_OUTPUT_SCHEMA, health_handler))
    registry.register(
        ToolSpec(
            "warmup",
            "预热当前会话。",
            _tool_input_schema(include_session=True),
            COMMON_OUTPUT_SCHEMA,
            warmup_handler,
            requires_session=True,
            preconditions=("必须已存在活动会话，或显式提供 session_id。",),
            empty_state_behavior="无活动会话时返回 session_required。",
            input_example={"session_id": "sess-001"},
        )
    )
    registry.register(
        ToolSpec(
            "open_binary",
            "打开二进制并绑定当前会话。",
            _tool_input_schema(
                properties={
                    "path": _string_schema("二进制文件路径。"),
                    "run_auto_analysis": _boolean_schema("是否在打开后等待自动分析。默认 true。"),
                },
                required=("path",),
                include_session=True,
            ),
            COMMON_OUTPUT_SCHEMA,
            open_binary_handler,
            requires_session=False,
            empty_state_behavior="无需现有会话；成功后返回新绑定会话。",
            input_example={"path": "D:/samples/sample.exe", "run_auto_analysis": True, "session_id": "sess-001"},
        )
    )
    registry.register(
        ToolSpec(
            "close_binary",
            "关闭指定或当前会话。",
            _tool_input_schema(include_session=True),
            COMMON_OUTPUT_SCHEMA,
            close_binary_handler,
            requires_session=False,
            preconditions=("若不传 session_id，则必须存在活动会话。",),
            empty_state_behavior="无活动会话且未传 session_id 时返回 session_required。",
            input_example={"session_id": "sess-001"},
        )
    )
    registry.register(
        ToolSpec(
            "switch_binary",
            "切换当前默认会话。",
            _tool_input_schema(required=("session_id",), include_session=True),
            COMMON_OUTPUT_SCHEMA,
            switch_binary_handler,
            requires_session=False,
            preconditions=("session_id 必须指向已存在会话。",),
            empty_state_behavior="session_id 不存在时返回 session_not_found。",
            input_example={"session_id": "sess-001"},
        )
    )
    registry.register(
        ToolSpec(
            "list_binaries",
            "列出所有打开的会话。",
            _tool_input_schema(),
            COMMON_OUTPUT_SCHEMA,
            list_binaries_handler,
            requires_session=False,
            empty_state_behavior="无会话时返回空列表。",
            input_example={},
        )
    )
    registry.register(
        ToolSpec(
            "current_binary",
            "返回当前默认会话。",
            _tool_input_schema(),
            COMMON_OUTPUT_SCHEMA,
            current_binary_handler,
            requires_session=False,
            empty_state_behavior="无会话时返回 {session: null}，不视为错误。",
            input_example={},
        )
    )
    registry.register(
        ToolSpec(
            "save_binary",
            "保存当前或指定会话对应的 IDB。",
            _tool_input_schema(
                properties={"path": _string_schema("可选。保存目标路径；为空时覆盖/使用 IDA 默认路径。")},
                include_session=True,
            ),
            COMMON_OUTPUT_SCHEMA,
            save_binary_handler,
            requires_session=False,
            preconditions=("若不传 session_id，则必须存在活动会话。",),
            empty_state_behavior="无活动会话且未传 session_id 时返回 session_required。",
            input_example={"session_id": "sess-001"},
        )
    )
    registry.register(
        ToolSpec(
            "deactivate_binary",
            "解除默认会话绑定。",
            _tool_input_schema(),
            COMMON_OUTPUT_SCHEMA,
            deactivate_binary_handler,
            requires_session=False,
            preconditions=("必须存在活动会话。",),
            empty_state_behavior="无活动会话时返回 session_required。",
            input_example={},
        )
    )
    registry.register(
        ToolSpec(
            "analyze_directory",
            "扫描目录、挑选候选二进制并做批量深度分析。",
            _tool_input_schema(
                properties={
                    "path": _string_schema("要扫描的目录路径。"),
                    "recursive": _boolean_schema("是否递归扫描子目录。"),
                    "max_candidates": _integer_schema("最多保留多少个候选文件进入筛选结果。", minimum=1),
                    "max_deep_analysis": _integer_schema("最多对多少个候选样本做深度分析。", minimum=1),
                    "include_extensions": _array_schema("允许的扩展名白名单，例如 ['.exe', '.dll', '.elf']。", _string_schema("扩展名。")),
                    "exclude_patterns": _array_schema("排除文件/目录名模式。", _string_schema("排除模式。")),
                    "prefer_managed": _boolean_schema("是否优先托管/.NET 候选。"),
                    "prefer_native": _boolean_schema("是否优先原生候选。"),
                    "prefer_entry_binary": _boolean_schema("是否优先入口二进制。"),
                    "prefer_user_code": _boolean_schema("是否优先用户代码而非插件/运行库。"),
                    "scoring_profile": _string_schema("评分档位，例如 default / managed_first / entry_only。"),
                },
                required=("path",),
            ),
            COMMON_OUTPUT_SCHEMA,
            analyze_directory_handler,
            requires_session=False,
            empty_state_behavior="无需现有会话；内部会临时创建分析会话并在结束后恢复原上下文。",
            input_example={"path": "D:/samples", "recursive": True, "max_candidates": 20, "max_deep_analysis": 5},
        )
    )
    return protected


def _register_read_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    _tool(
        registry,
        name="survey_binary",
        description="返回当前会话的二进制概览。",
        source="core.survey_binary",
        runtime=runtime,
        input_schema=_tool_input_schema(include_session=True),
        handler=lambda core, _: core.survey_binary(),
        preconditions=("必须已存在活动会话，或显式提供 session_id。",),
        empty_state_behavior="无活动会话时返回 session_required。",
        input_example={"session_id": "sess-001"},
    )
    _tool(
        registry,
        name="list_functions",
        description="分页列出函数。",
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
        description="返回单个函数详情以及 callers/callees。",
        source="core.get_function",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_function(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="get_function_profile",
        description="读取函数画像。",
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
        description="批量分析多个函数。",
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
        description="返回函数的统一高层表示。",
        source="core.decompile_function",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.decompile_function(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="disassemble_function",
        description="返回函数反汇编。",
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
        name="get_xrefs_to",
        description="读取目标地址的交叉引用。",
        source="core.get_xrefs_to",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_xrefs_to(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="query_xrefs",
        description="按条件查询交叉引用。",
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
        name="get_xrefs_to_field",
        description="读取结构字段交叉引用。",
        source="core.get_xrefs_to_field",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"struct_name": _string_schema("结构体名。"), "field_name": _string_schema("字段名。")},
            required=("struct_name", "field_name"),
            include_session=True,
        ),
        handler=lambda core, arguments: core.get_xrefs_to_field(_require_string(arguments, "struct_name"), _require_string(arguments, "field_name")),
    )
    _tool(
        registry,
        name="get_callers",
        description="读取函数调用者。",
        source="core.get_callers",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_callers(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="get_callees",
        description="读取函数调用目标。",
        source="core.get_callees",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_callees(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="get_basic_blocks",
        description="读取函数基本块。",
        source="core.get_basic_blocks",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_basic_blocks(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="list_strings",
        description="分页列出字符串。",
        source="core.list_strings",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=PAGINATION_PROPERTIES, include_session=True),
        handler=lambda core, arguments: core.list_strings(offset=_int_or_default(arguments, "offset", 0), limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100))),
    )
    _tool(
        registry,
        name="find_strings",
        description="按子串搜索字符串。",
        source="core.find_strings",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={**SEARCH_TEXT_PROPERTIES, **PAGINATION_PROPERTIES}, include_session=True, required=("pattern",)),
        handler=lambda core, arguments: core.find_strings(_search_text(arguments), offset=_int_or_default(arguments, "offset", 0), limit=_int_or_default(arguments, "count", _int_or_default(arguments, "limit", 100))),
    )
    _tool(
        registry,
        name="search_regex",
        description="对字符串做正则搜索。",
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
        description="读取函数栈帧。",
        source="core.get_stack_frame",
        runtime=runtime,
        input_schema=_tool_input_schema(properties=ADDR_OR_QUERY_PROPERTIES, include_session=True, any_of=(("addr",), ("query",))),
        handler=lambda core, arguments: core.get_stack_frame(_addr_or_query(arguments)),
    )
    _tool(
        registry,
        name="read_struct",
        description="读取结构体字段定义。",
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
        description="搜索结构体。",
        source="core.search_structs",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={"filter": _string_schema("结构体名筛选文本。")}, include_session=True),
        handler=lambda core, arguments: core.search_structs(_string_or_default(arguments, "filter", "")),
    )
    _tool(
        registry,
        name="query_types",
        description="查询类型目录。",
        source="core.query_types",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={"filter": _string_schema("类型名筛选文本。")}, include_session=True),
        handler=lambda core, arguments: core.query_types(_string_or_default(arguments, "filter", "")),
    )
    _tool(
        registry,
        name="inspect_type",
        description="读取具体类型详情。",
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
        description="导出函数。",
        source="core.export_functions",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "items": _array_schema("要导出的函数列表；不传则按 limit 导出全部函数。", _string_schema("函数地址或函数名。")),
                "query": _string_schema("单个函数；兼容别名。"),
                "addr": _string_schema("单个函数地址；兼容别名。"),
                "format": _string_schema("导出格式。", enum=["json", "c_header", "prototypes"]),
                "format_name": _string_schema("导出格式兼容别名。", enum=["json", "c_header", "prototypes"]),
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
        name="build_callgraph",
        description="构建调用图。",
        source="core.build_callgraph",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "items": _array_schema("根函数列表。", _string_schema("函数地址或函数名。"), min_items=1),
                "query": _string_schema("单个根函数查询；兼容别名。"),
                "addr": _string_schema("单个根函数地址；兼容别名。"),
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


def _register_unsafe_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    _tool(
        registry,
        name="set_comments",
        description="设置注释。",
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
        description="追加注释。",
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
        description="按汇编语句打补丁。",
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
        description="批量重命名符号。",
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
        description="声明 C 类型。",
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
        description="设置类型。",
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
        name="apply_types",
        description="批量应用类型。",
        source="core.apply_types",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"items": _array_schema("类型赋值列表。", TYPE_ASSIGN_ITEM_SCHEMA, min_items=1)},
            required=("items",),
            include_session=True,
        ),
        handler=lambda core, arguments: core.apply_types(_json_object_list(arguments, "items")),
        writeback_kind="apply_type",
    )
    _tool(
        registry,
        name="infer_types",
        description="推断并写入类型。",
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
        description="直接写入字节补丁。",
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
        name="evaluate_python",
        description="在 IDA 上下文执行 Python 代码。",
        source="core.evaluate_python",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"code": _string_schema("要执行的 Python 代码。")},
            required=("code",),
        ),
        handler=lambda core, arguments: core.evaluate_python(_require_string(arguments, "code")),
        session_required=False,
    )
    _tool(
        registry,
        name="execute_python_file",
        description="执行磁盘上的 Python 脚本。",
        source="core.execute_python_file",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"path": _string_schema("Python 脚本文件路径。")},
            required=("path",),
        ),
        handler=lambda core, arguments: core.execute_python_file(_require_string(arguments, "path")),
        session_required=False,
    )


def _register_debug_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    _tool(
        registry,
        name="debug_start",
        description="启动调试会话。",
        source="core.debug_start",
        runtime=runtime,
        input_schema=_tool_input_schema(properties={"path": _string_schema("可选。要调试的目标程序路径；为空时尝试复用当前输入文件。")}),
        handler=lambda core, arguments: core.debug_start(_string_or_default(arguments, "path", "")),
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
        description="读取当前线程全部寄存器。",
        source="core.debug_registers",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_registers(),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_registers_all_threads",
        description="读取所有线程寄存器。",
        source="core.debug_registers_all_threads",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"names": _array_schema("只读取指定寄存器名集合。", _string_schema("寄存器名。"), min_items=1)}
        ),
        handler=lambda core, arguments: core.debug_registers_all_threads(
            names=_string_list(arguments, "names") if isinstance(arguments.get("names"), list) else None
        ),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_registers_thread",
        description="读取指定线程寄存器。",
        source="core.debug_registers_thread",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"thread_id": _integer_schema("线程 ID。", minimum=0)},
            required=("thread_id",),
        ),
        handler=lambda core, arguments: core.debug_registers(thread_id=_int_or_default(arguments, "thread_id", 0)),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_general_registers",
        description="读取当前线程通用寄存器。",
        source="core.debug_general_registers",
        runtime=runtime,
        input_schema=_tool_input_schema(),
        handler=lambda core, arguments: core.debug_registers(names=["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "rip", "rsp", "rbp"]),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_general_registers_thread",
        description="读取指定线程通用寄存器。",
        source="core.debug_general_registers_thread",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"thread_id": _integer_schema("线程 ID。", minimum=0)},
            required=("thread_id",),
        ),
        handler=lambda core, arguments: core.debug_registers(thread_id=_int_or_default(arguments, "thread_id", 0), names=["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "rip", "rsp", "rbp"]),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_named_registers",
        description="读取指定寄存器集合。",
        source="core.debug_named_registers",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={"names": _array_schema("要读取的寄存器名列表。", _string_schema("寄存器名。"), min_items=1)},
            required=("names",),
        ),
        handler=lambda core, arguments: core.debug_registers(names=_string_list(arguments, "names")),
        session_required=False,
    )
    _tool(
        registry,
        name="debug_named_registers_thread",
        description="读取指定线程的指定寄存器集合。",
        source="core.debug_named_registers_thread",
        runtime=runtime,
        input_schema=_tool_input_schema(
            properties={
                "thread_id": _integer_schema("线程 ID。", minimum=0),
                "names": _array_schema("要读取的寄存器名列表。", _string_schema("寄存器名。"), min_items=1),
            },
            required=("thread_id", "names"),
        ),
        handler=lambda core, arguments: core.debug_registers(thread_id=_int_or_default(arguments, "thread_id", 0), names=_string_list(arguments, "names")),
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


def _register_resources(
    resources: ResourceRegistry,
    runtime: HeadlessRuntime,
    tools: ToolRegistry,
    *,
    allow_unsafe: bool,
    allow_debugger: bool,
) -> None:
    def resource_payload(
        *,
        source: str,
        data: JsonValue,
        status: ToolStatus = "ok",
        warnings: list[str] | None = None,
        error: JsonObject | None = None,
    ) -> JsonObject:
        return cast(JsonObject, build_result(status=status, source=source, data=data, warnings=warnings, error=error))

    def global_reader(source: str, reader: Callable[[], object]) -> Callable[[dict[str, str]], JsonValue]:
        def wrapped(_: dict[str, str]) -> JsonValue:
            try:
                return _normalize_tool_data(resource_payload(source=source, data=_normalize_tool_data(reader())))
            except Exception as exc:
                return _normalize_tool_data(_error_result_from_exception(name=source, source=source, exc=exc, session_required=False))

        return wrapped

    def global_template_reader(source: str, reader: Callable[[dict[str, str]], object]) -> Callable[[dict[str, str]], JsonValue]:
        def wrapped(params: dict[str, str]) -> JsonValue:
            try:
                return _normalize_tool_data(resource_payload(source=source, data=_normalize_tool_data(reader(params))))
            except Exception as exc:
                return _normalize_tool_data(_error_result_from_exception(name=source, source=source, exc=exc, session_required=False))

        return wrapped

    def active_reader(source: str, reader: Callable[[IdaCore], object]) -> Callable[[dict[str, str]], JsonValue]:
        def wrapped(_: dict[str, str]) -> JsonValue:
            try:
                runtime.activate_for_request(None)
                return _normalize_tool_data(resource_payload(source=source, data=_normalize_tool_data(reader(IdaCore()))))
            except Exception as exc:
                return _normalize_tool_data(_error_result_from_exception(name=source, source=source, exc=exc, session_required=True))

        return wrapped

    def template_reader(source: str, reader: Callable[[IdaCore, dict[str, str]], object]) -> Callable[[dict[str, str]], JsonValue]:
        def wrapped(params: dict[str, str]) -> JsonValue:
            try:
                runtime.activate_for_request(None)
                return _normalize_tool_data(resource_payload(source=source, data=_normalize_tool_data(reader(IdaCore(), params))))
            except Exception as exc:
                return _normalize_tool_data(_error_result_from_exception(name=source, source=source, exc=exc, session_required=True))

        return wrapped

    def capability_matrix_document() -> JsonObject:
        current_session: JsonValue = None
        current_snapshot: JsonValue = None
        try:
            current_session = _normalize_tool_data(runtime.current_binary())
            runtime.activate_for_request(None)
            current_snapshot = IdaCore().capabilities()
        except Exception:
            current_session = None
            current_snapshot = None
        return {
            "service": {
                "headless_only": True,
                "stdio_only": True,
                "multi_session": True,
                "feature_gates": {"unsafe": allow_unsafe, "debugger": allow_debugger},
            },
            "resource_scopes": {
                "global": [
                    "ida://capability-matrix",
                    "ida://docs/tools",
                    "ida://session/current",
                    "ida://sessions",
                ],
                "session": [
                    "ida://idb/metadata",
                    "ida://idb/segments",
                    "ida://idb/entrypoints",
                    "ida://idb/capabilities",
                    "ida://survey",
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
            },
            "current_session": current_session,
            "current_snapshot": current_snapshot,
        }

    resources.register_static(ResourceSpec("ida://idb/metadata", "idb_metadata", "当前 IDB 元数据。", "application/json", active_reader("resource.idb_metadata", lambda core: core.idb_metadata())))
    resources.register_static(ResourceSpec("ida://idb/segments", "idb_segments", "当前 IDB 段信息。", "application/json", active_reader("resource.idb_segments", lambda core: core.segments())))
    resources.register_static(ResourceSpec("ida://idb/entrypoints", "idb_entrypoints", "当前 IDB 入口点。", "application/json", active_reader("resource.idb_entrypoints", lambda core: core.entrypoints())))
    resources.register_static(ResourceSpec("ida://idb/capabilities", "idb_capabilities", "当前活动会话的实时能力矩阵。", "application/json", active_reader("resource.idb_capabilities", lambda core: core.capabilities())))
    resources.register_static(
        ResourceSpec(
            "ida://capability-matrix",
            "capability_matrix",
            "全局能力边界文档；即使当前没有活动会话也可读取。",
            "application/json",
            global_reader("resource.capability_matrix", capability_matrix_document),
            scope="global",
            requires_session=False,
        )
    )
    resources.register_static(ResourceSpec("ida://survey", "survey", "当前样本的综合概览。", "application/json", active_reader("resource.survey", lambda core: core.survey_binary())))
    resources.register_static(ResourceSpec("ida://types", "types", "当前类型目录。", "application/json", active_reader("resource.types", lambda core: core.query_types())))
    resources.register_static(ResourceSpec("ida://structs", "structs", "当前结构体列表。", "application/json", active_reader("resource.structs", lambda core: core.search_structs())))
    resources.register_static(ResourceSpec("ida://functions", "functions", "当前函数列表。", "application/json", active_reader("resource.functions", lambda core: core.list_functions(limit=2000))))
    resources.register_static(ResourceSpec("ida://functions/profiles", "function_profiles", "当前函数画像摘要。", "application/json", active_reader("resource.function_profiles", lambda core: [core.get_function_profile(str(item.get("addr")), include_asm=False) for item in core.list_functions(limit=200)])))
    resources.register_static(ResourceSpec("ida://globals", "globals", "当前全局符号列表。", "application/json", active_reader("resource.globals", lambda core: core.list_globals(limit=2000))))
    resources.register_static(ResourceSpec("ida://imports", "imports", "当前导入表。", "application/json", active_reader("resource.imports", lambda core: core.list_imports(limit=2000))))
    resources.register_static(ResourceSpec("ida://imports/categories", "imports_categories", "当前导入的分类视图。", "application/json", active_reader("resource.imports_categories", lambda core: core.survey_binary()["imports_by_category"])))
    resources.register_static(ResourceSpec("ida://strings", "strings", "当前字符串列表。", "application/json", active_reader("resource.strings", lambda core: core.list_strings(limit=2000))))
    resources.register_static(ResourceSpec("ida://callgraph/summary", "callgraph_summary", "当前样本的调用图摘要。", "application/json", active_reader("resource.callgraph_summary", lambda core: core.survey_binary()["call_graph_summary"])))
    resources.register_static(ResourceSpec("ida://managed/summary", "managed_summary", "托管/.NET 能力与符号级摘要。", "application/json", active_reader("resource.managed_summary", lambda core: core.managed_summary())))
    resources.register_static(ResourceSpec("ida://managed/types", "managed_types", "托管/.NET 符号级类型目录。", "application/json", active_reader("resource.managed_types", lambda core: core.managed_types(limit=2000))))
    resources.register_static(ResourceSpec("ida://managed/namespaces", "managed_namespaces", "托管/.NET 命名空间统计。", "application/json", active_reader("resource.managed_namespaces", lambda core: core.managed_summary()["top_namespaces"])))
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
            global_reader("resource.session_current", lambda: {"session": runtime.current_binary() if runtime.list_binaries() else None}),
            scope="global",
            requires_session=False,
        )
    )
    resources.register_static(
        ResourceSpec(
            "ida://sessions",
            "sessions",
            "当前所有会话；即使为空也返回统一 envelope。",
            "application/json",
            global_reader("resource.sessions", lambda: runtime.list_binaries()),
            scope="global",
            requires_session=False,
        )
    )

    resources.register_template(
        uri_template="ida://struct/{name}",
        name="struct_name",
        description="读取指定结构体定义。",
        mime_type="application/json",
        handler=template_reader("resource.struct_name", lambda core, params: core.read_struct(params["name"])),
    )
    resources.register_template(
        uri_template="ida://function/{query}",
        name="function_query",
        description="读取指定函数详情。",
        mime_type="application/json",
        handler=template_reader("resource.function_query", lambda core, params: core.get_function(params["query"])),
    )
    resources.register_template(
        uri_template="ida://function-profile/{query}",
        name="function_profile_query",
        description="读取指定函数画像。",
        mime_type="application/json",
        handler=template_reader("resource.function_profile_query", lambda core, params: core.get_function_profile(params["query"], include_asm=False)),
    )
    resources.register_template(
        uri_template="ida://decompile/{query}",
        name="decompile_query",
        description="读取指定函数的高层表示。",
        mime_type="application/json",
        handler=template_reader("resource.decompile_query", lambda core, params: core.decompile_function(params["query"])),
    )
    resources.register_template(
        uri_template="ida://basic-blocks/{addr}",
        name="basic_blocks_addr",
        description="读取指定函数的基本块信息。",
        mime_type="application/json",
        handler=template_reader("resource.basic_blocks_addr", lambda core, params: core.get_basic_blocks(params["addr"])),
    )
    resources.register_template(
        uri_template="ida://stack-frame/{addr}",
        name="stack_frame",
        description="读取指定函数栈帧。",
        mime_type="application/json",
        handler=template_reader("resource.stack_frame", lambda core, params: core.get_stack_frame(params["addr"])),
    )
    resources.register_template(
        uri_template="ida://type/{name}",
        name="type_name",
        description="读取指定类型详情。",
        mime_type="application/json",
        handler=template_reader("resource.type_name", lambda core, params: core.inspect_type(params["name"])),
    )
    resources.register_template(
        uri_template="ida://import/{name}",
        name="import_name",
        description="读取指定导入符号。",
        mime_type="application/json",
        handler=template_reader("resource.import_name", lambda core, params: core.query_imports(filter_text=params["name"], limit=200)),
    )
    resources.register_template(
        uri_template="ida://export/{name}",
        name="export_name",
        description="读取指定导出符号。",
        mime_type="application/json",
        handler=template_reader("resource.export_name", lambda core, params: [item for item in core.entrypoints() if str(item.get("name", "")).lower() == params["name"].lower()]),
    )
    resources.register_template(
        uri_template="ida://xrefs/from/{addr}",
        name="xrefs_from",
        description="读取指定地址的向外 xref。",
        mime_type="application/json",
        handler=template_reader("resource.xrefs_from", lambda core, params: core.get_xrefs_from(params["addr"])),
    )
    resources.register_template(
        uri_template="ida://callgraph/{root}",
        name="callgraph_root",
        description="读取指定根函数的调用图。",
        mime_type="application/json",
        handler=template_reader("resource.callgraph_root", lambda core, params: core.build_callgraph([params["root"]], max_depth=3)),
    )
    resources.register_template(
        uri_template="ida://data-flow/{addr}",
        name="data_flow_addr",
        description="读取指定地址的增强版数据流追踪。",
        mime_type="application/json",
        handler=template_reader("resource.data_flow_addr", lambda core, params: core.trace_data_flow(params["addr"], direction="both", max_depth=3)),
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
    _register_resources(resources, runtime, tools, allow_unsafe=allow_unsafe, allow_debugger=allow_debugger)
    return ServiceBundle(tools=tools, resources=resources)


def _require_string(arguments: JsonObject, key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串")
    return value


def _string_or_default(arguments: JsonObject, key: str, default: str = "") -> str:
    """读取可选字符串，不合法时立即报错。"""
    value = arguments.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串")
    return value


def _int_or_default(arguments: JsonObject, key: str, default: int) -> int:
    """读取可选整数，不接受隐式字符串或复合对象。"""
    value = arguments.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} 必须是整数")
    return value


def _bool_or_default(arguments: JsonObject, key: str, default: bool = False) -> bool:
    """读取可选布尔值。"""
    value = arguments.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{key} 必须是布尔值")
    return value


def _string_list(arguments: JsonObject, key: str) -> list[str]:
    value = arguments.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} 必须是字符串列表")
    result = [str(item) for item in value]
    return result


def _optional_query_list(arguments: JsonObject) -> list[str] | None:
    raw_queries = arguments.get("items")
    if isinstance(raw_queries, list):
        return [str(item) for item in raw_queries]
    for key in ("query", "addr"):
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
    return _string_or_default(arguments, "filter", "")


def _search_text(arguments: JsonObject) -> str:
    value = arguments.get("pattern")
    if isinstance(value, str):
        return value
    raise ValueError("必须提供 pattern")


def _addr_list(arguments: JsonObject, key: str) -> list[str]:
    value = arguments.get(key)
    if isinstance(value, list):
        return [str(item) for item in value]
    single = arguments.get("addr")
    if isinstance(single, str):
        return [single]
    raise ValueError(f"{key} 必须是地址列表，或提供单个 addr")


def _root_queries(arguments: JsonObject) -> list[str]:
    raw_roots = arguments.get("items")
    if isinstance(raw_roots, list):
        return [str(item) for item in raw_roots]
    for key in ("query", "addr"):
        value = arguments.get(key)
        if isinstance(value, str):
            return [value]
    raise ValueError("必须提供 items，或提供 query/addr")


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


def _tool_doc_payload(tools: ToolRegistry, name: str) -> JsonObject:
    """读取单个工具的自描述文档。"""
    for item in tools.list_tools():
        tool_name = item.get("name")
        if isinstance(tool_name, str) and tool_name == name:
            return item
    raise KeyError(f"未知工具：{name}")
