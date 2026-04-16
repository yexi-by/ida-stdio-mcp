"""函数分析工具。"""

from __future__ import annotations

from ..models import JsonObject
from ..result import build_result
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry, ToolSpec


def register_function_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册函数类工具。"""

    def list_functions(arguments: JsonObject):
        try:
            limit = int(arguments.get("limit", 100))
            offset = int(arguments.get("offset", 0))
            functions = runtime.list_functions()
            data = functions[offset : offset + limit]
            return build_result(status="ok", source="ida_funcs", data=data)
        except Exception as exc:
            return build_result(status="error", source="ida_funcs", data=None, error=str(exc))

    def get_function(arguments: JsonObject):
        query = arguments.get("query")
        if not isinstance(query, str):
            return build_result(status="error", source="ida_funcs", data=None, error="query 必须是字符串")
        try:
            record = runtime.resolve_function(query)
            callers = runtime.get_callers(query)
            callees = runtime.get_callees(query)
            return build_result(
                status="ok",
                source="ida_funcs",
                data={
                    "function": record,
                    "callers": callers,
                    "callees": callees,
                },
            )
        except Exception as exc:
            return build_result(status="error", source="ida_funcs", data=None, error=str(exc))

    def decompile_function(arguments: JsonObject):
        query = arguments.get("query")
        if not isinstance(query, str):
            return build_result(status="error", source="ida_hexrays", data=None, error="query 必须是字符串")
        try:
            result = runtime.decompile_function(query)
            status = "ok" if result["representation"] == "hexrays" else "degraded"
            return build_result(
                status=status,
                source=str(result["representation"]),
                data=result,
                warnings=list(result.get("warnings", [])),
            )
        except Exception as exc:
            return build_result(status="error", source="ida_hexrays", data=None, error=str(exc))

    def disassemble_function(arguments: JsonObject):
        query = arguments.get("query")
        if not isinstance(query, str):
            return build_result(status="error", source="ida_lines", data=None, error="query 必须是字符串")
        try:
            max_lines = int(arguments.get("max_lines", 200))
            return build_result(
                status="ok",
                source="ida_lines",
                data=runtime.disassemble_function(query, max_lines=max_lines),
            )
        except Exception as exc:
            return build_result(status="error", source="ida_lines", data=None, error=str(exc))

    def get_callers(arguments: JsonObject):
        query = arguments.get("query")
        if not isinstance(query, str):
            return build_result(status="error", source="coderefs", data=None, error="query 必须是字符串")
        try:
            return build_result(status="ok", source="coderefs", data=runtime.get_callers(query))
        except Exception as exc:
            return build_result(status="error", source="coderefs", data=None, error=str(exc))

    def get_callees(arguments: JsonObject):
        query = arguments.get("query")
        if not isinstance(query, str):
            return build_result(status="error", source="coderefs", data=None, error="query 必须是字符串")
        try:
            return build_result(status="ok", source="coderefs", data=runtime.get_callees(query))
        except Exception as exc:
            return build_result(status="error", source="coderefs", data=None, error=str(exc))

    common_schema: JsonObject = {
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "source": {"type": "string"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "error": {"type": ["string", "null"]},
            "data": {},
        },
        "required": ["status", "source", "warnings", "error", "data"],
    }

    registry.register(ToolSpec("list_functions", "列出函数摘要。", {"type": "object", "properties": {"limit": {"type": "integer"}, "offset": {"type": "integer"}}, "required": []}, common_schema, list_functions))
    registry.register(ToolSpec("get_function", "返回单个函数及其 callers/callees。", {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, common_schema, get_function))
    registry.register(ToolSpec("decompile_function", "返回函数最优高层表示；优先 Hex-Rays，不可用时回退汇编文本。", {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, common_schema, decompile_function))
    registry.register(ToolSpec("disassemble_function", "返回函数反汇编。", {"type": "object", "properties": {"query": {"type": "string"}, "max_lines": {"type": "integer"}}, "required": ["query"]}, common_schema, disassemble_function))
    registry.register(ToolSpec("get_callers", "返回函数调用者。", {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, common_schema, get_callers))
    registry.register(ToolSpec("get_callees", "返回函数调用目标。", {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, common_schema, get_callees))
