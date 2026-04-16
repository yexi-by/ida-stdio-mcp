"""字符串工具。"""

from __future__ import annotations

from ..models import JsonObject
from ..result import build_result
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry, ToolSpec


def register_string_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册字符串工具。"""

    def list_strings(arguments: JsonObject):
        try:
            limit = int(arguments.get("limit", 100))
            offset = int(arguments.get("offset", 0))
            strings = runtime.list_strings()
            return build_result(status="ok", source="idautils.Strings", data=strings[offset : offset + limit])
        except Exception as exc:
            return build_result(status="error", source="idautils.Strings", data=None, error=str(exc))

    def find_strings(arguments: JsonObject):
        pattern = arguments.get("pattern")
        if not isinstance(pattern, str):
            return build_result(status="error", source="idautils.Strings", data=None, error="pattern 必须是字符串")
        try:
            return build_result(status="ok", source="idautils.Strings", data=runtime.find_strings(pattern))
        except Exception as exc:
            return build_result(status="error", source="idautils.Strings", data=None, error=str(exc))

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

    registry.register(ToolSpec("list_strings", "列出当前数据库中的字符串。", {"type": "object", "properties": {"limit": {"type": "integer"}, "offset": {"type": "integer"}}, "required": []}, common_schema, list_strings))
    registry.register(ToolSpec("find_strings", "按子串查找字符串。", {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}, common_schema, find_strings))
