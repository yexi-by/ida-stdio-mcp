"""survey 工具。"""

from __future__ import annotations

from ..models import JsonObject
from ..result import build_result
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry, ToolSpec


def register_survey_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册 survey 工具。"""

    def survey_binary(_: JsonObject):
        try:
            return build_result(status="ok", source="runtime", data=runtime.survey_binary())
        except Exception as exc:
            return build_result(status="error", source="runtime", data=None, error=str(exc))

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

    registry.register(
        ToolSpec(
            "survey_binary",
            "返回当前数据库的基础统计、段、入口点、重点函数和重点字符串。",
            {"type": "object", "properties": {}, "required": []},
            common_schema,
            survey_binary,
        )
    )
