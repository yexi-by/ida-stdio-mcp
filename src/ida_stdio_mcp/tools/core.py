"""核心生命周期工具。"""

from __future__ import annotations

from pathlib import Path

from ..models import JsonObject
from ..result import build_result
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry, ToolSpec


def register_core_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册生命周期工具。"""

    def health(_: JsonObject):
        return build_result(status="ok", source="runtime", data=runtime.health())

    def warmup(arguments: JsonObject):
        if not runtime.has_binary():
            return build_result(
                status="error",
                source="runtime",
                data=None,
                error="当前没有打开任何二进制",
            )
        return build_result(
            status="ok",
            source="runtime",
            data=runtime.warmup(
                build_caches=bool(arguments.get("build_caches", True)),
                init_hexrays=bool(arguments.get("init_hexrays", True)),
            ),
        )

    def open_binary(arguments: JsonObject):
        path = arguments.get("path")
        if not isinstance(path, str):
            return build_result(status="error", source="runtime", data=None, error="path 必须是字符串")
        summary = runtime.open_binary(Path(path), wait_auto_analysis=bool(arguments.get("wait_auto_analysis", True)))
        return build_result(status="ok", source="runtime", data=summary)

    def close_binary(_: JsonObject):
        runtime.close_binary()
        return build_result(status="ok", source="runtime", data={"closed": True})

    def current_binary(_: JsonObject):
        summary = runtime.current_binary_summary()
        if summary is None:
            return build_result(status="degraded", source="runtime", data=None, warnings=["当前没有激活数据库"])
        return build_result(status="ok", source="runtime", data=summary)

    common_output_schema: JsonObject = {
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
            name="health",
            description="返回服务与当前数据库的健康状态。",
            input_schema={"type": "object", "properties": {}, "required": []},
            output_schema=common_output_schema,
            handler=health,
        )
    )
    registry.register(
        ToolSpec(
            name="warmup",
            description="预热字符串/函数/survey 缓存，并按需初始化 Hex-Rays。",
            input_schema={
                "type": "object",
                "properties": {
                    "build_caches": {"type": "boolean"},
                    "init_hexrays": {"type": "boolean"},
                },
                "required": [],
            },
            output_schema=common_output_schema,
            handler=warmup,
        )
    )
    registry.register(
        ToolSpec(
            name="open_binary",
            description="打开一个二进制并激活当前单样本数据库。",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "wait_auto_analysis": {"type": "boolean"},
                },
                "required": ["path"],
            },
            output_schema=common_output_schema,
            handler=open_binary,
        )
    )
    registry.register(
        ToolSpec(
            name="close_binary",
            description="关闭当前数据库。",
            input_schema={"type": "object", "properties": {}, "required": []},
            output_schema=common_output_schema,
            handler=close_binary,
        )
    )
    registry.register(
        ToolSpec(
            name="current_binary",
            description="返回当前激活数据库摘要。",
            input_schema={"type": "object", "properties": {}, "required": []},
            output_schema=common_output_schema,
            handler=current_binary,
        )
    )
