"""字节读取工具。"""

from __future__ import annotations

from ..models import JsonObject
from ..result import build_result
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry, ToolSpec


def register_byte_tools(registry: ToolRegistry, runtime: HeadlessRuntime) -> None:
    """注册字节读取工具。"""

    def read_bytes(arguments: JsonObject):
        address = arguments.get("address")
        size = arguments.get("size", 32)
        if not isinstance(address, str):
            return build_result(status="error", source="ida_bytes", data=None, error="address 必须是字符串")
        try:
            value = runtime.read_bytes(int(address, 16), int(size))
            return build_result(status="ok", source="ida_bytes", data=value)
        except Exception as exc:
            return build_result(status="error", source="ida_bytes", data=None, error=str(exc))

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
            "read_bytes",
            "读取指定地址范围内的字节并返回十六进制文本。",
            {
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "size": {"type": "integer"},
                },
                "required": ["address"],
            },
            common_schema,
            read_bytes,
        )
    )
