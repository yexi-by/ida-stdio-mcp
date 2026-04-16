"""MCP 工具注册表。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from .models import JsonObject, ToolResult

ToolHandler = Callable[[JsonObject], ToolResult]


@dataclass(slots=True, frozen=True)
class ToolSpec:
    """工具元数据。"""

    name: str
    description: str
    input_schema: JsonObject
    output_schema: JsonObject
    handler: ToolHandler


class ToolRegistry:
    """管理 MCP 工具定义与调用。"""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        """注册工具。"""
        self._tools[tool.name] = tool

    def list_tools(self) -> list[JsonObject]:
        """导出 `tools/list` 所需的工具定义。"""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "outputSchema": tool.output_schema,
            }
            for tool in self._tools.values()
        ]

    def call(self, name: str, arguments: JsonObject) -> ToolResult:
        """按名称执行工具。"""
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"未知工具：{name}")
        return tool.handler(arguments)

    @staticmethod
    def format_tool_result(result: ToolResult) -> JsonObject:
        """把统一工具结果包装为 MCP `tools/call` 结果。"""
        payload = json.dumps(result, ensure_ascii=False)
        return {
            "content": [{"type": "text", "text": payload}],
            "structuredContent": result,
            "isError": result["status"] == "error",
        }
