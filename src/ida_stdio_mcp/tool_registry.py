"""MCP 工具与资源注册表。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable

from .models import JsonObject, JsonValue, ResourceContent, ToolResult

ToolHandler = Callable[[JsonObject], ToolResult]
ResourceHandler = Callable[[dict[str, str]], JsonValue]


@dataclass(slots=True, frozen=True)
class ToolSpec:
    """工具元数据。"""

    name: str
    description: str
    input_schema: JsonObject
    output_schema: JsonObject
    handler: ToolHandler


@dataclass(slots=True, frozen=True)
class ResourceSpec:
    """静态资源元数据。"""

    uri: str
    name: str
    description: str
    mime_type: str
    handler: ResourceHandler


@dataclass(slots=True, frozen=True)
class ResourceTemplateSpec:
    """模板资源元数据。"""

    uri_template: str
    name: str
    description: str
    mime_type: str
    pattern: re.Pattern[str]
    parameter_names: tuple[str, ...]
    handler: ResourceHandler


class ToolRegistry:
    """管理 MCP 工具定义与调用。"""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        self._tools[tool.name] = tool

    def apply_whitelist(self, whitelist: set[str], *, protected: set[str] | None = None) -> tuple[list[str], list[str]]:
        """按白名单裁剪工具集合。"""
        protected_names = protected or set()
        keep = whitelist | protected_names
        unknown = sorted(name for name in whitelist if name not in self._tools)
        for name in list(self._tools):
            if name not in keep:
                self._tools.pop(name)
        kept = sorted(name for name in self._tools if name in whitelist)
        return kept, unknown

    def list_tools(self) -> list[JsonObject]:
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
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"未知工具：{name}")
        return tool.handler(arguments)

    @staticmethod
    def format_tool_result(result: ToolResult) -> JsonObject:
        payload = json.dumps(result, ensure_ascii=False)
        return {
            "content": [{"type": "text", "text": payload}],
            "structuredContent": result,
            "isError": result["status"] == "error",
        }


class ResourceRegistry:
    """管理 MCP resources/list、templates/list 与 read。"""

    def __init__(self) -> None:
        self._static_resources: dict[str, ResourceSpec] = {}
        self._templates: list[ResourceTemplateSpec] = []

    def register_static(self, spec: ResourceSpec) -> None:
        self._static_resources[spec.uri] = spec

    def register_template(
        self,
        *,
        uri_template: str,
        name: str,
        description: str,
        mime_type: str,
        handler: ResourceHandler,
    ) -> None:
        parameter_names = tuple(re.findall(r"\{([^{}]+)\}", uri_template))
        pattern_text = re.escape(uri_template)
        for parameter_name in parameter_names:
            pattern_text = pattern_text.replace(r"\{" + parameter_name + r"\}", rf"(?P<{parameter_name}>[^/]+)")
        compiled = re.compile(rf"^{pattern_text}$")
        self._templates.append(
            ResourceTemplateSpec(
                uri_template=uri_template,
                name=name,
                description=description,
                mime_type=mime_type,
                pattern=compiled,
                parameter_names=parameter_names,
                handler=handler,
            )
        )

    def list_resources(self) -> list[JsonObject]:
        return [
            {
                "uri": spec.uri,
                "name": spec.name,
                "description": spec.description,
                "mimeType": spec.mime_type,
            }
            for spec in self._static_resources.values()
        ]

    def list_templates(self) -> list[JsonObject]:
        return [
            {
                "uriTemplate": spec.uri_template,
                "name": spec.name,
                "description": spec.description,
                "mimeType": spec.mime_type,
            }
            for spec in self._templates
        ]

    def read(self, uri: str) -> tuple[list[ResourceContent], bool]:
        static = self._static_resources.get(uri)
        if static is not None:
            payload = static.handler({})
            return [self._content(uri, static.mime_type, payload)], False

        for template in self._templates:
            match = template.pattern.match(uri)
            if match is None:
                continue
            payload = template.handler(match.groupdict())
            return [self._content(uri, template.mime_type, payload)], False

        raise KeyError(f"未知资源：{uri}")

    @staticmethod
    def _content(uri: str, mime_type: str, payload: JsonValue) -> ResourceContent:
        return {
            "uri": uri,
            "mimeType": mime_type,
            "text": json.dumps(payload, ensure_ascii=False, indent=2),
        }
