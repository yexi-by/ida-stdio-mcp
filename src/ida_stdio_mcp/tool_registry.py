"""MCP 工具与资源注册表。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, cast

from .errors import ToolInputValidationError
from .models import GateName
from .models import JsonObject, JsonValue, ResourceContent, ToolResult
from .result import build_error_info
from .schema_validation import validate_arguments

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
    validation_schema: JsonObject | None = None
    requires_session: bool = False
    feature_gate: GateName = "public"
    preconditions: tuple[str, ...] = ()
    empty_state_behavior: str = ""
    input_example: JsonValue | None = None


@dataclass(slots=True, frozen=True)
class ResourceSpec:
    """静态资源元数据。"""

    uri: str
    name: str
    description: str
    mime_type: str
    handler: ResourceHandler
    scope: str = "session"
    requires_session: bool = True


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
    scope: str = "session"
    requires_session: bool = True


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
                "inputExample": tool.input_example if tool.input_example is not None else self._input_example(tool.validation_schema or tool.input_schema),
                "requiresSession": tool.requires_session,
                "featureGate": tool.feature_gate,
                "preconditions": list(tool.preconditions),
                "emptyStateBehavior": tool.empty_state_behavior,
            }
            for tool in self._tools.values()
        ]

    def call(self, name: str, arguments: JsonObject) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"未知工具：{name}")
        try:
            validate_arguments(tool.validation_schema or tool.input_schema, arguments)
        except ToolInputValidationError as exc:
            return {
                "status": "error",
                "source": name,
                "warnings": [],
                "error": cast(
                    JsonObject,
                    build_error_info(
                    code="invalid_arguments",
                    message=str(exc),
                    details={
                        "tool": name,
                        **{key: value for key, value in exc.details.items()},
                    },
                    next_steps=exc.next_steps,
                    ),
                ),
                "data": None,
            }
        return tool.handler(arguments)

    @staticmethod
    def format_tool_result(result: ToolResult) -> JsonObject:
        payload = json.dumps(result, ensure_ascii=False)
        return cast(
            JsonObject,
            {
            "content": [{"type": "text", "text": payload}],
            "structuredContent": result,
            "isError": result["status"] == "error",
            },
        )

    def _input_example(self, schema: JsonObject) -> JsonValue:
        """根据 schema 生成最小可用示例。"""
        return self._example_for_schema(schema)

    def _example_for_schema(self, schema: JsonObject, field_name: str | None = None) -> JsonValue:
        one_of = schema.get("oneOf")
        if isinstance(one_of, list) and one_of:
            first = one_of[0]
            if isinstance(first, dict):
                return self._example_for_schema(first, field_name)

        schema_type = schema.get("type")
        if schema_type == "object":
            result: JsonObject = {}
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                return result
            required = schema.get("required", [])
            required_names = [item for item in required if isinstance(item, str)] if isinstance(required, list) else []
            for name in required_names:
                property_schema = properties.get(name)
                if isinstance(property_schema, dict):
                    result[name] = self._example_for_schema(property_schema, name)
            raw_required_any_of = schema.get("x-required-any-of")
            if isinstance(raw_required_any_of, list) and raw_required_any_of:
                first_branch = raw_required_any_of[0]
                if isinstance(first_branch, list):
                    for name in first_branch:
                        if not isinstance(name, str) or name in result:
                            continue
                        property_schema = properties.get(name)
                        if isinstance(property_schema, dict):
                            result[name] = self._example_for_schema(property_schema, name)
            return result
        if schema_type == "array":
            items = schema.get("items")
            if isinstance(items, dict):
                return [self._example_for_schema(items, field_name)]
            return []
        if schema_type == "string":
            enum = schema.get("enum")
            if isinstance(enum, list) and enum:
                first = enum[0]
                if isinstance(first, str):
                    return first
            return self._string_example(field_name)
        if schema_type == "integer":
            minimum = schema.get("minimum")
            if isinstance(minimum, int):
                return minimum
            if field_name == "thread_id":
                return 1
            if field_name in {"offset"}:
                return 0
            if field_name in {"count", "limit", "max_hits", "max_depth", "size"}:
                return 4
            return 0
        if schema_type == "boolean":
            return True
        return None

    @staticmethod
    def _string_example(field_name: str | None) -> str:
        examples = {
            "path": "D:/samples/sample.exe",
            "session_id": "sess-001",
            "addr": "main",
            "query": "main",
            "root": "main",
            "filter": "main",
            "pattern": "CreateFile",
            "module": "kernel32",
            "name": "main",
            "comment": "示例注释",
            "asm": "nop",
            "hex": "90",
            "type": "int",
            "ty": "int",
            "source": "eax",
            "target": "ebx",
        }
        if field_name is None:
            return "example"
        return examples.get(field_name, "example")


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
        scope: str = "session",
        requires_session: bool = True,
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
                scope=scope,
                requires_session=requires_session,
            )
        )

    def list_resources(self) -> list[JsonObject]:
        return [
            {
                "uri": spec.uri,
                "name": spec.name,
                "description": spec.description,
                "mimeType": spec.mime_type,
                "scope": spec.scope,
                "requiresSession": spec.requires_session,
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
                "scope": spec.scope,
                "requiresSession": spec.requires_session,
            }
            for spec in self._templates
        ]

    def read(self, uri: str) -> tuple[list[ResourceContent], bool]:
        static = self._static_resources.get(uri)
        if static is not None:
            payload = static.handler({})
            return [self._content(uri, static.mime_type, payload)], self._payload_is_error(payload)

        for template in self._templates:
            match = template.pattern.match(uri)
            if match is None:
                continue
            payload = template.handler(match.groupdict())
            return [self._content(uri, template.mime_type, payload)], self._payload_is_error(payload)

        raise KeyError(f"未知资源：{uri}")

    @staticmethod
    def _content(uri: str, mime_type: str, payload: JsonValue) -> ResourceContent:
        return {
            "uri": uri,
            "mimeType": mime_type,
            "text": json.dumps(payload, ensure_ascii=False, indent=2),
        }

    @staticmethod
    def _payload_is_error(payload: JsonValue) -> bool:
        if not isinstance(payload, dict):
            return False
        status = payload.get("status")
        return isinstance(status, str) and status == "error"
