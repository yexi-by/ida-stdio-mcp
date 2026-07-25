"""官方 MCP SDK 与 Supervisor 业务接口之间的严格适配层。"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
from importlib.metadata import version
from types import MappingProxyType
from typing import Any, Protocol, cast

import mcp.types as mcp_types
from jsonschema import Draft202012Validator
from mcp import McpError
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl, BaseModel, ValidationError

from ida_re_mcp.constants import (
    MAX_INLINE_RESULT_BYTES,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    RESOURCE_CHUNK_BYTES,
)
from ida_re_mcp.domain.base import JsonObject, StrictModel, tool_json_schema
from ida_re_mcp.domain.catalog import ToolSpec
from ida_re_mcp.domain.errors import (
    ResourceNotFoundError,
    ResourceRequestError,
    ToolExecutionError,
)
from ida_re_mcp.domain.resources import BinaryResourceData, TextResourceData
from ida_re_mcp.protocol.handlers import McpHandler

logger = logging.getLogger(__name__)

_RESOURCE_NOT_FOUND = -32002
_MAX_ERROR_MESSAGE_CHARS = 2_048
_INVALID_ARGUMENTS = "invalid_arguments"


class _OutputValidator(Protocol):
    def validate(self, instance: object) -> None: ...


def _validation_details(error: ValidationError) -> JsonObject:
    """把 Pydantic 错误收敛为稳定、有限且不含输入值的结构。"""

    issues: list[dict[str, Any]] = []
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        issues.append(
            {
                "path": [str(part) for part in item["loc"]],
                "message": str(item["msg"])[:512],
                "type": str(item["type"]),
            }
        )
    return cast(JsonObject, {"issues": issues[:64]})


def _compact_json(value: JsonObject) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _tool_error(
    code: str,
    message: str,
    details: JsonObject | None = None,
) -> mcp_types.CallToolResult:
    """构造 Agent 可据此修正请求的稳定工具执行错误。"""

    payload: JsonObject = {
        "code": code,
        "message": message[:_MAX_ERROR_MESSAGE_CHARS],
        "details": details or {},
    }
    serialized = _compact_json(payload)
    if len(serialized.encode("utf-8")) > MAX_INLINE_RESULT_BYTES:
        payload["details"] = {"truncated": True}
        serialized = _compact_json(payload)
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=serialized)],
        isError=True,
    )


def _tool_definition(spec: ToolSpec) -> mcp_types.Tool:
    return mcp_types.Tool(
        name=spec.name,
        title=spec.title,
        description=spec.description,
        inputSchema=cast(dict[str, Any], tool_json_schema(spec.input_model)),
        outputSchema=cast(dict[str, Any], tool_json_schema(spec.output_model)),
        annotations=mcp_types.ToolAnnotations(
            readOnlyHint=spec.read_only,
            destructiveHint=spec.destructive,
            idempotentHint=spec.idempotent,
            openWorldHint=spec.open_world,
        ),
    )


def _protocol_error(
    code: int,
    message: str,
    data: JsonObject | None = None,
) -> McpError:
    return McpError(
        mcp_types.ErrorData(
            code=code,
            message=message,
            data=data,
        )
    )


class McpRuntime:
    """固定工具目录、官方生命周期和 stdio transport 的 MCP 运行时。"""

    def __init__(
        self,
        handler: McpHandler,
        *,
        catalog: tuple[ToolSpec, ...],
    ) -> None:
        ordered = tuple(sorted(catalog, key=lambda item: item.name))
        names = tuple(item.name for item in ordered)
        if not names:
            raise ValueError("MCP 工具目录不能为空")
        if len(names) != len(set(names)):
            raise ValueError("MCP 工具目录包含重复名称")

        self._handler = handler
        self._catalog = ordered
        self._catalog_by_name = MappingProxyType({spec.name: spec for spec in ordered})
        self._tools = tuple(_tool_definition(spec) for spec in ordered)
        output_validators: dict[str, _OutputValidator] = {}
        for spec in ordered:
            schema = tool_json_schema(spec.output_model)
            Draft202012Validator.check_schema(schema)
            output_validators[spec.name] = cast(
                _OutputValidator,
                Draft202012Validator(schema),
            )
        self._output_validators = MappingProxyType(output_validators)
        self._server: Server[object, object] = Server(
            PRODUCT_NAME,
            version=PRODUCT_VERSION,
            instructions=(
                "所有静态查询必须显式提供 workspace_id 与 revision。"
                "所有写入必须通过 change.prepare 与 change.apply 发布新 revision。"
            ),
        )
        self._initialization = InitializationOptions(
            server_name=PRODUCT_NAME,
            server_version=PRODUCT_VERSION,
            capabilities=mcp_types.ServerCapabilities(
                tools=mcp_types.ToolsCapability(),
                resources=mcp_types.ResourcesCapability(),
            ),
            instructions=self._server.instructions,
        )
        self._register_handlers()

    def protocol_report(self) -> JsonObject:
        """返回 doctor 所需的当前 MCP 运行时事实。"""

        return {
            "transport": "stdio",
            "sdk": "mcp",
            "sdk_version": version("mcp"),
            "preferred_protocol": mcp_types.LATEST_PROTOCOL_VERSION,
            "negotiation": "official_sdk",
            "capabilities": ["resources", "tools"],
            "tool_count": len(self._catalog),
        }

    async def serve_stdio(self) -> None:
        """通过官方 UTF-8 单行 JSON-RPC stdio transport 运行服务。"""

        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream,
                write_stream,
                self._initialization,
                raise_exceptions=False,
                stateless=False,
            )

    def _register_handlers(self) -> None:
        self._server.list_tools()(self._list_tools)
        self._server.request_handlers[mcp_types.CallToolRequest] = self._handle_call_tool_request
        self._server.list_resources()(self._list_resources)
        self._server.read_resource()(self._read_resource)

    async def _list_tools(self) -> list[mcp_types.Tool]:
        return list(self._tools)

    async def _handle_call_tool_request(
        self,
        request: mcp_types.CallToolRequest,
    ) -> mcp_types.ServerResult:
        name = request.params.name
        if name not in self._catalog_by_name:
            raise _protocol_error(
                mcp_types.INVALID_PARAMS,
                f"Unknown tool: {name}",
            )
        result = await self._call_tool(name, request.params.arguments or {})
        return mcp_types.ServerResult(result)

    async def _call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> mcp_types.CallToolResult:
        spec = self._catalog_by_name[name]
        try:
            parsed = spec.input_model.model_validate(arguments)
        except ValidationError as error:
            return _tool_error(
                _INVALID_ARGUMENTS,
                "工具参数无效",
                _validation_details(error),
            )

        try:
            raw_result = await self._handler.execute_tool(spec.name, parsed)
            validated = self._validate_output(spec, raw_result)
            structured = validated.model_dump(mode="json")
            serialized = _compact_json(cast(JsonObject, structured))
            if len(serialized.encode("utf-8")) > MAX_INLINE_RESULT_BYTES:
                raise ValueError("工具结果超过 inline 上限")
            self._output_validators[spec.name].validate(structured)
        except ToolExecutionError as error:
            return _tool_error(
                error.code.value,
                error.message,
                error.details,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.exception("工具 %s 执行失败", spec.name)
            raise _protocol_error(
                mcp_types.INTERNAL_ERROR,
                "Internal server error",
            ) from error

        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=serialized)],
            structuredContent=structured,
            isError=False,
        )

    async def _list_resources(
        self,
        request: mcp_types.ListResourcesRequest,
    ) -> mcp_types.ListResourcesResult:
        cursor = request.params.cursor if request.params is not None else None
        try:
            page = await self._handler.list_resources(cursor)
        except ResourceRequestError as error:
            data: JsonObject | None = {"uri": error.uri} if error.uri is not None else None
            raise _protocol_error(
                mcp_types.INVALID_PARAMS,
                error.message[:_MAX_ERROR_MESSAGE_CHARS],
                data,
            ) from error
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.exception("列出 resources 失败")
            raise _protocol_error(
                mcp_types.INTERNAL_ERROR,
                "Internal server error",
            ) from error

        return mcp_types.ListResourcesResult(
            resources=[
                mcp_types.Resource(
                    uri=AnyUrl(item.uri),
                    name=item.name,
                    title=item.title,
                    description=item.description,
                    mimeType=item.mime_type,
                    size=item.size_bytes,
                )
                for item in page.resources
            ],
            nextCursor=page.next_cursor,
        )

    async def _read_resource(self, uri: AnyUrl) -> list[ReadResourceContents]:
        requested_uri = str(uri)
        try:
            read = await self._handler.read_resource(requested_uri)
            contents = [self._resource_content(requested_uri, item) for item in read.contents]
        except ResourceNotFoundError as error:
            raise _protocol_error(
                _RESOURCE_NOT_FOUND,
                "Resource not found",
                {"uri": error.uri},
            ) from error
        except ResourceRequestError as error:
            raise _protocol_error(
                mcp_types.INVALID_PARAMS,
                error.message[:_MAX_ERROR_MESSAGE_CHARS],
                {"uri": error.uri or requested_uri},
            ) from error
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.exception("读取 resource 失败")
            raise _protocol_error(
                mcp_types.INTERNAL_ERROR,
                "Internal server error",
            ) from error
        return contents

    @staticmethod
    def _validate_output(
        spec: ToolSpec,
        value: StrictModel | JsonObject,
    ) -> StrictModel:
        candidate: object
        if isinstance(value, BaseModel):
            candidate = value.model_dump(mode="python")
        else:
            candidate = value
        return spec.output_model.model_validate(candidate)

    @staticmethod
    def _resource_content(
        requested_uri: str,
        item: TextResourceData | BinaryResourceData,
    ) -> ReadResourceContents:
        if item.uri != requested_uri:
            raise ValueError("resource 内容 URI 与请求不一致")
        if isinstance(item, TextResourceData):
            if len(item.text.encode("utf-8")) > RESOURCE_CHUNK_BYTES:
                raise ValueError("文本 resource chunk 超出上限")
            content: str | bytes = item.text
        else:
            try:
                content = base64.b64decode(item.blob, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError("二进制 resource chunk 不是规范 base64") from error
            if len(content) > RESOURCE_CHUNK_BYTES:
                raise ValueError("二进制 resource chunk 超出上限")
        return ReadResourceContents(
            content=content,
            mime_type=item.mime_type,
        )
