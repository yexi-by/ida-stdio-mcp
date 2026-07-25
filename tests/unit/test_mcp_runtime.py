from __future__ import annotations

import asyncio
import base64
import json
from typing import cast

import mcp.types as mcp_types
import pytest
from mcp import McpError
from mcp.server.lowlevel import Server
from pydantic import AnyUrl, Field

from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import ToolSpec
from ida_re_mcp.domain.errors import (
    BusinessErrorCode,
    ResourceNotFoundError,
    ResourceRequestError,
    ToolExecutionError,
)
from ida_re_mcp.domain.resources import (
    BinaryResourceData,
    ResourceDescriptor,
    ResourcePage,
    ResourceRead,
    TextResourceData,
)
from ida_re_mcp.protocol.server import McpRuntime

_RESOURCE_URI = (
    "ida-re://workspaces/workspace_abcdef/revisions/revision_abcdef/artifacts/artifact_abcdef"
)
_SERVER_ATTRIBUTE = "_server"


class _EchoInput(StrictModel):
    value: str = Field(min_length=1, max_length=64)


class _EchoOutput(StrictModel):
    value: str


class _FakeHandler:
    def __init__(self) -> None:
        self.executions: list[tuple[str, StrictModel]] = []
        self.resource_cursor: str | None = None
        self.fail_resource_list = False
        self.fail_resource_read = False
        self.fail_resource_read_invalid = False
        self.fail_resource_read_internal = False

    async def execute_tool(
        self,
        name: str,
        arguments: StrictModel,
    ) -> StrictModel | JsonObject:
        self.executions.append((name, arguments))
        if name == "business.echo":
            raise ToolExecutionError(
                BusinessErrorCode.REVISION_CONFLICT,
                "revision 已改变",
                details={"current_revision": "revision_current"},
            )
        if name == "internal.echo":
            raise RuntimeError("sensitive-internal-detail")
        typed = cast(_EchoInput, arguments)
        return _EchoOutput(value=typed.value)

    async def list_resources(self, cursor: str | None) -> ResourcePage:
        self.resource_cursor = cursor
        if self.fail_resource_list:
            raise ResourceRequestError("resource cursor 无效", uri=_RESOURCE_URI)
        return ResourcePage(
            resources=[
                ResourceDescriptor(
                    uri=_RESOURCE_URI,
                    name="analysis.txt",
                    title="分析结果",
                    description="不可变测试 artifact",
                    mime_type="text/plain",
                    size_bytes=6,
                )
            ],
            next_cursor="cursor_next",
        )

    async def read_resource(self, uri: str) -> ResourceRead:
        if self.fail_resource_read:
            raise ResourceNotFoundError(uri=uri)
        if self.fail_resource_read_invalid:
            raise ResourceRequestError("resource URI 无效", uri=uri)
        if self.fail_resource_read_internal:
            raise RuntimeError("sensitive-resource-integrity-detail")
        return ResourceRead(
            contents=[
                TextResourceData(
                    kind="text",
                    uri=_RESOURCE_URI,
                    mime_type="text/plain",
                    text="文本",
                ),
                BinaryResourceData(
                    kind="blob",
                    uri=_RESOURCE_URI,
                    mime_type="application/octet-stream",
                    blob=base64.b64encode(b"\x00\x01\xff").decode("ascii"),
                ),
            ]
        )


def _spec(name: str) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=f"{name} title",
        description=f"{name} description",
        input_model=_EchoInput,
        output_model=_EchoOutput,
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=False,
    )


def _runtime(handler: _FakeHandler | None = None) -> tuple[McpRuntime, _FakeHandler]:
    selected = handler or _FakeHandler()
    runtime = McpRuntime(
        selected,
        catalog=tuple(
            _spec(name)
            for name in (
                "z.echo",
                "internal.echo",
                "business.echo",
                "a.echo",
            )
        ),
    )
    return runtime, selected


async def _dispatch(runtime: McpRuntime, request: object) -> mcp_types.ServerResult:
    server = cast(Server[object, object], getattr(runtime, _SERVER_ATTRIBUTE))
    handler = server.request_handlers[type(request)]
    return await handler(request)


async def _call_tool(
    runtime: McpRuntime,
    name: str,
    arguments: dict[str, object],
) -> mcp_types.CallToolResult:
    response = await _dispatch(
        runtime,
        mcp_types.CallToolRequest(
            params=mcp_types.CallToolRequestParams(
                name=name,
                arguments=arguments,
            )
        ),
    )
    assert isinstance(response.root, mcp_types.CallToolResult)
    return response.root


def _error_payload(result: mcp_types.CallToolResult) -> JsonObject:
    assert result.isError is True
    assert result.structuredContent is None
    assert len(result.content) == 1
    content = result.content[0]
    assert isinstance(content, mcp_types.TextContent)
    return cast(JsonObject, json.loads(content.text))


def test_official_list_tools_is_sorted_and_uses_closed_strict_schemas() -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime()
        response = await _dispatch(runtime, mcp_types.ListToolsRequest())
        assert isinstance(response.root, mcp_types.ListToolsResult)
        tools = response.root.tools
        assert [tool.name for tool in tools] == [
            "a.echo",
            "business.echo",
            "internal.echo",
            "z.echo",
        ]
        for tool in tools:
            for schema in (tool.inputSchema, tool.outputSchema):
                assert schema is not None
                assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
                assert schema["type"] == "object"
                assert schema["additionalProperties"] is False
            assert tool.annotations is not None
            assert tool.annotations.readOnlyHint is True
            assert tool.annotations.destructiveHint is False

    asyncio.run(scenario())


def test_official_call_tool_returns_structured_and_text_content() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        result = await _call_tool(runtime, "a.echo", {"value": "hello"})

        assert result.isError is False
        assert result.structuredContent == {"value": "hello"}
        assert len(result.content) == 1
        content = result.content[0]
        assert isinstance(content, mcp_types.TextContent)
        assert cast(JsonObject, json.loads(content.text)) == {"value": "hello"}
        assert len(handler.executions) == 1
        assert handler.executions[0][0] == "a.echo"
        assert handler.executions[0][1] == _EchoInput(value="hello")

    asyncio.run(scenario())


def test_official_call_tool_reports_invalid_arguments_without_invoking_handler() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        result = await _call_tool(
            runtime,
            "a.echo",
            {"value": 7, "unexpected": True},
        )

        payload = _error_payload(result)
        assert payload["code"] == "invalid_arguments"
        assert payload["message"] == "工具参数无效"
        assert handler.executions == []
        details = cast(JsonObject, payload["details"])
        assert isinstance(details["issues"], list)

    asyncio.run(scenario())


def test_official_call_tool_reports_unknown_tool() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        with pytest.raises(McpError) as error:
            await _call_tool(runtime, "missing.tool", {"value": "ignored"})
        assert error.value.error.code == mcp_types.INVALID_PARAMS
        assert error.value.error.message == "Unknown tool: missing.tool"
        assert handler.executions == []

    asyncio.run(scenario())


def test_official_call_tool_preserves_business_error() -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime()
        payload = _error_payload(await _call_tool(runtime, "business.echo", {"value": "input"}))

        assert payload == {
            "code": "revision_conflict",
            "message": "revision 已改变",
            "details": {"current_revision": "revision_current"},
        }

    asyncio.run(scenario())


def test_official_call_tool_sanitizes_internal_exception() -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime()
        with pytest.raises(McpError) as error:
            await _call_tool(runtime, "internal.echo", {"value": "input"})
        assert error.value.error.code == mcp_types.INTERNAL_ERROR
        assert error.value.error.message == "Internal server error"
        assert error.value.error.data is None
        serialized = error.value.error.model_dump_json()
        assert "sensitive-internal-detail" not in serialized
        assert "RuntimeError" not in serialized

    asyncio.run(scenario())


def test_official_resource_handlers_map_descriptor_text_and_blob() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        listed_response = await _dispatch(
            runtime,
            mcp_types.ListResourcesRequest(
                params=mcp_types.PaginatedRequestParams(cursor="cursor_input")
            ),
        )
        assert isinstance(listed_response.root, mcp_types.ListResourcesResult)
        listed = listed_response.root
        assert handler.resource_cursor == "cursor_input"
        assert listed.nextCursor == "cursor_next"
        assert len(listed.resources) == 1
        descriptor = listed.resources[0]
        assert str(descriptor.uri) == _RESOURCE_URI
        assert descriptor.name == "analysis.txt"
        assert descriptor.mimeType == "text/plain"
        assert descriptor.size == 6

        read_response = await _dispatch(
            runtime,
            mcp_types.ReadResourceRequest(
                params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
            ),
        )
        assert isinstance(read_response.root, mcp_types.ReadResourceResult)
        contents = read_response.root.contents
        assert len(contents) == 2
        text = contents[0]
        blob = contents[1]
        assert isinstance(text, mcp_types.TextResourceContents)
        assert text.text == "文本"
        assert text.mimeType == "text/plain"
        assert isinstance(blob, mcp_types.BlobResourceContents)
        assert blob.blob == base64.b64encode(b"\x00\x01\xff").decode("ascii")
        assert blob.mimeType == "application/octet-stream"

    asyncio.run(scenario())


def test_official_resource_handlers_map_resource_errors() -> None:
    async def scenario() -> None:
        handler = _FakeHandler()
        runtime, _handler = _runtime(handler)

        handler.fail_resource_list = True
        with pytest.raises(McpError) as list_error:
            await _dispatch(runtime, mcp_types.ListResourcesRequest())
        assert list_error.value.error.code == mcp_types.INVALID_PARAMS
        assert list_error.value.error.message == "resource cursor 无效"
        assert list_error.value.error.data == {"uri": _RESOURCE_URI}

        handler.fail_resource_list = False
        handler.fail_resource_read = True
        with pytest.raises(McpError) as read_error:
            await _dispatch(
                runtime,
                mcp_types.ReadResourceRequest(
                    params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
                ),
            )
        assert read_error.value.error.code == -32002
        assert read_error.value.error.message == "Resource not found"
        assert read_error.value.error.data == {"uri": _RESOURCE_URI}

        handler.fail_resource_read = False
        handler.fail_resource_read_invalid = True
        with pytest.raises(McpError) as invalid_error:
            await _dispatch(
                runtime,
                mcp_types.ReadResourceRequest(
                    params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
                ),
            )
        assert invalid_error.value.error.code == mcp_types.INVALID_PARAMS
        assert invalid_error.value.error.message == "resource URI 无效"
        assert invalid_error.value.error.data == {"uri": _RESOURCE_URI}

    asyncio.run(scenario())


def test_official_resource_handler_sanitizes_internal_failure() -> None:
    async def scenario() -> None:
        handler = _FakeHandler()
        handler.fail_resource_read_internal = True
        runtime, _handler = _runtime(handler)

        with pytest.raises(McpError) as error:
            await _dispatch(
                runtime,
                mcp_types.ReadResourceRequest(
                    params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
                ),
            )
        assert error.value.error.code == mcp_types.INTERNAL_ERROR
        assert error.value.error.message == "Internal server error"
        assert "sensitive-resource-integrity-detail" not in error.value.error.model_dump_json()

    asyncio.run(scenario())
