from __future__ import annotations

import asyncio
import base64
import json
from typing import cast

import pytest
from mcp_types.v2026_07_28 import (
    CallToolResultResponse as SdkCallToolResultResponse,
)
from mcp_types.v2026_07_28 import (
    JSONRPCErrorResponse as SdkJsonRpcErrorResponse,
)
from mcp_types.v2026_07_28 import (
    ListResourcesResultResponse as SdkListResourcesResultResponse,
)
from mcp_types.v2026_07_28 import (
    ListToolsResultResponse as SdkListToolsResultResponse,
)
from mcp_types.v2026_07_28 import (
    ReadResourceResultResponse as SdkReadResourceResultResponse,
)
from pydantic import Field

from ida_re_mcp.constants import (
    MAX_INLINE_RESULT_BYTES,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    PROTOCOL_VERSION,
    RESOURCE_CHUNK_BYTES,
)
from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import TOOL_CATALOG, ToolSpec
from ida_re_mcp.domain.errors import BusinessErrorCode, ResourceRequestError, ToolExecutionError
from ida_re_mcp.domain.resources import (
    BinaryResourceData,
    ResourceDescriptor,
    ResourcePage,
    ResourceRead,
    TextResourceData,
)
from ida_re_mcp.domain.tools import OperationWaitOutput
from ida_re_mcp.protocol.dispatch import CurrentProtocol
from ida_re_mcp.protocol.handlers import RequestContext
from ida_re_mcp.protocol.models import (
    OFFICIAL_REQUEST_MODELS,
    CallToolResult,
    ClientImplementation,
    ListResourcesResult,
    ListToolsResult,
    ReadResourceResult,
    RequestId,
)


class FakeHandler:
    def __init__(self) -> None:
        self.cancelled: list[tuple[RequestId, str | None]] = []
        self.raise_tool_error = False
        self.raise_internal_error = False
        self.invalid_output = False
        self.raise_cancel_error = False
        self.binary_resource_bytes: bytes | None = None
        self.seen_client_info: ClientImplementation | None = None

    async def call_tool(
        self,
        name: str,
        arguments: StrictModel,
        context: RequestContext,
    ) -> StrictModel | JsonObject:
        assert name == "operation.wait"
        assert context.protocol_version == PROTOCOL_VERSION
        self.seen_client_info = context.client_info
        if self.raise_tool_error:
            raise ToolExecutionError(
                BusinessErrorCode.OPERATION_NOT_FOUND,
                "operation 不存在",
                details={"operation_id": "operation_missing"},
            )
        if self.raise_internal_error:
            raise RuntimeError("sensitive detail")
        if self.invalid_output:
            return {"unexpected": True}
        return OperationWaitOutput(
            operation_id="operation_abcdef",
            state="running",
            progress=0.5,
        )

    async def list_resources(
        self,
        cursor: str | None,
        context: RequestContext,
    ) -> ResourcePage:
        assert cursor is None
        assert context.request_id == "resources"
        return ResourcePage(
            resources=[
                ResourceDescriptor(
                    uri=(
                        "ida-re://workspaces/workspace_abcdef/"
                        "revisions/revision_abcdef/artifacts/artifact_abcdef"
                    ),
                    name="report.md",
                    mime_type="text/markdown",
                    size_bytes=6,
                )
            ],
            ttl_ms=1_000,
        )

    async def read_resource(
        self,
        uri: str,
        context: RequestContext,
    ) -> ResourceRead:
        if uri.endswith("artifact_missing"):
            raise ResourceRequestError("resource 不存在", uri=uri)
        if self.binary_resource_bytes is not None:
            return ResourceRead(
                contents=[
                    BinaryResourceData(
                        kind="blob",
                        uri=uri,
                        mime_type="application/octet-stream",
                        blob=base64.b64encode(self.binary_resource_bytes).decode("ascii"),
                    )
                ]
            )
        return ResourceRead(
            contents=[
                TextResourceData(
                    kind="text",
                    uri=uri,
                    mime_type="text/markdown",
                    text="# test",
                )
            ]
        )

    async def cancel_request(self, request_id: RequestId, reason: str | None) -> None:
        if self.raise_cancel_error:
            raise RuntimeError("cancel failed")
        self.cancelled.append((request_id, reason))


def _meta(
    version: str = PROTOCOL_VERSION,
    *,
    include_client_info: bool = True,
) -> JsonObject:
    meta: JsonObject = {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    if include_client_info:
        meta["io.modelcontextprotocol/clientInfo"] = {
            "name": "test-client",
            "version": "1.0.0",
        }
    return meta


def _request(
    method: str,
    params: JsonObject,
    *,
    request_id: RequestId = 1,
    include_client_info: bool = True,
) -> bytes:
    return (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": {
                    "_meta": _meta(include_client_info=include_client_info),
                    **params,
                },
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


async def _handle_decoded(protocol: CurrentProtocol, line: bytes) -> JsonObject:
    response = await protocol.handle_line(line)
    assert response is not None
    return cast(JsonObject, json.loads(response))


def _decoded(protocol: CurrentProtocol, line: bytes) -> JsonObject:
    return asyncio.run(_handle_decoded(protocol, line))


def _assert_server_meta(result: JsonObject) -> None:
    meta = cast(JsonObject, result["_meta"])
    server_info = cast(JsonObject, meta["io.modelcontextprotocol/serverInfo"])
    assert server_info["name"] == PRODUCT_NAME
    assert server_info["version"] == PRODUCT_VERSION


def test_discover_advertises_only_current_tools_and_resources() -> None:
    protocol = CurrentProtocol(FakeHandler())
    response = _decoded(protocol, _request("server/discover", {}, request_id="discover"))
    result = cast(JsonObject, response["result"])
    assert result["supportedVersions"] == [PROTOCOL_VERSION]
    assert result["capabilities"] == {"tools": {}, "resources": {}}
    assert "serverInfo" not in result
    _assert_server_meta(result)


def test_protocol_reuses_official_current_generated_wire_types() -> None:
    assert set(OFFICIAL_REQUEST_MODELS) == {
        "server/discover",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
    }
    assert all(
        model_type.__module__ == "mcp_types.v2026_07_28"
        for model_type in OFFICIAL_REQUEST_MODELS.values()
    )
    assert all(
        model_type.__module__ == "mcp_types.v2026_07_28"
        for model_type in (
            CallToolResult,
            ListResourcesResult,
            ListToolsResult,
            ReadResourceResult,
        )
    )


def test_tools_list_is_fixed_sorted_and_has_closed_schemas() -> None:
    protocol = CurrentProtocol(FakeHandler())
    response = _decoded(protocol, _request("tools/list", {}))
    result = cast(JsonObject, response["result"])
    _assert_server_meta(result)
    tools = cast(list[JsonObject], result["tools"])
    names = [cast(str, tool["name"]) for tool in tools]
    assert names == sorted(names)
    assert "expert.execute" not in names
    assert all(
        cast(JsonObject, tool["inputSchema"])["additionalProperties"] is False for tool in tools
    )


def test_every_tool_schema_is_current_closed_and_uses_only_internal_refs() -> None:
    def assert_schema(schema: JsonObject) -> None:
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False

        pending: list[object] = [schema]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                mapping = cast(dict[object, object], value)
                reference = mapping.get("$ref")
                if reference is not None:
                    assert isinstance(reference, str)
                    assert reference.startswith("#/$defs/")
                pending.extend(mapping.values())
            elif isinstance(value, list):
                pending.extend(cast(list[object], value))

    for spec in TOOL_CATALOG:
        definition = spec.as_wire_definition()
        assert_schema(cast(JsonObject, definition["inputSchema"]))
        assert_schema(cast(JsonObject, definition["outputSchema"]))


def test_tool_call_validates_input_and_output() -> None:
    protocol = CurrentProtocol(FakeHandler())
    response = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {
                    "operation_id": "operation_abcdef",
                    "wait_ms": 0,
                },
            },
        ),
    )
    result = cast(JsonObject, response["result"])
    _assert_server_meta(result)
    assert result["isError"] is False
    assert cast(JsonObject, result["structuredContent"])["state"] == "running"


def test_unknown_tool_and_invalid_arguments_are_invalid_params() -> None:
    protocol = CurrentProtocol(FakeHandler())
    unknown = _decoded(
        protocol,
        _request("tools/call", {"name": "unknown.tool", "arguments": {}}),
    )
    assert cast(JsonObject, unknown["error"])["code"] == -32602

    invalid = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {
                    "operation_id": "operation_abcdef",
                    "wait_ms": "0",
                },
            },
        ),
    )
    error = cast(JsonObject, invalid["error"])
    assert error["code"] == -32602
    assert "0" not in json.dumps(error.get("data"), ensure_ascii=False)


def test_tool_execution_error_is_visible_but_internal_error_is_sanitized() -> None:
    handler = FakeHandler()
    protocol = CurrentProtocol(handler)
    handler.raise_tool_error = True
    business = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {"operation_id": "operation_abcdef"},
            },
        ),
    )
    business_result = cast(JsonObject, business["result"])
    _assert_server_meta(business_result)
    assert business_result["isError"] is True
    assert BusinessErrorCode.OPERATION_NOT_FOUND.value in cast(
        str,
        cast(list[JsonObject], business_result["content"])[0]["text"],
    )

    handler.raise_tool_error = False
    handler.raise_internal_error = True
    internal = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {"operation_id": "operation_abcdef"},
            },
        ),
    )
    assert cast(JsonObject, internal["error"]) == {
        "code": -32603,
        "message": "Internal error",
    }
    assert "sensitive detail" not in json.dumps(internal)

    handler.raise_internal_error = False
    handler.invalid_output = True
    invalid_output = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {"operation_id": "operation_abcdef"},
            },
        ),
    )
    assert cast(JsonObject, invalid_output["error"]) == {
        "code": -32603,
        "message": "Internal error",
    }


def test_missing_meta_unknown_method_and_bad_json_map_strictly() -> None:
    protocol = CurrentProtocol(FakeHandler())

    no_meta = _decoded(
        protocol,
        b'{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}\n',
    )
    assert cast(JsonObject, no_meta["error"])["code"] == -32602

    unknown = _decoded(protocol, _request("server/no_such_method", {}))
    assert cast(JsonObject, unknown["error"])["code"] == -32601

    incomplete_unknown = _decoded(
        protocol,
        (
            b'{"jsonrpc":"2.0","id":"unknown-with-incomplete-meta",'
            b'"method":"server/no_such_method","params":{"_meta":{'
            b'"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}\n'
        ),
    )
    assert cast(JsonObject, incomplete_unknown["error"])["code"] == -32602

    duplicate = _decoded(
        protocol,
        b'{"jsonrpc":"2.0","id":1,"id":2,"method":"server/discover"}\n',
    )
    assert cast(JsonObject, duplicate["error"])["code"] == -32700
    assert duplicate["id"] is None
    assert SdkJsonRpcErrorResponse.model_validate(duplicate).error.code == -32700

    multiline = _decoded(protocol, b'{"jsonrpc":"2.0"}\n{"jsonrpc":"2.0"}\n')
    assert cast(JsonObject, multiline["error"])["code"] == -32700
    assert multiline["id"] is None


def test_current_requests_are_stateless_and_repeatable() -> None:
    protocol = CurrentProtocol(FakeHandler())
    first_discovery = _decoded(protocol, _request("server/discover", {}))
    tools = _decoded(protocol, _request("tools/list", {}))
    second_discovery = _decoded(protocol, _request("server/discover", {}))

    assert first_discovery["result"] == second_discovery["result"]
    assert "result" in tools


@pytest.mark.parametrize(
    "method",
    [
        "prompts/list",
        "completion/complete",
        "subscriptions/listen",
        "tasks/get",
        "sampling/createMessage",
    ],
)
def test_unadvertised_protocol_surfaces_are_method_not_found(method: str) -> None:
    response = _decoded(CurrentProtocol(FakeHandler()), _request(method, {}))

    assert cast(JsonObject, response["error"])["code"] == -32601


def test_invalid_envelope_is_invalid_request() -> None:
    protocol = CurrentProtocol(FakeHandler())
    response = _decoded(
        protocol,
        b'{"jsonrpc":"1.0","id":1,"method":"server/discover","params":{}}\n',
    )
    assert cast(JsonObject, response["error"])["code"] == -32600


@pytest.mark.parametrize("params", [[], "invalid", 1, True])
def test_method_params_with_wrong_json_type_are_invalid_params(params: object) -> None:
    line = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "bad-params",
                "method": "server/discover",
                "params": params,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    response = _decoded(CurrentProtocol(FakeHandler()), line)

    assert cast(JsonObject, response["error"])["code"] == -32602


def test_resource_list_read_and_not_found() -> None:
    protocol = CurrentProtocol(FakeHandler())
    listed = _decoded(
        protocol,
        _request("resources/list", {}, request_id="resources"),
    )
    listed_result = cast(JsonObject, listed["result"])
    _assert_server_meta(listed_result)
    resources = cast(list[JsonObject], listed_result["resources"])
    uri = cast(str, resources[0]["uri"])
    assert resources[0]["size"] == 6

    read = _decoded(protocol, _request("resources/read", {"uri": uri}))
    read_result = cast(JsonObject, read["result"])
    _assert_server_meta(read_result)
    contents = cast(list[JsonObject], read_result["contents"])
    assert contents[0]["text"] == "# test"

    missing_uri = uri.removesuffix("artifact_abcdef") + "artifact_missing"
    missing = _decoded(
        protocol,
        _request("resources/read", {"uri": missing_uri}),
    )
    assert cast(JsonObject, missing["error"])["code"] == -32602


@pytest.mark.parametrize(
    "uri",
    [
        (
            "ida-re://workspaces/workspace_abcdef/revisions/revision_abcdef/"
            "artifacts/artifact_abcdef?offset=1"
        ),
        (
            "ida-re://workspaces/workspace_abcdef/revisions/revision_abcdef/"
            "artifacts/artifact_%61bcdef"
        ),
        "ida-re://workspaces/short/revisions/revision_abcdef/artifacts/artifact_abcdef",
    ],
)
def test_resource_read_rejects_noncanonical_artifact_uri(uri: str) -> None:
    response = _decoded(CurrentProtocol(FakeHandler()), _request("resources/read", {"uri": uri}))

    assert cast(JsonObject, response["error"])["code"] == -32602


def test_cancel_notification_is_forwarded_without_response() -> None:
    handler = FakeHandler()
    protocol = CurrentProtocol(handler)
    response = asyncio.run(
        protocol.handle_line(
            b'{"jsonrpc":"2.0","method":"notifications/cancelled",'
            b'"params":{"requestId":"request_abcdef","reason":"user"}}\n'
        )
    )
    assert response is None
    assert handler.cancelled == [("request_abcdef", "user")]


def test_cancel_notification_accepts_optional_notification_meta() -> None:
    handler = FakeHandler()
    protocol = CurrentProtocol(handler)
    response = asyncio.run(
        protocol.handle_line(
            b'{"jsonrpc":"2.0","method":"notifications/cancelled",'
            b'"params":{"_meta":{"io.modelcontextprotocol/subscriptionId":7},'
            b'"requestId":"request_abcdef"}}\n'
        )
    )
    assert response is None
    assert handler.cancelled == [("request_abcdef", None)]


def test_cancel_notification_failure_never_produces_a_json_rpc_response() -> None:
    handler = FakeHandler()
    handler.raise_cancel_error = True
    protocol = CurrentProtocol(handler)

    response = asyncio.run(
        protocol.handle_line(
            b'{"jsonrpc":"2.0","method":"notifications/cancelled",'
            b'"params":{"requestId":"request_abcdef"}}\n'
        )
    )

    assert response is None


def test_client_info_is_optional_on_response_bearing_request() -> None:
    handler = FakeHandler()
    protocol = CurrentProtocol(handler)
    response = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {"operation_id": "operation_abcdef"},
            },
            include_client_info=False,
        ),
    )
    _assert_server_meta(cast(JsonObject, response["result"]))
    assert handler.seen_client_info is None


def test_current_open_metadata_and_optional_client_fields_are_accepted() -> None:
    handler = FakeHandler()
    protocol = CurrentProtocol(handler)
    request = cast(
        JsonObject,
        json.loads(
            _request(
                "tools/call",
                {
                    "name": "operation.wait",
                    "arguments": {"operation_id": "operation_abcdef"},
                },
            )
        ),
    )
    params = cast(JsonObject, request["params"])
    meta = cast(JsonObject, params["_meta"])
    client_info = cast(JsonObject, meta["io.modelcontextprotocol/clientInfo"])
    client_info["websiteUrl"] = "https://client.example"
    meta["io.modelcontextprotocol/logLevel"] = "warning"
    meta["traceparent"] = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
    meta["com.example/request"] = {"tenant": "test"}
    capabilities = cast(JsonObject, meta["io.modelcontextprotocol/clientCapabilities"])
    capabilities["com.example/custom"] = {"enabled": True}
    capabilities["extensions"] = {"com.example/extension": {}}

    response = _decoded(
        protocol,
        json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n",
    )

    assert "result" in response
    assert handler.seen_client_info is not None
    assert handler.seen_client_info.website_url == "https://client.example"


def test_invalid_meta_extension_key_is_invalid_params() -> None:
    protocol = CurrentProtocol(FakeHandler())
    request = cast(
        JsonObject,
        json.loads(_request("server/discover", {}, request_id="invalid-meta")),
    )
    params = cast(JsonObject, request["params"])
    meta = cast(JsonObject, params["_meta"])
    meta["bad key"] = True

    response = _decoded(
        protocol,
        json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n",
    )

    assert cast(JsonObject, response["error"])["code"] == -32602


def test_client_capability_extension_requires_prefixed_name() -> None:
    protocol = CurrentProtocol(FakeHandler())
    request = cast(
        JsonObject,
        json.loads(_request("server/discover", {}, request_id="invalid-extension")),
    )
    params = cast(JsonObject, request["params"])
    meta = cast(JsonObject, params["_meta"])
    capabilities = cast(JsonObject, meta["io.modelcontextprotocol/clientCapabilities"])
    capabilities["extensions"] = {"unprefixed": {}}

    response = _decoded(
        protocol,
        json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n",
    )

    assert cast(JsonObject, response["error"])["code"] == -32602


def test_unknown_notification_is_ignored_without_response() -> None:
    protocol = CurrentProtocol(FakeHandler())
    response = asyncio.run(
        protocol.handle_line(
            b'{"jsonrpc":"2.0","method":"notifications/no_such_event","params":{}}\n'
        )
    )
    assert response is None


class _PayloadInput(StrictModel):
    pass


class _PayloadOutput(StrictModel):
    text: str = Field(min_length=1)


class _PayloadHandler(FakeHandler):
    def __init__(self, size: int) -> None:
        super().__init__()
        self.size = size

    async def call_tool(
        self,
        name: str,
        arguments: StrictModel,
        context: RequestContext,
    ) -> StrictModel | JsonObject:
        del name, arguments, context
        return _PayloadOutput(text="x" * self.size)


def _payload_spec() -> ToolSpec:
    return ToolSpec(
        name="payload.read",
        title="读取 payload",
        description="测试 inline 边界。",
        input_model=_PayloadInput,
        output_model=_PayloadOutput,
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=False,
    )


@pytest.mark.parametrize("extra_bytes, expected_error", [(0, False), (1, True)])
def test_tool_structured_content_enforces_exact_32_kib_limit(
    extra_bytes: int,
    expected_error: bool,
) -> None:
    overhead = len(b'{"text":""}')
    protocol = CurrentProtocol(
        _PayloadHandler(MAX_INLINE_RESULT_BYTES - overhead + extra_bytes),
        catalog=(_payload_spec(),),
    )

    response = _decoded(
        protocol,
        _request("tools/call", {"name": "payload.read", "arguments": {}}),
    )

    if expected_error:
        assert cast(JsonObject, response["error"]) == {
            "code": -32603,
            "message": "Internal error",
        }
    else:
        result = cast(JsonObject, response["result"])
        structured = cast(JsonObject, result["structuredContent"])
        assert (
            len(json.dumps(structured, separators=(",", ":")).encode("utf-8"))
            == MAX_INLINE_RESULT_BYTES
        )


@pytest.mark.parametrize("extra_bytes, expected_error", [(0, False), (1, True)])
def test_binary_resource_chunk_limit_uses_decoded_size(
    extra_bytes: int,
    expected_error: bool,
) -> None:
    handler = FakeHandler()
    handler.binary_resource_bytes = b"x" * (RESOURCE_CHUNK_BYTES + extra_bytes)
    protocol = CurrentProtocol(handler)
    uri = "ida-re://workspaces/workspace_abcdef/revisions/revision_abcdef/artifacts/artifact_abcdef"

    response = _decoded(protocol, _request("resources/read", {"uri": uri}))

    if expected_error:
        assert cast(JsonObject, response["error"]) == {
            "code": -32603,
            "message": "Internal error",
        }
    else:
        contents = cast(
            list[JsonObject],
            cast(JsonObject, response["result"])["contents"],
        )
        assert len(base64.b64decode(cast(str, contents[0]["blob"]))) == RESOURCE_CHUNK_BYTES


def test_current_sdk_types_parse_supported_non_discovery_results() -> None:
    """b2 的 discover 类型落后于 RC; 其余 current 结果仍用于真实 wire 解析。"""

    protocol = CurrentProtocol(FakeHandler())
    tools = _decoded(protocol, _request("tools/list", {}, request_id="tools"))
    called = _decoded(
        protocol,
        _request(
            "tools/call",
            {
                "name": "operation.wait",
                "arguments": {"operation_id": "operation_abcdef"},
            },
            request_id="call",
        ),
    )
    resources = _decoded(
        protocol,
        _request("resources/list", {}, request_id="resources"),
    )
    uri = cast(
        str,
        cast(
            list[JsonObject],
            cast(JsonObject, resources["result"])["resources"],
        )[0]["uri"],
    )
    read = _decoded(
        protocol,
        _request("resources/read", {"uri": uri}, request_id="read"),
    )

    assert SdkListToolsResultResponse.model_validate(tools).id.root == "tools"
    assert SdkCallToolResultResponse.model_validate(called).id.root == "call"
    assert SdkListResourcesResultResponse.model_validate(resources).id.root == "resources"
    assert SdkReadResourceResultResponse.model_validate(read).id.root == "read"


def test_protocol_accepts_exact_transport_payload_and_rejects_one_byte_more() -> None:
    protocol = CurrentProtocol(FakeHandler())
    request = _request("server/discover", {}).removesuffix(b"\n")
    exact = request + (b" " * (8 * 1024 * 1024 - len(request))) + b"\n"

    accepted = _decoded(protocol, exact)
    rejected = _decoded(protocol, exact[:-1] + b" \n")

    assert "result" in accepted
    assert cast(JsonObject, rejected["error"])["code"] == -32700


@pytest.mark.parametrize(
    "line",
    [
        (
            b'{"jsonrpc":"2.0","id":1,"method":"server/discover","params":'
            b'{"_meta":{"io.modelcontextprotocol/protocolVersion":"\\ud800",'
            b'"io.modelcontextprotocol/clientCapabilities":{}}}}\n'
        ),
        (
            b'{"jsonrpc":"2.0","id":1e400,"method":"server/discover","params":'
            b'{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
            b'"io.modelcontextprotocol/clientCapabilities":{}}}}\n'
        ),
    ],
)
def test_non_json_scalar_values_are_parse_errors(line: bytes) -> None:
    response = _decoded(CurrentProtocol(FakeHandler()), line)
    assert cast(JsonObject, response["error"]) == {
        "code": -32700,
        "message": "Parse error",
    }


def test_json_batch_is_not_a_supported_current_request_shape() -> None:
    response = _decoded(CurrentProtocol(FakeHandler()), b"[]\n")

    assert cast(JsonObject, response["error"]) == {
        "code": -32600,
        "message": "Invalid Request",
    }
