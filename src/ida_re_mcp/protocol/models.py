"""MCP 2026-07-28 current-only wire 类型与 RC 严格化覆盖。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Final, Literal, cast

from mcp_types.v2026_07_28 import (
    BlobResourceContents,
    CallToolResult,
    ListResourcesResult,
    ListToolsResult,
    ReadResourceResult,
    ServerCapabilities,
    TextContent,
    TextResourceContents,
)
from mcp_types.v2026_07_28 import (
    CallToolRequest as SdkCallToolRequest,
)
from mcp_types.v2026_07_28 import (
    DiscoverRequest as SdkDiscoverRequest,
)
from mcp_types.v2026_07_28 import (
    Error as JsonRpcErrorData,
)
from mcp_types.v2026_07_28 import (
    JSONRPCErrorResponse as JsonRpcError,
)
from mcp_types.v2026_07_28 import (
    JSONRPCResultResponse as JsonRpcSuccess,
)
from mcp_types.v2026_07_28 import (
    ListResourcesRequest as SdkListResourcesRequest,
)
from mcp_types.v2026_07_28 import (
    ListToolsRequest as SdkListToolsRequest,
)
from mcp_types.v2026_07_28 import (
    MetaObject as ResultMeta,
)
from mcp_types.v2026_07_28 import (
    ReadResourceRequest as SdkReadResourceRequest,
)
from mcp_types.v2026_07_28 import (
    Resource as WireResource,
)
from mcp_types.v2026_07_28 import (
    Tool as ToolDefinition,
)
from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.resources import ArtifactUri

__all__ = [
    "OFFICIAL_REQUEST_MODELS",
    "BlobResourceContents",
    "CallToolRequest",
    "CallToolResult",
    "CancelledNotification",
    "ClientCapabilities",
    "ClientImplementation",
    "DiscoverRequest",
    "DiscoverResult",
    "JsonRpcError",
    "JsonRpcErrorData",
    "JsonRpcSuccess",
    "ListResourcesRequest",
    "ListResourcesResult",
    "ListToolsRequest",
    "ListToolsResult",
    "NotificationEnvelope",
    "ReadResourceRequest",
    "ReadResourceResult",
    "RequestEnvelope",
    "RequestId",
    "ResultMeta",
    "ServerCapabilities",
    "TextContent",
    "TextResourceContents",
    "ToolDefinition",
    "WireResource",
]

type RequestId = Annotated[int, Field(strict=True)] | str
type LoggingLevel = Literal[
    "alert",
    "critical",
    "debug",
    "emergency",
    "error",
    "info",
    "notice",
    "warning",
]

_META_KEY_PATTERN = re.compile(
    r"^(?:(?:[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)"
    r"(?:\.[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\/)?"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)?$"
)


class _OpenMeta(StrictModel):
    """实现 current `_meta` 的开放但有命名约束的扩展点。"""

    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    @model_validator(mode="before")
    @classmethod
    def _validate_meta_keys(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        mapping = cast(dict[object, object], value)
        invalid = [
            key
            for key in mapping
            if not isinstance(key, str) or _META_KEY_PATTERN.fullmatch(key) is None
        ]
        if invalid:
            raise ValueError("`_meta` 包含不符合 MCP 命名规则的键")
        return mapping


class Icon(StrictModel):
    src: str = Field(min_length=1, max_length=8_192)
    mime_type: str | None = Field(default=None, alias="mimeType", max_length=128)
    sizes: list[str] | None = Field(default=None, max_length=32)
    theme: Literal["dark", "light"] | None = None


class ClientImplementation(StrictModel):
    name: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=128)
    title: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=2_048)
    icons: list[Icon] | None = Field(default=None, max_length=16)
    website_url: str | None = Field(default=None, alias="websiteUrl", max_length=8_192)


class ElicitationCapability(StrictModel):
    form: JsonObject | None = None
    url: JsonObject | None = None


class SamplingCapability(StrictModel):
    context: JsonObject | None = None
    tools: JsonObject | None = None


class ClientCapabilities(StrictModel):
    """当前协议允许客户端声明第三方能力。"""

    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        strict=True,
        validate_default=True,
    )

    elicitation: ElicitationCapability | None = None
    experimental: dict[str, JsonObject] | None = None
    extensions: dict[str, JsonObject] | None = None
    roots: JsonObject | None = None
    sampling: SamplingCapability | None = None

    @model_validator(mode="after")
    def _validate_extension_keys(self) -> ClientCapabilities:
        if self.extensions is None:
            return self
        invalid = [
            key
            for key in self.extensions
            if "/" not in key or _META_KEY_PATTERN.fullmatch(key) is None
        ]
        if invalid:
            raise ValueError("client capability extension 键必须使用带前缀的 MCP 名称")
        return self


class RequestMeta(_OpenMeta):
    """请求元数据是规范定义的开放扩展点。"""

    protocol_version: str = Field(
        alias="io.modelcontextprotocol/protocolVersion",
        min_length=1,
        max_length=128,
    )
    client_info: ClientImplementation | None = Field(
        default=None,
        alias="io.modelcontextprotocol/clientInfo",
    )
    client_capabilities: ClientCapabilities = Field(
        alias="io.modelcontextprotocol/clientCapabilities"
    )
    log_level: LoggingLevel | None = Field(
        default=None,
        alias="io.modelcontextprotocol/logLevel",
    )
    progress_token: RequestId | None = Field(default=None, alias="progressToken")


class RequestParams(StrictModel):
    meta: RequestMeta = Field(alias="_meta")


class PaginatedRequestParams(RequestParams):
    cursor: str | None = Field(default=None, min_length=8, max_length=256)


class ToolCallParams(RequestParams):
    name: Annotated[
        str,
        StringConstraints(
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9_.-]+$",
            strict=True,
        ),
    ]
    arguments: dict[str, JsonValue] | None = None
    input_responses: dict[str, JsonValue] | None = Field(default=None, alias="inputResponses")
    request_state: str | None = Field(
        default=None,
        alias="requestState",
        min_length=1,
        max_length=8 * 1024 * 1024,
    )


class ResourceReadParams(RequestParams):
    uri: ArtifactUri
    input_responses: dict[str, JsonValue] | None = Field(default=None, alias="inputResponses")
    request_state: str | None = Field(
        default=None,
        alias="requestState",
        min_length=1,
        max_length=8 * 1024 * 1024,
    )


class DiscoverRequest(StrictModel):
    jsonrpc: Literal["2.0"]
    id: RequestId
    method: Literal["server/discover"]
    params: RequestParams


class ListToolsRequest(StrictModel):
    jsonrpc: Literal["2.0"]
    id: RequestId
    method: Literal["tools/list"]
    params: PaginatedRequestParams


class CallToolRequest(StrictModel):
    jsonrpc: Literal["2.0"]
    id: RequestId
    method: Literal["tools/call"]
    params: ToolCallParams


class ListResourcesRequest(StrictModel):
    jsonrpc: Literal["2.0"]
    id: RequestId
    method: Literal["resources/list"]
    params: PaginatedRequestParams


class ReadResourceRequest(StrictModel):
    jsonrpc: Literal["2.0"]
    id: RequestId
    method: Literal["resources/read"]
    params: ResourceReadParams


class RequestEnvelope(StrictModel):
    """仅用于在方法专属校验前读取 JSON-RPC 信封。"""

    jsonrpc: Literal["2.0"]
    id: RequestId
    method: str
    params: JsonValue | None = None


class NotificationMeta(_OpenMeta):
    """通知元数据允许 trace 与第三方扩展键。"""

    subscription_id: RequestId | None = Field(
        default=None,
        alias="io.modelcontextprotocol/subscriptionId",
    )


class CancelledNotificationParams(StrictModel):
    request_id: RequestId = Field(alias="requestId")
    reason: str | None = Field(default=None, max_length=2_048)
    meta: NotificationMeta | None = Field(default=None, alias="_meta")


class CancelledNotification(StrictModel):
    jsonrpc: Literal["2.0"]
    method: Literal["notifications/cancelled"]
    params: CancelledNotificationParams


class NotificationEnvelope(StrictModel):
    jsonrpc: Literal["2.0"]
    method: str
    params: JsonValue | None = None


class DiscoverResult(StrictModel):
    """beta discovery 类型与 RC 响应差异所需的最小模型。"""

    meta: ResultMeta = Field(alias="_meta")
    result_type: Literal["complete"] = Field(alias="resultType")
    supported_versions: list[str] = Field(alias="supportedVersions", min_length=1)
    capabilities: ServerCapabilities
    instructions: str
    ttl_ms: int = Field(alias="ttlMs", ge=0)
    cache_scope: Literal["public"] = Field(alias="cacheScope")


OFFICIAL_REQUEST_MODELS: Final[Mapping[str, type[BaseModel]]] = MappingProxyType(
    {
        "server/discover": SdkDiscoverRequest,
        "tools/list": SdkListToolsRequest,
        "tools/call": SdkCallToolRequest,
        "resources/list": SdkListResourcesRequest,
        "resources/read": SdkReadResourceRequest,
    }
)
