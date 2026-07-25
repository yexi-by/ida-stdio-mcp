"""Supervisor 接入 current-only 协议边界所需的最小接口。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.resources import ResourcePage, ResourceRead
from ida_re_mcp.protocol.models import ClientCapabilities, ClientImplementation, RequestId


@dataclass(frozen=True, slots=True)
class RequestContext:
    """每个请求独立携带、绝不从连接继承的客户端上下文。"""

    protocol_version: str
    client_info: ClientImplementation | None
    client_capabilities: ClientCapabilities
    request_id: RequestId


class ProtocolHandler(Protocol):
    """由 Supervisor 实现的协议无关业务入口。"""

    async def call_tool(
        self,
        name: str,
        arguments: StrictModel,
        context: RequestContext,
    ) -> StrictModel | JsonObject: ...

    async def list_resources(
        self,
        cursor: str | None,
        context: RequestContext,
    ) -> ResourcePage: ...

    async def read_resource(
        self,
        uri: str,
        context: RequestContext,
    ) -> ResourceRead: ...


@runtime_checkable
class CancellationHandler(Protocol):
    """Supervisor 可选实现的在途请求取消入口。"""

    async def cancel_request(self, request_id: RequestId, reason: str | None) -> None: ...
