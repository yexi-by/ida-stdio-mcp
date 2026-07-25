"""MCP 边界调用 Supervisor 所需的最小业务接口。"""

from __future__ import annotations

from typing import Protocol

from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.resources import ResourcePage, ResourceRead


class McpHandler(Protocol):
    """由 Supervisor 实现、与 MCP 传输细节无关的业务入口。"""

    async def execute_tool(
        self,
        name: str,
        arguments: StrictModel,
    ) -> StrictModel | JsonObject: ...

    async def list_resources(self, cursor: str | None) -> ResourcePage: ...

    async def read_resource(self, uri: str) -> ResourceRead: ...
