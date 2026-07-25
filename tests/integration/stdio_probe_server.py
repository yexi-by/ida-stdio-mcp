"""为真实 stdio 取消与 EOF 门禁提供可观察的官方运行时探针。"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from pydantic import Field

from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import ToolSpec
from ida_re_mcp.domain.errors import ResourceNotFoundError
from ida_re_mcp.domain.resources import ResourcePage, ResourceRead
from ida_re_mcp.protocol import McpRuntime

_STATE_ENV = "IDA_RE_MCP_PROBE_STATE"
_EXIT_ENV = "IDA_RE_MCP_PROBE_EXIT"
_INTERNAL_ERROR_ENV = "IDA_RE_MCP_PROBE_INTERNAL_ERROR"


class ProbeWaitInput(StrictModel):
    delay_ms: int = Field(ge=1, le=30_000)


class ProbeWaitOutput(StrictModel):
    completed: bool


class ProbeHandler:
    def __init__(self) -> None:
        self._state_path = Path(os.environ[_STATE_ENV])

    async def execute_tool(
        self,
        name: str,
        arguments: StrictModel,
    ) -> StrictModel | JsonObject:
        if name != "probe.wait" or not isinstance(arguments, ProbeWaitInput):
            raise RuntimeError("探针收到无效工具调用")
        self._state_path.write_text("running", encoding="utf-8")
        if os.environ.get(_EXIT_ENV) == "1":
            os._exit(7)
        if os.environ.get(_INTERNAL_ERROR_ENV) == "1":
            raise RuntimeError("sensitive-probe-internal-detail")
        try:
            await asyncio.sleep(arguments.delay_ms / 1000)
        except asyncio.CancelledError:
            self._state_path.write_text("cancelled", encoding="utf-8")
            raise
        self._state_path.write_text("completed", encoding="utf-8")
        return ProbeWaitOutput(completed=True)

    async def list_resources(self, cursor: str | None) -> ResourcePage:
        del cursor
        return ResourcePage(resources=[])

    async def read_resource(self, uri: str) -> ResourceRead:
        raise ResourceNotFoundError(uri=uri)


async def _run() -> None:
    runtime = McpRuntime(
        ProbeHandler(),
        catalog=(
            ToolSpec(
                name="probe.wait",
                title="等待探针",
                description="等待指定时间并记录取消或完成状态。",
                input_model=ProbeWaitInput,
                output_model=ProbeWaitOutput,
                read_only=True,
                destructive=False,
                idempotent=True,
                open_world=False,
            ),
        ),
    )
    await runtime.serve_stdio()


if __name__ == "__main__":
    asyncio.run(_run())
