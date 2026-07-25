"""跨工具共享但不构成统一响应信封的最小领域类型。"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ida_re_mcp.domain.address import AddressRef
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.identifiers import EntityId, RevisionId, WorkspaceId


class Coverage(StrictModel):
    """说明结果是否覆盖了请求范围以及任何边界。"""

    status: Literal["complete", "partial", "unknown"]
    sampled: bool = False
    truncated: bool = False
    reasons: list[str] = Field(default_factory=list, max_length=32)


class Evidence(StrictModel):
    """可供 Agent 复核的一条底层事实。"""

    kind: Literal[
        "instruction",
        "xref",
        "decompiler",
        "microcode",
        "debug_event",
        "loader",
        "type_system",
        "user_annotation",
    ]
    address: AddressRef | None = None
    entity_id: EntityId | None = None
    detail: str | None = Field(default=None, max_length=2_048)


class Provenance(StrictModel):
    """将查询结论固定到 workspace revision 与分析后端。"""

    workspace_id: WorkspaceId
    revision: RevisionId
    backend: Literal["ida", "hexrays", "ida_debugger", "ida_re"]
    evidence: list[Evidence] = Field(default_factory=list, max_length=256)
    warnings: list[str] = Field(default_factory=list, max_length=64)


class StaticQuery(StrictModel):
    """所有静态查询都显式绑定 revision。"""

    workspace_id: WorkspaceId
    revision: RevisionId
