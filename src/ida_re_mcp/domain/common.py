"""跨工具共享但不构成统一响应信封的最小领域类型。"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ida_re_mcp.domain.address import AddressRef
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.identifiers import EntityId, RevisionId, WorkspaceId


class Coverage(StrictModel):
    """说明本次查询结果是否完整。"""

    status: Literal["complete", "partial", "unknown"] = Field(
        description="结果是否完整：complete 为完整，partial 为部分结果，unknown 为无法判断。"
    )
    sampled: bool = Field(default=False, description="结果是否来自抽样，而不是完整遍历。")
    truncated: bool = Field(default=False, description="结果是否因为数量或大小限制被截断。")
    reasons: list[str] = Field(
        default_factory=list,
        max_length=32,
        description="结果不完整的机器代码；中文摘要会说明是否需要继续查询。",
    )


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
    """记录结果来自哪个分析项目、分析版本和 IDA 功能。"""

    workspace_id: WorkspaceId = Field(description="产生这份结果的分析项目编号。")
    revision: RevisionId = Field(description="产生这份结果的分析版本。")
    backend: Literal["ida", "hexrays", "ida_debugger", "ida_re"] = Field(
        description="提供结果的 IDA 功能。"
    )
    evidence: list[Evidence] = Field(default_factory=list, max_length=256)
    warnings: list[str] = Field(default_factory=list, max_length=64)


class StaticQuery(StrictModel):
    """指定要查询的分析项目和分析版本。"""

    workspace_id: WorkspaceId = Field(
        description="分析项目编号；接手已有任务时先用 workspace.list 查找。"
    )
    revision: RevisionId = Field(
        description="要查询的分析版本；通常使用 workspace.get 返回的 current_revision。"
    )
