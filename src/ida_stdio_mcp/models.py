"""项目内共享的数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]
ToolStatus = Literal["ok", "degraded", "unsupported", "error"]
BinaryKind = Literal["pe", "elf", "macho", "unknown"]
AnalysisDomain = Literal["native", "managed", "unknown"]
GateName = Literal["public", "unsafe", "debugger"]


class ToolResult(TypedDict):
    """统一工具返回结构。"""

    status: ToolStatus
    source: str
    warnings: list[str]
    error: JsonValue
    data: JsonValue


class ErrorInfo(TypedDict):
    """统一错误对象。"""

    code: str
    message: str
    details: dict[str, JsonValue]
    next_steps: list[str]


class ResourceContent(TypedDict):
    """MCP resource read 返回项。"""

    uri: str
    mimeType: str
    text: str


class BinarySummary(TypedDict):
    """当前二进制摘要。"""

    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, JsonValue]
    is_active: bool
    is_current_context: bool
    bound_contexts: int
    dirty: bool
    writeback_kind: str | None
    persistent_after_save: bool
    saved_path: str
    undo_supported: bool


@dataclass(slots=True, frozen=True)
class CandidateFile:
    """目录扫描阶段识别出的候选文件。"""

    path: Path
    binary_kind: BinaryKind
    score: int
    size: int
    sha256: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
