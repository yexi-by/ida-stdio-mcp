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


class ToolResult(TypedDict):
    """统一工具返回结构。"""

    status: ToolStatus
    source: str
    warnings: list[str]
    error: str | None
    data: JsonValue


class FunctionRecord(TypedDict):
    """函数摘要信息。"""

    addr: str
    name: str
    size: int
    size_hex: str
    segment: str


class StringRecord(TypedDict):
    """字符串摘要信息。"""

    addr: str
    length: int
    text: str


class CallEdgeRecord(TypedDict):
    """调用边信息。"""

    caller_addr: str
    caller_name: str
    callee_addr: str
    callee_name: str
    source: str


class BinarySummary(TypedDict):
    """当前二进制摘要。"""

    input_path: str
    idb_path: str
    module: str
    binary_kind: BinaryKind
    analysis_domain: AnalysisDomain
    imagebase: str


@dataclass(slots=True, frozen=True)
class CandidateFile:
    """目录扫描阶段识别出的候选文件。"""

    path: Path
    binary_kind: BinaryKind
    score: int
    size: int
    sha256: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
