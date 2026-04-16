"""统一结果构造器。"""

from __future__ import annotations

from .models import JsonValue, ToolResult, ToolStatus


def build_result(
    *,
    status: ToolStatus,
    source: str,
    data: JsonValue,
    warnings: list[str] | None = None,
    error: str | None = None,
) -> ToolResult:
    """构造统一工具输出。"""
    return {
        "status": status,
        "source": source,
        "warnings": warnings or [],
        "error": error,
        "data": data,
    }
