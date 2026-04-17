"""统一结果构造器。"""

from __future__ import annotations

from typing import cast

from .models import ErrorInfo, JsonObject, JsonValue, ToolResult, ToolStatus


def normalize_json_value(value: JsonValue) -> JsonValue:
    """显式规范 JSON 值，消除 TypedDict/字典不变型带来的静态歧义。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [normalize_json_value(item) for item in value]
    return {str(key): normalize_json_value(item) for key, item in value.items()}


def normalize_json_object(value: JsonObject) -> JsonObject:
    """显式规范 JSON 对象。"""
    normalized = normalize_json_value(value)
    return cast(JsonObject, normalized)


def build_error_info(
    *,
    code: str,
    message: str,
    details: JsonObject | None = None,
    next_steps: list[str] | None = None,
) -> ErrorInfo:
    """构造统一错误对象。"""
    return cast(
        ErrorInfo,
        {
        "code": code,
        "message": message,
        "details": details or {},
        "next_steps": next_steps or [],
        },
    )


def build_result(
    *,
    status: ToolStatus,
    source: str,
    data: JsonValue,
    warnings: list[str] | None = None,
    error: str | JsonObject | None = None,
) -> ToolResult:
    """构造统一工具输出。"""
    normalized_error: JsonValue = None
    if isinstance(error, str):
        normalized_error = normalize_json_object(cast(JsonObject, build_error_info(code="tool_error", message=error)))
    elif isinstance(error, dict):
        normalized_error = normalize_json_object(error)
    return cast(
        ToolResult,
        {
        "status": status,
        "source": source,
        "warnings": warnings or [],
        "error": normalized_error,
        "data": data,
        },
    )
