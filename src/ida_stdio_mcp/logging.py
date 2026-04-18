"""日志初始化与统一日志门面。"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias, cast

from loguru import logger
from rich.console import Console

from .config import LoggingConfig
from .models import JsonObject, JsonValue, ToolResult

if TYPE_CHECKING:
    from loguru import Record
else:
    # loguru 的 Record 只存在于类型存根里，运行时不能直接导入。
    Record: TypeAlias = dict[str, object]

CONSOLE = Console(stderr=True, soft_wrap=True)
_SUMMARY_LIMIT = 600
_DEFAULT_EXTRA: JsonObject = {
    "event": "",
    "category": "",
    "request_id": "",
    "tool_name": "",
    "resource_uri": "",
    "status": "",
    "duration_ms": "",
    "context_id": "",
    "session_id": "",
    "details": "",
}


logger.configure(extra=_DEFAULT_EXTRA)


def _truncate_text(text: str, *, limit: int = _SUMMARY_LIMIT) -> str:
    """截断过长日志文本，避免文件日志被单次调用刷爆。"""
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}...(已省略 {omitted} 个字符)"


def _summarize_value(value: JsonValue, *, depth: int = 0) -> JsonValue:
    """把 JSON 值压缩成适合日志落盘的摘要。"""
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return _truncate_text(value, limit=240)
    if isinstance(value, list):
        if depth >= 2:
            return f"<list len={len(value)}>"
        head = [_summarize_value(item, depth=depth + 1) for item in value[:8]]
        if len(value) > 8:
            head.append(f"...(+{len(value) - 8})")
        return head
    if depth >= 2:
        return f"<object keys={len(value)}>"
    summary: JsonObject = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= 12:
            summary["_truncated"] = f"...(+{len(value) - 12} keys)"
            break
        summary[str(key)] = _summarize_value(item, depth=depth + 1)
    return summary


def _render_detail_value(value: JsonValue) -> str:
    """把结构化日志字段渲染成可读字符串。"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return _truncate_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def _file_formatter(record: Record) -> str:
    """渲染文件日志。"""
    time_text = record["time"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    level_name = record["level"].name
    message_text = record["message"]

    rendered = [f"{time_text} | {str(level_name): <8} | {message_text}"]
    extra_value = record["extra"]
    ordered_keys = (
        "event",
        "category",
        "request_id",
        "tool_name",
        "resource_uri",
        "status",
        "duration_ms",
        "context_id",
        "session_id",
        "details",
    )
    for key in ordered_keys:
        if key not in extra_value:
            continue
        raw_field = extra_value[key]
        if raw_field is None:
            continue
        field = _render_detail_value(cast(JsonValue, raw_field))
        if field:
            rendered.append(f"{key}={field}")
    return " | ".join(rendered) + "\n"


def _event_logger(
    *,
    level: str,
    message: str,
    event: str,
    category: str,
    fields: JsonObject | None = None,
) -> None:
    """统一事件日志入口。"""
    extra = normalize_event_fields(event=event, category=category, fields=fields)
    logger.bind(**extra).log(level.upper(), message)


def normalize_event_fields(*, event: str, category: str, fields: JsonObject | None = None) -> JsonObject:
    """规范事件字段，避免不同模块各写一套口径。"""
    normalized = dict(_DEFAULT_EXTRA)
    normalized["event"] = event
    normalized["category"] = category
    if fields is None:
        return normalized
    for key, value in fields.items():
        normalized[key] = _summarize_value(value)
    return normalized


def _request_id_text(request_id: JsonValue) -> str:
    """把请求 ID 压缩成日志友好文本。"""
    if request_id is None:
        return ""
    if isinstance(request_id, (str, int, float, bool)):
        return str(request_id)
    return _truncate_text(json.dumps(_summarize_value(request_id), ensure_ascii=False, separators=(",", ":")))


def _call_context_fields(arguments: JsonObject) -> JsonObject:
    """抽取调用上下文字段。"""
    fields: JsonObject = {}
    session_id = arguments.get("session_id")
    if isinstance(session_id, str) and session_id:
        fields["session_id"] = session_id
    context_id = arguments.get("context_id")
    if isinstance(context_id, str) and context_id:
        fields["context_id"] = context_id
    return fields


def log_tool_call_started(tool_name: str, request_id: JsonValue, arguments: JsonObject) -> None:
    """记录工具调用开始。"""
    fields = _call_context_fields(arguments)
    fields["request_id"] = _request_id_text(request_id)
    fields["tool_name"] = tool_name
    fields["details"] = {"arguments": _summarize_value(arguments)}
    _event_logger(level="DEBUG", message=f"开始调用工具：{tool_name}", event="tool_call_start", category="tool", fields=fields)


def log_tool_call_finished(tool_name: str, request_id: JsonValue, arguments: JsonObject, result: ToolResult, *, duration_ms: float) -> None:
    """记录工具调用结束。"""
    status = str(result["status"])
    error_summary: JsonValue = None
    if isinstance(result["error"], dict):
        error_summary = {"code": result["error"].get("code"), "message": result["error"].get("message")}
    details: JsonObject = {
        "warnings": _summarize_value(cast(JsonValue, list(result["warnings"]))),
        "error": error_summary,
        "data": _summarize_value(result["data"]),
    }
    fields = _call_context_fields(arguments)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "tool_name": tool_name,
            "status": status,
            "duration_ms": round(duration_ms, 3),
            "details": details,
        }
    )
    _event_logger(level="DEBUG", message=f"工具调用完成：{tool_name}", event="tool_call_finish", category="tool", fields=fields)
    if status != "ok":
        _event_logger(level="WARNING", message=f"工具返回非成功状态：{tool_name} -> {status}", event="tool_call_attention", category="tool", fields=fields)


def log_tool_call_exception(tool_name: str, request_id: JsonValue, arguments: JsonObject, exc: Exception, *, duration_ms: float) -> None:
    """记录工具调用异常。"""
    fields = _call_context_fields(arguments)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "tool_name": tool_name,
            "status": "exception",
            "duration_ms": round(duration_ms, 3),
            "details": {"message": str(exc)},
        }
    )
    logger.bind(**normalize_event_fields(event="tool_call_exception", category="tool", fields=fields)).exception("工具调用异常：{}", tool_name)


def log_resource_read_started(uri: str, request_id: JsonValue, params: JsonObject) -> None:
    """记录资源读取开始。"""
    fields = _call_context_fields(params)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "resource_uri": uri,
            "details": {"params": _summarize_value(params)},
        }
    )
    _event_logger(level="DEBUG", message=f"开始读取资源：{uri}", event="resource_read_start", category="resource", fields=fields)


def log_resource_read_finished(
    uri: str,
    request_id: JsonValue,
    params: JsonObject,
    *,
    duration_ms: float,
    is_error: bool,
    payload_summary: JsonValue,
) -> None:
    """记录资源读取结束。"""
    fields = _call_context_fields(params)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "resource_uri": uri,
            "status": "error" if is_error else "ok",
            "duration_ms": round(duration_ms, 3),
            "details": {"payload": _summarize_value(payload_summary)},
        }
    )
    _event_logger(level="DEBUG", message=f"资源读取完成：{uri}", event="resource_read_finish", category="resource", fields=fields)
    if is_error:
        _event_logger(level="WARNING", message=f"资源返回错误状态：{uri}", event="resource_read_attention", category="resource", fields=fields)


def log_resource_read_exception(uri: str, request_id: JsonValue, params: JsonObject, exc: Exception, *, duration_ms: float) -> None:
    """记录资源读取异常。"""
    fields = _call_context_fields(params)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "resource_uri": uri,
            "status": "exception",
            "duration_ms": round(duration_ms, 3),
            "details": {"message": str(exc), "params": _summarize_value(params)},
        }
    )
    logger.bind(**normalize_event_fields(event="resource_read_exception", category="resource", fields=fields)).exception("资源读取异常：{}", uri)


def configure_logging(config: LoggingConfig) -> Path:
    """配置终端与文件日志。"""
    config.directory.mkdir(parents=True, exist_ok=True)
    log_path = config.directory / f"ida-stdio-mcp-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

    logger.remove()
    logger.add(
        sys.stderr,
        level=config.level,
        colorize=True,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
    )
    logger.add(
        log_path,
        level="DEBUG",
        encoding="utf-8",
        enqueue=False,
        format=_file_formatter,
    )
    logger.info("日志系统已初始化，文件日志：{}", log_path)
    return log_path
