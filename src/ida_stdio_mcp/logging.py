"""日志初始化与统一日志门面。"""

from __future__ import annotations

import json
import sys
import traceback
from datetime import datetime
from pathlib import Path
from types import TracebackType
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
_CONSOLE_HIDDEN_EVENTS = {"tool_call_traceback", "resource_read_traceback"}
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


class LoguruExceptionRecordProtocol:
    """描述 loguru 异常记录对象中本模块需要读取的字段。"""

    type: type[BaseException]
    value: BaseException
    traceback: TracebackType | None


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


def _compact_json(value: JsonValue, *, limit: int = _SUMMARY_LIMIT) -> str:
    """把 JSON 值压缩成单行文本，供终端日志展示。"""
    return _truncate_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), limit=limit)


def _escape_loguru_template(text: str) -> str:
    """转义 loguru formatter 会再次解释的花括号。"""
    return text.replace("{", "{{").replace("}", "}}")


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


def _format_exception(record: Record) -> str:
    """渲染完整异常链，确保未知异常可在文件日志中复盘。"""
    exception = record.get("exception")
    if exception is None:
        return ""
    typed_exception = cast(LoguruExceptionRecordProtocol, exception)
    return "".join(
        traceback.format_exception(
            typed_exception.type,
            typed_exception.value,
            typed_exception.traceback,
        )
    )


def _exception_traceback_text(exc: Exception) -> str:
    """把异常对象转换成完整 traceback 文本。"""
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def _console_filter(record: Record) -> bool:
    """过滤只应该进入文件日志的排障明细。"""
    extra_value = record["extra"]
    event = extra_value.get("event")
    return event not in _CONSOLE_HIDDEN_EVENTS


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
    exception_text = _format_exception(record)
    if exception_text:
        return _escape_loguru_template(" | ".join(rendered) + "\n" + exception_text)
    return _escape_loguru_template(" | ".join(rendered)) + "\n"


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
    request_id_text = _request_id_text(request_id)
    arguments_summary = _summarize_value(arguments)
    fields["request_id"] = request_id_text
    fields["tool_name"] = tool_name
    fields["details"] = {"arguments": arguments_summary}
    _event_logger(
        level="INFO",
        message=f"工具调用开始：{tool_name} request_id={request_id_text} args={_compact_json(arguments_summary)}",
        event="tool_call_start",
        category="tool",
        fields=fields,
    )


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
    _event_logger(
        level="INFO",
        message=f"工具调用完成：{tool_name} status={status} duration={duration_ms:.1f}ms",
        event="tool_call_finish",
        category="tool",
        fields=fields,
    )
    if status != "ok":
        attention_level = "ERROR" if status == "error" else "WARNING"
        _event_logger(
            level=attention_level,
            message=f"工具返回非成功状态：{tool_name} status={status} duration={duration_ms:.1f}ms error={_compact_json(error_summary)}",
            event="tool_call_attention",
            category="tool",
            fields=fields,
        )


def log_tool_call_exception(tool_name: str, request_id: JsonValue, arguments: JsonObject, exc: Exception, *, duration_ms: float) -> None:
    """记录工具调用异常。"""
    fields = _call_context_fields(arguments)
    traceback_text = _exception_traceback_text(exc)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "tool_name": tool_name,
            "status": "exception",
            "duration_ms": round(duration_ms, 3),
            "details": {"exception_type": type(exc).__name__, "message": str(exc)},
        }
    )
    _event_logger(
        level="ERROR",
        message=f"工具调用异常：{tool_name} duration={duration_ms:.1f}ms error={type(exc).__name__}: {exc}",
        event="tool_call_exception",
        category="tool",
        fields=fields,
    )
    trace_fields = dict(fields)
    trace_fields["details"] = {"traceback": "<完整 traceback 已写入当前日志行正文>"}
    logger.bind(**normalize_event_fields(event="tool_call_traceback", category="tool", fields=trace_fields)).debug(
        "工具调用完整异常栈：{}\n{}",
        tool_name,
        traceback_text,
    )


def log_resource_read_started(uri: str, request_id: JsonValue, params: JsonObject) -> None:
    """记录资源读取开始。"""
    fields = _call_context_fields(params)
    request_id_text = _request_id_text(request_id)
    params_summary = _summarize_value(params)
    fields.update(
        {
            "request_id": request_id_text,
            "resource_uri": uri,
            "details": {"params": params_summary},
        }
    )
    _event_logger(
        level="INFO",
        message=f"资源读取开始：{uri} request_id={request_id_text} params={_compact_json(params_summary)}",
        event="resource_read_start",
        category="resource",
        fields=fields,
    )


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
    status = "error" if is_error else "ok"
    _event_logger(
        level="INFO",
        message=f"资源读取完成：{uri} status={status} duration={duration_ms:.1f}ms",
        event="resource_read_finish",
        category="resource",
        fields=fields,
    )
    if is_error:
        _event_logger(
            level="ERROR",
            message=f"资源返回错误状态：{uri} duration={duration_ms:.1f}ms",
            event="resource_read_attention",
            category="resource",
            fields=fields,
        )


def log_resource_read_exception(uri: str, request_id: JsonValue, params: JsonObject, exc: Exception, *, duration_ms: float) -> None:
    """记录资源读取异常。"""
    fields = _call_context_fields(params)
    traceback_text = _exception_traceback_text(exc)
    fields.update(
        {
            "request_id": _request_id_text(request_id),
            "resource_uri": uri,
            "status": "exception",
            "duration_ms": round(duration_ms, 3),
            "details": {"exception_type": type(exc).__name__, "message": str(exc), "params": _summarize_value(params)},
        }
    )
    _event_logger(
        level="ERROR",
        message=f"资源读取异常：{uri} duration={duration_ms:.1f}ms error={type(exc).__name__}: {exc}",
        event="resource_read_exception",
        category="resource",
        fields=fields,
    )
    trace_fields = dict(fields)
    trace_fields["details"] = {"traceback": "<完整 traceback 已写入当前日志行正文>"}
    logger.bind(**normalize_event_fields(event="resource_read_traceback", category="resource", fields=trace_fields)).debug(
        "资源读取完整异常栈：{}\n{}",
        uri,
        traceback_text,
    )


def configure_logging(config: LoggingConfig) -> Path:
    """配置终端与文件日志。"""
    config.directory.mkdir(parents=True, exist_ok=True)
    log_path = config.directory / f"ida-stdio-mcp-{datetime.now().strftime('%Y%m%d')}.log"

    logger.remove()
    logger.add(
        sys.stderr,
        level=config.level,
        colorize=True,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>",
        filter=_console_filter,
    )
    logger.add(
        log_path,
        level="DEBUG",
        encoding="utf-8",
        enqueue=False,
        mode="a",
        format=_file_formatter,
    )
    logger.info("日志系统已初始化，文件日志：{}", log_path)
    return log_path
