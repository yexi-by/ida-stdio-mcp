"""MCP 2026-07-28 的单行 JSON-RPC 分发器。"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from pydantic import BaseModel, JsonValue, ValidationError

from ida_re_mcp.constants import (
    MAX_INLINE_RESULT_BYTES,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    PROTOCOL_VERSION,
    RESOURCE_CHUNK_BYTES,
)
from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import TOOL_CATALOG, ToolSpec
from ida_re_mcp.domain.errors import ResourceRequestError, ToolExecutionError
from ida_re_mcp.domain.resources import BinaryResourceData
from ida_re_mcp.protocol.handlers import CancellationHandler, ProtocolHandler, RequestContext
from ida_re_mcp.protocol.models import (
    OFFICIAL_REQUEST_MODELS,
    BlobResourceContents,
    CallToolRequest,
    CallToolResult,
    CancelledNotification,
    ClientImplementation,
    DiscoverRequest,
    DiscoverResult,
    JsonRpcError,
    JsonRpcErrorData,
    JsonRpcSuccess,
    ListResourcesRequest,
    ListResourcesResult,
    ListToolsRequest,
    ListToolsResult,
    NotificationEnvelope,
    ReadResourceRequest,
    ReadResourceResult,
    RequestEnvelope,
    RequestId,
    RequestMeta,
    ResultMeta,
    TextResourceContents,
    ToolDefinition,
    WireResource,
)
from ida_re_mcp.protocol.stdio import MAX_STDIO_INPUT_BYTES

_LOGGER = logging.getLogger(__name__)

PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
UNSUPPORTED_PROTOCOL_VERSION: Final = -32022

_SUPPORTED_METHODS: Final = frozenset(
    {
        "server/discover",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
    }
)
_DISCOVERY_TTL_MS: Final = 60 * 60 * 1_000
_TOOL_LIST_TTL_MS: Final = 5 * 60 * 1_000


@dataclass(frozen=True, slots=True)
class _ProtocolFault(Exception):
    code: int
    message: str
    data: JsonValue | None = None


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ValueError(f"非有限 JSON 数值: {value}")


def _validation_issues(error: ValidationError) -> JsonObject:
    issues: list[JsonValue] = []
    all_issues = error.errors(include_input=False, include_url=False)
    for item in all_issues[:32]:
        location = ".".join(str(part) for part in item["loc"])
        issues.append(
            {
                "path": location,
                "type": str(item["type"]),
                "message": str(item["msg"]),
            }
        )
    return {
        "issues": issues,
        "truncated": len(all_issues) > len(issues),
    }


def _dump_model(model: BaseModel) -> JsonObject:
    value = model.model_dump(mode="json", by_alias=True, exclude_none=True)
    return cast(JsonObject, value)


def _encode(message: BaseModel) -> bytes:
    value = message.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(message, JsonRpcError) and message.id is None:
        # JSON-RPC 无法关联请求时必须显式返回 id:null, 不能被 exclude_none 丢弃。
        value["id"] = None
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _safe_request_id(value: object) -> RequestId | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, str)):
        return value
    return None


def _has_invalid_json_value(value: object) -> bool:
    """拒绝未配对 surrogate 与解析溢出产生的非有限浮点数。"""

    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            try:
                current.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                return True
        elif isinstance(current, float) and not math.isfinite(current):
            return True
        elif isinstance(current, dict):
            mapping = cast(dict[object, object], current)
            pending.extend(mapping.keys())
            pending.extend(mapping.values())
        elif isinstance(current, list):
            pending.extend(cast(list[object], current))
    return False


class CurrentProtocol:
    """只实现 MCP 2026-07-28 的无状态 stdio 请求边界。"""

    def __init__(
        self,
        handler: ProtocolHandler,
        *,
        catalog: Sequence[ToolSpec] = TOOL_CATALOG,
    ) -> None:
        self._handler = handler
        self._catalog = tuple(catalog)
        names = tuple(spec.name for spec in self._catalog)
        if names != tuple(sorted(names)):
            raise ValueError("工具目录必须按名称确定性排序")
        if len(names) != len(set(names)):
            raise ValueError("工具目录包含重复名称")
        self._catalog_by_name: Mapping[str, ToolSpec] = {spec.name: spec for spec in self._catalog}
        self._server_info = ClientImplementation(
            name=PRODUCT_NAME,
            version=PRODUCT_VERSION,
            title="IDA Reverse Engineering MCP",
            description="IDA Pro 9.3+ headless Native 与 Unity IL2CPP 逆向工程服务",
        )
        self._result_meta = ResultMeta.model_validate(
            {"io.modelcontextprotocol/serverInfo": _dump_model(self._server_info)}
        )

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self._catalog)

    async def handle_line(self, line: bytes | str) -> bytes | None:
        """处理一行 UTF-8 JSON-RPC。通知不产生响应。"""

        raw: bytes
        if isinstance(line, str):
            try:
                raw = line.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                return self._error(None, PARSE_ERROR, "Parse error")
        else:
            raw = line

        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        elif raw.endswith(b"\r"):
            return self._error(None, PARSE_ERROR, "Parse error")
        if len(raw) > MAX_STDIO_INPUT_BYTES:
            return self._error(None, PARSE_ERROR, "Parse error")
        if not raw or b"\n" in raw or b"\r" in raw:
            return self._error(None, PARSE_ERROR, "Parse error")

        try:
            decoded = raw.decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            _DuplicateKey,
            RecursionError,
            ValueError,
        ):
            return self._error(None, PARSE_ERROR, "Parse error")
        if _has_invalid_json_value(value):
            return self._error(None, PARSE_ERROR, "Parse error")

        if not isinstance(value, dict):
            return self._error(None, INVALID_REQUEST, "Invalid Request")
        json_object = cast(JsonObject, value)

        if "id" not in json_object:
            try:
                await self._handle_notification(json_object)
            except Exception as error:
                # JSON-RPC notification 永远没有响应, 取消回调失败也不能伪造 id=null 错误。
                _LOGGER.error("取消通知处理失败: %s", type(error).__name__)
            return None

        request_id = _safe_request_id(json_object.get("id"))
        try:
            envelope = RequestEnvelope.model_validate(json_object)
        except ValidationError:
            return self._error(request_id, INVALID_REQUEST, "Invalid Request")

        try:
            self._validate_current_meta(envelope.params)
            result = await self._dispatch(json_object, envelope)
        except _ProtocolFault as error:
            return self._error(request_id, error.code, error.message, error.data)
        except Exception:
            return self._error(request_id, INTERNAL_ERROR, "Internal error")
        try:
            response = JsonRpcSuccess.model_validate(
                {
                    "jsonrpc": "2.0",
                    "id": envelope.id,
                    "result": result,
                }
            )
            return _encode(response)
        except (TypeError, UnicodeEncodeError, ValueError):
            return self._error(request_id, INTERNAL_ERROR, "Internal error")

    async def _handle_notification(self, value: JsonObject) -> None:
        try:
            envelope = NotificationEnvelope.model_validate(value)
        except ValidationError:
            return
        if envelope.method != "notifications/cancelled":
            return
        try:
            notification = CancelledNotification.model_validate(value)
        except ValidationError:
            return
        if isinstance(self._handler, CancellationHandler):
            await self._handler.cancel_request(
                notification.params.request_id,
                notification.params.reason,
            )

    def _validate_current_meta(self, params: JsonValue | None) -> None:
        if not isinstance(params, dict):
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params")
        meta = params.get("_meta")
        if not isinstance(meta, dict):
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params")
        requested = meta.get("io.modelcontextprotocol/protocolVersion")
        if not isinstance(requested, str):
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params")
        if requested != PROTOCOL_VERSION:
            raise _ProtocolFault(
                UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
                {"supported": [PROTOCOL_VERSION], "requested": requested},
            )
        try:
            RequestMeta.model_validate(meta)
        except ValidationError as error:
            raise _ProtocolFault(
                INVALID_PARAMS,
                "Invalid params",
                _validation_issues(error),
            ) from error

    async def _dispatch(self, value: JsonObject, envelope: RequestEnvelope) -> JsonObject:
        if envelope.method not in _SUPPORTED_METHODS:
            raise _ProtocolFault(METHOD_NOT_FOUND, "Method not found")

        if envelope.method == "server/discover":
            request = self._validate_request(DiscoverRequest, value)
            return self._discover(request)
        if envelope.method == "tools/list":
            request = self._validate_request(ListToolsRequest, value)
            return self._list_tools(request)
        if envelope.method == "tools/call":
            request = self._validate_request(CallToolRequest, value)
            return await self._call_tool(request)
        if envelope.method == "resources/list":
            request = self._validate_request(ListResourcesRequest, value)
            return await self._list_resources(request)
        request = self._validate_request(ReadResourceRequest, value)
        return await self._read_resource(request)

    @staticmethod
    def _validate_request(
        model_type: type[StrictModel],
        value: JsonObject,
    ) -> StrictModel:
        try:
            request = model_type.model_validate(value)
        except ValidationError as error:
            raise _ProtocolFault(
                INVALID_PARAMS,
                "Invalid params",
                _validation_issues(error),
            ) from error
        CurrentProtocol._validate_official_request(value)
        return request

    @staticmethod
    def _validate_official_request(value: JsonObject) -> None:
        """以官方 current 生成类型复核请求。

        beta 类型仍把 RC 已改为可选的 clientInfo 标成必填。复核副本只为绕过这一个
        已知差异补占位 Implementation, 业务上下文继续使用未经改写的严格模型。
        """

        method = value.get("method")
        if not isinstance(method, str):
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params")
        official_model = OFFICIAL_REQUEST_MODELS.get(method)
        if official_model is None:
            raise _ProtocolFault(METHOD_NOT_FOUND, "Method not found")

        official_value = value
        params = value.get("params")
        if isinstance(params, dict):
            meta = params.get("_meta")
            if isinstance(meta, dict) and "io.modelcontextprotocol/clientInfo" not in meta:
                official_meta: JsonObject = {
                    **meta,
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "unspecified-client",
                        "version": "unspecified",
                    },
                }
                official_params: JsonObject = {**params, "_meta": official_meta}
                official_value = {**value, "params": official_params}
        try:
            official_model.model_validate(official_value)
        except ValidationError as error:
            raise _ProtocolFault(
                INVALID_PARAMS,
                "Invalid params",
                _validation_issues(error),
            ) from error

    @staticmethod
    def _context(
        request: DiscoverRequest
        | ListToolsRequest
        | CallToolRequest
        | ListResourcesRequest
        | ReadResourceRequest,
    ) -> RequestContext:
        return RequestContext(
            protocol_version=request.params.meta.protocol_version,
            client_info=request.params.meta.client_info,
            client_capabilities=request.params.meta.client_capabilities,
            request_id=request.id,
        )

    def _discover(self, request: StrictModel) -> JsonObject:
        typed = cast(DiscoverRequest, request)
        result = DiscoverResult.model_validate(
            {
                "_meta": _dump_model(self._result_meta),
                "resultType": "complete",
                "supportedVersions": [PROTOCOL_VERSION],
                "capabilities": {"tools": {}, "resources": {}},
                "instructions": (
                    "所有静态查询必须显式传递 workspace_id 与 revision。"
                    "写入先 change.prepare 然后以 expected_revision 调用 change.apply。"
                ),
                "ttlMs": _DISCOVERY_TTL_MS,
                "cacheScope": "public",
            }
        )
        self._context(typed)
        return _dump_model(result)

    def _list_tools(self, request: StrictModel) -> JsonObject:
        typed = cast(ListToolsRequest, request)
        if typed.params.cursor is not None:
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params", {"field": "cursor"})
        definitions = [
            ToolDefinition.model_validate(spec.as_wire_definition()) for spec in self._catalog
        ]
        result = ListToolsResult.model_validate(
            {
                "_meta": _dump_model(self._result_meta),
                "resultType": "complete",
                "tools": [
                    item.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for item in definitions
                ],
                "ttlMs": _TOOL_LIST_TTL_MS,
                "cacheScope": "public",
            }
        )
        return _dump_model(result)

    async def _call_tool(self, request: StrictModel) -> JsonObject:
        typed = cast(CallToolRequest, request)
        if typed.params.input_responses is not None or typed.params.request_state is not None:
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params")
        spec = self._catalog_by_name.get(typed.params.name)
        if spec is None:
            raise _ProtocolFault(
                INVALID_PARAMS,
                f"Unknown tool: {typed.params.name}",
            )
        try:
            arguments = spec.input_model.model_validate(typed.params.arguments or {})
        except ValidationError as error:
            raise _ProtocolFault(
                INVALID_PARAMS,
                "Invalid tool arguments",
                _validation_issues(error),
            ) from error

        try:
            raw_result = await self._handler.call_tool(
                spec.name,
                arguments,
                self._context(typed),
            )
        except ToolExecutionError as error:
            payload: JsonObject = {
                "code": error.code.value,
                "message": error.message[:2_048],
                "details": error.details,
            }
            serialized_error = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
            if len(serialized_error.encode("utf-8")) > MAX_INLINE_RESULT_BYTES:
                payload["details"] = {"truncated": True}
                serialized_error = json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            result = CallToolResult.model_validate(
                {
                    "_meta": _dump_model(self._result_meta),
                    "resultType": "complete",
                    "content": [{"type": "text", "text": serialized_error}],
                    "isError": True,
                }
            )
            return _dump_model(result)

        validated = self._validate_tool_output(spec, raw_result)
        structured = validated.model_dump(mode="json")
        serialized = json.dumps(
            structured,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(serialized.encode("utf-8")) > MAX_INLINE_RESULT_BYTES:
            raise RuntimeError("工具结果超过 inline 上限。handler 必须返回 artifact")
        result = CallToolResult.model_validate(
            {
                "_meta": _dump_model(self._result_meta),
                "resultType": "complete",
                "content": [{"type": "text", "text": serialized}],
                "structuredContent": cast(JsonValue, structured),
                "isError": False,
            }
        )
        return _dump_model(result)

    @staticmethod
    def _validate_tool_output(
        spec: ToolSpec,
        value: StrictModel | JsonObject,
    ) -> StrictModel:
        candidate: object
        if isinstance(value, BaseModel):
            candidate = value.model_dump(mode="python")
        else:
            candidate = value
        try:
            return spec.output_model.model_validate(candidate)
        except ValidationError as error:
            raise RuntimeError(f"{spec.name} handler 返回值不符合 output schema") from error

    async def _list_resources(self, request: StrictModel) -> JsonObject:
        typed = cast(ListResourcesRequest, request)
        page = await self._handler.list_resources(
            typed.params.cursor,
            self._context(typed),
        )
        resources = [
            WireResource.model_validate(
                {
                    "uri": item.uri,
                    "name": item.name,
                    "title": item.title,
                    "description": item.description,
                    "mimeType": item.mime_type,
                    "size": item.size_bytes,
                }
            )
            for item in page.resources
        ]
        result = ListResourcesResult.model_validate(
            {
                "_meta": _dump_model(self._result_meta),
                "resultType": "complete",
                "resources": [
                    item.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for item in resources
                ],
                "nextCursor": page.next_cursor,
                "ttlMs": page.ttl_ms,
                "cacheScope": page.cache_scope,
            }
        )
        return _dump_model(result)

    async def _read_resource(self, request: StrictModel) -> JsonObject:
        typed = cast(ReadResourceRequest, request)
        if typed.params.input_responses is not None or typed.params.request_state is not None:
            raise _ProtocolFault(INVALID_PARAMS, "Invalid params")
        try:
            read = await self._handler.read_resource(
                typed.params.uri,
                self._context(typed),
            )
        except ResourceRequestError as error:
            data: JsonObject | None = {"uri": error.uri} if error.uri is not None else None
            raise _ProtocolFault(INVALID_PARAMS, error.message, data) from error

        contents: list[TextResourceContents | BlobResourceContents] = []
        for item in read.contents:
            if isinstance(item, BinaryResourceData):
                try:
                    decoded_size = len(base64.b64decode(item.blob, validate=True))
                except (ValueError, binascii.Error) as error:
                    raise RuntimeError("二进制 resource chunk 不是规范 base64") from error
                if decoded_size > RESOURCE_CHUNK_BYTES:
                    raise RuntimeError("二进制 resource chunk 超出上限")
                contents.append(
                    BlobResourceContents.model_validate(
                        {
                            "uri": item.uri,
                            "mimeType": item.mime_type,
                            "blob": item.blob,
                        }
                    )
                )
            else:
                if len(item.text.encode("utf-8")) > RESOURCE_CHUNK_BYTES:
                    raise RuntimeError("文本 resource chunk 超出上限")
                contents.append(
                    TextResourceContents.model_validate(
                        {
                            "uri": item.uri,
                            "mimeType": item.mime_type,
                            "text": item.text,
                        }
                    )
                )
        result = ReadResourceResult.model_validate(
            {
                "_meta": _dump_model(self._result_meta),
                "resultType": "complete",
                "contents": [
                    item.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for item in contents
                ],
                "ttlMs": read.ttl_ms,
                "cacheScope": read.cache_scope,
            }
        )
        return _dump_model(result)

    @staticmethod
    def _error(
        request_id: RequestId | None,
        code: int,
        message: str,
        data: JsonValue | None = None,
    ) -> bytes:
        try:
            return _encode(
                JsonRpcError.model_validate(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": JsonRpcErrorData(
                            code=code,
                            message=message,
                            data=data,
                        ).model_dump(mode="json", by_alias=True, exclude_none=True),
                    }
                )
            )
        except (TypeError, UnicodeEncodeError, ValueError):
            return _encode(
                JsonRpcError.model_validate(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": INTERNAL_ERROR,
                            "message": "Internal error",
                        },
                    }
                )
            )
