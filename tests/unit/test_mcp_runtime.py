from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import cast

import mcp.types as mcp_types
import pytest
from mcp import McpError
from mcp.server.lowlevel import Server
from pydantic import AnyUrl, Field

from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import ToolSpec, build_tool_catalog
from ida_re_mcp.domain.errors import (
    BusinessErrorCode,
    ResourceNotFoundError,
    ResourceRequestError,
    ToolExecutionError,
)
from ida_re_mcp.domain.resources import (
    BinaryResourceData,
    ResourceDescriptor,
    ResourcePage,
    ResourceRead,
    TextResourceData,
)
from ida_re_mcp.protocol.messages import (
    SUPPORTED_SUCCESS_SUMMARIES,
    error_summary,
    safe_error_message,
    sanitize_error_details,
    success_summary,
)
from ida_re_mcp.protocol.server import McpRuntime

_RESOURCE_URI = (
    "ida-re://workspaces/workspace_abcdef/revisions/revision_abcdef/artifacts/artifact_abcdef"
)
_SERVER_ATTRIBUTE = "_server"


class _EchoInput(StrictModel):
    value: str = Field(min_length=1, max_length=64)


class _EchoOutput(StrictModel):
    value: str
    workspace_id: str = "workspace_abcdef"
    address: str = "0x401000"
    sha256: str = "a" * 64
    details: list[str] = Field(default_factory=lambda: ["完整数据不能丢失"])


class _FakeHandler:
    def __init__(self) -> None:
        self.executions: list[tuple[str, StrictModel]] = []
        self.resource_cursor: str | None = None
        self.fail_resource_list = False
        self.fail_resource_read = False
        self.fail_resource_read_invalid = False
        self.fail_resource_read_internal = False

    async def execute_tool(
        self,
        name: str,
        arguments: StrictModel,
    ) -> StrictModel | JsonObject:
        self.executions.append((name, arguments))
        if name == "business.echo":
            raise ToolExecutionError(
                BusinessErrorCode.REVISION_CONFLICT,
                "revision 已改变",
                details={"current_revision": "revision_current"},
            )
        if name == "not_found.echo":
            raise ToolExecutionError(
                BusinessErrorCode.REVISION_NOT_FOUND,
                "revision 不存在或已被 GC 回收",
            )
        if name == "internal.echo":
            raise RuntimeError("sensitive-internal-detail")
        if name == "unsafe.echo":
            raise ToolExecutionError(
                BusinessErrorCode.EXECUTION_FAILED,
                r"worker failed at D:\private\sessions\sample.i64 with RuntimeError",
                details={
                    "stdout_log": r"D:\private\logs\stdout.log",
                    "exception_type": "RuntimeError",
                    "current_revision": "revision_current",
                },
            )
        typed = cast(_EchoInput, arguments)
        return _EchoOutput(value=typed.value)

    async def list_resources(self, cursor: str | None) -> ResourcePage:
        self.resource_cursor = cursor
        if self.fail_resource_list:
            raise ResourceRequestError("resource cursor 无效", uri=_RESOURCE_URI)
        return ResourcePage(
            resources=[
                ResourceDescriptor(
                    uri=_RESOURCE_URI,
                    name="analysis.txt",
                    title="分析结果",
                    description="不可变测试 artifact",
                    mime_type="text/plain",
                    size_bytes=6,
                )
            ],
            next_cursor="cursor_next",
        )

    async def read_resource(self, uri: str) -> ResourceRead:
        if self.fail_resource_read:
            raise ResourceNotFoundError(uri=uri)
        if self.fail_resource_read_invalid:
            raise ResourceRequestError("resource URI 无效", uri=uri)
        if self.fail_resource_read_internal:
            raise RuntimeError("sensitive-resource-integrity-detail")
        return ResourceRead(
            contents=[
                TextResourceData(
                    kind="text",
                    uri=_RESOURCE_URI,
                    mime_type="text/plain",
                    text="文本",
                ),
                BinaryResourceData(
                    kind="blob",
                    uri=_RESOURCE_URI,
                    mime_type="application/octet-stream",
                    blob=base64.b64encode(b"\x00\x01\xff").decode("ascii"),
                ),
            ]
        )


def _spec(name: str) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=f"{name} title",
        description=f"{name} description",
        input_model=_EchoInput,
        output_model=_EchoOutput,
        read_only=True,
        destructive=False,
        idempotent=True,
        open_world=False,
    )


def _runtime(
    handler: _FakeHandler | None = None,
    *,
    diagnostic_log_root: Path | None = None,
) -> tuple[McpRuntime, _FakeHandler]:
    selected = handler or _FakeHandler()
    runtime = McpRuntime(
        selected,
        catalog=tuple(
            _spec(name)
            for name in (
                "z.echo",
                "internal.echo",
                "business.echo",
                "not_found.echo",
                "unsafe.echo",
                "a.echo",
            )
        ),
        diagnostic_log_root=diagnostic_log_root,
    )
    return runtime, selected


async def _dispatch(runtime: McpRuntime, request: object) -> mcp_types.ServerResult:
    server = cast(Server[object, object], getattr(runtime, _SERVER_ATTRIBUTE))
    handler = server.request_handlers[type(request)]
    return await handler(request)


async def _call_tool(
    runtime: McpRuntime,
    name: str,
    arguments: dict[str, object],
) -> mcp_types.CallToolResult:
    response = await _dispatch(
        runtime,
        mcp_types.CallToolRequest(
            params=mcp_types.CallToolRequestParams(
                name=name,
                arguments=arguments,
            )
        ),
    )
    assert isinstance(response.root, mcp_types.CallToolResult)
    return response.root


def _error_payload(result: mcp_types.CallToolResult) -> JsonObject:
    assert result.isError is True
    assert result.structuredContent is None
    assert len(result.content) == 2
    summary = result.content[0]
    machine = result.content[1]
    assert isinstance(summary, mcp_types.TextContent)
    assert isinstance(machine, mcp_types.TextContent)
    payload = cast(JsonObject, json.loads(machine.text))
    assert "操作失败：" in summary.text
    assert str(payload["code"]) in summary.text
    assert "下一步：" in summary.text
    return payload


def test_official_list_tools_is_sorted_and_uses_closed_strict_schemas() -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime()
        response = await _dispatch(runtime, mcp_types.ListToolsRequest())
        assert isinstance(response.root, mcp_types.ListToolsResult)
        tools = response.root.tools
        assert [tool.name for tool in tools] == [
            "a.echo",
            "business.echo",
            "internal.echo",
            "not_found.echo",
            "unsafe.echo",
            "z.echo",
        ]
        for tool in tools:
            for schema in (tool.inputSchema, tool.outputSchema):
                assert schema is not None
                assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
                assert schema["type"] == "object"
                assert schema["additionalProperties"] is False
            assert tool.annotations is not None
            assert tool.annotations.readOnlyHint is True
            assert tool.annotations.destructiveHint is False

    asyncio.run(scenario())


def test_official_call_tool_returns_structured_and_text_content() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        result = await _call_tool(runtime, "a.echo", {"value": "hello"})

        assert result.isError is False
        assert result.structuredContent == {
            "value": "hello",
            "workspace_id": "workspace_abcdef",
            "address": "0x401000",
            "sha256": "a" * 64,
            "details": ["完整数据不能丢失"],
        }
        assert len(result.content) == 1
        content = result.content[0]
        assert isinstance(content, mcp_types.TextContent)
        assert content.text == (
            "工具 a.echo 已执行成功。\n"
            "字段、地址、ID、哈希值和其他完整数据请读取 structuredContent；"
            "本段文字只说明结果和下一步。"
        )
        assert "hello" not in content.text
        with pytest.raises(json.JSONDecodeError):
            json.loads(content.text)
        assert len(handler.executions) == 1
        assert handler.executions[0][0] == "a.echo"
        assert handler.executions[0][1] == _EchoInput(value="hello")

    asyncio.run(scenario())


def test_official_call_tool_reports_invalid_arguments_without_invoking_handler() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        result = await _call_tool(
            runtime,
            "a.echo",
            {"value": 7, "unexpected": True},
        )

        payload = _error_payload(result)
        assert payload["code"] == "invalid_arguments"
        assert payload["message"] == (
            "工具参数不正确。请按照 tools/list 返回的 inputSchema 修改后重试。"
        )
        assert handler.executions == []
        details = cast(JsonObject, payload["details"])
        issues = details["issues"]
        assert isinstance(issues, list)
        messages: list[str] = []
        paths: list[list[str]] = []
        for issue in issues:
            assert isinstance(issue, dict)
            message = issue.get("message")
            path = issue.get("path")
            assert isinstance(message, str)
            assert isinstance(path, list)
            assert all(isinstance(part, str) for part in path)
            messages.append(message)
            paths.append(cast(list[str], path))
        assert set(messages) == {"参数类型不正确", "参数未在工具定义中"}
        assert paths == [["value"], ["unexpected"]]
        assert "Input should be" not in json.dumps(details, ensure_ascii=False)

    asyncio.run(scenario())


def test_official_call_tool_reports_unknown_tool() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        with pytest.raises(McpError) as error:
            await _call_tool(runtime, "missing.tool", {"value": "ignored"})
        assert error.value.error.code == mcp_types.INVALID_PARAMS
        assert error.value.error.message == (
            "找不到工具 `missing.tool`。请先读取 tools/list，并使用其中列出的工具名称。"
        )
        assert handler.executions == []

    asyncio.run(scenario())


def test_official_call_tool_preserves_business_error() -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime()
        payload = _error_payload(await _call_tool(runtime, "business.echo", {"value": "input"}))

        assert payload == {
            "code": "revision_conflict",
            "message": "revision 已改变",
            "details": {"current_revision": "revision_current"},
        }

    asyncio.run(scenario())


def test_official_call_tool_preserves_revision_not_found() -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime()
        payload = _error_payload(await _call_tool(runtime, "not_found.echo", {"value": "input"}))

        assert payload == {
            "code": "revision_not_found",
            "message": "revision 不存在或已被 GC 回收",
            "details": {},
        }

    asyncio.run(scenario())


def test_official_call_tool_sanitizes_internal_exception(tmp_path: Path) -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime(diagnostic_log_root=tmp_path)
        with pytest.raises(McpError) as error:
            await _call_tool(runtime, "internal.echo", {"value": "input"})
        assert error.value.error.code == mcp_types.INTERNAL_ERROR
        assert error.value.error.message == (
            "工具执行失败，服务内部出现错误。请重试；"
            "如果仍然失败，请运行 doctor 检查配置并查看日志。"
        )
        assert error.value.error.data is None
        serialized = error.value.error.model_dump_json()
        assert "sensitive-internal-detail" not in serialized
        assert "RuntimeError" not in serialized
        log = (tmp_path / "service-errors.log").read_text(encoding="utf-8")
        assert "MCP 工具 internal.echo 执行失败" in log
        assert "sensitive-internal-detail" in log

    asyncio.run(scenario())


def test_official_call_tool_hides_internal_details_in_business_error(tmp_path: Path) -> None:
    async def scenario() -> None:
        runtime, _handler = _runtime(diagnostic_log_root=tmp_path)
        payload = _error_payload(await _call_tool(runtime, "unsafe.echo", {"value": "input"}))

        assert payload == {
            "code": "execution_failed",
            "message": (
                "工具执行失败。内部诊断信息已经写入日志。"
                "请运行 doctor 检查配置，并查看服务说明中列出的日志目录。"
            ),
            "details": {
                "stdout_log": "已隐藏内部诊断信息",
                "exception_type": "已隐藏内部诊断信息",
                "current_revision": "revision_current",
            },
        }
        serialized = json.dumps(payload, ensure_ascii=False)
        assert r"D:\private" not in serialized
        assert "RuntimeError" not in serialized
        log = (tmp_path / "service-errors.log").read_text(encoding="utf-8")
        assert r"D:\private\sessions\sample.i64" in log
        assert "stdout_log" in log
        assert "stdout.log" in log

    asyncio.run(scenario())


def test_official_resource_handlers_map_descriptor_text_and_blob() -> None:
    async def scenario() -> None:
        runtime, handler = _runtime()
        listed_response = await _dispatch(
            runtime,
            mcp_types.ListResourcesRequest(
                params=mcp_types.PaginatedRequestParams(cursor="cursor_input")
            ),
        )
        assert isinstance(listed_response.root, mcp_types.ListResourcesResult)
        listed = listed_response.root
        assert handler.resource_cursor == "cursor_input"
        assert listed.nextCursor == "cursor_next"
        assert len(listed.resources) == 1
        descriptor = listed.resources[0]
        assert str(descriptor.uri) == _RESOURCE_URI
        assert descriptor.name == "analysis.txt"
        assert descriptor.mimeType == "text/plain"
        assert descriptor.size == 6

        read_response = await _dispatch(
            runtime,
            mcp_types.ReadResourceRequest(
                params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
            ),
        )
        assert isinstance(read_response.root, mcp_types.ReadResourceResult)
        contents = read_response.root.contents
        assert len(contents) == 2
        text = contents[0]
        blob = contents[1]
        assert isinstance(text, mcp_types.TextResourceContents)
        assert text.text == "文本"
        assert text.mimeType == "text/plain"
        assert isinstance(blob, mcp_types.BlobResourceContents)
        assert blob.blob == base64.b64encode(b"\x00\x01\xff").decode("ascii")
        assert blob.mimeType == "application/octet-stream"

    asyncio.run(scenario())


def test_official_resource_handlers_map_resource_errors() -> None:
    async def scenario() -> None:
        handler = _FakeHandler()
        runtime, _handler = _runtime(handler)

        handler.fail_resource_list = True
        with pytest.raises(McpError) as list_error:
            await _dispatch(runtime, mcp_types.ListResourcesRequest())
        assert list_error.value.error.code == mcp_types.INVALID_PARAMS
        assert list_error.value.error.message == (
            "无法列出工具生成的文件：分页位置无效或已经过期。请不传 cursor，从第一页重新读取。"
        )
        assert list_error.value.error.data == {"uri": _RESOURCE_URI}

        handler.fail_resource_list = False
        handler.fail_resource_read = True
        with pytest.raises(McpError) as read_error:
            await _dispatch(
                runtime,
                mcp_types.ReadResourceRequest(
                    params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
                ),
            )
        assert read_error.value.error.code == -32002
        assert read_error.value.error.message == (
            "找不到这个工具生成的文件。请重新调用生成文件的工具，并使用它返回的完整文件地址。"
        )
        assert read_error.value.error.data == {"uri": _RESOURCE_URI}

        handler.fail_resource_read = False
        handler.fail_resource_read_invalid = True
        with pytest.raises(McpError) as invalid_error:
            await _dispatch(
                runtime,
                mcp_types.ReadResourceRequest(
                    params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
                ),
            )
        assert invalid_error.value.error.code == mcp_types.INVALID_PARAMS
        assert invalid_error.value.error.message == (
            "无法读取工具生成的文件：文件地址格式不正确。请使用生成文件的工具返回的完整文件地址。"
        )
        assert invalid_error.value.error.data == {"uri": _RESOURCE_URI}

    asyncio.run(scenario())


def test_official_resource_handler_sanitizes_internal_failure() -> None:
    async def scenario() -> None:
        handler = _FakeHandler()
        handler.fail_resource_read_internal = True
        runtime, _handler = _runtime(handler)

        with pytest.raises(McpError) as error:
            await _dispatch(
                runtime,
                mcp_types.ReadResourceRequest(
                    params=mcp_types.ReadResourceRequestParams(uri=AnyUrl(_RESOURCE_URI))
                ),
            )
        assert error.value.error.code == mcp_types.INTERNAL_ERROR
        assert error.value.error.message == (
            "无法读取工具生成的文件，服务内部出现错误。请重试；"
            "如果仍然失败，请运行 doctor 检查配置并查看日志。"
        )
        assert "sensitive-resource-integrity-detail" not in error.value.error.model_dump_json()

    asyncio.run(scenario())


def test_runtime_instructions_explain_handoff_and_storage_paths() -> None:
    selected = _FakeHandler()
    runtime = McpRuntime(
        selected,
        catalog=(_spec("a.echo"),),
        data_root=Path(r"D:\work\ida-stdio-mcp\data"),
        log_root=Path(r"D:\work\ida-stdio-mcp\data\logs"),
    )
    server = cast(Server[object, object], getattr(runtime, _SERVER_ATTRIBUTE))
    instructions = server.instructions
    assert instructions is not None
    assert "先调用 workspace.list" in instructions
    assert "再调用 workspace.get" in instructions
    assert "不要重复导入或重新分析" in instructions
    assert "workspace.retry" in instructions
    assert "structuredContent" in instructions
    assert r"D:\work\ida-stdio-mcp\data" in instructions
    assert r"D:\work\ida-stdio-mcp\data\logs" in instructions


def test_all_public_tools_have_deterministic_bounded_success_summaries() -> None:
    public_tools = {
        spec.name
        for spec in build_tool_catalog(
            enable_authoring=True,
            enable_debug=True,
            enable_expert=True,
        )
    }
    assert SUPPORTED_SUCCESS_SUMMARIES == public_tools
    for name in sorted(SUPPORTED_SUCCESS_SUMMARIES):
        text = success_summary(name, {})
        assert 0 < len(text) <= 2_048
        assert "structuredContent" in text
        assert not text.lstrip().startswith("{")


def test_success_summaries_include_next_steps_without_copying_large_fields() -> None:
    retried = success_summary(
        "workspace.retry",
        {
            "workspace_id": "workspace_retry",
            "sample_sha256": "c" * 64,
            "analysis_operation_id": "operation_retry",
        },
    )
    assert "workspace_retry" in retried
    assert "operation_retry" in retried
    assert "operation.wait" in retried

    queued = success_summary(
        "analysis.refine",
        {
            "operation_id": "operation_abcdef",
            "workspace_id": "workspace_abcdef",
            "base_revision": "revision_base",
        },
    )
    assert "operation_abcdef" in queued
    assert "operation.wait" in queued

    completed = success_summary(
        "operation.wait",
        {
            "operation_id": "operation_abcdef",
            "state": "succeeded",
            "progress": None,
            "result": {
                "workspace_id": "workspace_abcdef",
                "revision": "revision_new",
                "artifact_uri": _RESOURCE_URI,
                "sha256": "b" * 64,
                "large_payload": "不应复制" * 4_096,
            },
            "failure": None,
        },
    )
    assert "revision_new" in completed
    assert _RESOURCE_URI in completed
    assert "不应复制" not in completed

    failed = success_summary(
        "operation.wait",
        {
            "operation_id": "operation_failed",
            "state": "failed",
            "progress": None,
            "result": None,
            "failure": {
                "code": "worker_crashed",
                "message": "IDA 分析进程意外退出",
                "retryable": True,
            },
        },
    )
    assert "IDA 分析进程意外退出" in failed
    assert "可以重试" in failed

    expert = success_summary(
        "expert.execute",
        {
            "workspace_id": "workspace_abcdef",
            "base_revision": "revision_base",
            "revision": "revision_new",
            "output_mode": "inline",
            "stdout": "sensitive-large-stdout",
            "stderr": "",
            "result_repr": "sensitive-large-result",
            "artifact": None,
        },
    )
    assert "revision_new" in expert
    assert "sensitive-large" not in expert


def test_long_error_reason_keeps_next_step() -> None:
    summary = error_summary("execution_failed", "失败原因" * 1_024)

    assert len(summary) <= 2_048
    assert "…" in summary
    assert "下一步：" in summary
    assert "运行 doctor" in summary
    assert "完整的机器错误对象" in summary

    operation = success_summary(
        "operation.wait",
        {
            "operation_id": "operation_failed",
            "state": "failed",
            "progress": None,
            "result": None,
            "failure": {
                "code": "execution_failed",
                "message": "后台失败" * 1_024,
                "retryable": False,
            },
        },
    )
    assert len(operation) <= 2_048
    assert "请先按失败原因修正问题" in operation
    assert "structuredContent" in operation


def test_error_sanitizer_hides_embedded_posix_path_and_path_field() -> None:
    assert safe_error_message("worker failed at /home/user/sample.i64") == (
        "工具执行失败。内部诊断信息已经写入日志。"
        "请运行 doctor 检查配置，并查看服务说明中列出的日志目录。"
    )
    assert safe_error_message("失败位置：/home/user/sample.i64") == (
        "工具执行失败。内部诊断信息已经写入日志。"
        "请运行 doctor 检查配置，并查看服务说明中列出的日志目录。"
    )
    assert sanitize_error_details(
        {
            "nested": {
                "path": "/home/user/sample.i64",
                "message": "failed at /var/tmp/ida/output.txt",
            },
            "current_revision": "revision_current",
        }
    ) == {
        "nested": {
            "path": "已隐藏内部诊断信息",
            "message": "已隐藏内部诊断信息",
        },
        "current_revision": "revision_current",
    }


def test_empty_workspace_list_points_to_workspace_create() -> None:
    summary = success_summary(
        "workspace.list",
        {
            "workspaces": [],
            "next_cursor": None,
        },
    )

    assert "没有找到已经保存的分析项目" in summary
    assert "workspace.create" in summary
    assert "选择 workspace_id" not in summary
