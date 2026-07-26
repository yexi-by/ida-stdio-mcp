from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from mcp import ClientSession, McpError, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from pydantic import AnyUrl

from ida_re_mcp.constants import RESOURCE_CHUNK_BYTES
from ida_re_mcp.supervisor import ArtifactStore

_PROBE_SERVER = Path(__file__).with_name("stdio_probe_server.py")


def _environment(data_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["APPDATA"] = str(data_root / "roaming")
    environment["LOCALAPPDATA"] = str(data_root / "local")
    environment["WIN_PD_OVERRIDE_APPDATA"] = environment["APPDATA"]
    environment["WIN_PD_OVERRIDE_LOCAL_APPDATA"] = environment["LOCALAPPDATA"]
    environment["PYTHONUTF8"] = "1"
    environment["IDA_RE_MCP_DATA_ROOT"] = str(data_root / "runtime-data")
    environment["IDA_RE_MCP_LOG_ROOT"] = str(data_root / "runtime-logs")
    environment["PYTHONPYCACHEPREFIX"] = str(data_root / "pycache")
    environment["XDG_CONFIG_HOME"] = str(data_root / "xdg-config")
    environment["XDG_DATA_HOME"] = str(data_root / "xdg-data")
    environment["XDG_STATE_HOME"] = str(data_root / "xdg-state")
    return environment


def _seed_resources(data_root: Path) -> tuple[str, str, str, bytes]:
    store = ArtifactStore(data_root / "runtime-data" / "artifacts")
    text = "a" * (RESOURCE_CHUNK_BYTES - 5) + "界" + "z"
    binary = bytes(range(251)) * ((RESOURCE_CHUNK_BYTES + 17) // 251 + 1)
    binary = binary[: RESOURCE_CHUNK_BYTES + 17]
    text_artifact = store.put_bytes(
        workspace_id="workspace_integration",
        revision="revision_integration",
        data=text.encode("utf-8"),
        media_type="text/plain",
        name="boundary.txt",
    )
    binary_artifact = store.put_bytes(
        workspace_id="workspace_integration",
        revision="revision_integration",
        data=binary,
        media_type="application/octet-stream",
        name="boundary.bin",
    )
    return text_artifact.uri, binary_artifact.uri, text, binary


def _probe_parameters(
    data_root: Path,
    state_path: Path,
    *,
    exit_on_call: bool = False,
    internal_error_on_call: bool = False,
) -> StdioServerParameters:
    environment = _environment(data_root)
    environment["IDA_RE_MCP_PROBE_STATE"] = str(state_path)
    if exit_on_call:
        environment["IDA_RE_MCP_PROBE_EXIT"] = "1"
    if internal_error_on_call:
        environment["IDA_RE_MCP_PROBE_INTERNAL_ERROR"] = "1"
    return StdioServerParameters(
        command=sys.executable,
        args=[str(_PROBE_SERVER)],
        env=environment,
        cwd=Path.cwd(),
    )


async def _wait_for_state(
    state_path: Path,
    expected: str,
    *,
    timeout_seconds: float = 5,
) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while loop.time() < deadline:
        if state_path.exists() and state_path.read_text(encoding="utf-8") == expected:
            return
        await asyncio.sleep(0.01)
    actual = state_path.read_text(encoding="utf-8") if state_path.exists() else "<missing>"
    raise AssertionError(f"探针状态未变为 {expected}: {actual}")


async def _official_client_scenario(data_root: Path) -> None:
    text_uri, binary_uri, expected_text, expected_binary = _seed_resources(data_root)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ida_re_mcp", "serve"],
        env=_environment(data_root),
        cwd=Path.cwd(),
    )
    error_path = data_root / "sdk-stderr.log"
    error_path.parent.mkdir(parents=True, exist_ok=True)
    with error_path.open("w+", encoding="utf-8") as error_log:
        async with stdio_client(parameters, errlog=error_log) as streams:
            async with ClientSession(
                *streams,
                client_info=types.Implementation(
                    name="ida-re-mcp-integration-test",
                    version="1",
                ),
            ) as client:
                initialized = await client.initialize()
                assert initialized.serverInfo.name == "ida-re-mcp"
                assert initialized.protocolVersion
                capabilities = initialized.capabilities.model_dump(
                    mode="json",
                    exclude_none=True,
                )
                assert set(capabilities) == {"resources", "tools"}

                tools = await client.list_tools()
                names = [tool.name for tool in tools.tools]
                assert names == sorted(names)
                assert "operation.wait" in names
                assert "workspace.list" in names
                assert "expert.execute" not in names
                assert all(
                    tool.inputSchema.get("additionalProperties") is False for tool in tools.tools
                )
                assert all(tool.outputSchema is not None for tool in tools.tools)

                resources = await client.list_resources()
                assert {str(item.uri) for item in resources.resources} == {
                    text_uri,
                    binary_uri,
                }

                text_resource = await client.read_resource(AnyUrl(text_uri))
                assert len(text_resource.contents) == 2
                assert all(
                    isinstance(item, types.TextResourceContents) for item in text_resource.contents
                )
                assert (
                    "".join(
                        item.text
                        for item in text_resource.contents
                        if isinstance(item, types.TextResourceContents)
                    )
                    == expected_text
                )

                binary_resource = await client.read_resource(AnyUrl(binary_uri))
                assert len(binary_resource.contents) == 2
                assert all(
                    isinstance(item, types.BlobResourceContents)
                    for item in binary_resource.contents
                )
                assert (
                    b"".join(
                        base64.b64decode(item.blob, validate=True)
                        for item in binary_resource.contents
                        if isinstance(item, types.BlobResourceContents)
                    )
                    == expected_binary
                )

                workspace_list = await client.call_tool("workspace.list", {})
                assert workspace_list.isError is False
                assert workspace_list.structuredContent == {
                    "next_cursor": None,
                    "workspaces": [],
                }
                concurrent = await asyncio.gather(
                    *(client.call_tool("workspace.list", {}) for _ in range(8))
                )
                assert all(
                    not item.isError
                    and item.structuredContent
                    == {
                        "next_cursor": None,
                        "workspaces": [],
                    }
                    for item in concurrent
                )

                invalid_arguments = await client.call_tool(
                    "workspace.list",
                    {"unexpected": True},
                )
                assert invalid_arguments.isError is True
                assert invalid_arguments.structuredContent is None
                invalid_content = invalid_arguments.content[0]
                assert isinstance(invalid_content, types.TextContent)
                invalid_payload = cast(dict[str, Any], json.loads(invalid_content.text))
                assert invalid_payload["code"] == "invalid_arguments"

                business_error = await client.call_tool(
                    "operation.wait",
                    {"operation_id": "operation_missing", "wait_ms": 0},
                )
                assert business_error.isError is True
                assert business_error.structuredContent is None
                business_content = business_error.content[0]
                assert isinstance(business_content, types.TextContent)
                business_payload = cast(dict[str, Any], json.loads(business_content.text))
                assert business_payload["code"] == "operation_not_found"

                try:
                    await client.call_tool("missing.tool", {})
                except McpError as error:
                    assert error.error.code == types.INVALID_PARAMS
                    assert error.error.message == "Unknown tool: missing.tool"
                else:
                    raise AssertionError("调用未知工具应返回 JSON-RPC Invalid params")

                missing_uri = (
                    "ida-re://workspaces/workspace_missing/"
                    f"revisions/revision_missing/artifacts/art_{'0' * 64}"
                )
                try:
                    await client.read_resource(AnyUrl(missing_uri))
                except McpError as error:
                    assert error.error.code == -32002
                    assert error.error.message == "Resource not found"
                else:
                    raise AssertionError("读取不存在的 resource 应失败")

                try:
                    await client.read_resource(AnyUrl("ida-re://unsupported/resource"))
                except McpError as error:
                    assert error.error.code == types.INVALID_PARAMS
                    assert error.error.message == "resource URI 无效"
                else:
                    raise AssertionError("无效 resource URI 应返回 JSON-RPC Invalid params")

        error_log.seek(0)
        assert error_log.read() == ""


def test_official_sdk_client_negotiates_real_stdio(tmp_path: Path) -> None:
    asyncio.run(_official_client_scenario(tmp_path))


def test_two_stdio_agents_share_artifacts_and_isolate_runtime_sessions(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        text_uri, binary_uri, _, _ = _seed_resources(tmp_path)
        ready = (asyncio.Event(), asyncio.Event())
        release = asyncio.Event()

        async def connect(index: int) -> set[str]:
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "ida_re_mcp", "serve"],
                env=_environment(tmp_path),
                cwd=Path.cwd(),
            )
            error_path = tmp_path / f"multi-agent-{index}.stderr.log"
            with error_path.open("w+", encoding="utf-8") as error_log:
                async with stdio_client(parameters, errlog=error_log) as streams:
                    async with ClientSession(
                        *streams,
                        client_info=types.Implementation(
                            name=f"ida-re-mcp-agent-{index}",
                            version="1",
                        ),
                    ) as client:
                        await client.initialize()
                        resources = await client.list_resources()
                        ready[index].set()
                        await release.wait()
                        return {str(item.uri) for item in resources.resources}

        tasks = (
            asyncio.create_task(connect(0)),
            asyncio.create_task(connect(1)),
        )
        try:
            await asyncio.wait_for(
                asyncio.gather(*(event.wait() for event in ready)),
                timeout=60,
            )
            session_root = tmp_path / "runtime-data" / "sessions"
            sessions = sorted(path for path in session_root.iterdir() if path.is_dir())
            assert len(sessions) == 2
            assert sessions[0] != sessions[1]
            lease_root = tmp_path / "runtime-data" / "session-leases"
            assert all((lease_root / f"{path.name}.lease.lock").is_file() for path in sessions)
            cursor_keys = [(path / "cursor.key").read_bytes() for path in sessions]
            assert len(set(cursor_keys)) == 2

            log_sessions = sorted(
                path for path in (tmp_path / "runtime-logs" / "sessions").iterdir() if path.is_dir()
            )
            assert [path.name for path in log_sessions] == [path.name for path in sessions]
        finally:
            release.set()
            listed = await asyncio.gather(*tasks)
        assert listed == [{text_uri, binary_uri}, {text_uri, binary_uri}]

    asyncio.run(scenario())


def test_real_stdio_cancel_notification_cancels_inflight_request(tmp_path: Path) -> None:
    async def scenario() -> None:
        state_path = tmp_path / "cancel-state.txt"
        error_path = tmp_path / "cancel-stderr.log"
        with error_path.open("w+", encoding="utf-8") as error_log:
            async with stdio_client(
                _probe_parameters(tmp_path / "cancel", state_path),
                errlog=error_log,
            ) as streams:
                async with ClientSession(*streams) as client:
                    await client.initialize()
                    request_id = cast(int, vars(client)["_request_id"])
                    pending = asyncio.create_task(
                        client.call_tool("probe.wait", {"delay_ms": 30_000})
                    )
                    await _wait_for_state(state_path, "running")
                    await client.send_notification(
                        types.ClientNotification(
                            root=types.CancelledNotification(
                                params=types.CancelledNotificationParams(
                                    requestId=request_id,
                                    reason="integration-test",
                                )
                            )
                        )
                    )
                    with pytest.raises(McpError):
                        await asyncio.wait_for(pending, timeout=5)
                    await _wait_for_state(state_path, "cancelled")

                    recovered = await client.call_tool("probe.wait", {"delay_ms": 1})
                    assert recovered.isError is False
                    assert recovered.structuredContent == {"completed": True}

            error_log.seek(0)
            assert error_log.read() == ""

    asyncio.run(scenario())


def test_real_stdio_dispatches_tool_calls_concurrently(tmp_path: Path) -> None:
    async def scenario() -> None:
        state_path = tmp_path / "concurrency-state.txt"
        error_path = tmp_path / "concurrency-stderr.log"
        with error_path.open("w+", encoding="utf-8") as error_log:
            async with stdio_client(
                _probe_parameters(tmp_path / "concurrency", state_path),
                errlog=error_log,
            ) as streams:
                async with ClientSession(*streams) as client:
                    await client.initialize()
                    slow = asyncio.create_task(client.call_tool("probe.wait", {"delay_ms": 2_000}))
                    await _wait_for_state(state_path, "running")
                    fast = await asyncio.wait_for(
                        client.call_tool("probe.wait", {"delay_ms": 1}),
                        timeout=0.5,
                    )
                    assert fast.isError is False
                    assert fast.structuredContent == {"completed": True}
                    assert not slow.done()
                    completed = await asyncio.wait_for(slow, timeout=3)
                    assert completed.isError is False

            error_log.seek(0)
            assert error_log.read() == ""

    asyncio.run(scenario())


def test_real_stdio_sanitizes_internal_protocol_error(tmp_path: Path) -> None:
    async def scenario() -> None:
        state_path = tmp_path / "internal-state.txt"
        error_path = tmp_path / "internal-stderr.log"
        with error_path.open("w+", encoding="utf-8") as error_log:
            async with stdio_client(
                _probe_parameters(
                    tmp_path / "internal",
                    state_path,
                    internal_error_on_call=True,
                ),
                errlog=error_log,
            ) as streams:
                async with ClientSession(*streams) as client:
                    await client.initialize()
                    with pytest.raises(McpError) as error:
                        await client.call_tool("probe.wait", {"delay_ms": 1})
                    assert error.value.error.code == types.INTERNAL_ERROR
                    assert error.value.error.message == "Internal server error"
                    serialized = error.value.error.model_dump_json()
                    assert "sensitive-probe-internal-detail" not in serialized
                    assert "RuntimeError" not in serialized

    asyncio.run(scenario())


def test_real_stdio_eof_cancels_inflight_request_and_exits(tmp_path: Path) -> None:
    async def scenario() -> None:
        state_path = tmp_path / "eof-state.txt"
        error_path = tmp_path / "eof-stderr.log"
        pending: asyncio.Task[types.CallToolResult] | None = None
        with error_path.open("w+", encoding="utf-8") as error_log:
            async with stdio_client(
                _probe_parameters(tmp_path / "eof", state_path),
                errlog=error_log,
            ) as streams:
                async with ClientSession(*streams) as client:
                    await client.initialize()
                    pending = asyncio.create_task(
                        client.call_tool("probe.wait", {"delay_ms": 30_000})
                    )
                    await _wait_for_state(state_path, "running")

            assert pending is not None
            await _wait_for_state(state_path, "cancelled")
            pending.cancel()
            results = await asyncio.gather(pending, return_exceptions=True)
            assert len(results) == 1
            assert isinstance(results[0], asyncio.CancelledError)
            error_log.seek(0)
            assert error_log.read() == ""

    asyncio.run(scenario())


def test_real_stdio_reports_abrupt_server_exit(tmp_path: Path) -> None:
    async def scenario() -> None:
        state_path = tmp_path / "exit-state.txt"
        error_path = tmp_path / "exit-stderr.log"
        with error_path.open("w+", encoding="utf-8") as error_log:
            async with stdio_client(
                _probe_parameters(
                    tmp_path / "exit",
                    state_path,
                    exit_on_call=True,
                ),
                errlog=error_log,
            ) as streams:
                async with ClientSession(*streams) as client:
                    await client.initialize()
                    with pytest.raises(McpError, match="Connection closed"):
                        await client.call_tool("probe.wait", {"delay_ms": 30_000})

            assert state_path.read_text(encoding="utf-8") == "running"
            error_log.seek(0)
            assert error_log.read() == ""

    asyncio.run(scenario())
