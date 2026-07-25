"""真实 stdio → MCP → Supervisor → IDA → revision 的产品链路门禁。"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

JsonObject = dict[str, object]


def _tree_identity(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _environment(base: dict[str, str], runtime: Path) -> dict[str, str]:
    environment = base.copy()
    environment["APPDATA"] = str(runtime / "roaming")
    environment["LOCALAPPDATA"] = str(runtime / "local")
    environment["WIN_PD_OVERRIDE_APPDATA"] = environment["APPDATA"]
    environment["WIN_PD_OVERRIDE_LOCAL_APPDATA"] = environment["LOCALAPPDATA"]
    environment["PYTHONUTF8"] = "1"
    environment["XDG_CONFIG_HOME"] = str(runtime / "xdg-config")
    environment["XDG_DATA_HOME"] = str(runtime / "xdg-data")
    environment["XDG_STATE_HOME"] = str(runtime / "xdg-state")
    return environment


@asynccontextmanager
async def _official_session(
    *,
    environment: dict[str, str],
    stderr_path: Path,
) -> AsyncGenerator[ClientSession]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ida_re_mcp", "serve"],
        env=environment,
        cwd=Path(__file__).resolve().parents[2],
    )
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stderr_path.open("w+", encoding="utf-8") as error_log:
        try:
            async with stdio_client(parameters, errlog=error_log) as streams:
                async with ClientSession(
                    *streams,
                    read_timeout_seconds=timedelta(seconds=180),
                    client_info=types.Implementation(
                        name="ida-re-mcp-ida-e2e",
                        version="1",
                    ),
                ) as client:
                    initialized = await client.initialize()
                    assert initialized.serverInfo.name == "ida-re-mcp"
                    assert initialized.capabilities.tools is not None
                    assert initialized.capabilities.resources is not None
                    yield client
        finally:
            error_log.flush()
            error_log.seek(0)
            stderr = error_log.read()
            assert stderr == "", stderr


async def _call_tool(
    client: ClientSession,
    *,
    name: str,
    arguments: JsonObject,
    timeout: float = 180,
) -> JsonObject:
    result = await client.call_tool(
        name,
        arguments,
        read_timeout_seconds=timedelta(seconds=timeout),
    )
    assert result.isError is False, result
    assert result.structuredContent is not None, result
    return cast(JsonObject, result.structuredContent)


async def _wait_operation(
    client: ClientSession,
    *,
    operation_id: str,
) -> JsonObject:
    while True:
        output = await _call_tool(
            client,
            name="operation.wait",
            arguments={"operation_id": operation_id, "wait_ms": 30_000},
        )
        state = output["state"]
        if state == "succeeded":
            return cast(JsonObject, output["result"])
        if state in {"failed", "cancelled"}:
            pytest.fail(f"长操作未成功: {output}")


@pytest.mark.ida
def test_real_stdio_static_and_transaction_chain(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    async def scenario() -> None:
        fixture_before = _tree_identity(fixture_directory)
        sample = tmp_path / "native_pe_x64.dll"
        shutil.copyfile(fixture_directory / sample.name, sample)
        runtime = tmp_path / "runtime"
        async with _official_session(
            environment=_environment(ida_environment, runtime),
            stderr_path=tmp_path / "static-stdio-stderr.log",
        ) as client:
            created = await _call_tool(
                client,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            workspace_id = cast(str, created["workspace_id"])
            operation_id = cast(str, created["analysis_operation_id"])
            initialized = await _wait_operation(
                client,
                operation_id=operation_id,
            )
            revision = cast(str, initialized["revision"])

            searched = await _call_tool(
                client,
                name="program.search",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "domains": ["function"],
                    "text_query": "fixture_validate",
                    "page_size": 50,
                },
            )
            matches = cast(list[JsonObject], searched["matches"])
            assert matches
            target = cast(JsonObject, matches[0]["address"])
            assert target["kind"] == "database"

            prepared = await _call_tool(
                client,
                name="change.prepare",
                arguments={
                    "workspace_id": workspace_id,
                    "base_revision": revision,
                    "operations": [
                        {
                            "kind": "rename",
                            "target": target,
                            "new_name": "agent_verified_entry",
                        }
                    ],
                },
            )
            applied = await _call_tool(
                client,
                name="change.apply",
                arguments={
                    "workspace_id": workspace_id,
                    "expected_revision": revision,
                    "change_set_id": prepared["change_set_id"],
                    "digest": prepared["digest"],
                },
            )
            next_revision = cast(str, applied["revision"])
            assert next_revision != revision

            verified = await _call_tool(
                client,
                name="program.search",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "domains": ["function"],
                    "text_query": "agent_verified_entry",
                    "page_size": 50,
                },
            )
            assert any(
                "agent_verified_entry" in cast(str, item["preview"])
                for item in cast(list[JsonObject], verified["matches"])
            )
        assert _tree_identity(fixture_directory) == fixture_before

    asyncio.run(scenario())


@pytest.mark.ida
@pytest.mark.debugger
def test_real_stdio_debug_chain(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    async def scenario() -> None:
        fixture_before = _tree_identity(fixture_directory)
        sample = tmp_path / "debug_target_x64.exe"
        shutil.copyfile(fixture_directory / sample.name, sample)
        async with _official_session(
            environment=_environment(ida_environment, tmp_path / "runtime"),
            stderr_path=tmp_path / "debug-stdio-stderr.log",
        ) as client:
            created = await _call_tool(
                client,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            workspace_id = cast(str, created["workspace_id"])
            sample_sha256 = cast(str, created["sample_sha256"])
            initialized = await _wait_operation(
                client,
                operation_id=cast(str, created["analysis_operation_id"]),
            )
            revision = cast(str, initialized["revision"])
            established = await _call_tool(
                client,
                name="debug.establish",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "target": {
                        "kind": "launch",
                        "arguments": [],
                        "stop_on_entry": True,
                    },
                    "timeout_ms": 30_000,
                },
            )
            session_id = cast(str, established["debug_session_id"])
            stop_id = cast(str, established["stop_id"])
            assert established["state"] == "suspended"

            initial_events = await _call_tool(
                client,
                name="debug.events",
                arguments={
                    "debug_session_id": session_id,
                    "after_sequence": 0,
                    "wait_ms": 0,
                    "limit": 200,
                },
            )
            cursor = cast(int, initial_events["last_sequence"])
            breakpoint_result = await _call_tool(
                client,
                name="debug.breakpoints",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": stop_id,
                    "replace": [
                        {
                            "address": {
                                "kind": "image",
                                "image_id": f"image~{sample_sha256}",
                                "rva": "0x1000",
                            },
                            "enabled": True,
                        }
                    ],
                },
            )
            breakpoints = cast(list[JsonObject], breakpoint_result["breakpoints"])
            assert len(breakpoints) == 1
            assert breakpoints[0]["state"] == "active"

            controlled = await _call_tool(
                client,
                name="debug.control",
                arguments={
                    "debug_session_id": session_id,
                    "action": "continue",
                    "stop_id": stop_id,
                    "timeout_ms": 30_000,
                },
            )
            cursor = max(cursor, cast(int, controlled["observed_event_sequence"]))
            hit_stop_id: str | None = None
            for _attempt in range(6):
                events_output = await _call_tool(
                    client,
                    name="debug.events",
                    arguments={
                        "debug_session_id": session_id,
                        "after_sequence": cursor,
                        "wait_ms": 30_000,
                        "limit": 200,
                    },
                )
                events = cast(list[JsonObject], events_output["events"])
                for event in events:
                    if event["kind"] == "breakpoint":
                        hit_stop_id = cast(str, event["stop_id"])
                        break
                cursor = cast(int, events_output["last_sequence"])
                if hit_stop_id is not None:
                    break
            assert hit_stop_id is not None

            threads_snapshot = await _call_tool(
                client,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["threads"],
                },
            )
            assert threads_snapshot["state"] == "suspended"
            assert cast(list[object], threads_snapshot["threads"])
            register_snapshot = await _call_tool(
                client,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["registers"],
                },
            )
            register_names = {
                cast(str, register["name"])
                for register in cast(list[JsonObject], register_snapshot["registers"])
            }
            assert {"RIP", "RSP"}.issubset(register_names)
            stack_snapshot = await _call_tool(
                client,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["stack"],
                },
            )
            assert cast(list[object], stack_snapshot["stack"])

            finished = await _call_tool(
                client,
                name="debug.finish",
                arguments={
                    "debug_session_id": session_id,
                    "action": "terminate",
                    "timeout_ms": 30_000,
                },
            )
            assert finished["state"] == "exited"
        assert _tree_identity(fixture_directory) == fixture_before

    asyncio.run(scenario())
