"""真实 stdio → MCP → Supervisor → IDA → revision 的产品链路门禁。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.constants import PROTOCOL_VERSION

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


def _meta() -> JsonObject:
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "ida-re-mcp-full-chain-e2e",
            "version": "1.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


async def _call_tool(
    process: asyncio.subprocess.Process,
    *,
    request_id: int,
    name: str,
    arguments: JsonObject,
    timeout: float = 180,
) -> JsonObject:
    assert process.stdin is not None
    assert process.stdout is not None
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "_meta": _meta(),
            "name": name,
            "arguments": arguments,
        },
    }
    process.stdin.write(
        json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    await process.stdin.drain()
    raw = await asyncio.wait_for(process.stdout.readline(), timeout=timeout)
    if not raw:
        stderr = (
            await process.stderr.read() if process.stderr is not None else b"stderr unavailable"
        )
        pytest.fail(f"stdio 服务提前退出: {stderr.decode(errors='replace')}")
    response = cast(JsonObject, json.loads(raw))
    assert response.get("id") == request_id
    assert "error" not in response, response
    result = cast(JsonObject, response["result"])
    assert result.get("isError") is False, result
    return cast(JsonObject, result["structuredContent"])


async def _wait_operation(
    process: asyncio.subprocess.Process,
    *,
    request_id: int,
    operation_id: str,
) -> tuple[int, JsonObject]:
    while True:
        output = await _call_tool(
            process,
            request_id=request_id,
            name="operation.wait",
            arguments={"operation_id": operation_id, "wait_ms": 30_000},
        )
        request_id += 1
        state = output["state"]
        if state == "succeeded":
            return request_id, cast(JsonObject, output["result"])
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
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ida_re_mcp",
            "serve",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_environment(ida_environment, runtime),
            creationflags=subprocess_creation_flags(),
        )
        request_id = 1
        try:
            created = await _call_tool(
                process,
                request_id=request_id,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            request_id += 1
            workspace_id = cast(str, created["workspace_id"])
            operation_id = cast(str, created["analysis_operation_id"])
            request_id, initialized = await _wait_operation(
                process,
                request_id=request_id,
                operation_id=operation_id,
            )
            revision = cast(str, initialized["revision"])

            searched = await _call_tool(
                process,
                request_id=request_id,
                name="program.search",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "domains": ["function"],
                    "text_query": "fixture_validate",
                    "page_size": 50,
                },
            )
            request_id += 1
            matches = cast(list[JsonObject], searched["matches"])
            assert matches
            target = cast(JsonObject, matches[0]["address"])
            assert target["kind"] == "database"

            prepared = await _call_tool(
                process,
                request_id=request_id,
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
            request_id += 1
            applied = await _call_tool(
                process,
                request_id=request_id,
                name="change.apply",
                arguments={
                    "workspace_id": workspace_id,
                    "expected_revision": revision,
                    "change_set_id": prepared["change_set_id"],
                    "digest": prepared["digest"],
                },
            )
            request_id += 1
            next_revision = cast(str, applied["revision"])
            assert next_revision != revision

            verified = await _call_tool(
                process,
                request_id=request_id,
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
        finally:
            if process.stdin is not None:
                process.stdin.close()
                await process.stdin.wait_closed()
            try:
                await asyncio.wait_for(process.wait(), timeout=30)
            except TimeoutError:
                process.kill()
                await process.wait()
                pytest.fail("stdio 服务未在 stdin EOF 后退出")
            stderr = await process.stderr.read() if process.stderr is not None else b""
            assert process.returncode == 0, stderr.decode(errors="replace")
            assert stderr == b""
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
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ida_re_mcp",
            "serve",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_environment(ida_environment, tmp_path / "runtime"),
            creationflags=subprocess_creation_flags(),
        )
        request_id = 1
        try:
            created = await _call_tool(
                process,
                request_id=request_id,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            request_id += 1
            workspace_id = cast(str, created["workspace_id"])
            sample_sha256 = cast(str, created["sample_sha256"])
            request_id, initialized = await _wait_operation(
                process,
                request_id=request_id,
                operation_id=cast(str, created["analysis_operation_id"]),
            )
            revision = cast(str, initialized["revision"])
            established = await _call_tool(
                process,
                request_id=request_id,
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
            request_id += 1
            session_id = cast(str, established["debug_session_id"])
            stop_id = cast(str, established["stop_id"])
            assert established["state"] == "suspended"

            initial_events = await _call_tool(
                process,
                request_id=request_id,
                name="debug.events",
                arguments={
                    "debug_session_id": session_id,
                    "after_sequence": 0,
                    "wait_ms": 0,
                    "limit": 200,
                },
            )
            request_id += 1
            cursor = cast(int, initial_events["last_sequence"])
            breakpoint_result = await _call_tool(
                process,
                request_id=request_id,
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
            request_id += 1
            breakpoints = cast(list[JsonObject], breakpoint_result["breakpoints"])
            assert len(breakpoints) == 1
            assert breakpoints[0]["state"] == "active"

            controlled = await _call_tool(
                process,
                request_id=request_id,
                name="debug.control",
                arguments={
                    "debug_session_id": session_id,
                    "action": "continue",
                    "stop_id": stop_id,
                    "timeout_ms": 30_000,
                },
            )
            request_id += 1
            cursor = max(cursor, cast(int, controlled["observed_event_sequence"]))
            hit_stop_id: str | None = None
            for _attempt in range(6):
                events_output = await _call_tool(
                    process,
                    request_id=request_id,
                    name="debug.events",
                    arguments={
                        "debug_session_id": session_id,
                        "after_sequence": cursor,
                        "wait_ms": 30_000,
                        "limit": 200,
                    },
                )
                request_id += 1
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
                process,
                request_id=request_id,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["threads"],
                },
            )
            request_id += 1
            assert threads_snapshot["state"] == "suspended"
            assert cast(list[object], threads_snapshot["threads"])
            register_snapshot = await _call_tool(
                process,
                request_id=request_id,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["registers"],
                },
            )
            request_id += 1
            register_names = {
                cast(str, register["name"])
                for register in cast(list[JsonObject], register_snapshot["registers"])
            }
            assert {"RIP", "RSP"}.issubset(register_names)
            stack_snapshot = await _call_tool(
                process,
                request_id=request_id,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["stack"],
                },
            )
            request_id += 1
            assert cast(list[object], stack_snapshot["stack"])

            finished = await _call_tool(
                process,
                request_id=request_id,
                name="debug.finish",
                arguments={
                    "debug_session_id": session_id,
                    "action": "terminate",
                    "timeout_ms": 30_000,
                },
            )
            assert finished["state"] == "exited"
        finally:
            if process.stdin is not None:
                process.stdin.close()
                await process.stdin.wait_closed()
            try:
                await asyncio.wait_for(process.wait(), timeout=30)
            except TimeoutError:
                process.kill()
                await process.wait()
                pytest.fail("debug stdio 服务未在 stdin EOF 后退出")
            stderr = await process.stderr.read() if process.stderr is not None else b""
            assert process.returncode == 0, stderr.decode(errors="replace")
            assert stderr == b""
        assert _tree_identity(fixture_directory) == fixture_before

    asyncio.run(scenario())


def subprocess_creation_flags() -> int:
    if os.name == "nt":
        return 0x08000000  # CREATE_NO_WINDOW
    return 0
