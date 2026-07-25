from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import cast

import pytest
from mcp.client import Client, Transport
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from mcp_types import Implementation, TextContent

from ida_re_mcp.constants import PROTOCOL_VERSION


def _environment(data_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["APPDATA"] = str(data_root / "roaming")
    environment["LOCALAPPDATA"] = str(data_root / "local")
    environment["WIN_PD_OVERRIDE_APPDATA"] = environment["APPDATA"]
    environment["WIN_PD_OVERRIDE_LOCAL_APPDATA"] = environment["LOCALAPPDATA"]
    environment["PYTHONUTF8"] = "1"
    environment["XDG_CONFIG_HOME"] = str(data_root / "xdg-config")
    environment["XDG_DATA_HOME"] = str(data_root / "xdg-data")
    environment["XDG_STATE_HOME"] = str(data_root / "xdg-state")
    return environment


def _current_meta() -> dict[str, object]:
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "stdio-current-test",
            "version": "1.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


async def _raw_stdio_scenario(data_root: Path) -> None:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "ida_re_mcp",
        "serve",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_environment(data_root),
    )
    requests = [
        {
            "jsonrpc": "2.0",
            "id": "discover",
            "method": "server/discover",
            "params": {"_meta": _current_meta()},
        },
        {
            "jsonrpc": "2.0",
            "id": "unsupported-method",
            "method": "server/no_such_method",
            "params": {"_meta": _current_meta()},
        },
    ]
    payload = b"{invalid\n" + b"".join(
        json.dumps(item, separators=(",", ":")).encode("utf-8") + b"\n" for item in requests
    )

    stdout, stderr = await asyncio.wait_for(process.communicate(payload), timeout=20)

    assert process.returncode == 0
    assert stderr == b""
    lines = stdout.splitlines()
    assert len(lines) == len(requests) + 1
    messages: dict[str, dict[str, object]] = {}
    parse_errors: list[dict[str, object]] = []
    for raw in lines:
        value: object = json.loads(raw)
        assert isinstance(value, dict)
        message = cast(dict[str, object], value)
        if message.get("id") is None:
            parse_errors.append(message)
        else:
            messages[cast(str, message["id"])] = message
    assert len(parse_errors) == 1
    assert cast(dict[str, object], parse_errors[0]["error"])["code"] == -32700
    discovery = cast(dict[str, object], messages["discover"]["result"])
    assert discovery["supportedVersions"] == [PROTOCOL_VERSION]
    assert discovery["capabilities"] == {"resources": {}, "tools": {}}
    assert "serverInfo" not in discovery
    assert cast(dict[str, object], messages["unsupported-method"]["error"])["code"] == -32601


async def _official_client_scenario(data_root: Path) -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ida_re_mcp", "serve"],
        env=_environment(data_root),
        cwd=Path.cwd(),
    )
    # mcp-types 2.0.0b2 的 DiscoverResult 尚未同步 RC 中 serverInfo 的位置;
    # 显式 current mode 可验证其余官方 client wire, 而不引入过时字段。
    error_path = data_root / "sdk-stderr.log"
    error_path.parent.mkdir(parents=True, exist_ok=True)
    with error_path.open("w+", encoding="utf-8") as error_log:
        transport = cast(Transport, stdio_client(parameters, errlog=error_log))
        async with Client(
            transport,
            mode=PROTOCOL_VERSION,
            client_info=Implementation(name="official-current-client", version="2.0.0b2"),
            cache=False,
        ) as client:
            assert client.protocol_version == PROTOCOL_VERSION

            tools = await client.list_tools()
            names = [tool.name for tool in tools.tools]
            assert names == sorted(names)
            assert "operation.wait" in names
            assert "expert.execute" not in names

            resources = await client.list_resources()
            assert resources.resources == []

            workspace_list = await client.call_tool("workspace.list", {})
            assert workspace_list.is_error is False
            assert workspace_list.structured_content == {
                "next_cursor": None,
                "workspaces": [],
            }

            business_error = await client.call_tool(
                "operation.wait",
                {"operation_id": "operation_missing", "wait_ms": 0},
            )
            assert business_error.is_error is True
            content = business_error.content[0]
            assert isinstance(content, TextContent)
            assert "operation_not_found" in content.text

            missing_uri = (
                "ida-re://workspaces/workspace_missing/"
                "revisions/revision_missing/artifacts/artifact_missing"
            )
            with pytest.raises(MCPError) as raised:
                await client.read_resource(missing_uri)
            assert raised.value.code == -32602

        error_log.seek(0)
        assert error_log.read() == ""


def test_real_stdio_is_current_only_and_official_client_conformant(tmp_path: Path) -> None:
    asyncio.run(_raw_stdio_scenario(tmp_path / "raw"))
    asyncio.run(_official_client_scenario(tmp_path / "sdk"))
