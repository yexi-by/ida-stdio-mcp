"""使用官方 MCP client 验证隔离安装后的 stdio 服务。"""

from __future__ import annotations

import argparse
import asyncio
import os
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


def _parse_args() -> Path:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    executable = parser.parse_args().executable.resolve()
    if not executable.is_file():
        parser.error(f"找不到 ida-re-mcp 可执行文件: {executable}")
    return executable


async def _run(executable: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="ida-re-mcp-stdio-smoke-") as temporary:
        runtime_root = Path(temporary)
        environment = os.environ.copy()
        environment["IDA_RE_MCP_DATA_ROOT"] = str(runtime_root / "data")
        environment["IDA_RE_MCP_LOG_ROOT"] = str(runtime_root / "logs")
        environment["PYTHONPYCACHEPREFIX"] = str(runtime_root / "pycache")
        parameters = StdioServerParameters(
            command=str(executable),
            args=["serve"],
            env=environment,
            cwd=Path.cwd(),
        )
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as error_log:
            try:
                async with asyncio.timeout(30):
                    async with stdio_client(parameters, errlog=error_log) as streams:
                        async with ClientSession(
                            *streams,
                            client_info=types.Implementation(
                                name="ida-re-mcp-stdio-smoke",
                                version="1",
                            ),
                        ) as client:
                            initialized = await client.initialize()
                            if initialized.serverInfo.name != "ida-re-mcp":
                                raise RuntimeError("initialize 返回了错误的产品身份")
                            capabilities = initialized.capabilities.model_dump(
                                mode="json",
                                exclude_none=True,
                            )
                            if set(capabilities) != {"resources", "tools"}:
                                raise RuntimeError("initialize 广告了 tools/resources 之外的能力")

                            listed = await client.list_tools()
                            names = [tool.name for tool in listed.tools]
                            if len(names) != 23 or names != sorted(names):
                                raise RuntimeError(
                                    "tools/list 未返回完整且确定性排序的默认工具目录"
                                )
                            if "expert.execute" in names or "workspace.list" not in names:
                                raise RuntimeError("tools/list 的默认策略目录不正确")

                            result = await client.call_tool("workspace.list", {})
                            if result.isError or result.structuredContent != {
                                "next_cursor": None,
                                "workspaces": [],
                            }:
                                raise RuntimeError("workspace.list smoke 失败")
            except Exception as error:
                error_log.seek(0)
                server_error = error_log.read()
                if server_error:
                    raise RuntimeError(f"stdio server 失败: {server_error}") from error
                raise

            error_log.seek(0)
            if error_log.read():
                raise RuntimeError("stdio smoke 产生了 stderr")


def main() -> None:
    asyncio.run(_run(_parse_args()))


if __name__ == "__main__":
    main()
