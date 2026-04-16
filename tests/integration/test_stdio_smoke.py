"""stdio 端到端冒烟测试。"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import cast

from ida_stdio_mcp.models import JsonObject


class StdioSmokeTests(unittest.TestCase):
    """验证原生 stdio MCP 主链路可直接工作。"""

    @staticmethod
    def _repo_root() -> Path:
        """返回仓库根目录。"""
        return Path(__file__).resolve().parents[2]

    def _send_request(self, process: subprocess.Popen[str], payload: JsonObject) -> JsonObject:
        """向子进程写入一条 JSON-RPC 请求并读取一条响应。"""
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        process.stdin.flush()
        line = process.stdout.readline().strip()
        self.assertTrue(line, "stdio 服务未返回响应")
        return cast(JsonObject, json.loads(line))

    def test_stdio_initialize_tools_list_and_health(self) -> None:
        """通过 uv run python -m 直接启动服务并完成基本握手。"""
        uv_path = shutil.which("uv")
        if uv_path is None:
            self.skipTest("当前环境缺少 uv")

        process = subprocess.Popen(
            [
                uv_path,
                "run",
                "python",
                "-m",
                "ida_stdio_mcp",
                "--config",
                str(self._repo_root() / "setting.toml"),
            ],
            cwd=self._repo_root(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            initialize_response = self._send_request(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {},
                },
            )
            result = initialize_response["result"]
            self.assertIsInstance(result, dict)
            assert isinstance(result, dict)
            server_info = result["serverInfo"]
            self.assertIsInstance(server_info, dict)
            assert isinstance(server_info, dict)
            self.assertEqual(server_info["name"], "ida-stdio-mcp")

            assert process.stdin is not None
            process.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            process.stdin.flush()

            tools_response = self._send_request(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
            )
            tools_result = tools_response["result"]
            self.assertIsInstance(tools_result, dict)
            assert isinstance(tools_result, dict)
            tools = tools_result["tools"]
            self.assertIsInstance(tools, list)
            assert isinstance(tools, list)
            tool_names = {
                tool_name
                for tool in tools
                if isinstance(tool, dict)
                for tool_name in [tool.get("name")]
                if isinstance(tool_name, str)
            }
            self.assertIn("health", tool_names)
            self.assertIn("analyze_directory", tool_names)

            health_response = self._send_request(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "health", "arguments": {}},
                },
            )
            health_result = health_response["result"]
            self.assertIsInstance(health_result, dict)
            assert isinstance(health_result, dict)
            structured = health_result["structuredContent"]
            self.assertIsInstance(structured, dict)
            assert isinstance(structured, dict)
            self.assertEqual(structured["status"], "ok")
            data = structured["data"]
            self.assertIsInstance(data, dict)
            assert isinstance(data, dict)
            self.assertEqual(data["runtime_ready"], True)
            self.assertEqual(data["binary_open"], False)
        finally:
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

            stderr_text = ""
            if process.stderr is not None:
                stderr_text = process.stderr.read()
                process.stderr.close()
            if process.stdout is not None:
                process.stdout.close()
            if process.returncode not in {0, None}:
                self.fail(f"stdio 服务退出码异常：{process.returncode}\n{stderr_text}")


if __name__ == "__main__":
    unittest.main()
