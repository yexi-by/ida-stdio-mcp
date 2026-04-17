"""真实样本黑盒回归测试。"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from ida_stdio_mcp.config import load_config
from ida_stdio_mcp.models import JsonObject, JsonValue
from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.service import build_service
from ida_stdio_mcp.stdio_server import ServerIdentity, StdioMcpServer


def expect_object(value: JsonValue, *, name: str) -> JsonObject:
    """把 JSON 值收窄为对象。"""
    if not isinstance(value, dict):
        raise AssertionError(f"{name} 应为对象，实际为 {type(value).__name__}")
    return value


def expect_list(value: JsonValue, *, name: str) -> list[JsonValue]:
    """把 JSON 值收窄为数组。"""
    if not isinstance(value, list):
        raise AssertionError(f"{name} 应为数组，实际为 {type(value).__name__}")
    return value


class RealWorldRegressionTests(unittest.TestCase):
    """用真实 Unity 样本覆盖黑盒报告中的关键阻塞项。"""

    @staticmethod
    def _repo_root() -> Path:
        return Path(__file__).resolve().parents[2]

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = cls._repo_root()
        cls.real_native_fixture = Path(
            os.environ.get(
                "IDA_STDIO_MCP_REAL_NATIVE_BINARY",
                r"D:\h-game\サキュバスデュエル\SuccubusDuel.exe",
            )
        ).resolve()
        cls.real_managed_fixture = Path(
            os.environ.get(
                "IDA_STDIO_MCP_REAL_MANAGED_BINARY",
                r"D:\h-game\サキュバスデュエル\SuccubusDuel_Data\Managed\Assembly-CSharp.dll",
            )
        ).resolve()

    def setUp(self) -> None:
        self.config = load_config(self.repo_root / "setting.toml")
        self.runtime = HeadlessRuntime()
        self.service = build_service(
            self.runtime,
            self.config,
            allow_unsafe=True,
            allow_debugger=True,
            profile_path=None,
        )
        self.server = StdioMcpServer(
            tools=self.service.tools,
            resources=self.service.resources,
            identity=ServerIdentity(
                protocol_version=self.config.server.protocol_version,
                server_name=self.config.server.server_name,
                server_version=self.config.server.server_version,
            ),
        )

    def tearDown(self) -> None:
        self.runtime.shutdown()

    def _require_real_managed(self) -> None:
        if not self.real_managed_fixture.exists():
            self.skipTest(f"真实托管样本不存在：{self.real_managed_fixture}")

    def _require_real_native(self) -> None:
        if not self.real_native_fixture.exists():
            self.skipTest(f"真实原生样本不存在：{self.real_native_fixture}")

    def _call_tool(self, name: str, arguments: JsonObject | None = None) -> JsonObject:
        response = self.server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        response_result = expect_object(response["result"], name="tool.result")
        return expect_object(response_result["structuredContent"], name="tool.structured")

    def _read_resource(self, uri: str) -> JsonObject:
        response = self.server.dispatch_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": {"uri": uri},
            }
        )
        self.assertIsNotNone(response)
        assert response is not None
        return expect_object(response["result"], name="resource.result")

    def test_real_managed_capability_writeback_and_csharp_decompile(self) -> None:
        """真实托管样本上验证能力矩阵、类型写回持久化与 C# 反编译。"""
        self._require_real_managed()
        temp_root = Path(tempfile.mkdtemp(prefix="ida-stdio-managed-"))
        try:
            copied_assembly = temp_root / self.real_managed_fixture.name
            saved_idb = temp_root / "Assembly-CSharp.blackbox.saved.i64"
            shutil.copy2(self.real_managed_fixture, copied_assembly)

            opened = self._call_tool(
                "open_binary",
                {"path": str(copied_assembly), "session_id": "managed-real"},
            )
            self.assertEqual(opened["status"], "ok")

            capability_resource = self._read_resource("ida://idb/capabilities")
            capability_contents = expect_list(capability_resource["contents"], name="capability.contents")
            capability_first = expect_object(capability_contents[0], name="capability.contents[0]")
            capability_envelope = expect_object(
                json.loads(str(capability_first["text"])),
                name="capability.payload",
            )
            capability_payload = expect_object(capability_envelope["data"], name="capability.payload.data")
            self.assertEqual(capability_payload.get("analysis_domain"), "managed")
            self.assertEqual(capability_payload.get("type_writeback_support"), "full")
            representations = capability_payload.get("representations")
            self.assertIsInstance(representations, list)
            assert isinstance(representations, list)
            self.assertIn("csharp", representations)

            decompile = self._call_tool(
                "decompile_function",
                {"query": "PlayerInformation::Save", "session_id": "managed-real"},
            )
            self.assertEqual(decompile["status"], "ok")
            decompile_data = expect_object(decompile["data"], name="decompile.data")
            self.assertEqual(decompile_data.get("representation"), "csharp")
            decompile_text = decompile_data.get("text")
            self.assertIsInstance(decompile_text, str)
            assert isinstance(decompile_text, str)
            self.assertIn("public bool Save", decompile_text)
            self.assertIn("save{index}.txt", decompile_text)

            set_types = self._call_tool(
                "set_types",
                {
                    "items": [
                        {
                            "addr": "PlayerInformation::Save",
                            "type": "bool __fastcall PlayerInformation__Save(void *self, int index)",
                        }
                    ],
                    "session_id": "managed-real",
                },
            )
            self.assertEqual(set_types["status"], "ok")

            profile_after_write = self._call_tool(
                "get_function_profile",
                {"query": "PlayerInformation::Save", "include_asm": False, "session_id": "managed-real"},
            )
            self.assertEqual(profile_after_write["status"], "ok")
            profile_after_write_data = expect_object(profile_after_write["data"], name="profile_after_write.data")
            prototype = profile_after_write_data.get("prototype")
            self.assertIsInstance(prototype, str)
            assert isinstance(prototype, str)
            self.assertIn("bool __fastcall", prototype)

            exported = self._call_tool(
                "export_functions",
                {"items": ["PlayerInformation::Save"], "format": "prototypes", "session_id": "managed-real"},
            )
            self.assertEqual(exported["status"], "ok")
            exported_data = expect_list(exported["data"], name="exported.data")
            exported_first = expect_object(exported_data[0], name="exported.data[0]")
            functions = expect_list(exported_first["functions"], name="exported.data[0].functions")
            function_first = expect_object(functions[0], name="exported.functions[0]")
            signature = function_first.get("signature")
            self.assertIsInstance(signature, str)
            assert isinstance(signature, str)
            self.assertIn("bool __fastcall", signature)

            saved = self._call_tool(
                "save_binary",
                {"path": str(saved_idb), "session_id": "managed-real"},
            )
            self.assertEqual(saved["status"], "ok")
            self.assertTrue(saved_idb.exists())

            closed = self._call_tool("close_binary", {"session_id": "managed-real"})
            self.assertEqual(closed["status"], "ok")

            reopened = self._call_tool(
                "open_binary",
                {"path": str(saved_idb), "session_id": "managed-reopen"},
            )
            self.assertEqual(reopened["status"], "ok")

            profile_after_reopen = self._call_tool(
                "get_function_profile",
                {"query": "PlayerInformation::Save", "include_asm": False, "session_id": "managed-reopen"},
            )
            self.assertEqual(profile_after_reopen["status"], "ok")
            profile_after_reopen_data = expect_object(profile_after_reopen["data"], name="profile_after_reopen.data")
            persisted_prototype = profile_after_reopen_data.get("prototype")
            self.assertIsInstance(persisted_prototype, str)
            assert isinstance(persisted_prototype, str)
            self.assertIn("bool __fastcall", persisted_prototype)
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    def test_real_string_reads_are_exact_for_managed_and_native(self) -> None:
        """真实样本上验证地址到字符串值的映射闭环。"""
        self._require_real_managed()
        self._require_real_native()

        managed_opened = self._call_tool(
            "open_binary",
            {"path": str(self.real_managed_fixture), "session_id": "managed-strings"},
        )
        self.assertEqual(managed_opened["status"], "ok")
        managed_hits = self._call_tool(
            "find_strings",
            {"pattern": "{0}/save{1}.txt", "limit": 5, "session_id": "managed-strings"},
        )
        self.assertEqual(managed_hits["status"], "ok")
        managed_hits_data = expect_object(managed_hits["data"], name="managed_hits.data")
        managed_rows = expect_list(managed_hits_data["data"], name="managed_hits.data.data")
        self.assertGreater(len(managed_rows), 0)
        managed_first = expect_object(managed_rows[0], name="managed_hits.data.data[0]")
        managed_addr = managed_first.get("addr")
        self.assertIsInstance(managed_addr, str)
        assert isinstance(managed_addr, str)
        managed_read = self._call_tool(
            "read_strings",
            {"addrs": [managed_addr], "session_id": "managed-strings"},
        )
        self.assertEqual(managed_read["status"], "ok")
        managed_read_rows = expect_list(managed_read["data"], name="managed_read.data")
        managed_read_first = expect_object(managed_read_rows[0], name="managed_read.data[0]")
        self.assertEqual(managed_read_first.get("string"), "{0}/save{1}.txt")

        native_opened = self._call_tool(
            "open_binary",
            {"path": str(self.real_native_fixture), "session_id": "native-strings"},
        )
        self.assertEqual(native_opened["status"], "ok")
        native_hits = self._call_tool(
            "find_strings",
            {"pattern": "__cdecl", "limit": 5, "session_id": "native-strings"},
        )
        self.assertEqual(native_hits["status"], "ok")
        native_hits_data = expect_object(native_hits["data"], name="native_hits.data")
        native_rows = expect_list(native_hits_data["data"], name="native_hits.data.data")
        self.assertGreater(len(native_rows), 0)
        native_first = expect_object(native_rows[0], name="native_hits.data.data[0]")
        native_addr = native_first.get("addr")
        self.assertIsInstance(native_addr, str)
        assert isinstance(native_addr, str)
        native_read = self._call_tool(
            "read_strings",
            {"addrs": [native_addr], "session_id": "native-strings"},
        )
        self.assertEqual(native_read["status"], "ok")
        native_read_rows = expect_list(native_read["data"], name="native_read.data")
        native_read_first = expect_object(native_read_rows[0], name="native_read.data[0]")
        self.assertEqual(native_read_first.get("string"), "__cdecl")


if __name__ == "__main__":
    unittest.main()
