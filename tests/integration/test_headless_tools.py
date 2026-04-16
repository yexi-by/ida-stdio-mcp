"""真实 headless 集成测试。"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from ida_stdio_mcp.runtime import HeadlessRuntime


class HeadlessToolTests(unittest.TestCase):
    """验证 runtime 的核心只读能力。"""

    @classmethod
    def setUpClass(cls) -> None:
        binary_path = os.environ.get("IDA_STDIO_MCP_TEST_BINARY")
        if not binary_path:
            raise unittest.SkipTest("缺少 IDA_STDIO_MCP_TEST_BINARY")
        cls.runtime = HeadlessRuntime()
        cls.runtime.open_binary(Path(binary_path))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.runtime.close_binary()

    def test_health_and_survey(self) -> None:
        health = self.runtime.health()
        self.assertTrue(health["runtime_ready"])
        self.assertTrue(health["binary_open"])
        survey = self.runtime.survey_binary()
        stats = survey["statistics"]
        self.assertGreater(stats["function_count"], 0)

    def test_list_functions_and_disassemble(self) -> None:
        functions = self.runtime.list_functions()
        self.assertGreater(len(functions), 0)
        target = functions[0]["addr"]
        lines = self.runtime.disassemble_function(target, max_lines=8)
        self.assertGreater(len(lines), 0)

    def test_strings_and_decompile(self) -> None:
        strings = self.runtime.list_strings()
        self.assertIsInstance(strings, list)
        functions = self.runtime.list_functions()
        result = self.runtime.decompile_function(functions[0]["addr"])
        self.assertIn(result["representation"], {"hexrays", "asm_fallback"})


if __name__ == "__main__":
    unittest.main()
