"""托管反编译辅助逻辑测试。"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

from ida_stdio_mcp.managed_decompiler import configure_managed_decompiler, extract_method_source, managed_decompiler_command, managed_decompiler_health


class ManagedDecompilerTests(unittest.TestCase):
    """验证托管源码截取逻辑。"""

    def tearDown(self) -> None:
        """恢复默认托管反编译器配置。"""
        configure_managed_decompiler(enabled=True, command="", timeout_sec=30)

    def test_extracts_block_method(self) -> None:
        """从普通块状方法中截取完整方法源码。"""
        source = """
namespace Demo;

public class PlayerInformation
{
    public void Save()
    {
        var value = "ok";
        System.Console.WriteLine(value);
    }
}
"""
        method = extract_method_source(source, "Save")
        self.assertIsNotNone(method)
        assert method is not None
        self.assertIn("public void Save()", method)
        self.assertIn('var value = "ok";', method)

    def test_extracts_expression_bodied_method(self) -> None:
        """从表达式体方法中截取单行方法源码。"""
        source = """
public class DemoType
{
    public string Name() => "demo";
}
"""
        method = extract_method_source(source, "Name")
        self.assertEqual(method, 'public string Name() => "demo";')

    def test_returns_none_when_method_missing(self) -> None:
        """目标方法不存在时返回 None。"""
        source = "public class DemoType { public void Save() { } }"
        self.assertIsNone(extract_method_source(source, "Load"))

    def test_health_reports_disabled_state(self) -> None:
        """配置禁用时能力状态应显式为 unavailable。"""
        configure_managed_decompiler(enabled=False, command="", timeout_sec=30)

        state = managed_decompiler_health()

        self.assertEqual(state.status, "unavailable")
        self.assertEqual(state.source, "setting.toml:managed_decompiler.enabled")

    def test_health_reports_missing_configured_command(self) -> None:
        """配置命令不存在时应显式报 misconfigured。"""
        configure_managed_decompiler(enabled=True, command="definitely-missing-ilspycmd-for-test", timeout_sec=5)

        state = managed_decompiler_health()

        self.assertEqual(state.status, "misconfigured")
        self.assertIn("definitely-missing-ilspycmd-for-test", state.reason)

    def test_environment_override_wins_over_configured_command(self) -> None:
        """环境变量应能作为临时覆盖修复配置中的坏命令。"""
        with patch.dict(os.environ, {"IDA_STDIO_MCP_ILSPYCMD": sys.executable}):
            configure_managed_decompiler(enabled=True, command="definitely-missing-ilspycmd-for-test", timeout_sec=5)

            state = managed_decompiler_health()
            command = managed_decompiler_command()

        self.assertEqual(state.status, "available")
        self.assertEqual(state.source, "env:IDA_STDIO_MCP_ILSPYCMD")
        self.assertEqual(command, sys.executable)


if __name__ == "__main__":
    unittest.main()
