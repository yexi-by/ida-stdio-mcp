"""托管反编译辅助逻辑测试。"""

from __future__ import annotations

import unittest

from ida_stdio_mcp.managed_decompiler import extract_method_source


class ManagedDecompilerTests(unittest.TestCase):
    """验证托管源码截取逻辑。"""

    def test_extracts_block_method(self) -> None:
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
        source = """
public class DemoType
{
    public string Name() => "demo";
}
"""
        method = extract_method_source(source, "Name")
        self.assertEqual(method, 'public string Name() => "demo";')

    def test_returns_none_when_method_missing(self) -> None:
        source = "public class DemoType { public void Save() { } }"
        self.assertIsNone(extract_method_source(source, "Load"))


if __name__ == "__main__":
    unittest.main()
