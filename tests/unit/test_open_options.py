"""headless 打开参数单元测试。"""

from __future__ import annotations

import unittest

from ida_stdio_mcp.open_options import HeadlessOpenOptions


class HeadlessOpenOptionsTests(unittest.TestCase):
    """覆盖 loader、processor 与插件参数到 IDA args 的转换。"""

    def test_empty_options_produce_empty_args(self) -> None:
        """默认配置不应向 IDA 传入伪造参数。"""
        options = HeadlessOpenOptions()

        self.assertEqual(options.to_ida_args(), "")
        self.assertEqual(options.to_json()["ida_args"], "")

    def test_options_render_to_headless_ida_args(self) -> None:
        """结构化配置应映射为 idapro.open_database(args=...)。"""
        options = HeadlessOpenOptions(loader="pe", processor="metapc", plugin_options=("objc:off", "pdb:off"))

        self.assertEqual(options.to_ida_args(), "-Tpe -pmetapc -Oobjc:off -Opdb:off")
        self.assertEqual(options.to_json()["loader"], "pe")
        self.assertEqual(options.to_json()["processor"], "metapc")
        self.assertEqual(options.to_json()["plugin_options"], ["objc:off", "pdb:off"])


if __name__ == "__main__":
    unittest.main()
