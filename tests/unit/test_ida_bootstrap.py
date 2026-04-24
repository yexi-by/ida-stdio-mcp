"""IDA 9.3+ 运行时引导单元测试。"""

from __future__ import annotations

import unittest
from types import ModuleType
from unittest.mock import patch

from ida_stdio_mcp import ida_bootstrap
from ida_stdio_mcp.errors import RuntimeNotReadyError


class IdaBootstrapTests(unittest.TestCase):
    """覆盖无 IDA、低版本与有效 9.3+ 三种启动路径。"""

    def tearDown(self) -> None:
        """清理引导模块缓存。"""
        ida_bootstrap.reset_ida_runtime_cache_for_tests()

    def test_missing_ida_runtime_fails_fast(self) -> None:
        """缺少 idapro 时应立即返回可修复错误。"""
        with patch("ida_stdio_mcp.ida_bootstrap.import_module", side_effect=ImportError("missing")):
            with self.assertRaises(RuntimeNotReadyError):
                ida_bootstrap.ensure_ida_environment()

    def test_low_version_fails_fast(self) -> None:
        """低于 9.3 的运行时不再兼容。"""
        module = self._fake_idapro((9, 2, 0))
        with patch("ida_stdio_mcp.ida_bootstrap.import_module", return_value=module):
            with self.assertRaises(RuntimeNotReadyError):
                ida_bootstrap.ensure_ida_environment()

    def test_valid_93_runtime_is_accepted(self) -> None:
        """9.3+ 运行时可以通过校验。"""
        module = self._fake_idapro((9, 3, 1))
        with patch("ida_stdio_mcp.ida_bootstrap.import_module", return_value=module):
            loaded = ida_bootstrap.ensure_ida_environment()
            info = ida_bootstrap.get_ida_runtime_info()
        self.assertIs(loaded, module)
        self.assertEqual(info.version, (9, 3, 1))

    @staticmethod
    def _fake_idapro(version: tuple[int, int, int]) -> ModuleType:
        """构造最小 idapro 替身。"""
        module = ModuleType("idapro")

        def get_library_version() -> tuple[int, int, int]:
            """返回测试版本。"""
            return version

        setattr(module, "get_library_version", get_library_version)
        return module


if __name__ == "__main__":
    unittest.main()
