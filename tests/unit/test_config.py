"""配置加载单元测试。"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ida_stdio_mcp.config import AppConfig, load_config, package_version
from ida_stdio_mcp.errors import ConfigurationError


def _config_text(
    *,
    logging_fields: str = "",
    server_fields: str = "",
    runtime_workspace_fields: str = "",
    limits_fields: str = "",
    external_analyzers_fields: str = "",
    ida_runtime_fields: str = "",
    open_target_fields: str = "",
    debugger_fields: str = "",
    hexrays_fields: str = "",
    managed_decompiler_fields: str = "",
) -> str:
    """生成包含必需段落的最小 setting.toml。"""
    return f"""
[logging]
{logging_fields}
[server]
{server_fields}
[runtime_workspace]
{runtime_workspace_fields}
[ida_runtime]
{ida_runtime_fields}
[open_target]
{open_target_fields}
[debugger]
{debugger_fields}
[hexrays]
{hexrays_fields}
[managed_decompiler]
{managed_decompiler_fields}
[limits]
{limits_fields}
[external_analyzers]
{external_analyzers_fields}
"""


class ConfigTests(unittest.TestCase):
    """覆盖配置默认值和非法类型失败路径。"""

    def _load_temp_config(self, content: str) -> AppConfig:
        """写入临时配置并加载。"""
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "setting.toml"
            path.write_text(content, encoding="utf-8")
            return load_config(path)

    def test_missing_optional_values_use_defaults(self) -> None:
        """缺失可选字段时使用默认值。"""
        config = self._load_temp_config(_config_text())

        self.assertEqual(config.logging.level, "INFO")
        self.assertEqual(config.server.server_name, "ida-stdio-mcp")
        self.assertEqual(config.server.server_version, package_version())
        self.assertFalse(config.server.isolated_contexts)
        self.assertIsNone(config.ida_runtime.install_dir)
        self.assertEqual(config.open_target.loader, "")
        self.assertEqual(config.open_target.processor, "")
        self.assertEqual(config.open_target.plugin_options, ())
        self.assertEqual(config.debugger.backend_candidates, ())
        self.assertEqual(config.debugger.wait_for_suspend_ms, 1500)
        self.assertTrue(config.debugger.launch_use_request_default)
        self.assertFalse(config.debugger.remote_enabled)
        self.assertFalse(config.hexrays.enable_experimental_microcode)
        self.assertTrue(config.managed_decompiler.enabled)
        self.assertEqual(config.managed_decompiler.command, "")
        self.assertEqual(config.managed_decompiler.timeout_sec, 30)
        self.assertEqual(config.limits.default_page_size, 100)
        self.assertEqual(config.external_analyzers, ())

    def test_capability_sections_are_loaded(self) -> None:
        """能力初始化相关配置应从统一 setting.toml 读取。"""
        config = self._load_temp_config(
            _config_text(
                ida_runtime_fields='install_dir = "ida"',
                open_target_fields='loader = "pe"\nprocessor = "metapc"\nplugin_options = ["objc:off"]',
                debugger_fields='backend_candidates = ["win32", "linux"]\nwait_for_suspend_ms = 250\nlaunch_use_request_default = false\nremote_enabled = true',
                hexrays_fields="enable_experimental_microcode = true",
                managed_decompiler_fields='enabled = false\ncommand = "ilspycmd"\ntimeout_sec = 7',
            )
        )

        self.assertIsNotNone(config.ida_runtime.install_dir)
        self.assertEqual(config.open_target.loader, "pe")
        self.assertEqual(config.open_target.processor, "metapc")
        self.assertEqual(config.open_target.plugin_options, ("objc:off",))
        self.assertEqual(config.debugger.backend_candidates, ("win32", "linux"))
        self.assertEqual(config.debugger.wait_for_suspend_ms, 250)
        self.assertFalse(config.debugger.launch_use_request_default)
        self.assertTrue(config.debugger.remote_enabled)
        self.assertTrue(config.hexrays.enable_experimental_microcode)
        self.assertFalse(config.managed_decompiler.enabled)
        self.assertEqual(config.managed_decompiler.command, "ilspycmd")
        self.assertEqual(config.managed_decompiler.timeout_sec, 7)

    def test_server_version_is_not_read_from_setting_toml(self) -> None:
        """server_version 不允许在 setting.toml 中形成第二事实来源。"""
        with self.assertRaisesRegex(ConfigurationError, "server.server_version 已废弃"):
            self._load_temp_config(_config_text(server_fields='server_version = "9.9.9"'))

    def test_invalid_scalar_types_raise_configuration_error(self) -> None:
        """已出现但类型错误的字段不得静默回退到默认值。"""
        cases = (
            (
                _config_text(logging_fields="level = 1"),
                "logging.level 必须是字符串",
            ),
            (
                _config_text(server_fields='isolated_contexts = "true"'),
                "server.isolated_contexts 必须是布尔值",
            ),
            (
                _config_text(limits_fields='default_page_size = "100"'),
                "limits.default_page_size 必须是整数",
            ),
            (
                _config_text(open_target_fields='plugin_options = "x"'),
                "open_target.plugin_options 必须是字符串数组",
            ),
            (
                _config_text(debugger_fields='backend_candidates = [1]'),
                "debugger.backend_candidates 必须是字符串数组",
            ),
            (
                _config_text(managed_decompiler_fields='enabled = "false"'),
                "managed_decompiler.enabled 必须是布尔值",
            ),
        )
        for content, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigurationError, message):
                    self._load_temp_config(content)


if __name__ == "__main__":
    unittest.main()
