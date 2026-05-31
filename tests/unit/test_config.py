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
) -> str:
    """生成包含必需段落的最小 setting.toml。"""
    return f"""
[logging]
{logging_fields}
[server]
{server_fields}
[runtime_workspace]
{runtime_workspace_fields}
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
        self.assertEqual(config.limits.default_page_size, 100)
        self.assertEqual(config.external_analyzers, ())

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
        )
        for content, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigurationError, message):
                    self._load_temp_config(content)


if __name__ == "__main__":
    unittest.main()
