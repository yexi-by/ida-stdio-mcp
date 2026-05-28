"""脚本执行大结果落盘测试。"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from ida_stdio_mcp.config import RuntimeWorkspaceConfig
from ida_stdio_mcp.core.script import ScriptCoreMixin
from ida_stdio_mcp.models import JsonObject, JsonValue
from ida_stdio_mcp.runtime_workspace import configure_runtime_workspace, get_runtime_workspace_paths


class DummyScriptCore(ScriptCoreMixin):
    """用于单测脚本 mixin 的最小核心对象。"""

    def jsonify(self, value: object) -> JsonValue:
        """把 Python 对象转换成 JSON 值。"""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            values = cast(list[object], value)
            return [self.jsonify(item) for item in values]
        if isinstance(value, dict):
            mapping = cast(dict[object, object], value)
            return {str(key): self.jsonify(item) for key, item in mapping.items()}
        return str(value)

    def _json_object(self, value: object) -> JsonObject:
        """把 Python 对象收窄成 JSON 对象。"""
        normalized = self.jsonify(value)
        if not isinstance(normalized, dict):
            raise TypeError("期望 JSON 对象")
        return normalized


class ScriptArtifactTests(unittest.TestCase):
    """验证 evaluate_python 大结果自动落盘契约。"""

    def test_large_result_is_saved_with_hash_size_and_schema(self) -> None:
        """result 超过返回阈值时写入 artifact 并返回元数据。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                core = DummyScriptCore()

                result = core.evaluate_python("result = list(range(5000))", max_output_chars=1000)

                artifacts = result.get("artifacts")
                self.assertIsInstance(artifacts, dict)
                assert isinstance(artifacts, dict)
                result_artifact = artifacts.get("result")
                self.assertIsInstance(result_artifact, dict)
                assert isinstance(result_artifact, dict)
                path_value = result_artifact.get("path")
                sha256_value = result_artifact.get("sha256")
                size_value = result_artifact.get("size")
                schema_value = result_artifact.get("schema")
                self.assertIsInstance(path_value, str)
                self.assertIsInstance(sha256_value, str)
                self.assertIsInstance(size_value, int)
                self.assertIsInstance(schema_value, dict)
                assert isinstance(path_value, str)
                assert isinstance(sha256_value, str)
                assert isinstance(schema_value, dict)
                schema_object = cast(JsonObject, schema_value)
                artifact_path = Path(path_value)
                content = artifact_path.read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(), sha256_value)
                self.assertEqual(len(content), size_value)
                decoded = json.loads(content.decode("utf-8"))
                self.assertIsInstance(decoded, list)
                self.assertEqual(decoded[:3], [0, 1, 2])
                self.assertEqual(schema_object.get("type"), "array")
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )

    def test_large_stdout_is_saved_with_hash_size_and_schema(self) -> None:
        """stdout 超过返回阈值时写入完整文本 artifact。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                core = DummyScriptCore()

                result = core.evaluate_python("print('x' * 5000)", max_output_chars=1000)

                artifacts = result.get("artifacts")
                self.assertIsInstance(artifacts, dict)
                assert isinstance(artifacts, dict)
                stdout_artifact = artifacts.get("stdout")
                self.assertIsInstance(stdout_artifact, dict)
                assert isinstance(stdout_artifact, dict)
                path_value = stdout_artifact.get("path")
                sha256_value = stdout_artifact.get("sha256")
                size_value = stdout_artifact.get("size")
                schema_value = stdout_artifact.get("schema")
                self.assertIsInstance(path_value, str)
                self.assertIsInstance(sha256_value, str)
                self.assertIsInstance(size_value, int)
                self.assertIsInstance(schema_value, dict)
                assert isinstance(path_value, str)
                assert isinstance(sha256_value, str)
                assert isinstance(schema_value, dict)
                schema_object = cast(JsonObject, schema_value)
                content = Path(path_value).read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(), sha256_value)
                self.assertEqual(len(content), size_value)
                self.assertEqual(content.decode("utf-8"), f"{'x' * 5000}\n")
                self.assertEqual(schema_object.get("type"), "string")
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )


if __name__ == "__main__":
    unittest.main()
