"""外部分析器和 artifact 关联单元测试。"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from ida_stdio_mcp.analysis_artifacts import external_analyzer_health, import_analysis_artifact, run_external_analyzer
from ida_stdio_mcp.config import ExternalAnalyzerConfig, RuntimeWorkspaceConfig
from ida_stdio_mcp.core.artifacts import ArtifactCoreMixin
from ida_stdio_mcp.models import JsonObject, JsonValue
from ida_stdio_mcp.runtime_workspace import configure_runtime_workspace, get_runtime_workspace_paths


class DummyArtifactCore(ArtifactCoreMixin):
    """用于测试 artifact mixin 的最小核心对象。"""

    def _json_object(self, value: object) -> JsonObject:
        """把对象收窄为 JSON 对象。"""
        if not isinstance(value, dict):
            raise TypeError("期望 JSON 对象")
        mapping = cast(dict[object, object], value)
        return {str(key): self._json_value(item) for key, item in mapping.items()}

    def _json_value(self, value: object) -> JsonValue:
        """把对象转换为 JSON 值。"""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            values = cast(list[object], value)
            return [self._json_value(item) for item in values]
        if isinstance(value, dict):
            mapping = cast(dict[object, object], value)
            return {str(key): self._json_value(item) for key, item in mapping.items()}
        return str(value)

    def list_functions(self, *, filter_text: str = "", offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """返回固定函数列表。"""
        functions: list[JsonObject] = [
            {"addr": "0x401000", "name": "dispatch_main", "size": 32},
            {"addr": "0x402000", "name": "load_resource", "size": 24},
        ]
        lowered = filter_text.lower()
        if lowered:
            functions = [item for item in functions if lowered in str(item.get("name", "")).lower()]
        return functions[offset : offset + limit]

    def disassembly_lines(self, start_ea: int) -> list[JsonObject]:
        """返回带间接跳转和 hash 混合的反汇编行。"""
        if start_ea == 0x401000:
            return [
                {"addr": "0x401000", "text": "imul eax, eax, 0x01000193"},
                {"addr": "0x401004", "text": "xor eax, ecx"},
                {"addr": "0x401008", "text": "jmp qword ptr [rax*8+jpt_401000] ; switch jumptable"},
            ]
        return [{"addr": "0x402000", "text": "ret"}]

    def function_constants(self, start_ea: int) -> list[int]:
        """返回固定立即数。"""
        if start_ea == 0x401000:
            return [0x01000193, 0x1234]
        return []

    def get_function_profile(self, query: str, *, include_asm: bool = True) -> JsonObject:
        """返回固定函数画像。"""
        ea = self.parse_address(query)
        return {"addr": hex(ea), "name": self.best_name(ea), "include_asm": include_asm}

    def best_name(self, ea: int) -> str:
        """返回固定名称。"""
        return "dispatch_main" if ea == 0x401000 else f"sub_{ea:x}"

    def parse_address(self, value: str) -> int:
        """解析十六进制地址或固定符号。"""
        if value == "dispatch_main":
            return 0x401000
        return int(value, 0)

    def find_strings(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """模拟字符串搜索。"""
        if pattern == "thumb_ev01_01":
            return {"data": [{"addr": "0x500000", "string": pattern}], "next_offset": None}
        return {"data": [], "next_offset": None}


class FailingScanArtifactCore(DummyArtifactCore):
    """模拟函数扫描阶段失败的核心对象。"""

    def function_constants(self, start_ea: int) -> list[int]:
        """模拟 IDA 常量读取失败。"""
        raise RuntimeError(f"constants failed at {hex(start_ea)}")


class FailingCorrelateArtifactCore(DummyArtifactCore):
    """模拟 artifact 关联阶段部分失败的核心对象。"""

    def get_function_profile(self, query: str, *, include_asm: bool = True) -> JsonObject:
        """模拟地址关联读取函数画像失败。"""
        raise RuntimeError(f"profile failed for {query}")

    def find_strings(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """模拟字符串索引不可用。"""
        raise RuntimeError(f"string index failed for {pattern}")


class AnalysisArtifactTests(unittest.TestCase):
    """覆盖外部分析 artifact 的导入、执行和关联。"""

    def test_run_external_analyzer_imports_json_output(self) -> None:
        """配置型外部分析器可执行并导入 JSON 输出。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                input_path = root / "input.bin"
                input_path.write_bytes(b"sample")
                analyzer = ExternalAnalyzerConfig(
                    name="json-writer",
                    command=(
                        sys.executable,
                        "-c",
                        "import json, pathlib, sys; pathlib.Path(sys.argv[2]).write_text(json.dumps({'input': sys.argv[1], 'hash': '0x01000193', 'string': 'thumb_ev01_01'}), encoding='utf-8')",
                        "{input}",
                        "{output}",
                    ),
                    timeout_sec=10,
                )

                result = run_external_analyzer((analyzer,), name="json-writer", input_path=str(input_path))

                self.assertEqual(result.get("status"), "ok")
                data = result.get("data")
                self.assertIsInstance(data, dict)
                assert isinstance(data, dict)
                artifact = data.get("json_artifact")
                self.assertIsInstance(artifact, dict)
                assert isinstance(artifact, dict)
                self.assertIsInstance(artifact.get("artifact_id"), str)
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )

    def test_external_analyzer_placeholder_entry_is_checked_after_render(self) -> None:
        """命令入口使用占位符时，应在运行时渲染后再检查可执行性。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                analyzer = ExternalAnalyzerConfig(
                    name="placeholder-entry",
                    command=(
                        "{input}",
                        "-c",
                        "import json, pathlib, sys; pathlib.Path(sys.argv[1]).write_text(json.dumps({'ok': True}), encoding='utf-8')",
                        "{output}",
                    ),
                    timeout_sec=10,
                )

                state = external_analyzer_health((analyzer,))
                result = run_external_analyzer((analyzer,), name="placeholder-entry", input_path=sys.executable)

                self.assertEqual(state["status"], "uninitialized")
                self.assertEqual(result["status"], "ok")
                data = result.get("data")
                self.assertIsInstance(data, dict)
                assert isinstance(data, dict)
                command = data.get("command")
                self.assertIsInstance(command, list)
                assert isinstance(command, list)
                self.assertEqual(command[0], sys.executable)
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )

    def test_external_analyzer_health_reports_missing_command(self) -> None:
        """配置存在但命令不可执行时应进入 misconfigured。"""
        analyzer = ExternalAnalyzerConfig(
            name="missing",
            command=("definitely-missing-external-analyzer-for-test",),
            timeout_sec=10,
        )

        state = external_analyzer_health((analyzer,))
        result = run_external_analyzer((analyzer,), name="missing", input_path="<输入文件>")

        self.assertEqual(state["status"], "misconfigured")
        self.assertEqual(result["status"], "unsupported")
        data = result.get("data")
        self.assertIsInstance(data, dict)
        assert isinstance(data, dict)
        self.assertEqual(data.get("capability_status"), "misconfigured")

    def test_external_analyzer_timeout_is_explicit_error(self) -> None:
        """外部分析器超时应和非 JSON、退出码失败区分开。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                input_path = root / "input.bin"
                input_path.write_bytes(b"sample")
                analyzer = ExternalAnalyzerConfig(
                    name="slow",
                    command=(sys.executable, "-c", "import time; time.sleep(2)"),
                    timeout_sec=1,
                )

                result = run_external_analyzer((analyzer,), name="slow", input_path=str(input_path))

                self.assertEqual(result["status"], "error")
                data = result.get("data")
                self.assertIsInstance(data, dict)
                assert isinstance(data, dict)
                self.assertEqual(data.get("reason"), "timeout")
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )

    def test_external_analyzer_invalid_json_is_degraded(self) -> None:
        """产物不是 JSON 时不能假装已导入 artifact。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                input_path = root / "input.bin"
                input_path.write_bytes(b"sample")
                analyzer = ExternalAnalyzerConfig(
                    name="bad-json",
                    command=(sys.executable, "-c", "import sys; print('not json')"),
                    timeout_sec=10,
                )

                result = run_external_analyzer((analyzer,), name="bad-json", input_path=str(input_path))

                self.assertEqual(result["status"], "degraded")
                warnings = result.get("warnings")
                self.assertIsInstance(warnings, list)
                assert isinstance(warnings, list)
                self.assertIn("stdout 不是 JSON，未导入 analysis artifact。", warnings)
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )

    def test_scan_dispatchers_and_correlate_artifact(self) -> None:
        """通用 dispatcher 扫描和 artifact 关联可在无 IDA stub 上验证。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                artifact_path = root / "analysis.json"
                artifact_path.write_text(
                    json.dumps(
                        {
                            "hash": "0x01000193",
                            "addr": "0x401000",
                            "native": "dispatch_main",
                            "resource": "thumb_ev01_01",
                        }
                    ),
                    encoding="utf-8",
                )
                imported = import_analysis_artifact(artifact_path)
                record = imported.get("record")
                self.assertIsInstance(record, dict)
                assert isinstance(record, dict)
                artifact_id = record.get("artifact_id")
                self.assertIsInstance(artifact_id, str)
                assert isinstance(artifact_id, str)
                core = DummyArtifactCore()

                dispatchers = core.scan_dispatchers()
                self.assertEqual(dispatchers.get("status"), "ok")
                dispatch_data = dispatchers.get("data")
                self.assertIsInstance(dispatch_data, dict)
                assert isinstance(dispatch_data, dict)
                items = dispatch_data.get("items")
                self.assertIsInstance(items, list)
                assert isinstance(items, list)
                self.assertGreater(len(items), 0)
                first = items[0]
                self.assertIsInstance(first, dict)
                assert isinstance(first, dict)
                patterns = first.get("patterns")
                self.assertIsInstance(patterns, list)
                assert isinstance(patterns, list)
                self.assertIn("hash_mixing_or_hash_constants", patterns)

                correlated = core.correlate_analysis_artifact(artifact_id=artifact_id)
                self.assertEqual(correlated.get("status"), "ok")
                correlated_data = correlated.get("data")
                self.assertIsInstance(correlated_data, dict)
                assert isinstance(correlated_data, dict)
                matches = correlated_data.get("matches")
                self.assertIsInstance(matches, dict)
                assert isinstance(matches, dict)
                self.assertTrue(matches.get("addresses"))
                self.assertTrue(matches.get("hashes"))
                self.assertTrue(matches.get("strings"))
                self.assertTrue(matches.get("function_names"))
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )

    def test_artifact_failures_are_reported_as_degraded(self) -> None:
        """扫描和关联失败不得静默变成空结果。"""
        previous_paths = get_runtime_workspace_paths()
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                configure_runtime_workspace(RuntimeWorkspaceConfig(directory=root / "runtime", symbol_cache_directory=root / "symbols"))
                artifact_path = root / "analysis.json"
                artifact_path.write_text(
                    json.dumps(
                        {
                            "addr": "0x401000",
                            "resource": "thumb_ev01_01",
                        }
                    ),
                    encoding="utf-8",
                )
                imported = import_analysis_artifact(artifact_path)
                record = imported.get("record")
                self.assertIsInstance(record, dict)
                assert isinstance(record, dict)
                artifact_id = record.get("artifact_id")
                self.assertIsInstance(artifact_id, str)
                assert isinstance(artifact_id, str)

                dispatchers = FailingScanArtifactCore().scan_dispatchers()
                self.assertEqual(dispatchers.get("status"), "degraded")
                scan_warnings = dispatchers.get("warnings")
                self.assertIsInstance(scan_warnings, list)
                assert isinstance(scan_warnings, list)
                self.assertTrue(scan_warnings)
                scan_data = dispatchers.get("data")
                self.assertIsInstance(scan_data, dict)
                assert isinstance(scan_data, dict)
                failed_functions = scan_data.get("failed_functions")
                self.assertIsInstance(failed_functions, int)
                assert isinstance(failed_functions, int)
                self.assertGreater(failed_functions, 0)
                self.assertTrue(scan_data.get("diagnostics"))

                correlated = FailingCorrelateArtifactCore().correlate_analysis_artifact(artifact_id=artifact_id)
                self.assertEqual(correlated.get("status"), "degraded")
                correlate_warnings = correlated.get("warnings")
                self.assertIsInstance(correlate_warnings, list)
                assert isinstance(correlate_warnings, list)
                self.assertTrue(correlate_warnings)
                correlated_data = correlated.get("data")
                self.assertIsInstance(correlated_data, dict)
                assert isinstance(correlated_data, dict)
                diagnostics = correlated_data.get("diagnostics")
                self.assertIsInstance(diagnostics, list)
                assert isinstance(diagnostics, list)
                stages = {str(item.get("stage")) for item in diagnostics if isinstance(item, dict)}
                self.assertIn("address", stages)
                self.assertIn("string", stages)
            finally:
                configure_runtime_workspace(
                    RuntimeWorkspaceConfig(
                        directory=previous_paths.directory,
                        symbol_cache_directory=previous_paths.symbol_cache_directory,
                    )
                )


if __name__ == "__main__":
    unittest.main()
