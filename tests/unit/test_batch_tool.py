"""批处理工具单元测试。"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

from ida_stdio_mcp.config import load_config
from ida_stdio_mcp.models import BinarySummary
from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.tool_registry import ToolRegistry
from ida_stdio_mcp.tools.batch import register_batch_tools


class _FakeRuntime:
    """只为批处理测试提供最小运行时桩。"""

    def __init__(self) -> None:
        self._current: BinarySummary | None = None
        self.opened_paths: list[Path] = []

    def current_binary_summary(self) -> BinarySummary | None:
        """返回当前激活数据库摘要。"""
        return self._current

    def open_binary(self, input_path: Path) -> BinarySummary:
        """记录打开动作并构造假的摘要。"""
        summary: BinarySummary = {
            "input_path": str(input_path),
            "idb_path": f"{input_path}.i64",
            "module": input_path.name,
            "binary_kind": "elf" if input_path.suffix.lower() == ".elf" else "pe",
            "analysis_domain": "native",
            "imagebase": "0x400000",
        }
        self._current = summary
        self.opened_paths.append(input_path)
        return summary

    def close_binary(self) -> None:
        """关闭当前数据库。"""
        self._current = None

    def survey_binary(self) -> dict[str, object]:
        """返回固定 survey 结果。"""
        return {
            "statistics": {
                "function_count": 3,
                "string_count": 1,
                "segment_count": 2,
                "entrypoint_count": 1,
            },
            "interesting_functions": [{"addr": "0x401000", "name": "main"}],
        }

    def decompile_function(self, query: str) -> dict[str, object]:
        """返回固定高层表示。"""
        return {
            "representation": "asm_fallback" if query == "main" else "hexrays",
            "language": "asm",
            "text": "push rbp",
            "warnings": ["Hex-Rays 不可用，已回退到汇编文本"],
        }


class BatchToolTests(unittest.TestCase):
    """验证 analyze_directory 的总入口行为。"""

    @staticmethod
    def _repo_root() -> Path:
        """返回仓库根目录。"""
        return Path(__file__).resolve().parents[2]

    def test_analyze_directory_returns_structured_summary(self) -> None:
        """目录分析应返回候选、已分析与跳过汇总。"""
        config = load_config(self._repo_root() / "setting.toml")
        runtime = cast(HeadlessRuntime, _FakeRuntime())
        registry = ToolRegistry()
        register_batch_tools(registry, runtime, config)

        result = registry.call(
            "analyze_directory",
            {
                "path": str(self._repo_root() / "tests" / "fixtures" / "mixed"),
                "recursive": True,
                "max_candidates": 10,
                "max_deep_analysis": 1,
                "include_extensions": [".elf", ".exe"],
                "exclude_patterns": ["*.txt"],
            },
        )

        self.assertEqual(result["status"], "ok")
        data = result["data"]
        self.assertIsInstance(data, dict)
        assert isinstance(data, dict)
        summary = data["summary"]
        self.assertIsInstance(summary, dict)
        assert isinstance(summary, dict)
        self.assertEqual(summary["candidate_count"], 2)
        self.assertEqual(summary["analyzed_count"], 1)
        self.assertEqual(summary["skipped_count"], 1)

        analyzed = data["analyzed"]
        self.assertIsInstance(analyzed, list)
        assert isinstance(analyzed, list)
        self.assertEqual(len(analyzed), 1)

        skipped = data["skipped"]
        self.assertIsInstance(skipped, list)
        assert isinstance(skipped, list)
        self.assertEqual(len(skipped), 1)


if __name__ == "__main__":
    unittest.main()
