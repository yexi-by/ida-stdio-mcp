"""目录扫描单元测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ida_stdio_mcp.directory_analysis import DirectoryAnalysisPolicy, detect_binary_kind, iter_candidate_files


class DirectoryAnalysisTests(unittest.TestCase):
    """覆盖候选识别与排序。"""

    @staticmethod
    def _fixture_root() -> Path:
        return Path(__file__).resolve().parents[1] / "fixtures"

    def test_detect_binary_kind_from_magic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            elf_path = root / "sample.elf"
            elf_path.write_bytes(b"\x7fELFdummy")
            self.assertEqual(detect_binary_kind(elf_path), "elf")

    def test_detect_binary_kind_from_minimal_pe_fixture(self) -> None:
        fixture = self._fixture_root() / "minimal_pe.exe"
        self.assertEqual(detect_binary_kind(fixture), "pe")

    def test_iter_candidate_files_skips_duplicates_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            exe_path = root / "app.exe"
            dup_path = root / "copy.exe"
            text_path = root / "notes.txt"
            content = b"MZ" + b"\x00" * 64
            exe_path.write_bytes(content)
            dup_path.write_bytes(content)
            text_path.write_text("hello", encoding="utf-8")

            results = iter_candidate_files(
                root,
                recursive=False,
                include_extensions=(".exe", ".dll", ".elf"),
                exclude_patterns=(),
                policy=DirectoryAnalysisPolicy(
                    prefer_managed=False,
                    prefer_native=False,
                    prefer_entry_binary=True,
                    prefer_user_code=True,
                    scoring_profile="default",
                ),
            )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].binary_kind, "pe")
            self.assertEqual(results[0].path.name, "app.exe")

    def test_iter_candidate_files_prioritizes_unity_user_code(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            managed = root / "Game_Data" / "Managed"
            managed.mkdir(parents=True)
            assembly = managed / "Assembly-CSharp.dll"
            runtime_lib = managed / "UnityEngine.CoreModule.dll"
            assembly.write_bytes(b"MZ" + b"\x01" * 128)
            runtime_lib.write_bytes(b"MZ" + b"\x02" * 128)

            results = iter_candidate_files(
                root,
                recursive=True,
                include_extensions=(".dll",),
                exclude_patterns=(),
                policy=DirectoryAnalysisPolicy(
                    prefer_managed=True,
                    prefer_native=False,
                    prefer_entry_binary=False,
                    prefer_user_code=True,
                    scoring_profile="managed_first",
                ),
            )

            self.assertGreaterEqual(len(results), 2)
            self.assertEqual(results[0].path.name, "Assembly-CSharp.dll")


if __name__ == "__main__":
    unittest.main()
