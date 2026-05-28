"""文档、skill 与当前 MCP 工具面的对齐测试。"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from ida_stdio_mcp.runtime import HeadlessRuntime
from ida_stdio_mcp.service import build_service


PUBLIC_DOCUMENTS = (
    Path("README.md"),
    Path("docs/能力矩阵.md"),
    Path("skills/ida-stdio-mcp/SKILL.md"),
    Path("skills/ida-stdio-mcp/references/tool-surfaces.md"),
    Path("skills/ida-stdio-mcp/references/expert.md"),
    Path("skills/ida-stdio-mcp/references/workflows.md"),
    Path("skills/ida-stdio-mcp/references/troubleshooting.md"),
)

FORBIDDEN_PUBLIC_TERMS = (
    "--unsafe",
    "--debugger",
    "allow_unsafe",
    "allow_debugger",
    "feature_gates",
    "featureGate",
    "GateName",
    "安全门控",
    "危险能力",
    "硬门控",
    "需启用",
    "`slim`",
    "`full`",
    "`expert`",
    "full/expert",
)

TOOL_PREFIXES = (
    "analyze_",
    "append_",
    "apply_",
    "build_",
    "close_",
    "convert_",
    "debug_",
    "declare_",
    "decompile_",
    "define_",
    "delete_",
    "disassemble_",
    "evaluate_",
    "execute_",
    "explain_",
    "export_",
    "find_",
    "get_",
    "infer_",
    "inspect_",
    "investigate_",
    "list_",
    "microcode_",
    "open_",
    "patch_",
    "query_",
    "read_",
    "rename_",
    "run_",
    "save_",
    "search_",
    "set_",
    "trace_",
    "triage_",
    "undefine_",
    "upsert_",
    "write_",
)
REMOVED_PUBLIC_TOOLS = {
    "apply_types",
    "debug_registers_all_threads",
    "debug_registers_thread",
    "debug_general_registers",
    "debug_general_registers_thread",
    "debug_named_registers",
    "debug_named_registers_thread",
}


class DocumentationAlignmentTests(unittest.TestCase):
    """校验用户可见文档与注册工具保持一致。"""

    tool_names: set[str] = set()

    @staticmethod
    def _repo_root() -> Path:
        """返回仓库根目录。"""
        return Path(__file__).resolve().parents[2]

    @classmethod
    def setUpClass(cls) -> None:
        """读取当前服务实际注册的工具名。"""
        service = build_service(HeadlessRuntime(), tool_surface="all")
        cls.tool_names = {str(tool["name"]) for tool in service.tools.list_tools()}

    def test_public_docs_do_not_reference_removed_gate_terms(self) -> None:
        """公开文档不得再描述启动门槛或旧工具面。"""
        failures: list[str] = []
        for relative_path in PUBLIC_DOCUMENTS:
            content = (self._repo_root() / relative_path).read_text(encoding="utf-8")
            for term in FORBIDDEN_PUBLIC_TERMS:
                if term in content:
                    failures.append(f"{relative_path}: {term}")
        self.assertEqual(failures, [])

    def test_public_docs_reference_existing_tools(self) -> None:
        """公开文档中反引号包裹的工具名必须存在于当前 all 工具面。"""
        missing: list[str] = []
        token_pattern = re.compile(r"`([a-z][a-z0-9_]+)`")
        for relative_path in PUBLIC_DOCUMENTS:
            content = (self._repo_root() / relative_path).read_text(encoding="utf-8")
            tokens = sorted(set(token_pattern.findall(content)))
            for token in tokens:
                if not token.startswith(TOOL_PREFIXES):
                    continue
                if token not in self.tool_names:
                    missing.append(f"{relative_path}: {token}")
        self.assertEqual(missing, [])

    def test_removed_duplicate_tools_are_not_registered(self) -> None:
        """重复入口不得出现在当前 all 工具面。"""
        self.assertEqual(self.tool_names & REMOVED_PUBLIC_TOOLS, set())


if __name__ == "__main__":
    unittest.main()
