"""headless 集成测试运行器。"""

from __future__ import annotations

import argparse
import importlib
import sys
import unittest
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    """打开 fixture 后执行 integration 测试。"""
    parser = argparse.ArgumentParser(description="运行 ida-stdio-mcp headless 集成测试")
    parser.add_argument("binary", type=Path, help="待分析样本路径")
    args = parser.parse_args(argv)
    if not args.binary.exists():
        print(f"样本不存在：{args.binary}", file=sys.stderr)
        return 1

    import os

    os.environ["IDA_STDIO_MCP_TEST_BINARY"] = str(args.binary.resolve())
    sys.path.insert(0, str(Path.cwd()))
    _ = importlib.import_module("tests.integration.test_headless_tools")
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(Path("tests/integration")),
        top_level_dir=str(Path.cwd()),
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1
