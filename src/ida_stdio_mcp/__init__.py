"""ida-stdio-mcp 包入口。"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .main import main as main


def main(argv: list[str] | None = None) -> int:
    """惰性导入命令行入口，避免普通模块导入时强制加载 IDA。"""
    from .main import main as real_main

    return real_main(argv)

__all__ = ["main"]
