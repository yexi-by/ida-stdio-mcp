"""工具白名单 profile 加载器。"""

from __future__ import annotations

from pathlib import Path


def load_profile(path: Path) -> set[str]:
    """读取一行一个工具名的 profile 文件。"""
    lines = path.read_text(encoding="utf-8").splitlines()
    result: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        result.add(stripped)
    return result
