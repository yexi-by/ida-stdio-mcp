"""统一管理运行时副作用目录。"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Generator

from .config import RuntimeWorkspaceConfig


@dataclass(slots=True, frozen=True)
class RuntimeWorkspacePaths:
    """运行时副作用目录。"""

    directory: Path
    symbol_cache_directory: Path


_workspace_paths: RuntimeWorkspacePaths | None = None
_workspace_lock = RLock()


def configure_runtime_workspace(config: RuntimeWorkspaceConfig) -> RuntimeWorkspacePaths:
    """初始化运行时副作用目录。"""
    directory = config.directory.resolve()
    symbol_cache_directory = config.symbol_cache_directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    symbol_cache_directory.mkdir(parents=True, exist_ok=True)
    paths = RuntimeWorkspacePaths(
        directory=directory,
        symbol_cache_directory=symbol_cache_directory,
    )
    global _workspace_paths
    with _workspace_lock:
        _workspace_paths = paths
    return paths


def get_runtime_workspace_paths() -> RuntimeWorkspacePaths:
    """读取当前运行时副作用目录。"""
    global _workspace_paths
    with _workspace_lock:
        paths = _workspace_paths
        if paths is None:
            directory = (Path.cwd() / ".runtime").resolve()
            symbol_cache_directory = (directory / "symbol-cache").resolve()
            directory.mkdir(parents=True, exist_ok=True)
            symbol_cache_directory.mkdir(parents=True, exist_ok=True)
            paths = RuntimeWorkspacePaths(
                directory=directory,
                symbol_cache_directory=symbol_cache_directory,
            )
            _workspace_paths = paths
    return paths


@contextmanager
def symbol_cache_scope() -> Generator[RuntimeWorkspacePaths, None, None]:
    """在统一符号缓存目录内执行会话打开。"""
    paths = get_runtime_workspace_paths()
    previous_cwd = Path.cwd()
    previous_alt_symbol_path = os.environ.get("_NT_ALT_SYMBOL_PATH")
    os.chdir(paths.symbol_cache_directory)
    if previous_alt_symbol_path is None or not previous_alt_symbol_path.strip():
        os.environ["_NT_ALT_SYMBOL_PATH"] = str(paths.symbol_cache_directory)
    try:
        yield paths
    finally:
        os.chdir(previous_cwd)
        if previous_alt_symbol_path is None:
            os.environ.pop("_NT_ALT_SYMBOL_PATH", None)
        else:
            os.environ["_NT_ALT_SYMBOL_PATH"] = previous_alt_symbol_path
