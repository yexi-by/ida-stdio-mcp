"""为隔离子进程选择不会额外派生 trampoline 的 Python。"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Final

_VENV_LAUNCHER_ENV: Final = "__PYVENV_LAUNCHER__"


def prepare_python_process_launch(
    environment: Mapping[str, str],
) -> tuple[str, dict[str, str]]:
    """返回当前环境对应的真实 Python 可执行文件和子进程环境。

    Windows venv 的 ``python.exe`` 可能只是 redirect executor。CPython 的
    multiprocessing 也会绕过这一层，并用 ``__PYVENV_LAUNCHER__`` 保留 venv
    的 ``sys.prefix`` 与 site-packages；这里沿用同一规则，使 Popen 跟踪的 PID
    就是真正运行 IDALib 的进程。
    """

    executable = sys.executable
    if not executable:
        raise RuntimeError("当前 Python 没有可用于启动 worker 的可执行文件")
    child_environment = dict(environment)
    if os.name != "nt":
        return executable, child_environment

    base_executable = getattr(sys, "_base_executable", None)
    if not isinstance(base_executable, str) or not base_executable:
        raise RuntimeError("当前 Windows Python 没有可用于启动 worker 的基础解释器")
    if _same_path(executable, base_executable):
        child_environment.pop(_VENV_LAUNCHER_ENV, None)
        return executable, child_environment

    base_path = Path(base_executable)
    if not base_path.is_file():
        raise RuntimeError("当前 Windows Python 的基础解释器不存在")
    child_environment[_VENV_LAUNCHER_ENV] = executable
    return str(base_path), child_environment


def _same_path(first: str, second: str) -> bool:
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))
