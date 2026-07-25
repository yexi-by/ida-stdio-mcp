"""隔离 IDAPython 动态导入与 owner 线程检查。

普通 Python 进程可以安全导入本模块。只有实际执行 worker 操作时才会触发
IDA 模块加载。
"""

from __future__ import annotations

import importlib
import threading
from dataclasses import dataclass
from types import ModuleType

from ida_re_mcp.worker.errors import CapabilityError, WorkerError


@dataclass(frozen=True, slots=True)
class IdaModules:
    """按名字保存已经确认存在的 IDAPython 模块。"""

    modules: dict[str, ModuleType]

    def __getattr__(self, name: str) -> ModuleType:
        try:
            return self.modules[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def require_ida(*module_names: str) -> IdaModules:
    """动态加载 IDAPython 模块; 普通解释器下返回明确能力错误。"""

    loaded: dict[str, ModuleType] = {}
    for module_name in module_names:
        if not module_name.startswith("ida_") and module_name != "idautils":
            raise ValueError(f"非法 IDAPython 模块名: {module_name}")
        try:
            loaded[module_name] = importlib.import_module(module_name)
        except (ImportError, OSError) as exc:
            raise CapabilityError(
                "当前进程没有可用的 IDA Pro 9.3+ IDAPython 运行时",
                capability="ida_runtime",
                details={"module": module_name, "reason": type(exc).__name__},
            ) from exc
    return IdaModules(loaded)


class OwnerThreadBound:
    """保证全部 IDA API 调用都发生在创建 worker 的线程。"""

    def __init__(self) -> None:
        self._owner_thread_id = threading.get_ident()

    def _assert_owner_thread(self) -> None:
        if threading.get_ident() != self._owner_thread_id:
            raise WorkerError(
                "worker_thread_violation",
                "IDA API 只能由创建 worker 的 owner 线程调用",
            )
