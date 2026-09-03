"""Windows launch 目标的 Job Object 生命周期约束。"""

from __future__ import annotations

import os
from ctypes import (
    Structure,
    WinDLL,
    byref,
    c_size_t,
    c_ulong,
    c_ulonglong,
    c_void_p,
    get_last_error,
    sizeof,
)
from ctypes.wintypes import BOOL, DWORD, HANDLE, LPCWSTR, WORD

from ida_re_mcp.worker.errors import CapabilityError, WorkerError

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010
_MEM_COMMIT = 0x1000
_IMAGE_FILE_MACHINE_UNKNOWN = 0x0000
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664


class _IoCounters(Structure):
    _fields_ = [
        ("ReadOperationCount", c_ulonglong),
        ("WriteOperationCount", c_ulonglong),
        ("OtherOperationCount", c_ulonglong),
        ("ReadTransferCount", c_ulonglong),
        ("WriteTransferCount", c_ulonglong),
        ("OtherTransferCount", c_ulonglong),
    ]


class _BasicLimitInformation(Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", c_ulonglong),
        ("PerJobUserTimeLimit", c_ulonglong),
        ("LimitFlags", DWORD),
        ("MinimumWorkingSetSize", c_size_t),
        ("MaximumWorkingSetSize", c_size_t),
        ("ActiveProcessLimit", DWORD),
        ("Affinity", c_size_t),
        ("PriorityClass", DWORD),
        ("SchedulingClass", DWORD),
    ]


class _ExtendedLimitInformation(Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", c_size_t),
        ("JobMemoryLimit", c_size_t),
        ("PeakProcessMemoryUsed", c_size_t),
        ("PeakJobMemoryUsed", c_size_t),
    ]


class _MemoryBasicInformation(Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("PartitionId", WORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class WindowsJob:
    """关闭句柄时终止全部已归属 launch 进程。"""

    def __init__(self) -> None:
        if os.name != "nt":
            raise CapabilityError(
                "动态调试只支持 Windows 本机 x86 和 x64",
                capability="windows_local_debugger",
            )
        self._kernel32 = WinDLL("kernel32", use_last_error=True)
        self._configure_signatures()
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise WorkerError(
                "job_object_failed",
                "无法创建 Windows Job Object",
                details={"winerror": get_last_error()},
            )
        self._handle: HANDLE | None = HANDLE(handle)
        information = _ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self._kernel32.SetInformationJobObject(
            self._require_handle(),
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            byref(information),
            sizeof(information),
        ):
            winerror = get_last_error()
            self.close()
            raise WorkerError(
                "job_object_failed",
                "无法设置 KILL_ON_JOB_CLOSE",
                details={"winerror": winerror},
            )

    def _configure_signatures(self) -> None:
        self._kernel32.CreateJobObjectW.argtypes = [c_void_p, LPCWSTR]
        self._kernel32.CreateJobObjectW.restype = HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            HANDLE,
            c_ulong,
            c_void_p,
            DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = BOOL
        self._kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
        self._kernel32.OpenProcess.restype = HANDLE
        self._kernel32.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = BOOL
        self._kernel32.IsProcessInJob.argtypes = [HANDLE, HANDLE, c_void_p]
        self._kernel32.IsProcessInJob.restype = BOOL
        self._kernel32.CloseHandle.argtypes = [HANDLE]
        self._kernel32.CloseHandle.restype = BOOL

    def assign(self, pid: int) -> None:
        """把真实 PROCESS_STARTED PID 加入 Job Object。"""

        if isinstance(pid, bool) or pid <= 0:
            raise WorkerError("job_assignment_failed", "launch 目标 PID 无效")
        handle = self._require_handle()
        access = _PROCESS_TERMINATE | _PROCESS_SET_QUOTA | _PROCESS_QUERY_LIMITED_INFORMATION
        process = self._kernel32.OpenProcess(access, False, pid)
        if not process:
            raise WorkerError(
                "job_assignment_failed",
                "无法打开 launch 目标进程以加入 Job Object",
                details={"pid": pid, "winerror": get_last_error()},
            )
        try:
            if not self._kernel32.AssignProcessToJobObject(handle, process):
                raise WorkerError(
                    "job_assignment_failed",
                    "无法把 launch 目标加入 Job Object",
                    details={"pid": pid, "winerror": get_last_error()},
                )
            assigned = BOOL()
            if not self._kernel32.IsProcessInJob(process, handle, byref(assigned)):
                raise WorkerError(
                    "job_assignment_failed",
                    "无法验证 launch 目标的 Job Object 归属",
                    details={"pid": pid, "winerror": get_last_error()},
                )
            if not assigned.value:
                raise WorkerError(
                    "job_assignment_failed",
                    "launch 目标未实际归属 Job Object",
                    details={"pid": pid},
                )
        finally:
            self._kernel32.CloseHandle(process)

    def close(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        if not self._kernel32.CloseHandle(handle):
            raise WorkerError(
                "job_object_failed",
                "无法关闭 Windows Job Object",
                details={"winerror": get_last_error()},
            )

    def _require_handle(self) -> HANDLE:
        handle = self._handle
        if handle is None or not handle.value:
            raise WorkerError("job_object_closed", "Windows Job Object 已关闭")
        return handle

    def __enter__(self) -> WindowsJob:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


def verify_process_architecture(pid: int, *, bitness: int) -> None:
    """确认真实 launch/attach 目标与 x86/x64 IDB 的位数一致。"""

    if os.name != "nt":
        raise CapabilityError(
            "动态调试只支持 Windows 本机 x86 和 x64",
            capability="windows_local_debugger",
        )
    expected_machine = {
        32: _IMAGE_FILE_MACHINE_I386,
        64: _IMAGE_FILE_MACHINE_AMD64,
    }.get(bitness)
    if expected_machine is None or isinstance(bitness, bool):
        raise CapabilityError(
            "动态调试只支持 32 位 x86 和 64 位 x64 IDB",
            capability="windows_local_debugger",
            details={"bitness": bitness},
        )
    if isinstance(pid, bool) or pid <= 0:
        raise WorkerError("debug_process_query_failed", "目标进程 PID 无效")
    kernel32 = WinDLL("kernel32", use_last_error=True)
    try:
        is_wow64_process2 = kernel32.IsWow64Process2
    except AttributeError as exc:
        raise CapabilityError(
            "当前 Windows 不提供 IsWow64Process2",
            capability="windows_local_debugger",
        ) from exc
    kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    kernel32.OpenProcess.restype = HANDLE
    is_wow64_process2.argtypes = [HANDLE, c_void_p, c_void_p]
    is_wow64_process2.restype = BOOL
    kernel32.CloseHandle.argtypes = [HANDLE]
    kernel32.CloseHandle.restype = BOOL
    process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not process:
        raise WorkerError(
            "debug_process_query_failed",
            "无法打开目标进程以验证架构",
            details={"pid": pid, "winerror": get_last_error()},
        )
    try:
        process_machine = WORD()
        native_machine = WORD()
        if not is_wow64_process2(
            process,
            byref(process_machine),
            byref(native_machine),
        ):
            raise WorkerError(
                "debug_process_query_failed",
                "Windows 无法返回目标进程架构",
                details={"pid": pid, "winerror": get_last_error()},
            )
    finally:
        kernel32.CloseHandle(process)
    effective_machine = (
        int(native_machine.value)
        if int(process_machine.value) == _IMAGE_FILE_MACHINE_UNKNOWN
        else int(process_machine.value)
    )
    if effective_machine != expected_machine:
        raise CapabilityError(
            "目标进程架构与 IDB 不一致，请使用位数相同的 Windows x86 或 x64 进程",
            capability="windows_local_debugger",
            details={
                "pid": pid,
                "idb_bitness": bitness,
                "expected_machine": f"0x{expected_machine:04x}",
                "process_machine": f"0x{int(process_machine.value):04x}",
                "native_machine": f"0x{int(native_machine.value):04x}",
            },
        )


def query_process_memory(pid: int) -> list[dict[str, object]]:
    """用 Windows VirtualQueryEx 读取目标的真实已提交内存映射。"""

    if os.name != "nt":
        raise CapabilityError(
            "进程内存映射首版只支持 Windows",
            capability="windows_memory_maps",
        )
    kernel32 = WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    kernel32.OpenProcess.restype = HANDLE
    kernel32.VirtualQueryEx.argtypes = [
        HANDLE,
        c_void_p,
        c_void_p,
        c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = c_size_t
    kernel32.CloseHandle.argtypes = [HANDLE]
    kernel32.CloseHandle.restype = BOOL
    process = kernel32.OpenProcess(
        _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ,
        False,
        pid,
    )
    if not process:
        raise WorkerError(
            "debug_memory_unavailable",
            "无法打开目标进程以读取内存映射",
            details={"pid": pid},
        )
    mappings: list[dict[str, object]] = []
    address = 0
    try:
        while address < (1 << 64) - 1:
            information = _MemoryBasicInformation()
            result = int(
                kernel32.VirtualQueryEx(
                    process,
                    c_void_p(address),
                    byref(information),
                    sizeof(information),
                )
            )
            if result == 0:
                break
            base = int(information.BaseAddress or 0)
            size = int(information.RegionSize)
            if size <= 0 or base + size <= address:
                break
            if int(information.State) == _MEM_COMMIT:
                mappings.append(
                    {
                        "start": f"0x{base:x}",
                        "end": f"0x{base + size:x}",
                        "allocation_base": f"0x{int(information.AllocationBase or 0):x}",
                        "allocation_protection": int(information.AllocationProtect),
                        "protection": int(information.Protect),
                        "state": int(information.State),
                        "type": int(information.Type),
                        "source": "windows_virtual_query_ex",
                    }
                )
            address = base + size
    finally:
        kernel32.CloseHandle(process)
    if not mappings:
        raise WorkerError(
            "debug_memory_unavailable",
            "Windows 未返回目标进程内存映射",
            details={"pid": pid},
        )
    return mappings
