"""IDA 调试器运行时能力。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import time_ns
from typing import Callable, Iterable, cast

from ..ida_bootstrap import ensure_ida_environment
from ..models import JsonObject, JsonValue
from ..runtime_workspace import get_runtime_workspace_paths

ensure_ida_environment()

import ida_dbg  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_idaapi  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_idd  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_name  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_nalt  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import idaapi  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。

BADADDR = ida_idaapi.BADADDR
ToolEnvelope = JsonObject

START_PROCESS = cast(Callable[[str, str, str], bool], ida_dbg.start_process)
ATTACH_PROCESS = cast(Callable[..., object], ida_dbg.attach_process)
EXIT_PROCESS = cast(Callable[[], None], ida_dbg.exit_process)
CONTINUE_PROCESS = cast(Callable[[], None], ida_dbg.continue_process)
STEP_INTO = ida_dbg.step_into
STEP_OVER = ida_dbg.step_over
STEP_UNTIL_RET = ida_dbg.step_until_ret
REQUEST_RUN_TO = cast(Callable[[int], bool], ida_dbg.request_run_to)
REQUEST_START_PROCESS = cast(Callable[[str, str, str], int], ida_dbg.request_start_process)
REQUEST_ATTACH_PROCESS = cast(Callable[[int, int], int], ida_dbg.request_attach_process)
RUN_REQUESTS_RAW = getattr(ida_dbg, "run_requests", None)
RUN_REQUESTS = cast(Callable[[], bool] | None, RUN_REQUESTS_RAW if callable(RUN_REQUESTS_RAW) else None)
GET_PROCESS_STATE = ida_dbg.get_process_state
GET_REG_VAL = cast(Callable[[str], object], ida_dbg.get_reg_val)
GET_BPT_QTY = ida_dbg.get_bpt_qty
GET_NTH_BPT = cast(Callable[[int, ida_dbg.bpt_t], bool], ida_dbg.getn_bpt)
ADD_BPT = cast(Callable[[int], bool], ida_dbg.add_bpt)
DEL_BPT = cast(Callable[[int], bool], ida_dbg.del_bpt)
EXIST_BPT = cast(Callable[[int], bool], ida_dbg.exist_bpt)
ENABLE_BPT = cast(Callable[[int, bool], bool], idaapi.enable_bpt)
GET_CURRENT_THREAD = cast(Callable[[], int], ida_dbg.get_current_thread)
GET_THREAD_QTY = ida_dbg.get_thread_qty
GET_NTH_THREAD = cast(Callable[[int], int], ida_dbg.getn_thread)
GET_NTH_THREAD_NAME = cast(Callable[[int], str], ida_dbg.getn_thread_name)
GET_REG_VALS = cast(Callable[[int, int], object], ida_dbg.get_reg_vals)
COLLECT_STACK_TRACE = cast(Callable[[int, ida_idd.call_stack_t], bool], ida_dbg.collect_stack_trace)
GET_MODULE_INFO = cast(Callable[[int, ida_idd.modinfo_t], bool], ida_dbg.get_module_info)
READ_DBG_MEMORY = cast(Callable[[int, int], bytes | None], ida_dbg.read_dbg_memory)
WRITE_DBG_MEMORY = cast(Callable[[int, bytes], int], ida_dbg.write_dbg_memory)
GET_TEV_QTY = ida_dbg.get_tev_qty
GET_TEV_TYPE = cast(Callable[[int], int], ida_dbg.get_tev_type)
GET_TEV_TID = cast(Callable[[int], int], ida_dbg.get_tev_tid)
GET_TEV_EA = cast(Callable[[int], int], ida_dbg.get_tev_ea)
GET_BPT_TEV_EA = cast(Callable[[int], int], ida_dbg.get_bpt_tev_ea)
GET_CALL_TEV_CALLEE = cast(Callable[[int], int], ida_dbg.get_call_tev_callee)
GET_RET_TEV_RETURN = cast(Callable[[int], int], ida_dbg.get_ret_tev_return)
GET_NICE_COLORED_NAME = cast(Callable[[int, int], str], ida_name.get_nice_colored_name)
NEW_BPT = cast(Callable[[], ida_dbg.bpt_t], ida_dbg.bpt_t)
NEW_CALL_STACK = cast(Callable[[], ida_idd.call_stack_t], ida_idd.call_stack_t)
NEW_MODINFO = cast(Callable[[], ida_idd.modinfo_t], ida_idd.modinfo_t)

DEBUG_TIMELINE_LIMIT = 5_000
DEBUG_CAPTURE_STACK_BYTES_DEFAULT = 64
DEBUG_CAPTURE_STACK_BYTES_MAX = 4096
_DEBUG_TIMELINE: list[JsonObject] = []
_DEBUG_CALL_CAPTURE_BY_ADDR: dict[int, JsonObject] = {}
_debug_sequence = 0
_debug_hook: "_McpDebugHooks | None" = None


def _append_debug_event(kind: str, data: JsonObject | None = None) -> JsonObject:
    """追加一条进程内调试时间线事件。"""
    global _debug_sequence
    _debug_sequence += 1
    event: JsonObject = {
        "seq": _debug_sequence,
        "kind": kind,
        "timestamp_ns": time_ns(),
        "data": data or {},
    }
    _DEBUG_TIMELINE.append(event)
    if len(_DEBUG_TIMELINE) > DEBUG_TIMELINE_LIMIT:
        del _DEBUG_TIMELINE[: len(_DEBUG_TIMELINE) - DEBUG_TIMELINE_LIMIT]
    return event


def _debug_json_scalar(value: object) -> JsonValue:
    """把调试器返回的标量压成 JSON 值。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    pyval = getattr(value, "pyval", None)
    if callable(pyval):
        try:
            return _debug_json_scalar(pyval())
        except Exception:
            pass
    try:
        return int(str(value), 0)
    except Exception:
        return str(value)


def _debug_int_result(value: object) -> int:
    """把 IDA 调试器整数返回值收窄为 int。"""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return int(str(value), 0)


def _debug_register_value(name: str) -> JsonValue | None:
    """读取单个寄存器值；不可用时返回 None。"""
    try:
        return _debug_json_scalar(GET_REG_VAL(name))
    except Exception:
        return None


def _debug_int_from_value(value: JsonValue | None) -> int | None:
    """把寄存器 JSON 值收窄为整数地址。"""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _debug_stack_pointer_value() -> int | None:
    """按常见架构寄存器名读取栈指针。"""
    for name in ("rsp", "esp", "sp", "xsp"):
        value = _debug_int_from_value(_debug_register_value(name))
        if value is not None:
            return value
    return None


def _debug_memory_hex(addr: int, size: int) -> str | None:
    """读取调试内存并转成十六进制字符串。"""
    try:
        data = READ_DBG_MEMORY(addr, size)
    except Exception:
        return None
    if data is None:
        return None
    return data.hex()


def _debug_capture_runtime_snapshot(config: JsonObject) -> JsonObject:
    """根据捕获配置读取寄存器和栈样本。"""
    snapshot: JsonObject = {}
    include_registers = config.get("include_registers")
    register_names_value = config.get("register_names")
    register_names: list[str] = []
    if isinstance(register_names_value, list):
        register_names = [str(item) for item in register_names_value]
    if include_registers is True:
        registers: JsonObject = {}
        names = register_names or ["rax", "rcx", "rdx", "r8", "r9", "eax", "ecx", "edx", "esp", "ebp", "rsp", "rbp"]
        for name in names:
            value = _debug_register_value(name)
            if value is not None:
                registers[name] = value
        snapshot["registers"] = registers

    stack_bytes_value = config.get("stack_bytes")
    stack_size = stack_bytes_value if isinstance(stack_bytes_value, int) and not isinstance(stack_bytes_value, bool) else 0
    if stack_size > 0:
        stack_pointer = _debug_stack_pointer_value()
        if stack_pointer is not None:
            stack_hex = _debug_memory_hex(stack_pointer, min(stack_size, DEBUG_CAPTURE_STACK_BYTES_MAX))
            snapshot["stack"] = {
                "addr": hex(stack_pointer),
                "size": min(stack_size, DEBUG_CAPTURE_STACK_BYTES_MAX),
                "hex": stack_hex or "",
                "available": stack_hex is not None,
            }
    return snapshot


class _McpDebugHooks(ida_dbg.DBG_Hooks):
    """把 IDA 调试事件记录到 MCP 可导出的时间线。"""

    def dbg_process_start(self, pid: int, tid: int, ea: int, modinfo_name: str, modinfo_base: int, modinfo_size: int) -> None:
        """记录进程启动事件。"""
        _append_debug_event(
            "process_start",
            {
                "pid": pid,
                "thread_id": tid,
                "addr": hex(ea),
                "module": modinfo_name,
                "module_base": hex(modinfo_base),
                "module_size": modinfo_size,
            },
        )

    def dbg_process_attach(self, pid: int, tid: int, ea: int, modinfo_name: str, modinfo_base: int, modinfo_size: int) -> None:
        """记录进程附加事件。"""
        _append_debug_event(
            "process_attach",
            {
                "pid": pid,
                "thread_id": tid,
                "addr": hex(ea),
                "module": modinfo_name,
                "module_base": hex(modinfo_base),
                "module_size": modinfo_size,
            },
        )

    def dbg_process_exit(self, pid: int, tid: int, ea: int, exit_code: int) -> None:
        """记录进程退出事件。"""
        _append_debug_event("process_exit", {"pid": pid, "thread_id": tid, "addr": hex(ea), "exit_code": exit_code})

    def dbg_process_detach(self, pid: int, tid: int, ea: int) -> None:
        """记录进程分离事件。"""
        _append_debug_event("process_detach", {"pid": pid, "thread_id": tid, "addr": hex(ea)})

    def dbg_thread_start(self, pid: int, tid: int, ea: int) -> None:
        """记录线程启动事件。"""
        _append_debug_event("thread_start", {"pid": pid, "thread_id": tid, "addr": hex(ea)})

    def dbg_thread_exit(self, pid: int, tid: int, ea: int, exit_code: int) -> None:
        """记录线程退出事件。"""
        _append_debug_event("thread_exit", {"pid": pid, "thread_id": tid, "addr": hex(ea), "exit_code": exit_code})

    def dbg_bpt(self, tid: int, bptea: int) -> int:
        """记录断点命中与调用捕获命中。"""
        data: JsonObject = {"thread_id": tid, "addr": hex(bptea)}
        capture = _DEBUG_CALL_CAPTURE_BY_ADDR.get(bptea)
        if capture is not None:
            data["capture"] = capture
            data["snapshot"] = _debug_capture_runtime_snapshot(capture)
            _append_debug_event("call_capture_hit", data)
        else:
            _append_debug_event("breakpoint_hit", data)
        return 0

    def dbg_exception(self, pid: int, tid: int, ea: int, exc_code: int, exc_can_cont: bool, exc_ea: int, exc_info: str) -> int:
        """记录异常事件。"""
        _append_debug_event(
            "exception",
            {
                "pid": pid,
                "thread_id": tid,
                "addr": hex(ea),
                "exception_code": exc_code,
                "can_continue": exc_can_cont,
                "exception_addr": hex(exc_ea),
                "info": exc_info,
            },
        )
        return 0

    def dbg_library_load(self, pid: int, tid: int, ea: int, modinfo_name: str, modinfo_base: int, modinfo_size: int) -> None:
        """记录库加载事件。"""
        _append_debug_event(
            "library_load",
            {
                "pid": pid,
                "thread_id": tid,
                "addr": hex(ea),
                "module": modinfo_name,
                "module_base": hex(modinfo_base),
                "module_size": modinfo_size,
            },
        )

    def dbg_library_unload(self, pid: int, tid: int, ea: int, info: str) -> None:
        """记录库卸载事件。"""
        _append_debug_event("library_unload", {"pid": pid, "thread_id": tid, "addr": hex(ea), "info": info})

    def dbg_trace(self, tid: int, ip: int) -> int:
        """记录指令跟踪事件。"""
        _append_debug_event("trace", {"thread_id": tid, "ip": hex(ip)})
        return 0


class DebugCoreMixin:
    """提供 IDA 调试器启动、执行控制、断点、寄存器、栈和内存能力。"""

    def parse_address(self, value: str) -> int:
        """由核心类提供地址解析。"""
        raise NotImplementedError

    def best_name(self, ea: int) -> str:
        """由核心类提供地址命名。"""
        raise NotImplementedError

    def jsonify(self, value: object) -> JsonValue:
        """由核心类提供 JSON 值转换。"""
        raise NotImplementedError

    def _json_object(self, value: object) -> JsonObject:
        """由核心类提供 JSON 对象收窄。"""
        raise NotImplementedError

    def _iter_objects(self, value: object) -> list[object]:
        """由核心类提供迭代对象收窄。"""
        return list(cast(Iterable[object], value))

    def _ensure_debug_hooks(self) -> JsonObject:
        """安装调试事件 hook，用于时间线和调用捕获。"""
        global _debug_hook
        if _debug_hook is not None:
            return {"installed": True, "already_installed": True}
        hook_factory = cast(Callable[[], _McpDebugHooks], _McpDebugHooks)
        hook = hook_factory()
        try:
            installed = bool(hook.hook())
        except Exception as exc:
            return {"installed": False, "already_installed": False, "error": str(exc)}
        if installed:
            _debug_hook = hook
        return {"installed": installed, "already_installed": False}

    def debug_start(self, path: str = "", *, args: str = "", cwd: str = "") -> ToolEnvelope:
        """启动调试会话。"""
        return self.debug_launch(path, args=args, cwd=cwd)

    def debug_launch(self, path: str = "", *, args: str = "", cwd: str = "", use_request: bool = False) -> ToolEnvelope:
        """启动调试目标。"""
        target = path or (ida_nalt.get_input_file_path() or "")
        if not target:
            return {"status": "unsupported", "data": {"reason": "当前没有可调试目标"}, "warnings": ["请显式提供 path"]}
        hooks = self._ensure_debug_hooks()
        start_cwd = self._debug_start_cwd(target, cwd)
        cwd_source = "explicit" if cwd.strip() else "target_parent"
        state_before = self._debug_state_snapshot()
        ok = False
        if use_request:
            request_result = int(REQUEST_START_PROCESS(target, args, start_cwd))
            run_requests = self._debug_run_pending_requests()
            ok = request_result > 0
        else:
            request_result = int(bool(START_PROCESS(target, args, start_cwd)))
            run_requests = {"available": RUN_REQUESTS is not None, "ran": False, "skipped": True}
        state = self._debug_state_snapshot()
        backend_ready = bool(state["backend_available"])
        session_active = bool(state["session_active"])
        _append_debug_event(
            "launch",
            {
                "path": target,
                "args": args,
                "cwd": start_cwd,
                "use_request": use_request,
                "request_result": request_result,
                "session_active": session_active,
            },
        )
        if ok and backend_ready and session_active:
            return self._json_object({
                "status": "ok",
                "data": {
                    "started": True,
                    "path": target,
                    "args": args,
                    "cwd": start_cwd,
                    "cwd_source": cwd_source,
                    "backend_available": backend_ready,
                    "session_active": session_active,
                    "hooks": hooks,
                    "run_requests": run_requests,
                    "state_before": state_before,
                    "state": state,
                },
                "warnings": [],
            })
        return self._json_object({
            "status": "unsupported",
            "data": {
                "started": bool(ok),
                "path": target,
                "args": args,
                "cwd": start_cwd,
                "cwd_source": cwd_source,
                "backend_available": backend_ready,
                "session_active": session_active,
                "hooks": hooks,
                "run_requests": run_requests,
                "state_before": state_before,
                "state": state,
            },
            "warnings": ["当前环境未形成可用调试链路，后续寄存器/栈回溯/内存接口不可继续调用"],
        })

    def debug_attach(self, pid: int, *, event_id: int = -1, use_request: bool = False) -> ToolEnvelope:
        """附加到正在运行的进程。"""
        if pid <= 0:
            raise ValueError("pid 必须是正整数")
        hooks = self._ensure_debug_hooks()
        state_before = self._debug_state_snapshot()
        if use_request:
            attach_result = int(REQUEST_ATTACH_PROCESS(pid, event_id))
            run_requests = self._debug_run_pending_requests()
        else:
            try:
                attach_result = _debug_int_result(ATTACH_PROCESS(pid, event_id))
            except TypeError:
                attach_result = _debug_int_result(ATTACH_PROCESS(pid))
            run_requests = {"available": RUN_REQUESTS is not None, "ran": False, "skipped": True}
        state_after = self._debug_state_snapshot()
        session_active = bool(state_after["session_active"])
        _append_debug_event(
            "attach",
            {
                "pid": pid,
                "event_id": event_id,
                "use_request": use_request,
                "attach_result": attach_result,
                "session_active": session_active,
            },
        )
        status = "ok" if session_active or attach_result == 1 else "unsupported"
        warnings: list[str] = []
        if status != "ok":
            warnings.append("当前 IDA 调试后端未能附加到目标进程。")
        return self._json_object(
            {
                "status": status,
                "data": {
                    "pid": pid,
                    "event_id": event_id,
                    "attached": status == "ok",
                    "attach_result": attach_result,
                    "hooks": hooks,
                    "run_requests": run_requests,
                    "state_before": state_before,
                    "state_after": state_after,
                },
                "warnings": warnings,
            }
        )

    def debug_exit(self) -> ToolEnvelope:
        """退出调试。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        EXIT_PROCESS()
        _append_debug_event("exit_request", {})
        return self._json_object({"status": "ok", "data": {"exited": True}, "warnings": []})

    def debug_continue(self) -> ToolEnvelope:
        """继续执行。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        CONTINUE_PROCESS()
        _append_debug_event("continue", self._debug_state_snapshot())
        return self._json_object({"status": "ok", "data": {"continued": True}, "warnings": []})

    def debug_run_to(self, addr: str) -> ToolEnvelope:
        """运行到指定地址。"""
        before = self._debug_state_snapshot()
        if not bool(before["session_active"]):
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话", "state": before}, "warnings": ["未附加调试器"]})

        ea = self.parse_address(addr)
        request_ok = bool(REQUEST_RUN_TO(ea))
        run_requests: JsonObject
        if request_ok:
            run_requests = self._debug_run_pending_requests()
        else:
            run_requests = {"available": RUN_REQUESTS is not None, "skipped": True}
        after_request = self._debug_state_snapshot()
        _append_debug_event(
            "run_to",
            {
                "addr": hex(ea),
                "request_ok": request_ok,
                "run_requests": run_requests,
                "state_after_request": after_request,
            },
        )
        if request_ok:
            warnings = self._debug_request_warnings(run_requests)
            return self._json_object({
                "status": "ok",
                "data": {
                    "requested": True,
                    "addr": addr,
                    "resolved_addr": hex(ea),
                    "mode": "request_run_to",
                    "run_requests": run_requests,
                    "state_before": before,
                    "state_after_request": after_request,
                },
                "warnings": warnings,
            })

        fallback = self._debug_continue_with_breakpoint(ea)
        if bool(fallback["continued"]):
            warnings = ["request_run_to 失败，已改用断点后继续执行。", str(fallback["breakpoint_warning"])]
            return self._json_object({
                "status": "degraded",
                "data": {
                    "requested": False,
                    "addr": addr,
                    "resolved_addr": hex(ea),
                    "mode": "breakpoint_continue_fallback",
                    "fallback": fallback,
                    "run_requests": run_requests,
                    "state_before": before,
                    "state_after_request": after_request,
                    "state_after_fallback": self._debug_state_snapshot(),
                },
                "warnings": warnings,
            })

        return self._json_object({
            "status": "unsupported",
            "data": {
                "requested": False,
                "addr": addr,
                "resolved_addr": hex(ea),
                "run_requests": run_requests,
                "fallback": fallback,
                "state_before": before,
                "state_after_request": after_request,
            },
            "warnings": ["request_run_to 失败，断点 fallback 也未能继续执行。"],
        })

    def debug_step_into(self) -> ToolEnvelope:
        """单步进入。"""
        return self.debug_step(action="into")

    def debug_step_over(self) -> ToolEnvelope:
        """单步越过。"""
        return self.debug_step(action="over")

    def debug_step(self, *, action: str = "into") -> ToolEnvelope:
        """执行单步动作。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        if action == "into":
            ok = bool(STEP_INTO())
        elif action == "over":
            ok = bool(STEP_OVER())
        elif action == "out":
            ok = bool(STEP_UNTIL_RET())
        else:
            raise ValueError("debug_step 的 action 必须是 into、over 或 out")
        state = self._debug_state_snapshot()
        _append_debug_event("step", {"action": action, "ok": ok, "state": state})
        status = "ok" if ok else "unsupported"
        warnings = [] if ok else ["IDA 调试后端未接受单步请求"]
        return self._json_object({"status": status, "data": {"step": action, "accepted": ok, "state": state}, "warnings": warnings})

    def _debug_start_cwd(self, target: str, cwd: str) -> str:
        """确定调试启动目录，避免依赖 IDA 当前进程目录。"""
        explicit_cwd = cwd.strip()
        if explicit_cwd:
            cwd_path = Path(explicit_cwd)
            if not cwd_path.is_dir():
                raise ValueError(f"cwd 必须是已存在目录：{explicit_cwd}")
            return str(cwd_path)

        target_parent = Path(target).parent
        if target_parent == Path("."):
            return ""
        return str(target_parent)

    def _debug_state_snapshot(self) -> JsonObject:
        """读取调试器状态快照，失败字段转为诊断信息。"""
        process_state = int(GET_PROCESS_STATE())
        diagnostics: list[JsonValue] = []
        current_thread: int | None = None
        thread_count = 0

        if process_state != -1:
            try:
                raw_current_thread = int(GET_CURRENT_THREAD())
                if raw_current_thread not in (-1, BADADDR):
                    current_thread = raw_current_thread
            except Exception as exc:
                diagnostics.append(f"读取当前线程失败：{exc}")

            try:
                thread_count = int(GET_THREAD_QTY())
            except Exception as exc:
                diagnostics.append(f"读取线程数量失败：{exc}")

        snapshot: JsonObject = {
            "backend_available": bool(ida_idd.get_dbg()),
            "session_active": process_state != -1,
            "process_state": process_state,
            "current_thread": current_thread,
            "thread_count": thread_count,
        }
        if diagnostics:
            snapshot["diagnostics"] = diagnostics
        return snapshot

    def _debug_run_pending_requests(self) -> JsonObject:
        """调度 IDA request_* 队列，兼容未暴露 run_requests 的运行时。"""
        if RUN_REQUESTS is None:
            return {"available": False, "ran": False}
        try:
            return {"available": True, "ran": True, "result": bool(RUN_REQUESTS())}
        except Exception as exc:
            return {"available": True, "ran": False, "error": str(exc)}

    def _debug_request_warnings(self, run_requests: JsonObject) -> list[str]:
        """把 request 队列调度结果转换成用户可读告警。"""
        if run_requests.get("available") is False:
            return ["当前 IDA Python 运行时未暴露 run_requests，已提交 run_to 请求但无法显式调度队列。"]
        error_text = run_requests.get("error")
        if isinstance(error_text, str) and error_text:
            return [f"run_requests 调度失败：{error_text}"]
        return []

    def _debug_continue_with_breakpoint(self, ea: int) -> JsonObject:
        """在 request_run_to 不可用时改用断点继续执行。"""
        try:
            breakpoint_preexisting = bool(EXIST_BPT(ea))
        except Exception as exc:
            return {
                "continued": False,
                "breakpoint_preexisting": False,
                "breakpoint_added": False,
                "continue_error": "",
                "breakpoint_warning": f"断点查询失败：{exc}",
            }
        breakpoint_added = False
        if not breakpoint_preexisting:
            try:
                breakpoint_added = bool(ADD_BPT(ea))
            except Exception as exc:
                return {
                    "continued": False,
                    "breakpoint_preexisting": breakpoint_preexisting,
                    "breakpoint_added": False,
                    "continue_error": "",
                    "breakpoint_warning": f"断点添加失败：{exc}",
                }
            if not breakpoint_added:
                return {
                    "continued": False,
                    "breakpoint_preexisting": breakpoint_preexisting,
                    "breakpoint_added": False,
                    "continue_error": "",
                    "breakpoint_warning": "断点添加失败。",
                }

        try:
            CONTINUE_PROCESS()
        except Exception as exc:
            return {
                "continued": False,
                "breakpoint_preexisting": breakpoint_preexisting,
                "breakpoint_added": breakpoint_added,
                "continue_error": str(exc),
                "breakpoint_warning": "已新增 fallback 断点，但继续执行失败。" if breakpoint_added else "复用已有断点，但继续执行失败。",
            }

        return {
            "continued": True,
            "breakpoint_preexisting": breakpoint_preexisting,
            "breakpoint_added": breakpoint_added,
            "continue_error": "",
            "breakpoint_warning": "新增的 fallback 断点会保留在 IDA 断点列表中，命中后可用 debug_delete_breakpoints 清理。"
            if breakpoint_added
            else "复用了目标地址已有断点。",
        }

    def debug_breakpoints(self) -> list[JsonObject]:
        """列出断点。"""
        results: list[JsonObject] = []
        for index in range(GET_BPT_QTY()):
            bpt = NEW_BPT()
            if GET_NTH_BPT(index, bpt):
                results.append({"addr": hex(bpt.ea), "enabled": bool(bpt.enabled), "size": bpt.size})
        return results

    def debug_add_breakpoints(self, addrs: list[str]) -> list[JsonObject]:
        """添加断点。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not ADD_BPT(ea):
                raise RuntimeError(f"添加断点失败：{addr_text}")
            _append_debug_event("breakpoint_add", {"addr": hex(ea)})
            results.append({"addr": hex(ea)})
        return results

    def debug_delete_breakpoints(self, addrs: list[str]) -> list[JsonObject]:
        """删除断点。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not DEL_BPT(ea):
                raise RuntimeError(f"删除断点失败：{addr_text}")
            _append_debug_event("breakpoint_delete", {"addr": hex(ea)})
            results.append({"addr": hex(ea)})
        return results

    def debug_toggle_breakpoints(self, items: list[JsonObject]) -> list[JsonObject]:
        """启停断点。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            enabled = bool(item.get("enabled", True))
            if not isinstance(addr_text, str):
                raise ValueError("debug_toggle_breakpoints 的 addr 必须为字符串")
            ea = self.parse_address(addr_text)
            if not EXIST_BPT(ea):
                raise RuntimeError(f"找不到断点：{addr_text}")
            if not ENABLE_BPT(ea, enabled):
                raise RuntimeError(f"更新断点失败：{addr_text}")
            _append_debug_event("breakpoint_toggle", {"addr": hex(ea), "enabled": enabled})
            results.append({"addr": hex(ea), "enabled": enabled})
        return results

    def debug_registers(self, *, thread_id: int | None = None, names: list[str] | None = None) -> JsonObject:
        """读取寄存器。"""
        if GET_PROCESS_STATE() == -1:
            raise RuntimeError("当前没有活动调试会话")
        current_thread = thread_id if thread_id is not None else int(GET_CURRENT_THREAD())
        debugger = ida_idd.get_dbg()
        regvals = self._iter_objects(GET_REG_VALS(current_thread, -1))
        selected = {item.lower() for item in names} if names is not None else None
        registers: dict[str, JsonValue] = {}
        for reg_index, regval in enumerate(regvals):
            reg_info = cast(object, debugger.regs(reg_index))
            reg_name = str(getattr(reg_info, "name"))
            if selected is not None and reg_name.lower() not in selected:
                continue
            try:
                pyval_fn = cast(Callable[[object], object], getattr(regval, "pyval"))
                registers[reg_name] = self.jsonify(pyval_fn(getattr(reg_info, "dtype")))
            except Exception:
                registers[reg_name] = str(regval)
        return self._json_object({"thread_id": current_thread, "registers": registers})

    def debug_register_snapshots(self, *, names: list[str] | None = None) -> ToolEnvelope:
        """读取所有线程的寄存器快照。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})

        current_thread = int(GET_CURRENT_THREAD())
        thread_count = int(GET_THREAD_QTY())
        threads: list[JsonObject] = []
        warnings: list[str] = []

        for index in range(thread_count):
            thread_id = int(GET_NTH_THREAD(index))
            if thread_id in (BADADDR, -1):
                warnings.append(f"第 {index} 个线程句柄无效，已跳过")
                continue
            thread_name = GET_NTH_THREAD_NAME(index)
            try:
                snapshot = self.debug_registers(thread_id=thread_id, names=names)
                threads.append(
                    {
                        "index": index,
                        "thread_id": thread_id,
                        "thread_name": thread_name or "",
                        "is_current": thread_id == current_thread,
                        "registers": snapshot["registers"],
                    }
                )
            except Exception as exc:
                warnings.append(f"线程 {thread_id} 寄存器读取失败：{exc}")

        if not threads:
            return self._json_object({
                "status": "unsupported",
                "data": {"reason": "没有可读取的线程寄存器", "thread_count": thread_count},
                "warnings": warnings or ["调试器未返回可用线程"],
            })

        return self._json_object({
            "status": "ok",
            "data": {"current_thread": current_thread, "thread_count": thread_count, "threads": threads},
            "warnings": warnings,
        })

    def debug_stacktrace(self) -> ToolEnvelope:
        """读取当前线程调用栈。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})

        thread_id = int(GET_CURRENT_THREAD())
        trace = NEW_CALL_STACK()
        if not COLLECT_STACK_TRACE(thread_id, trace):
            return self._json_object({"status": "unsupported", "data": {"reason": "读取调用栈失败", "thread_id": thread_id}, "warnings": ["collect_stack_trace 失败"]})

        frames: list[JsonObject] = []
        for index, frame in enumerate(trace):
            call_ea = int(frame.callea)
            function_ea = int(frame.funcea) if int(frame.funcea) != BADADDR else call_ea
            module_name = "<unknown>"
            module_info = NEW_MODINFO()
            if GET_MODULE_INFO(call_ea, module_info):
                raw_module_name = module_info.name
                if isinstance(raw_module_name, str) and raw_module_name:
                    module_name = Path(raw_module_name).name

            symbol_name = GET_NICE_COLORED_NAME(
                function_ea,
                ida_name.GNCN_NOCOLOR
                | ida_name.GNCN_NOLABEL
                | ida_name.GNCN_NOSEG
                | ida_name.GNCN_PREFDBG,
            )
            frames.append(
                {
                    "index": index,
                    "call_addr": hex(call_ea),
                    "function_addr": hex(function_ea),
                    "frame_pointer": hex(int(frame.fp)),
                    "function_ok": bool(frame.funcok),
                    "module": module_name,
                    "symbol": symbol_name or self.best_name(function_ea),
                }
            )

        return self._json_object({"status": "ok", "data": {"thread_id": thread_id, "frames": frames}, "warnings": []})

    def debug_read_memory(self, addr: str, size: int) -> ToolEnvelope:
        """读取调试内存。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        data = READ_DBG_MEMORY(self.parse_address(addr), size)
        if data is None:
            return self._json_object({"status": "unsupported", "data": {"reason": "读取调试内存失败", "addr": addr}, "warnings": ["read_dbg_memory 返回 None"]})
        return self._json_object({"status": "ok", "data": {"addr": addr, "size": len(data), "hex": data.hex()}, "warnings": []})

    def debug_write_memory(self, addr: str, hex_data: str) -> ToolEnvelope:
        """写入调试内存。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        blob = bytes.fromhex(hex_data)
        written = WRITE_DBG_MEMORY(self.parse_address(addr), blob)
        if written != len(blob):
            return self._json_object({"status": "unsupported", "data": {"reason": "写入调试内存失败", "written": written, "expected": len(blob)}, "warnings": ["write_dbg_memory 未完整写入"]})
        _append_debug_event("memory_write", {"addr": addr, "size": len(blob)})
        return self._json_object({"status": "ok", "data": {"addr": addr, "size": len(blob)}, "warnings": []})

    def debug_stack(self, *, size: int = 128) -> ToolEnvelope:
        """读取当前线程栈顶内存。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        bounded_size = max(1, min(size, DEBUG_CAPTURE_STACK_BYTES_MAX))
        stack_pointer = _debug_stack_pointer_value()
        if stack_pointer is None:
            return self._json_object({"status": "unsupported", "data": {"reason": "无法读取栈指针"}, "warnings": ["未识别 rsp/esp/sp/xsp 寄存器"]})
        data = READ_DBG_MEMORY(stack_pointer, bounded_size)
        if data is None:
            return self._json_object(
                {
                    "status": "unsupported",
                    "data": {"reason": "读取栈内存失败", "addr": hex(stack_pointer), "size": bounded_size},
                    "warnings": ["read_dbg_memory 返回 None"],
                }
            )
        return self._json_object(
            {
                "status": "ok",
                "data": {"addr": hex(stack_pointer), "size": len(data), "hex": data.hex()},
                "warnings": [],
            }
        )

    def debug_capture_calls(
        self,
        *,
        action: str = "list",
        addrs: list[str] | None = None,
        include_registers: bool = True,
        stack_bytes: int = DEBUG_CAPTURE_STACK_BYTES_DEFAULT,
        register_names: list[str] | None = None,
    ) -> ToolEnvelope:
        """配置基于断点命中的通用调用捕获。"""
        hooks = self._ensure_debug_hooks()
        normalized_addrs = addrs or []
        warnings: list[str] = []
        changed: list[JsonObject] = []
        bounded_stack_bytes = max(0, min(stack_bytes, DEBUG_CAPTURE_STACK_BYTES_MAX))

        if action == "clear":
            cleared = len(_DEBUG_CALL_CAPTURE_BY_ADDR)
            _DEBUG_CALL_CAPTURE_BY_ADDR.clear()
            _append_debug_event("call_capture_clear", {"cleared": cleared})
        elif action in ("enable", "disable"):
            if not normalized_addrs:
                raise ValueError("enable/disable 调用捕获时必须提供 addrs")
            for addr_text in normalized_addrs:
                ea = self.parse_address(addr_text)
                if action == "enable":
                    if not EXIST_BPT(ea) and not ADD_BPT(ea):
                        raise RuntimeError(f"添加调用捕获断点失败：{addr_text}")
                    config: JsonObject = {
                        "addr": hex(ea),
                        "name": self.best_name(ea),
                        "include_registers": include_registers,
                        "stack_bytes": bounded_stack_bytes,
                    }
                    if register_names is not None:
                        config["register_names"] = cast(JsonValue, [str(name) for name in register_names])
                    _DEBUG_CALL_CAPTURE_BY_ADDR[ea] = config
                    changed.append(config)
                    _append_debug_event("call_capture_enable", config)
                else:
                    removed = _DEBUG_CALL_CAPTURE_BY_ADDR.pop(ea, None)
                    row: JsonObject = {"addr": hex(ea), "removed": removed is not None}
                    changed.append(row)
                    _append_debug_event("call_capture_disable", row)
        elif action != "list":
            raise ValueError("debug_capture_calls 的 action 必须是 enable、disable、list 或 clear")

        if hooks.get("installed") is False:
            warnings.append("调试事件 hook 安装失败，捕获配置已记录但不会收到命中事件。")

        captures = [config for _, config in sorted(_DEBUG_CALL_CAPTURE_BY_ADDR.items())]
        return self._json_object(
            {
                "status": "ok",
                "data": {
                    "action": action,
                    "changed": changed,
                    "captures": captures,
                    "hooks": hooks,
                    "timeline_events": len(_DEBUG_TIMELINE),
                },
                "warnings": warnings,
            }
        )

    def debug_export_timeline(self, *, limit: int = 500, include_ida_trace: bool = True, path: str = "") -> ToolEnvelope:
        """导出调试时间线到 JSON 文件。"""
        bounded_limit = max(1, min(limit, DEBUG_TIMELINE_LIMIT))
        local_events = _DEBUG_TIMELINE[-bounded_limit:]
        ida_trace_events = self._debug_ida_trace_events(limit=bounded_limit) if include_ida_trace else []
        payload: dict[str, object] = {
            "local_event_count": len(_DEBUG_TIMELINE),
            "returned_local_events": len(local_events),
            "ida_trace_event_count": len(ida_trace_events),
            "local_events": local_events,
            "ida_trace_events": ida_trace_events,
            "state": self._debug_state_snapshot(),
            "captures": [config for _, config in sorted(_DEBUG_CALL_CAPTURE_BY_ADDR.items())],
        }
        payload_object = self._json_object(payload)
        artifact = self._write_debug_timeline_artifact(payload_object, path=path)
        summary = {
            "local_event_count": len(_DEBUG_TIMELINE),
            "returned_local_events": len(local_events),
            "ida_trace_event_count": len(ida_trace_events),
        }
        return self._json_object({"status": "ok", "data": {"artifact": artifact, "summary": summary}, "warnings": []})

    def _write_debug_timeline_artifact(self, payload: JsonObject, *, path: str) -> JsonObject:
        """保存调试时间线 artifact。"""
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        encoded = content.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if path.strip():
            output_path = Path(path).expanduser().resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            directory = get_runtime_workspace_paths().directory / "debug-timeline"
            directory.mkdir(parents=True, exist_ok=True)
            output_path = directory / f"{time_ns()}-timeline-{digest[:12]}.json"
        output_path.write_bytes(encoded)
        return {"path": str(output_path), "sha256": digest, "size": len(encoded), "schema": {"type": "object", "format": "ida-debug-timeline"}}

    def _debug_ida_trace_events(self, *, limit: int) -> list[JsonObject]:
        """读取 IDA trace buffer 的简要事件。"""
        events: list[JsonObject] = []
        try:
            count = int(GET_TEV_QTY())
        except Exception as exc:
            return [{"error": f"读取 IDA trace 数量失败：{exc}"}]
        type_names = {
            int(ida_dbg.tev_none): "none",
            int(ida_dbg.tev_insn): "insn",
            int(ida_dbg.tev_call): "call",
            int(ida_dbg.tev_ret): "ret",
            int(ida_dbg.tev_bpt): "bpt",
            int(ida_dbg.tev_mem): "mem",
            int(ida_dbg.tev_event): "event",
        }
        for index in range(min(count, limit)):
            try:
                event_type = int(GET_TEV_TYPE(index))
                event: JsonObject = {
                    "index": index,
                    "type": type_names.get(event_type, str(event_type)),
                    "thread_id": int(GET_TEV_TID(index)),
                }
                ea = int(GET_TEV_EA(index))
                if ea != BADADDR:
                    event["addr"] = hex(ea)
                if event_type == int(ida_dbg.tev_call):
                    callee = int(GET_CALL_TEV_CALLEE(index))
                    if callee != BADADDR:
                        event["callee"] = hex(callee)
                        event["callee_name"] = self.best_name(callee)
                elif event_type == int(ida_dbg.tev_ret):
                    return_ea = int(GET_RET_TEV_RETURN(index))
                    if return_ea != BADADDR:
                        event["return_addr"] = hex(return_ea)
                elif event_type == int(ida_dbg.tev_bpt):
                    bpt_ea = int(GET_BPT_TEV_EA(index))
                    if bpt_ea != BADADDR:
                        event["breakpoint_addr"] = hex(bpt_ea)
                events.append(event)
            except Exception as exc:
                events.append({"index": index, "error": str(exc)})
        return events
