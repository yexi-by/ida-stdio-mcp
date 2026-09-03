# pyright: reportAny=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""Windows 本机 x86/x64 IDA debugger worker 与真实事件状态机。"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from ida_re_mcp.constants import MAX_MEMORY_READ_BYTES, MAX_OPERATION_WAIT_MS, MAX_PAGE_SIZE
from ida_re_mcp.worker._ida import IdaModules, OwnerThreadBound, require_ida
from ida_re_mcp.worker.errors import CapabilityError, WorkerError, WorkerInputError
from ida_re_mcp.worker.job import (
    WindowsJob,
    query_process_memory,
    verify_process_architecture,
)

_CANONICAL_HEX = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_MAX_EVENTS = 4096
_X64_REGISTER_NAMES = (
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "RIP",
    "EFL",
)
_X86_REGISTER_NAMES = (
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "EFL",
)
_STOP_EVENT_KINDS = frozenset(
    {
        "process_started",
        "process_attached",
        "breakpoint",
        "step",
        "exception",
        "process_suspended",
    }
)
_TERMINAL_EVENT_KINDS = frozenset(
    {
        "process_exited",
        "process_detached",
        "worker_lost",
        "request_error",
    }
)


def _idb_bitness(api: IdaModules) -> int:
    processor = str(api.ida_ida.inf_get_procname()).casefold()
    is_64_bit = bool(api.ida_ida.inf_is_64bit())
    is_32_bit = bool(api.ida_ida.inf_is_32bit_exactly())
    bitness = 64 if is_64_bit else 32 if is_32_bit else 16
    if processor != "metapc" or bitness not in {32, 64}:
        raise CapabilityError(
            "Windows 本机调试只支持 32 位 x86 和 64 位 x64 IDB，请打开对应 IDB 后重试",
            capability="windows_local_debugger",
            details={"processor": processor, "bitness": bitness},
        )
    return bitness


class DebugState(StrEnum):
    """公开调试状态。"""

    LAUNCHING = "launching"
    RUNNING = "running"
    SUSPENDED = "suspended"
    EXITED = "exited"
    DETACHED = "detached"
    LOST = "lost"
    FAILED = "failed"


class DebugEventProvenance(StrEnum):
    """事件事实的来源, 避免把 debugger 状态读取伪装成 IDA 事件。"""

    IDA_EVENT = "ida_event"
    STATE_OBSERVATION = "state_observation"
    SERVICE_EVENT = "service_event"


@dataclass(frozen=True, slots=True)
class DebugEvent:
    sequence: int
    kind: str
    state: DebugState
    timestamp_ns: int
    payload: dict[str, object]
    provenance: DebugEventProvenance
    stop_id: str | None = None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "sequence": self.sequence,
            "kind": self.kind,
            "state": self.state.value,
            "timestamp_ns": self.timestamp_ns,
            "payload": self.payload,
            "provenance": self.provenance.value,
        }
        if self.stop_id is not None:
            result["stop_id"] = self.stop_id
        return result


class _CancellationObserved(Exception):
    def __init__(self, event: DebugEvent | None = None) -> None:
        super().__init__("debug request cancellation observed")
        self.event = event


class DebugStateMachine:
    """只依据已观察事件和真实 debugger state 更新状态。"""

    def __init__(self) -> None:
        self.state = DebugState.DETACHED
        self.stop_id: str | None = None
        self._events: deque[DebugEvent] = deque(maxlen=_MAX_EVENTS)
        self._next_sequence = 1
        self._renew_stop_id = False

    @property
    def latest_sequence(self) -> int:
        return self._next_sequence - 1

    def begin_establish(self) -> None:
        if self.state not in {
            DebugState.DETACHED,
            DebugState.EXITED,
            DebugState.FAILED,
            DebugState.LOST,
        }:
            raise WorkerError("debug_state_conflict", "已有活动调试会话")
        self.state = DebugState.LAUNCHING
        self.stop_id = None
        self._renew_stop_id = False

    def observe(
        self,
        kind: str,
        payload: Mapping[str, object] | None = None,
        *,
        provenance: DebugEventProvenance,
    ) -> DebugEvent:
        data = dict(payload or {})
        if provenance == DebugEventProvenance.IDA_EVENT:
            event_id = data.get("event_id")
            if (
                not isinstance(event_id, int)
                or isinstance(event_id, bool)
                or event_id < 0
                or kind in {"execution_resumed", "request_error", "worker_lost"}
            ):
                raise WorkerError(
                    "debug_state_conflict",
                    "ida_event 必须绑定真实非负 event_id 且不得伪装服务事件",
                )
        if provenance == DebugEventProvenance.STATE_OBSERVATION and (
            kind != "execution_resumed" or data.get("observed_debugger_state") != "DSTATE_RUN"
        ):
            raise WorkerError(
                "debug_state_conflict",
                "state_observation 只能表示已验证的 DSTATE_RUN",
            )
        if provenance == DebugEventProvenance.SERVICE_EVENT and kind not in {
            "request_error",
            "worker_lost",
        }:
            raise WorkerError(
                "debug_state_conflict",
                "service_event 只能表示 worker 生命周期或请求错误",
            )
        existing_stop_id = (
            self.stop_id if self.state == DebugState.SUSPENDED and not self._renew_stop_id else None
        )
        if kind in {"process_started", "process_attached"}:
            observed = data.get("process_state")
            if observed == "suspended":
                self.state = DebugState.SUSPENDED
            elif observed == "running":
                self.state = DebugState.RUNNING
            else:
                self.state = DebugState.LOST
        elif kind in {"breakpoint", "step", "exception", "process_suspended"}:
            self.state = DebugState.SUSPENDED
        elif kind == "process_exited":
            self.state = DebugState.EXITED
        elif kind == "process_detached":
            self.state = DebugState.DETACHED
        elif kind == "worker_lost":
            self.state = DebugState.LOST
        elif kind == "request_error":
            self.state = DebugState.FAILED
        if self.state == DebugState.SUSPENDED and kind in _STOP_EVENT_KINDS:
            self.stop_id = existing_stop_id or uuid.uuid4().hex
        elif self.state != DebugState.SUSPENDED:
            self.stop_id = None
        if kind in _STOP_EVENT_KINDS or kind in _TERMINAL_EVENT_KINDS:
            self._renew_stop_id = False
        event = DebugEvent(
            self._next_sequence,
            kind,
            self.state,
            time.time_ns(),
            data,
            provenance,
            self.stop_id,
        )
        self._events.append(event)
        self._next_sequence += 1
        return event

    def observe_running_state(self, action: str) -> DebugEvent:
        """记录 `get_process_state()==DSTATE_RUN`, 不伪造 IDA resume event。"""

        if self.state != DebugState.SUSPENDED:
            raise WorkerError("debug_state_conflict", "只有 suspended 状态可以恢复执行")
        self.state = DebugState.RUNNING
        self.stop_id = None
        self._renew_stop_id = False
        return self.observe(
            "execution_resumed",
            {
                "action": action,
                "observed_debugger_state": "DSTATE_RUN",
            },
            provenance=DebugEventProvenance.STATE_OBSERVATION,
        )

    def begin_execution(self, stop_id: object) -> str:
        """接受执行请求后立即使旧停点失效; 不伪造尚未观察到的 running。"""

        valid_stop_id = self.require_suspended(stop_id)
        self.stop_id = None
        self._renew_stop_id = True
        return valid_stop_id

    def require_suspended(self, stop_id: object) -> str:
        if self.state != DebugState.SUSPENDED or self.stop_id is None:
            raise WorkerError("debug_state_conflict", "该操作要求真实 suspended 状态")
        if not isinstance(stop_id, str) or stop_id != self.stop_id:
            raise WorkerError("debug_state_conflict", "stop_id 已失效或不属于当前停点")
        return stop_id

    def events_after(self, sequence: int, limit: int) -> list[DebugEvent]:
        if sequence < 0:
            raise WorkerInputError("event sequence 不能为负数")
        if self._events and sequence < self._events[0].sequence - 1:
            raise WorkerError("cursor_stale", "debug event cursor 已超出保留窗口")
        return [event for event in self._events if event.sequence > sequence][:limit]

    def latest_event_of(self, kinds: frozenset[str]) -> DebugEvent | None:
        """返回最近一次已观察到的指定事件, 不制造新的生命周期事实。"""

        return next((event for event in reversed(self._events) if event.kind in kinds), None)


@dataclass(slots=True)
class _Breakpoint:
    id: str
    module: str
    rva: int
    enabled: bool
    runtime_address: int | None = None
    active: bool = False

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "breakpoint_id": self.id,
            "module": self.module,
            "rva": _hex(self.rva),
            "enabled": self.enabled,
            "active": self.active,
        }
        if self.runtime_address is not None:
            result["runtime_address"] = _hex(self.runtime_address)
        return result


class DebugWorker(OwnerThreadBound):
    """一个 checkout 对应一个真实 Windows 本地调试会话。"""

    def __init__(
        self,
        checkout_path: Path,
        sample_path: Path,
        *,
        allow_attach: bool = False,
    ) -> None:
        super().__init__()
        self.checkout_path = checkout_path.resolve(strict=True)
        self.sample_path = sample_path.resolve(strict=True)
        self.allow_attach = allow_attach
        self.session_id = uuid.uuid4().hex
        self.machine = DebugStateMachine()
        self._api: IdaModules | None = None
        self._checkout_bitness: Literal[32, 64] | None = None
        self._mode: str | None = None
        self._job: WindowsJob | None = None
        self._owned_pid: int | None = None
        self._verified_target_pid: int | None = None
        self._modules: dict[str, dict[str, object]] = {}
        self._breakpoints: dict[str, _Breakpoint] = {}
        self._closed = False
        self._established = False
        self._cancellation: threading.Event | None = None
        self._last_debug_event_fingerprint: tuple[object, ...] | None = None
        self._establish_event: DebugEvent | None = None

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        self._assert_owner_thread()
        if self._closed:
            raise WorkerError("worker_closed", "debug worker 已关闭")
        api = self._require_runtime()
        handlers = {
            "debug.establish": self._establish,
            "debug.control": self._control,
            "debug.events": self._events,
            "debug.inspect": self._inspect,
            "debug.breakpoints": self._breakpoint_operation,
            "debug.finish": self._finish,
        }
        handler = handlers.get(operation)
        if handler is None:
            raise WorkerInputError("debug worker 不支持该操作", details={"operation": operation})
        try:
            return handler(api, input)
        except _CancellationObserved as cancellation:
            result = self._session_result(cancellation.event)
            result["cancelled"] = True
            return result

    def bind_cancellation(self, cancellation: threading.Event | None) -> None:
        """由 IPC owner 循环绑定当前命令的线程安全取消标志。"""

        self._assert_owner_thread()
        self._cancellation = cancellation

    def poll(self) -> None:
        """由 worker owner 循环周期性调用, 持续泵送真实 IDA 事件。"""

        self._assert_owner_thread()
        if self._api is None or self._closed:
            return
        self._pump_once(self._api)

    def close(self) -> None:
        """只终止 owned launch; attach 会话只能 detach。"""

        self._assert_owner_thread()
        if self._closed:
            return
        api = self._api
        try:
            if api is not None and int(api.ida_dbg.get_process_state()) != int(
                api.ida_dbg.DSTATE_NOTASK
            ):
                if self._mode == "attach":
                    if api.ida_dbg.detach_process():
                        self._wait_for(
                            api,
                            lambda event: event.kind == "process_detached",
                            timeout_ms=3000,
                            allow_cancel=False,
                        )
                elif self._mode == "launch":
                    if api.ida_dbg.exit_process():
                        self._wait_for(
                            api,
                            lambda event: event.kind == "process_exited",
                            timeout_ms=3000,
                            allow_cancel=False,
                        )
        except WorkerError:
            self.machine.observe(
                "worker_lost",
                {"reason": "close_timeout"},
                provenance=DebugEventProvenance.SERVICE_EVENT,
            )
        finally:
            job = self._job
            self._job = None
            try:
                if job is not None:
                    job.close()
            finally:
                self._closed = True

    def _require_runtime(self) -> IdaModules:
        if os.name != "nt":
            raise CapabilityError(
                "动态调试只支持 Windows 本机 x86 和 x64",
                capability="windows_local_debugger",
            )
        if self._api is None:
            self._api = require_ida(
                "ida_dbg",
                "ida_ida",
                "ida_idaapi",
                "ida_idd",
                "ida_loader",
                "ida_name",
                "ida_nalt",
            )
            current_path = Path(
                self._api.ida_loader.get_path(self._api.ida_loader.PATH_TYPE_IDB)
            ).resolve(strict=False)
            if current_path != self.checkout_path:
                raise WorkerError(
                    "checkout_mismatch",
                    "IDA 当前数据库不是 debug worker 私有 checkout",
                )
        if self._checkout_bitness is None:
            self._checkout_bitness = cast(Literal[32, 64], _idb_bitness(self._api))
        return self._api

    def _bitness(self) -> Literal[32, 64]:
        bitness = self._checkout_bitness
        if bitness is None:
            raise RuntimeError("debug worker 尚未固定 checkout IDB 位数")
        return bitness

    def _ensure_backend(self, api: IdaModules) -> None:
        api.ida_dbg.set_remote_debugger("", "", -1)
        current = api.ida_idd.dbg_get_name()
        if current is None or "win32" not in str(current).casefold():
            if not api.ida_dbg.load_debugger("win32", False):
                raise CapabilityError(
                    "IDA 无法在 headless 进程加载 win32 本地 debugger backend",
                    capability="windows_local_debugger",
                    details={"backend": "win32"},
                )
        loaded = api.ida_idd.dbg_get_name()
        if loaded is None or "win32" not in str(loaded).casefold():
            raise CapabilityError(
                "IDA 加载后的 debugger backend 不是 win32",
                capability="windows_local_debugger",
            )
        api.ida_dbg.set_remote_debugger("", "", -1)

    def _establish(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        mode = _text(input.get("mode"), "mode")
        if mode not in {"launch", "attach"}:
            raise WorkerInputError("mode 只允许 launch 或 attach")
        if mode == "attach" and not self.allow_attach:
            raise WorkerError("policy_denied", "attach 默认关闭")
        if self._established:
            raise WorkerError("debug_state_conflict", "一个 debug worker 只允许建立一个会话")
        self._established = True
        timeout_ms = _timeout(input)
        self.machine.begin_establish()
        self._ensure_backend(api)
        self._modules.clear()
        self._breakpoints.clear()
        self._owned_pid = None
        self._verified_target_pid = None
        self._last_debug_event_fingerprint = None
        self._establish_event = None
        if mode == "launch":
            target_value = input.get("target")
            if target_value is not None:
                target = Path(_text(target_value, "target")).resolve(strict=True)
                if target != self.sample_path:
                    raise WorkerError(
                        "policy_denied",
                        "debug launch 只能使用当前 workspace 的原样本副本",
                    )
            raw_args = input.get("arguments", [])
            if not isinstance(raw_args, list) or any(
                not isinstance(item, str) for item in raw_args
            ):
                raise WorkerInputError("arguments 必须是字符串数组")
            arguments = cast(list[str], raw_args)
            if any("\x00" in item or "\r" in item or "\n" in item for item in arguments):
                raise WorkerInputError("arguments 不允许 NUL 或换行")
            stop_on_entry = input.get("stop_on_entry", True)
            if not isinstance(stop_on_entry, bool):
                raise WorkerInputError("stop_on_entry 必须是布尔值")
            options = int(api.ida_dbg.DOPT_REDO_STACK)
            if stop_on_entry:
                options |= int(api.ida_dbg.DOPT_ENTRY_BPT)
            api.ida_dbg.set_debugger_options(options)
            self._job = WindowsJob()
            self._mode = "launch"
            result = int(
                api.ida_dbg.start_process(
                    str(self.sample_path),
                    subprocess.list2cmdline(arguments),
                    str(self.sample_path.parent),
                )
            )
            if result != 1:
                self._job.close()
                self._job = None
                self.machine.observe(
                    "request_error",
                    {"action": "launch", "ida_result": result},
                    provenance=DebugEventProvenance.SERVICE_EVENT,
                )
                raise WorkerError(
                    "debug_start_failed",
                    "IDA 拒绝启动 workspace 样本",
                    details={"ida_result": result},
                )
            observed = self._wait_for(
                api,
                lambda event: event.kind in {"process_started", "request_error"},
                timeout_ms=timeout_ms,
            )
            if observed.kind != "process_started":
                raise WorkerError("debug_start_failed", "IDA 报告 launch 请求错误")
            self._verify_established_target(api, observed)
            self._establish_event = observed
            if self.machine.state == DebugState.LOST:
                raise WorkerError(
                    "debug_target_lost",
                    "PROCESS_STARTED 到达时 IDA 已无法确认目标状态",
                )
            if stop_on_entry and self.machine.state != DebugState.SUSPENDED:
                entry_event = self._wait_for(
                    api,
                    lambda event: event.kind
                    in {"breakpoint", "process_suspended", "exception", "process_exited"},
                    timeout_ms=timeout_ms,
                )
                if entry_event.kind == "process_exited":
                    raise WorkerError(
                        "debug_target_exited",
                        "目标在到达入口停点前退出",
                    )
        elif mode == "attach":
            pid = _integer(input.get("pid"), "pid", minimum=1)
            self._mode = "attach"
            result = int(api.ida_dbg.attach_process(pid, -1))
            if result != 1:
                self.machine.observe(
                    "request_error",
                    {"action": "attach", "ida_result": result},
                    provenance=DebugEventProvenance.SERVICE_EVENT,
                )
                raise WorkerError(
                    "debug_attach_failed",
                    "IDA 拒绝 attach 指定 PID",
                    details={"ida_result": result, "pid": pid},
                )
            observed = self._wait_for(
                api,
                lambda event: event.kind in {"process_attached", "request_error"},
                timeout_ms=timeout_ms,
            )
            if observed.kind != "process_attached":
                raise WorkerError("debug_attach_failed", "IDA 报告 attach 请求错误")
            self._verify_established_target(api, observed)
            self._establish_event = observed
            if self.machine.state == DebugState.LOST:
                raise WorkerError(
                    "debug_target_lost",
                    "PROCESS_ATTACHED 到达时 IDA 已无法确认目标状态",
                )
        return self._session_result()

    def _verify_established_target(self, api: IdaModules, event: DebugEvent) -> None:
        pid = event.payload.get("pid")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise WorkerError("debug_process_query_failed", "调试建立事件缺少有效目标 PID")
        if self._verified_target_pid == pid:
            return
        try:
            verify_process_architecture(pid, bitness=self._bitness())
        except WorkerError:
            if self._mode == "attach":
                if api.ida_dbg.detach_process():
                    try:
                        self._wait_for(
                            api,
                            lambda item: item.kind == "process_detached",
                            timeout_ms=3_000,
                            allow_cancel=False,
                        )
                    except WorkerError:
                        pass
            elif self._mode == "launch":
                job = self._job
                self._job = None
                if job is not None:
                    try:
                        job.close()
                    except WorkerError:
                        pass
            self.machine.observe(
                "request_error",
                {"action": "verify_process_architecture", "pid": pid},
                provenance=DebugEventProvenance.SERVICE_EVENT,
            )
            raise
        self._verified_target_pid = pid

    def _control(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        action = _text(input.get("action"), "action")
        timeout_ms = _timeout(input)
        if action == "pause":
            if self.machine.state != DebugState.RUNNING:
                raise WorkerError("debug_state_conflict", "pause 只允许 running 状态")
            if not api.ida_dbg.suspend_process():
                raise WorkerError("debug_control_failed", "IDA 拒绝 pause")
            event = self._wait_for(
                api,
                lambda item: item.kind
                in {"process_suspended", "breakpoint", "exception", "process_exited"},
                timeout_ms=timeout_ms,
                cancellation_pause_requested=True,
            )
            if event.kind == "process_exited":
                raise WorkerError("debug_target_exited", "目标在 pause 前退出")
            return self._session_result(event)
        stop_id = input.get("stop_id")
        if action == "continue":
            self.machine.require_suspended(stop_id)
            immediate = self._resume_process(api, stop_id)
            if immediate is not None and immediate.kind in {
                "process_suspended",
                "breakpoint",
                "exception",
                "process_exited",
            }:
                return self._session_result(immediate)
            process_state = int(api.ida_dbg.get_process_state())
            if process_state == int(api.ida_dbg.DSTATE_RUN):
                event = self.machine.observe_running_state(action)
                return self._session_result(event)
            event = self._wait_for(
                api,
                lambda item: item.kind
                in {
                    "process_suspended",
                    "breakpoint",
                    "exception",
                    "process_exited",
                    "request_error",
                },
                timeout_ms=timeout_ms,
            )
            if event.kind == "request_error":
                raise WorkerError("debug_control_failed", "IDA 执行 continue 请求失败")
            return self._session_result(event)
        self.machine.require_suspended(stop_id)
        start_sequence = self.machine.latest_sequence
        if action == "step_into":
            accepted = bool(api.ida_dbg.step_into())
        elif action == "step_over":
            accepted = bool(api.ida_dbg.step_over())
        elif action == "run_to":
            runtime_address = self._resolve_module_rva(api, input.get("address"))
            return self._run_to(api, stop_id, runtime_address, timeout_ms)
        else:
            raise WorkerInputError("action 只允许 pause、continue、step_into、step_over 或 run_to")
        if not accepted:
            raise WorkerError("debug_control_failed", f"IDA 拒绝 {action}")
        self.machine.begin_execution(stop_id)
        if int(api.ida_dbg.get_process_state()) == int(api.ida_dbg.DSTATE_RUN):
            self.machine.observe_running_state(action)
        event = self._wait_for(
            api,
            lambda item: item.sequence > start_sequence
            and item.kind in {"step", "breakpoint", "exception", "process_exited", "request_error"},
            timeout_ms=timeout_ms,
        )
        if event.kind == "request_error":
            raise WorkerError("debug_control_failed", f"IDA 执行 {action} 请求失败")
        return self._session_result(event)

    def _run_to(
        self,
        api: IdaModules,
        stop_id: object,
        runtime_address: int,
        timeout_ms: int,
    ) -> dict[str, object]:
        """用显式临时断点实现可取消的 run-to, 避免 IDA 的阻塞式便捷调用。"""

        status = int(api.ida_dbg.check_bpt(runtime_address))
        added = status == int(api.ida_dbg.BPTCK_NONE)
        restore_disabled = status == int(api.ida_dbg.BPTCK_NO)
        if added and not api.ida_dbg.add_bpt(runtime_address, 0, api.ida_idd.BPT_DEFAULT):
            raise WorkerError("debug_control_failed", "IDA 拒绝设置 run-to 临时断点")
        if restore_disabled and not api.ida_dbg.enable_bpt(runtime_address, True):
            raise WorkerError("debug_control_failed", "IDA 拒绝临时启用 run-to 地址断点")
        if not self._is_breakpoint_active(api, runtime_address):
            self._restore_run_to_breakpoint(
                api,
                runtime_address,
                added=added,
                restore_disabled=restore_disabled,
            )
            raise WorkerError("debug_control_failed", "run-to 临时断点未实际激活")

        start_sequence = self.machine.latest_sequence
        try:
            immediate = self._resume_process(api, stop_id)
            if immediate is not None and immediate.kind in {
                "step",
                "breakpoint",
                "exception",
                "process_exited",
            }:
                return self._session_result(immediate)
            if int(api.ida_dbg.get_process_state()) == int(api.ida_dbg.DSTATE_RUN):
                self.machine.observe_running_state("run_to")
            event = self._wait_for(
                api,
                lambda item: item.sequence > start_sequence
                and item.kind
                in {"step", "breakpoint", "exception", "process_exited", "request_error"},
                timeout_ms=timeout_ms,
            )
            if event.kind == "request_error":
                raise WorkerError("debug_control_failed", "IDA 执行 run_to 请求失败")
            return self._session_result(event)
        finally:
            self._restore_run_to_breakpoint(
                api,
                runtime_address,
                added=added,
                restore_disabled=restore_disabled,
            )

    def _restore_run_to_breakpoint(
        self,
        api: IdaModules,
        runtime_address: int,
        *,
        added: bool,
        restore_disabled: bool,
    ) -> None:
        status = int(api.ida_dbg.check_bpt(runtime_address))
        if added and status != int(api.ida_dbg.BPTCK_NONE):
            if not api.ida_dbg.del_bpt(runtime_address):
                raise WorkerError("debug_control_failed", "IDA 无法清理 run-to 临时断点")
        elif restore_disabled and status != int(api.ida_dbg.BPTCK_NONE):
            if not api.ida_dbg.enable_bpt(runtime_address, False):
                raise WorkerError("debug_control_failed", "IDA 无法恢复 run-to 断点状态")

    def _events(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        after = _integer(input.get("after_sequence", 0), "after_sequence", minimum=0)
        if after > self.machine.latest_sequence:
            raise WorkerError(
                "cursor_stale",
                "debug event cursor 超过 worker 最新事件",
                details={"observed_latest_sequence": self.machine.latest_sequence},
            )
        limit = _integer(input.get("limit", 50), "limit", minimum=1, maximum=MAX_PAGE_SIZE)
        wait_ms = _integer(
            input.get("wait_ms", 0),
            "wait_ms",
            minimum=0,
            maximum=MAX_OPERATION_WAIT_MS,
        )
        deadline = time.monotonic() + wait_ms / 1000
        events = self.machine.events_after(after, limit)
        while not events and time.monotonic() < deadline:
            if self._is_cancel_requested():
                raise _CancellationObserved()
            self._pump_once(api)
            events = self.machine.events_after(after, limit)
            if not events:
                time.sleep(0.005)
        return {
            "debug_session_id": self.session_id,
            "events": [event.as_dict() for event in events],
            "latest_sequence": self.machine.latest_sequence,
            "state": self.machine.state.value,
            "stop_id": self.machine.stop_id,
        }

    def _inspect(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        view = _text(input.get("view", "state"), "view")
        if view == "state":
            return self._session_result()
        self.machine.require_suspended(input.get("stop_id"))
        if view == "modules":
            self._refresh_modules(api)
            return {"modules": list(self._modules.values()), **self._session_result()}
        if view == "threads":
            thread_quantity = int(api.ida_dbg.get_thread_qty())
            if thread_quantity <= 0:
                raise WorkerError(
                    "debug_thread_unavailable",
                    "suspended 目标没有可观察线程",
                )
            current_thread = int(api.ida_dbg.get_current_thread())
            threads = [
                {
                    "thread_id": int(api.ida_dbg.getn_thread(index)),
                    "name": str(api.ida_dbg.getn_thread_name(index) or ""),
                    "current": int(api.ida_dbg.getn_thread(index)) == current_thread,
                }
                for index in range(thread_quantity)
            ]
            if len({cast(int, item["thread_id"]) for item in threads}) != len(threads):
                raise WorkerError(
                    "debug_thread_unavailable",
                    "IDA 返回重复 thread_id",
                )
            if sum(bool(item["current"]) for item in threads) != 1:
                raise WorkerError(
                    "debug_thread_unavailable",
                    "IDA 当前线程不属于线程快照或不唯一",
                )
            return {"threads": threads, **self._session_result()}
        thread_id = input.get("thread_id", api.ida_dbg.get_current_thread())
        tid = _integer(thread_id, "thread_id", minimum=0)
        if not api.ida_dbg.select_thread(tid):
            raise WorkerError("debug_thread_not_found", "指定 thread_id 不存在")
        if view == "registers":
            bitness = self._bitness()
            register_names = _X64_REGISTER_NAMES if bitness == 64 else _X86_REGISTER_NAMES
            raw_names = input.get("registers", list(register_names))
            if not isinstance(raw_names, list) or any(
                not isinstance(item, str) for item in raw_names
            ):
                raise WorkerInputError("registers 必须是字符串数组")
            names = cast(list[str], raw_names)
            normalized = [name.upper() for name in names]
            if any(name not in register_names for name in normalized):
                raise WorkerInputError(
                    f"registers 仅允许当前 {bitness} 位 IDB 的 Windows 通用寄存器"
                )
            registers: dict[str, object] = {}
            for name in normalized:
                try:
                    register_info = api.ida_idd.register_info_t()
                    if not api.ida_dbg.get_dbg_reg_info(
                        name,
                        register_info,
                    ) or not api.ida_dbg.is_reg_integer(name):
                        raise WorkerError(
                            "debug_register_unavailable",
                            "当前 debugger backend 未提供请求的整数寄存器",
                            details={"register": name, "thread_id": tid},
                        )
                    value = api.ida_dbg.get_reg_val(name)
                except WorkerError:
                    raise
                except Exception as exc:
                    raise WorkerError(
                        "debug_register_unavailable",
                        "IDA 无法读取请求的寄存器",
                        details={
                            "stage": "metadata_or_value",
                            "register": name,
                            "thread_id": tid,
                            "exception_type": type(exc).__name__,
                        },
                    ) from exc
                if isinstance(value, int) and not isinstance(value, bool):
                    registers[name] = _hex(value)
                elif isinstance(value, float):
                    registers[name] = value
                elif isinstance(value, bytes):
                    registers[name] = {"bytes_hex": value.hex()}
                else:
                    raise WorkerError(
                        "debug_register_unavailable",
                        "IDA 未返回请求的寄存器值",
                        details={"register": name, "thread_id": tid},
                    )
            return {"thread_id": tid, "registers": registers, **self._session_result()}
        if view == "stack":
            try:
                trace = api.ida_idd.call_stack_t()
                collected = api.ida_dbg.collect_stack_trace(tid, trace)
            except Exception as exc:
                raise WorkerError(
                    "debug_stack_unavailable",
                    "IDA 无法建立调用栈快照",
                    details={
                        "stage": "collect",
                        "exception_type": type(exc).__name__,
                    },
                ) from exc
            if not collected:
                raise WorkerError("debug_stack_unavailable", "IDA 无法读取调用栈")
            frames: list[dict[str, object]] = []
            try:
                for frame in trace:
                    function_address = int(frame.funcea)
                    frames.append(
                        {
                            "call_address": _hex(int(frame.callea)),
                            "function_address": _hex(function_address),
                            "frame_pointer": _hex(int(frame.fp)),
                            "function_known": bool(frame.funcok),
                            "name": str(api.ida_name.get_name(function_address) or ""),
                        }
                    )
            except Exception as exc:
                raise WorkerError(
                    "debug_stack_unavailable",
                    "IDA 返回的调用栈快照不可读取",
                    details={
                        "stage": "read_frames",
                        "exception_type": type(exc).__name__,
                    },
                ) from exc
            return {"thread_id": tid, "frames": frames, **self._session_result()}
        if view == "memory":
            size = _integer(
                input.get("size"),
                "size",
                minimum=1,
                maximum=MAX_MEMORY_READ_BYTES,
            )
            address = self._resolve_runtime_address(
                api,
                input.get("address"),
                size=size,
            )
            data = api.ida_idd.dbg_read_memory(address, size)
            if data is None or len(data) != size:
                raise WorkerError(
                    "debug_memory_unavailable",
                    "IDA 无法完整读取目标进程内存",
                    details={"address": _hex(address), "size": size},
                )
            return {
                "address": _hex(address),
                "size": size,
                "bytes_hex": bytes(data).hex(),
                **self._session_result(),
            }
        if view == "memory_maps":
            api.ida_dbg.invalidate_dbg_state(api.ida_dbg.DBGINV_MEMCFG)
            api.ida_dbg.refresh_debugger_memory()
            ranges = api.ida_idd.meminfo_vec_t()
            ida_result = int(api.ida_dbg.get_dbg_memory_info(ranges))
            if ida_result >= 0 and len(ranges):
                maps: list[dict[str, object]] = []
                bitness_by_code = {0: 16, 1: 32, 2: 64}
                for item in ranges:
                    bitness = bitness_by_code.get(int(item.bitness))
                    if bitness is None:
                        raise WorkerError(
                            "debug_memory_unavailable",
                            "IDA 返回未知内存段位宽",
                            details={"bitness_code": int(item.bitness)},
                        )
                    maps.append(
                        {
                            "start": _hex(int(item.start_ea)),
                            "end": _hex(int(item.end_ea)),
                            "name": str(item.name),
                            "class": str(item.sclass),
                            "segment_base": _hex(int(item.sbase)),
                            "bitness": bitness,
                            "permissions": int(item.perm),
                            "source": "ida_debugger",
                        }
                    )
            else:
                pid = self._owned_pid
                if pid is None:
                    raise WorkerError(
                        "debug_memory_unavailable",
                        "IDA backend 不支持内存映射且当前不是 owned launch",
                        details={"ida_result": ida_result},
                    )
                maps = query_process_memory(pid)
            return {"memory_maps": maps, **self._session_result()}
        raise WorkerInputError(
            "view 只允许 state、modules、threads、registers、stack、memory 或 memory_maps"
        )

    def _breakpoint_operation(
        self, api: IdaModules, input: Mapping[str, object]
    ) -> dict[str, object]:
        if self.machine.state != DebugState.SUSPENDED or self.machine.stop_id is None:
            raise WorkerError(
                "debug_state_conflict",
                "断点配置只允许在真实 suspended 停点执行",
            )
        action = _text(input.get("action"), "action")
        if action == "list":
            return {
                "breakpoints": [
                    breakpoint.as_dict()
                    for breakpoint in sorted(self._breakpoints.values(), key=lambda item: item.id)
                ],
                **self._session_result(),
            }
        if action == "add":
            location = _mapping(input.get("location"), "location")
            if set(location) != {"module", "rva"}:
                raise WorkerInputError("breakpoint location 必须严格包含 module 和 rva")
            module = _text(location.get("module"), "location.module")
            rva = _canonical_hex(location.get("rva"), "location.rva")
            breakpoint = _Breakpoint(uuid.uuid4().hex, module, rva, True)
            self._activate_breakpoint(api, breakpoint)
            self._breakpoints[breakpoint.id] = breakpoint
            return {"breakpoint": breakpoint.as_dict(), **self._session_result()}
        breakpoint_id = _text(input.get("breakpoint_id"), "breakpoint_id")
        breakpoint = self._breakpoints.get(breakpoint_id)
        if breakpoint is None:
            raise WorkerError("breakpoint_not_found", "breakpoint_id 不存在")
        if action == "remove":
            if breakpoint.runtime_address is not None:
                if not api.ida_dbg.del_bpt(breakpoint.runtime_address):
                    raise WorkerError("debug_breakpoint_failed", "IDA 拒绝删除断点")
            del self._breakpoints[breakpoint_id]
            return {"removed": breakpoint_id, **self._session_result()}
        if action == "enable":
            enabled = input.get("enabled")
            if not isinstance(enabled, bool):
                raise WorkerInputError("enabled 必须是布尔值")
            previous_enabled = breakpoint.enabled
            previous_active = breakpoint.active
            if breakpoint.runtime_address is not None:
                if not api.ida_dbg.enable_bpt(breakpoint.runtime_address, enabled):
                    raise WorkerError("debug_breakpoint_failed", "IDA 拒绝更新断点")
                breakpoint.enabled = enabled
                breakpoint.active = enabled and self._is_breakpoint_active(
                    api,
                    breakpoint.runtime_address,
                )
            elif enabled:
                breakpoint.enabled = True
                try:
                    self._activate_breakpoint(api, breakpoint)
                except WorkerError:
                    breakpoint.enabled = previous_enabled
                    breakpoint.active = previous_active
                    raise
            else:
                breakpoint.enabled = False
                breakpoint.active = False
            return {"breakpoint": breakpoint.as_dict(), **self._session_result()}
        raise WorkerInputError("breakpoint action 只允许 list、add、remove 或 enable")

    def _finish(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        action = _text(input.get("action"), "action")
        timeout_ms = _timeout(input)
        if action == "terminate":
            if self._mode != "launch":
                raise WorkerError("policy_denied", "只能 terminate 本服务 launch 的目标")
            if self.machine.state == DebugState.EXITED:
                observed = self.machine.latest_event_of(frozenset({"process_exited"}))
                if observed is None:
                    raise WorkerError(
                        "debug_state_conflict",
                        "exited 状态缺少已观察的 PROCESS_EXITED 事实",
                    )
                return self._session_result(observed)
            if self.machine.state == DebugState.DETACHED:
                raise WorkerError("debug_state_conflict", "launch 目标不处于可终止状态")
            if int(api.ida_dbg.get_process_state()) == int(api.ida_dbg.DSTATE_NOTASK):
                raise WorkerError(
                    "debug_state_conflict",
                    "IDA 已无活动 launch 目标且未观察到 PROCESS_EXITED",
                )
            if not api.ida_dbg.exit_process():
                raise WorkerError("debug_finish_failed", "IDA 拒绝 terminate")
            event = self._wait_for(
                api,
                lambda item: item.kind == "process_exited",
                timeout_ms=timeout_ms,
                allow_cancel=False,
            )
            if self._job is not None:
                self._job.close()
                self._job = None
            return self._session_result(event)
        if action == "detach":
            if self._mode != "attach":
                raise WorkerError("policy_denied", "launch 目标不得用 detach 规避 Job Object")
            if self.machine.state == DebugState.DETACHED:
                observed = self.machine.latest_event_of(frozenset({"process_detached"}))
                if observed is None:
                    raise WorkerError(
                        "debug_state_conflict",
                        "detached 状态缺少已观察的 PROCESS_DETACHED 事实",
                    )
                return self._session_result(observed)
            if self.machine.state == DebugState.EXITED:
                raise WorkerError("debug_state_conflict", "attach 目标不处于可 detach 状态")
            if int(api.ida_dbg.get_process_state()) == int(api.ida_dbg.DSTATE_NOTASK):
                raise WorkerError(
                    "debug_state_conflict",
                    "IDA 已无活动 attach 目标且未观察到 PROCESS_DETACHED",
                )
            if not api.ida_dbg.detach_process():
                raise WorkerError("debug_finish_failed", "IDA 拒绝 detach")
            event = self._wait_for(
                api,
                lambda item: item.kind == "process_detached",
                timeout_ms=timeout_ms,
                allow_cancel=False,
            )
            return self._session_result(event)
        raise WorkerInputError("finish action 只允许 terminate 或 detach")

    def _resume_process(self, api: IdaModules, stop_id: object) -> DebugEvent | None:
        result = int(
            api.ida_dbg.wait_for_next_event(
                api.ida_dbg.WFNE_CONT | api.ida_dbg.WFNE_NOWAIT | api.ida_dbg.WFNE_SILENT,
                0,
            )
        )
        if result < int(api.ida_dbg.DEC_TIMEOUT):
            raise WorkerError(
                "debug_control_failed",
                "IDA 无法恢复目标执行",
                details={"ida_result": result},
            )
        self.machine.begin_execution(stop_id)
        if result > int(api.ida_dbg.DEC_TIMEOUT):
            return self._consume_current_event(api)
        return None

    def _pump_once(self, api: IdaModules, *, wait_seconds: int = 0) -> DebugEvent | None:
        event_code = int(
            api.ida_dbg.wait_for_next_event(
                api.ida_dbg.WFNE_ANY | api.ida_dbg.WFNE_SILENT,
                wait_seconds,
            )
        )
        if event_code == int(api.ida_dbg.DEC_NOTASK):
            if self.machine.state in {DebugState.EXITED, DebugState.DETACHED}:
                return None
            return self.machine.observe(
                "worker_lost",
                {"reason": "debugger_notask_without_terminal_event"},
                provenance=DebugEventProvenance.SERVICE_EVENT,
            )
        if event_code < int(api.ida_dbg.DEC_TIMEOUT):
            return self.machine.observe(
                "request_error",
                {
                    "action": "wait_for_next_event",
                    "ida_result": event_code,
                },
                provenance=DebugEventProvenance.SERVICE_EVENT,
            )
        if event_code == int(api.ida_dbg.DEC_TIMEOUT):
            return None
        return self._consume_current_event(api)

    def _consume_current_event(self, api: IdaModules) -> DebugEvent | None:
        """消费刚由 IDA 返回的当前事件, 不再次调用 wait_for_next_event。"""

        event = api.ida_dbg.get_debug_event()
        if event is None:
            raise WorkerError("debug_event_missing", "IDA 返回事件码但没有 debug_event")
        kind = self._event_kind(api, int(event.eid()))
        payload: dict[str, object] = {
            "address": _hex(int(event.ea)),
            "event_id": int(event.eid()),
        }
        pid = int(event.pid)
        thread_id = int(event.tid)
        if pid >= 0:
            payload["pid"] = pid
        if thread_id >= 0:
            payload["thread_id"] = thread_id
        if kind in {"process_started", "process_attached", "library_loaded"}:
            module = event.modinfo()
            module_info: dict[str, object] = {
                "name": str(module.name),
                "base": _hex(int(module.base)),
                "size": int(module.size),
                "end": _hex(int(module.base) + int(module.size)),
            }
            payload["module"] = module_info
            self._modules[str(module.name)] = module_info
        elif kind == "library_unloaded":
            payload["module_name"] = str(event.info())
        elif kind == "breakpoint":
            payload["breakpoint_address"] = _hex(int(event.bpt_ea()))
        elif kind == "exception":
            exception = event.exc()
            payload["exception"] = {
                "code": int(exception.code),
                "address": _hex(int(exception.ea)),
                "can_continue": bool(exception.can_cont),
                "information": str(exception.info),
            }
        elif kind in {"process_exited", "thread_exited"}:
            payload["exit_code"] = int(event.exit_code())
        if kind in {"process_started", "process_attached"}:
            state = int(api.ida_dbg.get_process_state())
            payload["process_state"] = (
                "suspended"
                if state == int(api.ida_dbg.DSTATE_SUSP)
                else "running"
                if state == int(api.ida_dbg.DSTATE_RUN)
                else "none"
            )
        fingerprint = (
            int(event.eid()),
            pid,
            thread_id,
            int(event.ea),
            repr(payload),
        )
        if fingerprint == self._last_debug_event_fingerprint and (
            (
                int(api.ida_dbg.get_process_state()) == int(api.ida_dbg.DSTATE_SUSP)
                and self.machine.state == DebugState.SUSPENDED
                and self.machine.stop_id is not None
            )
            or self.machine.state
            in {
                DebugState.EXITED,
                DebugState.DETACHED,
                DebugState.LOST,
                DebugState.FAILED,
            }
        ):
            return None
        self._last_debug_event_fingerprint = fingerprint
        observed = self.machine.observe(
            kind,
            payload,
            provenance=DebugEventProvenance.IDA_EVENT,
        )
        if kind == "process_started" and self._mode == "launch":
            self._owned_pid = pid
            if self._job is None:
                raise WorkerError("job_object_failed", "launch 事件到达时缺少 Job Object")
            try:
                self._job.assign(self._owned_pid)
            except WorkerError:
                api.ida_dbg.exit_process()
                self._job.close()
                self._job = None
                self.machine.observe(
                    "request_error",
                    {"action": "job_assignment"},
                    provenance=DebugEventProvenance.SERVICE_EVENT,
                )
                raise
        if kind == "library_unloaded":
            self._forget_unloaded_module(api, payload)
        if kind in {"process_exited", "process_detached"}:
            self._clear_runtime_facts()
            if self._job is not None:
                self._job.close()
                self._job = None
            self._owned_pid = None
            self._verified_target_pid = None
        elif kind == "library_loaded" or self.machine.state == DebugState.SUSPENDED:
            self._reconcile_breakpoints(api)
        return observed

    def _event_kind(self, api: IdaModules, event_id: int) -> str:
        mapping = {
            int(api.ida_idd.PROCESS_STARTED): "process_started",
            int(api.ida_idd.PROCESS_EXITED): "process_exited",
            int(api.ida_idd.PROCESS_ATTACHED): "process_attached",
            int(api.ida_idd.PROCESS_DETACHED): "process_detached",
            int(api.ida_idd.PROCESS_SUSPENDED): "process_suspended",
            int(api.ida_idd.THREAD_STARTED): "thread_started",
            int(api.ida_idd.THREAD_EXITED): "thread_exited",
            int(api.ida_idd.LIB_LOADED): "library_loaded",
            int(api.ida_idd.LIB_UNLOADED): "library_unloaded",
            int(api.ida_idd.BREAKPOINT): "breakpoint",
            int(api.ida_idd.STEP): "step",
            int(api.ida_idd.EXCEPTION): "exception",
            int(api.ida_idd.INFORMATION): "information",
        }
        return mapping.get(event_id, "unknown")

    def _wait_for(
        self,
        api: IdaModules,
        predicate: Callable[[DebugEvent], bool],
        *,
        timeout_ms: int,
        allow_cancel: bool = True,
        cancellation_pause_requested: bool = False,
    ) -> DebugEvent:
        deadline = time.monotonic() + timeout_ms / 1000
        pause_requested = cancellation_pause_requested
        while time.monotonic() < deadline:
            if allow_cancel and self._is_cancel_requested():
                if self.machine.state == DebugState.SUSPENDED and self.machine.stop_id is not None:
                    raise _CancellationObserved()
                process_state = int(api.ida_dbg.get_process_state())
                if process_state == int(api.ida_dbg.DSTATE_RUN) and not pause_requested:
                    pause_result = bool(api.ida_dbg.request_suspend_process())
                    if not pause_result:
                        raise WorkerError(
                            "debug_cancel_failed",
                            "取消请求无法触发真实 debugger pause",
                        )
                    api.ida_dbg.run_requests()
                    pause_requested = True
            event = self._pump_once(api, wait_seconds=1)
            if (
                allow_cancel
                and self._is_cancel_requested()
                and self.machine.state == DebugState.SUSPENDED
                and self.machine.stop_id is not None
            ):
                raise _CancellationObserved(event)
            if event is not None and predicate(event):
                return event
            if event is not None and event.kind == "request_error":
                raise WorkerError(
                    "debug_event_failed",
                    "IDA wait_for_next_event 返回请求错误",
                    details={"event_sequence": event.sequence},
                )
            time.sleep(0.005)
        self.machine.observe(
            "worker_lost",
            {"reason": "event_timeout", "timeout_ms": timeout_ms},
            provenance=DebugEventProvenance.SERVICE_EVENT,
        )
        raise WorkerError(
            "debug_event_timeout",
            "未在时限内观察到对应 IDA debugger 事件",
            details={"timeout_ms": timeout_ms},
        )

    def _is_cancel_requested(self) -> bool:
        cancellation = self._cancellation
        return cancellation is not None and cancellation.is_set()

    def _refresh_modules(self, api: IdaModules) -> None:
        module = api.ida_idd.modinfo_t()
        self._modules.clear()
        if not api.ida_dbg.get_first_module(module):
            return
        while True:
            info: dict[str, object] = {
                "name": str(module.name),
                "base": _hex(int(module.base)),
                "size": int(module.size),
                "end": _hex(int(module.base) + int(module.size)),
            }
            self._modules[str(module.name)] = info
            if not api.ida_dbg.get_next_module(module):
                break

    def _module(self, api: IdaModules, requested: str) -> Mapping[str, object] | None:
        self._refresh_modules(api)
        return self._cached_module(requested)

    def _cached_module(self, requested: str) -> Mapping[str, object] | None:
        normalized = requested.casefold()
        matches = [
            value
            for path, value in self._modules.items()
            if path.casefold() == normalized or Path(path).name.casefold() == normalized
        ]
        if len(matches) > 1:
            raise WorkerError("ambiguous_reference", "module 名称匹配多个已加载模块")
        return matches[0] if matches else None

    def _resolve_module_rva(self, api: IdaModules, raw: object) -> int:
        ref = _mapping(raw, "address")
        if set(ref) != {"space", "module", "rva"} or ref.get("space") != "runtime_module":
            raise WorkerInputError("run_to 地址必须是严格的 runtime_module + module + rva")
        module = _text(ref.get("module"), "address.module")
        rva = _canonical_hex(ref.get("rva"), "address.rva")
        module_info = self._module(api, module)
        if module_info is None:
            raise WorkerError("module_not_loaded", "目标 module 尚未加载")
        size = cast(int, module_info["size"])
        if rva >= size:
            raise WorkerError("address_unmapped", "RVA 超出 module 范围")
        return int(cast(str, module_info["base"]), 16) + rva

    def _resolve_runtime_address(
        self,
        api: IdaModules,
        raw: object,
        *,
        size: int,
    ) -> int:
        ref = _mapping(raw, "address")
        if set(ref) != {"space", "module", "va", "stop_id"} or ref.get("space") != "runtime":
            raise WorkerInputError("memory 地址必须是严格的 runtime + module + va + stop_id")
        self.machine.require_suspended(ref.get("stop_id"))
        module_name = _text(ref.get("module"), "address.module")
        va = _canonical_hex(ref.get("va"), "address.va")
        module = self._module(api, module_name)
        if module is None:
            raise WorkerError(
                "module_not_loaded",
                "runtime 地址无法唯一绑定到 module",
            )
        start = int(cast(str, module["base"]), 16)
        end = int(cast(str, module["end"]), 16)
        if not start <= va or va > end - size:
            raise WorkerError("address_unmapped", "runtime VA 不在指定 module 内")
        return va

    def _activate_breakpoint(self, api: IdaModules, breakpoint: _Breakpoint) -> None:
        module = self._module(api, breakpoint.module)
        if module is None:
            breakpoint.active = False
            breakpoint.runtime_address = None
            return
        if breakpoint.rva >= cast(int, module["size"]):
            raise WorkerError("address_unmapped", "breakpoint RVA 超出 module 范围")
        address = int(cast(str, module["base"]), 16) + breakpoint.rva
        check = int(api.ida_dbg.check_bpt(address))
        if check == int(api.ida_dbg.BPTCK_NONE):
            if not api.ida_dbg.add_bpt(address, 0, api.ida_idd.BPT_DEFAULT):
                raise WorkerError(
                    "debug_breakpoint_failed",
                    "IDA 拒绝设置 module+rva 断点",
                    details={"module": breakpoint.module, "rva": _hex(breakpoint.rva)},
                )
            check = int(api.ida_dbg.check_bpt(address))
        should_enable = breakpoint.enabled and check == int(api.ida_dbg.BPTCK_NO)
        should_disable = not breakpoint.enabled and check != int(api.ida_dbg.BPTCK_NO)
        if (should_enable or should_disable) and not api.ida_dbg.enable_bpt(
            address,
            breakpoint.enabled,
        ):
            raise WorkerError("debug_breakpoint_failed", "IDA 拒绝更新断点")
        breakpoint.runtime_address = address
        breakpoint.active = breakpoint.enabled and self._is_breakpoint_active(api, address)

    def _is_breakpoint_active(self, api: IdaModules, address: int) -> bool:
        status = int(api.ida_dbg.check_bpt(address))
        return status in {
            int(api.ida_dbg.BPTCK_YES),
            int(api.ida_dbg.BPTCK_ACT),
        }

    def _reconcile_breakpoints(self, api: IdaModules) -> None:
        self._refresh_modules(api)
        for breakpoint in self._breakpoints.values():
            module = self._cached_module(breakpoint.module)
            if module is None:
                self._drop_resolved_breakpoint(api, breakpoint)
                continue
            if breakpoint.rva >= cast(int, module["size"]):
                self._drop_resolved_breakpoint(api, breakpoint)
                continue
            expected = int(cast(str, module["base"]), 16) + breakpoint.rva
            if breakpoint.runtime_address is not None and breakpoint.runtime_address != expected:
                self._drop_resolved_breakpoint(api, breakpoint)
            self._activate_breakpoint(api, breakpoint)

    def _drop_resolved_breakpoint(
        self,
        api: IdaModules,
        breakpoint: _Breakpoint,
    ) -> None:
        address = breakpoint.runtime_address
        if address is not None and int(api.ida_dbg.check_bpt(address)) != int(
            api.ida_dbg.BPTCK_NONE
        ):
            if not api.ida_dbg.del_bpt(address):
                raise WorkerError(
                    "debug_breakpoint_failed",
                    "IDA 拒绝清理已失效的 runtime breakpoint",
                    details={"runtime_address": _hex(address)},
                )
        breakpoint.runtime_address = None
        breakpoint.active = False

    def _forget_unloaded_module(
        self,
        api: IdaModules,
        payload: Mapping[str, object],
    ) -> None:
        raw_address = payload.get("address")
        address = int(raw_address, 16) if isinstance(raw_address, str) else None
        raw_name = payload.get("module_name")
        name = raw_name.casefold() if isinstance(raw_name, str) else None
        unloaded: list[str] = []
        for path, module in self._modules.items():
            base = int(cast(str, module["base"]), 16)
            if base == address or (
                name is not None and (path.casefold() == name or Path(path).name.casefold() == name)
            ):
                unloaded.append(path)
        for path in unloaded:
            del self._modules[path]
        for breakpoint in self._breakpoints.values():
            if breakpoint.runtime_address is not None and any(
                breakpoint.module.casefold() in {path.casefold(), Path(path).name.casefold()}
                for path in unloaded
            ):
                self._drop_resolved_breakpoint(api, breakpoint)

    def _clear_runtime_facts(self) -> None:
        self._modules.clear()
        for breakpoint in self._breakpoints.values():
            breakpoint.runtime_address = None
            breakpoint.active = False

    def _session_result(self, event: DebugEvent | None = None) -> dict[str, object]:
        result: dict[str, object] = {
            "debug_session_id": self.session_id,
            "state": self.machine.state.value,
            "stop_id": self.machine.stop_id,
            "latest_sequence": self.machine.latest_sequence,
            "mode": self._mode,
        }
        if self._owned_pid is not None:
            result["owned_pid"] = self._owned_pid
        if event is not None:
            result["event"] = event.as_dict()
        if self._establish_event is not None:
            result["establish_event"] = self._establish_event.as_dict()
        return result


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise WorkerInputError(f"{label} 必须是字符串键对象")
    return cast(Mapping[str, object], value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkerInputError(f"{label} 必须是非空字符串")
    return value


def _integer(value: object, label: str, *, minimum: int, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise WorkerInputError(f"{label} 必须是大于等于 {minimum} 的整数")
    if maximum is not None and value > maximum:
        raise WorkerInputError(f"{label} 超过上限 {maximum}")
    return value


def _canonical_hex(value: object, label: str) -> int:
    text = _text(value, label)
    if _CANONICAL_HEX.fullmatch(text) is None:
        raise WorkerInputError(f"{label} 必须是规范小写十六进制")
    return int(text, 16)


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _timeout(input: Mapping[str, object]) -> int:
    return _integer(
        input.get("timeout_ms", 10_000),
        "timeout_ms",
        minimum=1,
        maximum=MAX_OPERATION_WAIT_MS,
    )
