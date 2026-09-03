"""DebugWorker 的停点身份、断点事务和地址边界测试。"""

from __future__ import annotations

from pathlib import Path
from threading import Event
from types import ModuleType
from typing import cast

import pytest

from ida_re_mcp.worker._ida import IdaModules
from ida_re_mcp.worker.debug import (
    DebugEventProvenance,
    DebugState,
    DebugStateMachine,
    DebugWorker,
)
from ida_re_mcp.worker.errors import WorkerError

_X86_REGISTERS = ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "EFL")
_X64_REGISTERS = (
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


class _ModuleInfo:
    name = ""
    base = 0
    size = 0


class _RegisterInfo:
    pass


class _FakeIda(ModuleType):
    def __init__(self, bitness: int) -> None:
        super().__init__("ida_ida")
        self._bitness = bitness

    def inf_get_procname(self) -> str:
        return "metapc"

    def inf_is_64bit(self) -> bool:
        return self._bitness == 64

    def inf_is_32bit_exactly(self) -> bool:
        return self._bitness == 32


class _FakeDebugEvent:
    def __init__(self, event_id: int, *, ea: int = 0x180001000) -> None:
        self.pid = 100
        self.tid = 7
        self.ea = ea
        self._event_id = event_id

    def eid(self) -> int:
        return self._event_id

    def modinfo(self) -> _ModuleInfo:
        module = _ModuleInfo()
        module.name = r"C:\fixtures\debug_target_x64.exe"
        module.base = 0x180000000
        module.size = 0x4000
        return module

    def bpt_ea(self) -> int:
        return self.ea

    def info(self) -> str:
        return r"C:\fixtures\debug_target_x64.exe"

    def exit_code(self) -> int:
        return 0


class _FakeDbg(ModuleType):
    DSTATE_NOTASK = 0
    DSTATE_SUSP = -1
    DSTATE_RUN = 1
    BPTCK_NONE = 0
    BPTCK_NO = 1
    BPTCK_YES = 2
    BPTCK_ACT = 3
    DEC_NOTASK = -2
    DEC_ERROR = -1
    DEC_TIMEOUT = 0
    WFNE_ANY = 1
    WFNE_SUSP = 2
    WFNE_SILENT = 4
    WFNE_CONT = 8
    WFNE_NOWAIT = 16
    WFNE_USEC = 32

    def __init__(self) -> None:
        super().__init__("ida_dbg")
        self.breakpoints: dict[int, int] = {}
        self.reject_add = False
        self.reject_enable = False
        self.read_calls = 0
        self.suspend_calls = 0
        self.process_state = self.DSTATE_SUSP
        self._events: list[_FakeDebugEvent] = []
        self._current_event: _FakeDebugEvent | None = None
        self.repeat_current_event = False
        self.continue_event: _FakeDebugEvent | None = None
        self.wait_error = False
        self.forced_wait_code: int | None = None
        self.modules_available = True
        self.register_values = {
            name: index for index, name in enumerate((*_X64_REGISTERS, *_X86_REGISTERS), start=1)
        }

    def get_first_module(self, module: object) -> bool:
        assert isinstance(module, _ModuleInfo)
        if not self.modules_available:
            return False
        module.name = r"C:\fixtures\debug_target_x64.exe"
        module.base = 0x180000000
        module.size = 0x4000
        return True

    def get_next_module(self, _module: object) -> bool:
        return False

    def add_bpt(self, address: int, _size: int, _kind: int) -> bool:
        if self.reject_add:
            return False
        self.breakpoints[address] = self.BPTCK_YES
        return True

    def check_bpt(self, address: int) -> int:
        return self.breakpoints.get(address, self.BPTCK_NONE)

    def enable_bpt(self, address: int, enabled: bool) -> bool:
        if self.reject_enable:
            return False
        if address not in self.breakpoints:
            return False
        self.breakpoints[address] = self.BPTCK_YES if enabled else self.BPTCK_NO
        return True

    def del_bpt(self, address: int) -> bool:
        return self.breakpoints.pop(address, None) is not None

    def get_current_thread(self) -> int:
        return 7

    def select_thread(self, thread_id: int) -> bool:
        return thread_id == 7

    def get_dbg_reg_info(self, name: str, _info: _RegisterInfo) -> bool:
        return name in self.register_values

    def is_reg_integer(self, name: str) -> bool:
        return name in self.register_values

    def get_reg_val(self, name: str) -> int:
        return self.register_values[name]

    def step_into(self) -> bool:
        self.process_state = self.DSTATE_RUN
        return True

    def step_over(self) -> bool:
        self.process_state = self.DSTATE_RUN
        return True

    def get_process_state(self) -> int:
        return self.process_state

    def suspend_process(self) -> bool:
        self.suspend_calls += 1
        self.process_state = self.DSTATE_SUSP
        self._events.append(_FakeDebugEvent(_FakeIdd.PROCESS_SUSPENDED))
        return True

    def request_suspend_process(self) -> bool:
        return self.suspend_process()

    def run_requests(self) -> bool:
        return True

    def wait_for_next_event(self, flags: int, _timeout: int) -> int:
        if self.forced_wait_code is not None:
            return self.forced_wait_code
        if self.wait_error:
            return -1
        if flags & self.WFNE_CONT:
            if self.continue_event is not None:
                self._current_event = self.continue_event
                self.continue_event = None
                self.process_state = self.DSTATE_SUSP
                return self._current_event.eid()
            self.process_state = self.DSTATE_RUN
            return self.DEC_TIMEOUT
        if self._events:
            self._current_event = self._events.pop(0)
        elif not self.repeat_current_event or self._current_event is None:
            return 0
        return self._current_event.eid()

    def get_debug_event(self) -> _FakeDebugEvent | None:
        return self._current_event

    def queue_event(self, event_id: int, *, ea: int = 0x180001000) -> None:
        self._events.append(_FakeDebugEvent(event_id, ea=ea))


class _FakeIdd(ModuleType):
    BPT_DEFAULT = 0
    PROCESS_STARTED = 1
    PROCESS_EXITED = 2
    PROCESS_ATTACHED = 3
    PROCESS_DETACHED = 4
    PROCESS_SUSPENDED = 5
    THREAD_STARTED = 6
    THREAD_EXITED = 7
    LIB_LOADED = 8
    LIB_UNLOADED = 9
    BREAKPOINT = 10
    STEP = 11
    EXCEPTION = 12
    INFORMATION = 13

    def __init__(self, debugger: _FakeDbg) -> None:
        super().__init__("ida_idd")
        self.modinfo_t = _ModuleInfo
        self.register_info_t = _RegisterInfo
        self._debugger = debugger

    def dbg_read_memory(self, _address: int, size: int) -> bytes:
        self._debugger.read_calls += 1
        return bytes(size)


class _InjectedDebugWorker(DebugWorker):
    def inject_api(self, api: IdaModules) -> None:
        self._api = api


def _worker(tmp_path: Path, *, bitness: int = 64) -> tuple[_InjectedDebugWorker, _FakeDbg]:
    checkout = tmp_path / "checkout.i64"
    sample = tmp_path / "debug_target_x64.exe"
    checkout.write_bytes(b"idb")
    sample.write_bytes(b"MZ")
    worker = _InjectedDebugWorker(checkout, sample)
    debugger = _FakeDbg()
    api = IdaModules(
        {
            "ida_dbg": debugger,
            "ida_ida": _FakeIda(bitness),
            "ida_idd": _FakeIdd(debugger),
        }
    )
    worker.inject_api(api)
    worker.machine.begin_establish()
    worker.machine.observe(
        "process_started",
        {"process_state": "suspended", "event_id": _FakeIdd.PROCESS_STARTED},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    return worker, debugger


@pytest.mark.parametrize(
    ("bitness", "expected_names", "other_instruction_pointer"),
    [
        (32, list(_X86_REGISTERS), "RIP"),
        (64, list(_X64_REGISTERS), "EIP"),
    ],
)
def test_register_snapshot_uses_idb_bitness(
    tmp_path: Path,
    bitness: int,
    expected_names: list[str],
    other_instruction_pointer: str,
) -> None:
    worker, _debugger = _worker(tmp_path, bitness=bitness)
    result = worker.execute(
        "debug.inspect",
        {"view": "registers", "stop_id": worker.machine.stop_id},
    )

    registers = result["registers"]
    assert isinstance(registers, dict)
    assert list(cast(dict[str, object], registers)) == expected_names

    with pytest.raises(WorkerError) as rejected:
        worker.execute(
            "debug.inspect",
            {
                "view": "registers",
                "stop_id": worker.machine.stop_id,
                "registers": [other_instruction_pointer],
            },
        )

    assert rejected.value.code == "invalid_worker_input"


def test_control_acceptance_invalidates_old_stop_before_fast_stop() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()
    first = machine.observe(
        "process_started",
        {"process_state": "suspended", "event_id": _FakeIdd.PROCESS_STARTED},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    assert first.stop_id is not None

    machine.begin_execution(first.stop_id)
    assert machine.state == DebugState.SUSPENDED
    assert machine.stop_id is None

    second = machine.observe(
        "step",
        {"event_id": _FakeIdd.STEP},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    assert second.stop_id is not None
    assert second.stop_id != first.stop_id
    with pytest.raises(WorkerError, match="stop_id"):
        machine.require_suspended(first.stop_id)


def test_started_event_without_real_process_state_is_lost() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()

    event = machine.observe(
        "process_started",
        {"process_state": "none", "event_id": _FakeIdd.PROCESS_STARTED},
        provenance=DebugEventProvenance.IDA_EVENT,
    )

    assert event.state == DebugState.LOST
    assert machine.stop_id is None


def test_breakpoint_add_and_enable_are_transactional(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    debugger.reject_add = True
    with pytest.raises(WorkerError) as rejected:
        worker.execute(
            "debug.breakpoints",
            {
                "action": "add",
                "location": {"module": "debug_target_x64.exe", "rva": "0x1000"},
            },
        )
    assert rejected.value.code == "debug_breakpoint_failed"
    assert worker.execute("debug.breakpoints", {"action": "list"})["breakpoints"] == []

    debugger.reject_add = False
    added = worker.execute(
        "debug.breakpoints",
        {
            "action": "add",
            "location": {"module": "debug_target_x64.exe", "rva": "0x1000"},
        },
    )
    breakpoint_value = added["breakpoint"]
    assert isinstance(breakpoint_value, dict)
    breakpoint = cast(dict[str, object], breakpoint_value)
    breakpoint_id_value = breakpoint.get("breakpoint_id")
    assert isinstance(breakpoint_id_value, str)
    breakpoint_id = breakpoint_id_value
    assert breakpoint["active"] is True

    debugger.reject_enable = True
    with pytest.raises(WorkerError) as enable_rejected:
        worker.execute(
            "debug.breakpoints",
            {
                "action": "enable",
                "breakpoint_id": breakpoint_id,
                "enabled": False,
            },
        )
    assert enable_rejected.value.code == "debug_breakpoint_failed"
    listed = worker.execute("debug.breakpoints", {"action": "list"})
    listed_breakpoints = listed["breakpoints"]
    assert isinstance(listed_breakpoints, list)
    typed_breakpoints = cast(list[dict[str, object]], listed_breakpoints)
    assert typed_breakpoints[0]["enabled"] is True

    debugger.reject_enable = False
    disabled = worker.execute(
        "debug.breakpoints",
        {
            "action": "enable",
            "breakpoint_id": breakpoint_id,
            "enabled": False,
        },
    )
    disabled_breakpoint = disabled["breakpoint"]
    assert isinstance(disabled_breakpoint, dict)
    assert disabled_breakpoint["enabled"] is False
    assert disabled_breakpoint["active"] is False

    worker.execute(
        "debug.breakpoints",
        {"action": "remove", "breakpoint_id": breakpoint_id},
    )
    assert debugger.breakpoints == {}


def test_memory_read_rejects_a_range_crossing_module_end(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    stop_id = worker.machine.stop_id
    assert stop_id is not None

    with pytest.raises(WorkerError) as rejected:
        worker.execute(
            "debug.inspect",
            {
                "view": "memory",
                "stop_id": stop_id,
                "address": {
                    "space": "runtime",
                    "module": "debug_target_x64.exe",
                    "va": "0x180003fff",
                    "stop_id": stop_id,
                },
                "size": 2,
            },
        )

    assert rejected.value.code == "address_unmapped"
    assert debugger.read_calls == 0


def test_run_to_cancellation_observes_real_pause_and_removes_temporary_breakpoint(
    tmp_path: Path,
) -> None:
    worker, debugger = _worker(tmp_path)
    old_stop_id = worker.machine.stop_id
    assert old_stop_id is not None
    cancellation = Event()
    cancellation.set()
    worker.bind_cancellation(cancellation)
    try:
        result = worker.execute(
            "debug.control",
            {
                "action": "run_to",
                "stop_id": old_stop_id,
                "address": {
                    "space": "runtime_module",
                    "module": "debug_target_x64.exe",
                    "rva": "0x1040",
                },
                "timeout_ms": 1_000,
            },
        )
    finally:
        worker.bind_cancellation(None)

    assert result["cancelled"] is True
    assert result["state"] == "suspended"
    assert result["stop_id"] != old_stop_id
    assert debugger.suspend_calls == 1
    assert debugger.breakpoints == {}
    event = result["event"]
    assert isinstance(event, dict)
    assert event["kind"] == "process_suspended"


def test_suspended_current_event_is_not_emitted_repeatedly(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    before = worker.machine.latest_sequence
    debugger.queue_event(_FakeIdd.PROCESS_SUSPENDED)
    debugger.repeat_current_event = True

    worker.poll()
    worker.poll()
    worker.poll()

    assert worker.machine.latest_sequence == before + 1


def test_continue_consumes_an_immediate_stop_event_without_losing_it(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    debugger.queue_event(_FakeIdd.BREAKPOINT)
    worker.poll()
    previous_sequence = worker.machine.latest_sequence
    previous_stop_id = worker.machine.stop_id
    assert previous_stop_id is not None

    # IDA 可以在 WFNE_CONT 的同一次调用中直接返回下一停点。事件指纹即使相同,
    # 只要旧 stop 已失效, 也必须作为新的真实停点接收。
    debugger.continue_event = _FakeDebugEvent(_FakeIdd.BREAKPOINT)
    result = worker.execute(
        "debug.control",
        {
            "action": "continue",
            "stop_id": previous_stop_id,
            "timeout_ms": 1_000,
        },
    )

    assert result["state"] == "suspended"
    assert result["stop_id"] != previous_stop_id
    assert result["latest_sequence"] == previous_sequence + 1
    event = result["event"]
    assert isinstance(event, dict)
    assert event["kind"] == "breakpoint"
    assert event["sequence"] == previous_sequence + 1


def test_wait_for_next_event_error_is_an_observed_failure_not_a_timeout(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    debugger.wait_error = True

    worker.poll()

    assert worker.machine.state == DebugState.FAILED
    events = worker.machine.events_after(0, 20)
    assert events[-1].kind == "request_error"
    assert events[-1].payload == {
        "action": "wait_for_next_event",
        "ida_result": -1,
    }


def test_dec_notask_preserves_observed_terminal_state(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    worker.machine.observe(
        "process_exited",
        {"event_id": _FakeIdd.PROCESS_EXITED, "exit_code": 0},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    terminal_sequence = worker.machine.latest_sequence
    debugger.forced_wait_code = debugger.DEC_NOTASK

    worker.poll()

    assert worker.machine.state == DebugState.EXITED
    assert worker.machine.latest_sequence == terminal_sequence


def test_dec_notask_without_terminal_event_marks_session_lost(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    debugger.forced_wait_code = debugger.DEC_NOTASK

    worker.poll()

    assert worker.machine.state == DebugState.LOST
    event = worker.machine.events_after(0, 20)[-1]
    assert event.kind == "worker_lost"
    assert event.payload["reason"] == "debugger_notask_without_terminal_event"


def test_module_load_and_unload_reconcile_pending_breakpoint(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    debugger.modules_available = False
    added = worker.execute(
        "debug.breakpoints",
        {
            "action": "add",
            "location": {"module": "debug_target_x64.exe", "rva": "0x1000"},
        },
    )
    pending = added["breakpoint"]
    assert isinstance(pending, dict)
    assert pending["active"] is False
    assert "runtime_address" not in pending

    debugger.modules_available = True
    debugger.queue_event(_FakeIdd.LIB_LOADED)
    worker.poll()
    active_result = worker.execute("debug.breakpoints", {"action": "list"})
    active_breakpoints = active_result["breakpoints"]
    assert isinstance(active_breakpoints, list)
    active = cast(list[dict[str, object]], active_breakpoints)[0]
    assert active["active"] is True
    assert active["runtime_address"] == "0x180001000"
    assert debugger.breakpoints == {0x180001000: debugger.BPTCK_YES}

    debugger.modules_available = False
    debugger.queue_event(_FakeIdd.LIB_UNLOADED, ea=0x180000000)
    worker.poll()
    unloaded_result = worker.execute("debug.breakpoints", {"action": "list"})
    unloaded_breakpoints = unloaded_result["breakpoints"]
    assert isinstance(unloaded_breakpoints, list)
    unloaded = cast(list[dict[str, object]], unloaded_breakpoints)[0]
    assert unloaded["active"] is False
    assert "runtime_address" not in unloaded
    assert debugger.breakpoints == {}


def test_empty_module_snapshot_clears_previous_cache(tmp_path: Path) -> None:
    worker, debugger = _worker(tmp_path)
    populated = worker.execute(
        "debug.inspect",
        {"view": "modules", "stop_id": worker.machine.stop_id},
    )
    assert populated["modules"]

    debugger.modules_available = False
    empty = worker.execute(
        "debug.inspect",
        {"view": "modules", "stop_id": worker.machine.stop_id},
    )
    assert empty["modules"] == []
