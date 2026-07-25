"""Debugger 状态只能由真实观察事件推进。"""

from __future__ import annotations

import pytest

from ida_re_mcp.worker.debug import (
    DebugEventProvenance,
    DebugState,
    DebugStateMachine,
)
from ida_re_mcp.worker.errors import WorkerError


def test_launch_requires_observed_process_event() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()
    assert machine.state == DebugState.LAUNCHING
    assert machine.stop_id is None

    event = machine.observe(
        "process_started",
        {"pid": 42, "process_state": "suspended", "event_id": 1},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    assert event.kind == "process_started"
    assert machine.state == DebugState.SUSPENDED
    assert machine.stop_id is not None
    assert event.stop_id == machine.stop_id


def test_running_invalidates_stop_and_new_stop_gets_new_id() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()
    machine.observe(
        "process_started",
        {"process_state": "suspended", "event_id": 1},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    first_stop = machine.stop_id
    machine.require_suspended(first_stop)

    resumed = machine.observe_running_state("continue")
    assert resumed.kind == "execution_resumed"
    assert resumed.provenance == DebugEventProvenance.STATE_OBSERVATION
    assert resumed.payload["observed_debugger_state"] == "DSTATE_RUN"
    assert machine.state == DebugState.RUNNING
    assert machine.stop_id is None
    with pytest.raises(WorkerError, match="suspended"):
        machine.require_suspended(first_stop)

    machine.observe(
        "breakpoint",
        {"address": "0x140001000", "event_id": 10},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    assert machine.state == DebugState.SUSPENDED
    assert machine.stop_id is not None
    assert machine.stop_id != first_stop


def test_exit_and_detach_are_terminal_observations() -> None:
    launched = DebugStateMachine()
    launched.begin_establish()
    launched.observe(
        "process_started",
        {"process_state": "running", "event_id": 1},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    launched.observe(
        "process_exited",
        {"exit_code": 0, "event_id": 2},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    assert launched.state == DebugState.EXITED
    assert launched.stop_id is None

    attached = DebugStateMachine()
    attached.begin_establish()
    attached.observe(
        "process_attached",
        {"process_state": "suspended", "event_id": 3},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    attached.observe(
        "process_detached",
        {"event_id": 4},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    assert attached.state == DebugState.DETACHED


def test_cannot_establish_over_active_session() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()
    machine.observe(
        "process_started",
        {"process_state": "running", "event_id": 1},
        provenance=DebugEventProvenance.IDA_EVENT,
    )
    with pytest.raises(WorkerError) as captured:
        machine.begin_establish()
    assert captured.value.code == "debug_state_conflict"


def test_event_cursor_is_monotonic_and_stale_cursor_fails() -> None:
    machine = DebugStateMachine()
    for index in range(4100):
        machine.observe(
            "information",
            {"index": index, "event_id": 13},
            provenance=DebugEventProvenance.IDA_EVENT,
        )
    recent = machine.events_after(4098, 10)
    assert [event.sequence for event in recent] == [4099, 4100]
    with pytest.raises(WorkerError) as captured:
        machine.events_after(0, 10)
    assert captured.value.code == "cursor_stale"


def test_failed_event_is_not_reported_as_successful_stop() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()
    event = machine.observe(
        "request_error",
        {"action": "launch"},
        provenance=DebugEventProvenance.SERVICE_EVENT,
    )
    assert event.state == DebugState.FAILED
    assert machine.stop_id is None


def test_ida_event_cannot_be_forged_without_event_id() -> None:
    machine = DebugStateMachine()
    machine.begin_establish()

    with pytest.raises(WorkerError) as captured:
        machine.observe(
            "process_started",
            {"process_state": "suspended"},
            provenance=DebugEventProvenance.IDA_EVENT,
        )

    assert captured.value.code == "debug_state_conflict"
    assert machine.state == DebugState.LAUNCHING
