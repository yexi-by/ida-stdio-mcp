import json
from collections.abc import Mapping
from typing import cast

import pytest
from pydantic import ValidationError

from ida_re_mcp.constants import MAX_INLINE_RESULT_BYTES
from ida_re_mcp.domain.address import ImageAddress, RuntimeAddress
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.catalog import TOOL_CATALOG
from ida_re_mcp.domain.tools import (
    DebugBreakpointsInput,
    DebugControlInput,
    DebugEstablishInput,
    DebugEventsInput,
    DebugFinishInput,
    DebugInspectInput,
)
from ida_re_mcp.supervisor.debug_adapter import (
    DebugContext,
    DebugModuleFact,
    DebugState,
    adapt_debug_breakpoints,
    adapt_debug_control,
    adapt_debug_establish,
    adapt_debug_events,
    adapt_debug_finish,
    adapt_debug_inspect,
    build_debug_breakpoint_replacement,
    build_debug_breakpoint_rollback,
    prepare_debug_breakpoint_enable,
    prepare_debug_breakpoint_list,
    prepare_debug_control,
    prepare_debug_establish,
    prepare_debug_events,
    prepare_debug_finish,
    prepare_debug_inspect,
)

WORKSPACE_ID = "workspace_abcdef"
REVISION = "revision_abcdef"
IMAGE_ID = "image_abcdef"
SESSION_ID = "session_abcdef"
STOP_ID = "stop_abcdef"
MODULE_ID = "module_abcdef"


def _context(*, state: str = "suspended", stop_id: str | None = STOP_ID) -> DebugContext:
    return DebugContext(
        workspace_id=WORKSPACE_ID,
        revision=REVISION,
        sample_name="target.exe",
        image_id=IMAGE_ID,
        debug_session_id=SESSION_ID,
        stop_id=stop_id,
        state=cast(DebugState, state),
        process_id=1234,
        modules=(
            DebugModuleFact(
                module_id=MODULE_ID,
                name=r"C:\samples\target.exe",
                base=0x140000000,
                size=0x10000,
            ),
        ),
    )


def _raw_session(
    *,
    state: str = "suspended",
    stop_id: str | None = STOP_ID,
    latest_sequence: int = 4,
    **extra: object,
) -> dict[str, object]:
    return {
        "debug_session_id": SESSION_ID,
        "state": state,
        "stop_id": stop_id,
        "latest_sequence": latest_sequence,
        **extra,
    }


def _assert_output_model(tool_name: str, output: StrictModel) -> None:
    spec = next(item for item in TOOL_CATALOG if item.name == tool_name)
    dumped = output.model_dump(mode="python")
    spec.output_model.model_validate(dumped)


def test_establish_launch_is_exact_and_builds_context() -> None:
    request = DebugEstablishInput.model_validate(
        {
            "workspace_id": WORKSPACE_ID,
            "revision": REVISION,
            "target": {
                "kind": "launch",
                "arguments": ["--mode", "test"],
                "stop_on_entry": True,
            },
            "timeout_ms": 5000,
        }
    )

    command = prepare_debug_establish(request)
    adapted = adapt_debug_establish(
        request,
        _raw_session(
            owned_pid=1234,
            establish_event={
                "sequence": 1,
                "kind": "process_started",
                "state": "suspended",
                "timestamp_ns": 10,
                "provenance": "ida_event",
                "stop_id": STOP_ID,
                "payload": {
                    "pid": 1234,
                    "event_id": 1,
                    "process_state": "suspended",
                    "module": {
                        "name": r"C:\samples\target.exe",
                        "base": "0x140000000",
                        "size": 0x10000,
                    },
                },
            },
        ),
        sample_name=r"C:\samples\target.exe",
        image_id=IMAGE_ID,
    )

    assert command.operation == "debug.establish"
    assert command.input == {
        "mode": "launch",
        "arguments": ["--mode", "test"],
        "stop_on_entry": True,
        "timeout_ms": 5000,
    }
    assert adapted.context.sample_name == "target.exe"
    assert adapted.output.process_id == 1234
    assert adapted.output.observed_event_sequence == 1
    assert adapted.output.completion_kind == "process_started"
    _assert_output_model("debug.establish", adapted.output)

    with pytest.raises(ValueError, match="PROCESS_STARTED/ATTACHED"):
        adapt_debug_establish(
            request,
            _raw_session(owned_pid=1234),
            sample_name=r"C:\samples\target.exe",
            image_id=IMAGE_ID,
        )


def test_unfulfillable_launch_environment_and_breakpoint_condition_are_rejected() -> None:
    with pytest.raises(ValidationError):
        DebugEstablishInput.model_validate(
            {
                "workspace_id": WORKSPACE_ID,
                "revision": REVISION,
                "target": {
                    "kind": "launch",
                    "environment": {"SECRET": "value"},
                },
            }
        )
    with pytest.raises(ValidationError):
        DebugBreakpointsInput.model_validate(
            {
                "debug_session_id": SESSION_ID,
                "stop_id": STOP_ID,
                "replace": [
                    {
                        "address": {
                            "kind": "image",
                            "image_id": IMAGE_ID,
                            "rva": "0x1000",
                        },
                        "condition": "rax == 1",
                    }
                ],
            }
        )


def test_control_maps_image_rva_and_adapts_observed_state() -> None:
    context = _context()
    request = DebugControlInput(
        debug_session_id=SESSION_ID,
        action="run_to",
        stop_id=STOP_ID,
        target=ImageAddress(kind="image", image_id=IMAGE_ID, rva="0x1234"),
        timeout_ms=7000,
    )

    command = prepare_debug_control(context, request)
    adapted = adapt_debug_control(
        context,
        _raw_session(
            stop_id="stop_next",
            latest_sequence=9,
            event={
                "sequence": 9,
                "kind": "breakpoint",
                "state": "suspended",
                "timestamp_ns": 90,
                "provenance": "ida_event",
                "stop_id": "stop_next",
                "payload": {
                    "address": "0x140001234",
                    "event_id": 10,
                },
            },
        ),
    )

    assert command.input["address"] == {
        "space": "runtime_module",
        "module": "target.exe",
        "rva": "0x1234",
    }
    assert adapted.context.stop_id == "stop_next"
    assert adapted.output.observed_event_sequence == 9
    assert adapted.output.completion_provenance == "ida_event"
    assert adapted.output.completion_kind == "breakpoint"
    _assert_output_model("debug.control", adapted.output)


def test_events_preserve_worker_kinds_and_module_facts() -> None:
    context = _context(state="running", stop_id=None)
    request = DebugEventsInput(debug_session_id=SESSION_ID, after_sequence=4)
    command = prepare_debug_events(context, request)
    raw = _raw_session(
        state="running",
        stop_id=None,
        latest_sequence=6,
        events=[
            {
                "sequence": 5,
                "kind": "library_loaded",
                "state": "running",
                "timestamp_ns": 100,
                "provenance": "ida_event",
                "payload": {
                    "pid": 1234,
                    "thread_id": 2,
                    "address": "0x180001000",
                    "event_id": 10,
                    "module": {
                        "name": r"C:\Windows\System32\helper.dll",
                        "base": "0x180000000",
                        "size": 0x3000,
                    },
                },
            },
            {
                "sequence": 6,
                "kind": "execution_resumed",
                "state": "running",
                "timestamp_ns": 101,
                "provenance": "state_observation",
                "payload": {
                    "action": "continue",
                    "observed_debugger_state": "DSTATE_RUN",
                },
            },
        ],
    )

    adapted = adapt_debug_events(context, request, raw)

    assert command.input["after_sequence"] == 4
    assert [event.kind for event in adapted.output.events] == [
        "library_loaded",
        "execution_resumed",
    ]
    assert adapted.output.events[0].module is not None
    assert adapted.output.events[1].action == "continue"
    assert adapted.output.events[0].provenance == "ida_event"
    assert adapted.output.events[1].provenance == "state_observation"
    assert adapted.output.events[1].observed_debugger_state == "DSTATE_RUN"
    assert adapted.output.last_sequence == 6
    assert adapted.output.observed_latest_sequence == 6
    assert adapted.output.has_more is False
    assert any(fact.name.endswith("helper.dll") for fact in adapted.context.modules)
    _assert_output_model("debug.events", adapted.output)


def test_events_page_by_returned_sequence_and_exact_inline_budget() -> None:
    context = _context(state="running", stop_id=None)
    raw_events: list[dict[str, object]] = [
        {
            "sequence": sequence,
            "kind": "information",
            "state": "running",
            "timestamp_ns": sequence,
            "provenance": "ida_event",
            "payload": {
                "event_id": 13,
                "reason": f"event-{sequence:03d}-" + "界" * 500,
            },
        }
        for sequence in range(1, 206)
    ]
    cursor = 0
    collected: list[int] = []
    page_sizes: list[int] = []
    while cursor < 205:
        request = DebugEventsInput(
            debug_session_id=SESSION_ID,
            after_sequence=cursor,
            limit=200,
        )
        worker_page = [event for event in raw_events if cast(int, event["sequence"]) > cursor][
            : request.limit
        ]
        adapted = adapt_debug_events(
            context,
            request,
            _raw_session(
                state="running",
                stop_id=None,
                latest_sequence=205,
                events=worker_page,
            ),
        )
        output = adapted.output
        encoded = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        assert len(encoded) <= MAX_INLINE_RESULT_BYTES
        assert output.events
        assert output.last_sequence == output.events[-1].sequence
        assert output.observed_latest_sequence == 205
        assert output.has_more is (output.last_sequence < 205)
        collected.extend(event.sequence for event in output.events)
        page_sizes.append(len(output.events))
        cursor = output.last_sequence
        context = adapted.context

    assert collected == list(range(1, 206))
    assert len(collected) == len(set(collected))
    assert len(page_sizes) > 2
    assert page_sizes[0] < 200

    empty = adapt_debug_events(
        context,
        DebugEventsInput(
            debug_session_id=SESSION_ID,
            after_sequence=205,
            limit=200,
        ),
        _raw_session(
            state="running",
            stop_id=None,
            latest_sequence=205,
            events=[],
        ),
    ).output
    assert empty.events == []
    assert empty.last_sequence == 205
    assert empty.observed_latest_sequence == 205
    assert empty.has_more is False


def test_events_reject_a_gap_in_worker_sequence() -> None:
    context = _context(state="running", stop_id=None)
    request = DebugEventsInput(
        debug_session_id=SESSION_ID,
        after_sequence=4,
        limit=10,
    )
    with pytest.raises(ValueError, match="不连续"):
        adapt_debug_events(
            context,
            request,
            _raw_session(
                state="running",
                stop_id=None,
                latest_sequence=6,
                events=[
                    {
                        "sequence": 6,
                        "kind": "information",
                        "state": "running",
                        "timestamp_ns": 100,
                        "provenance": "ida_event",
                        "payload": {"event_id": 13},
                    }
                ],
            ),
        )


def test_control_requires_real_ida_event_or_explicit_state_observation() -> None:
    context = _context()
    resumed = adapt_debug_control(
        context,
        _raw_session(
            state="running",
            stop_id=None,
            latest_sequence=5,
            event={
                "sequence": 5,
                "kind": "execution_resumed",
                "state": "running",
                "timestamp_ns": 100,
                "provenance": "state_observation",
                "payload": {
                    "action": "continue",
                    "observed_debugger_state": "DSTATE_RUN",
                },
            },
        ),
    )
    assert resumed.output.completion_provenance == "state_observation"
    assert resumed.output.completion_kind == "execution_resumed"
    assert resumed.output.observed_debugger_state == "DSTATE_RUN"
    assert resumed.output.state == "running"

    with pytest.raises(ValueError, match="完成证据"):
        adapt_debug_control(
            context,
            _raw_session(state="running", stop_id=None, latest_sequence=5),
        )

    with pytest.raises(ValueError, match="真实 IDA 事件"):
        adapt_debug_control(
            context,
            _raw_session(
                state="failed",
                stop_id=None,
                latest_sequence=5,
                event={
                    "sequence": 5,
                    "kind": "request_error",
                    "state": "failed",
                    "timestamp_ns": 100,
                    "provenance": "service_event",
                    "payload": {"reason": "rejected"},
                },
            ),
        )


def test_multi_view_inspect_maps_runtime_module_and_aggregates() -> None:
    context = _context()
    memory_address = RuntimeAddress(
        kind="runtime",
        module_id=MODULE_ID,
        va="0x140002000",
        stop_id=STOP_ID,
    )
    request = DebugInspectInput(
        debug_session_id=SESSION_ID,
        stop_id=STOP_ID,
        views=["state", "modules", "threads", "registers", "stack", "memory", "maps"],
        memory_address=memory_address,
        memory_size=4,
    )

    commands = prepare_debug_inspect(context, request)
    base = _raw_session()
    raw_results: list[Mapping[str, object]] = [
        base,
        _raw_session(
            modules=[
                {
                    "name": r"C:\samples\target.exe",
                    "base": "0x140000000",
                    "size": 0x10000,
                    "end": "0x140010000",
                }
            ]
        ),
        _raw_session(threads=[{"thread_id": 2, "name": "main", "current": True}]),
        _raw_session(
            registers={
                "RAX": "0x1",
                "RBX": "0x2",
                "RCX": "0x3",
                "RDX": "0x4",
                "RSI": "0x5",
                "RDI": "0x6",
                "RBP": "0x200100",
                "RSP": "0x200000",
                "R8": "0x8",
                "R9": "0x9",
                "R10": "0xa",
                "R11": "0xb",
                "R12": "0xc",
                "R13": "0xd",
                "R14": "0xe",
                "R15": "0xf",
                "RIP": "0x140002000",
                "EFL": "0x202",
            }
        ),
        _raw_session(
            frames=[
                {
                    "call_address": "0x140002000",
                    "function_address": "0x140001000",
                    "frame_pointer": "0x200100",
                    "function_known": True,
                    "name": "fixture_entry",
                }
            ]
        ),
        _raw_session(address="0x140002000", size=4, bytes_hex="01020304"),
        _raw_session(
            memory_maps=[
                {
                    "start": "0x140000000",
                    "end": "0x140010000",
                    "name": "target",
                    "class": "CODE",
                    "segment_base": "0x0",
                    "bitness": 64,
                    "permissions": 5,
                    "source": "ida_debugger",
                },
                {
                    "start": "0x200000",
                    "end": "0x210000",
                    "allocation_base": "0x200000",
                    "allocation_protection": 4,
                    "protection": 4,
                    "state": 0x1000,
                    "type": 0x20000,
                    "source": "windows_virtual_query_ex",
                },
            ]
        ),
    ]

    adapted = adapt_debug_inspect(context, request, raw_results)

    assert len(commands) == 7
    assert commands[-1].input["view"] == "memory_maps"
    assert commands[-2].input["address"] == {
        "space": "runtime",
        "module": r"C:\samples\target.exe",
        "va": "0x140002000",
        "stop_id": STOP_ID,
    }
    assert adapted.output.memory_bytes == "01020304"
    assert adapted.output.stack[0].frame_pointer_value == "0x200100"
    assert adapted.output.stack[0].call_address is not None
    assert adapted.output.stack[0].call_address.stop_id == STOP_ID
    assert adapted.output.stack[0].function_address is not None
    assert [item.source for item in adapted.output.memory_maps] == [
        "ida_debugger",
        "windows_virtual_query_ex",
    ]
    _assert_output_model("debug.inspect", adapted.output)

    incomplete_registers = list(raw_results)
    incomplete_registers[3] = _raw_session(registers={"RIP": "0x140002000", "RSP": "0x200000"})
    with pytest.raises(ValueError, match="完整且唯一"):
        adapt_debug_inspect(context, request, incomplete_registers)


def test_breakpoint_replacement_plan_and_rollback_preserve_old_state() -> None:
    context = _context()
    request = DebugBreakpointsInput.model_validate(
        {
            "debug_session_id": SESSION_ID,
            "stop_id": STOP_ID,
            "replace": [
                {
                    "address": {
                        "kind": "image",
                        "image_id": IMAGE_ID,
                        "rva": "0x1000",
                    }
                },
                {
                    "address": {
                        "kind": "module",
                        "module_id": MODULE_ID,
                        "rva": "0x2000",
                    },
                    "enabled": False,
                },
            ],
        }
    )
    old_raw = _raw_session(
        breakpoints=[
            {
                "breakpoint_id": "breakpoint_old",
                "module": "target.exe",
                "rva": "0x3000",
                "enabled": False,
                "active": False,
                "runtime_address": "0x140003000",
            }
        ]
    )

    assert prepare_debug_breakpoint_list(context, request).input == {"action": "list"}
    plan = build_debug_breakpoint_replacement(context, request, old_raw)
    assert plan.previous[0].rva == 0x3000
    assert plan.remove_commands[0].input["breakpoint_id"] == "breakpoint_old"
    assert [step.command.input["action"] for step in plan.add_steps] == ["add", "add"]
    assert plan.add_steps[1].command.input["location"] == {
        "module": r"C:\samples\target.exe",
        "rva": "0x2000",
    }
    enable = prepare_debug_breakpoint_enable(
        {"breakpoint": {"breakpoint_id": "breakpoint_new"}},
        enabled=False,
    )
    assert enable is not None and enable.input["action"] == "enable"

    current_raw = _raw_session(
        breakpoints=[
            {
                "breakpoint_id": "breakpoint_new",
                "module": "target.exe",
                "rva": "0x1000",
                "enabled": True,
                "active": True,
                "runtime_address": "0x140001000",
            }
        ]
    )
    rollback = build_debug_breakpoint_rollback(context, plan, current_raw)
    assert rollback.add_steps[0].command.input["location"] == {
        "module": "target.exe",
        "rva": "0x3000",
    }
    assert rollback.add_steps[0].enabled is False

    final_raw = _raw_session(
        breakpoints=[
            {
                "breakpoint_id": "breakpoint_one",
                "module": "target.exe",
                "rva": "0x1000",
                "enabled": True,
                "active": True,
                "runtime_address": "0x140001000",
            },
            {
                "breakpoint_id": "breakpoint_two",
                "module": r"C:\samples\target.exe",
                "rva": "0x2000",
                "enabled": False,
                "active": False,
                "runtime_address": "0x140002000",
            },
        ]
    )
    output = adapt_debug_breakpoints(context, request, final_raw)
    assert [item.state for item in output.breakpoints] == ["active", "disabled"]
    _assert_output_model("debug.breakpoints", output)

    wrong_aslr = _raw_session(
        breakpoints=[
            {
                "breakpoint_id": "breakpoint_one",
                "module": "target.exe",
                "rva": "0x1000",
                "enabled": True,
                "active": True,
                "runtime_address": "0x150001000",
            },
            {
                "breakpoint_id": "breakpoint_two",
                "module": r"C:\samples\target.exe",
                "rva": "0x2000",
                "enabled": False,
                "active": False,
                "runtime_address": "0x140002000",
            },
        ]
    )
    with pytest.raises(ValueError, match="module\\+rva"):
        adapt_debug_breakpoints(context, request, wrong_aslr)


def test_finish_maps_only_observed_terminal_state() -> None:
    context = _context()
    request = DebugFinishInput(
        debug_session_id=SESSION_ID,
        action="terminate",
        timeout_ms=9000,
    )

    command = prepare_debug_finish(context, request)
    adapted = adapt_debug_finish(
        context,
        _raw_session(
            state="exited",
            stop_id=None,
            latest_sequence=12,
            event={
                "sequence": 12,
                "kind": "process_exited",
                "state": "exited",
                "timestamp_ns": 120,
                "provenance": "ida_event",
                "payload": {
                    "pid": 1234,
                    "event_id": 2,
                    "exit_code": 0,
                },
            },
        ),
    )

    assert command.input == {"action": "terminate", "timeout_ms": 9000}
    assert adapted.context.state == "exited"
    assert adapted.context.stop_id is None
    assert adapted.output.observed_event_sequence == 12
    assert adapted.output.completion_kind == "process_exited"
    _assert_output_model("debug.finish", adapted.output)

    with pytest.raises(ValueError, match="PROCESS_EXITED/DETACHED"):
        adapt_debug_finish(
            context,
            _raw_session(state="exited", stop_id=None, latest_sequence=12),
        )
