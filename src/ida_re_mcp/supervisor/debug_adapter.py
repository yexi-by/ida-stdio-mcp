"""公共 Debug 工具与 DebugWorker JSON 契约之间的纯适配层。"""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Final, Literal, cast

from ida_re_mcp.constants import MAX_INLINE_RESULT_BYTES
from ida_re_mcp.domain.address import ImageAddress, RuntimeAddress
from ida_re_mcp.domain.tools import (
    BreakpointAddress,
    BreakpointState,
    DebugBreakpointsInput,
    DebugBreakpointsOutput,
    DebugControlInput,
    DebugControlOutput,
    DebugEstablishInput,
    DebugEstablishOutput,
    DebugEvent,
    DebugEventModule,
    DebugEventsInput,
    DebugEventsOutput,
    DebugException,
    DebugFinishInput,
    DebugFinishOutput,
    DebugInspectInput,
    DebugInspectOutput,
    DebugLaunchTarget,
    DebugMemoryMap,
    DebugModule,
    DebugThread,
    IdaDebuggerMemoryMap,
    RegisterValue,
    StackFrame,
    WindowsVirtualQueryMemoryMap,
)
from ida_re_mcp.worker.ipc import JsonObject as WorkerJsonObject

type DebugState = Literal[
    "launching",
    "running",
    "suspended",
    "exited",
    "detached",
    "lost",
    "failed",
]
type WorkerDebugOperation = Literal[
    "debug.establish",
    "debug.control",
    "debug.events",
    "debug.inspect",
    "debug.breakpoints",
    "debug.finish",
]
type DebugEventProvenance = Literal["ida_event", "state_observation", "service_event"]
type DebugControlProvenance = Literal["ida_event", "state_observation"]
type DebugControlCompletionKind = Literal[
    "process_suspended",
    "breakpoint",
    "step",
    "exception",
    "process_exited",
    "execution_resumed",
]

_CANONICAL_HEX: Final = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_STATES: Final = frozenset(
    {"launching", "running", "suspended", "exited", "detached", "lost", "failed"}
)
_EVENT_KINDS: Final = frozenset(
    {
        "process_started",
        "process_attached",
        "process_suspended",
        "execution_resumed",
        "library_loaded",
        "library_unloaded",
        "thread_started",
        "thread_exited",
        "breakpoint",
        "step",
        "exception",
        "process_exited",
        "process_detached",
        "information",
        "request_error",
        "worker_lost",
        "unknown",
    }
)
_EVENT_PROVENANCE: Final = frozenset(
    {
        "ida_event",
        "state_observation",
        "service_event",
    }
)
_CONTROL_COMPLETION_KINDS: Final = frozenset(
    {
        "process_suspended",
        "breakpoint",
        "step",
        "exception",
        "process_exited",
        "execution_resumed",
    }
)
_WINDOWS_X64_GENERAL_REGISTERS: Final = frozenset(
    {
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
    }
)
_WINDOWS_X86_GENERAL_REGISTERS: Final = frozenset(
    {
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
    }
)


class DebugAdapterError(ValueError):
    """worker 原始结果与当前公共 Debug 契约不一致。"""


@dataclass(frozen=True, slots=True)
class DebugModuleFact:
    module_id: str
    name: str
    base: int
    size: int


@dataclass(frozen=True, slots=True)
class DebugContext:
    workspace_id: str
    revision: str
    sample_name: str
    image_id: str
    debug_session_id: str
    stop_id: str | None
    state: DebugState
    process_id: int
    bitness: Literal[32, 64]
    modules: tuple[DebugModuleFact, ...] = ()


@dataclass(frozen=True, slots=True)
class WorkerDebugCommand:
    operation: WorkerDebugOperation
    input: WorkerJsonObject


@dataclass(frozen=True, slots=True)
class DebugAdaptation[OutputT]:
    context: DebugContext
    output: OutputT


@dataclass(frozen=True, slots=True)
class WorkerBreakpointFact:
    breakpoint_id: str
    module: str
    rva: int
    enabled: bool
    active: bool
    runtime_address: int | None


@dataclass(frozen=True, slots=True)
class BreakpointAddStep:
    command: WorkerDebugCommand
    enabled: bool
    requested: BreakpointAddress | None


@dataclass(frozen=True, slots=True)
class BreakpointReplacementPlan:
    previous: tuple[WorkerBreakpointFact, ...]
    remove_commands: tuple[WorkerDebugCommand, ...]
    add_steps: tuple[BreakpointAddStep, ...]
    verify_command: WorkerDebugCommand


@dataclass(frozen=True, slots=True)
class _Session:
    debug_session_id: str
    state: DebugState
    stop_id: str | None
    latest_sequence: int


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DebugAdapterError(f"{label} 必须是字符串键对象")
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise DebugAdapterError(f"{label} 必须是字符串键对象")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise DebugAdapterError(f"{label} 必须是数组")
    return cast(list[object], value)


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise DebugAdapterError(f"{label} 必须是字符串")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise DebugAdapterError(f"{label} 必须是整数")
    if minimum is not None and value < minimum:
        raise DebugAdapterError(f"{label} 小于允许范围")
    if maximum is not None and value > maximum:
        raise DebugAdapterError(f"{label} 超出允许范围")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise DebugAdapterError(f"{label} 必须是布尔值")
    return value


def _hex_value(value: object, label: str) -> tuple[str, int]:
    text = _text(value, label)
    if _CANONICAL_HEX.fullmatch(text) is None:
        raise DebugAdapterError(f"{label} 不是规范十六进制字符串")
    number = int(text, 16)
    if number > 0xFFFF_FFFF_FFFF_FFFF:
        raise DebugAdapterError(f"{label} 超出无符号 64 位")
    return text, number


def _hex(number: int) -> str:
    if not 0 <= number <= 0xFFFF_FFFF_FFFF_FFFF:
        raise DebugAdapterError("地址超出无符号 64 位")
    return f"0x{number:x}"


def _basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _state(value: object, label: str) -> DebugState:
    text = _text(value, label)
    if text not in _STATES:
        raise DebugAdapterError(f"{label} 不是当前 DebugState")
    return cast(DebugState, text)


def _session(raw: Mapping[str, object], expected_session_id: str | None = None) -> _Session:
    session_id = _text(raw.get("debug_session_id"), "debug_session_id")
    if expected_session_id is not None and session_id != expected_session_id:
        raise DebugAdapterError("worker debug_session_id 与当前会话不一致")
    state = _state(raw.get("state"), "state")
    stop_value = raw.get("stop_id")
    if stop_value is None:
        stop_id = None
    else:
        stop_id = _text(stop_value, "stop_id")
    if state == "suspended" and stop_id is None:
        raise DebugAdapterError("suspended worker 结果缺少 stop_id")
    if state != "suspended" and stop_id is not None:
        raise DebugAdapterError("非 suspended worker 结果不得携带 stop_id")
    latest = _integer(raw.get("latest_sequence"), "latest_sequence", minimum=0)
    return _Session(session_id, state, stop_id, latest)


def _require_context(context: DebugContext, debug_session_id: str) -> None:
    if debug_session_id != context.debug_session_id:
        raise DebugAdapterError("请求不属于当前 debug_session_id")


def _require_stop(context: DebugContext, stop_id: str) -> None:
    if context.state != "suspended" or context.stop_id != stop_id:
        raise DebugAdapterError("stop_id 已失效或当前状态不是 suspended")


def _updated_context(context: DebugContext, session: _Session) -> DebugContext:
    return replace(context, state=session.state, stop_id=session.stop_id)


def _module_id(context: DebugContext, name: str, base: int) -> str:
    for fact in context.modules:
        if fact.name.casefold() == name.casefold() and fact.base == base:
            return fact.module_id
    identity = f"{context.debug_session_id}\0{name.casefold()}\0{base:x}".encode()
    return f"module_{hashlib.sha256(identity).hexdigest()[:24]}"


def _module_fact(context: DebugContext, raw: object) -> DebugModuleFact:
    value = _mapping(raw, "module")
    name = _text(value.get("name"), "module.name")
    _, base = _hex_value(value.get("base"), "module.base")
    size = _integer(value.get("size"), "module.size", minimum=0)
    if base + size > 1 << 64:
        raise DebugAdapterError("module 地址范围溢出")
    return DebugModuleFact(_module_id(context, name, base), name, base, size)


def _merge_module(
    modules: tuple[DebugModuleFact, ...],
    fact: DebugModuleFact,
) -> tuple[DebugModuleFact, ...]:
    kept = tuple(
        current
        for current in modules
        if not (current.name.casefold() == fact.name.casefold() and current.base == fact.base)
    )
    return (*kept, fact)


def _module_by_id(context: DebugContext, module_id: str) -> DebugModuleFact:
    matches = [fact for fact in context.modules if fact.module_id == module_id]
    if len(matches) != 1:
        raise DebugAdapterError("runtime module_id 不属于当前模块快照")
    return matches[0]


def _module_by_name(context: DebugContext, module_name: str) -> DebugModuleFact | None:
    normalized = module_name.casefold()
    matches = [
        fact
        for fact in context.modules
        if fact.name.casefold() == normalized or _basename(fact.name).casefold() == normalized
    ]
    if len(matches) > 1:
        raise DebugAdapterError("module 名称在当前模块快照中不唯一")
    return matches[0] if matches else None


def _module_by_address(context: DebugContext, address: int) -> DebugModuleFact | None:
    matches = [
        fact
        for fact in context.modules
        if fact.size > 0 and fact.base <= address < fact.base + fact.size
    ]
    if len(matches) > 1:
        raise DebugAdapterError("运行时地址同时落入多个模块")
    return matches[0] if matches else None


def _runtime_address(
    context: DebugContext,
    address: int,
    stop_id: str | None,
) -> RuntimeAddress | None:
    if stop_id is None:
        return None
    module = _module_by_address(context, address)
    if module is None:
        return None
    return RuntimeAddress(
        kind="runtime",
        module_id=module.module_id,
        va=_hex(address),
        stop_id=stop_id,
    )


def prepare_debug_establish(request: DebugEstablishInput) -> WorkerDebugCommand:
    target = request.target
    if isinstance(target, DebugLaunchTarget):
        payload: WorkerJsonObject = {
            "mode": "launch",
            "arguments": list(target.arguments),
            "stop_on_entry": target.stop_on_entry,
            "timeout_ms": request.timeout_ms,
        }
    else:
        payload = {
            "mode": "attach",
            "pid": target.process_id,
            "timeout_ms": request.timeout_ms,
        }
    return WorkerDebugCommand("debug.establish", payload)


def adapt_debug_establish(
    request: DebugEstablishInput,
    raw: Mapping[str, object],
    *,
    sample_name: str,
    image_id: str,
    bitness: Literal[32, 64],
) -> DebugAdaptation[DebugEstablishOutput]:
    session = _session(raw)
    if session.state not in {"running", "suspended"}:
        raise DebugAdapterError("debug.establish 未观察到 running 或 suspended")
    if isinstance(request.target, DebugLaunchTarget):
        process_id = _integer(raw.get("owned_pid"), "owned_pid", minimum=1)
    else:
        process_id = request.target.process_id
    context = DebugContext(
        workspace_id=request.workspace_id,
        revision=request.revision,
        sample_name=_basename(_text(sample_name, "sample_name")),
        image_id=_text(image_id, "image_id"),
        debug_session_id=session.debug_session_id,
        stop_id=session.stop_id,
        state=session.state,
        process_id=process_id,
        bitness=bitness,
    )
    raw_event = raw.get("establish_event")
    if raw_event is None:
        raise DebugAdapterError("debug.establish 缺少真实 PROCESS_STARTED/ATTACHED 完成证据")
    context, event = _adapt_event(context, raw_event)
    expected_kind = (
        "process_started" if isinstance(request.target, DebugLaunchTarget) else "process_attached"
    )
    if (
        event.kind != expected_kind
        or event.provenance != "ida_event"
        or event.process_id != process_id
        or event.sequence > session.latest_sequence
    ):
        raise DebugAdapterError("debug.establish 完成证据与目标进程或请求类型不一致")
    context = _updated_context(context, session)
    output = DebugEstablishOutput(
        debug_session_id=session.debug_session_id,
        workspace_id=request.workspace_id,
        revision=request.revision,
        state=cast(Literal["running", "suspended"], session.state),
        stop_id=session.stop_id,
        process_id=process_id,
        observed_event_sequence=event.sequence,
        completion_provenance="ida_event",
        completion_kind=cast(
            Literal["process_started", "process_attached"],
            event.kind,
        ),
    )
    return DebugAdaptation(context, output)


def prepare_debug_control(
    context: DebugContext,
    request: DebugControlInput,
) -> WorkerDebugCommand:
    _require_context(context, request.debug_session_id)
    payload: WorkerJsonObject = {
        "action": request.action,
        "timeout_ms": request.timeout_ms,
    }
    if request.action == "pause":
        if context.state != "running":
            raise DebugAdapterError("pause 只允许当前 running 会话")
    else:
        if request.stop_id is None:
            raise DebugAdapterError("控制操作缺少 stop_id")
        _require_stop(context, request.stop_id)
        payload["stop_id"] = request.stop_id
    if request.action == "run_to":
        if request.target is None:
            raise DebugAdapterError("run_to 缺少 image target")
        if request.target.image_id != context.image_id:
            raise DebugAdapterError("run_to image_id 不属于当前 workspace 镜像")
        payload["address"] = {
            "space": "runtime_module",
            "module": context.sample_name,
            "rva": request.target.rva,
        }
    return WorkerDebugCommand("debug.control", payload)


def adapt_debug_control(
    context: DebugContext,
    raw: Mapping[str, object],
) -> DebugAdaptation[DebugControlOutput]:
    session = _session(raw, context.debug_session_id)
    raw_event = raw.get("event")
    if raw_event is None:
        raise DebugAdapterError("debug.control 缺少完成证据")
    updated, event = _adapt_event(context, raw_event)
    if event.sequence != session.latest_sequence:
        raise DebugAdapterError("debug.control 完成证据不是 worker 最新观察")
    if event.state != session.state or event.stop_id != session.stop_id:
        raise DebugAdapterError("debug.control 完成证据与 worker 会话状态不一致")
    if event.provenance not in {"ida_event", "state_observation"}:
        raise DebugAdapterError("debug.control 只能由真实 IDA 事件或明确状态观察完成")
    if event.kind not in _CONTROL_COMPLETION_KINDS:
        raise DebugAdapterError("debug.control 返回了不允许的完成事件")
    if session.state not in {"running", "suspended", "exited"}:
        raise DebugAdapterError("debug.control 未返回可由控制动作观察到的状态")
    updated = _updated_context(updated, session)
    output = DebugControlOutput(
        debug_session_id=context.debug_session_id,
        state=cast(Literal["running", "suspended", "exited"], session.state),
        stop_id=session.stop_id,
        observed_event_sequence=event.sequence,
        completion_provenance=cast(DebugControlProvenance, event.provenance),
        completion_kind=cast(DebugControlCompletionKind, event.kind),
        observed_debugger_state=event.observed_debugger_state,
    )
    return DebugAdaptation(updated, output)


def adapt_debug_cancelled(
    context: DebugContext,
    raw: Mapping[str, object],
) -> DebugContext:
    """只吸收取消完成后的真实会话状态, 不把取消本身包装成工具成功。"""

    session = _session(raw, context.debug_session_id)
    return _updated_context(context, session)


def prepare_debug_events(
    context: DebugContext,
    request: DebugEventsInput,
) -> WorkerDebugCommand:
    _require_context(context, request.debug_session_id)
    return WorkerDebugCommand(
        "debug.events",
        {
            "after_sequence": request.after_sequence,
            "wait_ms": request.wait_ms,
            "limit": request.limit,
        },
    )


def _event_module(
    context: DebugContext,
    payload: Mapping[str, object],
) -> tuple[DebugContext, DebugEventModule | None]:
    raw_module = payload.get("module")
    if raw_module is None:
        return context, None
    fact = _module_fact(context, raw_module)
    updated = replace(context, modules=_merge_module(context.modules, fact))
    public = DebugEventModule(
        module_id=fact.module_id,
        name=fact.name,
        base=_hex(fact.base),
        size=fact.size,
    )
    return updated, public


def _adapt_event(
    context: DebugContext,
    raw: object,
) -> tuple[DebugContext, DebugEvent]:
    value = _mapping(raw, "event")
    provenance = _text(value.get("provenance"), "event.provenance")
    if provenance not in _EVENT_PROVENANCE:
        raise DebugAdapterError(f"worker 返回未知事件 provenance: {provenance}")
    kind = _text(value.get("kind"), "event.kind")
    if kind not in _EVENT_KINDS:
        raise DebugAdapterError(f"worker 返回未知事件 kind: {kind}")
    payload = _mapping(value.get("payload"), "event.payload")
    state = _state(value.get("state"), "event.state")
    stop_value = value.get("stop_id")
    stop_id = _text(stop_value, "event.stop_id") if stop_value is not None else None
    if state == "suspended" and stop_id is None:
        raise DebugAdapterError("suspended 事件缺少 stop_id")
    if state != "suspended" and stop_id is not None:
        raise DebugAdapterError("非 suspended 事件不得携带 stop_id")

    updated, module = _event_module(context, payload)
    process_id = (
        _integer(payload["pid"], "event.payload.pid", minimum=0) if "pid" in payload else None
    )
    if (
        kind in {"process_started", "process_attached"}
        and process_id == context.process_id
        and module is not None
    ):
        # launch 使用服务私有样本副本, 其运行时模块名不必等于用户原文件名。
        updated = replace(updated, sample_name=_basename(module.name))
    address: RuntimeAddress | None = None
    raw_address = payload.get("address")
    address_value: int | None = None
    if raw_address is not None:
        _, address_value = _hex_value(raw_address, "event.payload.address")
        address = _runtime_address(updated, address_value, stop_id)

    exception: DebugException | None = None
    raw_exception = payload.get("exception")
    if raw_exception is not None:
        exception_value = _mapping(raw_exception, "event.payload.exception")
        _, exception_address_value = _hex_value(
            exception_value.get("address"),
            "event.payload.exception.address",
        )
        exception = DebugException(
            code=_integer(
                exception_value.get("code"),
                "event.payload.exception.code",
                minimum=0,
                maximum=0xFFFF_FFFF,
            ),
            address=_runtime_address(updated, exception_address_value, stop_id),
            can_continue=_boolean(
                exception_value.get("can_continue"),
                "event.payload.exception.can_continue",
            ),
            information=_text(
                exception_value.get("information"),
                "event.payload.exception.information",
                allow_empty=True,
            ),
        )

    exit_code_value = payload.get("exit_code")
    exit_code = (
        _integer(exit_code_value, "event.payload.exit_code")
        if exit_code_value is not None
        else None
    )
    action_value = payload.get("action")
    action = (
        _text(action_value, "event.payload.action", allow_empty=True)
        if action_value is not None
        else None
    )
    reason_value = payload.get("reason")
    reason = (
        _text(reason_value, "event.payload.reason", allow_empty=True)
        if reason_value is not None
        else None
    )
    observed_state_value = payload.get("observed_debugger_state")
    observed_debugger_state = (
        _text(
            observed_state_value,
            "event.payload.observed_debugger_state",
        )
        if observed_state_value is not None
        else None
    )
    event_id_value = payload.get("event_id")
    event_id = (
        _integer(event_id_value, "event.payload.event_id", minimum=0)
        if event_id_value is not None
        else None
    )
    if provenance == "state_observation" and (
        kind != "execution_resumed"
        or observed_debugger_state != "DSTATE_RUN"
        or event_id is not None
    ):
        raise DebugAdapterError("state_observation 不是有效的 DSTATE_RUN 恢复观察")
    if provenance != "state_observation" and observed_debugger_state is not None:
        raise DebugAdapterError("非 state_observation 事件携带 debugger 状态观察")
    if provenance == "ida_event" and (
        event_id is None or kind in {"execution_resumed", "request_error", "worker_lost"}
    ):
        raise DebugAdapterError("ida_event 缺少真实 event_id 或伪装了服务事件")
    if provenance == "service_event" and (
        kind not in {"request_error", "worker_lost"} or event_id is not None
    ):
        raise DebugAdapterError("service_event kind 无效")
    event = DebugEvent(
        sequence=_integer(value.get("sequence"), "event.sequence", minimum=1),
        timestamp_ns=_integer(value.get("timestamp_ns"), "event.timestamp_ns", minimum=0),
        provenance=cast(DebugEventProvenance, provenance),
        kind=cast(
            Literal[
                "process_started",
                "process_attached",
                "process_suspended",
                "execution_resumed",
                "library_loaded",
                "library_unloaded",
                "thread_started",
                "thread_exited",
                "breakpoint",
                "step",
                "exception",
                "process_exited",
                "process_detached",
                "information",
                "request_error",
                "worker_lost",
                "unknown",
            ],
            kind,
        ),
        state=state,
        stop_id=stop_id,
        process_id=process_id,
        thread_id=(
            _integer(payload["thread_id"], "event.payload.thread_id", minimum=0)
            if "thread_id" in payload
            else None
        ),
        address=address,
        event_id=event_id,
        module=module,
        exception=exception,
        exit_code=exit_code,
        action=action,
        reason=reason,
        observed_debugger_state=cast(Literal["DSTATE_RUN"] | None, observed_debugger_state),
    )
    if kind == "library_unloaded" and address_value is not None:
        unloaded = _module_by_address(updated, address_value)
        if unloaded is not None:
            updated = replace(
                updated,
                modules=tuple(
                    fact for fact in updated.modules if fact.module_id != unloaded.module_id
                ),
            )
    return updated, event


def adapt_debug_events(
    context: DebugContext,
    request: DebugEventsInput,
    raw: Mapping[str, object],
) -> DebugAdaptation[DebugEventsOutput]:
    _require_context(context, request.debug_session_id)
    session = _session(raw, context.debug_session_id)
    if request.after_sequence > session.latest_sequence:
        raise DebugAdapterError("after_sequence 超过 worker 最新事件")
    current = context
    parsed: list[tuple[DebugContext, DebugEvent]] = []
    previous_sequence = request.after_sequence
    for raw_event in _sequence(raw.get("events"), "events"):
        current, event = _adapt_event(current, raw_event)
        if event.sequence != previous_sequence + 1:
            raise DebugAdapterError("worker 事件 sequence 不连续, 可能发生丢失或重复")
        previous_sequence = event.sequence
        parsed.append((current, event))
    if len(parsed) > request.limit:
        raise DebugAdapterError("worker 返回事件数超过请求 limit")
    if parsed and parsed[-1][1].sequence > session.latest_sequence:
        raise DebugAdapterError("事件 sequence 超过 latest_sequence")
    if not parsed and session.latest_sequence > request.after_sequence:
        raise DebugAdapterError("worker 遗漏 after_sequence 之后的可用事件")

    events: list[DebugEvent] = []
    page_context = context
    for candidate_context, event in parsed:
        candidate_events = [*events, event]
        candidate = DebugEventsOutput(
            debug_session_id=context.debug_session_id,
            events=candidate_events,
            last_sequence=event.sequence,
            observed_latest_sequence=session.latest_sequence,
            has_more=event.sequence < session.latest_sequence,
        )
        if _inline_debug_events_size(candidate) > MAX_INLINE_RESULT_BYTES:
            break
        events = candidate_events
        page_context = candidate_context
    if parsed and not events:
        raise DebugAdapterError("单个 debug event 超过 inline 输出上限")

    last_sequence = events[-1].sequence if events else request.after_sequence
    current = replace(page_context, state=session.state, stop_id=session.stop_id)
    output = DebugEventsOutput(
        debug_session_id=context.debug_session_id,
        events=events,
        last_sequence=last_sequence,
        observed_latest_sequence=session.latest_sequence,
        has_more=last_sequence < session.latest_sequence,
    )
    return DebugAdaptation(current, output)


def _inline_debug_events_size(output: DebugEventsOutput) -> int:
    return len(
        json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def prepare_debug_inspect(
    context: DebugContext,
    request: DebugInspectInput,
) -> tuple[WorkerDebugCommand, ...]:
    _require_context(context, request.debug_session_id)
    _require_stop(context, request.stop_id)
    commands: list[WorkerDebugCommand] = []
    for view in request.views:
        payload: WorkerJsonObject = {
            "view": "memory_maps" if view == "maps" else view,
            "stop_id": request.stop_id,
        }
        if view == "memory":
            if request.memory_address is None or request.memory_size is None:
                raise DebugAdapterError("memory 视图缺少地址或长度")
            module = _module_by_id(context, request.memory_address.module_id)
            payload["address"] = {
                "space": "runtime",
                "module": module.name,
                "va": request.memory_address.va,
                "stop_id": request.stop_id,
            }
            payload["size"] = request.memory_size
        commands.append(WorkerDebugCommand("debug.inspect", payload))
    return tuple(commands)


def _adapt_modules(
    context: DebugContext,
    stop_id: str,
    raw: object,
) -> tuple[DebugContext, list[DebugModule]]:
    current = context
    facts: list[DebugModuleFact] = []
    modules: list[DebugModule] = []
    for item in _sequence(raw, "modules"):
        fact = _module_fact(current, item)
        current = replace(current, modules=_merge_module(current.modules, fact))
        facts.append(fact)
        modules.append(
            DebugModule(
                module_id=fact.module_id,
                name=fact.name,
                base=RuntimeAddress(
                    kind="runtime",
                    module_id=fact.module_id,
                    va=_hex(fact.base),
                    stop_id=stop_id,
                ),
                size=fact.size,
            )
        )
    # modules view 是当前完整快照; 丢弃已卸载的旧 facts。
    return replace(current, modules=tuple(facts)), modules


def _adapt_threads(raw: object) -> list[DebugThread]:
    threads: list[DebugThread] = []
    for item in _sequence(raw, "threads"):
        value = _mapping(item, "thread")
        raw_name = _text(value.get("name"), "thread.name", allow_empty=True)
        threads.append(
            DebugThread(
                thread_id=_integer(value.get("thread_id"), "thread.thread_id", minimum=0),
                name=raw_name or None,
                current=_boolean(value.get("current"), "thread.current"),
            )
        )
    if not threads:
        raise DebugAdapterError("threads 快照不得为空")
    if len({thread.thread_id for thread in threads}) != len(threads):
        raise DebugAdapterError("threads 快照包含重复 thread_id")
    if sum(thread.current for thread in threads) != 1:
        raise DebugAdapterError("threads 快照必须且只能标记一个 current 线程")
    return threads


def _adapt_registers(raw: object, *, bitness: Literal[32, 64]) -> list[RegisterValue]:
    values = _mapping(raw, "registers")
    expected = _WINDOWS_X86_GENERAL_REGISTERS if bitness == 32 else _WINDOWS_X64_GENERAL_REGISTERS
    if set(values) != set(expected):
        raise DebugAdapterError(f"registers 未返回完整且唯一的 Windows {bitness} 位通用寄存器集")
    registers: list[RegisterValue] = []
    for name in sorted(values):
        canonical, _ = _hex_value(values[name], f"registers.{name}")
        registers.append(RegisterValue(name=name, value=canonical))
    return registers


def _adapt_stack(
    context: DebugContext,
    stop_id: str,
    raw: object,
) -> list[StackFrame]:
    frames: list[StackFrame] = []
    for index, item in enumerate(_sequence(raw, "frames")):
        value = _mapping(item, "frame")
        _, call_va = _hex_value(value.get("call_address"), "frame.call_address")
        _, function_va = _hex_value(value.get("function_address"), "frame.function_address")
        frame_pointer, _ = _hex_value(value.get("frame_pointer"), "frame.frame_pointer")
        name = _text(value.get("name"), "frame.name", allow_empty=True)
        frames.append(
            StackFrame(
                index=index,
                call_address=_runtime_address(context, call_va, stop_id),
                function_address=_runtime_address(context, function_va, stop_id),
                frame_pointer_value=frame_pointer,
                function_known=_boolean(value.get("function_known"), "frame.function_known"),
                function_name=name or None,
            )
        )
    return frames


def _adapt_memory_maps(raw: object) -> list[DebugMemoryMap]:
    maps: list[DebugMemoryMap] = []
    for item in _sequence(raw, "memory_maps"):
        value = _mapping(item, "memory_map")
        source = _text(value.get("source"), "memory_map.source")
        start, start_value = _hex_value(value.get("start"), "memory_map.start")
        end, end_value = _hex_value(value.get("end"), "memory_map.end")
        if end_value <= start_value:
            raise DebugAdapterError("memory_map.end 必须大于 start")
        if source == "ida_debugger":
            segment_base, _ = _hex_value(
                value.get("segment_base"),
                "memory_map.segment_base",
            )
            bitness = _integer(value.get("bitness"), "memory_map.bitness")
            if bitness not in {16, 32, 64}:
                raise DebugAdapterError("memory_map.bitness 不是 16/32/64")
            maps.append(
                IdaDebuggerMemoryMap(
                    source="ida_debugger",
                    start=start,
                    end=end,
                    name=_text(value.get("name"), "memory_map.name", allow_empty=True),
                    segment_class=_text(
                        value.get("class"),
                        "memory_map.class",
                        allow_empty=True,
                    ),
                    segment_base=segment_base,
                    bitness=cast(Literal[16, 32, 64], bitness),
                    permissions=_integer(
                        value.get("permissions"),
                        "memory_map.permissions",
                        minimum=0,
                    ),
                )
            )
        elif source == "windows_virtual_query_ex":
            allocation_base, _ = _hex_value(
                value.get("allocation_base"),
                "memory_map.allocation_base",
            )
            maps.append(
                WindowsVirtualQueryMemoryMap(
                    source="windows_virtual_query_ex",
                    start=start,
                    end=end,
                    allocation_base=allocation_base,
                    allocation_protection=_integer(
                        value.get("allocation_protection"),
                        "memory_map.allocation_protection",
                        minimum=0,
                    ),
                    protection=_integer(
                        value.get("protection"),
                        "memory_map.protection",
                        minimum=0,
                    ),
                    state=_integer(value.get("state"), "memory_map.state", minimum=0),
                    memory_type=_integer(value.get("type"), "memory_map.type", minimum=0),
                )
            )
        else:
            raise DebugAdapterError(f"未知 memory map source: {source}")
    return maps


def adapt_debug_inspect(
    context: DebugContext,
    request: DebugInspectInput,
    raw_results: Sequence[Mapping[str, object]],
) -> DebugAdaptation[DebugInspectOutput]:
    _require_context(context, request.debug_session_id)
    _require_stop(context, request.stop_id)
    if len(raw_results) != len(request.views):
        raise DebugAdapterError("debug.inspect 结果数量与 views 不一致")

    current = context
    modules: list[DebugModule] = []
    threads: list[DebugThread] = []
    registers: list[RegisterValue] = []
    stack: list[StackFrame] = []
    memory_address = None
    memory_bytes = None
    memory_maps: list[DebugMemoryMap] = []
    for view, raw in zip(request.views, raw_results, strict=True):
        if view != "modules":
            continue
        session = _session(raw, context.debug_session_id)
        if session.state != "suspended" or session.stop_id != request.stop_id:
            raise DebugAdapterError("debug.inspect worker 结果不属于请求 stop_id")
        current, modules = _adapt_modules(
            current,
            request.stop_id,
            raw.get("modules"),
        )
    for view, raw in zip(request.views, raw_results, strict=True):
        session = _session(raw, context.debug_session_id)
        if session.state != "suspended" or session.stop_id != request.stop_id:
            raise DebugAdapterError("debug.inspect worker 结果不属于请求 stop_id")
        if view == "threads":
            threads = _adapt_threads(raw.get("threads"))
        elif view == "registers":
            registers = _adapt_registers(raw.get("registers"), bitness=current.bitness)
        elif view == "stack":
            stack = _adapt_stack(current, request.stop_id, raw.get("frames"))
        elif view == "memory":
            if request.memory_address is None or request.memory_size is None:
                raise DebugAdapterError("memory 请求缺少公共地址")
            returned_address, _ = _hex_value(raw.get("address"), "memory.address")
            if returned_address != request.memory_address.va:
                raise DebugAdapterError("worker 返回的 memory.address 与请求不一致")
            size = _integer(raw.get("size"), "memory.size", minimum=1)
            if size != request.memory_size:
                raise DebugAdapterError("worker 返回的 memory.size 与请求不一致")
            memory_bytes = _text(raw.get("bytes_hex"), "memory.bytes_hex", allow_empty=True)
            if len(memory_bytes) != size * 2:
                raise DebugAdapterError("worker memory bytes 长度与 size 不一致")
            memory_address = request.memory_address
        elif view == "maps":
            memory_maps = _adapt_memory_maps(raw.get("memory_maps"))

    output = DebugInspectOutput(
        debug_session_id=context.debug_session_id,
        stop_id=request.stop_id,
        state="suspended",
        modules=modules,
        threads=threads,
        registers=registers,
        stack=stack,
        memory_address=memory_address,
        memory_bytes=memory_bytes,
        memory_maps=memory_maps,
    )
    return DebugAdaptation(current, output)


def prepare_debug_breakpoint_list(
    context: DebugContext,
    request: DebugBreakpointsInput,
) -> WorkerDebugCommand:
    _require_context(context, request.debug_session_id)
    _require_stop(context, request.stop_id)
    return WorkerDebugCommand("debug.breakpoints", {"action": "list"})


def _worker_breakpoints(
    context: DebugContext,
    raw: Mapping[str, object],
) -> tuple[WorkerBreakpointFact, ...]:
    session = _session(raw, context.debug_session_id)
    if session.state != "suspended" or session.stop_id != context.stop_id:
        raise DebugAdapterError("breakpoint list 不属于当前 stop_id")
    result: list[WorkerBreakpointFact] = []
    for item in _sequence(raw.get("breakpoints"), "breakpoints"):
        value = _mapping(item, "breakpoint")
        _, rva = _hex_value(value.get("rva"), "breakpoint.rva")
        runtime_value = value.get("runtime_address")
        runtime_address = (
            _hex_value(runtime_value, "breakpoint.runtime_address")[1]
            if runtime_value is not None
            else None
        )
        module_name = _text(value.get("module"), "breakpoint.module")
        enabled = _boolean(value.get("enabled"), "breakpoint.enabled")
        active = _boolean(value.get("active"), "breakpoint.active")
        if active and (not enabled or runtime_address is None):
            raise DebugAdapterError("active breakpoint 必须启用并携带 runtime_address")
        if enabled and runtime_address is not None and not active:
            raise DebugAdapterError("已解析且启用的 breakpoint 未处于真实 active 状态")
        if runtime_address is not None:
            module = _module_by_name(context, module_name)
            if module is None or runtime_address != module.base + rva:
                raise DebugAdapterError("breakpoint runtime_address 不匹配当前 module+rva")
        result.append(
            WorkerBreakpointFact(
                breakpoint_id=_text(value.get("breakpoint_id"), "breakpoint.breakpoint_id"),
                module=module_name,
                rva=rva,
                enabled=enabled,
                active=active,
                runtime_address=runtime_address,
            )
        )
    return tuple(result)


def _remove_commands(
    breakpoints: Sequence[WorkerBreakpointFact],
) -> tuple[WorkerDebugCommand, ...]:
    return tuple(
        WorkerDebugCommand(
            "debug.breakpoints",
            {"action": "remove", "breakpoint_id": item.breakpoint_id},
        )
        for item in breakpoints
    )


def _add_step(
    module: str,
    rva: int,
    enabled: bool,
    requested: BreakpointAddress | None,
) -> BreakpointAddStep:
    return BreakpointAddStep(
        WorkerDebugCommand(
            "debug.breakpoints",
            {
                "action": "add",
                "location": {
                    "module": module,
                    "rva": _hex(rva),
                },
            },
        ),
        enabled,
        requested,
    )


def build_debug_breakpoint_replacement(
    context: DebugContext,
    request: DebugBreakpointsInput,
    current_raw: Mapping[str, object],
) -> BreakpointReplacementPlan:
    _require_context(context, request.debug_session_id)
    _require_stop(context, request.stop_id)
    previous = _worker_breakpoints(context, current_raw)
    additions: list[BreakpointAddStep] = []
    resolved_locations: set[tuple[str, int]] = set()
    for spec in request.replace:
        if isinstance(spec.address, ImageAddress):
            if spec.address.image_id != context.image_id:
                raise DebugAdapterError("breakpoint image_id 不属于当前 workspace 镜像")
            module_name = context.sample_name
        else:
            module_name = _module_by_id(context, spec.address.module_id).name
        resolved = (module_name.casefold(), int(spec.address.rva, 16))
        if resolved in resolved_locations:
            raise DebugAdapterError("breakpoint 解析后存在重复 module+rva")
        resolved_locations.add(resolved)
        additions.append(
            _add_step(
                module_name,
                int(spec.address.rva, 16),
                spec.enabled,
                spec.address,
            )
        )
    return BreakpointReplacementPlan(
        previous=previous,
        remove_commands=_remove_commands(previous),
        add_steps=tuple(additions),
        verify_command=WorkerDebugCommand("debug.breakpoints", {"action": "list"}),
    )


def build_debug_breakpoint_rollback(
    context: DebugContext,
    replacement: BreakpointReplacementPlan,
    current_raw: Mapping[str, object],
) -> BreakpointReplacementPlan:
    current = _worker_breakpoints(context, current_raw)
    return BreakpointReplacementPlan(
        previous=current,
        remove_commands=_remove_commands(current),
        add_steps=tuple(
            _add_step(item.module, item.rva, item.enabled, None) for item in replacement.previous
        ),
        verify_command=WorkerDebugCommand("debug.breakpoints", {"action": "list"}),
    )


def prepare_debug_breakpoint_enable(
    add_result: Mapping[str, object],
    *,
    enabled: bool,
) -> WorkerDebugCommand | None:
    if enabled:
        return None
    raw = _mapping(add_result.get("breakpoint"), "breakpoint")
    breakpoint_id = _text(raw.get("breakpoint_id"), "breakpoint.breakpoint_id")
    return WorkerDebugCommand(
        "debug.breakpoints",
        {
            "action": "enable",
            "breakpoint_id": breakpoint_id,
            "enabled": False,
        },
    )


def adapt_debug_breakpoints(
    context: DebugContext,
    request: DebugBreakpointsInput,
    final_raw: Mapping[str, object],
) -> DebugBreakpointsOutput:
    _require_context(context, request.debug_session_id)
    _require_stop(context, request.stop_id)
    actual = _worker_breakpoints(context, final_raw)
    by_location: dict[tuple[str, int], WorkerBreakpointFact] = {}
    for item in actual:
        key = (item.module.casefold(), item.rva)
        if key in by_location:
            raise DebugAdapterError("worker 存在重复 module+rva breakpoint")
        by_location[key] = item
    if len(actual) != len(request.replace):
        raise DebugAdapterError("worker 最终 breakpoint 集合与 replace 不一致")

    breakpoints: list[BreakpointState] = []
    for spec in request.replace:
        module_name = (
            context.sample_name
            if isinstance(spec.address, ImageAddress)
            else _module_by_id(context, spec.address.module_id).name
        )
        key = (module_name.casefold(), int(spec.address.rva, 16))
        item = by_location.get(key)
        if item is None or item.enabled != spec.enabled:
            raise DebugAdapterError("worker 最终 breakpoint 状态与 replace 不一致")
        runtime = None
        if item.runtime_address is not None:
            module = _module_by_name(context, item.module)
            if module is None:
                raise DebugAdapterError("active breakpoint 缺少当前 module fact")
            runtime = RuntimeAddress(
                kind="runtime",
                module_id=module.module_id,
                va=_hex(item.runtime_address),
                stop_id=request.stop_id,
            )
        state: Literal["pending", "active", "disabled"]
        if not item.enabled:
            state = "disabled"
        elif item.active:
            state = "active"
        else:
            state = "pending"
        breakpoints.append(
            BreakpointState(
                entity_id=item.breakpoint_id,
                requested=spec.address,
                runtime=runtime,
                state=state,
            )
        )
    return DebugBreakpointsOutput(
        debug_session_id=context.debug_session_id,
        stop_id=request.stop_id,
        breakpoints=breakpoints,
    )


def prepare_debug_finish(
    context: DebugContext,
    request: DebugFinishInput,
) -> WorkerDebugCommand:
    _require_context(context, request.debug_session_id)
    return WorkerDebugCommand(
        "debug.finish",
        {"action": request.action, "timeout_ms": request.timeout_ms},
    )


def adapt_debug_finish(
    context: DebugContext,
    raw: Mapping[str, object],
) -> DebugAdaptation[DebugFinishOutput]:
    session = _session(raw, context.debug_session_id)
    raw_event = raw.get("event")
    if raw_event is None:
        raise DebugAdapterError("debug.finish 缺少真实 PROCESS_EXITED/DETACHED 完成证据")
    updated, event = _adapt_event(context, raw_event)
    if (
        event.provenance != "ida_event"
        or event.kind not in {"process_exited", "process_detached"}
        or event.sequence != session.latest_sequence
        or event.state != session.state
        or event.stop_id is not None
    ):
        raise DebugAdapterError("debug.finish 完成证据与 worker 终止状态不一致")
    updated = _updated_context(updated, session)
    output = DebugFinishOutput(
        debug_session_id=context.debug_session_id,
        state=cast(Literal["exited", "detached"], session.state),
        observed_event_sequence=event.sequence,
        completion_provenance="ida_event",
        completion_kind=cast(
            Literal["process_exited", "process_detached"],
            event.kind,
        ),
    )
    return DebugAdaptation(updated, output)
