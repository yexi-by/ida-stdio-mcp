"""公共静态工具模型与 AnalysisWorker JSON 契约之间的纯函数适配层。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal, cast

from pydantic import JsonValue, ValidationError

from ida_re_mcp.constants import MAX_GRAPH_NODES, MAX_PAGE_SIZE
from ida_re_mcp.domain.address import (
    AddressRef,
    DatabaseAddress,
    ImageAddress,
    RuntimeAddress,
)
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.common import Coverage, Evidence, Provenance
from ida_re_mcp.domain.identifiers import RevisionId, WorkspaceId
from ida_re_mcp.domain.tools import (
    AddressInspectInput,
    AddressInspectOutput,
    DataflowSliceInput,
    DataflowSliceOutput,
    FunctionByAddress,
    FunctionByEntity,
    FunctionInspectInput,
    FunctionInspectOutput,
    GraphQueryInput,
    GraphQueryOutput,
    ProgramOverviewInput,
    ProgramOverviewOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
    Sha256,
    TypeAtAddress,
    TypeByName,
    TypeInspectInput,
    TypeInspectOutput,
)

type StaticAdapterInput = (
    ProgramOverviewInput
    | ProgramSearchInput
    | AddressInspectInput
    | FunctionInspectInput
    | GraphQueryInput
    | DataflowSliceInput
    | TypeInspectInput
)
type StaticAdapterOutput = (
    ProgramOverviewOutput
    | ProgramSearchOutput
    | AddressInspectOutput
    | FunctionInspectOutput
    | GraphQueryOutput
    | DataflowSliceOutput
    | TypeInspectOutput
)
type ProvenanceBackend = Literal["ida", "hexrays"]
type EvidenceKind = Literal[
    "instruction",
    "xref",
    "decompiler",
    "microcode",
    "loader",
    "type_system",
]

_STATIC_NAMES: Final = frozenset(
    {
        "program.overview",
        "program.search",
        "address.inspect",
        "function.inspect",
        "graph.query",
        "dataflow.slice",
        "type.inspect",
    }
)
_CANONICAL_HEX: Final = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_ENTITY_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{7,159}$")
_HEX_PAYLOAD: Final = re.compile(r"^(?:0|[1-9a-f][0-9a-f]*)$")
_CALL_XREF_TYPES: Final = frozenset({16, 17})
_CODE_XREF_KINDS: Final = {
    16: "code_call",
    17: "code_call",
    18: "code_jump",
    19: "code_jump",
    21: "code_flow",
}
_DATA_XREF_KINDS: Final = {
    1: "data_offset",
    2: "data_write",
    3: "data_read",
}
_OVERVIEW_SECTIONS: Final = frozenset(
    {
        "segments",
        "entry_points",
        "imports",
        "exports",
        "fixups",
        "unwind",
        "functions",
        "strings",
    }
)


class StaticAdapterError(RuntimeError):
    """静态适配层的稳定失败基类。"""


class StaticAdapterInputError(StaticAdapterError):
    """公共参数无法无损映射到当前 worker。"""


class StaticAdapterResultError(StaticAdapterError):
    """worker 结果不满足当前公共输出契约。"""


class StaticAdapterCapabilityError(StaticAdapterError):
    """当前 worker 没有足够事实满足请求语义。"""


class AnalysisContext(StrictModel):
    """将一次适配固定到显式 workspace revision 与原样本身份。"""

    workspace_id: WorkspaceId
    revision: RevisionId
    sample_sha256: Sha256


@dataclass(frozen=True, slots=True)
class WorkerRequest:
    """一个可直接交给 AnalysisWorker.execute 的无状态请求。"""

    operation: str
    input: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class StaticPageFacts:
    """worker 对一个可恢复静态页给出的权威位置事实。"""

    offset: int
    limit: int
    returned: int
    has_more: bool
    next_offset: int | None

    @property
    def advance(self) -> int:
        """返回下一页相对当前页的实际推进量。"""

        if self.next_offset is None:
            return 0
        return self.next_offset - self.offset


def build_worker_requests(
    name: str,
    args: StaticAdapterInput,
    *,
    offset: int = 0,
    limit_override: int | None = None,
) -> tuple[WorkerRequest, ...]:
    """把一个公共静态查询展开为确定顺序的一个或多个 worker 请求。"""

    if name not in _STATIC_NAMES:
        raise StaticAdapterInputError(f"不支持的静态工具: {name}")
    if offset < 0 or isinstance(offset, bool):
        raise StaticAdapterInputError("offset 必须是非负整数")
    override_maximum = (
        MAX_GRAPH_NODES if name in {"graph.query", "dataflow.slice"} else MAX_PAGE_SIZE
    )
    if limit_override is not None and (
        isinstance(limit_override, bool) or limit_override < 1 or limit_override > override_maximum
    ):
        raise StaticAdapterInputError(f"{name} limit_override 必须在 1..{override_maximum} 之间")

    if name == "program.overview":
        typed = _expect_args(args, ProgramOverviewInput, name)
        return (
            WorkerRequest(
                name,
                {
                    "include": list(typed.include),
                    "limit": min(MAX_PAGE_SIZE, limit_override or MAX_PAGE_SIZE),
                },
            ),
        )

    if name == "program.search":
        typed = _expect_args(args, ProgramSearchInput, name)
        limit = min(typed.page_size, limit_override or typed.page_size)
        return (
            WorkerRequest(
                name,
                {
                    "domains": list(typed.domains),
                    "text_query": typed.text_query,
                    "bytes_query": typed.bytes_query,
                    "case_sensitive": typed.case_sensitive,
                    "offset": offset,
                    "limit": limit,
                },
            ),
        )

    if name == "address.inspect":
        typed = _expect_args(args, AddressInspectInput, name)
        return (
            WorkerRequest(
                name,
                {
                    "address": _worker_address(typed.address),
                    "byte_count": typed.byte_count,
                    "limit": min(MAX_PAGE_SIZE, limit_override or MAX_PAGE_SIZE),
                },
            ),
        )

    if name == "function.inspect":
        typed = _expect_args(args, FunctionInspectInput, name)
        limit = min(typed.page_size, limit_override or typed.page_size)
        views: list[JsonValue] = []
        view_names = {
            "summary": "summary",
            "chunks": "chunks",
            "instructions": "disassembly",
            "pseudocode": "pseudocode",
            "ctree_map": "ctree",
            "blocks": "blocks",
            "calls": "calls",
            "strings": "strings",
            "stack": "stack",
            "locals": "lvars",
            "types": "types",
        }
        for view in typed.views:
            mapped = view_names.get(view)
            if mapped is not None and mapped not in views:
                views.append(mapped)
        return (
            WorkerRequest(
                name,
                {
                    "address": _function_worker_address(typed, typed.revision),
                    "views": views,
                    "offset": offset,
                    "limit": limit,
                },
            ),
        )

    if name == "graph.query":
        typed = _expect_args(args, GraphQueryInput, name)
        graph_limit = min(typed.max_nodes, limit_override or typed.max_nodes)
        return (
            WorkerRequest(
                name,
                {
                    "kind": typed.graph,
                    "roots": [_worker_address(root) for root in typed.roots],
                    "direction": typed.direction,
                    "max_depth": typed.max_depth,
                    "limit": graph_limit,
                },
            ),
        )

    if name == "dataflow.slice":
        typed = _expect_args(args, DataflowSliceInput, name)
        slice_limit = min(typed.max_steps, limit_override or typed.max_steps)
        return (
            WorkerRequest(
                name,
                {
                    "address": _selector_worker_address(
                        typed.function,
                        typed.revision,
                    ),
                    "seed": _worker_address(typed.seed.address),
                    "direction": typed.direction,
                    "semantics": typed.semantics,
                    "limit": slice_limit,
                },
            ),
        )

    typed = _expect_args(args, TypeInspectInput, name)
    limit = min(typed.page_size, limit_override or typed.page_size)
    selector = typed.type
    if isinstance(selector, TypeAtAddress):
        worker_input: dict[str, JsonValue] = {"address": _worker_address(selector.address)}
    elif isinstance(selector, TypeByName):
        worker_input = {"name": selector.name}
    else:
        worker_input = _decode_type_entity(selector.entity_id, typed.revision)
    return (
        WorkerRequest(
            name,
            {
                **worker_input,
                "offset": offset,
                "limit": limit,
            },
        ),
    )


def static_page_facts(
    name: str,
    args: StaticAdapterInput,
    raw_results: Sequence[Mapping[str, object]],
) -> StaticPageFacts | None:
    """读取 worker 返回的可恢复页事实; 非分页静态工具返回 None。"""

    if name not in {"program.search", "function.inspect", "type.inspect"}:
        return None
    requests = build_worker_requests(name, args)
    if len(requests) != 1 or len(raw_results) != 1:
        raise StaticAdapterResultError(f"{name} 分页结果数量不符合单流契约")
    page = _mapping(raw_results[0].get("page"), f"{name}.page")
    offset = _integer(page.get("offset"), f"{name}.page.offset", minimum=0)
    limit = _integer(
        page.get("limit"),
        f"{name}.page.limit",
        minimum=1,
        maximum=MAX_PAGE_SIZE,
    )
    returned = _integer(
        page.get("returned"),
        f"{name}.page.returned",
        minimum=0,
        maximum=limit,
    )
    has_more = _boolean(page.get("has_more"), f"{name}.page.has_more")
    raw_next_offset = page.get("next_offset")
    if has_more:
        next_offset = _integer(
            raw_next_offset,
            f"{name}.page.next_offset",
            minimum=offset + 1,
        )
        if returned != limit or next_offset != offset + limit:
            raise StaticAdapterResultError(f"{name} worker 返回不可恢复的分页推进事实")
    else:
        if raw_next_offset is not None:
            raise StaticAdapterResultError(f"{name} 末页不得返回 next_offset")
        next_offset = None
    return StaticPageFacts(
        offset=offset,
        limit=limit,
        returned=returned,
        has_more=has_more,
        next_offset=next_offset,
    )


def static_page_has_more(
    name: str,
    args: StaticAdapterInput,
    raw_results: Sequence[Mapping[str, object]],
) -> bool:
    """返回静态查询是否存在可恢复的下一页。"""

    facts = static_page_facts(name, args, raw_results)
    return facts is not None and facts.has_more


def static_page_advance(
    name: str,
    args: StaticAdapterInput,
    raw_results: Sequence[Mapping[str, object]],
) -> int:
    """返回 worker 已证明的下一页 offset 推进量。"""

    facts = static_page_facts(name, args, raw_results)
    return 0 if facts is None else facts.advance


def adapt_worker_results(
    name: str,
    args: StaticAdapterInput,
    raw_results: Sequence[Mapping[str, object]],
    context: AnalysisContext,
) -> StaticAdapterOutput:
    """聚合并严格验证按 build_worker_requests 原序返回的 worker 结果。"""

    requests = build_worker_requests(name, args)
    if len(raw_results) != len(requests):
        raise StaticAdapterResultError(
            f"{name} 期望 {len(requests)} 个 worker 结果, 实际收到 {len(raw_results)} 个"
        )
    results = tuple(
        _mapping(result, f"raw_results[{index}]") for index, result in enumerate(raw_results)
    )
    _validate_context(args, context)

    try:
        if name == "program.overview":
            return _adapt_program_overview(
                _expect_args(args, ProgramOverviewInput, name),
                _single(results),
                context,
            )
        if name == "program.search":
            return _adapt_program_search(
                _expect_args(args, ProgramSearchInput, name),
                results,
                context,
            )
        if name == "address.inspect":
            return _adapt_address_inspect(
                _expect_args(args, AddressInspectInput, name),
                _single(results),
                context,
            )
        if name == "function.inspect":
            return _adapt_function_inspect(
                _expect_args(args, FunctionInspectInput, name),
                _single(results),
                context,
            )
        if name == "graph.query":
            return _adapt_graph_query(
                _expect_args(args, GraphQueryInput, name),
                results,
                context,
            )
        if name == "dataflow.slice":
            return _adapt_dataflow_slice(
                _expect_args(args, DataflowSliceInput, name),
                _single(results),
                context,
            )
        return _adapt_type_inspect(
            _expect_args(args, TypeInspectInput, name),
            _single(results),
            context,
        )
    except ValidationError as error:
        raise StaticAdapterResultError(f"{name} worker 结果无法生成严格公共输出") from error


def _expect_args[InputModelT: StrictModel](
    args: StaticAdapterInput,
    expected: type[InputModelT],
    name: str,
) -> InputModelT:
    if not isinstance(args, expected):
        raise StaticAdapterInputError(f"{name} 收到不匹配的公共参数模型")
    return args


def _validate_context(args: StaticAdapterInput, context: AnalysisContext) -> None:
    if args.workspace_id != context.workspace_id or args.revision != context.revision:
        raise StaticAdapterInputError("AnalysisContext 与公共查询的 workspace/revision 不一致")


def _worker_address(address: AddressRef) -> dict[str, JsonValue]:
    if isinstance(address, RuntimeAddress):
        raise StaticAdapterInputError("静态分析拒绝 runtime 地址")
    if isinstance(address, ImageAddress):
        return {"space": "image", "rva": address.rva}
    if isinstance(address, DatabaseAddress):
        return {"space": "database", "ea": address.ea}
    return {"space": "file", "offset": address.offset}


def _function_worker_address(
    args: FunctionInspectInput,
    revision: str,
) -> dict[str, JsonValue]:
    return _selector_worker_address(args.function, revision)


def _selector_worker_address(
    selector: FunctionByAddress | FunctionByEntity,
    revision: str,
) -> dict[str, JsonValue]:
    if isinstance(selector, FunctionByAddress):
        return _worker_address(selector.address)
    return {
        "space": "database",
        "ea": _decode_function_entity(selector.entity_id, revision),
    }


def _revision_tag(revision: str) -> str:
    return hashlib.sha256(revision.encode("utf-8")).hexdigest()[:16]


def _entity_id(*parts: str) -> str:
    value = "~".join(("entity", *parts))
    if _ENTITY_ID.fullmatch(value) is None:
        raise StaticAdapterResultError("生成的 entity_id 超出当前 opaque 编码边界")
    return value


def _hex_payload(value: str, label: str) -> str:
    canonical = _hex_text(value, label)
    return canonical[2:]


def _function_entity(revision: str, address: str) -> str:
    return _entity_id("fn", _revision_tag(revision), _hex_payload(address, "function address"))


def _block_entity(revision: str, function_address: str, block_id: int) -> str:
    return _entity_id(
        "bb",
        _revision_tag(revision),
        _hex_payload(function_address, "function address"),
        str(block_id),
    )


def _local_entity(revision: str, function_address: str, index: int) -> str:
    return _entity_id(
        "lv",
        _revision_tag(revision),
        _hex_payload(function_address, "function address"),
        str(index),
    )


def _microcode_entity(revision: str, function_address: str, index: int) -> str:
    return _entity_id(
        "mc",
        _revision_tag(revision),
        _hex_payload(function_address, "function address"),
        str(index),
    )


def _address_entity(revision: str, address: str) -> str:
    return _entity_id("addr", _revision_tag(revision), _hex_payload(address, "address"))


def _segment_entity(revision: str, start: str) -> str:
    return _entity_id("seg", _revision_tag(revision), _hex_payload(start, "segment start"))


def _type_address_entity(revision: str, address: str) -> str:
    return _entity_id("ta", _revision_tag(revision), _hex_payload(address, "type address"))


def _type_name_entity(revision: str, name: str) -> str:
    encoded = base64.urlsafe_b64encode(name.encode("utf-8")).decode("ascii").rstrip("=")
    return _entity_id("tn", _revision_tag(revision), encoded)


def _field_entity(revision: str, type_entity: str, index: int) -> str:
    digest = hashlib.sha256(f"{type_entity}\0{index}".encode()).hexdigest()[:24]
    return _entity_id("field", _revision_tag(revision), digest)


def _decode_function_entity(entity_id: str, revision: str) -> str:
    parts = entity_id.split("~")
    if len(parts) != 4 or parts[:2] != ["entity", "fn"]:
        raise StaticAdapterInputError("function entity_id 不是当前可反解编码")
    _validate_revision_tag(parts[2], revision)
    return _payload_hex(parts[3], "function entity_id")


def _decode_type_entity(entity_id: str, revision: str) -> dict[str, JsonValue]:
    parts = entity_id.split("~")
    if len(parts) != 4 or parts[0] != "entity":
        raise StaticAdapterInputError("type entity_id 不是当前可反解编码")
    _validate_revision_tag(parts[2], revision)
    if parts[1] == "ta":
        return {
            "address": {
                "space": "database",
                "ea": _payload_hex(parts[3], "type entity_id"),
            }
        }
    if parts[1] != "tn" or not parts[3]:
        raise StaticAdapterInputError("type entity_id 类型不匹配")
    encoded = parts[3]
    try:
        padded = encoded + ("=" * (-len(encoded) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError, binascii.Error) as error:
        raise StaticAdapterInputError("type entity_id 名称编码无效") from error
    if _type_name_entity(revision, decoded) != entity_id:
        raise StaticAdapterInputError("type entity_id 不是 canonical 编码")
    return {"name": decoded}


def _validate_revision_tag(actual: str, revision: str) -> None:
    if actual != _revision_tag(revision):
        raise StaticAdapterInputError("entity_id 不属于请求的 revision")


def _payload_hex(value: str, label: str) -> str:
    if _HEX_PAYLOAD.fullmatch(value) is None or len(value) > 16:
        raise StaticAdapterInputError(f"{label} 地址载荷无效")
    number = int(value, 16)
    if number > 0xFFFF_FFFF_FFFF_FFFF:
        raise StaticAdapterInputError(f"{label} 地址超出 u64")
    return f"0x{number:x}"


def _database_address(value: str, label: str = "address") -> dict[str, JsonValue]:
    return {"kind": "database", "ea": _hex_text(value, label)}


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise StaticAdapterResultError(f"{label} 必须是字符串键对象")
    unknown_mapping = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in unknown_mapping):
        raise StaticAdapterResultError(f"{label} 必须是字符串键对象")
    return cast(Mapping[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StaticAdapterResultError(f"{label} 必须是数组")
    return cast(list[object], value)


def _items(container: Mapping[str, object], key: str, label: str) -> list[Mapping[str, object]]:
    return [
        _mapping(item, f"{label}.{key}[{index}]")
        for index, item in enumerate(_list(container.get(key), f"{label}.{key}"))
    ]


def _text(value: object, label: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise StaticAdapterResultError(f"{label} 必须是字符串")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise StaticAdapterResultError(f"{label} 必须是整数")
    if minimum is not None and value < minimum:
        raise StaticAdapterResultError(f"{label} 小于下限")
    if maximum is not None and value > maximum:
        raise StaticAdapterResultError(f"{label} 超过上限")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StaticAdapterResultError(f"{label} 必须是布尔值")
    return value


def _hex_text(value: object, label: str) -> str:
    text = _text(value, label, allow_empty=False)
    if _CANONICAL_HEX.fullmatch(text) is None or int(text, 16) > 0xFFFF_FFFF_FFFF_FFFF:
        raise StaticAdapterResultError(f"{label} 不是规范 u64 十六进制地址")
    return text


def _single(results: Sequence[Mapping[str, object]]) -> Mapping[str, object]:
    if len(results) != 1:
        raise StaticAdapterResultError("期望单个 worker 结果")
    return results[0]


def _validated_output[OutputModelT: StrictModel](
    model_type: type[OutputModelT],
    value: Mapping[str, object],
) -> OutputModelT:
    return model_type.model_validate(value, strict=True)


def _coverage(
    raw_results: Sequence[Mapping[str, object]],
    *,
    reasons: Sequence[str] = (),
    adapter_truncated: bool = False,
) -> Coverage:
    normalized_reasons = list(dict.fromkeys(reasons))
    raw_complete = True
    missing = False
    raw_truncated = False
    for index, raw in enumerate(raw_results):
        coverage_value = raw.get("coverage")
        if coverage_value is None:
            missing = True
            normalized_reasons.append(f"worker_result_{index}_coverage_missing")
            continue
        coverage = _mapping(coverage_value, f"raw_results[{index}].coverage")
        complete = _boolean(
            coverage.get("complete"),
            f"raw_results[{index}].coverage.complete",
        )
        if not complete:
            raw_complete = False
        explicit_truncated = coverage.get("truncated")
        if explicit_truncated is None:
            raw_truncated |= not complete
        else:
            raw_truncated |= _boolean(
                explicit_truncated,
                f"raw_results[{index}].coverage.truncated",
            )
        raw_reasons = coverage.get("reasons")
        if raw_reasons is not None:
            for reason_index, reason in enumerate(
                _list(raw_reasons, f"raw_results[{index}].coverage.reasons")
            ):
                normalized_reasons.append(
                    _text(
                        reason,
                        f"raw_results[{index}].coverage.reasons[{reason_index}]",
                    )
                )
    normalized_reasons = list(dict.fromkeys(normalized_reasons))
    if missing:
        status = "unknown"
    elif raw_complete and not normalized_reasons and not adapter_truncated:
        status = "complete"
    else:
        status = "partial"
    return Coverage(
        status=status,
        sampled=False,
        truncated=raw_truncated or adapter_truncated,
        reasons=normalized_reasons[:32],
    )


def _provenance(
    context: AnalysisContext,
    raw_results: Sequence[Mapping[str, object]],
    *,
    backend: ProvenanceBackend,
    evidence_kind: EvidenceKind,
    warnings: Sequence[str] = (),
) -> Provenance:
    evidence: list[Evidence] = []
    for index, raw in enumerate(raw_results):
        provenance = _mapping(raw.get("provenance"), f"raw_results[{index}].provenance")
        raw_revision = provenance.get("revision")
        if raw_revision is not None and raw_revision != context.revision:
            raise StaticAdapterResultError("worker provenance revision 与 AnalysisContext 不一致")
        raw_backend = _text(
            provenance.get("backend"),
            f"raw_results[{index}].provenance.backend",
            allow_empty=False,
        )
        details = [f"worker_backend={raw_backend}"]
        change_count = provenance.get("database_change_count")
        if change_count is not None:
            details.append(
                "database_change_count="
                + str(
                    _integer(
                        change_count,
                        f"raw_results[{index}].provenance.database_change_count",
                        minimum=0,
                    )
                )
            )
        checkout_sha256 = provenance.get("checkout_sha256")
        if checkout_sha256 is not None:
            checkout = _text(
                checkout_sha256,
                f"raw_results[{index}].provenance.checkout_sha256",
                allow_empty=False,
            )
            if re.fullmatch(r"[0-9a-f]{64}", checkout) is None:
                raise StaticAdapterResultError("worker checkout_sha256 格式无效")
            details.append(f"checkout_sha256={checkout}")
        processor = provenance.get("processor")
        if processor is not None:
            details.append(
                "ida_processor="
                + _text(
                    processor,
                    f"raw_results[{index}].provenance.processor",
                    allow_empty=False,
                )
            )
        evidence.append(Evidence(kind=evidence_kind, detail="; ".join(details)))
    return Provenance(
        workspace_id=context.workspace_id,
        revision=context.revision,
        backend=backend,
        evidence=evidence,
        warnings=list(dict.fromkeys(warnings))[:64],
    )


def _adapt_program_overview(
    args: ProgramOverviewInput,
    raw: Mapping[str, object],
    context: AnalysisContext,
) -> ProgramOverviewOutput:
    image = _mapping(raw.get("image"), "program.overview.image")
    raw_sha256 = _text(image.get("sha256"), "program.overview.image.sha256")
    if raw_sha256 and raw_sha256 != context.sample_sha256:
        raise StaticAdapterResultError("worker 原样本 SHA-256 与 AnalysisContext 不一致")
    selected = set(args.include) if args.include else set(_OVERVIEW_SECTIONS)

    segments_raw = _items(raw, "segments", "program.overview")
    segments: list[dict[str, object]] = []
    if "segments" in selected:
        for index, segment in enumerate(segments_raw):
            start = _hex_text(segment.get("start"), f"segments[{index}].start")
            permissions = {
                _text(item, f"segments[{index}].permissions")
                for item in _list(segment.get("permissions"), f"segments[{index}].permissions")
            }
            if not permissions <= {"read", "write", "execute"}:
                raise StaticAdapterResultError("segment permissions 包含未知值")
            segments.append(
                {
                    "entity_id": _segment_entity(context.revision, start),
                    "name": _text(segment.get("name"), f"segments[{index}].name"),
                    "start": _database_address(start),
                    "end": _database_address(
                        _hex_text(segment.get("end"), f"segments[{index}].end")
                    ),
                    "permissions": "".join(
                        (
                            "r" if "read" in permissions else "-",
                            "w" if "write" in permissions else "-",
                            "x" if "execute" in permissions else "-",
                        )
                    ),
                }
            )

    entry_points_raw = _items(raw, "entry_points", "program.overview")
    entry_points: list[dict[str, object]] = []
    if "entry_points" in selected:
        for index, entry in enumerate(entry_points_raw):
            address = _hex_text(entry.get("address"), f"entry_points[{index}].address")
            entry_points.append(
                {
                    "entity_id": _function_entity(context.revision, address),
                    "name": _text(entry.get("name"), f"entry_points[{index}].name"),
                    "address": _database_address(address),
                }
            )

    exports_raw = _items(raw, "exports", "program.overview")
    exports: list[dict[str, object]] = []
    if "exports" in selected:
        for index, entry in enumerate(exports_raw):
            address = _hex_text(entry.get("address"), f"exports[{index}].address")
            exports.append(
                {
                    "entity_id": _function_entity(context.revision, address),
                    "name": _text(entry.get("name"), f"exports[{index}].name"),
                    "address": _database_address(address),
                }
            )

    imports_raw = _items(raw, "imports", "program.overview")
    imports: list[dict[str, object]] = []
    if "imports" in selected:
        for index, item in enumerate(imports_raw):
            module = _text(item.get("module"), f"imports[{index}].module")
            name = _text(item.get("name"), f"imports[{index}].name")
            ordinal = _integer(item.get("ordinal"), f"imports[{index}].ordinal", minimum=0)
            imports.append(
                {
                    "entity_id": None,
                    "name": name or f"{module}!#{ordinal}",
                    "address": _database_address(
                        _hex_text(item.get("address"), f"imports[{index}].address")
                    ),
                }
            )

    fixups_raw = _items(raw, "fixups", "program.overview")
    fixups: list[dict[str, object]] = []
    if "fixups" in selected:
        for index, item in enumerate(fixups_raw):
            fixups.append(
                {
                    "address": _database_address(
                        _hex_text(item.get("address"), f"fixups[{index}].address")
                    ),
                    "fixup_type": _integer(
                        item.get("type"),
                        f"fixups[{index}].type",
                        minimum=0,
                    ),
                    "description": _text(
                        item.get("description"),
                        f"fixups[{index}].description",
                        allow_empty=True,
                    ),
                }
            )

    unwind_raw = _items(raw, "unwind_regions", "program.overview")
    unwind_regions: list[dict[str, object]] = []
    if "unwind" in selected:
        for index, item in enumerate(unwind_raw):
            start = _hex_text(item.get("start"), f"unwind_regions[{index}].start")
            kind = _text(item.get("kind"), f"unwind_regions[{index}].kind")
            if kind not in {"unwind", "catch", "unwind_and_catch"}:
                raise StaticAdapterResultError("unwind region kind 无效")
            unwind_regions.append(
                {
                    "entity_id": _function_entity(context.revision, start),
                    "start": _database_address(start),
                    "end": _database_address(
                        _hex_text(item.get("end"), f"unwind_regions[{index}].end")
                    ),
                    "kind": kind,
                }
            )

    functions_raw = _items(raw, "functions", "program.overview")
    functions: list[dict[str, object]] = []
    if "functions" in selected:
        for index, item in enumerate(functions_raw):
            address = _hex_text(item.get("address"), f"functions[{index}].address")
            functions.append(
                {
                    "entity_id": _function_entity(context.revision, address),
                    "name": _text(item.get("name"), f"functions[{index}].name"),
                    "address": _database_address(address),
                }
            )

    strings_raw = _items(raw, "strings", "program.overview")
    strings: list[dict[str, object]] = []
    if "strings" in selected:
        for index, item in enumerate(strings_raw):
            address = _hex_text(item.get("address"), f"strings[{index}].address")
            strings.append(
                {
                    "entity_id": _address_entity(context.revision, address),
                    "address": _database_address(address),
                    "preview": _text(
                        item.get("value"),
                        f"strings[{index}].value",
                        allow_empty=True,
                    ),
                    "length": _integer(
                        item.get("length"),
                        f"strings[{index}].length",
                        minimum=0,
                    ),
                }
            )

    counts = _mapping(raw.get("counts"), "program.overview.counts")
    bitness = _integer(image.get("bitness"), "program.overview.image.bitness")
    if bitness != 64:
        raise StaticAdapterCapabilityError("当前 Native 产品边界只支持 64 位镜像")
    processor = _text(
        image.get("processor"),
        "program.overview.image.processor",
    ).casefold()
    expected_architecture = {
        "metapc": "x86_64",
        "arm": "aarch64",
        "armb": "aarch64",
        "aarch64": "aarch64",
    }.get(processor)
    if expected_architecture is None:
        raise StaticAdapterCapabilityError(f"当前 Native 产品边界不支持 IDA processor {processor}")
    architecture = _text(
        image.get("architecture"),
        "program.overview.image.architecture",
    )
    if architecture != expected_architecture:
        raise StaticAdapterResultError("worker architecture 与 IDA processor 不一致")
    image_base = int(
        _hex_text(
            image.get("imagebase"),
            "program.overview.image.imagebase",
        ),
        16,
    )
    maximum_address = int(
        _hex_text(
            image.get("maximum_address"),
            "program.overview.image.maximum_address",
        ),
        16,
    )
    if maximum_address <= image_base:
        raise StaticAdapterResultError("worker image range 不是严格正区间")
    image_size = maximum_address - image_base
    if image_size > 0xFFFF_FFFF_FFFF_FFFF:
        raise StaticAdapterResultError("worker image size 超过无符号 64 位边界")
    if (
        _integer(
            image.get("image_size"),
            "program.overview.image.image_size",
            minimum=1,
        )
        != image_size
    ):
        raise StaticAdapterResultError("worker image_size 与 image range 不一致")
    coverage = _coverage((raw,))
    provenance = _provenance(
        context,
        (raw,),
        backend="ida",
        evidence_kind="loader",
    )
    return _validated_output(
        ProgramOverviewOutput,
        {
            "image": {
                "image_id": f"image~{context.sample_sha256}",
                "format": (
                    "ida-filetype-"
                    + str(
                        _integer(
                            image.get("file_type"),
                            "program.overview.image.file_type",
                            minimum=0,
                        )
                    )
                ),
                "architecture": architecture,
                "bitness": bitness,
                "endian": _text(
                    image.get("endianness"),
                    "program.overview.image.endianness",
                ),
                "image_base": f"0x{image_base:x}",
                "image_size": image_size,
                "sha256": context.sample_sha256,
            },
            "counts": {
                "functions": _integer(
                    counts.get("functions"),
                    "program.overview.counts.functions",
                    minimum=0,
                ),
                "strings": _integer(
                    counts.get("strings"),
                    "program.overview.counts.strings",
                    minimum=0,
                ),
                "imports": _integer(
                    counts.get("imports"),
                    "program.overview.counts.imports",
                    minimum=0,
                ),
                "exports": _integer(
                    counts.get("exports"),
                    "program.overview.counts.exports",
                    minimum=0,
                ),
                "fixups": _integer(
                    counts.get("fixups"),
                    "program.overview.counts.fixups",
                    minimum=0,
                ),
                "unwind_regions": _integer(
                    counts.get("unwind_functions"),
                    "program.overview.counts.unwind_functions",
                    minimum=0,
                ),
                "exception_regions": _integer(
                    counts.get("catch_functions"),
                    "program.overview.counts.catch_functions",
                    minimum=0,
                ),
            },
            "segments": segments,
            "entry_points": entry_points,
            "imports": imports,
            "exports": exports,
            "fixups": fixups,
            "unwind_regions": unwind_regions,
            "functions": functions,
            "strings": strings,
            "coverage": coverage,
            "provenance": provenance,
        },
    )


def _adapt_program_search(
    args: ProgramSearchInput,
    raw_results: Sequence[Mapping[str, object]],
    context: AnalysisContext,
) -> ProgramSearchOutput:
    raw = _single(raw_results)
    raw_domains = [
        _text(item, f"program.search.domains[{index}]")
        for index, item in enumerate(_list(raw.get("domains"), "program.search.domains"))
    ]
    if raw_domains != args.domains:
        raise StaticAdapterResultError("program.search worker domains 与请求顺序不一致")
    matches: list[dict[str, object]] = []
    reasons: list[str] = []
    for item_index, item in enumerate(_items(raw, "items", "program.search")):
        domain = _text(item.get("domain"), f"program.search.items[{item_index}].domain")
        if domain not in args.domains:
            raise StaticAdapterResultError("program.search worker 返回未请求的 domain")
        raw_address = _hex_text(
            item.get("address"),
            f"program.search.items[{item_index}].address",
        )
        address = _database_address(raw_address)
        if domain in {"function", "name"}:
            preview = _text(
                item.get("name"),
                f"program.search.items[{item_index}].name",
            )
        elif domain == "string":
            preview = _text(
                item.get("value"),
                f"program.search.items[{item_index}].value",
            )
        else:
            preview = _text(
                item.get("bytes"),
                f"program.search.items[{item_index}].bytes",
            )
        matches.append(
            {
                "domain": domain,
                "address": address,
                "entity_id": (
                    _function_entity(context.revision, raw_address)
                    if domain == "function"
                    else None
                ),
                "preview": preview[:2_048],
            }
        )
    facts = static_page_facts("program.search", args, raw_results)
    assert facts is not None
    if len(matches) != facts.returned:
        raise StaticAdapterResultError("program.search page.returned 与 items 数量不一致")
    coverage = _coverage(raw_results, reasons=reasons)
    return _validated_output(
        ProgramSearchOutput,
        {
            "matches": matches,
            "next_cursor": None,
            "coverage": coverage,
            "provenance": _provenance(
                context,
                raw_results,
                backend="ida",
                evidence_kind="loader",
                warnings=reasons,
            ),
        },
    )


def _adapt_address_inspect(
    args: AddressInspectInput,
    raw: Mapping[str, object],
    context: AnalysisContext,
) -> AddressInspectOutput:
    selected = (
        set(args.include)
        if args.include
        else {
            "bytes",
            "instruction",
            "data",
            "symbol",
            "xrefs",
            "function",
        }
    )
    address = _hex_text(raw.get("address"), "address.inspect.address")
    item = _mapping(raw.get("item"), "address.inspect.item")
    raw_instruction = raw.get("instruction")
    instruction = (
        None
        if raw_instruction is None
        else _mapping(raw_instruction, "address.inspect.instruction")
    )
    raw_function = raw.get("function")
    function = None if raw_function is None else _mapping(raw_function, "address.inspect.function")
    bytes_hex = _text(item.get("bytes"), "address.inspect.item.bytes")
    xrefs: list[dict[str, object]] = []
    unknown_xrefs = 0
    if "xrefs" in selected:
        for direction, key in (("outgoing", "xrefs_from"), ("incoming", "xrefs_to")):
            for index, xref in enumerate(_items(raw, key, "address.inspect")):
                is_code = _boolean(xref.get("is_code"), f"{key}[{index}].is_code")
                xref_type = _integer(xref.get("type"), f"{key}[{index}].type", minimum=0)
                kind = _xref_kind(xref_type, is_code=is_code)
                if kind is None:
                    unknown_xrefs += 1
                    continue
                other_key = "to" if direction == "outgoing" else "from"
                other = _hex_text(xref.get(other_key), f"{key}[{index}].{other_key}")
                source = address if direction == "outgoing" else other
                target = other if direction == "outgoing" else address
                xrefs.append(
                    {
                        "kind": kind,
                        "source": _database_address(source),
                        "target": _database_address(target),
                        "resolved": True,
                    }
                )
    reasons = ["unknown_xref_types_omitted"] if unknown_xrefs else []
    function_id: str | None = None
    function_entry: str | None = None
    if function is not None:
        function_entry = _hex_text(function.get("entry"), "address.inspect.function.entry")
        function_id = _function_entity(context.revision, function_entry)
    return _validated_output(
        AddressInspectOutput,
        {
            "address": _database_address(address),
            "entity_id": function_id if function_entry == address else None,
            "bytes_hex": bytes_hex if "bytes" in selected else None,
            "instruction": (
                {
                    "address": _database_address(address),
                    "size": _integer(
                        instruction.get("size"),
                        "address.inspect.instruction.size",
                        minimum=1,
                    ),
                    "mnemonic": _text(
                        instruction.get("mnemonic"),
                        "address.inspect.instruction.mnemonic",
                    ),
                    "text": _text(
                        instruction.get("text"),
                        "address.inspect.instruction.text",
                    )[:4_096],
                    "operands": _adapt_operands(
                        instruction.get("operands"),
                        "address.inspect.instruction.operands",
                    ),
                }
                if instruction is not None and "instruction" in selected
                else None
            ),
            "data_rendering": (
                f"hex:{bytes_hex}"
                if "data" in selected
                and _boolean(item.get("is_data"), "address.inspect.item.is_data")
                else None
            ),
            "symbol": (
                (_text(raw.get("name"), "address.inspect.name") or None)
                if "symbol" in selected
                else None
            ),
            "function_id": function_id if "function" in selected else None,
            "xrefs": xrefs,
            "coverage": _coverage((raw,), reasons=reasons),
            "provenance": _provenance(
                context,
                (raw,),
                backend="ida",
                evidence_kind="xref" if "xrefs" in selected else "instruction",
                warnings=reasons,
            ),
        },
    )


def _xref_kind(xref_type: int, *, is_code: bool) -> str | None:
    if is_code:
        return _CODE_XREF_KINDS.get(xref_type)
    return _DATA_XREF_KINDS.get(xref_type)


def _adapt_operands(raw: object, label: str) -> list[dict[str, object]]:
    operands: list[dict[str, object]] = []
    for position, operand in enumerate(_items({"operands": raw}, "operands", label)):
        index = _integer(
            operand.get("index"),
            f"{label}[{position}].index",
            minimum=0,
            maximum=7,
        )
        if index != position:
            raise StaticAdapterResultError(f"{label} 必须按连续 index 排列")
        raw_value = operand.get("value")
        raw_address = operand.get("address")
        operands.append(
            {
                "index": index,
                "type": _integer(
                    operand.get("type"),
                    f"{label}[{position}].type",
                    minimum=0,
                    maximum=255,
                ),
                "dtype": _integer(
                    operand.get("dtype"),
                    f"{label}[{position}].dtype",
                    minimum=0,
                    maximum=255,
                ),
                "text": _text(
                    operand.get("text"),
                    f"{label}[{position}].text",
                )[:4_096],
                "value": (
                    None
                    if raw_value is None
                    else _hex_text(raw_value, f"{label}[{position}].value")
                ),
                "address": (
                    None
                    if raw_address is None
                    else _database_address(_hex_text(raw_address, f"{label}[{position}].address"))
                ),
            }
        )
    if len(operands) > 8:
        raise StaticAdapterResultError(f"{label} 超过 8 个操作数")
    return operands


def _adapt_function_inspect(
    args: FunctionInspectInput,
    raw: Mapping[str, object],
    context: AnalysisContext,
) -> FunctionInspectOutput:
    selected = set(args.views)
    entry = _hex_text(raw.get("entry"), "function.inspect.entry")
    function_entity = _function_entity(context.revision, entry)
    raw_chunks = _items(raw, "chunks", "function.inspect")
    chunk_bounds: list[tuple[str, str]] = []
    for index, chunk in enumerate(raw_chunks):
        start = _hex_text(chunk.get("start"), f"function.inspect.chunks[{index}].start")
        end = _hex_text(chunk.get("end"), f"function.inspect.chunks[{index}].end")
        if int(end, 16) < int(start, 16):
            raise StaticAdapterResultError("function chunk end 早于 start")
        chunk_bounds.append((start, end))
    if chunk_bounds:
        function_end = max((end for _, end in chunk_bounds), key=lambda value: int(value, 16))
    else:
        size = _integer(raw.get("size"), "function.inspect.size", minimum=0)
        end_value = int(entry, 16) + size
        if end_value > 0xFFFF_FFFF_FFFF_FFFF:
            raise StaticAdapterResultError("function end 超出 u64")
        function_end = f"0x{end_value:x}"

    instructions: list[dict[str, object]] = []
    if "instructions" in selected:
        for index, instruction in enumerate(_items(raw, "instructions", "function.inspect")):
            instructions.append(
                {
                    "address": _database_address(
                        _hex_text(
                            instruction.get("address"),
                            f"function.inspect.instructions[{index}].address",
                        )
                    ),
                    "size": _integer(
                        instruction.get("size"),
                        f"function.inspect.instructions[{index}].size",
                        minimum=1,
                    ),
                    "mnemonic": _text(
                        instruction.get("mnemonic"),
                        f"function.inspect.instructions[{index}].mnemonic",
                    ),
                    "text": _text(
                        instruction.get("text"),
                        f"function.inspect.instructions[{index}].text",
                    )[:4_096],
                    "operands": _adapt_operands(
                        instruction.get("operands"),
                        f"function.inspect.instructions[{index}].operands",
                    ),
                }
            )

    pseudocode: list[str] = []
    if "pseudocode" in selected:
        pseudocode = [
            _text(line, f"function.inspect.pseudocode[{index}]")
            for index, line in enumerate(
                _list(raw.get("pseudocode"), "function.inspect.pseudocode")
            )
        ]

    ctree_map: list[dict[str, object]] = []
    if "ctree_map" in selected:
        for index, item in enumerate(_items(raw, "ctree", "function.inspect")):
            kind = _text(item.get("item"), f"function.inspect.ctree[{index}].item")
            if kind not in {"expression", "statement"}:
                raise StaticAdapterResultError("ctree item kind 无效")
            text_value = item.get("text")
            ctree_map.append(
                {
                    "kind": kind,
                    "address": _database_address(
                        _hex_text(
                            item.get("address"),
                            f"function.inspect.ctree[{index}].address",
                        )
                    ),
                    "opcode": _integer(
                        item.get("opcode"),
                        f"function.inspect.ctree[{index}].opcode",
                        minimum=0,
                    ),
                    "text": (
                        None
                        if text_value is None
                        else _text(text_value, f"function.inspect.ctree[{index}].text")[:4_096]
                    ),
                }
            )

    blocks: list[dict[str, object]] = []
    if "blocks" in selected:
        for index, block in enumerate(_items(raw, "blocks", "function.inspect")):
            block_id = _integer(
                block.get("id"),
                f"function.inspect.blocks[{index}].id",
                minimum=0,
            )
            blocks.append(
                {
                    "entity_id": _block_entity(
                        context.revision,
                        entry,
                        block_id,
                    ),
                    "start": _database_address(
                        _hex_text(
                            block.get("start"),
                            f"function.inspect.blocks[{index}].start",
                        )
                    ),
                    "end": _database_address(
                        _hex_text(
                            block.get("end"),
                            f"function.inspect.blocks[{index}].end",
                        )
                    ),
                    "successors": [
                        _block_entity(
                            context.revision,
                            entry,
                            _integer(
                                successor,
                                f"function.inspect.blocks[{index}].successors",
                                minimum=0,
                            ),
                        )
                        for successor in _list(
                            block.get("successors"),
                            f"function.inspect.blocks[{index}].successors",
                        )
                    ],
                    "predecessors": [
                        _block_entity(
                            context.revision,
                            entry,
                            _integer(
                                predecessor,
                                f"function.inspect.blocks[{index}].predecessors",
                                minimum=0,
                            ),
                        )
                        for predecessor in _list(
                            block.get("predecessors"),
                            f"function.inspect.blocks[{index}].predecessors",
                        )
                    ],
                }
            )

    calls: list[dict[str, object]] = []
    raw_calls: list[Mapping[str, object]] = []
    filtered_non_calls = 0
    if "calls" in selected:
        raw_calls = _items(raw, "calls", "function.inspect")
        for index, call in enumerate(raw_calls):
            xref_type = _integer(
                call.get("xref_type"),
                f"function.inspect.calls[{index}].xref_type",
                minimum=0,
            )
            if xref_type not in _CALL_XREF_TYPES:
                filtered_non_calls += 1
                continue
            calls.append(
                {
                    "kind": "code_call",
                    "source": _database_address(
                        _hex_text(
                            call.get("site"),
                            f"function.inspect.calls[{index}].site",
                        )
                    ),
                    "target": _database_address(
                        _hex_text(
                            call.get("target"),
                            f"function.inspect.calls[{index}].target",
                        )
                    ),
                    "resolved": True,
                }
            )

    strings: list[dict[str, object]] = []
    raw_strings: list[Mapping[str, object]] = []
    if "strings" in selected:
        raw_strings = _items(raw, "strings", "function.inspect")
        for index, string in enumerate(raw_strings):
            strings.append(
                {
                    "reference": _database_address(
                        _hex_text(
                            string.get("site"),
                            f"function.inspect.strings[{index}].site",
                        )
                    ),
                    "address": _database_address(
                        _hex_text(
                            string.get("address"),
                            f"function.inspect.strings[{index}].address",
                        )
                    ),
                    "value_hex": _text(
                        string.get("value_hex"),
                        f"function.inspect.strings[{index}].value_hex",
                    ),
                }
            )

    raw_stack = raw.get("stack")
    stack: dict[str, object] | None = None
    if "stack" in selected:
        stack_mapping = _mapping(raw_stack, "function.inspect.stack")
        stack = {
            "local_size": _integer(
                stack_mapping.get("local_size"),
                "function.inspect.stack.local_size",
                minimum=0,
            ),
            "saved_register_size": _integer(
                stack_mapping.get("saved_register_size"),
                "function.inspect.stack.saved_register_size",
                minimum=0,
            ),
            "argument_size": _integer(
                stack_mapping.get("argument_size"),
                "function.inspect.stack.argument_size",
                minimum=0,
            ),
            "frame_pointer_delta": _integer(
                stack_mapping.get("frame_pointer_delta"),
                "function.inspect.stack.frame_pointer_delta",
            ),
            "frame_size": _integer(
                stack_mapping.get("frame_size"),
                "function.inspect.stack.frame_size",
                minimum=0,
            ),
        }

    local_variables: list[dict[str, object]] = []
    if "locals" in selected:
        for raw_index, variable in enumerate(_items(raw, "lvars", "function.inspect")):
            index = _integer(
                variable.get("index"),
                f"function.inspect.lvars[{raw_index}].index",
                minimum=0,
            )
            storage = _text(
                variable.get("location"),
                f"function.inspect.lvars[{raw_index}].location",
            )
            if storage not in {"stack", "register", "other"}:
                raise StaticAdapterResultError("local variable storage 无效")
            local_variables.append(
                {
                    "entity_id": _local_entity(context.revision, entry, index),
                    "name": _text(
                        variable.get("name"),
                        f"function.inspect.lvars[{raw_index}].name",
                    ),
                    "type_display": _text(
                        variable.get("type"),
                        f"function.inspect.lvars[{raw_index}].type",
                    ),
                    "storage": storage,
                }
            )

    raw_type = raw.get("type")
    type_display = None if raw_type is None else _text(raw_type, "function.inspect.type")
    reasons: list[str] = []
    if "calls" in selected:
        reasons.append("unresolved_indirect_calls_not_enumerated")
        if filtered_non_calls:
            reasons.append("non_call_code_xrefs_filtered")
    facts = static_page_facts("function.inspect", args, (raw,))
    assert facts is not None
    page_lengths = [
        len(_list(raw.get(key), f"function.inspect.{key}"))
        for public_view, key in (
            ("instructions", "instructions"),
            ("pseudocode", "pseudocode"),
            ("ctree_map", "ctree"),
            ("blocks", "blocks"),
            ("calls", "calls"),
            ("strings", "strings"),
            ("locals", "lvars"),
        )
        if public_view in selected
    ]
    if max(page_lengths, default=0) != facts.returned:
        raise StaticAdapterResultError("function.inspect page.returned 与分页视图不一致")
    uses_hexrays = bool({"pseudocode", "ctree_map", "locals"} & selected)
    return _validated_output(
        FunctionInspectOutput,
        {
            "entity_id": function_entity,
            "name": _text(raw.get("name"), "function.inspect.name"),
            "start": _database_address(entry),
            "end": _database_address(function_end),
            "prototype": type_display,
            "chunks": (
                [
                    {
                        "start": _database_address(start),
                        "end": _database_address(end),
                    }
                    for start, end in chunk_bounds
                ]
                if "chunks" in selected
                else []
            ),
            "instructions": instructions,
            "pseudocode": pseudocode,
            "ctree_map": ctree_map,
            "blocks": blocks,
            "calls": calls,
            "strings": strings,
            "stack": stack,
            "locals": local_variables,
            "type_view": (
                {"display": type_display}
                if "types" in selected and type_display is not None
                else None
            ),
            "next_cursor": None,
            "coverage": _coverage((raw,), reasons=reasons),
            "provenance": _provenance(
                context,
                (raw,),
                backend="hexrays" if uses_hexrays else "ida",
                evidence_kind="decompiler" if uses_hexrays else "instruction",
                warnings=reasons,
            ),
        },
    )


def _adapt_graph_query(
    args: GraphQueryInput,
    raw_results: Sequence[Mapping[str, object]],
    context: AnalysisContext,
) -> GraphQueryOutput:
    raw = _single(raw_results)
    graph_kind = _text(raw.get("kind"), "graph.query.kind")
    if graph_kind != args.graph:
        raise StaticAdapterResultError("graph.query worker graph kind 与请求不一致")
    direction = _text(raw.get("direction"), "graph.query.direction")
    if direction != args.direction:
        raise StaticAdapterResultError("graph.query worker direction 与请求不一致")
    max_depth = _integer(raw.get("max_depth"), "graph.query.max_depth", minimum=0, maximum=32)
    if max_depth != args.max_depth:
        raise StaticAdapterResultError("graph.query worker max_depth 与请求不一致")

    raw_to_entity: dict[str, str] = {}
    nodes: list[dict[str, object]] = []
    reasons: list[str] = []
    for index, node in enumerate(_items(raw, "nodes", "graph.query")):
        raw_id = _text(node.get("id"), f"graph.query.nodes[{index}].id")
        if raw_id in raw_to_entity:
            raise StaticAdapterResultError("graph.query worker 返回重复 node id")
        node_kind = _text(node.get("kind"), f"graph.query.nodes[{index}].kind")
        if node_kind not in {"function", "basic_block", "instruction", "data", "unknown"}:
            raise StaticAdapterResultError("graph.query worker 返回未知 node kind")
        address = _hex_text(node.get("address"), f"graph.query.nodes[{index}].address")
        if node_kind == "function":
            entity_id = _function_entity(context.revision, address)
        elif node_kind == "basic_block":
            function_address = _hex_text(
                node.get("function"),
                f"graph.query.nodes[{index}].function",
            )
            block_id = _integer(
                node.get("block_id"),
                f"graph.query.nodes[{index}].block_id",
                minimum=0,
            )
            entity_id = _block_entity(context.revision, function_address, block_id)
        else:
            entity_id = _address_entity(context.revision, address)
        if entity_id in raw_to_entity.values():
            raise StaticAdapterResultError("graph.query worker 返回重复语义节点")
        raw_to_entity[raw_id] = entity_id
        nodes.append(
            {
                "entity_id": entity_id,
                "kind": node_kind,
                "label": _text(node.get("label"), f"graph.query.nodes[{index}].label"),
                "address": _database_address(address),
            }
        )
    if not nodes:
        raise StaticAdapterResultError("graph.query worker 返回空节点集")
    if len(nodes) > args.max_nodes:
        raise StaticAdapterResultError("graph.query worker 突破请求节点上限")

    edges: list[dict[str, object]] = []
    edge_keys: set[tuple[str, str, str, str | None]] = set()
    for index, edge in enumerate(_items(raw, "edges", "graph.query")):
        raw_source = _text(edge.get("source"), f"graph.query.edges[{index}].source")
        raw_target = _text(edge.get("target"), f"graph.query.edges[{index}].target")
        source = raw_to_entity.get(raw_source)
        target = raw_to_entity.get(raw_target)
        if source is None or target is None:
            raise StaticAdapterResultError("graph.query edge 引用了未返回节点")
        edge_kind = _text(edge.get("kind"), f"graph.query.edges[{index}].kind")
        if edge_kind not in {"flow", "call", "jump", "xref_code", "xref_data", "unresolved"}:
            raise StaticAdapterResultError("graph.query worker 返回未知 edge kind")
        raw_evidence = edge.get("site")
        evidence = (
            None
            if raw_evidence is None
            else _hex_text(raw_evidence, f"graph.query.edges[{index}].site")
        )
        key = (source, target, edge_kind, evidence)
        if key in edge_keys:
            raise StaticAdapterResultError("graph.query worker 返回重复边")
        edge_keys.add(key)
        edges.append(
            {
                "source": source,
                "target": target,
                "kind": edge_kind,
                "evidence": None if evidence is None else _database_address(evidence),
            }
        )

    unresolved = _integer(
        raw.get("unresolved_indirect_edges", 0),
        "graph.query.unresolved_indirect_edges",
        minimum=0,
    )
    if args.graph != "call" and unresolved:
        raise StaticAdapterResultError("非 call graph 不得返回未解析间接调用")
    if unresolved:
        reasons.append("unresolved_indirect_calls")
    evidence_kind: EvidenceKind = "instruction" if args.graph == "cfg" else "xref"
    return _validated_output(
        GraphQueryOutput,
        {
            "nodes": nodes,
            "edges": edges,
            "unresolved_indirect_edges": unresolved,
            "coverage": _coverage(raw_results, reasons=reasons),
            "provenance": _provenance(
                context,
                raw_results,
                backend="ida",
                evidence_kind=evidence_kind,
                warnings=reasons,
            ),
        },
    )


def _adapt_dataflow_slice(
    args: DataflowSliceInput,
    raw: Mapping[str, object],
    context: AnalysisContext,
) -> DataflowSliceOutput:
    function_address = _hex_text(raw.get("function"), "dataflow.slice.function")
    _hex_text(raw.get("seed"), "dataflow.slice.seed")
    direction = _text(raw.get("direction"), "dataflow.slice.direction")
    if direction != args.direction:
        raise StaticAdapterResultError("dataflow worker direction 与请求不一致")
    mode = _text(raw.get("mode"), "dataflow.slice.mode")
    if mode not in {"may", "must"}:
        raise StaticAdapterResultError("dataflow worker mode 无效")
    if args.semantics == "must" and mode != "must":
        raise StaticAdapterCapabilityError("worker 只能证明 MAY 切片, 无法满足 MUST 请求")
    if args.semantics == "may" and mode != "may":
        raise StaticAdapterResultError("dataflow worker 返回了非请求的 MUST 语义")

    rows: dict[int, tuple[str, set[str], set[str]]] = {}
    nodes: list[dict[str, object]] = []
    for raw_index, instruction in enumerate(_items(raw, "instructions", "dataflow.slice")):
        index = _integer(
            instruction.get("index"),
            f"dataflow.slice.instructions[{raw_index}].index",
            minimum=0,
        )
        address = _hex_text(
            instruction.get("address"),
            f"dataflow.slice.instructions[{raw_index}].address",
        )
        entity_id = _microcode_entity(
            context.revision,
            function_address,
            index,
        )
        definitions = {
            _text(
                item,
                f"dataflow.slice.instructions[{raw_index}].defs",
                allow_empty=False,
            )
            for item in _list(
                instruction.get("defs"),
                f"dataflow.slice.instructions[{raw_index}].defs",
            )
        }
        uses = {
            _text(
                item,
                f"dataflow.slice.instructions[{raw_index}].uses",
                allow_empty=False,
            )
            for item in _list(
                instruction.get("uses"),
                f"dataflow.slice.instructions[{raw_index}].uses",
            )
        }
        if index in rows:
            raise StaticAdapterResultError("dataflow worker 返回重复 microcode index")
        rows[index] = (entity_id, definitions, uses)
        nodes.append(
            {
                "entity_id": entity_id,
                "operation": _text(
                    instruction.get("text"),
                    f"dataflow.slice.instructions[{raw_index}].text",
                ),
                "address": _database_address(address),
            }
        )

    edges: list[dict[str, object]] = []
    edge_keys: set[tuple[int, int]] = set()
    for edge_index, edge in enumerate(_items(raw, "edges", "dataflow.slice")):
        source_index = _integer(
            edge.get("source_index"),
            f"dataflow.slice.edges[{edge_index}].source_index",
            minimum=0,
        )
        target_index = _integer(
            edge.get("target_index"),
            f"dataflow.slice.edges[{edge_index}].target_index",
            minimum=0,
        )
        relation = _text(
            edge.get("relation"),
            f"dataflow.slice.edges[{edge_index}].relation",
        )
        if relation != "defines":
            raise StaticAdapterResultError("dataflow worker 返回不支持的关系")
        if source_index not in rows or target_index not in rows:
            raise StaticAdapterResultError("dataflow edge 引用了未返回的 microcode 节点")
        if (source_index, target_index) in edge_keys:
            raise StaticAdapterResultError("dataflow worker 返回重复边")
        edge_keys.add((source_index, target_index))
        edges.append(
            {
                "source": rows[source_index][0],
                "target": rows[target_index][0],
                "relation": "defines",
            }
        )

    barriers: list[dict[str, object]] = []
    for index, barrier in enumerate(_items(raw, "unknown_barriers", "dataflow.slice")):
        reason = _text(
            barrier.get("reason"),
            f"dataflow.slice.unknown_barriers[{index}].reason",
        )
        if reason not in {
            "unknown_call",
            "unknown_memory",
            "alias_ambiguity",
            "unknown_call_or_alias_memory",
            "analysis_limit",
        }:
            raise StaticAdapterResultError("dataflow worker barrier reason 无效")
        raw_address = barrier.get("address")
        barriers.append(
            {
                "reason": reason,
                "address": (
                    None
                    if raw_address is None
                    else _database_address(
                        _hex_text(
                            raw_address,
                            f"dataflow.slice.unknown_barriers[{index}].address",
                        )
                    )
                ),
                "detail": {
                    "unknown_call": "调用副作用或寄存器破坏集合无法在当前函数内证明",
                    "unknown_memory": "内存来源或写入目标无法解析",
                    "alias_ambiguity": "间接内存访问可能与当前数据位置别名",
                    "unknown_call_or_alias_memory": "调用或别名内存副作用无法区分",
                    "analysis_limit": "有界 slice 达到请求的节点上限",
                }[reason],
            }
        )

    raw_coverage = _mapping(raw.get("coverage"), "dataflow.slice.coverage")
    if not _boolean(
        raw_coverage.get("bounded_to_function"),
        "dataflow.slice.coverage.bounded_to_function",
    ):
        raise StaticAdapterResultError("dataflow worker 未把切片限制在函数内")
    reasons = [f"dataflow_barrier:{barrier['reason']}" for barrier in barriers]
    actual_semantics = cast(Literal["may", "must"], mode)
    return _validated_output(
        DataflowSliceOutput,
        {
            "semantics": actual_semantics,
            "nodes": nodes,
            "edges": edges,
            "barriers": barriers,
            "coverage": _coverage((raw,), reasons=reasons),
            "provenance": _provenance(
                context,
                (raw,),
                backend="hexrays",
                evidence_kind="microcode",
                warnings=reasons,
            ),
        },
    )


def _adapt_type_inspect(
    args: TypeInspectInput,
    raw: Mapping[str, object],
    context: AnalysisContext,
) -> TypeInspectOutput:
    details = _mapping(raw.get("type"), "type.inspect.type")
    declaration = _text(details.get("declaration"), "type.inspect.type.declaration")
    address = details.get("address")
    raw_name = details.get("name")
    if (address is None) == (raw_name is None):
        raise StaticAdapterResultError("type worker identity 必须且只能包含 address 或 name")
    if address is not None:
        canonical_address = _hex_text(address, "type.inspect.type.address")
        entity_id = _type_address_entity(context.revision, canonical_address)
        name = declaration
    else:
        name = _text(raw_name, "type.inspect.type.name", allow_empty=False)
        entity_id = _type_name_entity(context.revision, name)

    predicates = {
        "pointer": _boolean(details.get("is_pointer"), "type.inspect.type.is_pointer"),
        "function": _boolean(details.get("is_function"), "type.inspect.type.is_function"),
        "struct": _boolean(details.get("is_struct"), "type.inspect.type.is_struct"),
        "union": _boolean(details.get("is_union"), "type.inspect.type.is_union"),
        "enum": _boolean(details.get("is_enum"), "type.inspect.type.is_enum"),
        "array": _boolean(details.get("is_array"), "type.inspect.type.is_array"),
    }
    kind = next((candidate for candidate, matches in predicates.items() if matches), "primitive")
    raw_members = details.get("members")
    members = [] if raw_members is None else _items(details, "members", "type.inspect.type")
    fields: list[dict[str, object]] = []
    seen_member_indexes: set[int] = set()
    for page_index, member in enumerate(members):
        index = _integer(
            member.get("index"),
            f"type.inspect.type.members[{page_index}].index",
            minimum=0,
        )
        if index in seen_member_indexes:
            raise StaticAdapterResultError("type worker 返回重复 member index")
        seen_member_indexes.add(index)
        fields.append(
            {
                "entity_id": _field_entity(context.revision, entity_id, index),
                "name": _text(
                    member.get("name"),
                    f"type.inspect.type.members[{page_index}].name",
                ),
                "offset_bits": _integer(
                    member.get("offset_bits"),
                    f"type.inspect.type.members[{page_index}].offset_bits",
                    minimum=0,
                ),
                "size_bits": _integer(
                    member.get("size_bits"),
                    f"type.inspect.type.members[{page_index}].size_bits",
                    minimum=0,
                ),
                "type_display": _text(
                    member.get("type"),
                    f"type.inspect.type.members[{page_index}].type",
                ),
            }
        )
    size_value = _integer(details.get("size"), "type.inspect.type.size")
    facts = static_page_facts("type.inspect", args, (raw,))
    assert facts is not None
    if len(fields) != facts.returned:
        raise StaticAdapterResultError("type.inspect page.returned 与 members 数量不一致")
    reasons: list[str] = []
    return _validated_output(
        TypeInspectOutput,
        {
            "entity_id": entity_id,
            "name": name,
            "kind": kind,
            "size": size_value if size_value >= 0 else None,
            "display": declaration,
            "fields": fields,
            "next_cursor": None,
            "coverage": _coverage((raw,), reasons=reasons),
            "provenance": _provenance(
                context,
                (raw,),
                backend="ida",
                evidence_kind="type_system",
                warnings=reasons,
            ),
        },
    )
