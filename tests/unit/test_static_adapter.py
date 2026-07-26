from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from ida_re_mcp.domain.address import DatabaseAddress, RuntimeAddress
from ida_re_mcp.domain.base import tool_json_schema
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
    OperandView,
    ProgramOverviewInput,
    ProgramOverviewOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
    SliceAddressSeed,
    TypeByEntity,
    TypeByName,
    TypeInspectInput,
    TypeInspectOutput,
)
from ida_re_mcp.supervisor.static_adapter import (
    AnalysisContext,
    StaticAdapterCapabilityError,
    StaticAdapterInputError,
    StaticAdapterResultError,
    adapt_worker_results,
    build_worker_requests,
    static_page_advance,
    static_page_facts,
    static_page_has_more,
)

_WORKSPACE_ID = "workspace_abcdef"
_REVISION = "revision_abcdef"
_SAMPLE_SHA256 = "1" * 64


def _context(
    *,
    native_container: Literal["elf", "pe"] | None = None,
) -> AnalysisContext:
    return AnalysisContext(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        sample_sha256=_SAMPLE_SHA256,
        native_container=native_container,
    )


def _raw(payload: dict[str, object]) -> dict[str, object]:
    return {
        **payload,
        "provenance": {
            "checkout_sha256": "2" * 64,
            "database_change_count": 7,
            "backend": "ida-pro-9.3-headless",
            "revision": _REVISION,
        },
    }


def _database(ea: str) -> DatabaseAddress:
    return DatabaseAddress(kind="database", ea=ea)


def test_operand_view_is_closed_and_rejects_undeclared_fields() -> None:
    schema = tool_json_schema(OperandView)
    assert schema["additionalProperties"] is False
    with pytest.raises(ValidationError):
        OperandView.model_validate(
            {
                "index": 0,
                "type": 5,
                "dtype": 2,
                "text": "0x2a",
                "value": "0x2a",
                "address": None,
                "raw": 42,
            }
        )


def test_program_overview_maps_identity_counts_and_coverage() -> None:
    args = ProgramOverviewInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
    )
    requests = build_worker_requests("program.overview", args)
    assert requests[0].input == {"include": [], "limit": 200}
    assert build_worker_requests(
        "program.overview",
        args,
        limit_override=7,
    )[0].input == {"include": [], "limit": 7}
    with pytest.raises(StaticAdapterInputError):
        build_worker_requests("program.overview", args, limit_override=201)

    raw_result = _raw(
        {
            "image": {
                "input_name": "sample.exe",
                "sha256": _SAMPLE_SHA256,
                "imagebase": "0x140000000",
                "minimum_address": "0x140001000",
                "maximum_address": "0x140003000",
                "processor": "metapc",
                "architecture": "x86_64",
                "image_size": 0x3000,
                "bitness": 64,
                "endianness": "little",
                "container": "pe",
            },
            "segments": [
                {
                    "name": ".text",
                    "class": "CODE",
                    "start": "0x140001000",
                    "end": "0x140002000",
                    "permissions": ["read", "execute"],
                    "bitness": 64,
                }
            ],
            "entry_points": [
                {
                    "address": "0x140001000",
                    "name": "entry",
                }
            ],
            "exports": [
                {
                    "ordinal": 1,
                    "address": "0x140001000",
                    "name": "entry",
                    "forwarder": "",
                }
            ],
            "imports": [
                {
                    "module": "KERNEL32",
                    "address": "0x140002000",
                    "name": "ExitProcess",
                    "ordinal": 0,
                }
            ],
            "fixups": [
                {
                    "address": "0x140001020",
                    "type": 1,
                    "description": "fixup",
                }
            ],
            "unwind_regions": [
                {
                    "start": "0x140001000",
                    "end": "0x140001100",
                    "kind": "unwind",
                }
            ],
            "functions": [
                {
                    "address": "0x140001000",
                    "name": "entry",
                }
            ],
            "strings": [
                {
                    "address": "0x140001800",
                    "value": "fixture",
                    "length": 7,
                }
            ],
            "counts": {
                "segments": 1,
                "entry_points": 1,
                "exports": 1,
                "import_modules": 1,
                "imports": 1,
                "functions": 4,
                "strings": 2,
                "fixups": 1,
                "unwind_functions": 1,
                "catch_functions": 0,
            },
            "coverage": {"complete": True, "limit": 200},
        }
    )
    output = adapt_worker_results(
        "program.overview",
        args,
        [raw_result],
        _context(native_container="pe"),
    )
    assert isinstance(output, ProgramOverviewOutput)
    assert output.image.sha256 == _SAMPLE_SHA256
    assert output.image.architecture == "x86_64"
    assert output.image.format == "pe32+"
    assert output.image.image_size == 0x3000
    assert output.counts.functions == 4
    assert output.segments[0].permissions == "r-x"
    assert output.entry_points[0].entity_id is not None
    assert output.exports[0].entity_id is not None
    assert output.fixups[0].fixup_type == 1
    assert output.unwind_regions[0].kind == "unwind"
    assert output.functions[0].name == "entry"
    assert output.strings[0].preview == "fixture"
    assert output.coverage.status == "complete"

    with pytest.raises(StaticAdapterResultError, match="container"):
        adapt_worker_results(
            "program.overview",
            args,
            [raw_result],
            _context(native_container="elf"),
        )

    elf_result = deepcopy(raw_result)
    elf_image = cast(dict[str, object], elf_result["image"])
    elf_image["container"] = "elf"
    elf_output = adapt_worker_results(
        "program.overview",
        args,
        [elf_result],
        _context(native_container="elf"),
    )
    assert isinstance(elf_output, ProgramOverviewOutput)
    assert elf_output.image.format == "elf64"

    unknown_result = deepcopy(raw_result)
    unknown_image = cast(dict[str, object], unknown_result["image"])
    unknown_image["container"] = "unknown"
    unknown_output = adapt_worker_results(
        "program.overview",
        args,
        [unknown_result],
        _context(),
    )
    assert isinstance(unknown_output, ProgramOverviewOutput)
    assert unknown_output.image.format == "unknown"


def test_program_search_uses_one_global_ordered_page_and_reports_exact_advance() -> None:
    args = ProgramSearchInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        domains=["function", "string", "bytes"],
        text_query="ordinary text",
        bytes_query="4142",
        cursor="cursor_abcdef",
        page_size=2,
    )
    requests = build_worker_requests(
        "program.search",
        args,
        offset=2,
        limit_override=1,
    )
    assert len(requests) == 1
    assert requests[0].input == {
        "domains": ["function", "string", "bytes"],
        "text_query": "ordinary text",
        "bytes_query": "4142",
        "case_sensitive": False,
        "offset": 2,
        "limit": 1,
    }
    raw = _raw(
        {
            "domains": ["function", "string", "bytes"],
            "items": [
                {
                    "domain": "bytes",
                    "address": "0x403000",
                    "bytes": "4142",
                }
            ],
            "page": {
                "offset": 2,
                "limit": 1,
                "returned": 1,
                "has_more": True,
                "next_offset": 3,
            },
            "coverage": {
                "complete": False,
                "truncated": True,
                "reasons": ["page_has_more"],
            },
        }
    )
    output = adapt_worker_results(
        "program.search",
        args,
        [raw],
        _context(),
    )
    assert isinstance(output, ProgramSearchOutput)
    assert [match.domain for match in output.matches] == ["bytes"]
    assert output.coverage.truncated is True
    facts = static_page_facts("program.search", args, [raw])
    assert facts is not None
    assert facts.next_offset == 3
    assert static_page_has_more("program.search", args, [raw]) is True
    assert static_page_advance("program.search", args, [raw]) == 1

    invalid = dict(raw)
    invalid["page"] = {
        "offset": 2,
        "limit": 1,
        "returned": 1,
        "has_more": True,
        "next_offset": 4,
    }
    with pytest.raises(StaticAdapterResultError):
        static_page_facts("program.search", args, [invalid])


def test_address_inspect_maps_known_xrefs_and_rejects_runtime_address() -> None:
    args = AddressInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        address=_database("0x401000"),
    )
    output = adapt_worker_results(
        "address.inspect",
        args,
        [
            _raw(
                {
                    "address": "0x401000",
                    "image_rva": "0x1000",
                    "name": "entry",
                    "segment": ".text",
                    "function": {"entry": "0x401000", "name": "entry"},
                    "item": {
                        "is_code": True,
                        "is_data": False,
                        "size": 5,
                        "bytes": "e800000000",
                    },
                    "instruction": {
                        "size": 5,
                        "mnemonic": "call",
                        "text": "call target",
                        "operands": [
                            {
                                "index": 0,
                                "type": 7,
                                "dtype": 9,
                                "text": "target",
                                "value": None,
                                "address": "0x402000",
                            }
                        ],
                    },
                    "xrefs_from": [
                        {"to": "0x402000", "type": 16, "is_code": True},
                        {"to": "0x403000", "type": 99, "is_code": True},
                    ],
                    "xrefs_to": [],
                    "coverage": {"complete": True},
                }
            )
        ],
        _context(),
    )
    assert isinstance(output, AddressInspectOutput)
    assert output.instruction is not None
    assert output.instruction.text == "call target"
    assert output.instruction.operands[0].type == 7
    assert output.instruction.operands[0].value is None
    operand_address = output.instruction.operands[0].address
    assert isinstance(operand_address, DatabaseAddress)
    assert operand_address.ea == "0x402000"
    assert len(output.xrefs) == 1
    assert output.coverage.status == "partial"

    runtime_args = AddressInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        address=RuntimeAddress(
            kind="runtime",
            module_id="module_abcdef",
            va="0x401000",
            stop_id="stop_abcdef",
        ),
    )
    with pytest.raises(StaticAdapterInputError):
        build_worker_requests("address.inspect", runtime_args)
    assert (
        build_worker_requests(
            "address.inspect",
            args,
            limit_override=1,
        )[0].input["limit"]
        == 1
    )


def test_function_entity_round_trip_and_all_raw_backed_views() -> None:
    args = FunctionInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        function=FunctionByAddress(kind="address", address=_database("0x401000")),
        views=[
            "summary",
            "chunks",
            "instructions",
            "pseudocode",
            "ctree_map",
            "blocks",
            "calls",
            "strings",
            "stack",
            "locals",
            "types",
        ],
    )
    output = adapt_worker_results(
        "function.inspect",
        args,
        [
            _raw(
                {
                    "entry": "0x401000",
                    "name": "entry",
                    "size": 32,
                    "flags": 0,
                    "does_return": True,
                    "chunks": [{"start": "0x401000", "end": "0x401020"}],
                    "instructions": [
                        {
                            "address": "0x401000",
                            "size": 5,
                            "mnemonic": "and",
                            "text": "and eax, 0x2a",
                            "operands": [
                                {
                                    "index": 0,
                                    "type": 1,
                                    "dtype": 2,
                                    "text": "eax",
                                    "value": None,
                                    "address": None,
                                },
                                {
                                    "index": 1,
                                    "type": 5,
                                    "dtype": 2,
                                    "text": "0x2a",
                                    "value": "0x2a",
                                    "address": None,
                                },
                            ],
                        }
                    ],
                    "pseudocode": ["target();"],
                    "ctree": [
                        {
                            "item": "expression",
                            "address": "0x401000",
                            "opcode": 57,
                            "text": "target()",
                        }
                    ],
                    "blocks": [
                        {
                            "id": 0,
                            "start": "0x401000",
                            "end": "0x401020",
                            "successors": [],
                            "predecessors": [],
                        }
                    ],
                    "calls": [
                        {
                            "site": "0x401000",
                            "target": "0x402000",
                            "name": "target",
                            "xref_type": 16,
                        }
                    ],
                    "strings": [
                        {
                            "site": "0x401005",
                            "address": "0x403000",
                            "value_hex": "74657374",
                        }
                    ],
                    "lvars": [
                        {
                            "index": 0,
                            "name": "value",
                            "type": "int",
                            "definition_address": "0x401000",
                            "width": 4,
                            "location": "stack",
                        }
                    ],
                    "stack": {
                        "local_size": 16,
                        "saved_register_size": 8,
                        "argument_size": 0,
                        "frame_pointer_delta": 0,
                        "frame_size": 32,
                    },
                    "type": "int __fastcall entry(void)",
                    "page": {
                        "offset": 0,
                        "limit": 50,
                        "returned": 1,
                        "has_more": False,
                        "next_offset": None,
                    },
                    "coverage": {
                        "complete": True,
                        "truncated": False,
                        "reasons": [],
                    },
                }
            )
        ],
        _context(),
    )
    assert isinstance(output, FunctionInspectOutput)
    assert output.instructions[0].operands[1].value == "0x2a"
    assert output.instructions[0].operands[1].address is None
    assert output.ctree_map[0].opcode == 57
    assert output.strings[0].value_hex == "74657374"
    assert output.stack is not None
    assert output.type_view is not None

    entity_args = FunctionInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        function=FunctionByEntity(kind="entity", entity_id=output.entity_id),
    )
    request = build_worker_requests("function.inspect", entity_args)[0]
    assert request.input["address"] == {"space": "database", "ea": "0x401000"}


def test_function_summary_accepts_worker_omission_of_unrequested_views() -> None:
    args = FunctionInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        function=FunctionByAddress(kind="address", address=_database("0x401000")),
    )

    output = adapt_worker_results(
        "function.inspect",
        args,
        [
            _raw(
                {
                    "entry": "0x401000",
                    "name": "renamed_entry",
                    "size": 32,
                    "flags": 0,
                    "does_return": True,
                    "page": {
                        "offset": 0,
                        "limit": 50,
                        "returned": 0,
                        "has_more": False,
                        "next_offset": None,
                    },
                    "coverage": {
                        "complete": True,
                        "truncated": False,
                        "reasons": [],
                    },
                }
            )
        ],
        _context(),
    )

    assert isinstance(output, FunctionInspectOutput)
    assert isinstance(output.start, DatabaseAddress)
    assert isinstance(output.end, DatabaseAddress)
    assert output.name == "renamed_entry"
    assert output.start.ea == "0x401000"
    assert output.end.ea == "0x401020"
    assert output.chunks == []
    assert output.instructions == []


def test_graph_query_uses_one_bounded_multihop_worker_contract() -> None:
    args = GraphQueryInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        graph="call",
        roots=[_database("0x401000")],
        direction="incoming",
        max_depth=2,
        max_nodes=20,
    )
    requests = build_worker_requests("graph.query", args)
    assert [request.operation for request in requests] == ["graph.query"]
    assert requests[0].input == {
        "kind": "call",
        "roots": [{"space": "database", "ea": "0x401000"}],
        "direction": "incoming",
        "max_depth": 2,
        "limit": 20,
    }
    assert (
        build_worker_requests(
            "graph.query",
            args,
            limit_override=3,
        )[0].input["limit"]
        == 3
    )
    graph_hard_limit = args.model_copy(update={"max_nodes": 1_000})
    graph_request = build_worker_requests(
        "graph.query",
        graph_hard_limit,
        limit_override=1_000,
    )[0]
    assert graph_request.input["limit"] == 1_000
    with pytest.raises(StaticAdapterInputError):
        build_worker_requests(
            "graph.query",
            graph_hard_limit,
            limit_override=1_001,
        )
    output = adapt_worker_results(
        "graph.query",
        args,
        [
            _raw(
                {
                    "kind": "call",
                    "direction": "incoming",
                    "max_depth": 2,
                    "nodes": [
                        {
                            "id": "fn:401000",
                            "kind": "function",
                            "address": "0x401000",
                            "label": "first",
                        },
                        {
                            "id": "fn:402000",
                            "kind": "function",
                            "address": "0x402000",
                            "label": "second",
                        },
                        {
                            "id": "fn:403000",
                            "kind": "function",
                            "address": "0x403000",
                            "label": "third",
                        },
                    ],
                    "edges": [
                        {
                            "source": "fn:402000",
                            "target": "fn:401000",
                            "kind": "call",
                            "site": "0x402010",
                        },
                        {
                            "source": "fn:403000",
                            "target": "fn:402000",
                            "kind": "call",
                            "site": "0x403010",
                        },
                    ],
                    "unresolved_indirect_edges": 1,
                    "coverage": {
                        "complete": False,
                        "truncated": False,
                        "reasons": [
                            "unresolved_indirect_calls",
                            "indirect_incoming_edges_unresolvable",
                        ],
                    },
                }
            ),
        ],
        _context(),
    )
    assert isinstance(output, GraphQueryOutput)
    assert len(output.nodes) == 3
    assert len(output.edges) == 2
    assert output.unresolved_indirect_edges == 1
    assert output.coverage.status == "partial"
    assert "unresolved_indirect_calls" in output.coverage.reasons


def test_graph_query_maps_cfg_blocks_without_reinterpreting_worker_traversal() -> None:
    args = GraphQueryInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        graph="cfg",
        roots=[_database("0x401010")],
        direction="both",
        max_depth=3,
        max_nodes=10,
    )
    output = adapt_worker_results(
        "graph.query",
        args,
        [
            _raw(
                {
                    "kind": "cfg",
                    "direction": "both",
                    "max_depth": 3,
                    "nodes": [
                        {
                            "id": "cfg:401000:0",
                            "kind": "basic_block",
                            "address": "0x401000",
                            "label": "entry: block 0",
                            "function": "0x401000",
                            "block_id": 0,
                        },
                        {
                            "id": "cfg:401000:1",
                            "kind": "basic_block",
                            "address": "0x401020",
                            "label": "entry: block 1",
                            "function": "0x401000",
                            "block_id": 1,
                        },
                    ],
                    "edges": [
                        {
                            "source": "cfg:401000:0",
                            "target": "cfg:401000:1",
                            "kind": "flow",
                        }
                    ],
                    "unresolved_indirect_edges": 0,
                    "coverage": {
                        "complete": True,
                        "truncated": False,
                        "reasons": [],
                    },
                }
            )
        ],
        _context(),
    )
    assert isinstance(output, GraphQueryOutput)
    assert [node.kind for node in output.nodes] == ["basic_block", "basic_block"]
    assert len({node.entity_id for node in output.nodes}) == 2
    assert output.edges[0].kind == "flow"
    assert output.coverage.status == "complete"


def test_dataflow_maps_barrier_and_refuses_unproven_must() -> None:
    may_args = DataflowSliceInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        function=FunctionByAddress(kind="address", address=_database("0x401000")),
        seed=SliceAddressSeed(kind="address", address=_database("0x401004")),
        direction="forward",
        semantics="may",
    )
    raw = _raw(
        {
            "function": "0x401000",
            "seed": "0x401004",
            "direction": "forward",
            "mode": "may",
            "instructions": [
                {
                    "index": 0,
                    "block": 0,
                    "address": "0x401000",
                    "opcode": 1,
                    "text": "mov r0, 1",
                    "defs": ["reg:0:8"],
                    "uses": [],
                    "barrier": False,
                },
                {
                    "index": 1,
                    "block": 0,
                    "address": "0x401004",
                    "opcode": 2,
                    "text": "use r0",
                    "defs": [],
                    "uses": ["reg:0:8"],
                    "barrier": True,
                },
            ],
            "unknown_barriers": [
                {
                    "address": "0x401004",
                    "reason": "unknown_call_or_alias_memory",
                }
            ],
            "edges": [
                {
                    "source_index": 0,
                    "target_index": 1,
                    "relation": "defines",
                }
            ],
            "coverage": {
                "complete": False,
                "truncated": False,
                "reasons": ["unknown_call_or_alias_memory"],
                "bounded_to_function": True,
                "microcode_maturity": 7,
            },
        }
    )
    output = adapt_worker_results("dataflow.slice", may_args, [raw], _context())
    assert isinstance(output, DataflowSliceOutput)
    assert output.semantics == "may"
    assert len(output.edges) == 1
    assert output.barriers[0].reason == "unknown_call_or_alias_memory"
    assert (
        build_worker_requests(
            "dataflow.slice",
            may_args,
            limit_override=2,
        )[0].input["limit"]
        == 2
    )
    maximum_args = may_args.model_copy(update={"max_steps": 1_000})
    assert (
        build_worker_requests(
            "dataflow.slice",
            maximum_args,
            limit_override=1_000,
        )[0].input["limit"]
        == 1_000
    )
    with pytest.raises(StaticAdapterInputError):
        build_worker_requests(
            "dataflow.slice",
            maximum_args,
            limit_override=1_001,
        )

    must_args = may_args.model_copy(update={"semantics": "must"})
    with pytest.raises(StaticAdapterCapabilityError):
        adapt_worker_results("dataflow.slice", must_args, [raw], _context())


def test_dataflow_must_preserves_analysis_limit_as_partial_result() -> None:
    args = DataflowSliceInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        function=FunctionByAddress(kind="address", address=_database("0x401000")),
        seed=SliceAddressSeed(kind="address", address=_database("0x401004")),
        direction="backward",
        semantics="must",
        max_steps=1,
    )
    raw = _raw(
        {
            "function": "0x401000",
            "seed": "0x401004",
            "direction": "backward",
            "mode": "must",
            "instructions": [
                {
                    "index": 1,
                    "block": 0,
                    "address": "0x401004",
                    "opcode": 2,
                    "text": "use r0",
                    "defs": [],
                    "uses": ["reg:0:8"],
                    "barrier": None,
                }
            ],
            "unknown_barriers": [{"address": None, "reason": "analysis_limit"}],
            "edges": [],
            "coverage": {
                "complete": False,
                "truncated": True,
                "reasons": ["analysis_limit"],
                "bounded_to_function": True,
                "microcode_maturity": 1,
            },
        }
    )

    output = adapt_worker_results("dataflow.slice", args, [raw], _context())

    assert isinstance(output, DataflowSliceOutput)
    assert output.semantics == "must"
    assert output.edges == []
    assert output.barriers[0].reason == "analysis_limit"
    assert output.coverage.status == "partial"
    assert output.coverage.truncated is True


def test_type_entity_round_trip_preserves_bit_offsets_and_schema_is_narrowed() -> None:
    args = TypeInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        type=TypeByName(kind="name", name="NativeType"),
    )
    output = adapt_worker_results(
        "type.inspect",
        args,
        [
            _raw(
                {
                    "type": {
                        "name": "NativeType",
                        "declaration": "struct NativeType",
                        "size": 8,
                        "is_pointer": False,
                        "is_function": False,
                        "is_struct": True,
                        "is_union": False,
                        "is_enum": False,
                        "is_array": False,
                        "members": [
                            {
                                "index": 0,
                                "name": "flags",
                                "offset_bits": 3,
                                "size_bits": 5,
                                "type": "unsigned int",
                            }
                        ],
                    },
                    "page": {
                        "offset": 0,
                        "limit": 50,
                        "returned": 1,
                        "has_more": False,
                        "next_offset": None,
                    },
                    "coverage": {
                        "complete": True,
                        "truncated": False,
                        "reasons": [],
                    },
                }
            )
        ],
        _context(),
    )
    assert isinstance(output, TypeInspectOutput)
    assert output.fields[0].offset_bits == 3
    entity_args = TypeInspectInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        type=TypeByEntity(kind="entity", entity_id=output.entity_id),
    )
    assert build_worker_requests("type.inspect", entity_args)[0].input == {
        "name": "NativeType",
        "offset": 0,
        "limit": 50,
    }

    with pytest.raises(ValidationError):
        ProgramSearchInput.model_validate(
            {
                "workspace_id": _WORKSPACE_ID,
                "revision": _REVISION,
                "text_query": "mov",
                "domains": ["instruction"],
            }
        )
    with pytest.raises(ValidationError):
        DataflowSliceInput.model_validate(
            {
                "workspace_id": _WORKSPACE_ID,
                "revision": _REVISION,
                "function": {"kind": "address", "address": _database("0x401000")},
                "seed": {"kind": "variable", "entity_id": "entity_variable"},
                "direction": "forward",
                "semantics": "may",
            }
        )


def test_context_mismatch_and_external_storage_are_independent(tmp_path: Path) -> None:
    del tmp_path
    args = ProgramOverviewInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
    )
    wrong = AnalysisContext(
        workspace_id="workspace_other",
        revision=_REVISION,
        sample_sha256=_SAMPLE_SHA256,
    )
    with pytest.raises(StaticAdapterInputError):
        adapt_worker_results("program.overview", args, [{}], wrong)
