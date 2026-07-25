# pyright: reportPrivateUsage=false
"""验证无需 IDA runtime 的确定性发现与有界图算法。"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

from ida_re_mcp.worker._ida import IdaModules
from ida_re_mcp.worker.analysis import AnalysisWorker, _GraphEdge, _GraphNode


class _StringItem:
    def __init__(self, address: int, value: str) -> None:
        self.ea = address
        self.length = len(value)
        self.strtype = 0
        self._value = value

    def __str__(self) -> str:
        return self._value


def _search_api() -> IdaModules:
    bad_address = (1 << 64) - 1

    def function_name(address: int) -> str:
        return {0x10: "func_a", 0x20: "func_b"}[address]

    def nlist_name(_index: int) -> str:
        return ""

    def nlist_address(_index: int) -> int:
        return 0

    def find_bytes(
        pattern: bytes,
        start: int,
        end: int,
        *,
        flags: int,
    ) -> int:
        del end, flags
        return 0x30 if pattern == b"AB" and start <= 0x30 else bad_address

    return cast(
        IdaModules,
        SimpleNamespace(
            idautils=SimpleNamespace(
                Functions=lambda: [0x10, 0x20],
                Strings=lambda: [
                    _StringItem(0x40, "first"),
                    _StringItem(0x50, "second"),
                ],
            ),
            ida_funcs=SimpleNamespace(get_func_name=function_name),
            ida_name=SimpleNamespace(
                get_nlist_size=lambda: 0,
                get_nlist_name=nlist_name,
                get_nlist_ea=nlist_address,
            ),
            ida_ida=SimpleNamespace(
                inf_get_min_ea=lambda: 0,
                inf_get_max_ea=lambda: 0x100,
            ),
            ida_idaapi=SimpleNamespace(BADADDR=bad_address),
            ida_bytes=SimpleNamespace(
                BIN_SEARCH_FORWARD=1,
                BIN_SEARCH_NOSHOW=2,
                find_bytes=find_bytes,
            ),
        ),
    )


def _worker(tmp_path: Path) -> AnalysisWorker:
    checkout = tmp_path / "fixture.i64"
    checkout.write_bytes(b"fixture")
    return AnalysisWorker(checkout)


def test_program_search_enumerates_in_stable_domain_and_address_order(
    tmp_path: Path,
) -> None:
    worker = _worker(tmp_path)
    api = _search_api()
    first = worker._program_search(
        api,
        {
            "domains": ["function", "string"],
            "text_query": "",
            "bytes_query": None,
            "case_sensitive": False,
            "offset": 0,
            "limit": 2,
        },
    )
    assert first["items"] == [
        {
            "domain": "function",
            "address": "0x10",
            "name": "func_a",
        },
        {
            "domain": "function",
            "address": "0x20",
            "name": "func_b",
        },
    ]
    assert first["page"] == {
        "offset": 0,
        "limit": 2,
        "returned": 2,
        "has_more": True,
        "next_offset": 2,
    }
    second = worker._program_search(
        api,
        {
            "domains": ["function", "string"],
            "text_query": "",
            "bytes_query": None,
            "case_sensitive": False,
            "offset": 2,
            "limit": 2,
        },
    )
    items = second["items"]
    assert isinstance(items, list)
    typed_items = cast(list[dict[str, object]], items)
    assert [item["address"] for item in typed_items] == ["0x40", "0x50"]


def test_program_search_keeps_text_and_byte_queries_independent(tmp_path: Path) -> None:
    result = _worker(tmp_path)._program_search(
        _search_api(),
        {
            "domains": ["function", "bytes"],
            "text_query": "func_a",
            "bytes_query": "4142",
            "case_sensitive": False,
            "offset": 0,
            "limit": 10,
        },
    )
    items = result["items"]
    assert isinstance(items, list)
    typed_items = cast(list[dict[str, object]], items)
    assert [item["domain"] for item in typed_items] == ["function", "bytes"]


def test_graph_traversal_is_deterministic_and_never_exceeds_node_budget() -> None:
    nodes = {
        key: _GraphNode(
            id=key,
            kind="function",
            address=address,
            label=key,
        )
        for key, address in (("a", 0x10), ("b", 0x20), ("c", 0x30))
    }
    neighbors = {
        "a": [(nodes["b"], _GraphEdge("a", "b", "call", 0x11))],
        "b": [(nodes["c"], _GraphEdge("b", "c", "call", 0x21))],
        "c": [],
    }

    def load(node_id: str) -> tuple[list[tuple[_GraphNode, _GraphEdge]], int]:
        return neighbors[node_id], 1 if node_id == "a" else 0

    first = AnalysisWorker._bounded_graph_traversal(
        [nodes["a"]],
        load,
        max_depth=2,
        limit=2,
        edge_limit=8,
    )
    second = AnalysisWorker._bounded_graph_traversal(
        [nodes["a"]],
        load,
        max_depth=2,
        limit=2,
        edge_limit=8,
    )
    assert first == second
    selected, edges, unresolved, node_limit, edge_limit = first
    assert [node.id for node in selected] == ["a", "b"]
    assert [(edge.source, edge.target) for edge in edges] == [("a", "b")]
    assert unresolved == 1
    assert node_limit is True
    assert edge_limit is False
