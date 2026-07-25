"""使用自有 fixture 验证 IDA 非连续函数块与公共 function.inspect 契约。"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Mapping
from pathlib import Path

import pytest

from ida_re_mcp.domain.address import DatabaseAddress
from ida_re_mcp.domain.tools import (
    FunctionByAddress,
    FunctionInspectInput,
    FunctionInspectOutput,
)
from ida_re_mcp.supervisor.static_adapter import AnalysisContext, adapt_worker_results
from ida_re_mcp.supervisor.workers import WorkerProcess
from ida_re_mcp.worker.ipc import JsonValue


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bootstrap(sample: Path, database: Path, log_root: Path) -> None:
    with WorkerProcess.launch(
        kind="bootstrap",
        log_root=log_root,
        sample=sample,
        connect_timeout_seconds=60,
    ) as worker:
        result = worker.execute(
            "workspace.bootstrap",
            {"staging_path": str(database)},
            timeout_seconds=120,
        )
    assert result["saved"] is True


def _named_function(worker: WorkerProcess, name: str) -> tuple[str, tuple[str, str]]:
    search = worker.execute(
        "program.search",
        {
            "domains": ["function"],
            "text_query": name,
            "bytes_query": None,
            "case_sensitive": False,
            "offset": 0,
            "limit": 20,
        },
        timeout_seconds=30,
    )
    raw_items = search.get("items")
    assert isinstance(raw_items, list)
    addresses: list[str] = []
    for item in raw_items:
        if not isinstance(item, dict) or item.get("name") != name:
            continue
        address = item.get("address")
        assert isinstance(address, str)
        addresses.append(address)
    assert len(addresses) == 1
    address = addresses[0]
    inspected = worker.execute(
        "function.inspect",
        {
            "address": {"space": "database", "ea": address},
            "views": ["chunks"],
            "offset": 0,
            "limit": 20,
        },
        timeout_seconds=30,
    )
    chunks = _chunks(inspected)
    assert len(chunks) == 1
    assert chunks[0][0] == address
    return address, chunks[0]


def _chunks(result: Mapping[str, JsonValue]) -> list[tuple[str, str]]:
    raw_chunks = result.get("chunks")
    assert isinstance(raw_chunks, list)
    chunks: list[tuple[str, str]] = []
    for raw_chunk in raw_chunks:
        assert isinstance(raw_chunk, dict)
        start = raw_chunk.get("start")
        end = raw_chunk.get("end")
        assert isinstance(start, str)
        assert isinstance(end, str)
        assert int(start, 16) < int(end, 16)
        chunks.append((start, end))
    return sorted(chunks, key=lambda chunk: int(chunk[0], 16))


def _public_chunks(result: FunctionInspectOutput) -> list[tuple[str, str]]:
    chunks: list[tuple[str, str]] = []
    for chunk in result.chunks:
        assert isinstance(chunk.start, DatabaseAddress)
        assert isinstance(chunk.end, DatabaseAddress)
        chunks.append((chunk.start.ea, chunk.end.ea))
    return sorted(chunks, key=lambda item: int(item[0], 16))


@pytest.mark.ida
def test_function_inspect_preserves_cold_multichunk_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    monkeypatch.setenv("IDADIR", ida_environment["IDADIR"])
    sample = fixture_directory / "native_pe_x64.dll"
    fixture_source = fixture_directory.parent / "src" / "annotate_multichunk.py"
    base_revision = tmp_path / "base.i64"
    annotated_revision = tmp_path / "annotated.i64"
    log_root = tmp_path / "logs"
    _bootstrap(sample, base_revision, log_root)
    base_hash = _sha256(base_revision)

    with WorkerProcess.launch(
        kind="analysis",
        log_root=log_root,
        checkout=base_revision,
        revision="revision_before_multichunk",
        connect_timeout_seconds=60,
    ) as worker:
        entry_address, entry_bounds = _named_function(
            worker,
            "fixture_multichunk_entry",
        )
        _, gap_bounds = _named_function(worker, "fixture_multichunk_gap")
        tail_address, tail_bounds = _named_function(
            worker,
            "fixture_multichunk_tail",
        )

    assert int(entry_bounds[1], 16) <= int(gap_bounds[0], 16)
    assert int(gap_bounds[1], 16) <= int(tail_bounds[0], 16)
    assert int(entry_bounds[1], 16) < int(tail_bounds[0], 16)

    shutil.copy2(base_revision, annotated_revision)
    with WorkerProcess.launch(
        kind="expert",
        log_root=log_root,
        checkout=annotated_revision,
        connect_timeout_seconds=60,
    ) as worker:
        annotation = worker.execute(
            "expert.execute",
            {
                "staging_path": str(annotated_revision),
                "code": fixture_source.read_text(encoding="utf-8"),
            },
            timeout_seconds=30,
        )
    assert annotation["saved"] is True
    assert annotation["cold_verification_required"] is True
    assert _sha256(base_revision) == base_hash
    assert _sha256(annotated_revision) != base_hash

    with WorkerProcess.launch(
        kind="analysis",
        log_root=log_root,
        checkout=annotated_revision,
        revision="revision_multichunk",
        connect_timeout_seconds=60,
    ) as verifier:
        raw = verifier.execute(
            "function.inspect",
            {
                "address": {"space": "database", "ea": entry_address},
                "views": ["chunks"],
                "offset": 0,
                "limit": 20,
            },
            timeout_seconds=30,
        )
        inspected_from_tail = verifier.execute(
            "function.inspect",
            {
                "address": {"space": "database", "ea": tail_address},
                "views": ["chunks"],
                "offset": 0,
                "limit": 20,
            },
            timeout_seconds=30,
        )

    expected_chunks = sorted(
        [entry_bounds, tail_bounds],
        key=lambda chunk: int(chunk[0], 16),
    )
    assert len(expected_chunks) == 2
    assert _chunks(raw) == expected_chunks
    assert _chunks(inspected_from_tail) == expected_chunks
    assert raw["entry"] == entry_address
    assert inspected_from_tail["entry"] == entry_address
    assert raw["size"] == sum(int(end, 16) - int(start, 16) for start, end in expected_chunks)

    context = AnalysisContext(
        workspace_id="workspace_multichunk",
        revision="revision_multichunk",
        sample_sha256=_sha256(sample),
    )
    public = adapt_worker_results(
        "function.inspect",
        FunctionInspectInput(
            workspace_id=context.workspace_id,
            revision=context.revision,
            function=FunctionByAddress(
                kind="address",
                address=DatabaseAddress(kind="database", ea=entry_address),
            ),
            views=["chunks"],
            page_size=20,
        ),
        [raw],
        context,
    )
    assert isinstance(public, FunctionInspectOutput)
    assert isinstance(public.start, DatabaseAddress)
    assert isinstance(public.end, DatabaseAddress)
    assert public.start.ea == entry_address
    assert public.end.ea == max(
        (end for _, end in expected_chunks),
        key=lambda address: int(address, 16),
    )
    assert len(public.chunks) == 2
    assert _public_chunks(public) == expected_chunks
