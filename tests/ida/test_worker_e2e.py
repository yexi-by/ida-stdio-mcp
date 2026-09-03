"""使用真实 IDALib 和 Windows debugger backend 验证 worker 链路。"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from ida_re_mcp.domain.address import DatabaseAddress
from ida_re_mcp.domain.tools import (
    AddressInspectInput,
    AddressInspectOutput,
    FunctionByAddress,
    FunctionInspectInput,
    FunctionInspectOutput,
    GraphQueryInput,
    GraphQueryOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
)
from ida_re_mcp.supervisor.static_adapter import (
    AnalysisContext,
    adapt_worker_results,
)
from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.ipc import IpcEndpoint, WorkerClient
from ida_re_mcp.worker.ipc import JsonValue as IpcJsonValue


@dataclass(slots=True)
class _RunningWorker:
    process: subprocess.Popen[bytes]
    client: WorkerClient

    def close(self) -> None:
        self.client.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
            pytest.fail("worker 在 IPC 关闭后未退出")
        if self.process.returncode != 0:
            stderr = (self.process.stderr.read() if self.process.stderr else b"").decode(
                "utf-8", errors="replace"
            )
            pytest.fail(f"worker 异常退出: {stderr}")


def _start_worker(
    tmp_path: Path,
    environment: dict[str, str],
    kind: str,
    *,
    checkout: Path | None = None,
    sample: Path | None = None,
) -> _RunningWorker:
    endpoint = IpcEndpoint.create(tmp_path)
    secret_name = f"IDA_RE_MCP_TEST_AUTH_{uuid.uuid4().hex.upper()}"
    child_environment = environment.copy()
    child_environment[secret_name] = base64.b64encode(endpoint.authkey).decode("ascii")
    command = [
        sys.executable,
        "-m",
        "ida_re_mcp.worker",
        "serve",
        "--kind",
        kind,
        "--family",
        endpoint.family,
        "--address",
        endpoint.address,
        "--authkey-env",
        secret_name,
    ]
    if checkout is not None:
        command.extend(("--checkout", str(checkout)))
    if sample is not None:
        command.extend(("--sample", str(sample)))
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_environment,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    client = WorkerClient(endpoint)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = (process.stderr.read() if process.stderr else b"").decode(
                "utf-8", errors="replace"
            )
            pytest.fail(f"worker 启动失败: {stderr}")
        try:
            client.connect()
            return _RunningWorker(process, client)
        except (OSError, EOFError):
            time.sleep(0.05)
    process.terminate()
    process.wait(timeout=10)
    pytest.fail("worker IPC 在 60 秒内未就绪")


def _bootstrap(
    tmp_path: Path,
    environment: dict[str, str],
    sample: Path,
) -> Path:
    staging = tmp_path / f"{sample.stem}.i64"
    worker = _start_worker(tmp_path, environment, "bootstrap", sample=sample)
    try:
        result = worker.client.execute(
            "workspace.bootstrap",
            {"staging_path": str(staging)},
        )
        assert result["saved"] is True
        assert result["cold_verification_required"] is True
        assert result["input_sha256"] == _sha256(sample)
        assert result["staging_sha256"] == _sha256(staging)
    finally:
        worker.close()
    return staging


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


@pytest.mark.ida
def test_runtime_probe_is_headless_and_current(
    ida_environment: dict[str, str],
) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "ida_re_mcp.worker", "probe"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env=ida_environment,
        timeout=30,
    )
    result = json.loads(completed.stdout)
    assert result["available"] is True
    assert result["headless"] is True
    assert result["python_ok"] is True
    assert result["ida_ok"] is True
    assert result["ida_kernel_version"] == "9.3"


@pytest.mark.ida
@pytest.mark.parametrize(
    ("fixture_name", "architecture", "bitness"),
    [
        ("native_pe_x86.dll", "x86", 32),
        ("native_pe_x64.dll", "x86_64", 64),
    ],
)
def test_bootstrap_and_static_analysis_leave_checkout_unchanged(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
    fixture_name: str,
    architecture: str,
    bitness: int,
) -> None:
    sample = fixture_directory / fixture_name
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    before = _sha256(checkout)
    worker = _start_worker(tmp_path, ida_environment, "analysis", checkout=checkout)
    try:
        overview = worker.client.execute("program.overview", {"limit": 100})
        image = overview["image"]
        assert isinstance(image, dict)
        assert image["bitness"] == bitness
        assert image["architecture"] == architecture
        assert image["container"] == "pe"
        assert isinstance(image["image_size"], int)
        assert image["image_size"] > 0  # type: ignore[operator]
        assert overview["counts"]["functions"] > 0  # type: ignore[index,operator]
        pe_coverage = overview["coverage"]
        assert isinstance(pe_coverage, dict)
        pe_reasons = pe_coverage["reasons"]
        assert isinstance(pe_reasons, list)
        assert "unwind_unsupported_for_elf_eh_frame" not in pe_reasons
        function = worker.client.execute(
            "function.inspect",
            {
                "address": {"space": "image", "rva": "0x1000"},
                "views": ["chunks", "disassembly", "blocks", "calls", "types"],
                "limit": 100,
            },
        )
        assert function["entry"]
        assert function["instructions"]  # type: ignore[index]
        assert function["blocks"]  # type: ignore[index]
    finally:
        worker.close()
    assert _sha256(checkout) == before


@pytest.mark.ida
@pytest.mark.parametrize(
    ("fixture_name", "architecture", "bitness"),
    [
        ("native_elf_x86.so", "x86", 32),
        ("native_elf_x64.so", "x86_64", 64),
        ("native_elf_armv7.so", "arm", 32),
        ("native_elf_arm64.so", "aarch64", 64),
    ],
)
def test_overview_normalizes_supported_elf_architectures(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
    fixture_name: str,
    architecture: str,
    bitness: int,
) -> None:
    sample = fixture_directory / fixture_name
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    worker = _start_worker(tmp_path, ida_environment, "analysis", checkout=checkout)
    try:
        overview = worker.client.execute("program.overview", {"limit": 100})
        image = overview["image"]
        assert isinstance(image, dict)
        assert image["architecture"] == architecture
        assert image["bitness"] == bitness
        assert image["container"] == "elf"
        imagebase = image["imagebase"]
        maximum = image["maximum_address"]
        image_size = image["image_size"]
        assert isinstance(imagebase, str)
        assert isinstance(maximum, str)
        assert isinstance(image_size, int)
        assert image_size == int(maximum, 16) - int(imagebase, 16)
        assert image_size > 0
        # 请求 unwind 时 ELF 必须显式降级, 不得以零结果谎报 complete.
        elf_coverage = overview["coverage"]
        assert isinstance(elf_coverage, dict)
        assert elf_coverage["complete"] is False
        elf_reasons = elf_coverage["reasons"]
        assert isinstance(elf_reasons, list)
        assert "unwind_unsupported_for_elf_eh_frame" in elf_reasons
    finally:
        worker.close()


@pytest.mark.ida
def test_static_pagination_and_microcode_dataflow_are_observable(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    sample = fixture_directory / "native_pe_x64.dll"
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    worker = _start_worker(tmp_path, ida_environment, "analysis", checkout=checkout)
    try:
        first_names = worker.client.execute(
            "program.search",
            {
                "domains": ["function"],
                "text_query": "fixture_",
                "bytes_query": None,
                "case_sensitive": False,
                "offset": 0,
                "limit": 1,
            },
        )
        first_page = first_names["page"]
        assert isinstance(first_page, dict)
        assert first_page["has_more"] is True
        next_offset = first_page["next_offset"]
        assert isinstance(next_offset, int)
        second_names = worker.client.execute(
            "program.search",
            {
                "domains": ["function"],
                "text_query": "fixture_",
                "bytes_query": None,
                "case_sensitive": False,
                "offset": next_offset,
                "limit": 1,
            },
        )
        first_items = first_names["items"]
        second_items = second_names["items"]
        assert isinstance(first_items, list)
        assert isinstance(second_items, list)
        assert first_items and second_items and first_items != second_items

        enumeration_request: dict[str, IpcJsonValue] = {
            "domains": ["function", "string"],
            "text_query": "",
            "bytes_query": None,
            "case_sensitive": False,
            "offset": 0,
            "limit": 200,
        }
        enumeration = worker.client.execute("program.search", enumeration_request)
        repeated_enumeration = worker.client.execute("program.search", enumeration_request)
        enumerated_items = enumeration["items"]
        assert isinstance(enumerated_items, list)
        assert enumerated_items == repeated_enumeration["items"]
        enumerated_domains: list[str] = []
        for item in enumerated_items:
            assert isinstance(item, dict)
            domain = item.get("domain")
            assert isinstance(domain, str)
            enumerated_domains.append(domain)
        assert "function" in enumerated_domains
        assert "string" in enumerated_domains
        assert enumerated_domains == sorted(
            enumerated_domains,
            key={"function": 0, "string": 1}.__getitem__,
        )
        public_context = AnalysisContext(
            workspace_id="workspace_operand_e2e",
            revision="revision_operand_e2e",
            sample_sha256=_sha256(sample),
        )
        public_enumeration = adapt_worker_results(
            "program.search",
            ProgramSearchInput(
                workspace_id=public_context.workspace_id,
                revision=public_context.revision,
                domains=["function", "string"],
                text_query="",
                page_size=200,
            ),
            [enumeration],
            public_context,
        )
        assert isinstance(public_enumeration, ProgramSearchOutput)
        assert any(
            match.domain == "function" and match.entity_id is not None
            for match in public_enumeration.matches
        )

        mixed_search = worker.client.execute(
            "program.search",
            {
                "domains": ["function", "bytes"],
                "text_query": "fixture_validate",
                "bytes_query": "666978747572653a206163636570746564",
                "case_sensitive": False,
                "offset": 0,
                "limit": 20,
            },
        )
        mixed_items = mixed_search["items"]
        assert isinstance(mixed_items, list)
        mixed_domains: set[str] = set()
        for item in mixed_items:
            assert isinstance(item, dict)
            domain = item.get("domain")
            assert isinstance(domain, str)
            mixed_domains.add(domain)
        assert mixed_domains == {
            "function",
            "bytes",
        }

        named_functions = worker.client.execute(
            "program.search",
            {
                "domains": ["function"],
                "text_query": "fixture_validate",
                "bytes_query": None,
                "case_sensitive": False,
                "offset": 0,
                "limit": 20,
            },
        )
        matches = named_functions["items"]
        assert isinstance(matches, list)
        validate_match: dict[str, IpcJsonValue] | None = None
        for item in matches:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if isinstance(name, str) and name.endswith("fixture_validate"):
                validate_match = item
                break
        assert validate_match is not None
        function_address = validate_match["address"]
        assert isinstance(function_address, str)

        call_graph = worker.client.execute(
            "graph.query",
            {
                "kind": "call",
                "roots": [{"space": "database", "ea": function_address}],
                "direction": "outgoing",
                "max_depth": 2,
                "limit": 200,
            },
        )
        call_nodes = call_graph["nodes"]
        call_edges = call_graph["edges"]
        assert isinstance(call_nodes, list)
        assert isinstance(call_edges, list)
        assert len(call_nodes) >= 3
        assert len(call_edges) >= 2
        unresolved = call_graph["unresolved_indirect_edges"]
        assert isinstance(unresolved, int)
        assert unresolved >= 1, call_graph
        call_coverage = call_graph["coverage"]
        assert isinstance(call_coverage, dict)
        assert call_coverage["complete"] is False
        call_reasons = call_coverage["reasons"]
        assert isinstance(call_reasons, list)
        assert "unresolved_indirect_calls" in call_reasons
        public_call_graph = adapt_worker_results(
            "graph.query",
            GraphQueryInput(
                workspace_id=public_context.workspace_id,
                revision=public_context.revision,
                graph="call",
                roots=[DatabaseAddress(kind="database", ea=function_address)],
                direction="outgoing",
                max_depth=2,
                max_nodes=200,
            ),
            [call_graph],
            public_context,
        )
        assert isinstance(public_call_graph, GraphQueryOutput)
        assert public_call_graph.unresolved_indirect_edges == unresolved
        assert public_call_graph.coverage.status == "partial"

        first_call = call_edges[0]
        assert isinstance(first_call, dict)
        target_id = first_call["target"]
        assert isinstance(target_id, str)
        target_node = next(
            node for node in call_nodes if isinstance(node, dict) and node.get("id") == target_id
        )
        target_address = target_node["address"]
        assert isinstance(target_address, str)
        incoming_graph = worker.client.execute(
            "graph.query",
            {
                "kind": "call",
                "roots": [{"space": "database", "ea": target_address}],
                "direction": "incoming",
                "max_depth": 2,
                "limit": 200,
            },
        )
        incoming_edges = incoming_graph["edges"]
        assert isinstance(incoming_edges, list)
        root_node = call_nodes[0]
        assert isinstance(root_node, dict)
        root_node_id = root_node["id"]
        assert isinstance(root_node_id, str)
        assert any(
            isinstance(edge, dict) and edge.get("source") == root_node_id for edge in incoming_edges
        )
        incoming_coverage = incoming_graph["coverage"]
        assert isinstance(incoming_coverage, dict)
        incoming_reasons = incoming_coverage["reasons"]
        assert isinstance(incoming_reasons, list)
        assert "indirect_incoming_edges_unresolvable" in incoming_reasons

        cfg_graph = worker.client.execute(
            "graph.query",
            {
                "kind": "cfg",
                "roots": [{"space": "database", "ea": function_address}],
                "direction": "outgoing",
                "max_depth": 3,
                "limit": 200,
            },
        )
        cfg_nodes = cfg_graph["nodes"]
        cfg_edges = cfg_graph["edges"]
        assert isinstance(cfg_nodes, list)
        assert isinstance(cfg_edges, list)
        assert len(cfg_nodes) >= 2
        assert cfg_edges

        xref_graph = worker.client.execute(
            "graph.query",
            {
                "kind": "xref",
                "roots": [{"space": "database", "ea": function_address}],
                "direction": "both",
                "max_depth": 2,
                "limit": 200,
            },
        )
        xref_nodes = xref_graph["nodes"]
        xref_edges = xref_graph["edges"]
        assert isinstance(xref_nodes, list)
        assert isinstance(xref_edges, list)
        assert len(xref_nodes) >= 2
        assert xref_edges

        first_instructions = worker.client.execute(
            "function.inspect",
            {
                "address": {"space": "database", "ea": function_address},
                "views": ["disassembly"],
                "offset": 0,
                "limit": 3,
            },
        )
        instruction_page = first_instructions["page"]
        assert isinstance(instruction_page, dict)
        assert instruction_page["has_more"] is True
        second_offset = instruction_page["next_offset"]
        assert isinstance(second_offset, int)
        second_instructions = worker.client.execute(
            "function.inspect",
            {
                "address": {"space": "database", "ea": function_address},
                "views": ["disassembly"],
                "offset": second_offset,
                "limit": 3,
            },
        )
        first_rows = first_instructions["instructions"]
        second_rows = second_instructions["instructions"]
        assert isinstance(first_rows, list)
        assert isinstance(second_rows, list)
        first_addresses: set[str] = set()
        second_addresses: set[str] = set()
        for row in first_rows:
            if isinstance(row, dict):
                address = row.get("address")
                if isinstance(address, str):
                    first_addresses.add(address)
        for row in second_rows:
            if isinstance(row, dict):
                address = row.get("address")
                if isinstance(address, str):
                    second_addresses.add(address)
        assert first_addresses.isdisjoint(second_addresses)

        all_instructions = worker.client.execute(
            "function.inspect",
            {
                "address": {"space": "database", "ea": function_address},
                "views": ["chunks", "disassembly"],
                "offset": 0,
                "limit": 200,
            },
        )
        raw_rows = all_instructions["instructions"]
        assert isinstance(raw_rows, list)
        public_function = adapt_worker_results(
            "function.inspect",
            FunctionInspectInput(
                workspace_id=public_context.workspace_id,
                revision=public_context.revision,
                function=FunctionByAddress(
                    kind="address",
                    address=DatabaseAddress(kind="database", ea=function_address),
                ),
                views=["chunks", "instructions"],
                page_size=200,
            ),
            [all_instructions],
            public_context,
        )
        assert isinstance(public_function, FunctionInspectOutput)
        immediate_instruction_address: DatabaseAddress | None = None
        reference_instruction_address: DatabaseAddress | None = None
        immediate_value: str | None = None
        reference_address: DatabaseAddress | None = None
        for instruction in public_function.instructions:
            assert instruction.operands == sorted(
                instruction.operands,
                key=lambda operand: operand.index,
            )
            for operand in instruction.operands:
                assert isinstance(operand.type, int)
                assert isinstance(operand.dtype, int)
                assert isinstance(operand.text, str)
                if operand.type == 5 and operand.value is not None:
                    assert operand.address is None
                    assert isinstance(instruction.address, DatabaseAddress)
                    immediate_instruction_address = instruction.address
                    immediate_value = operand.value
                if operand.type in {2, 6, 7} and isinstance(
                    operand.address,
                    DatabaseAddress,
                ):
                    assert operand.value is None
                    assert isinstance(instruction.address, DatabaseAddress)
                    reference_instruction_address = instruction.address
                    reference_address = operand.address
        assert immediate_instruction_address is not None
        assert immediate_value is not None
        assert int(immediate_value, 16) <= 0xFFFF_FFFF_FFFF_FFFF
        assert reference_instruction_address is not None
        assert reference_address is not None
        assert int(reference_address.ea, 16) <= 0xFFFF_FFFF_FFFF_FFFF

        for instruction_address in (
            immediate_instruction_address,
            reference_instruction_address,
        ):
            raw_address = worker.client.execute(
                "address.inspect",
                {
                    "address": {
                        "space": "database",
                        "ea": instruction_address.ea,
                    },
                    "byte_count": 16,
                    "limit": 50,
                },
            )
            public_address = adapt_worker_results(
                "address.inspect",
                AddressInspectInput(
                    workspace_id=public_context.workspace_id,
                    revision=public_context.revision,
                    address=instruction_address,
                    include=["instruction"],
                    byte_count=16,
                ),
                [raw_address],
                public_context,
            )
            assert isinstance(public_address, AddressInspectOutput)
            assert public_address.instruction is not None
            matching_function_instruction = next(
                instruction
                for instruction in public_function.instructions
                if instruction.address == instruction_address
            )
            assert public_address.instruction.operands == matching_function_instruction.operands

        seed_addresses = [
            row["address"]
            for row in raw_rows
            if isinstance(row, dict) and isinstance(row.get("address"), str)
        ]
        may_edge_observed = False
        unknown_barrier_observed = False
        rendered_microcode_observed = False
        for seed_address in seed_addresses:
            try:
                may = worker.client.execute(
                    "dataflow.slice",
                    {
                        "address": {"space": "database", "ea": function_address},
                        "seed": {"space": "database", "ea": seed_address},
                        "direction": "backward",
                        "semantics": "may",
                        "limit": 128,
                    },
                )
            except WorkerError as error:
                if error.code == "slice_seed_not_found":
                    continue
                pytest.fail(f"dataflow MAY 失败: {error.code}: {error.details}")
            edges = may["edges"]
            barriers = may["unknown_barriers"]
            assert isinstance(edges, list)
            assert isinstance(barriers, list)
            may_edge_observed |= bool(edges)
            microcode = may["instructions"]
            assert isinstance(microcode, list)
            for instruction in microcode:
                if not isinstance(instruction, dict):
                    continue
                text = instruction.get("text")
                if isinstance(text, str):
                    assert "<ida_hexrays." not in text
                    rendered_microcode_observed |= bool(text)
            unknown_barrier_observed |= any(
                isinstance(barrier, dict)
                and barrier.get("reason") in {"unknown_call", "alias_ambiguity"}
                for barrier in barriers
            )
            if may_edge_observed and unknown_barrier_observed:
                break
        assert may_edge_observed
        assert unknown_barrier_observed
        assert rendered_microcode_observed

        dataflow_functions = worker.client.execute(
            "program.search",
            {
                "domains": ["function"],
                "text_query": "fixture_dataflow_chain",
                "bytes_query": None,
                "case_sensitive": False,
                "offset": 0,
                "limit": 20,
            },
        )
        raw_dataflow_matches = dataflow_functions["items"]
        assert isinstance(raw_dataflow_matches, list)
        dataflow_address: str | None = None
        for item in raw_dataflow_matches:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            address = item.get("address")
            if (
                isinstance(name, str)
                and name.endswith("fixture_dataflow_chain")
                and isinstance(address, str)
            ):
                dataflow_address = address
                break
        assert dataflow_address is not None

        candidate_functions = [dataflow_address, function_address]
        discovered_functions = {dataflow_address, function_address}
        cursor = 0
        while cursor < len(candidate_functions) and len(candidate_functions) < 16:
            candidate = candidate_functions[cursor]
            cursor += 1
            inspected = worker.client.execute(
                "function.inspect",
                {
                    "address": {"space": "database", "ea": candidate},
                    "views": ["calls"],
                    "offset": 0,
                    "limit": 200,
                },
            )
            raw_calls = inspected["calls"]
            assert isinstance(raw_calls, list)
            if candidate == function_address:
                assert raw_calls
            for call in raw_calls:
                if not isinstance(call, dict):
                    continue
                if candidate == function_address:
                    assert call.get("xref_type") in {16, 17}
                target = call.get("target")
                if not isinstance(target, str) or target in discovered_functions:
                    continue
                if candidate == function_address:
                    assert target != function_address
                discovered_functions.add(target)
                candidate_functions.append(target)

        must_edge_observed = False
        must_forward_edge_observed = False
        must_failures: list[tuple[str, str, object]] = []
        for candidate in candidate_functions:
            inspected = worker.client.execute(
                "function.inspect",
                {
                    "address": {"space": "database", "ea": candidate},
                    "views": ["disassembly"],
                    "offset": 0,
                    "limit": 200,
                },
            )
            rows = inspected["instructions"]
            assert isinstance(rows, list)
            candidate_seeds: list[str] = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                candidate_seed = row.get("address")
                if isinstance(candidate_seed, str):
                    candidate_seeds.append(candidate_seed)
            for seed_address in candidate_seeds:
                try:
                    must = worker.client.execute(
                        "dataflow.slice",
                        {
                            "address": {"space": "database", "ea": candidate},
                            "seed": {"space": "database", "ea": seed_address},
                            "direction": "backward",
                            "semantics": "must",
                            "limit": 128,
                        },
                    )
                except WorkerError as error:
                    if error.code not in {
                        "capability_unavailable",
                        "slice_seed_not_found",
                    }:
                        raise
                    must_failures.append((candidate, seed_address, error.details))
                else:
                    must_edges = must["edges"]
                    assert isinstance(must_edges, list)
                    must_edge_observed |= bool(must_edges)
                    if not must_edges:
                        continue
                    first_edge = must_edges[0]
                    must_instructions = must["instructions"]
                    assert isinstance(first_edge, dict)
                    assert isinstance(must_instructions, list)
                    source_index = first_edge.get("source_index")
                    target_index = first_edge.get("target_index")
                    source_address = next(
                        (
                            instruction.get("address")
                            for instruction in must_instructions
                            if isinstance(instruction, dict)
                            and instruction.get("index") == source_index
                        ),
                        None,
                    )
                    assert isinstance(source_address, str)
                    forward = worker.client.execute(
                        "dataflow.slice",
                        {
                            "address": {"space": "database", "ea": candidate},
                            "seed": {"space": "database", "ea": source_address},
                            "direction": "forward",
                            "semantics": "must",
                            "limit": 128,
                        },
                    )
                    forward_edges = forward["edges"]
                    assert isinstance(forward_edges, list)
                    must_forward_edge_observed |= any(
                        isinstance(edge, dict)
                        and edge.get("source_index") == source_index
                        and edge.get("target_index") == target_index
                        for edge in forward_edges
                    )
            if must_edge_observed:
                break
        assert must_edge_observed, must_failures[:10]
        assert must_forward_edge_observed
    finally:
        worker.close()


@pytest.mark.ida
def test_mutation_and_il2cpp_publish_only_the_staging_database(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    sample = fixture_directory / "il2cpp_pe_x64.dll"
    base_revision = _bootstrap(tmp_path, ida_environment, sample)
    base_hash = _sha256(base_revision)
    staging = tmp_path / "mutation.i64"
    shutil.copy2(base_revision, staging)
    bundle_path = fixture_directory.parent / "src" / "il2cpp_bundle_example.ndjson"
    metadata = fixture_directory / "il2cpp_metadata_fingerprint.bin"
    metadata_sha256 = _sha256(metadata)
    metadata_size = metadata.stat().st_size

    worker = _start_worker(tmp_path, ida_environment, "mutation", checkout=staging)
    try:
        result = worker.client.execute(
            "mutation.apply",
            {
                "staging_path": str(staging),
                "operations": [
                    {
                        "kind": "rename",
                        "address": {"space": "image", "rva": "0x1020"},
                        "name": "ida_re_overload",
                    },
                    {
                        "kind": "comment",
                        "address": {"space": "image", "rva": "0x1020"},
                        "text": "current mutation E2E",
                        "repeatable": False,
                    },
                    {
                        "kind": "patch",
                        "address": {"space": "image", "rva": "0x1000"},
                        "bytes_hex": "b9",
                        "expected_bytes_hex": "b8",
                    },
                    {
                        "kind": "import_il2cpp_bundle",
                        "path": str(bundle_path),
                        "expected_native": {
                            "sha256": _sha256(sample),
                            "size": sample.stat().st_size,
                            "image_size": 0x5000,
                            "architecture": "x86_64",
                            "abi": "msvc-x64",
                            "pointer_width": 64,
                            "endianness": "little",
                        },
                        "expected_metadata": {
                            "sha256": metadata_sha256,
                            "size": metadata_size,
                        },
                        "type_resolutions": {},
                    },
                ],
            },
        )
        assert result["saved"] is True
        assert result["cold_verification_required"] is True
        assert result["staging_sha256"] == _sha256(staging)
    finally:
        worker.close()

    assert _sha256(base_revision) == base_hash
    assert _sha256(staging) != base_hash
    verifier = _start_worker(tmp_path, ida_environment, "analysis", checkout=staging)
    try:
        address = verifier.client.execute(
            "address.inspect",
            {
                "address": {"space": "image", "rva": "0x1000"},
                "byte_count": 1,
            },
        )
        assert address["item"]["bytes"] == "b9"  # type: ignore[index]
        renamed = verifier.client.execute(
            "address.inspect",
            {
                "address": {"space": "image", "rva": "0x1020"},
                "byte_count": 1,
            },
        )
        assert renamed["name"] == "ida_re_overload"
        imported_type = verifier.client.execute(
            "type.inspect",
            {"name": "Game::Actor"},
        )
        actor_type = imported_type["type"]
        assert isinstance(actor_type, dict)
        assert actor_type["size"] == 32
        actor_members = actor_type["members"]
        assert isinstance(actor_members, list)
        actor_fields = [
            (
                member["name"],
                member["offset_bits"],
                member["size_bits"],
            )
            for member in actor_members
            if isinstance(member, dict)
        ]
        assert actor_fields == [
            ("klass", 0, 64),
            ("monitor", 64, 64),
            ("instance_id", 128, 32),
            ("position", 160, 96),
        ]
        vec3_type = verifier.client.execute(
            "type.inspect",
            {"name": "Game::Vec3"},
        )["type"]
        assert isinstance(vec3_type, dict)
        assert vec3_type["size"] == 12
        vec3_members = vec3_type["members"]
        assert isinstance(vec3_members, list)
        assert [
            (member["name"], member["offset_bits"], member["size_bits"])
            for member in vec3_members
            if isinstance(member, dict)
        ] == [("x", 0, 32), ("y", 32, 32), ("z", 64, 32)]
        metadata_type = verifier.client.execute(
            "type.inspect",
            {"name": "MethodMetadata"},
        )["type"]
        assert isinstance(metadata_type, dict)
        assert metadata_type["size"] == 16
        metadata_members = metadata_type["members"]
        assert isinstance(metadata_members, list)
        assert [
            (member["name"], member["offset_bits"], member["size_bits"])
            for member in metadata_members
            if isinstance(member, dict)
        ] == [("name", 0, 64), ("token", 64, 32)]
    finally:
        verifier.close()

    cold_verifier = _start_worker(
        tmp_path,
        ida_environment,
        "expert",
        checkout=staging,
    )
    try:
        verified = cold_verifier.client.execute(
            "expert.execute",
            {
                "staging_path": str(staging),
                "code": (
                    "import ida_nalt, ida_typeinf\n"
                    "til = ida_typeinf.get_idati()\n"
                    "def named(name):\n"
                    "    value = ida_typeinf.tinfo_t()\n"
                    "    assert value.get_named_type(til, name)\n"
                    "    return value\n"
                    "def udt(name):\n"
                    "    value = named(name)\n"
                    "    details = ida_typeinf.udt_type_data_t()\n"
                    "    assert value.get_udt_details(details)\n"
                    "    return value, details\n"
                    "actor, actor_fields = udt('Game::Actor')\n"
                    "assert actor.get_size() == 32\n"
                    "assert actor_fields.total_size == 32\n"
                    "assert [(field.name, field.offset, field.size) "
                    "for field in actor_fields] == "
                    "[('klass', 0, 64), ('monitor', 64, 64), "
                    "('instance_id', 128, 32), ('position', 160, 96)]\n"
                    "vec3, vec3_fields = udt('Game::Vec3')\n"
                    "assert vec3.get_size() == vec3_fields.total_size == 12\n"
                    "assert [(field.name, field.offset, field.size) "
                    "for field in vec3_fields] == "
                    "[('x', 0, 32), ('y', 32, 32), ('z', 64, 32)]\n"
                    "metadata, metadata_fields = udt('MethodMetadata')\n"
                    "assert metadata.get_size() == metadata_fields.total_size == 16\n"
                    "assert [(field.name, field.offset, field.size) "
                    "for field in metadata_fields] == "
                    "[('name', 0, 64), ('token', 64, 32)]\n"
                    "state = named('Game::ActorState')\n"
                    "assert state.is_enum() and state.get_size() == 4\n"
                    "assert state.get_sign() == ida_typeinf.type_signed\n"
                    "state_members = ida_typeinf.enum_type_data_t()\n"
                    "assert state.get_enum_details(state_members)\n"
                    "assert [(member.name, member.value) for member in state_members] == "
                    "[('Idle', 0), ('Running', 1), ('Disabled', 2)]\n"
                    "function_type = ida_typeinf.tinfo_t()\n"
                    "ea = ida_nalt.get_imagebase() + 0x1000\n"
                    "assert ida_nalt.get_tinfo(function_type, ea)\n"
                    "assert function_type.is_func() and not function_type.is_vararg_cc()\n"
                    "signature = ida_typeinf.func_type_data_t()\n"
                    "assert function_type.get_func_details(signature)\n"
                    "assert signature.get_explicit_cc() == ida_typeinf.CM_CC_FASTCALL\n"
                    "assert signature.rettype.equals_to("
                    "ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))\n"
                    "assert [(argument.name, argument.type.get_size()) "
                    "for argument in signature] == "
                    "[('self', 8), ('bonus', 4), ('method', 8)]\n"
                    "actor_pointer = ida_typeinf.tinfo_t()\n"
                    "assert actor_pointer.create_ptr(actor)\n"
                    "assert signature[0].type.equals_to(actor_pointer)\n"
                    "assert signature[1].type.equals_to("
                    "ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32))\n"
                    "metadata.set_const()\n"
                    "metadata_pointer = ida_typeinf.tinfo_t()\n"
                    "assert metadata_pointer.create_ptr(metadata)\n"
                    "assert signature[2].type.equals_to(metadata_pointer)\n"
                    "True"
                ),
            },
        )
        assert verified["result_repr"] == "True"
    finally:
        cold_verifier.close()


@pytest.mark.ida
@pytest.mark.debugger
@pytest.mark.parametrize(
    ("fixture_name", "instruction_pointer_name", "stack_pointer_name", "result_name", "run_to_rva"),
    [
        ("debug_target_x86.exe", "EIP", "ESP", "EAX", "0x1020"),
        ("debug_target_x64.exe", "RIP", "RSP", "RAX", "0x1013"),
    ],
)
def test_windows_debugger_observes_real_breakpoint_and_registers(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
    fixture_name: str,
    instruction_pointer_name: str,
    stack_pointer_name: str,
    result_name: str,
    run_to_rva: str,
) -> None:
    sample = fixture_directory / fixture_name
    checkout = _bootstrap(tmp_path, ida_environment, sample)
    worker = _start_worker(
        tmp_path,
        ida_environment,
        "debug",
        checkout=checkout,
        sample=sample,
    )
    try:
        with pytest.raises(WorkerError) as denied:
            worker.client.execute(
                "debug.establish",
                {"mode": "attach", "pid": os.getpid(), "timeout_ms": 1_000},
            )
        assert denied.value.code == "policy_denied"
        established = worker.client.execute(
            "debug.establish",
            {
                "mode": "launch",
                "target": str(sample),
                "arguments": [],
                "stop_on_entry": True,
                "timeout_ms": 30_000,
            },
        )
        assert established["state"] == "suspended"
        breakpoint = worker.client.execute(
            "debug.breakpoints",
            {
                "action": "add",
                "location": {"module": sample.name, "rva": "0x1000"},
            },
        )
        assert breakpoint["breakpoint"]["active"] is True  # type: ignore[index]
        control = worker.client.execute(
            "debug.control",
            {
                "action": "continue",
                "stop_id": established["stop_id"],
                "timeout_ms": 30_000,
            },
        )
        latest_sequence = control["latest_sequence"]
        assert isinstance(latest_sequence, int)
        cursor = latest_sequence
        breakpoint_events: list[dict[str, IpcJsonValue]] = []
        stop_id = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not breakpoint_events:
            events = worker.client.execute(
                "debug.events",
                {"after_sequence": cursor, "limit": 50, "wait_ms": 5_000},
            )
            latest_sequence = events["latest_sequence"]
            assert isinstance(latest_sequence, int)
            cursor = latest_sequence
            observed = events["events"]
            assert isinstance(observed, list)
            breakpoint_events = [
                event
                for event in observed
                if isinstance(event, dict) and event.get("kind") == "breakpoint"
            ]
            stop_id = events["stop_id"]
        assert breakpoint_events
        assert stop_id is not None
        registers = worker.client.execute(
            "debug.inspect",
            {
                "view": "registers",
                "stop_id": stop_id,
                "registers": [instruction_pointer_name, stack_pointer_name, result_name],
            },
        )
        register_values = registers["registers"]
        assert isinstance(register_values, dict)
        instruction_pointer = register_values[instruction_pointer_name]
        assert isinstance(instruction_pointer, str)
        assert instruction_pointer.startswith("0x")
        memory = worker.client.execute(
            "debug.inspect",
            {
                "view": "memory",
                "stop_id": stop_id,
                "address": {
                    "space": "runtime",
                    "module": sample.name,
                    "va": instruction_pointer,
                    "stop_id": stop_id,
                },
                "size": 16,
            },
        )
        memory_bytes = memory["bytes_hex"]
        assert isinstance(memory_bytes, str)
        assert len(memory_bytes) == 32
        threads = worker.client.execute(
            "debug.inspect",
            {"view": "threads", "stop_id": stop_id},
        )
        assert threads["threads"]  # type: ignore[index]
        stack = worker.client.execute(
            "debug.inspect",
            {"view": "stack", "stop_id": stop_id},
        )
        assert stack["frames"]  # type: ignore[index]
        memory_maps = worker.client.execute(
            "debug.inspect",
            {"view": "memory_maps", "stop_id": stop_id},
        )
        assert memory_maps["memory_maps"]  # type: ignore[index]
        stepped = worker.client.execute(
            "debug.control",
            {
                "action": "step_into",
                "stop_id": stop_id,
                "timeout_ms": 30_000,
            },
        )
        assert stepped["state"] == "suspended"
        assert stepped["stop_id"] != stop_id
        stepped_over = worker.client.execute(
            "debug.control",
            {
                "action": "step_over",
                "stop_id": stepped["stop_id"],
                "timeout_ms": 30_000,
            },
        )
        assert stepped_over["state"] == "suspended"
        ran_to = worker.client.execute(
            "debug.control",
            {
                "action": "run_to",
                "stop_id": stepped_over["stop_id"],
                "address": {
                    "space": "runtime_module",
                    "module": sample.name,
                    "rva": run_to_rva,
                },
                "timeout_ms": 30_000,
            },
        )
        assert ran_to["state"] == "suspended"
        worker.client.execute(
            "debug.finish",
            {"action": "terminate", "timeout_ms": 30_000},
        )
    except WorkerError as exc:
        pytest.fail(f"真实 debugger E2E 失败: {exc.code}: {exc}")
    finally:
        worker.close()
