from __future__ import annotations

import pytest
from pydantic import ValidationError

from ida_re_mcp.domain.tools import (
    ChangePrepareInput,
    DebugInspectInput,
    ProgramSearchInput,
)


def test_static_query_requires_explicit_workspace_and_revision() -> None:
    with pytest.raises(ValidationError):
        ProgramSearchInput.model_validate(
            {
                "text_query": "license",
                "domains": ["string"],
            }
        )


def test_tool_arguments_do_not_coerce_or_accept_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ProgramSearchInput.model_validate(
            {
                "workspace_id": "workspace_abcdef",
                "revision": "revision_abcdef",
                "text_query": "license",
                "domains": ["string"],
                "page_size": "50",
            }
        )
    with pytest.raises(ValidationError):
        ProgramSearchInput.model_validate(
            {
                "workspace_id": "workspace_abcdef",
                "revision": "revision_abcdef",
                "text_query": "license",
                "domains": ["string"],
                "unexpected": True,
            }
        )


def test_program_search_separates_text_bytes_and_allows_explicit_enumeration() -> None:
    enumeration = ProgramSearchInput(
        workspace_id="workspace_abcdef",
        revision="revision_abcdef",
        domains=["function", "string"],
        text_query="",
    )
    assert enumeration.text_query == ""
    mixed = ProgramSearchInput(
        workspace_id="workspace_abcdef",
        revision="revision_abcdef",
        domains=["name", "bytes"],
        text_query="ordinary text",
        bytes_query="4142",
    )
    assert mixed.text_query == "ordinary text"
    assert mixed.bytes_query == "4142"

    with pytest.raises(ValidationError):
        ProgramSearchInput(
            workspace_id="workspace_abcdef",
            revision="revision_abcdef",
            domains=["name", "bytes"],
            text_query="ordinary text",
        )
    with pytest.raises(ValidationError):
        ProgramSearchInput(
            workspace_id="workspace_abcdef",
            revision="revision_abcdef",
            domains=["bytes"],
            text_query="4142",
            bytes_query="4142",
        )


def test_change_prepare_uses_tagged_closed_operations() -> None:
    value = ChangePrepareInput.model_validate(
        {
            "workspace_id": "workspace_abcdef",
            "base_revision": "revision_abcdef",
            "operations": [
                {
                    "kind": "patch_bytes",
                    "target": {"kind": "database", "ea": "0x401000"},
                    "expected_bytes": "7505",
                    "replacement_bytes": "9090",
                },
                {
                    "kind": "import_il2cpp_bundle",
                    "bundle_path": r"C:\inputs\annotations.ndjson",
                    "bundle_sha256": "11" * 32,
                    "metadata_path": r"C:\inputs\global-metadata.dat",
                    "metadata_sha256": "22" * 32,
                    "type_resolutions": [],
                },
                {
                    "kind": "set_type",
                    "target": {"kind": "database", "ea": "0x401000"},
                    "type_ref": {"kind": "primitive", "name": "u32"},
                },
            ],
        }
    )
    assert len(value.operations) == 3


def test_change_prepare_inverse_uses_dedicated_field() -> None:
    inverse = ChangePrepareInput.model_validate(
        {
            "workspace_id": "workspace_abcdef",
            "base_revision": "revision_abcdef",
            "inverse_of_change_id": "change_abcdef",
        }
    )
    assert inverse.operations == []


def test_debug_memory_read_has_hard_size_limit() -> None:
    with pytest.raises(ValidationError):
        DebugInspectInput.model_validate(
            {
                "debug_session_id": "debug_abcdef",
                "stop_id": "stop_abcdef",
                "views": ["memory"],
                "memory_address": {
                    "kind": "runtime",
                    "module_id": "module_abcdef",
                    "va": "0x7ff600001000",
                    "stop_id": "stop_abcdef",
                },
                "memory_size": 65_537,
            }
        )
