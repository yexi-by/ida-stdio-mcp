from __future__ import annotations

from pathlib import Path

import pytest

from ida_re_mcp.domain.tools import AnalysisRefineInput
from ida_re_mcp.supervisor.refine_adapter import (
    RefineAdapterInputError,
    RefineAdapterResultError,
    adapt_refine_worker_result,
    build_refine_worker_request,
)

_WORKSPACE_ID = "workspace_abcdef"
_REVISION = "revision_abcdef"
_IMAGE_ID = "image_abcdef"


def _arguments(
    *,
    actions: list[str] | None = None,
) -> AnalysisRefineInput:
    return AnalysisRefineInput.model_validate(
        {
            "workspace_id": _WORKSPACE_ID,
            "revision": _REVISION,
            "targets": [
                {
                    "kind": "image",
                    "image_id": _IMAGE_ID,
                    "rva": "0x1000",
                },
                {
                    "kind": "database",
                    "ea": "0x140002000",
                },
            ],
            "actions": actions
            or [
                "decompile",
                "reanalyze_function",
                "autoanalysis",
                "rebuild_xrefs",
            ],
        }
    )


def _result(staging_path: Path) -> dict[str, object]:
    return {
        "staging_path": str(staging_path.resolve()),
        "staging_sha256": "1" * 64,
        "actions": [
            {
                "action": "autoanalysis",
                "target_count": 2,
                "function_count": 2,
            },
            {
                "action": "rebuild_xrefs",
                "target_count": 2,
                "function_count": 2,
            },
            {
                "action": "reanalyze_function",
                "target_count": 2,
                "function_count": 2,
            },
            {
                "action": "decompile",
                "target_count": 2,
                "function_count": 2,
            },
        ],
        "database_change_count_before": 10,
        "database_change_count_after": 12,
        "cold_verification_required": True,
        "saved": True,
    }


def test_request_is_canonical_and_strips_public_image_identity(tmp_path: Path) -> None:
    staging = tmp_path / "staging.i64"
    request = build_refine_worker_request(_arguments(), staging)

    assert request.operation == "analysis.refine"
    assert request.input == {
        "staging_path": str(staging.resolve()),
        "targets": [
            {"space": "image", "rva": "0x1000"},
            {"space": "database", "ea": "0x140002000"},
        ],
        "actions": [
            "autoanalysis",
            "rebuild_xrefs",
            "reanalyze_function",
            "decompile",
        ],
    }


def test_global_autoanalysis_needs_no_target(tmp_path: Path) -> None:
    arguments = AnalysisRefineInput(
        workspace_id=_WORKSPACE_ID,
        revision=_REVISION,
        actions=["autoanalysis"],
    )
    request = build_refine_worker_request(arguments, tmp_path / "staging.i64")
    assert request.input["targets"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {
            "workspace_id": _WORKSPACE_ID,
            "revision": _REVISION,
            "targets": [],
            "actions": ["decompile"],
        },
        {
            "workspace_id": _WORKSPACE_ID,
            "revision": _REVISION,
            "targets": [
                {
                    "kind": "database",
                    "ea": "0x401000",
                },
                {
                    "kind": "database",
                    "ea": "0x401000",
                },
            ],
            "actions": ["autoanalysis"],
        },
        {
            "workspace_id": _WORKSPACE_ID,
            "revision": _REVISION,
            "targets": [],
            "actions": ["autoanalysis", "autoanalysis"],
        },
    ],
)
def test_adapter_rejects_semantically_invalid_requests(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    arguments = AnalysisRefineInput.model_validate(payload)
    with pytest.raises(RefineAdapterInputError):
        build_refine_worker_request(arguments, tmp_path / "staging.i64")


def test_result_is_strictly_bound_to_request_and_staging(tmp_path: Path) -> None:
    staging = tmp_path / "staging.i64"
    arguments = _arguments()
    result = adapt_refine_worker_result(arguments, _result(staging), staging)

    assert result.saved is True
    assert result.cold_verification_required is True
    assert [item.action for item in result.actions] == [
        "autoanalysis",
        "rebuild_xrefs",
        "reanalyze_function",
        "decompile",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("staging_path", "C:\\wrong\\staging.i64"),
        (
            "actions",
            [
                {
                    "action": "decompile",
                    "target_count": 2,
                    "function_count": 2,
                }
            ],
        ),
        (
            "actions",
            [
                {
                    "action": "autoanalysis",
                    "target_count": 1,
                    "function_count": 1,
                },
                {
                    "action": "rebuild_xrefs",
                    "target_count": 2,
                    "function_count": 2,
                },
                {
                    "action": "reanalyze_function",
                    "target_count": 2,
                    "function_count": 2,
                },
                {
                    "action": "decompile",
                    "target_count": 2,
                    "function_count": 2,
                },
            ],
        ),
    ],
)
def test_result_rejects_identity_action_and_count_mismatches(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    staging = tmp_path / "staging.i64"
    raw = _result(staging)
    raw[field] = value
    with pytest.raises(RefineAdapterResultError):
        adapt_refine_worker_result(_arguments(), raw, staging)


def test_result_rejects_unknown_fields(tmp_path: Path) -> None:
    staging = tmp_path / "staging.i64"
    raw = _result(staging)
    raw["accepted"] = True
    with pytest.raises(RefineAdapterResultError):
        adapt_refine_worker_result(_arguments(), raw, staging)
