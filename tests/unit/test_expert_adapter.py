from __future__ import annotations

from pathlib import Path

import pytest

from ida_re_mcp.supervisor.expert_adapter import (
    ExpertAdapterError,
    adapt_expert_worker_result,
)


def _result(staging: Path) -> dict[str, object]:
    return {
        "staging_path": str(staging.resolve()),
        "staging_sha256": "1" * 64,
        "saved": True,
        "stdout": "ok\n",
        "stderr": "",
        "result_repr": "42",
        "cold_verification_required": True,
    }


def test_adapt_expert_worker_result_binds_staging_and_output(tmp_path: Path) -> None:
    staging = tmp_path / "database.i64"
    raw = _result(staging)

    result = adapt_expert_worker_result(raw, staging)

    assert result.result_repr == "42"
    assert result.stdout == "ok\n"


def test_adapt_expert_worker_result_rejects_wrong_staging(tmp_path: Path) -> None:
    staging = tmp_path / "database.i64"
    raw = _result(staging)
    raw["staging_path"] = str(tmp_path / "other.i64")

    with pytest.raises(ExpertAdapterError, match="staging_path"):
        adapt_expert_worker_result(raw, staging)


def test_adapt_expert_worker_result_rechecks_combined_output_limit(
    tmp_path: Path,
) -> None:
    staging = tmp_path / "database.i64"
    raw = _result(staging)
    raw["stdout"] = "a" * 32_768
    raw["stderr"] = "b" * 32_769

    with pytest.raises(ExpertAdapterError, match="64 KiB"):
        adapt_expert_worker_result(raw, staging)
