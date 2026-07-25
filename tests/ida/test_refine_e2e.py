"""analysis.refine 的真实 IDA headless E2E。"""

from __future__ import annotations

import hashlib
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.domain.tools import AnalysisRefineInput
from ida_re_mcp.supervisor.refine_adapter import (
    adapt_refine_worker_result,
    build_refine_worker_request,
)
from ida_re_mcp.supervisor.workers import WorkerProcess
from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.ipc import JsonValue as IpcJsonValue


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
    ) as worker:
        result = worker.execute(
            "workspace.bootstrap",
            {"staging_path": str(database)},
            timeout_seconds=60,
        )
    assert result["saved"] is True


@pytest.mark.ida
def test_refine_reanalyzes_rebuilds_xrefs_and_decompiles_disposable_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    monkeypatch.setenv("IDADIR", ida_environment["IDADIR"])
    sample = fixture_directory / "native_pe_x64.dll"
    base_revision = tmp_path / "base.i64"
    staging = tmp_path / "refine.i64"
    log_root = tmp_path / "logs"
    _bootstrap(sample, base_revision, log_root)
    base_hash = _sha256(base_revision)
    shutil.copy2(base_revision, staging)

    arguments = AnalysisRefineInput.model_validate(
        {
            "workspace_id": "workspace_refine",
            "revision": "revision_refine",
            "targets": [
                {
                    "kind": "image",
                    "image_id": "image_refine",
                    "rva": "0x1000",
                }
            ],
            "actions": [
                "decompile",
                "reanalyze_function",
                "rebuild_xrefs",
                "autoanalysis",
            ],
        }
    )
    request = build_refine_worker_request(arguments, staging)
    with WorkerProcess.launch(
        kind="mutation",
        log_root=log_root,
        checkout=staging,
    ) as worker:
        raw = worker.execute(
            request.operation,
            cast(Mapping[str, IpcJsonValue], request.input),
            timeout_seconds=60,
        )
    result = adapt_refine_worker_result(arguments, raw, staging)

    assert result.saved is True
    assert result.staging_sha256 == _sha256(staging)
    assert [item.action for item in result.actions] == [
        "autoanalysis",
        "rebuild_xrefs",
        "reanalyze_function",
        "decompile",
    ]
    assert all(item.function_count == 1 for item in result.actions)
    assert _sha256(base_revision) == base_hash

    with WorkerProcess.launch(
        kind="analysis",
        log_root=log_root,
        checkout=staging,
        revision="revision_refined",
    ) as verifier:
        function = verifier.execute(
            "function.inspect",
            {
                "address": {"space": "image", "rva": "0x1000"},
                "views": ["chunks", "disassembly", "calls", "pseudocode", "ctree"],
                "limit": 50,
            },
            timeout_seconds=60,
        )
    assert function["instructions"]
    assert function["pseudocode"]
    assert function["ctree"]


@pytest.mark.ida
def test_refine_preflight_failure_does_not_save_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    monkeypatch.setenv("IDADIR", ida_environment["IDADIR"])
    sample = fixture_directory / "native_pe_x64.dll"
    base_revision = tmp_path / "base.i64"
    staging = tmp_path / "refine-failed.i64"
    log_root = tmp_path / "logs"
    _bootstrap(sample, base_revision, log_root)
    shutil.copy2(base_revision, staging)
    staging_hash = _sha256(staging)

    arguments = AnalysisRefineInput.model_validate(
        {
            "workspace_id": "workspace_refine",
            "revision": "revision_refine",
            "targets": [
                {
                    "kind": "image",
                    "image_id": "image_refine",
                    "rva": "0x2000",
                }
            ],
            "actions": ["rebuild_xrefs", "decompile"],
        }
    )
    request = build_refine_worker_request(arguments, staging)
    with WorkerProcess.launch(
        kind="mutation",
        log_root=log_root,
        checkout=staging,
    ) as worker:
        with pytest.raises(WorkerError) as failure:
            worker.execute(
                request.operation,
                cast(Mapping[str, IpcJsonValue], request.input),
                timeout_seconds=60,
            )

    assert failure.value.code == "unsupported"
    assert _sha256(staging) == staging_hash
