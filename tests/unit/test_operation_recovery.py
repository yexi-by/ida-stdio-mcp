from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import JsonValue

from ida_re_mcp.config import AppConfig, RuntimePaths
from ida_re_mcp.supervisor import (
    ColdValidationReceipt,
    ImageIdentity,
    OperationState,
    SupervisorStorage,
    WorkspaceRegistry,
    hash_staging_payload,
)


def _pe_image_identity() -> ImageIdentity:
    return ImageIdentity.model_validate(
        {
            "container": "pe",
            "architecture": "x86_64",
            "bitness": 64,
            "endian": "little",
            "image_size": 0x4000,
        },
        strict=True,
    )


def _runtime_paths(tmp_path: Path) -> RuntimePaths:
    data_root = tmp_path / "data"
    return RuntimePaths(
        data_root=data_root,
        log_root=tmp_path / "logs",
        workspace_root=data_root / "workspaces",
        artifact_root=data_root / "artifacts",
        checkout_root=data_root / "checkouts",
        temp_root=data_root / "temp",
    )


def _publish_without_operation(
    workspaces: WorkspaceRegistry,
    workspace_id: str,
    expected_revision: str | None,
    content: bytes,
) -> str:
    staging = workspaces.begin_staging(
        workspace_id,
        expected_revision=expected_revision,
    )
    staging.database_path.write_bytes(content)
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    return workspaces.publish_staging(staging, receipt=receipt).revision


@pytest.mark.parametrize("kind", ["workspace_create", "analysis_refine"])
def test_storage_restart_recovers_current_revision_operation_receipt(
    tmp_path: Path,
    kind: str,
) -> None:
    config = AppConfig()
    paths = _runtime_paths(tmp_path)
    first = SupervisorStorage.open(config=config, paths=paths)
    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ" + b"\0" * 510)
    workspace = first.workspaces.create(source)
    expected_revision = (
        _publish_without_operation(
            first.workspaces,
            workspace.workspace_id,
            None,
            b"base idb",
        )
        if kind == "analysis_refine"
        else None
    )
    operation = first.operations.create(
        kind,
        workspace_id=workspace.workspace_id,
    )
    first.operations.start(operation.operation_id)
    staging = first.workspaces.begin_staging(
        workspace.workspace_id,
        expected_revision=expected_revision,
    )
    staging.database_path.write_bytes(b"committed current idb")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    result: dict[str, JsonValue] = {
        "workspace_id": workspace.workspace_id,
        "previous_revision": expected_revision,
        "revision": staging.candidate_revision,
        "details": {
            "kind": kind,
            "actions": ["cold_validate", "publish", "manifest_cas"],
        },
    }
    published = first.workspaces.publish_staging(
        staging,
        receipt=receipt,
        operation_id=operation.operation_id,
        operation_result=result,
    )
    assert first.workspaces.get(workspace.workspace_id).current_revision == published.revision

    reopened = SupervisorStorage.open(config=config, paths=paths)
    restored = reopened.operations.get(operation.operation_id)

    assert restored.state is OperationState.SUCCEEDED
    assert restored.failure is None
    assert restored.result == result
    assert reopened.workspaces.get(workspace.workspace_id).current_revision == published.revision


def test_storage_restart_without_revision_receipt_marks_operation_crashed(
    tmp_path: Path,
) -> None:
    config = AppConfig()
    paths = _runtime_paths(tmp_path)
    first = SupervisorStorage.open(config=config, paths=paths)
    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ" + b"\0" * 510)
    workspace = first.workspaces.create(source)
    operation = first.operations.create(
        "workspace_create",
        workspace_id=workspace.workspace_id,
    )
    first.operations.start(operation.operation_id)
    revision = _publish_without_operation(
        first.workspaces,
        workspace.workspace_id,
        None,
        b"published without operation receipt",
    )

    reopened = SupervisorStorage.open(config=config, paths=paths)
    restored = reopened.operations.get(operation.operation_id)

    assert reopened.workspaces.get(workspace.workspace_id).current_revision == revision
    assert restored.state is OperationState.FAILED
    assert restored.result is None
    assert restored.failure is not None
    assert restored.failure.code == "worker_crashed"
