"""Supervisor 持久化组件的统一装配入口。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Self

from ida_re_mcp.config import AppConfig, RuntimePaths
from ida_re_mcp.supervisor.artifacts import ArtifactStore
from ida_re_mcp.supervisor.errors import WorkspaceNotFoundError
from ida_re_mcp.supervisor.operations import (
    OperationCoordinator,
    OperationRecovery,
    OperationSnapshot,
)
from ida_re_mcp.supervisor.workspaces import WorkspaceRegistry


@dataclass(frozen=True, slots=True)
class StorageUsage:
    """当前运行目录用量与软配额状态。"""

    workspace_bytes: int
    artifact_bytes: int
    supervisor_bytes: int
    quota_bytes: int

    @property
    def total_bytes(self) -> int:
        return self.workspace_bytes + self.artifact_bytes + self.supervisor_bytes

    @property
    def over_soft_quota(self) -> bool:
        return self.total_bytes > self.quota_bytes


@dataclass(frozen=True, slots=True)
class SupervisorStorage:
    """App 可直接使用的 Supervisor 存储组件集合。"""

    config: AppConfig
    paths: RuntimePaths
    operations: OperationCoordinator
    artifacts: ArtifactStore
    workspaces: WorkspaceRegistry

    @classmethod
    def open(
        cls,
        *,
        config: AppConfig,
        paths: RuntimePaths | None = None,
    ) -> Self:
        runtime_paths = (paths or RuntimePaths.discover()).ensure()
        workspaces = WorkspaceRegistry(
            runtime_paths.workspace_root,
            checkout_root=runtime_paths.checkout_root,
            retained_revisions=config.storage.retained_revisions,
        )
        return cls(
            config=config,
            paths=runtime_paths,
            operations=OperationCoordinator(
                storage_root=runtime_paths.operation_root,
                recover_incomplete=lambda snapshot: _recover_revision_operation(
                    workspaces,
                    snapshot,
                ),
            ),
            artifacts=ArtifactStore(
                runtime_paths.artifact_root,
                workspace_lease_root=workspaces.lease_root,
            ),
            workspaces=workspaces,
        )

    def usage(self) -> StorageUsage:
        quota_bytes = self.config.storage.quota_gib * 1024**3
        workspace_bytes = _directory_size(self.paths.workspace_root) + _directory_size(
            self.paths.checkout_root
        )
        artifact_bytes = _directory_size(self.paths.artifact_root)
        data_bytes = _directory_size(self.paths.data_root)
        return StorageUsage(
            workspace_bytes=workspace_bytes,
            artifact_bytes=artifact_bytes,
            supervisor_bytes=max(0, data_bytes - workspace_bytes - artifact_bytes),
            quota_bytes=quota_bytes,
        )


def _directory_size(root: Path) -> int:
    if not root.is_dir():
        return 0
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except FileNotFoundError:
            # 共享 data root 中的原子发布或 GC 可在枚举后移走该条目.
            continue
    return total


def _recover_revision_operation(
    workspaces: WorkspaceRegistry,
    snapshot: OperationSnapshot,
) -> OperationRecovery | None:
    if snapshot.kind not in {"workspace_create", "analysis_refine"}:
        return None
    if snapshot.workspace_id is None:
        return None
    try:
        result = workspaces.committed_operation_result(
            snapshot.workspace_id,
            snapshot.operation_id,
        )
    except WorkspaceNotFoundError:
        return None
    return OperationRecovery(result) if result is not None else None
