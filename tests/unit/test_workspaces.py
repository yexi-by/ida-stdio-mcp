from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest

from ida_re_mcp.supervisor import (
    StorageCorruptionError,
    WorkspaceNotFoundError,
    WorkspaceRegistry,
)


def test_workspace_copies_and_hashes_original_without_overwriting(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    original = b"MZ\x00trusted input"
    source.write_bytes(original)
    registry = WorkspaceRegistry(
        tmp_path / "data" / "workspaces",
        checkout_root=tmp_path / "data" / "checkouts",
    )

    workspace = registry.create(source)
    source.write_bytes(b"changed after import")

    assert workspace.sample_name == "sample.exe"
    assert workspace.sample_sha256 == hashlib.sha256(original).hexdigest()
    assert workspace.sample_size == len(original)
    assert workspace.sample_path.read_bytes() == original
    assert workspace.current_revision is None
    assert workspace.revisions == ()
    assert registry.list() == (registry.get(workspace.workspace_id),)


def test_uninitialized_workspace_can_be_discarded(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)

    registry.discard_uninitialized(workspace.workspace_id)

    with pytest.raises(WorkspaceNotFoundError):
        registry.get(workspace.workspace_id)


def test_workspace_missing_is_explicit(tmp_path: Path) -> None:
    registry = WorkspaceRegistry(tmp_path / "workspaces")

    with pytest.raises(WorkspaceNotFoundError):
        registry.get("ws_missing")


def test_workspace_rejects_tampered_private_sample(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"trusted sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)
    workspace.sample_path.write_bytes(b"tampered sample")

    with pytest.raises(StorageCorruptionError, match="原样本"):
        registry.get(workspace.workspace_id)


def test_workspace_gc_removes_crash_left_creating_directory(tmp_path: Path) -> None:
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    crashed = registry.root / ".creating" / "ws_crashed"
    crashed.mkdir()
    (crashed / "sample.bin").write_bytes(b"partial")

    preview = registry.collect_garbage(dry_run=True)
    assert preview.removed_paths == (crashed,)
    assert preview.reclaimed_bytes == len(b"partial")
    assert crashed.is_dir()

    applied = registry.collect_garbage(dry_run=False)
    assert applied.removed_paths == (crashed,)
    assert not crashed.exists()


def test_workspace_lock_serializes_same_workspace(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"input")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)
    entered = threading.Event()

    def contender() -> None:
        with registry.workspace_lock(workspace.workspace_id):
            entered.set()

    with registry.workspace_lock(workspace.workspace_id):
        thread = threading.Thread(target=contender)
        thread.start()
        assert not entered.wait(timeout=0.05)

    assert entered.wait(timeout=1)
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_workspace_locks_do_not_serialize_different_workspaces(tmp_path: Path) -> None:
    first_source = tmp_path / "first.bin"
    second_source = tmp_path / "second.bin"
    first_source.write_bytes(b"first")
    second_source.write_bytes(b"second")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    first = registry.create(first_source)
    second = registry.create(second_source)
    entered = threading.Event()

    def contender() -> None:
        with registry.workspace_lock(second.workspace_id):
            entered.set()

    with registry.workspace_lock(first.workspace_id):
        thread = threading.Thread(target=contender)
        thread.start()
        assert entered.wait(timeout=1)

    thread.join(timeout=1)
    assert not thread.is_alive()
