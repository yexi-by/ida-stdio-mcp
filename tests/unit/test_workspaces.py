from __future__ import annotations

import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.supervisor import (
    AnalysisRetryUnavailableError,
    StorageCorruptionError,
    WorkspaceNotFoundError,
    WorkspaceRegistry,
)
from ida_re_mcp.supervisor._process_lock import InterprocessFileLock


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
    manifest = cast(
        dict[str, object],
        json.loads((workspace.sample_path.parent / "workspace.json").read_text(encoding="utf-8")),
    )
    assert manifest["schema_version"] == "1"
    assert registry.list() == (registry.get(workspace.workspace_id),)


def test_uninitialized_workspace_can_be_discarded(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)

    registry.discard_uninitialized(workspace.workspace_id)

    with pytest.raises(WorkspaceNotFoundError):
        registry.get(workspace.workspace_id)


def test_workspace_rejects_candidate_changed_by_validator(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"trusted sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")

    def mutate_candidate(path: Path, _sha256: str, _size: int) -> None:
        path.write_bytes(b"changed during validation")

    with pytest.raises(StorageCorruptionError, match="候选样本"):
        registry.create(source, validate_copy=mutate_candidate)

    assert registry.list() == ()
    assert tuple((registry.root / ".creating").iterdir()) == ()
    assert source.read_bytes() == b"trusted sample"


def test_workspace_missing_is_explicit(tmp_path: Path) -> None:
    registry = WorkspaceRegistry(tmp_path / "workspaces")

    with pytest.raises(WorkspaceNotFoundError):
        registry.get("ws_missing")


def test_workspace_list_does_not_wait_for_active_worker_lease(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"trusted sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)
    acquired = threading.Event()
    release = threading.Event()

    def hold_worker_lease() -> None:
        with registry.workspace_lease_lock(workspace.workspace_id):
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_worker_lease)
    holder.start()
    assert acquired.wait(timeout=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            listed = executor.submit(registry.list).result(timeout=1)
        assert listed == (registry.get(workspace.workspace_id),)
    finally:
        release.set()
        holder.join(timeout=1)
    assert not holder.is_alive()


def test_workspace_rejects_tampered_private_sample(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"trusted sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)
    workspace.sample_path.write_bytes(b"tampered sample")

    with pytest.raises(StorageCorruptionError, match="原样本"):
        registry.get(workspace.workspace_id)


def test_prepare_analysis_retry_clears_only_expected_failed_outcome(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"trusted sample")
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    workspace = registry.create(source)
    registry.record_analysis_outcome(
        workspace.workspace_id,
        state="failed",
        reason="首次分析失败",
    )
    failed = registry.get(workspace.workspace_id)
    assert failed.analysis_outcome is not None

    prepared = registry.prepare_analysis_retry(
        workspace.workspace_id,
        expected_outcome=failed.analysis_outcome,
    )

    assert prepared.workspace_id == workspace.workspace_id
    assert prepared.sample_sha256 == workspace.sample_sha256
    assert prepared.analysis_outcome is None
    with pytest.raises(AnalysisRetryUnavailableError, match="没有可重试"):
        registry.prepare_analysis_retry(
            workspace.workspace_id,
            expected_outcome=failed.analysis_outcome,
        )


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


def test_workspace_gc_preserves_other_session_active_creation(tmp_path: Path) -> None:
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    active = registry.root / ".creating" / "ws_active"
    active.mkdir()
    (active / "sample.bin").write_bytes(b"partial")
    acquired = threading.Event()
    release = threading.Event()

    def hold_creation_lease() -> None:
        lease = registry.workspace_lease_lock("ws_active")
        with lease:
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_creation_lease)
    holder.start()
    assert acquired.wait(timeout=1)
    try:
        result = registry.collect_garbage(dry_run=False)
        assert result.removed_paths == ()
        assert result.skipped_workspace_ids == ("ws_active",)
        assert active.is_dir()
    finally:
        release.set()
        holder.join(timeout=1)
    assert not holder.is_alive()


def test_concurrent_workspace_gc_continues_when_creating_directory_disappears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = WorkspaceRegistry(tmp_path / "workspaces")
    second = WorkspaceRegistry(tmp_path / "workspaces")
    crashed = first.root / ".creating" / "ws_crashed"
    crashed.mkdir()
    (crashed / "sample.bin").write_bytes(b"partial")
    reached_lease = threading.Event()
    continue_gc = threading.Event()
    original_workspace_lease_lock = first.workspace_lease_lock

    def delayed_workspace_lease_lock(workspace_id: str) -> InterprocessFileLock:
        if workspace_id == "ws_crashed":
            reached_lease.set()
            assert continue_gc.wait(timeout=5)
        return original_workspace_lease_lock(workspace_id)

    monkeypatch.setattr(first, "workspace_lease_lock", delayed_workspace_lease_lock)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(first.collect_garbage, dry_run=False)
        try:
            assert reached_lease.wait(timeout=1)
            winner = second.collect_garbage(dry_run=False)
        finally:
            continue_gc.set()
        follower = future.result(timeout=1)

    assert winner.removed_paths == (crashed,)
    assert follower.removed_paths == ()


def test_workspace_gc_reclaims_expired_uninitialized_workspace_after_lease_release(
    tmp_path: Path,
) -> None:
    registry = WorkspaceRegistry(tmp_path / "workspaces")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    workspace = registry.create(source)
    registry.record_analysis_outcome(
        workspace.workspace_id,
        state="failed",
        reason="长操作失败",
    )
    retained = registry.get(workspace.workspace_id)
    assert retained.analysis_outcome is not None
    assert retained.analysis_outcome.reason == "长操作失败"
    workspace_root = workspace.sample_path.parent
    manifest_path = workspace_root / "workspace.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = 0.0
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    acquired = threading.Event()
    release = threading.Event()

    def hold_initialization_lease() -> None:
        lease = registry.workspace_lease_lock(workspace.workspace_id)
        with lease:
            acquired.set()
            release.wait(timeout=5)

    holder = threading.Thread(target=hold_initialization_lease)
    holder.start()
    assert acquired.wait(timeout=1)
    try:
        active = registry.collect_garbage(dry_run=False)
        assert active.removed_paths == ()
        assert active.skipped_workspace_ids == (workspace.workspace_id,)
        assert workspace_root.is_dir()
    finally:
        release.set()
        holder.join(timeout=1)
    assert not holder.is_alive()

    collected = registry.collect_garbage(dry_run=False)
    assert collected.removed_paths == (workspace_root,)
    assert not workspace_root.exists()
    with pytest.raises(WorkspaceNotFoundError):
        registry.get(workspace.workspace_id)


def test_concurrent_workspace_gc_continues_when_workspace_disappears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = WorkspaceRegistry(tmp_path / "workspaces")
    second = WorkspaceRegistry(tmp_path / "workspaces")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    workspace = first.create(source)
    workspace_root = workspace.sample_path.parent
    manifest_path = workspace_root / "workspace.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = 0.0
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    reached_lease = threading.Event()
    continue_gc = threading.Event()
    original_workspace_lease_lock = first.workspace_lease_lock

    def delayed_workspace_lease_lock(workspace_id: str) -> InterprocessFileLock:
        if workspace_id == workspace.workspace_id:
            reached_lease.set()
            assert continue_gc.wait(timeout=5)
        return original_workspace_lease_lock(workspace_id)

    monkeypatch.setattr(first, "workspace_lease_lock", delayed_workspace_lease_lock)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(first.collect_garbage, dry_run=False)
        try:
            assert reached_lease.wait(timeout=1)
            winner = second.collect_garbage(dry_run=False)
        finally:
            continue_gc.set()
        follower = future.result(timeout=1)

    assert winner.removed_paths == (workspace_root,)
    assert follower.removed_paths == ()
    assert follower.reclaimed_bytes == 0
    assert not workspace_root.exists()


def test_workspace_list_continues_when_gc_removes_enumerated_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = WorkspaceRegistry(tmp_path / "workspaces")
    collector = WorkspaceRegistry(tmp_path / "workspaces")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    workspace = reader.create(source)
    workspace_root = workspace.sample_path.parent
    manifest_path = workspace_root / "workspace.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = 0.0
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    reached_lease = threading.Event()
    continue_list = threading.Event()
    original_workspace_lease_lock = reader.workspace_lease_lock

    def delayed_workspace_lease_lock(workspace_id: str) -> InterprocessFileLock:
        if workspace_id == workspace.workspace_id:
            reached_lease.set()
            assert continue_list.wait(timeout=5)
        return original_workspace_lease_lock(workspace_id)

    monkeypatch.setattr(reader, "workspace_lease_lock", delayed_workspace_lease_lock)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(reader.list)
        try:
            assert reached_lease.wait(timeout=1)
            removed = collector.collect_garbage(dry_run=False)
        finally:
            continue_list.set()
        snapshots = future.result(timeout=1)

    assert removed.removed_paths == (workspace_root,)
    assert snapshots == ()


def test_workspace_list_continues_when_workspace_vanishes_before_type_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = WorkspaceRegistry(tmp_path / "workspaces")
    collector = WorkspaceRegistry(tmp_path / "workspaces")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"sample")
    workspace = reader.create(source)
    workspace_root = workspace.sample_path.parent
    manifest_path = workspace_root / "workspace.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = 0.0
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )

    reached_type_check = threading.Event()
    continue_list = threading.Event()
    reader_thread_id: int | None = None
    original_lstat = Path.lstat

    def delayed_lstat(path: Path) -> os.stat_result:
        if threading.get_ident() == reader_thread_id and path == workspace_root:
            reached_type_check.set()
            assert continue_list.wait(timeout=5)
        return original_lstat(path)

    def list_in_reader_thread() -> tuple[object, ...]:
        nonlocal reader_thread_id
        reader_thread_id = threading.get_ident()
        return reader.list()

    monkeypatch.setattr(Path, "lstat", delayed_lstat)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(list_in_reader_thread)
        try:
            assert reached_type_check.wait(timeout=1)
            removed = collector.collect_garbage(dry_run=False)
        finally:
            continue_list.set()
        snapshots = future.result(timeout=1)

    assert removed.removed_paths == (workspace_root,)
    assert snapshots == ()


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
