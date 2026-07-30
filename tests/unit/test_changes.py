from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest

import ida_re_mcp.supervisor.changes as changes_module
from ida_re_mcp.supervisor._fs import canonical_json_bytes
from ida_re_mcp.supervisor.changes import (
    ChangeSet,
    ChangeSetGarbageCollectionResult,
    ChangeSetIntegrityError,
    ChangeSetMismatchError,
    ChangeSetStore,
    ChangeSetValidationError,
)

_LEASE_PROBE = """
from pathlib import Path
import sys
import time

from ida_re_mcp.supervisor._process_lock import interprocess_file_lock

lease_root = Path(sys.argv[1])
workspace_id = sys.argv[2]
ready = Path(sys.argv[3])
release = Path(sys.argv[4])
lock = interprocess_file_lock(lease_root / f"{workspace_id}.lease.lock")
with lock:
    ready.write_text("ready", encoding="ascii")
    deadline = time.monotonic() + 30
    while not release.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("lease probe release timed out")
        time.sleep(0.01)
"""


def _rename_operation(new_name: str = "verified_name") -> dict[str, object]:
    return {
        "kind": "rename",
        "target": {
            "kind": "image",
            "image_id": "image_abcdef",
            "rva": "0x1234",
        },
        "expected_name": "sub_140001234",
        "new_name": new_name,
    }


def _revision_preimage(
    salt: str = "base",
    *,
    revision: str = "revision_abcdef",
) -> dict[str, object]:
    return {
        "revision": revision,
        "database_sha256": "11" * 32,
        "component_hashes": {
            "database.i64": "11" * 32,
            "database.i64.id0": hashlib.sha256(salt.encode()).hexdigest(),
        },
    }


def _prepare(
    store: ChangeSetStore,
    *,
    workspace_id: str = "workspace_abcdef",
    base_revision: str = "revision_abcdef",
) -> ChangeSet:
    return store.prepare(
        workspace_id=workspace_id,
        base_revision=base_revision,
        operations=[_rename_operation()],
        preimage=_revision_preimage(revision=base_revision),
    )


def _start_lease_probe(
    *,
    lease_root: Path,
    workspace_id: str,
    ready: Path,
    release: Path,
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _LEASE_PROBE,
            str(lease_root),
            workspace_id,
            str(ready),
            str(release),
        ],
        cwd=Path(__file__).resolve().parents[2],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def _wait_for_marker(
    marker: Path,
    process: subprocess.Popen[str],
    *,
    timeout: float = 10,
) -> None:
    deadline = time.monotonic() + timeout
    while not marker.is_file():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"子进程在写入 {marker.name} 前退出: "
                f"code={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            pytest.fail(f"等待子进程标记超时: {marker}")
        time.sleep(0.01)


def _finish_probe(
    process: subprocess.Popen[str],
    *,
    release: Path,
) -> None:
    release.touch(exist_ok=True)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        pytest.fail(f"子进程未按时退出: stdout={stdout!r}, stderr={stderr!r}")
    assert process.returncode == 0, (
        f"子进程失败: code={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
    )


def test_prepare_publishes_canonical_immutable_plan(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "data" / "changes")
    prepared = _prepare(store)

    assert prepared.change_set_id.startswith("cset_")
    assert len(prepared.digest) == 64
    assert prepared.storage_path.parent.name == "workspace_abcdef"
    record_path = prepared.storage_path / "change-set.json"
    hash_path = prepared.storage_path / "change-set.sha256"
    record_bytes = record_path.read_bytes()
    parsed = cast(dict[str, object], json.loads(record_bytes))
    assert record_bytes == canonical_json_bytes(parsed)
    assert hash_path.read_text(encoding="ascii") == f"{prepared.file_sha256}\n"
    assert hashlib.sha256(record_bytes).hexdigest() == prepared.file_sha256

    loaded = store.load_for_apply(
        workspace_id=prepared.workspace_id,
        base_revision=prepared.base_revision,
        change_set_id=prepared.change_set_id,
        digest=prepared.digest,
    )
    assert loaded == prepared


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workspace_id", "workspace_other"),
        ("base_revision", "revision_other"),
        ("change_set_id", "cset_missing"),
        ("digest", "0" * 64),
    ],
)
def test_apply_requires_all_four_identity_values(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    prepared = _prepare(store)
    arguments = {
        "workspace_id": prepared.workspace_id,
        "base_revision": prepared.base_revision,
        "change_set_id": prepared.change_set_id,
        "digest": prepared.digest,
    }
    arguments[field] = value
    with pytest.raises((ChangeSetMismatchError, changes_module.ChangeSetNotFoundError)):
        store.load_for_apply(**arguments)


def test_file_hash_and_plan_digest_are_both_verified(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    prepared = _prepare(store)
    record_path = prepared.storage_path / "change-set.json"
    hash_path = prepared.storage_path / "change-set.sha256"

    record_path.write_bytes(record_path.read_bytes() + b" ")
    with pytest.raises(ChangeSetIntegrityError, match="SHA-256"):
        store.load(
            workspace_id=prepared.workspace_id,
            base_revision=prepared.base_revision,
            change_set_id=prepared.change_set_id,
            digest=prepared.digest,
        )

    parsed = cast(dict[str, object], json.loads(record_path.read_bytes()))
    parsed["base_revision"] = "revision_tampered"
    tampered = canonical_json_bytes(parsed)
    record_path.write_bytes(tampered)
    hash_path.write_text(f"{hashlib.sha256(tampered).hexdigest()}\n", encoding="ascii")
    with pytest.raises((ChangeSetMismatchError, ChangeSetIntegrityError)):
        store.load(
            workspace_id=prepared.workspace_id,
            base_revision=prepared.base_revision,
            change_set_id=prepared.change_set_id,
            digest=prepared.digest,
        )


def test_unknown_fields_and_missing_schema_fail_closed(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    operation = _rename_operation()
    operation["unknown"] = True
    with pytest.raises(ChangeSetValidationError):
        store.prepare(
            workspace_id="workspace_abcdef",
            base_revision="revision_abcdef",
            operations=[operation],
            preimage=_revision_preimage(),
        )

    prepared = _prepare(store)
    record_path = prepared.storage_path / "change-set.json"
    hash_path = prepared.storage_path / "change-set.sha256"
    parsed = cast(dict[str, object], json.loads(record_path.read_bytes()))
    assert parsed["schema_version"] == "1"
    parsed.pop("schema_version")
    parsed["extra"] = "rejected"
    tampered = canonical_json_bytes(parsed)
    record_path.write_bytes(tampered)
    hash_path.write_text(f"{hashlib.sha256(tampered).hexdigest()}\n", encoding="ascii")
    with pytest.raises(ChangeSetIntegrityError, match="schema"):
        store.load(
            workspace_id=prepared.workspace_id,
            base_revision=prepared.base_revision,
            change_set_id=prepared.change_set_id,
            digest=prepared.digest,
        )


def test_preimage_must_match_operations_exactly(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    with pytest.raises(ChangeSetValidationError):
        store.prepare(
            workspace_id="workspace_abcdef",
            base_revision="revision_abcdef",
            operations=[_rename_operation()],
            preimage={
                "revision": "revision_other",
                "database_sha256": "11" * 32,
                "component_hashes": {"database.i64": "11" * 32},
            },
        )


def test_inverse_is_a_new_explicit_plan(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    original = _prepare(store)
    inverse = store.prepare(
        workspace_id=original.workspace_id,
        base_revision="revision_after_original",
        operations=[
            {
                "kind": "restore_revision",
                "restore_revision": original.base_revision,
                "source_change_id": "change_abcdef",
            }
        ],
        preimage={
            "revision": "revision_after_original",
            "database_sha256": "22" * 32,
            "component_hashes": {"database.i64": "22" * 32},
        },
        inverse_of_change_id="change_abcdef",
    )

    assert inverse.change_set_id != original.change_set_id
    assert inverse.digest != original.digest
    assert inverse.inverse_of_change_id == "change_abcdef"
    assert (
        store.load_for_apply(
            workspace_id=inverse.workspace_id,
            base_revision=inverse.base_revision,
            change_set_id=inverse.change_set_id,
            digest=inverse.digest,
        )
        == inverse
    )


def test_concurrent_prepare_is_idempotent_and_complete(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "changes")

    def prepare_one(_: int) -> ChangeSet:
        return _prepare(store)

    with ThreadPoolExecutor(max_workers=8) as executor:
        prepared = tuple(executor.map(prepare_one, range(32)))

    assert len({item.change_set_id for item in prepared}) == 1
    assert len({item.digest for item in prepared}) == 1
    assert all(
        (item.storage_path / "change-set.json").is_file()
        and (item.storage_path / "change-set.sha256").is_file()
        for item in prepared
    )
    for item in prepared:
        assert (
            store.load_for_apply(
                workspace_id=item.workspace_id,
                base_revision=item.base_revision,
                change_set_id=item.change_set_id,
                digest=item.digest,
            )
            == item
        )


def test_failed_prepare_leaves_no_published_or_staging_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    real_write = changes_module.atomic_write_bytes
    calls = 0

    def fail_second_write(path: Path, data: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected crash")
        real_write(path, data)

    monkeypatch.setattr(changes_module, "atomic_write_bytes", fail_second_write)
    with pytest.raises(OSError, match="injected crash"):
        _prepare(store)

    workspace_root = store.root / "workspace_abcdef"
    published = [path for path in workspace_root.iterdir() if path.name != ".staging"]
    staging = workspace_root / ".staging"
    assert published == []
    assert list(staging.iterdir()) == []


def test_publish_durability_failure_removes_visible_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ChangeSetStore(tmp_path / "changes")

    def fail_fsync(_path: Path) -> None:
        raise OSError("injected durability failure")

    monkeypatch.setattr(changes_module, "_fsync_directory", fail_fsync)
    with pytest.raises(OSError, match="durability"):
        _prepare(store)

    workspace_root = store.root / "workspace_abcdef"
    assert [path for path in workspace_root.iterdir() if path.name != ".staging"] == []
    assert list((workspace_root / ".staging").iterdir()) == []


def test_gc_removes_only_unreachable_plans_and_current_staging_residue(
    tmp_path: Path,
) -> None:
    lease_root = tmp_path / "data" / "workspaces" / ".locks"
    store = ChangeSetStore(
        tmp_path / "data" / "changes",
        workspace_lease_root=lease_root,
    )
    retained = _prepare(store, base_revision="revision_retained")
    unreachable = _prepare(store, base_revision="revision_unreachable")
    staging = store.root / retained.workspace_id / ".staging" / ".prepare-deadbeef"
    staging.mkdir()
    (staging / ".change-set.json.1234abcd.tmp").write_bytes(b"partial")
    complete_staging = store.root / retained.workspace_id / ".staging" / ".prepare-feedface"
    complete_staging.mkdir()
    for name in ("change-set.json", "change-set.sha256"):
        (complete_staging / name).write_bytes((unreachable.storage_path / name).read_bytes())

    scopes = {(retained.workspace_id, retained.base_revision)}
    preview = store.collect_garbage(retained_scopes=scopes, dry_run=True)

    assert isinstance(preview, ChangeSetGarbageCollectionResult)
    assert preview.dry_run
    assert preview.removed_change_set_paths == (unreachable.storage_path,)
    assert preview.removed_staging_paths == tuple(sorted((staging, complete_staging), key=str))
    assert preview.removed_paths == tuple(
        sorted((unreachable.storage_path, staging, complete_staging), key=str)
    )
    assert preview.reclaimed_bytes > 0
    assert preview.skipped_workspace_ids == ()
    assert all(path.is_dir() for path in preview.removed_paths)

    applied = store.collect_garbage(retained_scopes=scopes, dry_run=False)

    assert not applied.dry_run
    assert applied.removed_paths == preview.removed_paths
    assert applied.removed_change_set_paths == preview.removed_change_set_paths
    assert applied.removed_staging_paths == preview.removed_staging_paths
    assert applied.reclaimed_bytes == preview.reclaimed_bytes
    assert all(not path.exists() for path in applied.removed_paths)
    assert (
        store.load_for_apply(
            workspace_id=retained.workspace_id,
            base_revision=retained.base_revision,
            change_set_id=retained.change_set_id,
            digest=retained.digest,
        )
        == retained
    )
    empty = store.collect_garbage(retained_scopes=scopes, dry_run=False)
    assert empty.removed_paths == ()
    assert empty.reclaimed_bytes == 0


def test_gc_refreshes_retained_revisions_under_workspace_lease(tmp_path: Path) -> None:
    lease_root = tmp_path / "data" / "workspaces" / ".locks"
    store = ChangeSetStore(
        tmp_path / "data" / "changes",
        workspace_lease_root=lease_root,
    )
    published = _prepare(store, base_revision="revision_just_published")

    applied = store.collect_garbage(
        retained_scopes=set(),
        retained_revision_provider=lambda workspace_id: (
            {"revision_just_published"} if workspace_id == published.workspace_id else set()
        ),
        dry_run=False,
    )

    assert applied.removed_paths == ()
    assert (
        store.load_for_apply(
            workspace_id=published.workspace_id,
            base_revision=published.base_revision,
            change_set_id=published.change_set_id,
            digest=published.digest,
        )
        == published
    )


def test_gc_skips_workspace_held_by_other_process(
    tmp_path: Path,
) -> None:
    lease_root = tmp_path / "data" / "workspaces" / ".locks"
    store = ChangeSetStore(
        tmp_path / "data" / "changes",
        workspace_lease_root=lease_root,
    )
    unreachable = _prepare(store)
    staging = store.root / unreachable.workspace_id / ".staging" / ".prepare-deadbeef"
    staging.mkdir()
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    process = _start_lease_probe(
        lease_root=lease_root,
        workspace_id=unreachable.workspace_id,
        ready=ready,
        release=release,
    )
    try:
        _wait_for_marker(ready, process)

        preview = store.collect_garbage(retained_scopes=set(), dry_run=True)
        applied = store.collect_garbage(retained_scopes=set(), dry_run=False)

        assert preview.removed_paths == ()
        assert applied.removed_paths == ()
        assert preview.skipped_workspace_ids == (unreachable.workspace_id,)
        assert applied.skipped_workspace_ids == (unreachable.workspace_id,)
        assert unreachable.storage_path.is_dir()
        assert staging.is_dir()
    finally:
        _finish_probe(process, release=release)

    collected = store.collect_garbage(retained_scopes=set(), dry_run=False)
    assert collected.removed_paths == tuple(sorted((unreachable.storage_path, staging), key=str))
    assert all(not path.exists() for path in collected.removed_paths)


def test_gc_fails_closed_on_unknown_staging_layout(tmp_path: Path) -> None:
    lease_root = tmp_path / "data" / "workspaces" / ".locks"
    store = ChangeSetStore(
        tmp_path / "data" / "changes",
        workspace_lease_root=lease_root,
    )
    unreachable = _prepare(store)
    staging = store.root / unreachable.workspace_id / ".staging" / ".prepare-deadbeef"
    staging.mkdir()
    unexpected = staging / "unexpected.bin"
    unexpected.write_bytes(b"not a current staging file")

    with pytest.raises(ChangeSetIntegrityError, match="未知文件"):
        store.collect_garbage(retained_scopes=set(), dry_run=False)

    assert unreachable.storage_path.is_dir()
    assert staging.is_dir()
    assert unexpected.is_file()


def test_gc_fails_closed_on_published_directory_with_extra_content(
    tmp_path: Path,
) -> None:
    lease_root = tmp_path / "data" / "workspaces" / ".locks"
    store = ChangeSetStore(
        tmp_path / "data" / "changes",
        workspace_lease_root=lease_root,
    )
    unreachable = _prepare(store)
    extra = unreachable.storage_path / "unexpected.bin"
    extra.write_bytes(b"unexpected")

    with pytest.raises(ChangeSetIntegrityError, match="附加内容"):
        store.collect_garbage(retained_scopes=set(), dry_run=False)

    assert unreachable.storage_path.is_dir()
    assert extra.is_file()


def test_gc_requires_explicit_workspace_lifecycle_lease(tmp_path: Path) -> None:
    store = ChangeSetStore(tmp_path / "changes")
    _prepare(store)

    with pytest.raises(ValueError, match="lifecycle lease"):
        store.collect_garbage(retained_scopes=set(), dry_run=True)


def test_store_allows_data_directory_inside_working_tree(tmp_path: Path) -> None:
    working_tree = tmp_path / "repo"
    (working_tree / ".git").mkdir(parents=True)
    root = working_tree / "data" / "sessions" / "session_test" / "change-sets"

    store = ChangeSetStore(root)

    assert store.root == root.resolve()
    assert root.is_dir()


def test_store_rejects_directory_that_contains_working_tree(tmp_path: Path) -> None:
    working_tree = tmp_path / "repo"
    (working_tree / ".git").mkdir(parents=True)

    with pytest.raises(ValueError, match="项目根目录或它的上级目录"):
        ChangeSetStore(tmp_path, working_tree=working_tree)
