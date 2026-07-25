from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_re_mcp.constants import RESOURCE_CHUNK_BYTES
from ida_re_mcp.supervisor import (
    ArtifactFileInput,
    ArtifactIntegrityError,
    ArtifactMetadata,
    ArtifactNotFoundError,
    ArtifactStore,
    parse_artifact_uri,
)


def test_artifact_is_immutable_and_content_addressed(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")

    first = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_one",
        data=b"trusted report",
        media_type="text/markdown",
        name="report.md",
    )
    second = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_one",
        data=b"trusted report",
        media_type="text/markdown",
        name="report.md",
    )
    different_name = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_one",
        data=b"trusted report",
        media_type="text/markdown",
        name="other.md",
    )

    assert first == second
    assert first.artifact_id != different_name.artifact_id
    assert store.read_all("ws_one", "rev_one", first.artifact_id) == b"trusted report"
    assert parse_artifact_uri(first.uri) == ("ws_one", "rev_one", first.artifact_id)
    assert store.list() == (different_name, first) or store.list() == (first, different_name)


def test_artifact_chunking_has_hard_limit_and_cursor(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    metadata = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_one",
        data=b"abcdef",
        media_type="application/octet-stream",
    )

    first = store.read_uri(metadata.uri, offset=0, limit=2)
    second = store.read_uri(metadata.uri, offset=first.next_offset or 0, limit=4)

    assert first.data == b"ab"
    assert first.next_offset == 2
    assert first.eof is False
    assert second.data == b"cdef"
    assert second.next_offset is None
    assert second.eof is True
    with pytest.raises(ValueError):
        store.read_chunk(
            "ws_one",
            "rev_one",
            metadata.artifact_id,
            limit=RESOURCE_CHUNK_BYTES + 1,
        )


def test_large_file_is_exported_as_reconstructable_immutable_resources(
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    source = tmp_path / "database.i64"
    payload = bytes(range(251)) * ((RESOURCE_CHUNK_BYTES * 2 + 123_457) // 251 + 1)
    payload = payload[: RESOURCE_CHUNK_BYTES * 2 + 123_457]
    source.write_bytes(payload)

    exported = store.put_chunked_file(
        workspace_id="ws_one",
        revision="rev_one",
        source=source,
        media_type="application/vnd.hex-rays.idb",
        name="database.i64",
    )

    index = json.loads(store.read_all("ws_one", "rev_one", exported.index.artifact_id))
    assert index["schema_version"] == "2026-07-28"
    assert index["kind"] == "chunked_artifact"
    assert index["content"] == {
        "media_type": "application/vnd.hex-rays.idb",
        "name": "database.i64",
        "sha256": exported.content_sha256,
        "size": len(payload),
    }
    assert len(index["chunks"]) == 3
    assert all(item["size"] <= RESOURCE_CHUNK_BYTES for item in index["chunks"])

    reconstructed = b"".join(
        store.read_all(*parse_artifact_uri(item["uri"])) for item in index["chunks"]
    )
    assert reconstructed == payload
    assert exported.size == len(payload)
    assert store.list() == (exported.index,)


def test_chunked_file_rolls_back_new_resources_when_index_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    source = tmp_path / "database.i64"
    source.write_bytes(b"x" * (RESOURCE_CHUNK_BYTES + 1))
    original_put_bytes = store.put_bytes

    def fail_index(
        *,
        workspace_id: str,
        revision: str,
        data: bytes,
        media_type: str,
        name: str | None = None,
        listed: bool = True,
    ) -> ArtifactMetadata:
        if media_type == "application/vnd.ida-re.chunked-artifact+json":
            raise OSError("injected index failure")
        return original_put_bytes(
            workspace_id=workspace_id,
            revision=revision,
            data=data,
            media_type=media_type,
            name=name,
            listed=listed,
        )

    monkeypatch.setattr(store, "put_bytes", fail_index)
    with pytest.raises(OSError, match="injected"):
        store.put_chunked_file(
            workspace_id="ws_one",
            revision="rev_one",
            source=source,
            media_type="application/vnd.hex-rays.idb",
            name="database.i64",
        )

    assert store.list() == ()


def test_artifact_tampering_is_detected(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root)
    metadata = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_one",
        data=b"original",
        media_type="application/octet-stream",
    )
    blob = root / "ws_one" / "rev_one" / metadata.artifact_id / "artifact.blob"
    blob.write_bytes(b"tampered")

    with pytest.raises(ArtifactIntegrityError, match=r"SHA-256|大小"):
        store.get("ws_one", "rev_one", metadata.artifact_id)


def test_artifact_manifest_uses_strict_current_schema(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root)
    metadata = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_one",
        data=b"payload",
        media_type="application/octet-stream",
    )
    manifest_path = root / "ws_one" / "rev_one" / metadata.artifact_id / "artifact.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["unexpected"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ArtifactIntegrityError, match="manifest"):
        store.get("ws_one", "rev_one", metadata.artifact_id)


@pytest.mark.parametrize(
    "uri",
    [
        "ida-re://workspaces/ws/revisions/rev/artifacts/art?query=1",
        "ida-re://other/ws/revisions/rev/artifacts/art",
        "ida-re://workspaces/ws/revisions/rev",
    ],
)
def test_artifact_uri_rejects_non_current_shape(uri: str) -> None:
    with pytest.raises(ValueError):
        parse_artifact_uri(uri)


def test_artifact_file_group_is_materialized_atomically(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    first_source = tmp_path / "native.bin"
    second_source = tmp_path / "metadata.bin"
    first_source.write_bytes(b"native")
    second_source.write_bytes(b"metadata")

    results = store.put_files_atomic(
        (
            ArtifactFileInput(
                workspace_id="ws_one",
                revision="rev_one",
                source=first_source,
                media_type="application/octet-stream",
                name="native.bin",
            ),
            ArtifactFileInput(
                workspace_id="ws_one",
                revision="rev_one",
                source=second_source,
                media_type="application/octet-stream",
                name="metadata.bin",
            ),
        )
    )

    assert tuple(store.read_all("ws_one", "rev_one", item.artifact_id) for item in results) == (
        b"native",
        b"metadata",
    )

    target = tmp_path / "materialized" / "native.bin"
    materialized = store.materialize_uri(results[0].uri, target)
    assert materialized == results[0]
    assert target.read_bytes() == b"native"
    with pytest.raises(FileExistsError):
        store.materialize_uri(results[0].uri, target)


def test_artifact_file_group_rolls_back_only_new_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    shared_source = tmp_path / "shared.bin"
    new_source = tmp_path / "new.bin"
    failing_source = tmp_path / "failing.bin"
    shared_source.write_bytes(b"shared")
    new_source.write_bytes(b"new")
    failing_source.write_bytes(b"failure")
    shared = store.put_file(
        workspace_id="ws_one",
        revision="rev_one",
        source=shared_source,
        media_type="application/octet-stream",
        name="shared.bin",
    )
    original_put_file = store.put_file

    def fail_for_last_source(
        *,
        workspace_id: str,
        revision: str,
        source: Path,
        media_type: str,
        name: str | None = None,
    ) -> ArtifactMetadata:
        if source == failing_source:
            raise OSError("injected copy failure")
        return original_put_file(
            workspace_id=workspace_id,
            revision=revision,
            source=source,
            media_type=media_type,
            name=name,
        )

    monkeypatch.setattr(store, "put_file", fail_for_last_source)
    with pytest.raises(OSError, match="injected"):
        store.put_files_atomic(
            (
                ArtifactFileInput(
                    workspace_id="ws_one",
                    revision="rev_one",
                    source=shared_source,
                    media_type="application/octet-stream",
                    name="shared.bin",
                ),
                ArtifactFileInput(
                    workspace_id="ws_one",
                    revision="rev_one",
                    source=new_source,
                    media_type="application/octet-stream",
                    name="new.bin",
                ),
                ArtifactFileInput(
                    workspace_id="ws_one",
                    revision="rev_one",
                    source=failing_source,
                    media_type="application/octet-stream",
                    name="failing.bin",
                ),
            )
        )

    assert store.list() == (shared,)
    assert store.read_all("ws_one", "rev_one", shared.artifact_id) == b"shared"


def test_artifact_directory_publish_rolls_back_when_post_rename_sync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    calls = 0

    def fail_first_scope_sync(_path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected directory sync failure")

    monkeypatch.setattr(
        "ida_re_mcp.supervisor.artifacts._fsync_directory",
        fail_first_scope_sync,
    )

    with pytest.raises(OSError, match="injected"):
        store.put_bytes(
            workspace_id="ws_one",
            revision="rev_one",
            data=b"never partially visible",
            media_type="application/octet-stream",
        )

    scope = tmp_path / "artifacts" / "ws_one" / "rev_one"
    assert not tuple(scope.glob("art_*"))
    staging = scope / ".staging"
    assert not staging.exists() or not tuple(staging.iterdir())
    assert store.list() == ()


def test_artifact_file_group_rejects_changed_preflight_identity(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    source = tmp_path / "changed.bin"
    source.write_bytes(b"changed")

    with pytest.raises(ArtifactIntegrityError, match="预检身份"):
        store.put_files_atomic(
            (
                ArtifactFileInput(
                    workspace_id="ws_one",
                    revision="rev_one",
                    source=source,
                    media_type="application/octet-stream",
                    expected_sha256="0" * 64,
                    expected_size=len(b"changed"),
                ),
            )
        )

    assert store.list() == ()


def test_unpublished_artifact_cleanup_requires_exact_identity(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    metadata = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_candidate",
        data=b"candidate output",
        media_type="application/json",
    )

    store.discard_unpublished(metadata)

    assert store.list() == ()


def test_artifact_gc_only_removes_unretained_revision_scopes(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    retained = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_current",
        data=b"current",
        media_type="application/octet-stream",
    )
    orphan = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_orphan",
        data=b"orphan",
        media_type="application/octet-stream",
    )

    preview = store.collect_garbage(
        retained_scopes={("ws_one", "rev_current")},
        dry_run=True,
    )
    assert preview.dry_run is True
    assert preview.reclaimed_bytes > 0
    assert len(preview.removed_paths) == 1
    assert store.get("ws_one", "rev_orphan", orphan.artifact_id) == orphan

    applied = store.collect_garbage(
        retained_scopes={("ws_one", "rev_current")},
        dry_run=False,
    )
    assert applied.dry_run is False
    assert applied.reclaimed_bytes == preview.reclaimed_bytes
    assert store.get("ws_one", "rev_current", retained.artifact_id) == retained
    with pytest.raises(ArtifactNotFoundError):
        store.get("ws_one", "rev_orphan", orphan.artifact_id)


def test_artifact_gc_removes_crash_staging_inside_retained_scope_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root)
    retained = store.put_bytes(
        workspace_id="ws_one",
        revision="rev_current",
        data=b"current",
        media_type="application/octet-stream",
    )
    crash_staging = root / "ws_one" / "rev_current" / ".staging" / ".artifact-deadbeef"
    crash_staging.mkdir(parents=True)
    (crash_staging / "artifact.blob").write_bytes(b"partial")

    preview = store.collect_garbage(
        retained_scopes={("ws_one", "rev_current")},
        dry_run=True,
    )
    assert preview.removed_paths == (crash_staging,)
    assert preview.reclaimed_bytes == len(b"partial")
    assert store.get("ws_one", "rev_current", retained.artifact_id) == retained

    applied = store.collect_garbage(
        retained_scopes={("ws_one", "rev_current")},
        dry_run=False,
    )
    assert applied.removed_paths == (crash_staging,)
    assert not crash_staging.exists()
    assert store.get("ws_one", "rev_current", retained.artifact_id) == retained
