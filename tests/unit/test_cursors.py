from __future__ import annotations

from pathlib import Path

import pytest

from ida_re_mcp.supervisor.cursors import CursorCodec, CursorError, CursorPosition


def test_cursor_binds_query_and_revision(tmp_path: Path) -> None:
    codec = CursorCodec(tmp_path / "runtime" / "cursor.key")
    position = CursorPosition("search", "ws_one", "rev_one", "abcd", 50)
    cursor = codec.encode(position)

    assert (
        codec.decode(
            cursor,
            scope="search",
            workspace_id="ws_one",
            revision="rev_one",
            query_digest="abcd",
        )
        == position
    )
    with pytest.raises(CursorError):
        codec.decode(
            cursor,
            scope="search",
            workspace_id="ws_one",
            revision="rev_two",
            query_digest="abcd",
        )


def test_cursor_rejects_tampering_and_bad_key(tmp_path: Path) -> None:
    codec = CursorCodec(tmp_path / "runtime" / "cursor.key")
    cursor = codec.encode(CursorPosition("resources", None, None, "catalog", 1))
    with pytest.raises(CursorError):
        codec.decode(
            cursor[:-1] + ("A" if cursor[-1] != "A" else "B"),
            scope="resources",
            workspace_id=None,
            revision=None,
            query_digest="catalog",
        )

    key = tmp_path / "broken.key"
    key.write_bytes(b"short")
    with pytest.raises(CursorError):
        CursorCodec(key)
