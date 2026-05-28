"""补丁历史记录校验工具。"""

from __future__ import annotations

from ..models import JsonObject


def decode_patch_record_bytes(record: JsonObject, *, patch_id: int) -> tuple[bytes, bytes]:
    """读取补丁记录中的写入前和写入后字节。"""
    before_hex = record.get("before_hex")
    after_hex = record.get("after_hex")
    if not isinstance(before_hex, str) or not isinstance(after_hex, str):
        raise ValueError(f"补丁记录缺少 before_hex/after_hex：{patch_id}")
    try:
        before = bytes.fromhex(before_hex)
        after = bytes.fromhex(after_hex)
    except ValueError as exc:
        raise ValueError(f"补丁记录字节不是合法十六进制：{patch_id}") from exc
    if len(before) != len(after):
        raise ValueError(f"补丁记录写入前后长度不一致：{patch_id}")
    return before, after


def ensure_rollback_matches_current(*, patch_id: int, current: bytes, expected_after: bytes) -> None:
    """确认回滚目标仍处于该补丁写入后的字节状态。"""
    if current != expected_after:
        raise RuntimeError(
            f"当前字节与补丁记录不一致：{patch_id}；"
            "请先回滚后续重叠补丁，或重新确认当前补丁历史"
        )
