"""补丁历史回滚校验测试。"""

from __future__ import annotations

import unittest

from ida_stdio_mcp.core.patches import decode_patch_record_bytes, ensure_rollback_matches_current
from ida_stdio_mcp.models import JsonObject


class PatchHistoryTests(unittest.TestCase):
    """验证补丁回滚前置校验。"""

    def test_decode_patch_record_bytes_requires_balanced_hex(self) -> None:
        """补丁记录必须包含可解析且等长的写入前后字节。"""
        record: JsonObject = {"before_hex": "9090", "after_hex": "cccc"}

        before, after = decode_patch_record_bytes(record, patch_id=1)

        self.assertEqual(before, b"\x90\x90")
        self.assertEqual(after, b"\xcc\xcc")

    def test_rollback_rejects_overlapping_later_patch(self) -> None:
        """当前字节不等于记录写入后字节时拒绝回滚。"""
        with self.assertRaises(RuntimeError):
            ensure_rollback_matches_current(
                patch_id=1,
                current=b"\xcc\x90",
                expected_after=b"\xcc\xcc",
            )


if __name__ == "__main__":
    unittest.main()
