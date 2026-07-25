"""绑定查询身份与 revision 的有签名 opaque cursor。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast, overload

from ida_re_mcp.supervisor._fs import atomic_write_bytes, canonical_json_bytes


class CursorError(ValueError):
    """cursor 无效、被篡改或不再匹配当前查询。"""


@dataclass(frozen=True, slots=True)
class CursorPosition:
    scope: str
    workspace_id: str | None
    revision: str | None
    query_digest: str
    offset: int


class CursorCodec:
    """用平台数据目录中的私有密钥签发无服务器会话依赖的 cursor。"""

    def __init__(self, key_path: Path) -> None:
        self._key_path = key_path.resolve()
        self._key = self._load_or_create_key()

    def encode(self, position: CursorPosition) -> str:
        if position.offset < 0:
            raise ValueError("cursor offset 不能为负")
        payload = canonical_json_bytes(
            {
                "o": position.offset,
                "q": position.query_digest,
                "r": position.revision,
                "s": position.scope,
                "w": position.workspace_id,
            }
        )
        packed = zlib.compress(payload, level=9)
        encoded = base64.urlsafe_b64encode(packed).rstrip(b"=").decode("ascii")
        signature = hmac.new(self._key, packed, hashlib.sha256).digest()[:16]
        encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        return f"cur_{encoded}.{encoded_signature}"

    def decode(
        self,
        cursor: str,
        *,
        scope: str,
        workspace_id: str | None,
        revision: str | None,
        query_digest: str,
    ) -> CursorPosition:
        if not cursor.startswith("cur_") or cursor.count(".") != 1:
            raise CursorError("cursor 格式无效")
        encoded, encoded_signature = cursor[4:].split(".", 1)
        try:
            packed = _decode_base64url(encoded)
            signature = _decode_base64url(encoded_signature)
        except (ValueError, binascii.Error) as exc:
            raise CursorError("cursor 编码无效") from exc
        expected_signature = hmac.new(self._key, packed, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(signature, expected_signature):
            raise CursorError("cursor 签名无效")
        try:
            decompressor = zlib.decompressobj()
            payload = decompressor.decompress(packed, 4_097)
            if (
                len(payload) > 4_096
                or not decompressor.eof
                or decompressor.unconsumed_tail
                or decompressor.unused_data
            ):
                raise CursorError("cursor 内容无效")
            value: object = json.loads(payload.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError, zlib.error, ValueError) as exc:
            raise CursorError("cursor 内容无效") from exc
        if not isinstance(value, dict):
            raise CursorError("cursor 内容无效")
        item = cast(dict[object, object], value)
        if set(item) != {"o", "q", "r", "s", "w"}:
            raise CursorError("cursor 内容无效")
        offset = item["o"]
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise CursorError("cursor offset 无效")
        actual = CursorPosition(
            scope=_optional_text(item["s"], required=True),
            workspace_id=_optional_text(item["w"]),
            revision=_optional_text(item["r"]),
            query_digest=_optional_text(item["q"], required=True),
            offset=offset,
        )
        if (
            actual.scope != scope
            or actual.workspace_id != workspace_id
            or actual.revision != revision
            or actual.query_digest != query_digest
        ):
            raise CursorError("cursor 已过期或不属于当前查询")
        return actual

    def _load_or_create_key(self) -> bytes:
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            key = self._key_path.read_bytes()
        except FileNotFoundError:
            key = os.urandom(32)
            try:
                atomic_write_bytes(self._key_path, key)
            except OSError:
                if not self._key_path.is_file():
                    raise
                key = self._key_path.read_bytes()
        if len(key) != 32:
            raise CursorError("cursor 私钥损坏")
        try:
            os.chmod(self._key_path, 0o600)
        except OSError:
            pass
        return key


def query_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:24]


def _decode_base64url(value: str) -> bytes:
    if not value:
        raise ValueError("空 base64url")
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ValueError("非规范 base64url")
    return decoded


@overload
def _optional_text(value: object, *, required: bool) -> str: ...


@overload
def _optional_text(value: object) -> str | None: ...


def _optional_text(value: object, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise CursorError("cursor 字符串字段无效")
    return value
