"""IL2CPP bundle 使用的整数子集 JSON Canonicalization。"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Never, cast

SAFE_INTEGER_MAX = (1 << 53) - 1

JsonScalar = None | bool | int | str
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]


class CanonicalJsonError(ValueError):
    """输入不是本产品定义的 JCS 可验证 JSON 子集。"""


def _reject_float(_value: str) -> Never:
    raise CanonicalJsonError("canonical bundle 不允许浮点数")


def _parse_integer(value: str) -> int:
    parsed = int(value, 10)
    if abs(parsed) > SAFE_INTEGER_MAX:
        raise CanonicalJsonError("JSON 整数超出 I-JSON 安全范围")
    return parsed


def _reject_constant(value: str) -> Never:
    raise CanonicalJsonError(f"JSON 不允许非有限数值: {value}")


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError(f"JSON 对象包含重复键: {key}")
        result[key] = value
    return result


def _validate_unicode(value: JsonValue) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise CanonicalJsonError("JSON 字符串包含 Unicode surrogate")
        return
    if isinstance(value, list):
        for item in value:
            _validate_unicode(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode(key)
            _validate_unicode(item)


def parse_canonical_json(payload: bytes) -> JsonObject:
    """解析并验证单条 canonical JSON object。"""

    if payload.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJsonError("canonical JSON 不允许 UTF-8 BOM")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            parse_float=_reject_float,
            parse_int=_parse_integer,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalJsonError("无效 UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CanonicalJsonError("每条 bundle 记录必须是 JSON 对象")
    parsed = cast(JsonObject, value)
    _validate_unicode(parsed)
    if canonical_json_bytes(parsed) != payload:
        raise CanonicalJsonError("记录不符合 JSON Canonicalization")
    return parsed


def canonical_json_bytes(value: Mapping[str, JsonValue]) -> bytes:
    """编码 bundle 允许的 JCS 整数子集。"""

    normalized = dict(value)
    _validate_unicode(normalized)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_ndjson(records: Sequence[Mapping[str, JsonValue]]) -> bytes:
    """构建带末尾 LF 的 canonical NDJSON。"""

    if not records:
        raise CanonicalJsonError("bundle 至少需要一条记录")
    return b"".join(canonical_json_bytes(record) + b"\n" for record in records)
