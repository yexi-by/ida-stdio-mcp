"""IL2CPP bundle 只接受当前 canonical NDJSON 契约。"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.constants import IL2CPP_MEDIA_TYPE, IL2CPP_SCHEMA_VERSION
from ida_re_mcp.il2cpp import (
    BundleValidationError,
    ExpectedMetadata,
    ExpectedNative,
    canonical_ndjson,
    compute_record_id,
    parse_il2cpp_bundle,
)
from ida_re_mcp.il2cpp.canonical import JsonObject, JsonValue, parse_canonical_json

NATIVE_SHA256 = "11" * 32
METADATA_SHA256 = "22" * 32


def _with_id(record: JsonObject) -> JsonObject:
    value = deepcopy(record)
    value["id"] = compute_record_id(value)
    return value


def _records() -> list[JsonObject]:
    manifest: JsonObject = {
        "kind": "manifest",
        "schema": IL2CPP_SCHEMA_VERSION,
        "media_type": IL2CPP_MEDIA_TYPE,
        "native": {
            "sha256": NATIVE_SHA256,
            "size": 4096,
            "image_size": 0x5000,
            "architecture": "x86_64",
            "abi": "msvc-x64",
            "pointer_width": 64,
            "endianness": "little",
        },
        "metadata": {"sha256": METADATA_SHA256, "size": 1024},
    }
    image = _with_id(
        {
            "kind": "managed_image",
            "name": "Assembly-CSharp",
            "assembly_name": "Assembly-CSharp.dll",
        }
    )
    actor = _with_id(
        {
            "kind": "type",
            "image_id": image["id"],
            "namespace": "Game",
            "name": "Actor",
            "layout": {
                "kind": "struct",
                "size": 16,
                "alignment": 8,
                "fields": [
                    {
                        "name": "score",
                        "offset": 8,
                        "type": {"kind": "primitive", "name": "i32"},
                    }
                ],
            },
        }
    )
    method = _with_id(
        {
            "kind": "method",
            "image_id": image["id"],
            "declaring_type_id": actor["id"],
            "name": "GetScore",
            "rva": "0x1000",
            "managed_signature": {
                "return_type": "System.Int32",
                "parameters": [],
            },
            "native_signature": {
                "calling_convention": "win64",
                "return_type": {"kind": "primitive", "name": "i32"},
                "parameters": [
                    {
                        "name": "this",
                        "type": {
                            "kind": "pointer",
                            "to": {"kind": "named", "type_id": actor["id"]},
                            "const": False,
                        },
                    }
                ],
                "variadic": False,
            },
        }
    )
    symbol = _with_id(
        {
            "kind": "symbol",
            "name": "Actor_GetScore",
            "rva": "0x1000",
            "symbol_kind": "function",
            "method_id": method["id"],
            "type": None,
        }
    )
    return [manifest, image, actor, method, symbol]


def _write_bundle(path: Path, records: list[JsonObject]) -> None:
    path.write_bytes(canonical_ndjson(records))


def _expected_native() -> ExpectedNative:
    return ExpectedNative(
        NATIVE_SHA256,
        size=4096,
        image_size=0x5000,
        architecture="x86_64",
        abi="msvc-x64",
        pointer_width=64,
        endianness="little",
    )


def test_parse_valid_bundle(tmp_path: Path) -> None:
    path = tmp_path / "annotations.ndjson"
    _write_bundle(path, _records())
    bundle = parse_il2cpp_bundle(
        path,
        _expected_native(),
        ExpectedMetadata(METADATA_SHA256, size=1024),
    )
    assert bundle.record_count == 5
    assert bundle.images[0].assembly_name == "Assembly-CSharp.dll"
    assert bundle.types[0].name == "Actor"
    assert bundle.methods[0].rva == "0x1000"
    assert bundle.symbols[0].name == "Actor_GetScore"
    assert len(bundle.sha256) == 64


def test_record_ids_are_semantic_and_deterministic() -> None:
    first = _records()
    second = _records()
    assert [record.get("id") for record in first] == [record.get("id") for record in second]
    changed = deepcopy(first[2])
    changed["name"] = "OtherActor"
    assert compute_record_id(changed) != first[2]["id"]


def test_rejects_noncanonical_line(tmp_path: Path) -> None:
    path = tmp_path / "annotations.ndjson"
    payload = canonical_ndjson(_records())
    path.write_bytes(payload.replace(b'{"kind":"manifest"', b'{ "kind":"manifest"', 1))
    with pytest.raises(BundleValidationError, match="Canonicalization"):
        parse_il2cpp_bundle(path, NATIVE_SHA256, METADATA_SHA256)


def _change_native_hash(records: list[JsonObject]) -> None:
    native = cast(JsonObject, records[0]["native"])
    native["sha256"] = "33" * 32


def _change_type_id(records: list[JsonObject]) -> None:
    records[2]["id"] = "type_" + "00" * 32


def _change_method_rva(records: list[JsonObject]) -> None:
    records[3]["rva"] = "0x5000"


def _change_method_type_reference(records: list[JsonObject]) -> None:
    records[3]["declaring_type_id"] = "type_" + "ff" * 32


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            _change_native_hash,
            "native.sha256",
        ),
        (
            _change_type_id,
            "重算结果",
        ),
        (
            _change_method_rva,
            "image_size",
        ),
        (
            _change_method_type_reference,
            "未知 image/type",
        ),
    ],
)
def test_rejects_binding_identity_rva_and_reference_failures(
    tmp_path: Path,
    mutator: Callable[[list[JsonObject]], object],
    message: str,
) -> None:
    records = _records()
    mutator(records)
    if message == "未知 image/type":
        records[3]["id"] = compute_record_id(records[3])
    path = tmp_path / "annotations.ndjson"
    _write_bundle(path, records)
    with pytest.raises(BundleValidationError, match=message):
        parse_il2cpp_bundle(path, _expected_native(), ExpectedMetadata(METADATA_SHA256, 1024))


def test_rejects_unknown_fields_and_noncanonical_rva(tmp_path: Path) -> None:
    records = _records()
    records[1]["unexpected"] = cast(JsonValue, True)
    path = tmp_path / "annotations.ndjson"
    _write_bundle(path, records)
    with pytest.raises(BundleValidationError):
        parse_il2cpp_bundle(path, NATIVE_SHA256, METADATA_SHA256)

    records = _records()
    records[3]["rva"] = "0x01000"
    records[3]["id"] = compute_record_id(records[3])
    _write_bundle(path, records)
    with pytest.raises(BundleValidationError):
        parse_il2cpp_bundle(path, NATIVE_SHA256, METADATA_SHA256)


def test_rejects_missing_final_lf(tmp_path: Path) -> None:
    path = tmp_path / "annotations.ndjson"
    path.write_bytes(canonical_ndjson(_records()).removesuffix(b"\n"))
    with pytest.raises(BundleValidationError, match="LF"):
        parse_il2cpp_bundle(path, NATIVE_SHA256, METADATA_SHA256)


def _assert_bundle_rejected(
    tmp_path: Path,
    records: list[JsonObject],
    message: str,
) -> None:
    path = tmp_path / "rejected.ndjson"
    _write_bundle(path, records)
    with pytest.raises(BundleValidationError, match=message):
        parse_il2cpp_bundle(path, _expected_native(), ExpectedMetadata(METADATA_SHA256, 1024))


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        (
            [
                {
                    "name": "tail",
                    "offset": 8,
                    "type": {
                        "kind": "array",
                        "element": {"kind": "primitive", "name": "u32"},
                        "count": 3,
                    },
                }
            ],
            "字段末端",
        ),
        (
            [
                {
                    "name": "first",
                    "offset": 8,
                    "type": {"kind": "primitive", "name": "u32"},
                },
                {
                    "name": "overlap",
                    "offset": 8,
                    "type": {"kind": "primitive", "name": "u32"},
                },
            ],
            "字段发生重叠",
        ),
        (
            [
                {
                    "name": "misaligned",
                    "offset": 4,
                    "type": {"kind": "primitive", "name": "u64"},
                }
            ],
            "自然对齐",
        ),
    ],
)
def test_rejects_invalid_struct_field_ranges_and_alignment(
    tmp_path: Path,
    fields: list[JsonValue],
    message: str,
) -> None:
    records = _records()
    layout = cast(JsonObject, records[2]["layout"])
    layout["fields"] = fields
    _assert_bundle_rejected(tmp_path, records, message)


def test_rejects_invalid_aggregate_alignment_and_enum_value(tmp_path: Path) -> None:
    records = _records()
    layout = cast(JsonObject, records[2]["layout"])
    layout["alignment"] = 3
    _assert_bundle_rejected(tmp_path, records, "alignment")

    records = _records()
    layout = cast(JsonObject, records[2]["layout"])
    layout.clear()
    layout.update(
        {
            "kind": "enum",
            "underlying": "u8",
            "members": [{"name": "TooLarge", "value": 256}],
        }
    )
    _assert_bundle_rejected(tmp_path, records, "underlying")


def test_rejects_recursive_value_types_but_allows_pointer_recursion(tmp_path: Path) -> None:
    records = _records()
    actor_id = cast(str, records[2]["id"])
    layout = cast(JsonObject, records[2]["layout"])
    layout["fields"] = [
        {
            "name": "self",
            "offset": 0,
            "type": {"kind": "named", "type_id": actor_id},
        }
    ]
    _assert_bundle_rejected(tmp_path, records, "递归值类型 cycle")

    layout["fields"] = [
        {
            "name": "next",
            "offset": 0,
            "type": {
                "kind": "pointer",
                "to": {"kind": "named", "type_id": actor_id},
                "const": False,
            },
        }
    ]
    path = tmp_path / "pointer-recursion.ndjson"
    _write_bundle(path, records)
    assert parse_il2cpp_bundle(path, NATIVE_SHA256, METADATA_SHA256).types


def test_rejects_void_value_positions(tmp_path: Path) -> None:
    records = _records()
    layout = cast(JsonObject, records[2]["layout"])
    layout["fields"] = [
        {
            "name": "nothing",
            "offset": 0,
            "type": {"kind": "primitive", "name": "void"},
        }
    ]
    _assert_bundle_rejected(tmp_path, records, "void")

    records = _records()
    native_signature = cast(JsonObject, records[3]["native_signature"])
    native_signature["parameters"] = [
        {
            "name": "nothing",
            "type": {"kind": "primitive", "name": "void"},
        }
    ]
    _assert_bundle_rejected(tmp_path, records, "void")


def test_rejects_cross_image_method_and_function_rva_mismatch(tmp_path: Path) -> None:
    records = _records()
    second_image = _with_id(
        {
            "kind": "managed_image",
            "name": "Other",
            "assembly_name": "Other.dll",
        }
    )
    records.insert(2, second_image)
    method = records[4]
    method["image_id"] = second_image["id"]
    method["id"] = compute_record_id(method)
    records[5]["method_id"] = method["id"]
    _assert_bundle_rejected(tmp_path, records, "同一 managed image")

    records = _records()
    records[4]["rva"] = "0x1010"
    records[4]["id"] = compute_record_id(records[4])
    _assert_bundle_rejected(tmp_path, records, "RVA 与 method binding")


@pytest.mark.parametrize(
    ("symbol_kind", "method_id", "type_ref", "message"),
    [
        (
            "function",
            "method",
            {"kind": "primitive", "name": "u32"},
            "不得声明 data type",
        ),
        (
            "data",
            "method",
            {"kind": "primitive", "name": "u32"},
            "不得引用 method_id",
        ),
        (
            "data",
            None,
            None,
            "必须声明 type",
        ),
    ],
)
def test_rejects_nonexclusive_symbol_bindings(
    tmp_path: Path,
    symbol_kind: str,
    method_id: str | None,
    type_ref: JsonObject | None,
    message: str,
) -> None:
    records = _records()
    symbol = records[4]
    symbol["symbol_kind"] = symbol_kind
    symbol["method_id"] = records[3]["id"] if method_id is not None else None
    symbol["type"] = type_ref
    symbol["id"] = compute_record_id(symbol)
    _assert_bundle_rejected(tmp_path, records, message)


def test_rejects_data_symbol_extent_and_mixed_kind_rva_collision(tmp_path: Path) -> None:
    records = _records()
    symbol = records[4]
    symbol.update(
        {
            "name": "TailData",
            "rva": "0x4ff8",
            "symbol_kind": "data",
            "method_id": None,
            "type": {
                "kind": "array",
                "element": {"kind": "primitive", "name": "u64"},
                "count": 2,
            },
        }
    )
    symbol["id"] = compute_record_id(symbol)
    _assert_bundle_rejected(tmp_path, records, "data symbol 范围")

    records = _records()
    data_symbol = _with_id(
        {
            "kind": "symbol",
            "name": "WrongData",
            "rva": "0x1000",
            "symbol_kind": "data",
            "method_id": None,
            "type": {"kind": "primitive", "name": "u32"},
        }
    )
    records.append(data_symbol)
    _assert_bundle_rejected(tmp_path, records, "相同 RVA")


def test_rejects_reference_ids_with_the_wrong_record_kind(tmp_path: Path) -> None:
    records = _records()
    records[3]["declaring_type_id"] = records[1]["id"]
    records[3]["id"] = compute_record_id(records[3])
    records[4]["method_id"] = records[3]["id"]
    _assert_bundle_rejected(tmp_path, records, "declaring_type_id")


_REPOSITORY_ROOT = Path(__file__).parents[2]
_FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures"
_EXAMPLE_BUNDLE = _FIXTURE_DIRECTORY / "src" / "il2cpp_bundle_example.ndjson"
_EXAMPLE_NATIVE = _FIXTURE_DIRECTORY / "bin" / "il2cpp_pe_x64.dll"
_EXAMPLE_METADATA = _FIXTURE_DIRECTORY / "bin" / "il2cpp_metadata_fingerprint.bin"
_FORMAT_REFERENCE = (
    _REPOSITORY_ROOT / "skills" / "ida-re-mcp" / "references" / "il2cpp-bundle-format.md"
)
_EXAMPLE_NATIVE_SHA256 = "f7d61718ce407ed5ced0049c689aff5ee1a14332037f173d980604b2c0e97021"
_EXAMPLE_METADATA_SHA256 = "d2f9bc026488660c94b9d49485ecd1070d92483df1bd08bf946bf300fee45ee4"
_EXAMPLE_NATIVE_SIZE = 2560
_EXAMPLE_IMAGE_SIZE = 0x5000
_EXAMPLE_METADATA_SIZE = 206
_DOCUMENTED_EXAMPLE_START = b"<!-- il2cpp-bundle-example:start -->\n```ndjson\n"
_DOCUMENTED_EXAMPLE_END = b"```\n<!-- il2cpp-bundle-example:end -->"


def test_documented_example_bundle_stays_parseable() -> None:
    """守护示例与真实 PE x64、metadata fixture 的绑定关系。"""

    assert hashlib.sha256(_EXAMPLE_NATIVE.read_bytes()).hexdigest() == _EXAMPLE_NATIVE_SHA256
    assert hashlib.sha256(_EXAMPLE_METADATA.read_bytes()).hexdigest() == _EXAMPLE_METADATA_SHA256
    assert _EXAMPLE_NATIVE.stat().st_size == _EXAMPLE_NATIVE_SIZE
    assert _EXAMPLE_METADATA.stat().st_size == _EXAMPLE_METADATA_SIZE

    bundle = parse_il2cpp_bundle(
        _EXAMPLE_BUNDLE,
        ExpectedNative(
            _EXAMPLE_NATIVE_SHA256,
            size=_EXAMPLE_NATIVE_SIZE,
            image_size=_EXAMPLE_IMAGE_SIZE,
            architecture="x86_64",
            abi="msvc-x64",
            pointer_width=64,
            endianness="little",
        ),
        ExpectedMetadata(_EXAMPLE_METADATA_SHA256, size=_EXAMPLE_METADATA_SIZE),
    )
    assert bundle.record_count == 8
    assert [image.assembly_name for image in bundle.images] == ["Assembly-CSharp.dll"]
    assert {record.name for record in bundle.types} == {
        "Vec3",
        "ActorState",
        "MethodMetadata",
        "Actor",
    }
    assert {record.layout.kind for record in bundle.types} == {"struct", "enum"}
    assert [record.name for record in bundle.methods] == ["GetScore"]
    native_signature = bundle.methods[0].native_signature
    assert native_signature is not None
    assert [parameter.name for parameter in native_signature.parameters] == [
        "self",
        "bonus",
        "method",
    ]
    assert native_signature.parameters[-1].type.model_dump()["const"] is True
    assert [(record.name, record.rva) for record in bundle.symbols] == [
        ("Actor_GetScore", "0x1000")
    ]


def test_documented_example_bundle_is_canonical_ndjson() -> None:
    payload = _EXAMPLE_BUNDLE.read_bytes()
    assert not payload.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in payload
    assert payload.endswith(b"\n")
    lines = payload[:-1].split(b"\n")
    # 逐行重新 canonical 编码必须与原字节一致, 且首行是 manifest.
    assert all(canonical_ndjson([parse_canonical_json(line)]) == line + b"\n" for line in lines)
    assert parse_canonical_json(lines[0])["kind"] == "manifest"


def test_format_reference_embeds_the_exact_example_bundle() -> None:
    reference = _FORMAT_REFERENCE.read_bytes()
    prefix, separator, remainder = reference.partition(_DOCUMENTED_EXAMPLE_START)
    assert separator and prefix
    documented_bundle, separator, suffix = remainder.partition(_DOCUMENTED_EXAMPLE_END)
    assert separator and suffix
    assert documented_bundle == _EXAMPLE_BUNDLE.read_bytes()
