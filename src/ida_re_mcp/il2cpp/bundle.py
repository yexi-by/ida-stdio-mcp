# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""Canonical IL2CPP NDJSON 解析、身份与引用验证。"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard, cast

from pydantic import TypeAdapter, ValidationError

from ida_re_mcp.il2cpp.canonical import (
    CanonicalJsonError,
    JsonObject,
    JsonValue,
    canonical_json_bytes,
    parse_canonical_json,
)
from ida_re_mcp.il2cpp.models import (
    ArrayTypeRef,
    BundleRecord,
    EnumLayout,
    ManagedImageRecord,
    ManifestRecord,
    MethodRecord,
    NamedTypeRef,
    NativeBinding,
    PointerTypeRef,
    PrimitiveTypeRef,
    StructLayout,
    SymbolRecord,
    TypeRecord,
    TypeRef,
    UnionLayout,
)

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_RECORDS = 1_000_000
_RECORD_ADAPTER: TypeAdapter[BundleRecord] = TypeAdapter(BundleRecord)
_PRIMITIVE_LAYOUTS: dict[str, tuple[int, int]] = {
    "bool": (1, 1),
    "i8": (1, 1),
    "u8": (1, 1),
    "i16": (2, 2),
    "u16": (2, 2),
    "i32": (4, 4),
    "u32": (4, 4),
    "f32": (4, 4),
    "i64": (8, 8),
    "u64": (8, 8),
    "f64": (8, 8),
    "native_int": (8, 8),
    "native_uint": (8, 8),
}
_ENUM_LAYOUTS: dict[str, tuple[int, int]] = {
    "i8": (1, 1),
    "u8": (1, 1),
    "i16": (2, 2),
    "u16": (2, 2),
    "i32": (4, 4),
    "u32": (4, 4),
    "i64": (8, 8),
    "u64": (8, 8),
}


class BundleValidationError(ValueError):
    """bundle 不满足当前唯一格式。"""

    def __init__(self, message: str, *, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


@dataclass(frozen=True, slots=True)
class ExpectedNative:
    """由 workspace 原样本得出的不可伪造绑定。"""

    sha256: str
    size: int | None = None
    image_size: int | None = None
    architecture: str | None = None
    abi: str | None = None
    pointer_width: int | None = None
    endianness: str | None = None


@dataclass(frozen=True, slots=True)
class ExpectedMetadata:
    """由用户明确选择的 global-metadata 文件得出的绑定。"""

    sha256: str
    size: int | None = None


@dataclass(frozen=True, slots=True)
class Bundle:
    """完成全部验证后的只读 IL2CPP 注解集合。"""

    manifest: ManifestRecord
    images: tuple[ManagedImageRecord, ...]
    types: tuple[TypeRecord, ...]
    methods: tuple[MethodRecord, ...]
    symbols: tuple[SymbolRecord, ...]
    sha256: str
    record_count: int

    def type_by_id(self) -> dict[str, TypeRecord]:
        return {record.id: record for record in self.types}

    def method_by_id(self) -> dict[str, MethodRecord]:
        return {record.id: record for record in self.methods}

    def type_ref_size(self, type_ref: TypeRef) -> int:
        """返回已验证 TypeRef 在当前 native ABI 下的字节宽度。"""

        size, _ = _type_ref_layout(
            type_ref,
            self.type_by_id(),
            self.manifest.native.pointer_width // 8,
        )
        return size


def _normalize_sha256(value: str, label: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise BundleValidationError(f"{label} 不是 SHA-256 十六进制摘要")
    if value != normalized:
        raise BundleValidationError(f"{label} 必须使用小写 SHA-256")
    return normalized


def _coerce_expected_native(
    value: ExpectedNative | Mapping[str, object] | str,
) -> ExpectedNative:
    if isinstance(value, ExpectedNative):
        return value
    if isinstance(value, str):
        return ExpectedNative(_normalize_sha256(value, "expected_native"))
    sha256 = value.get("sha256")
    if not isinstance(sha256, str):
        raise BundleValidationError("expected_native 缺少 sha256")
    return ExpectedNative(
        _normalize_sha256(sha256, "expected_native.sha256"),
        _optional_int(value, "size"),
        _optional_int(value, "image_size"),
        _optional_str(value, "architecture"),
        _optional_str(value, "abi"),
        _optional_int(value, "pointer_width"),
        _optional_str(value, "endianness"),
    )


def _coerce_expected_metadata(
    value: ExpectedMetadata | Mapping[str, object] | str,
) -> ExpectedMetadata:
    if isinstance(value, ExpectedMetadata):
        return value
    if isinstance(value, str):
        return ExpectedMetadata(_normalize_sha256(value, "expected_metadata"))
    sha256 = value.get("sha256")
    if not isinstance(sha256, str):
        raise BundleValidationError("expected_metadata 缺少 sha256")
    return ExpectedMetadata(
        _normalize_sha256(sha256, "expected_metadata.sha256"),
        _optional_int(value, "size"),
    )


def _optional_str(value: Mapping[str, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise BundleValidationError(f"{key} 必须是字符串")
    return item


def _optional_int(value: Mapping[str, object], key: str) -> int | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, int) or isinstance(item, bool):
        raise BundleValidationError(f"{key} 必须是整数")
    return item


def _identity_payload(record: Mapping[str, JsonValue]) -> JsonObject:
    kind = record.get("kind")
    keys_by_kind = {
        "managed_image": ("kind", "name", "assembly_name"),
        "type": ("kind", "image_id", "namespace", "name"),
        "method": (
            "kind",
            "image_id",
            "declaring_type_id",
            "name",
            "managed_signature",
        ),
        "symbol": ("kind", "name", "rva", "symbol_kind"),
    }
    keys = keys_by_kind.get(kind if isinstance(kind, str) else "")
    if keys is None:
        raise BundleValidationError("该记录种类没有可计算身份")
    missing = [key for key in keys if key not in record]
    if missing:
        raise BundleValidationError(f"记录身份字段缺失: {', '.join(missing)}")
    return {key: record[key] for key in keys}


def compute_record_id(record: Mapping[str, JsonValue]) -> str:
    """按稳定语义身份重新计算记录 ID。"""

    kind = record.get("kind")
    prefixes = {
        "managed_image": "image",
        "type": "type",
        "method": "method",
        "symbol": "symbol",
    }
    prefix = prefixes.get(kind if isinstance(kind, str) else "")
    if prefix is None:
        raise BundleValidationError("manifest 不具有记录 ID")
    digest = hashlib.sha256(canonical_json_bytes(_identity_payload(record))).hexdigest()
    return f"{prefix}_{digest}"


def _iter_type_refs(type_ref: TypeRef) -> list[TypeRef]:
    result = [type_ref]
    if isinstance(type_ref, PointerTypeRef):
        result.extend(_iter_type_refs(type_ref.to))
    elif isinstance(type_ref, ArrayTypeRef):
        result.extend(_iter_type_refs(type_ref.element))
    return result


def _is_named_ref(type_ref: TypeRef) -> TypeGuard[NamedTypeRef]:
    return isinstance(type_ref, NamedTypeRef)


def _all_record_refs(record: BundleRecord) -> list[TypeRef]:
    refs: list[TypeRef] = []
    if isinstance(record, TypeRecord):
        if isinstance(record.layout, (StructLayout, UnionLayout)):
            for field in record.layout.fields:
                refs.extend(_iter_type_refs(field.type))
    elif isinstance(record, MethodRecord) and record.native_signature is not None:
        refs.extend(_iter_type_refs(record.native_signature.return_type))
        for parameter in record.native_signature.parameters:
            refs.extend(_iter_type_refs(parameter.type))
    elif isinstance(record, SymbolRecord) and record.type is not None:
        refs.extend(_iter_type_refs(record.type))
    return refs


def _value_type_dependencies(type_ref: TypeRef) -> set[str]:
    """返回会把 named type 内嵌到当前值布局中的依赖。"""

    if isinstance(type_ref, NamedTypeRef):
        return {type_ref.type_id}
    if isinstance(type_ref, ArrayTypeRef):
        return _value_type_dependencies(type_ref.element)
    if isinstance(type_ref, PointerTypeRef):
        return set()
    return set()


def _validate_value_type_cycles(types: tuple[TypeRecord, ...]) -> None:
    """拒绝无法形成有限 native 对象大小的值类型递归。"""

    dependencies: dict[str, set[str]] = {}
    dependents: dict[str, set[str]] = {record.id: set() for record in types}
    for record in types:
        refs: set[str] = set()
        if isinstance(record.layout, (StructLayout, UnionLayout)):
            for field in record.layout.fields:
                refs.update(_value_type_dependencies(field.type))
        dependencies[record.id] = refs
        for type_id in refs:
            dependents[type_id].add(record.id)

    ready = [type_id for type_id, refs in dependencies.items() if not refs]
    removed: set[str] = set()
    while ready:
        type_id = ready.pop()
        if type_id in removed:
            continue
        removed.add(type_id)
        for dependent in dependents[type_id]:
            dependencies[dependent].discard(type_id)
            if not dependencies[dependent]:
                ready.append(dependent)
    cyclic = sorted(set(dependencies) - removed)
    if cyclic:
        raise BundleValidationError(
            "type layout 包含非法递归值类型 cycle: " + ", ".join(cyclic[:8])
        )


def _validate_type_ref_shape(type_ref: TypeRef, *, allow_void: bool) -> None:
    """验证 void 只出现在返回类型或 pointer target 等无宽度位置。"""

    if isinstance(type_ref, PrimitiveTypeRef):
        if type_ref.name == "void" and not allow_void:
            raise BundleValidationError("void 不得作为字段、参数或 data symbol 的值类型")
        return
    if isinstance(type_ref, PointerTypeRef):
        _validate_type_ref_shape(type_ref.to, allow_void=True)
        return
    if isinstance(type_ref, ArrayTypeRef):
        _validate_type_ref_shape(type_ref.element, allow_void=False)


def _declared_type_layout(record: TypeRecord) -> tuple[int, int]:
    layout = record.layout
    if isinstance(layout, EnumLayout):
        return _ENUM_LAYOUTS[layout.underlying]
    return layout.size, layout.alignment


def _type_ref_layout(
    type_ref: TypeRef,
    types_by_id: Mapping[str, TypeRecord],
    pointer_size: int,
) -> tuple[int, int]:
    """计算一个可内嵌 native TypeRef 的字节宽度与自然对齐。"""

    _validate_type_ref_shape(type_ref, allow_void=False)
    if isinstance(type_ref, PrimitiveTypeRef):
        return _PRIMITIVE_LAYOUTS[type_ref.name]
    if isinstance(type_ref, NamedTypeRef):
        return _declared_type_layout(types_by_id[type_ref.type_id])
    if isinstance(type_ref, PointerTypeRef):
        return pointer_size, pointer_size
    element_size, element_alignment = _type_ref_layout(
        type_ref.element,
        types_by_id,
        pointer_size,
    )
    return element_size * type_ref.count, element_alignment


def _validate_type_layouts(
    types: tuple[TypeRecord, ...],
    native: NativeBinding,
) -> None:
    _validate_value_type_cycles(types)
    types_by_id = {record.id: record for record in types}
    pointer_size = native.pointer_width // 8
    for record in types:
        layout = record.layout
        if isinstance(layout, EnumLayout):
            continue
        previous_end = 0
        for field in layout.fields:
            field_size, field_alignment = _type_ref_layout(
                field.type,
                types_by_id,
                pointer_size,
            )
            field_end = field.offset + field_size
            if field_end > layout.size:
                raise BundleValidationError(
                    f"type 字段末端超出 layout size: {record.id}.{field.name}"
                )
            if field_alignment > layout.alignment:
                raise BundleValidationError(
                    f"type 字段自然对齐超过 layout alignment: {record.id}.{field.name}"
                )
            if field.offset % field_alignment:
                raise BundleValidationError(
                    f"type 字段 offset 不满足自然对齐: {record.id}.{field.name}"
                )
            if isinstance(layout, StructLayout) and field.offset < previous_end:
                raise BundleValidationError(f"struct 字段发生重叠: {record.id}.{field.name}")
            previous_end = max(previous_end, field_end)


def _validate_callable_type_refs(
    method: MethodRecord,
    types_by_id: Mapping[str, TypeRecord],
    pointer_size: int,
) -> None:
    signature = method.native_signature
    if signature is None:
        return
    _validate_type_ref_shape(signature.return_type, allow_void=True)
    if not (
        isinstance(signature.return_type, PrimitiveTypeRef) and signature.return_type.name == "void"
    ):
        _type_ref_layout(signature.return_type, types_by_id, pointer_size)
    for parameter in signature.parameters:
        _type_ref_layout(parameter.type, types_by_id, pointer_size)


def _parse_records(payload: bytes) -> list[tuple[int, JsonObject, BundleRecord]]:
    if not payload:
        raise BundleValidationError("bundle 不能为空")
    if len(payload) > MAX_BUNDLE_BYTES:
        raise BundleValidationError("bundle 超过 64 MiB 上限")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise BundleValidationError("bundle 不允许 UTF-8 BOM", line=1)
    if b"\r" in payload:
        raise BundleValidationError("bundle 只允许 LF 换行")
    if not payload.endswith(b"\n"):
        raise BundleValidationError("bundle 必须以 LF 结束")
    lines = payload[:-1].split(b"\n")
    if len(lines) > MAX_BUNDLE_RECORDS:
        raise BundleValidationError("bundle 记录数超过上限")
    result: list[tuple[int, JsonObject, BundleRecord]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise BundleValidationError("bundle 不允许空行", line=line_number)
        try:
            raw = parse_canonical_json(line)
            record = _RECORD_ADAPTER.validate_json(line, strict=True)
        except (CanonicalJsonError, ValidationError) as exc:
            raise BundleValidationError(str(exc), line=line_number) from exc
        result.append((line_number, raw, record))
    return result


def _validate_binding(
    manifest: ManifestRecord,
    expected_native: ExpectedNative,
    expected_metadata: ExpectedMetadata,
) -> None:
    native = manifest.native
    checks: tuple[tuple[str, object, object | None], ...] = (
        ("native.sha256", native.sha256, expected_native.sha256),
        ("native.size", native.size, expected_native.size),
        ("native.image_size", native.image_size, expected_native.image_size),
        ("native.architecture", native.architecture, expected_native.architecture),
        ("native.abi", native.abi, expected_native.abi),
        ("native.pointer_width", native.pointer_width, expected_native.pointer_width),
        ("native.endianness", native.endianness, expected_native.endianness),
        ("metadata.sha256", manifest.metadata.sha256, expected_metadata.sha256),
        ("metadata.size", manifest.metadata.size, expected_metadata.size),
    )
    for field, actual, expected in checks:
        if expected is not None and actual != expected:
            raise BundleValidationError(f"{field} 与 workspace 绑定不一致")


def _validate_rva(rva: str, native: NativeBinding, label: str) -> None:
    value = int(rva, 16)
    if value >= native.image_size:
        raise BundleValidationError(f"{label} 超出 native image_size")


def _validate_graph(records: list[tuple[int, JsonObject, BundleRecord]]) -> Bundle:
    manifest = cast(ManifestRecord, records[0][2])
    images = tuple(record for _, _, record in records if isinstance(record, ManagedImageRecord))
    types = tuple(record for _, _, record in records if isinstance(record, TypeRecord))
    methods = tuple(record for _, _, record in records if isinstance(record, MethodRecord))
    symbols = tuple(record for _, _, record in records if isinstance(record, SymbolRecord))

    all_ids: set[str] = set()
    for line_number, raw, record in records[1:]:
        record_id = getattr(record, "id", None)
        if not isinstance(record_id, str):
            raise BundleValidationError("非 manifest 记录缺少 id", line=line_number)
        if record_id in all_ids:
            raise BundleValidationError("bundle 包含重复 id", line=line_number)
        if record_id != compute_record_id(raw):
            raise BundleValidationError("记录 id 与服务端重算结果不一致", line=line_number)
        all_ids.add(record_id)

    image_ids = {record.id for record in images}
    types_by_id = {record.id: record for record in types}
    type_ids = set(types_by_id)
    methods_by_id = {record.id: record for record in methods}
    method_ids = set(methods_by_id)
    for record in types:
        if record.image_id not in image_ids:
            raise BundleValidationError(f"type 引用了未知 image_id: {record.id}")
    expected_cc = {
        "msvc-x64": "win64",
        "sysv-x64": "sysv",
        "aapcs64": "aapcs64",
    }[manifest.native.abi]
    for record in methods:
        if record.image_id not in image_ids or record.declaring_type_id not in type_ids:
            raise BundleValidationError(f"method 引用了未知 image/type: {record.id}")
        if types_by_id[record.declaring_type_id].image_id != record.image_id:
            raise BundleValidationError(
                f"method 与 declaring type 不属于同一 managed image: {record.id}"
            )
        _validate_rva(record.rva, manifest.native, f"method {record.id} rva")
        if (
            record.native_signature is not None
            and record.native_signature.calling_convention != expected_cc
        ):
            raise BundleValidationError(
                f"method native calling convention 与 ABI 不一致: {record.id}"
            )
    seen_symbol_rvas: set[str] = set()
    for record in symbols:
        _validate_rva(record.rva, manifest.native, f"symbol {record.id} rva")
        if record.rva in seen_symbol_rvas:
            raise BundleValidationError("bundle 包含相同 RVA 的重复 symbol")
        seen_symbol_rvas.add(record.rva)
        if record.method_id is not None and record.method_id not in method_ids:
            raise BundleValidationError(f"symbol 引用了未知 method_id: {record.id}")
        if record.symbol_kind == "function":
            assert record.method_id is not None
            if methods_by_id[record.method_id].rva != record.rva:
                raise BundleValidationError(
                    f"function symbol RVA 与 method binding 不一致: {record.id}"
                )
    for _, _, record in records:
        for type_ref in _all_record_refs(record):
            if _is_named_ref(type_ref) and type_ref.type_id not in type_ids:
                raise BundleValidationError(f"记录引用了未知 type_id: {type_ref.type_id}")
    _validate_type_layouts(types, manifest.native)
    pointer_size = manifest.native.pointer_width // 8
    for method in methods:
        _validate_callable_type_refs(method, types_by_id, pointer_size)
    for symbol in symbols:
        if symbol.type is None:
            continue
        symbol_size, _ = _type_ref_layout(symbol.type, types_by_id, pointer_size)
        if int(symbol.rva, 16) + symbol_size > manifest.native.image_size:
            raise BundleValidationError(f"data symbol 范围超出 native image_size: {symbol.id}")

    return Bundle(
        manifest=manifest,
        images=images,
        types=types,
        methods=methods,
        symbols=symbols,
        sha256="",
        record_count=len(records),
    )


def parse_il2cpp_bundle(
    path: Path,
    expected_native: ExpectedNative | Mapping[str, object] | str,
    expected_metadata: ExpectedMetadata | Mapping[str, object] | str,
) -> Bundle:
    """读取并完整验证 canonical IL2CPP NDJSON。

    本函数只解析本地声明文件, 不执行、导入或探测任何外部分析器。
    """

    bundle_path = path.resolve(strict=True)
    if not bundle_path.is_file():
        raise BundleValidationError("bundle path 必须是普通文件")
    payload = bundle_path.read_bytes()
    records = _parse_records(payload)
    if not records or not isinstance(records[0][2], ManifestRecord):
        raise BundleValidationError("bundle 第一条记录必须是 manifest", line=1)
    phases = {
        ManifestRecord: 0,
        ManagedImageRecord: 1,
        TypeRecord: 2,
        MethodRecord: 3,
        SymbolRecord: 4,
    }
    previous = -1
    manifest_count = 0
    for line_number, _, record in records:
        phase = phases[type(record)]
        if phase < previous:
            raise BundleValidationError("bundle 记录顺序不合法", line=line_number)
        if isinstance(record, ManifestRecord):
            manifest_count += 1
        previous = phase
    if manifest_count != 1:
        raise BundleValidationError("bundle 必须且只能包含一个 manifest")
    expected_native_value = _coerce_expected_native(expected_native)
    expected_metadata_value = _coerce_expected_metadata(expected_metadata)
    _validate_binding(
        records[0][2],
        expected_native_value,
        expected_metadata_value,
    )
    bundle = _validate_graph(records)
    return Bundle(
        manifest=bundle.manifest,
        images=bundle.images,
        types=bundle.types,
        methods=bundle.methods,
        symbols=bundle.symbols,
        sha256=hashlib.sha256(payload).hexdigest(),
        record_count=bundle.record_count,
    )
