"""Unity IL2CPP 原生注解 bundle 的封闭类型模型。"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ImageRecordId = Annotated[str, StringConstraints(pattern=r"^image_[0-9a-f]{64}$")]
TypeRecordId = Annotated[str, StringConstraints(pattern=r"^type_[0-9a-f]{64}$")]
MethodRecordId = Annotated[str, StringConstraints(pattern=r"^method_[0-9a-f]{64}$")]
SymbolRecordId = Annotated[str, StringConstraints(pattern=r"^symbol_[0-9a-f]{64}$")]
CanonicalRva = Annotated[str, StringConstraints(pattern=r"^0x(?:0|[1-9a-f][0-9a-f]*)$")]
Identifier = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class StrictModel(BaseModel):
    """所有 bundle 结构都拒绝额外字段和宽松类型转换。"""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class NativeBinding(StrictModel):
    sha256: Sha256
    size: int = Field(ge=1)
    image_size: int = Field(ge=1)
    architecture: Literal["x86_64", "aarch64"]
    abi: Literal["msvc-x64", "sysv-x64", "aapcs64"]
    pointer_width: Literal[64]
    endianness: Literal["little"]

    @model_validator(mode="after")
    def validate_architecture_abi(self) -> NativeBinding:
        valid = {
            "x86_64": {"msvc-x64", "sysv-x64"},
            "aarch64": {"aapcs64"},
        }
        if self.abi not in valid[self.architecture]:
            raise ValueError("architecture 与 ABI 不匹配")
        return self


class MetadataBinding(StrictModel):
    sha256: Sha256
    size: int = Field(ge=1)


class ManifestRecord(StrictModel):
    kind: Literal["manifest"]
    schema_version: Literal["2026-07-28"] = Field(alias="schema")
    media_type: Literal["application/vnd.ida-re.il2cpp-bundle+ndjson"]
    native: NativeBinding
    metadata: MetadataBinding


class ManagedImageRecord(StrictModel):
    kind: Literal["managed_image"]
    id: ImageRecordId
    name: Identifier
    assembly_name: Identifier


PrimitiveName = Literal[
    "void",
    "bool",
    "i8",
    "u8",
    "i16",
    "u16",
    "i32",
    "u32",
    "i64",
    "u64",
    "f32",
    "f64",
    "native_int",
    "native_uint",
]


class PrimitiveTypeRef(StrictModel):
    kind: Literal["primitive"]
    name: PrimitiveName


class NamedTypeRef(StrictModel):
    kind: Literal["named"]
    type_id: TypeRecordId


class PointerTypeRef(StrictModel):
    kind: Literal["pointer"]
    to: TypeRef
    const: bool = False


class ArrayTypeRef(StrictModel):
    kind: Literal["array"]
    element: TypeRef
    count: int = Field(ge=1, le=1_000_000)


type TypeRef = Annotated[
    PrimitiveTypeRef | NamedTypeRef | PointerTypeRef | ArrayTypeRef,
    Field(discriminator="kind"),
]


class FieldDefinition(StrictModel):
    name: Identifier
    offset: int = Field(ge=0)
    type: TypeRef


class StructLayout(StrictModel):
    kind: Literal["struct"]
    size: int = Field(ge=1)
    alignment: int = Field(ge=1, le=4096)
    fields: tuple[FieldDefinition, ...]

    @model_validator(mode="after")
    def validate_fields(self) -> StructLayout:
        if self.alignment & (self.alignment - 1):
            raise ValueError("struct alignment 必须是 1 到 4096 的二次幂")
        if self.size % self.alignment:
            raise ValueError("struct size 必须是 alignment 的整数倍")
        names: set[str] = set()
        previous_offset = -1
        for field in self.fields:
            if field.name in names:
                raise ValueError(f"重复字段名: {field.name}")
            if field.offset < previous_offset or field.offset >= self.size:
                raise ValueError("字段 offset 必须有序且位于类型范围内")
            names.add(field.name)
            previous_offset = field.offset
        return self


class UnionLayout(StrictModel):
    kind: Literal["union"]
    size: int = Field(ge=1)
    alignment: int = Field(ge=1, le=4096)
    fields: tuple[FieldDefinition, ...]

    @model_validator(mode="after")
    def validate_fields(self) -> UnionLayout:
        if self.alignment & (self.alignment - 1):
            raise ValueError("union alignment 必须是 1 到 4096 的二次幂")
        if self.size % self.alignment:
            raise ValueError("union size 必须是 alignment 的整数倍")
        names = [field.name for field in self.fields]
        if len(names) != len(set(names)):
            raise ValueError("union 包含重复字段名")
        if any(field.offset != 0 for field in self.fields):
            raise ValueError("union 字段 offset 必须为 0")
        return self


class EnumMember(StrictModel):
    name: Identifier
    value: int


class EnumLayout(StrictModel):
    kind: Literal["enum"]
    underlying: Literal["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64"]
    members: tuple[EnumMember, ...]

    @model_validator(mode="after")
    def validate_members(self) -> EnumLayout:
        names = [member.name for member in self.members]
        if len(names) != len(set(names)):
            raise ValueError("enum 包含重复成员名")
        bits = int(self.underlying[1:])
        signed = self.underlying.startswith("i")
        minimum = -(1 << (bits - 1)) if signed else 0
        maximum = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        if any(not minimum <= member.value <= maximum for member in self.members):
            raise ValueError("enum 成员值超出 underlying 可表示范围")
        return self


type TypeLayout = Annotated[
    StructLayout | UnionLayout | EnumLayout,
    Field(discriminator="kind"),
]


class TypeRecord(StrictModel):
    kind: Literal["type"]
    id: TypeRecordId
    image_id: ImageRecordId
    namespace: str = Field(max_length=1024)
    name: Identifier
    layout: TypeLayout


class ManagedParameter(StrictModel):
    name: str = Field(max_length=512)
    type: Identifier


class ManagedSignature(StrictModel):
    return_type: Identifier
    parameters: tuple[ManagedParameter, ...] = Field(max_length=256)


class NativeParameter(StrictModel):
    name: str = Field(max_length=512)
    type: TypeRef


class NativeSignature(StrictModel):
    calling_convention: Literal["win64", "sysv", "aapcs64"]
    return_type: TypeRef
    parameters: tuple[NativeParameter, ...] = Field(max_length=256)
    variadic: Literal[False] = False


class MethodRecord(StrictModel):
    kind: Literal["method"]
    id: MethodRecordId
    image_id: ImageRecordId
    declaring_type_id: TypeRecordId
    name: Identifier
    rva: CanonicalRva
    managed_signature: ManagedSignature
    native_signature: NativeSignature | None


class SymbolRecord(StrictModel):
    kind: Literal["symbol"]
    id: SymbolRecordId
    name: Identifier
    rva: CanonicalRva
    symbol_kind: Literal["function", "data"]
    method_id: MethodRecordId | None = None
    type: TypeRef | None = None

    @model_validator(mode="after")
    def validate_target(self) -> SymbolRecord:
        if self.symbol_kind == "function":
            if self.method_id is None:
                raise ValueError("function symbol 必须引用 method_id")
            if self.type is not None:
                raise ValueError("function symbol 不得声明 data type")
        else:
            if self.method_id is not None:
                raise ValueError("data symbol 不得引用 method_id")
            if self.type is None:
                raise ValueError("data symbol 必须声明 type")
        return self


type BundleRecord = ManifestRecord | ManagedImageRecord | TypeRecord | MethodRecord | SymbolRecord
