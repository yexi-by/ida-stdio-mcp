"""IL2CPP mutation 必须把声明布局完整物化为 IDA 类型。"""

from __future__ import annotations

from types import SimpleNamespace
from typing import ClassVar, Literal, cast

import pytest

from ida_re_mcp.il2cpp.models import (
    EnumLayout,
    EnumMember,
    FieldDefinition,
    NativeSignature,
    PrimitiveTypeRef,
    StructLayout,
    TypeRecord,
    UnionLayout,
)
from ida_re_mcp.worker._ida import IdaModules
from ida_re_mcp.worker.mutation import MutationWorker

_IMAGE_ID = "image_" + "11" * 32


class _FakeVector(list[object]):
    def push_back(self, value: object) -> None:
        self.append(value)

    def size(self) -> int:
        return len(self)


class _FakeUdtData(_FakeVector):
    def __init__(self) -> None:
        super().__init__()
        self.total_size = 0
        self.unpadded_size = 0
        self.effalign = 0
        self.sda = 0
        self.is_union = False
        self.taudt_bits = 0


class _FakeEnumData(_FakeVector):
    def __init__(self) -> None:
        super().__init__()
        self.radix: tuple[int, bool] | None = None

    def set_enum_radix(self, radix: int, signed: bool) -> None:
        self.radix = (radix, signed)


class _FakeFunctionData(_FakeVector):
    def __init__(self) -> None:
        super().__init__()
        self.calling_convention: int | None = None
        self.rettype: _FakeTinfo | None = None

    def set_cc(self, value: int) -> None:
        self.calling_convention = value


class _FakeMember:
    name = ""
    offset = 0
    size = 0
    type: _FakeTinfo
    effalign = 0


class _FakeEnumMember:
    name = ""
    value = 0


class _FakeTinfo:
    def __init__(self, primitive: int | None = None) -> None:
        self.size_bytes: int = 0 if primitive is None else _FakeTypeinf.PRIMITIVE_SIZES[primitive]
        self.udt: _FakeUdtData | None = None
        self.enum: _FakeEnumData | None = None
        self.enum_sign: int | None = None
        self.function: _FakeFunctionData | None = None

    def create_array(self, element: _FakeTinfo, count: int) -> bool:
        self.size_bytes = element.size_bytes * count
        return True

    def create_udt(self, members: _FakeUdtData, kind: int) -> bool:
        self.udt = members
        if kind == _FakeTypeinf.BTF_UNION:
            self.size_bytes = (
                max(
                    (cast(_FakeMember, member).size for member in members),
                    default=0,
                )
                // 8
            )
        elif members.taudt_bits & _FakeTypeinf.TAUDT_FIXED:
            self.size_bytes = members.total_size
        else:
            self.size_bytes = (
                max(
                    (
                        cast(_FakeMember, member).offset + cast(_FakeMember, member).size
                        for member in members
                    ),
                    default=0,
                )
                // 8
            )
        return True

    def create_enum(self, members: _FakeEnumData) -> bool:
        self.enum = members
        self.size_bytes = 4
        return True

    def create_func(self, function: _FakeFunctionData) -> bool:
        self.function = function
        return True

    def set_enum_width(self, width: int) -> int:
        self.size_bytes = width
        return _FakeTypeinf.TERR_OK

    def set_enum_sign(self, sign: int) -> int:
        self.enum_sign = sign
        return _FakeTypeinf.TERR_OK

    def get_size(self) -> int:
        return self.size_bytes


class _FakeTypeinf:
    BTF_VOID = 1
    BTF_BOOL = 2
    BTF_INT8 = 3
    BTF_UINT8 = 4
    BTF_INT16 = 5
    BTF_UINT16 = 6
    BTF_INT32 = 7
    BTF_UINT32 = 8
    BTF_INT64 = 9
    BTF_UINT64 = 10
    BTF_FLOAT = 11
    BTF_DOUBLE = 12
    BTF_STRUCT = 13
    BTF_UNION = 14
    TAUDT_FIXED = 0x400
    TERR_OK = 0
    type_signed = 21
    type_unsigned = 22
    CM_CC_CDECL = 31
    CM_CC_FASTCALL = 32
    PRIMITIVE_SIZES: ClassVar[dict[int, int]] = {
        BTF_VOID: 0,
        BTF_BOOL: 1,
        BTF_INT8: 1,
        BTF_UINT8: 1,
        BTF_INT16: 2,
        BTF_UINT16: 2,
        BTF_INT32: 4,
        BTF_UINT32: 4,
        BTF_INT64: 8,
        BTF_UINT64: 8,
        BTF_FLOAT: 4,
        BTF_DOUBLE: 8,
    }

    @staticmethod
    def tinfo_t(primitive: int | None = None) -> _FakeTinfo:
        return _FakeTinfo(primitive)

    @staticmethod
    def udt_type_data_t() -> _FakeUdtData:
        return _FakeUdtData()

    @staticmethod
    def udm_t() -> _FakeMember:
        return _FakeMember()

    @staticmethod
    def enum_type_data_t() -> _FakeEnumData:
        return _FakeEnumData()

    @staticmethod
    def edm_t() -> _FakeEnumMember:
        return _FakeEnumMember()

    @staticmethod
    def func_type_data_t() -> _FakeFunctionData:
        return _FakeFunctionData()


def _api() -> IdaModules:
    return cast(IdaModules, SimpleNamespace(ida_typeinf=_FakeTypeinf()))


class _TestMutationWorker(MutationWorker):
    def build_type(
        self,
        api: IdaModules,
        record: TypeRecord,
        pointer_width: int,
    ) -> object:
        return self._build_type(api, record, {}, pointer_width)

    def build_function_type(
        self,
        api: IdaModules,
        signature: NativeSignature,
        pointer_width: int,
    ) -> object:
        return self._build_function_type(api, signature, {}, pointer_width)


def _record(
    suffix: str,
    layout: StructLayout | UnionLayout | EnumLayout,
) -> TypeRecord:
    return TypeRecord(
        kind="type",
        id="type_" + suffix * 64,
        image_id=_IMAGE_ID,
        namespace="Game",
        name=f"Layout{suffix}",
        layout=layout,
    )


def _build(record: TypeRecord, pointer_width: int = 64) -> _FakeTinfo:
    return cast(
        _FakeTinfo,
        _TestMutationWorker().build_type(_api(), record, pointer_width),
    )


def test_struct_tail_padding_materializes_declared_size() -> None:
    record = _record(
        "2",
        StructLayout(
            kind="struct",
            size=16,
            alignment=8,
            fields=(
                FieldDefinition(
                    name="value",
                    offset=0,
                    type=PrimitiveTypeRef(kind="primitive", name="u32"),
                ),
            ),
        ),
    )

    result = _build(record)

    assert result.get_size() == 16
    assert result.udt is not None
    assert result.udt.total_size == 16
    assert result.udt.unpadded_size == 4
    assert result.udt.taudt_bits == _FakeTypeinf.TAUDT_FIXED
    assert result.udt.size() == 1
    value = cast(_FakeMember, result.udt[0])
    assert (value.name, value.offset, value.size) == ("value", 0, 32)


def test_empty_struct_materializes_declared_size_without_fake_fields() -> None:
    record = _record(
        "3",
        StructLayout(kind="struct", size=8, alignment=8, fields=()),
    )

    result = _build(record)

    assert result.get_size() == 8
    assert result.udt is not None
    assert result.udt.total_size == 8
    assert result.udt.unpadded_size == 0
    assert result.udt.taudt_bits == _FakeTypeinf.TAUDT_FIXED
    assert result.udt.size() == 0


def test_union_gets_full_width_storage_at_offset_zero() -> None:
    record = _record(
        "4",
        UnionLayout(
            kind="union",
            size=16,
            alignment=8,
            fields=(
                FieldDefinition(
                    name="code",
                    offset=0,
                    type=PrimitiveTypeRef(kind="primitive", name="u32"),
                ),
            ),
        ),
    )

    result = _build(record)

    assert result.get_size() == 16
    assert result.udt is not None
    assert result.udt.is_union is True
    code, storage = (cast(_FakeMember, member) for member in result.udt)
    assert (code.name, code.offset, code.size) == ("code", 0, 32)
    assert storage.name.startswith("__ida_re_storage_")
    assert (storage.offset, storage.size, storage.type.get_size()) == (0, 128, 16)


def test_enum_underlying_controls_width_sign_and_member_encoding() -> None:
    record = _record(
        "5",
        EnumLayout(
            kind="enum",
            underlying="i16",
            members=(
                EnumMember(name="Unknown", value=-1),
                EnumMember(name="Ready", value=1),
            ),
        ),
    )

    result = _build(record)

    assert result.get_size() == 2
    assert result.enum_sign == _FakeTypeinf.type_signed
    assert result.enum is not None
    assert result.enum.radix == (10, True)
    assert [
        (cast(_FakeEnumMember, member).name, cast(_FakeEnumMember, member).value)
        for member in result.enum
    ] == [("Unknown", (1 << 64) - 1), ("Ready", 1)]


@pytest.mark.parametrize(
    ("name", "pointer_width", "expected_size"),
    [
        ("native_int", 32, 4),
        ("native_uint", 32, 4),
        ("native_int", 64, 8),
        ("native_uint", 64, 8),
    ],
)
def test_native_integer_materializes_pointer_width(
    name: Literal["native_int", "native_uint"],
    pointer_width: int,
    expected_size: int,
) -> None:
    record = _record(
        "6",
        StructLayout(
            kind="struct",
            size=expected_size,
            alignment=expected_size,
            fields=(
                FieldDefinition(
                    name="value",
                    offset=0,
                    type=PrimitiveTypeRef(kind="primitive", name=name),
                ),
            ),
        ),
    )

    result = _build(record, pointer_width)

    assert result.get_size() == expected_size
    assert result.udt is not None
    value = cast(_FakeMember, result.udt[0])
    assert value.type.get_size() == expected_size


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("cdecl", _FakeTypeinf.CM_CC_CDECL),
        ("win64", _FakeTypeinf.CM_CC_FASTCALL),
        ("sysv", _FakeTypeinf.CM_CC_CDECL),
        ("aapcs32", _FakeTypeinf.CM_CC_CDECL),
        ("aapcs64", _FakeTypeinf.CM_CC_CDECL),
    ],
)
def test_native_calling_conventions_use_ida_constants(
    name: Literal["cdecl", "win64", "sysv", "aapcs32", "aapcs64"],
    expected: int,
) -> None:
    signature = NativeSignature(
        calling_convention=name,
        return_type=PrimitiveTypeRef(kind="primitive", name="void"),
        parameters=(),
        variadic=False,
    )

    result = cast(
        _FakeTinfo,
        _TestMutationWorker().build_function_type(_api(), signature, 64),
    )

    assert result.function is not None
    assert result.function.calling_convention == expected
