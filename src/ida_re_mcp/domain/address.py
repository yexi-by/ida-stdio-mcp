"""不同地址空间之间不可混用的显式地址引用。"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints, TypeAdapter

from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.identifiers import ImageId, ModuleId, StopId


def _validate_u64(value: str) -> str:
    if int(value, 16) > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("地址超出无符号 64 位范围")
    return value


type U64Hex = Annotated[
    str,
    StringConstraints(
        pattern=r"^0x(?:0|[1-9a-f][0-9a-f]*)$",
        max_length=18,
        strict=True,
    ),
    AfterValidator(_validate_u64),
]


class ImageAddress(StrictModel):
    """相对于程序默认加载地址的位置，不受实际调试加载地址影响。"""

    kind: Literal["image"]
    image_id: ImageId
    rva: U64Hex


class DatabaseAddress(StrictModel):
    """IDA 数据库中的地址，只能用于对应的分析版本。"""

    kind: Literal["database"]
    ea: U64Hex


class FileAddress(StrictModel):
    """原始样本中的文件偏移。"""

    kind: Literal["file"]
    offset: U64Hex


class RuntimeAddress(StrictModel):
    """程序暂停时的实际内存地址，只能用于同一个 stop_id。"""

    kind: Literal["runtime"]
    module_id: ModuleId
    va: U64Hex
    stop_id: StopId


type AddressRef = Annotated[
    ImageAddress | DatabaseAddress | FileAddress | RuntimeAddress,
    Field(discriminator="kind"),
]
type RevisionAddress = Annotated[
    ImageAddress | DatabaseAddress,
    Field(discriminator="kind"),
]
address_ref_adapter: TypeAdapter[AddressRef] = TypeAdapter(AddressRef)
