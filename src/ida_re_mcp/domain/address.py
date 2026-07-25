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
    """相对于已分析镜像基址的稳定地址。"""

    kind: Literal["image"]
    image_id: ImageId
    rva: U64Hex


class DatabaseAddress(StrictModel):
    """指定 IDB revision 中的数据库有效地址。"""

    kind: Literal["database"]
    ea: U64Hex


class FileAddress(StrictModel):
    """原始样本中的文件偏移。"""

    kind: Literal["file"]
    offset: U64Hex


class RuntimeAddress(StrictModel):
    """绑定调试暂停快照的运行时虚拟地址。"""

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
