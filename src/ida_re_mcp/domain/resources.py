"""不可变 artifact 的资源目录与读取结果。"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints

from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.identifiers import Cursor

_OPAQUE_URI_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._~-]{7,255}"
_ARTIFACT_URI_PATTERN = (
    rf"^ida-re://workspaces/{_OPAQUE_URI_SEGMENT}"
    rf"/revisions/{_OPAQUE_URI_SEGMENT}"
    rf"/artifacts/{_OPAQUE_URI_SEGMENT}$"
)

type ArtifactUri = Annotated[
    str,
    StringConstraints(pattern=_ARTIFACT_URI_PATTERN, strict=True),
]


class ResourceDescriptor(StrictModel):
    """`resources/list` 暴露的不可变 artifact 描述。"""

    uri: ArtifactUri
    name: str = Field(min_length=1, max_length=256)
    title: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=2_048)
    mime_type: str = Field(min_length=3, max_length=128)
    size_bytes: int = Field(ge=0)


class ResourcePage(StrictModel):
    """Supervisor 返回给协议层的资源分页。"""

    resources: list[ResourceDescriptor] = Field(max_length=200)
    next_cursor: Cursor | None = None


class TextResourceData(StrictModel):
    """UTF-8 文本资源块。"""

    kind: Literal["text"]
    uri: ArtifactUri
    mime_type: str
    text: str


def _validate_base64(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("blob 必须是有效 base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("blob 必须使用规范 base64 编码")
    return value


type Base64Text = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9+/]*={0,2}$", strict=True),
    AfterValidator(_validate_base64),
]


class BinaryResourceData(StrictModel):
    """以 base64 表达的二进制资源块。"""

    kind: Literal["blob"]
    uri: ArtifactUri
    mime_type: str
    blob: Base64Text


type ResourceData = Annotated[
    TextResourceData | BinaryResourceData,
    Field(discriminator="kind"),
]


class ResourceRead(StrictModel):
    """Supervisor 返回给协议层的资源读取结果。"""

    contents: list[ResourceData] = Field(min_length=1, max_length=64)
