"""ida-re-mcp 的公开领域契约。"""

from ida_re_mcp.domain.address import (
    AddressRef,
    DatabaseAddress,
    FileAddress,
    ImageAddress,
    RevisionAddress,
    RuntimeAddress,
    U64Hex,
    address_ref_adapter,
)
from ida_re_mcp.domain.base import JsonObject, StrictModel, current_json_schema
from ida_re_mcp.domain.catalog import (
    AUTHORING_TOOL_SPECS,
    CORE_TOOL_SPECS,
    DEBUG_TOOL_SPECS,
    EXPERT_TOOL_SPEC,
    TOOL_CATALOG,
    TOOL_CATALOG_BY_NAME,
    ToolSpec,
    build_tool_catalog,
)
from ida_re_mcp.domain.common import Coverage, Evidence, Provenance, StaticQuery
from ida_re_mcp.domain.errors import (
    BusinessErrorCode,
    ResourceRequestError,
    ToolExecutionError,
)
from ida_re_mcp.domain.resources import (
    ArtifactUri,
    BinaryResourceData,
    ResourceData,
    ResourceDescriptor,
    ResourcePage,
    ResourceRead,
    TextResourceData,
)

__all__ = [
    "AUTHORING_TOOL_SPECS",
    "CORE_TOOL_SPECS",
    "DEBUG_TOOL_SPECS",
    "EXPERT_TOOL_SPEC",
    "TOOL_CATALOG",
    "TOOL_CATALOG_BY_NAME",
    "AddressRef",
    "ArtifactUri",
    "BinaryResourceData",
    "BusinessErrorCode",
    "Coverage",
    "DatabaseAddress",
    "Evidence",
    "FileAddress",
    "ImageAddress",
    "JsonObject",
    "Provenance",
    "ResourceData",
    "ResourceDescriptor",
    "ResourcePage",
    "ResourceRead",
    "ResourceRequestError",
    "RevisionAddress",
    "RuntimeAddress",
    "StaticQuery",
    "StrictModel",
    "TextResourceData",
    "ToolExecutionError",
    "ToolSpec",
    "U64Hex",
    "address_ref_adapter",
    "build_tool_catalog",
    "current_json_schema",
]
