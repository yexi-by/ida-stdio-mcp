"""Unity IL2CPP 原生注解 bundle 公共入口。"""

from ida_re_mcp.il2cpp.bundle import (
    Bundle,
    BundleValidationError,
    ExpectedMetadata,
    ExpectedNative,
    compute_record_id,
    parse_il2cpp_bundle,
)
from ida_re_mcp.il2cpp.canonical import canonical_json_bytes, canonical_ndjson

__all__ = [
    "Bundle",
    "BundleValidationError",
    "ExpectedMetadata",
    "ExpectedNative",
    "canonical_json_bytes",
    "canonical_ndjson",
    "compute_record_id",
    "parse_il2cpp_bundle",
]
