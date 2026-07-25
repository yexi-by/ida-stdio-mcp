from __future__ import annotations

import pytest
from pydantic import ValidationError

from ida_re_mcp.domain.address import (
    DatabaseAddress,
    FileAddress,
    ImageAddress,
    RuntimeAddress,
    address_ref_adapter,
)


def test_address_ref_distinguishes_all_address_spaces() -> None:
    assert isinstance(
        address_ref_adapter.validate_python(
            {"kind": "image", "image_id": "image_abcd", "rva": "0x1234"}
        ),
        ImageAddress,
    )
    assert isinstance(
        address_ref_adapter.validate_python({"kind": "database", "ea": "0x401000"}),
        DatabaseAddress,
    )
    assert isinstance(
        address_ref_adapter.validate_python({"kind": "file", "offset": "0x20"}),
        FileAddress,
    )
    assert isinstance(
        address_ref_adapter.validate_python(
            {
                "kind": "runtime",
                "module_id": "module_abcd",
                "va": "0x7ff600001000",
                "stop_id": "stop_abcdef",
            }
        ),
        RuntimeAddress,
    )


@pytest.mark.parametrize(
    "value",
    [
        {"kind": "database", "ea": 0x401000},
        {"kind": "database", "ea": "401000"},
        {"kind": "database", "ea": "0x0401000"},
        {"kind": "database", "ea": "0xABC"},
        {"kind": "database", "ea": "0x10000000000000000"},
        {"kind": "database", "ea": "0x401000", "rva": "0x0"},
        {"kind": "runtime", "module_id": "short", "va": "0x1", "stop_id": "stop_abcdef"},
        {"kind": "unknown", "ea": "0x1"},
    ],
)
def test_address_ref_rejects_ambiguous_or_noncanonical_values(
    value: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        address_ref_adapter.validate_python(value)
