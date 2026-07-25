from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import cast

from ida_re_mcp.domain.catalog import TOOL_CATALOG, build_tool_catalog

EXPECTED_CORE_TOOLS = {
    "address.inspect",
    "analysis.refine",
    "change.apply",
    "change.prepare",
    "dataflow.slice",
    "debug.breakpoints",
    "debug.control",
    "debug.establish",
    "debug.events",
    "debug.finish",
    "debug.inspect",
    "function.inspect",
    "graph.query",
    "operation.cancel",
    "operation.wait",
    "program.overview",
    "program.search",
    "report.build",
    "type.inspect",
    "workspace.create",
    "workspace.export",
    "workspace.get",
    "workspace.list",
}


def _walk_refs(value: object) -> list[str]:
    refs: list[str] = []
    if isinstance(value, Mapping):
        for key, child in cast(Mapping[object, object], value).items():
            if key == "$ref" and isinstance(child, str):
                refs.append(child)
            refs.extend(_walk_refs(child))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in cast(Sequence[object], value):
            refs.extend(_walk_refs(child))
    return refs


def test_core_catalog_is_fixed_unique_and_deterministic() -> None:
    names = [spec.name for spec in TOOL_CATALOG]
    assert set(names) == EXPECTED_CORE_TOOLS
    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) for name in names)


def test_expert_tool_is_absent_by_default_and_explicitly_enabled() -> None:
    assert "expert.execute" not in {spec.name for spec in TOOL_CATALOG}
    enabled = build_tool_catalog(enable_expert=True)
    assert [spec.name for spec in enabled] == sorted(spec.name for spec in enabled)
    assert {spec.name for spec in enabled} == EXPECTED_CORE_TOOLS | {"expert.execute"}


def test_authoring_and_debug_facets_are_startup_catalog_switches() -> None:
    minimal = build_tool_catalog(enable_authoring=False, enable_debug=False)
    minimal_names = {spec.name for spec in minimal}
    assert not any(name.startswith("debug.") for name in minimal_names)
    assert not {"analysis.refine", "change.prepare", "change.apply"} & minimal_names
    assert {"operation.wait", "workspace.create", "program.overview"} <= minimal_names


def test_all_tool_schemas_are_closed_json_schema_2020_12() -> None:
    for spec in build_tool_catalog(enable_expert=True):
        definition = spec.as_wire_definition()
        for schema_name in ("inputSchema", "outputSchema"):
            schema = definition[schema_name]
            assert isinstance(schema, dict)
            assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
            assert schema["type"] == "object"
            assert schema["additionalProperties"] is False
            assert all(ref.startswith("#/$defs/") for ref in _walk_refs(schema))


def test_all_models_use_strict_forbid_configuration() -> None:
    for spec in build_tool_catalog(enable_expert=True):
        for model_type in (spec.input_model, spec.output_model):
            assert model_type.model_config.get("strict") is True
            assert model_type.model_config.get("extra") == "forbid"
