"""领域模型的严格校验基类与 JSON Schema 生成入口。"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, JsonValue

type JsonObject = dict[str, JsonValue]


class StrictModel(BaseModel):
    """拒绝隐式类型转换与未声明字段的领域模型。"""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


def tool_json_schema(model_type: type[StrictModel]) -> JsonObject:
    """为 MCP 工具生成显式的 JSON Schema 2020-12。"""

    schema = model_type.model_json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    return schema
