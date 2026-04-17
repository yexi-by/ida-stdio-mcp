"""最小可控的 JSON schema 校验器。

这里只支持本项目真实使用到的 schema 子集：

- object / array / string / integer / boolean
- required
- additionalProperties = false
- enum
- oneOf
- x-required-any-of（项目自定义：表达“至少满足一组字段”）

设计目标不是兼容完整 JSON Schema，而是把 MCP 工具入参约束做成
可预测、可定位、可机器修复的协议层校验。

注意：顶层 anyOf/oneOf/allOf 在不少 MCP 客户端和上游模型工具接口中
都存在兼容性问题，因此项目对外暴露的 inputSchema 不再使用顶层组合关键字，
而是把“至少满足一组字段”降级成 x-required-any-of，由服务端显式校验。
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

from .errors import ToolInputValidationError
from .models import JsonObject, JsonValue


def validate_arguments(schema: JsonObject, arguments: JsonObject) -> None:
    """校验工具入参；失败时抛出结构化异常。"""
    _validate_node(schema=schema, value=arguments, path="arguments")


def _validate_node(*, schema: JsonObject, value: JsonValue, path: str) -> None:
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        _validate_one_of(one_of, value, path)
        return

    schema_type = schema.get("type")
    if schema_type == "object":
        _validate_object(schema, value, path)
        return
    if schema_type == "array":
        _validate_array(schema, value, path)
        return
    if schema_type == "string":
        _ensure_type(isinstance(value, str), path=path, expected="string", actual=value)
        _validate_enum(schema, value, path)
        return
    if schema_type == "integer":
        _ensure_type(isinstance(value, int) and not isinstance(value, bool), path=path, expected="integer", actual=value)
        assert isinstance(value, int)
        minimum = schema.get("minimum")
        if isinstance(minimum, int) and value < minimum:
            _raise_validation_error(
                path=path,
                code="value_too_small",
                message=f"{path} 不能小于 {minimum}",
                expected=f">= {minimum}",
                actual=value,
            )
        return
    if schema_type == "boolean":
        _ensure_type(isinstance(value, bool), path=path, expected="boolean", actual=value)
        return


def _validate_object(schema: JsonObject, value: JsonValue, path: str) -> None:
    _ensure_type(isinstance(value, dict), path=path, expected="object", actual=value)
    assert isinstance(value, dict)
    properties = schema.get("properties", {})
    _ensure_type(isinstance(properties, dict), path=f"{path}.properties", expected="object", actual=properties)
    assert isinstance(properties, dict)

    required = schema.get("required", [])
    _ensure_type(isinstance(required, list), path=f"{path}.required", expected="array", actual=required)
    assert isinstance(required, list)

    for required_key in required:
        if not isinstance(required_key, str):
            continue
        if required_key not in value:
            available = sorted(properties.keys())
            _raise_validation_error(
                path=f"{path}.{required_key}",
                code="missing_field",
                message=f"缺少必填字段：{required_key}",
                expected="required field",
                actual=None,
                next_steps=[
                    f"补充字段 {required_key}",
                    f"当前可用字段：{', '.join(available)}" if available else "当前 schema 未声明其他字段",
                ],
            )

    allow_extra = bool(schema.get("additionalProperties", True))
    if not allow_extra:
        unknown = sorted(key for key in value if key not in properties)
        if unknown:
            _raise_validation_error(
                path=path,
                code="unknown_field",
                message=f"{path} 存在未声明字段：{', '.join(unknown)}",
                expected=f"仅允许字段：{', '.join(sorted(str(key) for key in properties))}",
                actual=unknown,
                next_steps=["删除未声明字段", "改用 schema 中定义的字段名"],
            )

    raw_required_any_of = schema.get("x-required-any-of")
    if isinstance(raw_required_any_of, list) and raw_required_any_of:
        if not _match_required_any_of(raw_required_any_of, value):
            branches: list[str] = []
            for branch in raw_required_any_of:
                if isinstance(branch, list):
                    branches.append("/".join(str(item) for item in branch))
            _raise_validation_error(
                path=path,
                code="missing_alternative_field",
                message=f"{path} 未满足任一备选字段组合",
                expected=branches,
                actual=sorted(str(key) for key in value.keys()),
                next_steps=["按 schema 提供任一组必填字段"],
            )

    for key, property_schema in properties.items():
        if key not in value:
            continue
        if not isinstance(property_schema, dict):
            continue
        child_value = value[key]
        _validate_node(schema=property_schema, value=child_value, path=f"{path}.{key}")


def _validate_array(schema: JsonObject, value: JsonValue, path: str) -> None:
    _ensure_type(isinstance(value, list), path=path, expected="array", actual=value)
    assert isinstance(value, list)
    min_items = schema.get("minItems")
    if isinstance(min_items, int) and len(value) < min_items:
        _raise_validation_error(
            path=path,
            code="too_few_items",
            message=f"{path} 至少需要 {min_items} 个元素",
            expected=f"minItems={min_items}",
            actual=len(value),
        )
    items_schema = schema.get("items")
    _ensure_type(isinstance(items_schema, dict), path=f"{path}.items", expected="object", actual=items_schema)
    assert isinstance(items_schema, dict)
    for index, item in enumerate(value):
        _validate_node(schema=items_schema, value=item, path=f"{path}[{index}]")


def _validate_one_of(options: Sequence[JsonValue], value: JsonValue, path: str) -> None:
    last_error: ToolInputValidationError | None = None
    for option in options:
        if not isinstance(option, dict):
            continue
        try:
            _validate_node(schema=cast(JsonObject, option), value=value, path=path)
            return
        except ToolInputValidationError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    _raise_validation_error(
        path=path,
        code="invalid_one_of",
        message=f"{path} 未命中任何允许的类型分支",
        expected="oneOf",
        actual=value,
    )


def _validate_enum(schema: JsonObject, value: JsonValue, path: str) -> None:
    raw_enum = schema.get("enum")
    if not isinstance(raw_enum, list):
        return
    allowed = [item for item in raw_enum if isinstance(item, str)]
    if not isinstance(value, str):
        return
    if allowed and value not in allowed:
        _raise_validation_error(
            path=path,
            code="invalid_enum_value",
            message=f"{path} 的取值非法：{value}",
            expected=allowed,
            actual=value,
        )


def _match_required_any_of(branches: Sequence[JsonValue], value: JsonObject) -> bool:
    for branch in branches:
        if not isinstance(branch, list):
            continue
        branch_items = [item for item in branch if isinstance(item, str)]
        if len(branch_items) == len(branch) and all(item in value for item in branch_items):
            return True
    return False


def _ensure_type(condition: bool, *, path: str, expected: str, actual: object) -> None:
    if condition:
        return
    _raise_validation_error(
        path=path,
        code="invalid_type",
        message=f"{path} 类型不匹配",
        expected=expected,
        actual=_actual_type_name(actual),
    )


def _actual_type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _raise_validation_error(
    *,
    path: str,
    code: str,
    message: str,
    expected: object,
    actual: object,
    next_steps: list[str] | None = None,
) -> None:
    details: JsonObject = {
        "path": path,
        "expected": _to_json_value(expected),
        "actual": _to_json_value(actual),
    }
    raise ToolInputValidationError(
        message,
        details=details,
        next_steps=next_steps or ["根据 inputSchema 修正字段名、类型和必填项"],
    )


def _to_json_value(value: object) -> JsonValue:
    """把错误详情转换为 JSON 值。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        list_value = cast(list[object], value)
        return [_to_json_value(item) for item in list_value]
    if isinstance(value, dict):
        dict_value = cast(dict[object, object], value)
        return {str(key): _to_json_value(item) for key, item in dict_value.items()}
    return str(value)
