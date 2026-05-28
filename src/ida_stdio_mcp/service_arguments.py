"""MCP 工具参数读取与类型收窄。"""

from __future__ import annotations

from typing import cast

from .models import JsonObject, JsonValue


def require_string(arguments: JsonObject, key: str) -> str:
    """读取必填字符串参数。"""
    value = arguments.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串")
    return value


def string_or_default(arguments: JsonObject, key: str, default: str = "") -> str:
    """读取可选字符串，不合法时立即报错。"""
    value = arguments.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串")
    return value


def int_or_default(arguments: JsonObject, key: str, default: int) -> int:
    """读取可选整数，不接受隐式字符串或复合对象。"""
    value = arguments.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} 必须是整数")
    return value


def bool_or_default(arguments: JsonObject, key: str, default: bool = False) -> bool:
    """读取可选布尔值。"""
    value = arguments.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{key} 必须是布尔值")
    return value


def string_list(arguments: JsonObject, key: str) -> list[str]:
    """读取字符串列表参数。"""
    value = arguments.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} 必须是字符串列表")
    return [str(item) for item in value]


def int_list(arguments: JsonObject, key: str) -> list[int]:
    """读取整数列表参数。"""
    value = arguments.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} 必须是整数列表")
    result: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(f"{key} 内部元素必须是整数")
        result.append(item)
    return result


def optional_query_list(arguments: JsonObject) -> list[str] | None:
    """读取可选批量查询列表或单个 query/addr。"""
    raw_queries = arguments.get("items")
    if isinstance(raw_queries, list):
        return [str(item) for item in raw_queries]
    for key in ("query", "addr"):
        value = arguments.get(key)
        if isinstance(value, str):
            return [value]
    return None


def json_object_list(arguments: JsonObject, key: str) -> list[JsonObject]:
    """读取 JSON 对象列表参数。"""
    value = arguments.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} 必须是对象列表")
    result: list[JsonObject] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{key} 内部元素必须是对象")
        result.append(cast(JsonObject, item))
    return result


def query_filter(arguments: JsonObject) -> str:
    """读取函数或符号筛选文本。"""
    return string_or_default(arguments, "filter", "")


def search_text(arguments: JsonObject) -> str:
    """读取必填搜索文本 pattern。"""
    value = arguments.get("pattern")
    if isinstance(value, str):
        return value
    raise ValueError("必须提供 pattern")


def addr_list(arguments: JsonObject, key: str) -> list[str]:
    """读取地址列表，支持单个 addr 作为快捷输入。"""
    value = arguments.get(key)
    if isinstance(value, list):
        return [str(item) for item in value]
    single = arguments.get("addr")
    if isinstance(single, str):
        return [single]
    raise ValueError(f"{key} 必须是地址列表，或提供单个 addr")


def root_queries(arguments: JsonObject) -> list[str]:
    """读取调用图根函数列表。"""
    raw_roots = arguments.get("items")
    if isinstance(raw_roots, list):
        return [str(item) for item in raw_roots]
    for key in ("query", "addr"):
        value = arguments.get(key)
        if isinstance(value, str):
            return [value]
    raise ValueError("必须提供 items，或提供 query/addr")


def addr_or_query(arguments: JsonObject) -> str:
    """读取地址或名称查询参数。"""
    for key in ("addr", "query"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    raise ValueError("必须提供 addr 或 query")


def int_value(value: JsonValue) -> str | int:
    """读取可作为整数写入值的字符串或整数。"""
    if isinstance(value, (str, int)):
        return value
    raise ValueError("value 必须是字符串或整数")
