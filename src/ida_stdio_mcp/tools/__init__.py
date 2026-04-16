"""工具注册入口。"""

from __future__ import annotations

from ..config import AppConfig
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry
from .batch import register_batch_tools
from .bytes_tools import register_byte_tools
from .core import register_core_tools
from .functions import register_function_tools
from .strings import register_string_tools
from .survey import register_survey_tools


def build_registry(runtime: HeadlessRuntime, config: AppConfig) -> ToolRegistry:
    """构建第一阶段工具注册表。"""
    registry = ToolRegistry()
    register_core_tools(registry, runtime)
    register_survey_tools(registry, runtime)
    register_function_tools(registry, runtime)
    register_string_tools(registry, runtime)
    register_byte_tools(registry, runtime)
    register_batch_tools(registry, runtime, config)
    return registry
