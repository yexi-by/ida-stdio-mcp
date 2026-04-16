"""项目内统一异常定义。"""

from __future__ import annotations


class IdaStdioMcpError(RuntimeError):
    """项目基础异常。"""


class ConfigurationError(IdaStdioMcpError):
    """配置错误。"""


class RuntimeNotReadyError(IdaStdioMcpError):
    """IDA 运行时尚未准备好。"""


class BinaryNotOpenError(IdaStdioMcpError):
    """当前没有激活的数据库。"""


class ToolExecutionError(IdaStdioMcpError):
    """工具执行失败。"""
