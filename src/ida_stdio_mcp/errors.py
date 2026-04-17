"""项目内统一异常定义。"""

from __future__ import annotations

from .models import JsonObject


class IdaStdioMcpError(RuntimeError):
    """项目基础异常。"""


class ConfigurationError(IdaStdioMcpError):
    """配置错误。"""


class RuntimeNotReadyError(IdaStdioMcpError):
    """IDA 运行时尚未准备好。"""


class BinaryNotOpenError(IdaStdioMcpError):
    """当前没有激活的数据库。"""


class SessionRequiredError(BinaryNotOpenError):
    """当前调用要求存在已绑定的活动会话。"""


class SessionNotFoundError(IdaStdioMcpError):
    """请求的会话不存在。"""


class ToolExecutionError(IdaStdioMcpError):
    """工具执行失败。"""


class ToolInputValidationError(IdaStdioMcpError):
    """工具输入不符合 schema。"""

    def __init__(self, message: str, *, details: JsonObject, next_steps: list[str] | None = None) -> None:
        super().__init__(message)
        self.details = details
        self.next_steps = next_steps or []
