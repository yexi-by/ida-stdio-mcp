"""领域失败与协议映射所需的稳定错误分类。"""

from __future__ import annotations

from enum import StrEnum

from pydantic import JsonValue


class BusinessErrorCode(StrEnum):
    """Agent 可以据此采取修复动作的工具执行错误。"""

    REVISION_CONFLICT = "revision_conflict"
    CURSOR_STALE = "cursor_stale"
    AMBIGUOUS_REFERENCE = "ambiguous_reference"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    UNSUPPORTED = "unsupported"
    DEBUG_STATE_CONFLICT = "debug_state_conflict"
    POLICY_DENIED = "policy_denied"
    WORKER_CRASHED = "worker_crashed"
    WORKSPACE_NOT_FOUND = "workspace_not_found"
    OPERATION_NOT_FOUND = "operation_not_found"
    CHANGE_SET_INVALID = "change_set_invalid"
    PRECONDITION_FAILED = "precondition_failed"
    RESOURCE_NOT_FOUND = "resource_not_found"
    EXECUTION_FAILED = "execution_failed"


class ToolExecutionError(Exception):
    """应作为 `isError=true` 返回给 Agent 的可修复业务失败。"""

    def __init__(
        self,
        code: BusinessErrorCode,
        message: str,
        *,
        details: dict[str, JsonValue] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class ResourceRequestError(Exception):
    """资源 URI 无效或资源不存在。"""

    def __init__(self, message: str, *, uri: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.uri = uri
