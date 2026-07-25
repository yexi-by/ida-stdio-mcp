"""Worker 边界使用的稳定错误类型。"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final


class WorkerError(RuntimeError):
    """可安全跨 IPC 边界传输的 worker 业务错误。"""

    code: Final[str]
    details: Final[dict[str, object]]

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, object]:
        """返回不包含异常实现细节的传输对象。"""

        result: dict[str, object] = {"code": self.code, "message": str(self)}
        if self.details:
            result["details"] = self.details
        return result


class CapabilityError(WorkerError):
    """当前 worker 运行时无法提供请求的 IDA 能力。"""

    def __init__(
        self,
        message: str,
        *,
        capability: str,
        details: Mapping[str, object] | None = None,
    ) -> None:
        merged: dict[str, object] = {"capability": capability}
        merged.update(details or {})
        super().__init__("capability_unavailable", message, details=merged)


class WorkerInputError(WorkerError):
    """当前输入不满足 worker 的新契约。"""

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__("invalid_worker_input", message, details=details)
