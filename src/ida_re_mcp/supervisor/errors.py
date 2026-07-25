"""Supervisor 持久化与状态机错误。"""

from __future__ import annotations


class SupervisorError(RuntimeError):
    """Supervisor 层可预期失败的基类。"""


class SupervisorAlreadyRunningError(SupervisorError):
    """同一运行数据目录已经由另一个 Supervisor 持有。"""


class InvalidIdentifierError(SupervisorError):
    """opaque 标识符不满足当前内部存储约束。"""


class OperationNotFoundError(SupervisorError):
    """operation 不存在或已超过保留期。"""


class OperationStateError(SupervisorError):
    """operation 状态转换非法。"""


class ArtifactNotFoundError(SupervisorError):
    """artifact 不存在。"""


class ArtifactIntegrityError(SupervisorError):
    """artifact 内容或元数据不再可信。"""


class WorkspaceNotFoundError(SupervisorError):
    """workspace 不存在。"""


class RevisionNotFoundError(SupervisorError):
    """revision 不存在或已被回收。"""


class RevisionConflictError(SupervisorError):
    """expected revision 与 workspace 当前 revision 不一致。"""


class StagingIntegrityError(SupervisorError):
    """staging 内容未通过发布前完整性校验。"""


class StorageCorruptionError(SupervisorError):
    """当前系统持久化状态损坏。"""
