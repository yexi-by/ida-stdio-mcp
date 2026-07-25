"""公开句柄类型。句柄只具备不透明字符串语义。"""

from typing import Annotated

from pydantic import StringConstraints

type OpaqueId = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._~-]*$",
        strict=True,
    ),
]

type WorkspaceId = OpaqueId
type RevisionId = OpaqueId
type EntityId = OpaqueId
type DebugSessionId = OpaqueId
type StopId = OpaqueId
type Cursor = OpaqueId
type OperationId = OpaqueId
type ArtifactId = OpaqueId
type ChangeSetId = OpaqueId
type ChangeId = OpaqueId
type ImageId = OpaqueId
type ModuleId = OpaqueId
