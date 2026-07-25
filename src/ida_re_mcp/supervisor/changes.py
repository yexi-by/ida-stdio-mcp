"""绑定 revision preimage 的不可变 ChangeSet 内容寻址存储。"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from ida_re_mcp.constants import MAX_IL2CPP_TYPE_RESOLUTIONS, PROTOCOL_VERSION
from ida_re_mcp.domain.address import RevisionAddress
from ida_re_mcp.domain.tools import ByteHex, CanonicalTypeRef, Sha256
from ida_re_mcp.il2cpp.models import NativeBinding
from ida_re_mcp.supervisor._fs import (
    atomic_write_bytes,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    validate_identifier,
    validate_sha256,
)
from ida_re_mcp.supervisor._process_lock import interprocess_file_lock
from ida_re_mcp.supervisor.artifacts import parse_artifact_uri
from ida_re_mcp.supervisor.errors import InvalidIdentifierError

_RECORD_NAME = "change-set.json"
_HASH_NAME = "change-set.sha256"
_STAGING_NAME = ".staging"
_DATABASE_NAME = "database.i64"
_CHANGE_SET_DIRECTORY_PATTERN = re.compile(r"^cset_[0-9a-f]{64}$")
_STAGING_DIRECTORY_PATTERN = re.compile(r"^\.prepare-[a-z0-9_]{8}$")
_STAGING_TEMPORARY_PATTERN = re.compile(
    r"^\.(change-set\.json|change-set\.sha256)\.[a-z0-9_]{8}\.tmp$"
)

type ArtifactUri = Annotated[
    str,
    StringConstraints(
        pattern=r"^ida-re://workspaces/[^/\s]+/revisions/[^/\s]+/artifacts/[^/\s]+$",
        strict=True,
    ),
]


class ChangeSetError(RuntimeError):
    """ChangeSet 存储的可预期失败。"""


class ChangeSetNotFoundError(ChangeSetError):
    """指定 ChangeSet 不存在。"""


class ChangeSetValidationError(ChangeSetError):
    """待准备计划不满足当前严格 schema。"""


class ChangeSetMismatchError(ChangeSetError):
    """调用方提交的 apply 身份与不可变计划不一致。"""


class ChangeSetIntegrityError(ChangeSetError):
    """ChangeSet 文件、摘要或路径身份不再可信。"""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class StoredRenameOperation(_StrictModel):
    kind: Literal["rename"]
    target: RevisionAddress
    expected_name: str | None
    new_name: str = Field(min_length=1, max_length=1_024)


class StoredCommentOperation(_StrictModel):
    kind: Literal["comment"]
    target: RevisionAddress
    placement: Literal["regular", "repeatable"]
    expected_text: str | None
    text: str = Field(max_length=65_536)


class StoredSetTypeOperation(_StrictModel):
    kind: Literal["set_type"]
    target: RevisionAddress
    type_ref: CanonicalTypeRef


class StoredPatchBytesOperation(_StrictModel):
    kind: Literal["patch_bytes"]
    target: RevisionAddress
    expected_bytes: ByteHex
    replacement_bytes: ByteHex

    @model_validator(mode="after")
    def validate_equal_length(self) -> Self:
        if len(self.expected_bytes) != len(self.replacement_bytes):
            raise ValueError("expected_bytes 与 replacement_bytes 长度必须相同")
        if not self.expected_bytes:
            raise ValueError("patch_bytes 至少修改一个字节")
        return self


class StoredIl2CppTypeResolution(_StrictModel):
    type_id: Annotated[
        str,
        StringConstraints(pattern=r"^type_[0-9a-f]{64}$", strict=True),
    ]
    action: Literal["keep", "replace"]


class StoredImportIl2CppBundleOperation(_StrictModel):
    kind: Literal["import_il2cpp_bundle"]
    bundle_artifact_uri: ArtifactUri
    bundle_sha256: Sha256
    bundle_size: int = Field(ge=1)
    metadata_artifact_uri: ArtifactUri
    metadata_sha256: Sha256
    metadata_size: int = Field(ge=1)
    expected_native: NativeBinding
    type_resolutions: tuple[StoredIl2CppTypeResolution, ...] = Field(
        max_length=MAX_IL2CPP_TYPE_RESOLUTIONS
    )

    @model_validator(mode="after")
    def validate_type_resolutions(self) -> Self:
        type_ids = [resolution.type_id for resolution in self.type_resolutions]
        if type_ids != sorted(type_ids):
            raise ValueError("stored type_resolutions 必须按 type_id 排序")
        if len(type_ids) != len(set(type_ids)):
            raise ValueError("stored type_resolutions 不得重复")
        return self


class StoredRestoreRevisionOperation(_StrictModel):
    """只由 inverse prepare 生成、由 Supervisor 执行的内部操作。"""

    kind: Literal["restore_revision"]
    restore_revision: str
    source_change_id: str


type StoredChangeOperation = Annotated[
    StoredRenameOperation
    | StoredCommentOperation
    | StoredSetTypeOperation
    | StoredPatchBytesOperation
    | StoredImportIl2CppBundleOperation
    | StoredRestoreRevisionOperation,
    Field(discriminator="kind"),
]


class RevisionPreimage(_StrictModel):
    """完整绑定 base revision 内容, 而不是猜测逐项 IDA 状态。"""

    revision: str
    database_sha256: Sha256
    component_hashes: dict[str, Sha256] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_components(self) -> Self:
        for relative in self.component_hashes:
            path = PurePosixPath(relative)
            if (
                not relative
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in relative
                or relative in {_RECORD_NAME, _HASH_NAME}
            ):
                raise ValueError("component_hashes 包含非法相对路径")
        database = self.component_hashes.get(_DATABASE_NAME)
        if database is None or database != self.database_sha256:
            raise ValueError("database_sha256 必须匹配 database.i64 组件")
        return self


class _PlanInput(_StrictModel):
    workspace_id: str
    base_revision: str
    operations: list[StoredChangeOperation] = Field(min_length=1, max_length=1_000)
    preimage: RevisionPreimage
    inverse_of_change_id: str | None = None

    @model_validator(mode="after")
    def validate_plan_mode(self) -> Self:
        if self.preimage.revision != self.base_revision:
            raise ValueError("preimage 必须绑定 base_revision")
        restore_operations = [
            operation
            for operation in self.operations
            if isinstance(operation, StoredRestoreRevisionOperation)
        ]
        if self.inverse_of_change_id is None:
            if restore_operations:
                raise ValueError("普通计划不得包含 restore_revision")
        elif (
            len(self.operations) != 1
            or len(restore_operations) != 1
            or restore_operations[0].source_change_id != self.inverse_of_change_id
            or restore_operations[0].restore_revision == self.base_revision
        ):
            raise ValueError("inverse 计划必须只包含匹配 source change 的 restore_revision")
        return self


class _ChangeSetFile(_StrictModel):
    schema_version: Literal["2026-07-28"]
    change_set_id: str
    workspace_id: str
    base_revision: str
    operations: list[StoredChangeOperation] = Field(min_length=1, max_length=1_000)
    preimage: RevisionPreimage
    inverse_of_change_id: str | None
    digest: Sha256

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        _PlanInput(
            workspace_id=self.workspace_id,
            base_revision=self.base_revision,
            operations=self.operations,
            preimage=self.preimage,
            inverse_of_change_id=self.inverse_of_change_id,
        )
        return self


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """已发布且经过完整性验证的不可变计划。"""

    change_set_id: str
    workspace_id: str
    base_revision: str
    operations: tuple[StoredChangeOperation, ...]
    preimage: RevisionPreimage
    inverse_of_change_id: str | None
    digest: str
    file_sha256: str
    storage_path: Path


@dataclass(frozen=True, slots=True)
class ChangeSetGarbageCollectionResult:
    """不可达 ChangeSet 与未发布 staging 的显式回收结果。"""

    dry_run: bool
    removed_paths: tuple[Path, ...]
    removed_change_set_paths: tuple[Path, ...]
    removed_staging_paths: tuple[Path, ...]
    reclaimed_bytes: int
    skipped_workspace_ids: tuple[str, ...]


class ChangeSetStore:
    """以 workspace 隔离并原子发布内容寻址 ChangeSet。"""

    def __init__(
        self,
        root: Path,
        *,
        working_tree: Path | None = None,
        workspace_lease_root: Path | None = None,
    ) -> None:
        self.root = root.resolve()
        tree = working_tree.resolve() if working_tree is not None else _find_working_tree(self.root)
        if tree is not None and _is_within(self.root, tree):
            raise ValueError("ChangeSet 存储不得位于工作树内")
        self.workspace_lease_root = (
            workspace_lease_root.resolve() if workspace_lease_root is not None else None
        )
        if self.workspace_lease_root is not None and (
            self.workspace_lease_root == self.root
            or _is_within(self.workspace_lease_root, self.root)
        ):
            raise ValueError("workspace lease 目录不得位于 ChangeSet 存储内")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()

    def prepare(
        self,
        *,
        workspace_id: str,
        base_revision: str,
        operations: Sequence[StoredChangeOperation | Mapping[str, object]],
        preimage: RevisionPreimage | Mapping[str, object],
        inverse_of_change_id: str | None = None,
    ) -> ChangeSet:
        """严格校验 canonical 计划并通过隐藏 staging 目录原子发布。"""

        try:
            plan = _PlanInput.model_validate(
                {
                    "workspace_id": workspace_id,
                    "base_revision": base_revision,
                    "operations": list(operations),
                    "preimage": preimage,
                    "inverse_of_change_id": inverse_of_change_id,
                }
            )
            _validate_plan_identifiers(plan)
        except (InvalidIdentifierError, ValidationError, ValueError) as error:
            raise ChangeSetValidationError("ChangeSet 不符合当前 schema") from error

        digest = _plan_digest(plan)
        change_set_id = f"cset_{digest}"
        model = _ChangeSetFile(
            schema_version=PROTOCOL_VERSION,
            change_set_id=change_set_id,
            workspace_id=plan.workspace_id,
            base_revision=plan.base_revision,
            operations=plan.operations,
            preimage=plan.preimage,
            inverse_of_change_id=plan.inverse_of_change_id,
            digest=digest,
        )
        record_bytes = canonical_json_bytes(_file_dict(model))
        file_sha256 = sha256_bytes(record_bytes)

        with self._lock:
            workspace_root = self._workspace_root(plan.workspace_id, create=True)
            final = workspace_root / change_set_id
            if final.exists():
                existing, existing_file_sha256 = self._read_verified(final)
                if existing != model or existing_file_sha256 != file_sha256:
                    raise ChangeSetIntegrityError("内容寻址 ChangeSet 路径发生身份冲突")
                return _from_file(
                    existing,
                    file_sha256=existing_file_sha256,
                    storage_path=final,
                )

            staging_root = workspace_root / _STAGING_NAME
            staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            staging = Path(tempfile.mkdtemp(prefix=".prepare-", dir=staging_root))
            published = False
            try:
                atomic_write_bytes(staging / _RECORD_NAME, record_bytes)
                atomic_write_bytes(staging / _HASH_NAME, f"{file_sha256}\n".encode("ascii"))
                os.rename(staging, final)
                published = True
                _fsync_directory(workspace_root)
            except BaseException:
                if published and final.is_dir():
                    shutil.rmtree(final)
                _remove_staging(staging, staging_root)
                raise
            return _from_file(model, file_sha256=file_sha256, storage_path=final)

    def load(
        self,
        *,
        workspace_id: str,
        base_revision: str,
        change_set_id: str,
        digest: str,
    ) -> ChangeSet:
        """同时校验 apply 身份、canonical 文件、文件哈希与计划 digest。"""

        try:
            validate_identifier(workspace_id, field="workspace_id")
            validate_identifier(base_revision, field="base_revision")
            validate_identifier(change_set_id, field="change_set_id")
            validate_sha256(digest, field="digest")
        except (InvalidIdentifierError, ValueError) as error:
            raise ChangeSetMismatchError("ChangeSet apply 身份无效") from error

        with self._lock:
            storage_path = self._workspace_root(workspace_id, create=False) / change_set_id
            if not storage_path.is_dir():
                raise ChangeSetNotFoundError(f"ChangeSet 不存在: {change_set_id}")
            model, file_sha256 = self._read_verified(storage_path)
            if (
                model.workspace_id != workspace_id
                or model.base_revision != base_revision
                or model.change_set_id != change_set_id
                or model.digest != digest
            ):
                raise ChangeSetMismatchError("ChangeSet apply 身份不匹配")
            return _from_file(model, file_sha256=file_sha256, storage_path=storage_path)

    def load_for_apply(
        self,
        *,
        workspace_id: str,
        base_revision: str,
        change_set_id: str,
        digest: str,
    ) -> ChangeSet:
        """返回通过全部 apply 前置校验的不可变计划。"""

        return self.load(
            workspace_id=workspace_id,
            base_revision=base_revision,
            change_set_id=change_set_id,
            digest=digest,
        )

    def collect_garbage(
        self,
        *,
        retained_scopes: set[tuple[str, str]],
        dry_run: bool = True,
    ) -> ChangeSetGarbageCollectionResult:
        """回收不可达计划与无活动 worker 的未发布 staging。"""

        if self.workspace_lease_root is None:
            raise ValueError("ChangeSet GC 必须配置 workspace lifecycle lease 目录")
        checked_scopes = {
            (
                validate_identifier(workspace_id, field="workspace_id"),
                validate_identifier(revision, field="revision"),
            )
            for workspace_id, revision in retained_scopes
        }
        with self._lock:
            workspace_roots = self._strict_workspace_roots()

        change_set_candidates: list[Path] = []
        staging_candidates: list[Path] = []
        skipped: list[str] = []
        reclaimed = 0
        for workspace_root in workspace_roots:
            workspace_id = workspace_root.name
            lease = interprocess_file_lock(self.workspace_lease_root / f"{workspace_id}.lease.lock")
            if not lease.try_acquire():
                skipped.append(workspace_id)
                continue
            try:
                with self._lock:
                    self._validate_workspace_root(workspace_root)
                    workspace_change_sets, workspace_staging = self._gc_candidates(
                        workspace_root=workspace_root,
                        workspace_id=workspace_id,
                        retained_scopes=checked_scopes,
                    )
                    change_set_candidates.extend(workspace_change_sets)
                    staging_candidates.extend(workspace_staging)
                    workspace_candidates = sorted(
                        (*workspace_change_sets, *workspace_staging),
                        key=str,
                    )
                    reclaimed += sum(_strict_directory_size(path) for path in workspace_candidates)
                    if not dry_run:
                        for candidate in workspace_change_sets:
                            _remove_gc_directory(candidate, parent=workspace_root)
                        staging_root = workspace_root / _STAGING_NAME
                        for candidate in workspace_staging:
                            _remove_gc_directory(candidate, parent=staging_root)
            finally:
                lease.release()

        removed_change_sets = tuple(sorted(change_set_candidates, key=str))
        removed_staging = tuple(sorted(staging_candidates, key=str))
        return ChangeSetGarbageCollectionResult(
            dry_run=dry_run,
            removed_paths=tuple(sorted((*removed_change_sets, *removed_staging), key=str)),
            removed_change_set_paths=removed_change_sets,
            removed_staging_paths=removed_staging,
            reclaimed_bytes=reclaimed,
            skipped_workspace_ids=tuple(skipped),
        )

    def _strict_workspace_roots(self) -> tuple[Path, ...]:
        workspace_roots: list[Path] = []
        for candidate in sorted(self.root.iterdir(), key=lambda item: item.name):
            if candidate.is_symlink() or not candidate.is_dir():
                raise ChangeSetIntegrityError("ChangeSet 根目录包含非法条目")
            try:
                validate_identifier(candidate.name, field="workspace_id")
            except InvalidIdentifierError as error:
                raise ChangeSetIntegrityError("ChangeSet workspace 目录名无效") from error
            self._validate_workspace_root(candidate)
            workspace_roots.append(candidate)
        return tuple(workspace_roots)

    def _validate_workspace_root(self, workspace_root: Path) -> None:
        if (
            workspace_root.is_symlink()
            or not workspace_root.is_dir()
            or workspace_root.resolve(strict=True).parent != self.root
        ):
            raise ChangeSetIntegrityError("ChangeSet workspace 路径越界")

    def _gc_candidates(
        self,
        *,
        workspace_root: Path,
        workspace_id: str,
        retained_scopes: set[tuple[str, str]],
    ) -> tuple[list[Path], list[Path]]:
        change_sets: list[Path] = []
        staging: list[Path] = []
        for candidate in sorted(workspace_root.iterdir(), key=lambda item: item.name):
            if candidate.name == _STAGING_NAME:
                staging.extend(
                    _strict_staging_candidates(
                        candidate,
                        workspace_root=workspace_root,
                        workspace_id=workspace_id,
                    )
                )
                continue
            if (
                _CHANGE_SET_DIRECTORY_PATTERN.fullmatch(candidate.name) is None
                or candidate.is_symlink()
                or not candidate.is_dir()
            ):
                raise ChangeSetIntegrityError("ChangeSet workspace 包含非法条目")
            model, _ = self._read_verified(candidate)
            if model.workspace_id != workspace_id:
                raise ChangeSetIntegrityError("ChangeSet workspace 身份与路径不一致")
            if (workspace_id, model.base_revision) not in retained_scopes:
                change_sets.append(candidate)
        return change_sets, staging

    def _read_verified(self, storage_path: Path) -> tuple[_ChangeSetFile, str]:
        _validate_published_directory(storage_path)
        record_path = storage_path / _RECORD_NAME
        hash_path = storage_path / _HASH_NAME
        expected_file_sha256 = _read_file_sha256(hash_path)
        if sha256_file(record_path) != expected_file_sha256:
            raise ChangeSetIntegrityError("ChangeSet 文件 SHA-256 校验失败")

        model = _read_current_record(record_path)
        if model.change_set_id != storage_path.name:
            raise ChangeSetIntegrityError("ChangeSet 文件身份与路径不一致")
        return model, expected_file_sha256

    def _workspace_root(self, workspace_id: str, *, create: bool) -> Path:
        validate_identifier(workspace_id, field="workspace_id")
        candidate = (self.root / workspace_id).resolve()
        if not _is_within(candidate, self.root) or candidate == self.root:
            raise ChangeSetIntegrityError("ChangeSet workspace 路径越界")
        if create:
            candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
        return candidate


def _validate_plan_identifiers(plan: _PlanInput) -> None:
    validate_identifier(plan.workspace_id, field="workspace_id")
    validate_identifier(plan.base_revision, field="base_revision")
    validate_identifier(plan.preimage.revision, field="preimage.revision")
    if plan.inverse_of_change_id is not None:
        validate_identifier(plan.inverse_of_change_id, field="inverse_of_change_id")
    for operation in plan.operations:
        if isinstance(operation, StoredRestoreRevisionOperation):
            validate_identifier(operation.restore_revision, field="restore_revision")
            validate_identifier(operation.source_change_id, field="source_change_id")
        elif isinstance(operation, StoredImportIl2CppBundleOperation):
            for uri in (
                operation.bundle_artifact_uri,
                operation.metadata_artifact_uri,
            ):
                workspace_id, revision, _ = parse_artifact_uri(uri)
                if workspace_id != plan.workspace_id or revision != plan.base_revision:
                    raise ValueError(
                        "IL2CPP artifact URI 必须绑定 ChangeSet workspace/base_revision"
                    )


def _validate_file_identifiers(model: _ChangeSetFile) -> None:
    validate_identifier(model.change_set_id, field="change_set_id")
    validate_sha256(model.digest, field="digest")
    _validate_plan_identifiers(
        _PlanInput(
            workspace_id=model.workspace_id,
            base_revision=model.base_revision,
            operations=model.operations,
            preimage=model.preimage,
            inverse_of_change_id=model.inverse_of_change_id,
        )
    )


def _read_current_record(record_path: Path) -> _ChangeSetFile:
    try:
        record_bytes = record_path.read_bytes()
        model = _ChangeSetFile.model_validate_json(record_bytes, strict=True)
        _validate_file_identifiers(model)
    except (InvalidIdentifierError, OSError, ValidationError, ValueError) as error:
        raise ChangeSetIntegrityError("ChangeSet 文件不符合当前 schema") from error
    if record_bytes != canonical_json_bytes(_file_dict(model)):
        raise ChangeSetIntegrityError("ChangeSet 文件不是 canonical JSON")
    plan = _PlanInput(
        workspace_id=model.workspace_id,
        base_revision=model.base_revision,
        operations=model.operations,
        preimage=model.preimage,
        inverse_of_change_id=model.inverse_of_change_id,
    )
    if _plan_digest(plan) != model.digest or model.change_set_id != f"cset_{model.digest}":
        raise ChangeSetIntegrityError("ChangeSet digest 校验失败")
    return model


def _read_file_sha256(hash_path: Path) -> str:
    try:
        expected_file_sha256 = hash_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ChangeSetIntegrityError("ChangeSet 文件哈希不可读") from error
    if not expected_file_sha256.endswith("\n") or "\n" in expected_file_sha256[:-1]:
        raise ChangeSetIntegrityError("ChangeSet 文件哈希格式无效")
    expected_file_sha256 = expected_file_sha256[:-1]
    try:
        return validate_sha256(expected_file_sha256, field="file_sha256")
    except ValueError as error:
        raise ChangeSetIntegrityError("ChangeSet 文件哈希格式无效") from error


def _validate_published_directory(storage_path: Path) -> None:
    if (
        _CHANGE_SET_DIRECTORY_PATTERN.fullmatch(storage_path.name) is None
        or storage_path.is_symlink()
        or not storage_path.is_dir()
    ):
        raise ChangeSetIntegrityError("ChangeSet 发布目录无效")
    entries = {entry.name: entry for entry in storage_path.iterdir()}
    if set(entries) != {_RECORD_NAME, _HASH_NAME}:
        raise ChangeSetIntegrityError("ChangeSet 文件集合不完整或包含附加内容")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries.values()):
        raise ChangeSetIntegrityError("ChangeSet 文件集合包含非法路径类型")


def _strict_staging_candidates(
    staging_root: Path,
    *,
    workspace_root: Path,
    workspace_id: str,
) -> list[Path]:
    if (
        staging_root.is_symlink()
        or not staging_root.is_dir()
        or staging_root.resolve(strict=True).parent != workspace_root.resolve(strict=True)
    ):
        raise ChangeSetIntegrityError("ChangeSet staging 根目录越界")
    candidates: list[Path] = []
    for candidate in sorted(staging_root.iterdir(), key=lambda item: item.name):
        if (
            _STAGING_DIRECTORY_PATTERN.fullmatch(candidate.name) is None
            or candidate.is_symlink()
            or not candidate.is_dir()
            or candidate.resolve(strict=True).parent != staging_root.resolve(strict=True)
        ):
            raise ChangeSetIntegrityError("ChangeSet staging 包含非法条目")
        _validate_staging_directory(candidate, workspace_id=workspace_id)
        candidates.append(candidate)
    return candidates


def _validate_staging_directory(staging: Path, *, workspace_id: str) -> None:
    entries = {entry.name: entry for entry in staging.iterdir()}
    temporary_records: list[Path] = []
    temporary_hashes: list[Path] = []
    for name, entry in entries.items():
        if entry.is_symlink() or not entry.is_file():
            raise ChangeSetIntegrityError("ChangeSet staging 包含非法路径类型")
        if name in {_RECORD_NAME, _HASH_NAME}:
            continue
        match = _STAGING_TEMPORARY_PATTERN.fullmatch(name)
        if match is None:
            raise ChangeSetIntegrityError("ChangeSet staging 包含未知文件")
        if match.group(1) == _RECORD_NAME:
            temporary_records.append(entry)
        else:
            temporary_hashes.append(entry)

    record_path = entries.get(_RECORD_NAME)
    hash_path = entries.get(_HASH_NAME)
    if record_path is None:
        if hash_path is not None or temporary_hashes or len(temporary_records) > 1:
            raise ChangeSetIntegrityError("ChangeSet staging 写入状态无效")
        return
    if temporary_records or len(temporary_hashes) > 1:
        raise ChangeSetIntegrityError("ChangeSet staging 写入状态无效")

    model = _read_current_record(record_path)
    if model.workspace_id != workspace_id:
        raise ChangeSetIntegrityError("ChangeSet staging workspace 身份不一致")
    if hash_path is not None:
        if temporary_hashes:
            raise ChangeSetIntegrityError("ChangeSet staging 写入状态无效")
        expected_file_sha256 = _read_file_sha256(hash_path)
        if sha256_file(record_path) != expected_file_sha256:
            raise ChangeSetIntegrityError("ChangeSet staging 文件 SHA-256 校验失败")


def _strict_directory_size(path: Path) -> int:
    total = 0
    for entry in path.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ChangeSetIntegrityError("拒绝计算非法 ChangeSet GC 路径")
        total += entry.stat().st_size
    return total


def _remove_gc_directory(path: Path, *, parent: Path) -> None:
    resolved_parent = parent.resolve(strict=True)
    if (
        path.is_symlink()
        or not path.is_dir()
        or path.resolve(strict=True).parent != resolved_parent
    ):
        raise ChangeSetIntegrityError("拒绝清理 ChangeSet GC 边界外路径")
    shutil.rmtree(path)
    _fsync_directory(resolved_parent)


def _plan_digest(plan: _PlanInput) -> str:
    material = {
        "base_revision": plan.base_revision,
        "inverse_of_change_id": plan.inverse_of_change_id,
        "operations": [
            operation.model_dump(mode="json", exclude_none=False) for operation in plan.operations
        ],
        "preimage": plan.preimage.model_dump(mode="json", exclude_none=False),
        "schema_version": PROTOCOL_VERSION,
        "workspace_id": plan.workspace_id,
    }
    return sha256_bytes(canonical_json_bytes(cast(dict[str, object], material)))


def _file_dict(model: _ChangeSetFile) -> dict[str, object]:
    return {
        "schema_version": model.schema_version,
        "change_set_id": model.change_set_id,
        "workspace_id": model.workspace_id,
        "base_revision": model.base_revision,
        "operations": [
            operation.model_dump(mode="json", exclude_none=False) for operation in model.operations
        ],
        "preimage": model.preimage.model_dump(mode="json", exclude_none=False),
        "inverse_of_change_id": model.inverse_of_change_id,
        "digest": model.digest,
    }


def _from_file(
    model: _ChangeSetFile,
    *,
    file_sha256: str,
    storage_path: Path,
) -> ChangeSet:
    return ChangeSet(
        change_set_id=model.change_set_id,
        workspace_id=model.workspace_id,
        base_revision=model.base_revision,
        operations=tuple(model.operations),
        preimage=model.preimage,
        inverse_of_change_id=model.inverse_of_change_id,
        digest=model.digest,
        file_sha256=file_sha256,
        storage_path=storage_path,
    )


def _remove_staging(staging: Path, staging_root: Path) -> None:
    try:
        staging.relative_to(staging_root)
    except ValueError as error:
        raise ChangeSetIntegrityError("拒绝清理 staging 边界外路径") from error
    shutil.rmtree(staging, ignore_errors=True)


def _find_working_tree(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
