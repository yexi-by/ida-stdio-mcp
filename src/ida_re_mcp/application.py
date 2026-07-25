"""标准 MCP、外部存储与隔离 IDA worker 的应用编排。"""

from __future__ import annotations

import asyncio
import base64
import codecs
import json
import shutil
import tempfile
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from ida_re_mcp.config import AppConfig, RuntimePaths, load_config
from ida_re_mcp.constants import MAX_INLINE_RESULT_BYTES, RESOURCE_CHUNK_BYTES
from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import build_tool_catalog
from ida_re_mcp.domain.errors import (
    BusinessErrorCode,
    ResourceNotFoundError,
    ResourceRequestError,
    ToolExecutionError,
)
from ida_re_mcp.domain.resources import (
    BinaryResourceData,
    ResourceData,
    ResourceDescriptor,
    ResourcePage,
    ResourceRead,
    TextResourceData,
)
from ida_re_mcp.domain.tools import (
    AddressInspectOutput,
    AnalysisRefineInput,
    AnalysisRefineOutput,
    ArtifactReference,
    ChangeApplyInput,
    ChangeApplyOutput,
    ChangeImpact,
    ChangePrepareInput,
    ChangePrepareOutput,
    DataflowSliceInput,
    DataflowSliceOutput,
    DebugBreakpointsInput,
    DebugControlInput,
    DebugEstablishInput,
    DebugEstablishOutput,
    DebugEventsInput,
    DebugFinishInput,
    DebugInspectInput,
    DebugLaunchTarget,
    ExpertExecuteInput,
    ExpertExecuteOutput,
    FunctionInspectInput,
    FunctionInspectOutput,
    GraphQueryInput,
    GraphQueryOutput,
    OperationCancelInput,
    OperationCancelOutput,
    OperationFailure,
    OperationWaitInput,
    OperationWaitOutput,
    ProgramOverviewInput,
    ProgramOverviewOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
    ReportBuildInput,
    ReportBuildOutput,
    RevisionSummary,
    TypeInspectInput,
    TypeInspectOutput,
    WorkspaceCreateInput,
    WorkspaceCreateOutput,
    WorkspaceExportInput,
    WorkspaceExportOutput,
    WorkspaceGetInput,
    WorkspaceGetOutput,
    WorkspaceListInput,
    WorkspaceListOutput,
    WorkspaceSummary,
)
from ida_re_mcp.il2cpp.models import NativeBinding
from ida_re_mcp.protocol import McpRuntime
from ida_re_mcp.supervisor._fs import canonical_json_bytes
from ida_re_mcp.supervisor._process_lock import (
    AsyncInterprocessFileLock,
    InterprocessFileLock,
    exclusive_process_lease,
)
from ida_re_mcp.supervisor.artifacts import (
    ArtifactFileInput,
    ArtifactIntegrityError,
    ArtifactMetadata,
    ArtifactNotFoundError,
    parse_artifact_uri,
)
from ida_re_mcp.supervisor.backend import (
    AnalysisBackend,
    DebugBackend,
    DebugRequestCancelled,
    IdaBackend,
    SubprocessIdaBackend,
)
from ida_re_mcp.supervisor.change_adapter import (
    ArtifactMaterialization,
    ChangeAdapterInputError,
    ChangeAdapterResultError,
    ChangeContext,
    ChangeSourceError,
    InverseSource,
    SolidifiedSource,
    build_canonical_plan,
    build_mutation_execution,
    build_preflight_execution,
    parse_preflight_impact,
    parse_worker_impact,
    source_solidification_requests,
    validate_local_sources,
)
from ida_re_mcp.supervisor.changes import (
    ChangeSetError,
    ChangeSetStore,
    StoredChangeOperation,
    StoredImportIl2CppBundleOperation,
)
from ida_re_mcp.supervisor.cursors import (
    CursorCodec,
    CursorError,
    CursorPosition,
    query_digest,
)
from ida_re_mcp.supervisor.debug_adapter import (
    BreakpointReplacementPlan,
    DebugAdapterError,
    DebugContext,
    WorkerDebugCommand,
    adapt_debug_breakpoints,
    adapt_debug_cancelled,
    adapt_debug_control,
    adapt_debug_establish,
    adapt_debug_events,
    adapt_debug_finish,
    adapt_debug_inspect,
    build_debug_breakpoint_replacement,
    build_debug_breakpoint_rollback,
    prepare_debug_breakpoint_enable,
    prepare_debug_breakpoint_list,
    prepare_debug_control,
    prepare_debug_establish,
    prepare_debug_events,
    prepare_debug_finish,
    prepare_debug_inspect,
)
from ida_re_mcp.supervisor.errors import (
    InvalidIdentifierError,
    OperationNotFoundError,
    OperationStateError,
    RevisionConflictError,
    RevisionNotFoundError,
    StagingIntegrityError,
    StorageCorruptionError,
    SupervisorAlreadyRunningError,
    SupervisorError,
    WorkspaceNotFoundError,
)
from ida_re_mcp.supervisor.expert_adapter import (
    ExpertAdapterError,
    adapt_expert_worker_result,
)
from ida_re_mcp.supervisor.native_formats import (
    NativeImageIdentity,
    UnsupportedNativeImageError,
    inspect_native_image,
)
from ida_re_mcp.supervisor.operations import OperationSnapshot, OperationState
from ida_re_mcp.supervisor.refine_adapter import (
    RefineAdapterInputError,
    RefineAdapterResultError,
    adapt_refine_worker_result,
    build_refine_worker_request,
)
from ida_re_mcp.supervisor.static_adapter import (
    AnalysisContext,
    StaticAdapterCapabilityError,
    StaticAdapterInput,
    StaticAdapterInputError,
    StaticAdapterResultError,
    static_page_facts,
)
from ida_re_mcp.supervisor.static_adapter import (
    adapt_worker_results as adapt_static_results,
)
from ida_re_mcp.supervisor.static_adapter import (
    build_worker_requests as build_static_requests,
)
from ida_re_mcp.supervisor.storage import SupervisorStorage
from ida_re_mcp.supervisor.workers import WorkerProcessError
from ida_re_mcp.supervisor.workspaces import (
    ColdValidationReceipt,
    RevisionCheckout,
    RevisionSnapshot,
    RevisionStaging,
    WorkspaceSnapshot,
    hash_staging_payload,
)
from ida_re_mcp.worker.errors import WorkerError

_STATIC_TOOL_NAMES = frozenset(
    {
        "program.overview",
        "program.search",
        "address.inspect",
        "function.inspect",
        "graph.query",
        "dataflow.slice",
        "type.inspect",
    }
)
_DEBUG_TOOL_NAMES = frozenset(
    {
        "debug.establish",
        "debug.control",
        "debug.events",
        "debug.inspect",
        "debug.breakpoints",
        "debug.finish",
    }
)
_WORKER_TIMEOUT_SECONDS = 120.0
_MAX_RESOURCE_CONTENTS = 64
_OPERATION_WAIT_POLL_SECONDS = 0.05
_TERMINAL_OPERATION_STATES = frozenset(
    {
        OperationState.SUCCEEDED,
        OperationState.FAILED,
        OperationState.CANCELLED,
    }
)
_WORKER_BUSINESS_ERRORS: dict[str, BusinessErrorCode] = {
    "ambiguous_reference": BusinessErrorCode.AMBIGUOUS_REFERENCE,
    "capability_unavailable": BusinessErrorCode.CAPABILITY_UNAVAILABLE,
    "cursor_stale": BusinessErrorCode.CURSOR_STALE,
    "debug_state_conflict": BusinessErrorCode.DEBUG_STATE_CONFLICT,
    "policy_denied": BusinessErrorCode.POLICY_DENIED,
    "revision_conflict": BusinessErrorCode.REVISION_CONFLICT,
    "slice_seed_not_found": BusinessErrorCode.UNSUPPORTED,
    "unsupported": BusinessErrorCode.UNSUPPORTED,
    "worker_crashed": BusinessErrorCode.WORKER_CRASHED,
    "worker_timeout": BusinessErrorCode.WORKER_CRASHED,
}


def _is_utf8_resource(media_type: str) -> bool:
    """判断 artifact 是否应以 MCP 文本 resource 返回。"""

    normalized = media_type.partition(";")[0].strip().lower()
    return (
        normalized.startswith("text/")
        or normalized
        in {
            "application/json",
            "application/javascript",
            "application/x-ndjson",
            "application/xml",
        }
        or normalized.endswith(("+json", "+ndjson", "+xml"))
    )


@dataclass(slots=True)
class _DebugSession:
    checkout: RevisionCheckout
    backend: DebugBackend
    context: DebugContext
    workspace_lock: AsyncInterprocessFileLock
    owned_target: bool
    idle_task: asyncio.Task[None] | None = None


@dataclass(slots=True)
class _AnalysisSession:
    workspace_id: str
    revision: str
    checkout: RevisionCheckout
    backend: AnalysisBackend
    in_use: bool
    last_used: float
    idle_task: asyncio.Task[None] | None = None


@dataclass(frozen=True, slots=True)
class _ColdImageIdentity:
    """发布前必须由冷重开 IDB 再次证明的原生镜像身份。"""

    sample_sha256: str
    architecture: str | None = None
    bitness: int | None = None
    endianness: str | None = None
    image_size: int | None = None

    @classmethod
    def from_overview(
        cls,
        sample_sha256: str,
        overview: ProgramOverviewOutput,
    ) -> _ColdImageIdentity:
        return cls(
            sample_sha256=sample_sha256,
            architecture=overview.image.architecture,
            bitness=overview.image.bitness,
            endianness=overview.image.endian,
            image_size=overview.image.image_size,
        )


class Application:
    """Supervisor 进程中的唯一产品应用对象。"""

    def __init__(
        self,
        *,
        config: AppConfig,
        storage: SupervisorStorage,
        changes: ChangeSetStore,
        cursors: CursorCodec,
        backend: IdaBackend,
        owner_lease: InterprocessFileLock | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.changes = changes
        self.cursors = cursors
        self.backend = backend
        self._owner_lease = owner_lease
        catalog = build_tool_catalog(
            enable_authoring=config.policy.authoring,
            enable_debug=config.policy.debug_launch or config.policy.debug_attach,
            enable_expert=config.policy.expert,
        )
        self._catalog_by_name = {spec.name: spec for spec in catalog}
        self._mcp = McpRuntime(self, catalog=catalog)
        self._operation_tasks: dict[str, asyncio.Task[None]] = {}
        self._cancellable_operations: set[str] = set()
        self._workspace_operations: dict[str, str] = {}
        self._debug_sessions: dict[str, _DebugSession] = {}
        self._analysis_sessions: dict[tuple[str, str], _AnalysisSession] = {}
        self._analysis_sessions_guard = asyncio.Lock()
        self._workspace_locks: dict[str, AsyncInterprocessFileLock] = {}
        self._analysis_slots = asyncio.Semaphore(config.workers.analysis_limit)
        self._debug_slots = asyncio.Semaphore(config.workers.debug_limit)
        self._closed = False

    @classmethod
    def open(
        cls,
        config_path: Path | None = None,
        *,
        paths: RuntimePaths | None = None,
        backend: IdaBackend | None = None,
    ) -> Application:
        config = load_config(config_path)
        runtime_paths = (paths or RuntimePaths.discover()).ensure()
        owner_lease = exclusive_process_lease(runtime_paths.data_root / ".supervisor.lease.lock")
        if not owner_lease.try_acquire():
            raise SupervisorAlreadyRunningError(
                "运行数据目录已被另一个 ida-re-mcp Supervisor 占用: "
                f"{runtime_paths.data_root.resolve()}"
            )
        try:
            storage = SupervisorStorage.open(config=config, paths=runtime_paths)
            return cls(
                config=config,
                storage=storage,
                changes=ChangeSetStore(
                    storage.paths.data_root / "change-sets",
                    workspace_lease_root=storage.workspaces.lease_root,
                ),
                cursors=CursorCodec(storage.paths.data_root / "cursor.key"),
                backend=backend or SubprocessIdaBackend(log_root=storage.paths.log_root),
                owner_lease=owner_lease,
            )
        except BaseException:
            owner_lease.release()
            raise

    async def serve(self) -> None:
        """通过官方 MCP stdio transport 运行服务。"""

        self._require_open()
        await self._mcp.serve_stdio()

    async def execute_tool(
        self,
        name: str,
        arguments: StrictModel,
    ) -> StrictModel | JsonObject:
        self._require_open()
        try:
            if name == "operation.wait":
                return await self._operation_wait(cast(OperationWaitInput, arguments))
            if name == "operation.cancel":
                return await self._operation_cancel(cast(OperationCancelInput, arguments))
            if name == "workspace.create":
                return await self._workspace_create(cast(WorkspaceCreateInput, arguments))
            if name == "workspace.list":
                return await self._workspace_list(cast(WorkspaceListInput, arguments))
            if name == "workspace.get":
                return await self._workspace_get(cast(WorkspaceGetInput, arguments))
            if name == "workspace.export":
                return await self._workspace_export(cast(WorkspaceExportInput, arguments))
            if name in _STATIC_TOOL_NAMES:
                return await self._static_query(name, arguments)
            if name == "report.build":
                return await self._report_build(cast(ReportBuildInput, arguments))
            if name == "analysis.refine":
                return await self._analysis_refine(cast(AnalysisRefineInput, arguments))
            if name == "change.prepare":
                return await self._change_prepare(cast(ChangePrepareInput, arguments))
            if name == "change.apply":
                return await self._change_apply(cast(ChangeApplyInput, arguments))
            if name in _DEBUG_TOOL_NAMES:
                return await self._debug_tool(name, arguments)
            if name == "expert.execute":
                return await self._expert_execute(cast(ExpertExecuteInput, arguments))
            raise ToolExecutionError(
                BusinessErrorCode.UNSUPPORTED,
                f"工具尚未实现: {name}",
            )
        except ToolExecutionError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            translated = _tool_error(exc)
            if translated is None:
                raise
            raise translated from exc

    async def list_resources(
        self,
        cursor: str | None,
    ) -> ResourcePage:
        artifacts = await asyncio.to_thread(self.storage.artifacts.list)
        digest = query_digest("\n".join(item.uri for item in artifacts).encode("utf-8"))
        offset = 0
        if cursor is not None:
            try:
                offset = self.cursors.decode(
                    cursor,
                    scope="resources",
                    workspace_id=None,
                    revision=None,
                    query_digest=digest,
                ).offset
            except CursorError as exc:
                raise ResourceRequestError("resource cursor 已失效") from exc
        page_items = artifacts[offset : offset + 200]
        next_offset = offset + len(page_items)
        next_cursor = (
            self.cursors.encode(CursorPosition("resources", None, None, digest, next_offset))
            if next_offset < len(artifacts)
            else None
        )
        return ResourcePage(
            resources=[
                ResourceDescriptor(
                    uri=item.uri,
                    name=item.name or item.artifact_id,
                    title=item.name,
                    description=f"不可变 artifact, SHA-256 {item.content_sha256}",
                    mime_type=item.media_type,
                    size_bytes=item.size,
                )
                for item in page_items
            ],
            next_cursor=next_cursor,
        )

    async def read_resource(
        self,
        uri: str,
    ) -> ResourceRead:
        contents: list[ResourceData] = []
        offset = 0
        try:
            workspace_id, revision, artifact_id = parse_artifact_uri(uri)
        except ValueError as exc:
            raise ResourceRequestError("resource URI 无效", uri=uri) from exc
        try:
            metadata = await asyncio.to_thread(
                self.storage.artifacts.get,
                workspace_id,
                revision,
                artifact_id,
                verify=True,
            )
            text_decoder = (
                codecs.getincrementaldecoder("utf-8")(errors="strict")
                if _is_utf8_resource(metadata.media_type)
                else None
            )
            while len(contents) < _MAX_RESOURCE_CONTENTS:
                chunk = await asyncio.to_thread(
                    self.storage.artifacts.read_verified_chunk,
                    metadata,
                    offset=offset,
                    limit=(
                        RESOURCE_CHUNK_BYTES - 4
                        if text_decoder is not None
                        else RESOURCE_CHUNK_BYTES
                    ),
                )
                if text_decoder is None:
                    contents.append(
                        BinaryResourceData(
                            kind="blob",
                            uri=uri,
                            mime_type=chunk.metadata.media_type,
                            blob=base64.b64encode(chunk.data).decode("ascii"),
                        )
                    )
                else:
                    contents.append(
                        TextResourceData(
                            kind="text",
                            uri=uri,
                            mime_type=chunk.metadata.media_type,
                            text=text_decoder.decode(chunk.data, final=chunk.eof),
                        )
                    )
                if chunk.eof:
                    return ResourceRead(contents=contents)
                assert chunk.next_offset is not None
                offset = chunk.next_offset
        except ArtifactNotFoundError as exc:
            raise ResourceNotFoundError(uri=uri) from exc
        raise RuntimeError("artifact 超过单次 resource 读取上限")

    async def doctor(self) -> tuple[bool, JsonObject]:
        self._require_open()
        worker = await self.backend.doctor()
        usage = await asyncio.to_thread(self.storage.usage)
        report: JsonObject = {
            "healthy": bool(worker.get("available")),
            "python": "3.13",
            "mcp": self._mcp.protocol_report(),
            "runtime_paths": {
                "data": str(self.storage.paths.data_root),
                "logs": str(self.storage.paths.log_root),
            },
            "storage": {
                "bytes": usage.total_bytes,
                "quota_bytes": usage.quota_bytes,
                "over_soft_quota": usage.over_soft_quota,
            },
            "worker": worker,
        }
        return bool(report["healthy"]), report

    async def gc(self, *, apply: bool) -> JsonObject:
        self._require_open()
        workspace_result = await asyncio.to_thread(
            self.storage.workspaces.collect_garbage,
            dry_run=not apply,
        )
        workspaces = await asyncio.to_thread(self.storage.workspaces.list)
        retained_scopes = {
            (workspace.workspace_id, revision.revision)
            for workspace in workspaces
            for revision in workspace.revisions
        }
        artifact_result = await asyncio.to_thread(
            self.storage.artifacts.collect_garbage,
            retained_scopes=retained_scopes,
            dry_run=not apply,
        )
        change_set_result = await asyncio.to_thread(
            self.changes.collect_garbage,
            retained_scopes=retained_scopes,
            dry_run=not apply,
        )
        expired_operations = (
            await asyncio.to_thread(self.storage.operations.purge_expired) if apply else 0
        )
        usage = await asyncio.to_thread(self.storage.usage)
        skipped = sorted(
            {
                *workspace_result.skipped_workspace_ids,
                *artifact_result.skipped_workspace_ids,
                *change_set_result.skipped_workspace_ids,
            }
        )
        skipped_json = cast(list[JsonValue], skipped)
        reclaimed_bytes = (
            workspace_result.reclaimed_bytes
            + artifact_result.reclaimed_bytes
            + change_set_result.reclaimed_bytes
        )
        protected_bytes = (
            usage.total_bytes if apply else max(0, usage.total_bytes - reclaimed_bytes)
        )
        candidates: JsonObject = {
            "workspace": [str(path) for path in workspace_result.removed_paths],
            "artifact": [str(path) for path in artifact_result.removed_paths],
            "change_set": [str(path) for path in change_set_result.removed_change_set_paths],
            "change_set_staging": [str(path) for path in change_set_result.removed_staging_paths],
        }
        storage: JsonObject = {
            "bytes": usage.total_bytes,
            "quota_bytes": usage.quota_bytes,
            "over_soft_quota": usage.over_soft_quota,
            "protected_bytes": protected_bytes,
            "protected_bytes_exceed_quota": protected_bytes > usage.quota_bytes,
        }
        return {
            "applied": apply,
            "candidates": candidates,
            "skipped_workspace_ids": skipped_json,
            "reclaimed_bytes": reclaimed_bytes,
            "expired_operations_removed": expired_operations,
            "storage": storage,
        }

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            for operation_id, task in self._operation_tasks.items():
                if not task.done():
                    try:
                        snapshot = self.storage.operations.get(operation_id)
                        if snapshot.state is OperationState.QUEUED:
                            self.storage.operations.cancel(operation_id)
                            continue
                    except SupervisorError:
                        pass
                    task.cancel()
            if self._operation_tasks:
                await asyncio.gather(*self._operation_tasks.values(), return_exceptions=True)
            for session in tuple(self._debug_sessions.values()):
                await self._close_debug_session(session)
            async with self._analysis_sessions_guard:
                analysis_sessions = tuple(self._analysis_sessions.values())
                self._analysis_sessions.clear()
                for session in analysis_sessions:
                    _cancel_idle_task(session.idle_task)
                    session.idle_task = None
            if analysis_sessions:
                await asyncio.gather(
                    *(self._close_analysis_session(session) for session in analysis_sessions),
                )
            if self._workspace_locks:
                await asyncio.gather(
                    *(lock.aclose() for lock in self._workspace_locks.values()),
                )
        finally:
            owner_lease = self._owner_lease
            self._owner_lease = None
            if owner_lease is not None:
                owner_lease.release()

    async def _operation_wait(self, arguments: OperationWaitInput) -> OperationWaitOutput:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (arguments.wait_ms / 1000)
        while True:
            snapshot = await asyncio.to_thread(
                self.storage.operations.get,
                arguments.operation_id,
            )
            if (
                snapshot.state in _TERMINAL_OPERATION_STATES
                or arguments.wait_ms == 0
                or loop.time() >= deadline
            ):
                return _operation_output(snapshot)
            await asyncio.sleep(
                min(
                    _OPERATION_WAIT_POLL_SECONDS,
                    max(0.0, deadline - loop.time()),
                )
            )

    async def _operation_cancel(
        self,
        arguments: OperationCancelInput,
    ) -> OperationCancelOutput:
        before = await asyncio.to_thread(
            self.storage.operations.get,
            arguments.operation_id,
        )
        snapshot = await asyncio.to_thread(
            self.storage.operations.cancel,
            arguments.operation_id,
        )
        if (
            before.state is OperationState.RUNNING
            and snapshot.state is OperationState.CANCEL_REQUESTED
            and snapshot.operation_id in self._cancellable_operations
        ):
            task = self._operation_tasks.get(snapshot.operation_id)
            if task is not None and not task.done():
                task.cancel()
        return OperationCancelOutput(
            operation_id=snapshot.operation_id,
            state=snapshot.state.value,
            cancellation_requested=(
                before.state
                not in {
                    OperationState.SUCCEEDED,
                    OperationState.FAILED,
                    OperationState.CANCELLED,
                }
            ),
        )

    async def _workspace_create(
        self,
        arguments: WorkspaceCreateInput,
    ) -> WorkspaceCreateOutput:
        sample = Path(arguments.sample_path)
        native_identity: NativeImageIdentity | None = None

        def validate_copy(path: Path, sample_sha256: str, _sample_size: int) -> None:
            nonlocal native_identity
            if arguments.expected_sha256 is not None and sample_sha256 != arguments.expected_sha256:
                raise ToolExecutionError(
                    BusinessErrorCode.PRECONDITION_FAILED,
                    "样本 SHA-256 与 expected_sha256 不一致",
                    details={
                        "actual_sha256": sample_sha256,
                    },
                )
            try:
                native_identity = inspect_native_image(path)
            except UnsupportedNativeImageError as exc:
                raise ToolExecutionError(
                    BusinessErrorCode.UNSUPPORTED,
                    str(exc),
                    details=cast(dict[str, JsonValue], exc.details),
                ) from exc

        workspace = await _complete_thread_call(
            lambda: self.storage.workspaces.create(sample, validate_copy=validate_copy)
        )
        validated_identity = native_identity
        if validated_identity is None:
            raise RuntimeError("workspace 候选样本缺少 Native 预检身份")
        operation_id = self._schedule_operation(
            "workspace_create",
            workspace.workspace_id,
            lambda current_operation_id: self._initialize_workspace(
                workspace,
                operation_id=current_operation_id,
                native_identity=validated_identity,
            ),
            discard_workspace_on_failure=True,
            cancellable=True,
        )
        self._workspace_operations[workspace.workspace_id] = operation_id
        return WorkspaceCreateOutput(
            workspace_id=workspace.workspace_id,
            revision=None,
            sample_sha256=workspace.sample_sha256,
            analysis_operation_id=operation_id,
        )

    async def _workspace_list(
        self,
        arguments: WorkspaceListInput,
    ) -> WorkspaceListOutput:
        workspaces = await asyncio.to_thread(self.storage.workspaces.list)
        digest = query_digest(
            "\n".join(
                f"{item.workspace_id}:{item.current_revision or '-'}" for item in workspaces
            ).encode()
        )
        offset = 0
        if arguments.cursor is not None:
            try:
                offset = self.cursors.decode(
                    arguments.cursor,
                    scope="workspace.list",
                    workspace_id=None,
                    revision=None,
                    query_digest=digest,
                ).offset
            except CursorError as exc:
                raise ToolExecutionError(
                    BusinessErrorCode.CURSOR_STALE,
                    "workspace cursor 已失效",
                ) from exc
        available = workspaces[offset : offset + arguments.page_size]
        summaries: list[WorkspaceSummary] = []
        output = WorkspaceListOutput(workspaces=[])
        for workspace in available:
            candidate_summaries = [*summaries, self._workspace_summary(workspace)]
            next_offset = offset + len(candidate_summaries)
            next_cursor = (
                self.cursors.encode(
                    CursorPosition("workspace.list", None, None, digest, next_offset)
                )
                if next_offset < len(workspaces)
                else None
            )
            candidate = WorkspaceListOutput(
                workspaces=candidate_summaries,
                next_cursor=next_cursor,
            )
            if _inline_model_size(candidate) > MAX_INLINE_RESULT_BYTES:
                break
            summaries = candidate_summaries
            output = candidate
        if available and not summaries:
            raise RuntimeError("单个 workspace 摘要超过 inline 上限")
        return output

    async def _workspace_get(
        self,
        arguments: WorkspaceGetInput,
    ) -> WorkspaceGetOutput:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            workspace = await asyncio.to_thread(
                self.storage.workspaces.get,
                arguments.workspace_id,
            )
            if workspace.current_revision is None:
                raise ToolExecutionError(
                    BusinessErrorCode.EXECUTION_FAILED,
                    "workspace 首次分析尚未成功发布 revision",
                )
            revision_summaries = [
                RevisionSummary(
                    revision=item.revision,
                    parent_revision=item.parent_revision,
                    idb_sha256=item.database_sha256,
                    reason=item.change_id or "initial_analysis",
                    pinned=item.pinned,
                )
                for item in workspace.revisions
            ]
            digest = query_digest(
                canonical_json_bytes(
                    {
                        "revisions": [
                            summary.model_dump(mode="json") for summary in revision_summaries
                        ]
                    }
                )
            )
            offset = 0
            if arguments.cursor is not None:
                offset = self.cursors.decode(
                    arguments.cursor,
                    scope="workspace.get",
                    workspace_id=workspace.workspace_id,
                    revision=workspace.current_revision,
                    query_digest=digest,
                ).offset
            overview = await self._static_query_unlocked(
                "program.overview",
                ProgramOverviewInput(
                    workspace_id=workspace.workspace_id,
                    revision=workspace.current_revision,
                    include=[],
                ),
            )
        typed_overview = cast(ProgramOverviewOutput, overview)
        image = typed_overview.image
        available = revision_summaries[offset : offset + arguments.page_size]
        selected: list[RevisionSummary] = []
        output = WorkspaceGetOutput(
            workspace_id=workspace.workspace_id,
            current_revision=workspace.current_revision,
            sample_name=workspace.sample_name,
            sample_sha256=workspace.sample_sha256,
            architecture=image.architecture,
            bitness=image.bitness,
            endian=image.endian,
            revisions=[],
            next_cursor=None,
        )
        for summary in available:
            candidate_revisions = [*selected, summary]
            next_offset = offset + len(candidate_revisions)
            next_cursor = (
                self.cursors.encode(
                    CursorPosition(
                        "workspace.get",
                        workspace.workspace_id,
                        workspace.current_revision,
                        digest,
                        next_offset,
                    )
                )
                if next_offset < len(revision_summaries)
                else None
            )
            candidate = WorkspaceGetOutput(
                workspace_id=workspace.workspace_id,
                current_revision=workspace.current_revision,
                sample_name=workspace.sample_name,
                sample_sha256=workspace.sample_sha256,
                architecture=image.architecture,
                bitness=image.bitness,
                endian=image.endian,
                revisions=candidate_revisions,
                next_cursor=next_cursor,
            )
            if _inline_model_size(candidate) > MAX_INLINE_RESULT_BYTES:
                break
            selected = candidate_revisions
            output = candidate
        if available and not selected:
            raise RuntimeError("单个 revision 摘要超过 inline 上限")
        return output

    async def _workspace_export(
        self,
        arguments: WorkspaceExportInput,
    ) -> WorkspaceExportOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        operation_id = self._schedule_operation(
            "workspace_export",
            arguments.workspace_id,
            lambda _operation_id: self._export_workspace(arguments),
        )
        return WorkspaceExportOutput(
            operation_id=operation_id,
            workspace_id=arguments.workspace_id,
            revision=arguments.revision,
        )

    async def _static_query(self, name: str, arguments: StrictModel) -> StrictModel:
        typed_arguments = cast(StaticAdapterInput, arguments)
        async with (
            self._workspace_lock(typed_arguments.workspace_id),
            self._analysis_slots,
        ):
            return await self._static_query_unlocked(name, typed_arguments)

    async def _static_query_unlocked(
        self,
        name: str,
        typed_arguments: StaticAdapterInput,
    ) -> StrictModel:
        workspace_id = typed_arguments.workspace_id
        revision = typed_arguments.revision
        cursor: str | None = None
        requested_limit: int | None = None
        if isinstance(
            typed_arguments,
            (ProgramSearchInput, FunctionInspectInput, TypeInspectInput),
        ):
            cursor = typed_arguments.cursor
            requested_limit = typed_arguments.page_size
        elif isinstance(typed_arguments, ProgramOverviewInput):
            requested_limit = 200
        elif isinstance(typed_arguments, GraphQueryInput):
            requested_limit = typed_arguments.max_nodes
        elif isinstance(typed_arguments, DataflowSliceInput):
            requested_limit = typed_arguments.max_steps
        digest = query_digest(
            canonical_json_bytes(
                {
                    "arguments": typed_arguments.model_dump(
                        mode="json",
                        exclude={"cursor"},
                    ),
                    "tool": name,
                }
            )
        )
        offset = 0
        if cursor is not None:
            try:
                offset = self.cursors.decode(
                    cursor,
                    scope=f"static:{name}",
                    workspace_id=workspace_id,
                    revision=revision,
                    query_digest=digest,
                ).offset
            except CursorError as exc:
                raise ToolExecutionError(
                    BusinessErrorCode.CURSOR_STALE,
                    "静态查询 cursor 已失效",
                ) from exc
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace_id,
        )
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            workspace_id,
            revision,
        )
        session = await self._acquire_analysis_session(workspace_id, revision)
        reusable = True
        try:
            requests = build_static_requests(
                name,
                typed_arguments,
                offset=offset,
                limit_override=requested_limit,
            )
            results: list[Mapping[str, object]] = []
            for request in requests:
                result = await session.backend.execute(
                    operation=request.operation,
                    input=request.input,
                    timeout_seconds=_WORKER_TIMEOUT_SECONDS,
                )
                results.append(cast(Mapping[str, object], result))
            output = adapt_static_results(
                name,
                typed_arguments,
                results,
                AnalysisContext(
                    workspace_id=workspace_id,
                    revision=revision,
                    sample_sha256=workspace.sample_sha256,
                ),
            )
            page = static_page_facts(name, typed_arguments, results)
            if page is not None and page.has_more:
                assert page.next_offset is not None
                next_cursor = self.cursors.encode(
                    CursorPosition(
                        f"static:{name}",
                        workspace_id,
                        revision,
                        digest,
                        page.next_offset,
                    )
                )
                output = output.model_copy(update={"next_cursor": next_cursor})
            if _inline_model_size(output) <= MAX_INLINE_RESULT_BYTES:
                return output
            return await self._store_static_artifact(
                name,
                workspace_id,
                revision,
                output,
            )
        except (WorkerProcessError, asyncio.CancelledError):
            reusable = False
            await self._discard_analysis_session(session)
            raise
        finally:
            if reusable:
                await self._release_analysis_session(session)

    async def _acquire_analysis_session(
        self,
        workspace_id: str,
        revision: str,
    ) -> _AnalysisSession:
        key = (workspace_id, revision)
        async with self._analysis_sessions_guard:
            existing = self._analysis_sessions.get(key)
            if existing is not None:
                if existing.in_use:
                    raise RuntimeError("同一 analysis session 被并发复用")
                _cancel_idle_task(existing.idle_task)
                existing.idle_task = None
                existing.in_use = True
                return existing

            if len(self._analysis_sessions) >= self.config.workers.analysis_limit:
                idle = [item for item in self._analysis_sessions.values() if not item.in_use]
                if not idle:
                    raise RuntimeError("analysis worker 池与并发信号量状态不一致")
                victim = min(idle, key=lambda item: item.last_used)
                del self._analysis_sessions[(victim.workspace_id, victim.revision)]
                await self._close_analysis_session(victim)

            checkout = await asyncio.to_thread(
                self.storage.workspaces.create_checkout,
                workspace_id,
                revision,
                purpose="analysis",
            )
            try:
                backend = await self.backend.open_analysis(
                    checkout_path=checkout.database_path,
                    revision=revision,
                )
            except BaseException:
                await asyncio.to_thread(
                    self.storage.workspaces.discard_checkout,
                    checkout,
                )
                raise
            session = _AnalysisSession(
                workspace_id=workspace_id,
                revision=revision,
                checkout=checkout,
                backend=backend,
                in_use=True,
                last_used=asyncio.get_running_loop().time(),
            )
            self._analysis_sessions[key] = session
            return session

    async def _release_analysis_session(self, session: _AnalysisSession) -> None:
        key = (session.workspace_id, session.revision)
        async with self._analysis_sessions_guard:
            if self._analysis_sessions.get(key) is not session:
                return
            session.in_use = False
            session.last_used = asyncio.get_running_loop().time()
            _cancel_idle_task(session.idle_task)

            async def expire() -> None:
                try:
                    await asyncio.sleep(self.config.workers.idle_seconds)
                except asyncio.CancelledError:
                    return
                await self._expire_analysis_session(key, session)

            session.idle_task = asyncio.create_task(
                expire(),
                name=f"analysis-idle:{session.workspace_id}:{session.revision}",
            )

    async def _expire_analysis_session(
        self,
        key: tuple[str, str],
        session: _AnalysisSession,
    ) -> None:
        async with self._analysis_sessions_guard:
            if self._analysis_sessions.get(key) is not session or session.in_use:
                return
            del self._analysis_sessions[key]
            session.idle_task = None
        await self._close_analysis_session(session)

    async def _discard_analysis_session(self, session: _AnalysisSession) -> None:
        key = (session.workspace_id, session.revision)
        async with self._analysis_sessions_guard:
            if self._analysis_sessions.get(key) is session:
                del self._analysis_sessions[key]
            _cancel_idle_task(session.idle_task)
            session.idle_task = None
            session.in_use = False
        await self._close_analysis_session(session)

    async def _open_transient_analysis(
        self,
        checkout_path: Path,
        revision: str,
    ) -> AnalysisBackend:
        async with self._analysis_sessions_guard:
            if len(self._analysis_sessions) >= self.config.workers.analysis_limit:
                idle = [item for item in self._analysis_sessions.values() if not item.in_use]
                if not idle:
                    raise RuntimeError("没有可回收的 analysis worker 容量用于冷验证")
                victim = min(idle, key=lambda item: item.last_used)
                del self._analysis_sessions[(victim.workspace_id, victim.revision)]
                await self._close_analysis_session(victim)
            return await self.backend.open_analysis(
                checkout_path=checkout_path,
                revision=revision,
            )

    async def _close_analysis_session(self, session: _AnalysisSession) -> None:
        _cancel_idle_task(session.idle_task)
        session.idle_task = None
        try:
            await session.backend.close()
        finally:
            await asyncio.to_thread(
                self.storage.workspaces.discard_checkout,
                session.checkout,
            )

    async def _put_public_artifact(
        self,
        *,
        workspace_id: str,
        revision: str,
        data: bytes,
        media_type: str,
        name: str,
    ) -> ArtifactMetadata:
        """公开 payload 超过单块上限时只暴露可逐块读取的索引 resource。"""

        if len(data) <= RESOURCE_CHUNK_BYTES:
            return await _complete_thread_call(
                lambda: self.storage.artifacts.put_bytes(
                    workspace_id=workspace_id,
                    revision=revision,
                    data=data,
                    media_type=media_type,
                    name=name,
                )
            )
        temporary = Path(
            tempfile.mkdtemp(
                prefix="artifact-payload-",
                dir=self.storage.paths.temp_root,
            )
        ).resolve()
        source = temporary / "payload.bin"
        try:
            await asyncio.to_thread(source.write_bytes, data)
            chunked = await _complete_thread_call(
                lambda: self.storage.artifacts.put_chunked_file(
                    workspace_id=workspace_id,
                    revision=revision,
                    source=source,
                    media_type=media_type,
                    name=name,
                )
            )
            return chunked.index
        finally:
            await _complete_thread_call(
                lambda: _safe_remove_temp_directory(
                    temporary,
                    self.storage.paths.temp_root,
                )
            )

    async def _store_static_artifact(
        self,
        name: str,
        workspace_id: str,
        revision: str,
        output: StrictModel,
    ) -> StrictModel:
        payload = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
            sort_keys=True,
        ).encode("utf-8")
        artifact = await self._put_public_artifact(
            workspace_id=workspace_id,
            revision=revision,
            data=payload,
            media_type="application/json",
            name=f"static-{name.replace('.', '-')}.json",
        )
        reference = ArtifactReference(
            uri=artifact.uri,
            sha256=artifact.content_sha256,
            size=artifact.size,
            media_type=artifact.media_type,
        )
        if isinstance(output, ProgramOverviewOutput):
            compact = output.model_copy(
                update={
                    "segments": [],
                    "entry_points": [],
                    "imports": [],
                    "exports": [],
                    "fixups": [],
                    "unwind_regions": [],
                    "functions": [],
                    "strings": [],
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, ProgramSearchOutput):
            compact = output.model_copy(update={"matches": [], "result_artifact": reference})
        elif isinstance(output, AddressInspectOutput):
            compact = output.model_copy(
                update={
                    "bytes_hex": None,
                    "instruction": None,
                    "data_rendering": None,
                    "symbol": None,
                    "function_id": None,
                    "xrefs": [],
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, FunctionInspectOutput):
            compact = output.model_copy(
                update={
                    "name": "",
                    "prototype": None,
                    "chunks": [],
                    "instructions": [],
                    "pseudocode": [],
                    "ctree_map": [],
                    "blocks": [],
                    "calls": [],
                    "strings": [],
                    "stack": None,
                    "locals": [],
                    "type_view": None,
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, GraphQueryOutput):
            compact = output.model_copy(
                update={"nodes": [], "edges": [], "result_artifact": reference}
            )
        elif isinstance(output, DataflowSliceOutput):
            compact = output.model_copy(
                update={
                    "nodes": [],
                    "edges": [],
                    "barriers": [],
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, TypeInspectOutput):
            compact = output.model_copy(
                update={
                    "name": "",
                    "display": "",
                    "fields": [],
                    "result_artifact": reference,
                }
            )
        else:
            raise RuntimeError(f"{name} 未声明 artifact-backed 输出")
        if _inline_model_size(compact) > MAX_INLINE_RESULT_BYTES:
            raise RuntimeError(f"{name} 的 artifact 引用输出仍超过 inline 上限")
        return compact

    async def _static_query_by_ids(
        self,
        name: str,
        workspace_id: str,
        revision: str,
        extra: Mapping[str, JsonValue],
    ) -> StrictModel:
        spec = self._catalog_by_name[name]
        arguments = spec.input_model.model_validate(
            {
                "workspace_id": workspace_id,
                "revision": revision,
                **extra,
            }
        )
        return await self._static_query(name, arguments)

    async def _report_build(
        self,
        arguments: ReportBuildInput,
    ) -> ReportBuildOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        operation_id = self._schedule_operation(
            "report_build",
            arguments.workspace_id,
            lambda _operation_id: self._build_report(arguments),
        )
        return ReportBuildOutput(
            operation_id=operation_id,
            workspace_id=arguments.workspace_id,
            revision=arguments.revision,
        )

    async def _analysis_refine(
        self,
        arguments: AnalysisRefineInput,
    ) -> AnalysisRefineOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        operation_id = self._schedule_operation(
            "analysis_refine",
            arguments.workspace_id,
            lambda current_operation_id: self._refine_workspace(
                arguments,
                operation_id=current_operation_id,
            ),
            cancellable=True,
        )
        return AnalysisRefineOutput(
            operation_id=operation_id,
            workspace_id=arguments.workspace_id,
            base_revision=arguments.revision,
        )

    async def _change_prepare(
        self,
        arguments: ChangePrepareInput,
    ) -> ChangePrepareOutput:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            workspace, revision, context, cold_identity = await self._change_context_unlocked(
                arguments.workspace_id,
                arguments.base_revision,
            )
            if arguments.inverse_of_change_id is not None:
                if (
                    revision.change_id != arguments.inverse_of_change_id
                    or revision.parent_revision is None
                ):
                    raise ToolExecutionError(
                        BusinessErrorCode.PRECONDITION_FAILED,
                        "inverse_of_change_id 只能撤销当前 HEAD 对应的 change",
                    )
                plan = build_canonical_plan(
                    arguments,
                    context,
                    inverse_source=InverseSource(
                        workspace_id=workspace.workspace_id,
                        change_id=arguments.inverse_of_change_id,
                        applied_revision=revision.revision,
                        parent_revision=revision.parent_revision,
                    ),
                )
                impact = _empty_change_impact()
            else:
                validated_sources = await asyncio.to_thread(
                    validate_local_sources,
                    arguments,
                    context,
                )
                execution = build_preflight_execution(
                    arguments,
                    context,
                    validated_sources,
                )
                staging = await self._begin_revision_staging(
                    arguments.workspace_id,
                    expected_revision=arguments.base_revision,
                )
                try:
                    raw = await self.backend.mutate(
                        staging_path=staging.database_path,
                        operations=execution.worker_operations,
                        timeout_seconds=_WORKER_TIMEOUT_SECONDS,
                    )
                    impact = parse_preflight_impact(
                        arguments,
                        validated_sources,
                        raw,
                    )
                    await self._cold_validate(staging, expected=cold_identity)
                finally:
                    if staging.path.exists():
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.abort_staging(staging)
                        )

                requests = source_solidification_requests(validated_sources)
                solidified_sources: tuple[SolidifiedSource, ...] = ()
                if requests:
                    artifact_inputs = tuple(
                        ArtifactFileInput(
                            workspace_id=arguments.workspace_id,
                            revision=arguments.base_revision,
                            source=item.source,
                            media_type=item.media_type,
                            name=item.name,
                            expected_sha256=item.expected_sha256,
                            expected_size=item.size,
                            listed=False,
                        )
                        for item in requests
                    )
                    artifacts = await _complete_thread_call(
                        lambda: self.storage.artifacts.put_files_atomic(artifact_inputs)
                    )
                    solidified_sources = tuple(
                        SolidifiedSource(
                            operation_index=request.operation_index,
                            role=request.role,
                            artifact_uri=artifact.uri,
                            content_sha256=artifact.content_sha256,
                            size=artifact.size,
                        )
                        for request, artifact in zip(requests, artifacts, strict=True)
                    )
                plan = build_canonical_plan(
                    arguments,
                    context,
                    validated_sources=validated_sources,
                    solidified_sources=solidified_sources,
                )

            change_set = await _complete_thread_call(
                lambda: self.changes.prepare(
                    workspace_id=arguments.workspace_id,
                    base_revision=arguments.base_revision,
                    operations=plan.operations,
                    preimage=plan.preimage,
                    inverse_of_change_id=plan.inverse_of_change_id,
                )
            )
            output = ChangePrepareOutput(
                workspace_id=arguments.workspace_id,
                base_revision=arguments.base_revision,
                change_set_id=change_set.change_set_id,
                digest=change_set.digest,
                operation_count=len(change_set.operations),
                impact=impact,
            )
            if _inline_model_size(output) <= MAX_INLINE_RESULT_BYTES:
                return output
            payload = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
                sort_keys=True,
            ).encode("utf-8")
            artifact = await self._put_public_artifact(
                workspace_id=arguments.workspace_id,
                revision=arguments.base_revision,
                data=payload,
                media_type="application/vnd.ida-re.change-impact+json",
                name=f"{change_set.change_set_id}-impact.json",
            )
            compact = output.model_copy(
                update={
                    "impact": output.impact.model_copy(
                        update={
                            "conflicts": [],
                            "conflicts_artifact": ArtifactReference(
                                uri=artifact.uri,
                                sha256=artifact.content_sha256,
                                size=artifact.size,
                                media_type=artifact.media_type,
                            ),
                        }
                    )
                }
            )
            if _inline_model_size(compact) > MAX_INLINE_RESULT_BYTES:
                raise RuntimeError("change.prepare artifact 引用结果仍超过 inline 上限")
            return compact

    async def _change_apply(
        self,
        arguments: ChangeApplyInput,
    ) -> ChangeApplyOutput:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            _workspace, revision, context, cold_identity = await self._change_context_unlocked(
                arguments.workspace_id,
                arguments.expected_revision,
            )
            change_set = await asyncio.to_thread(
                self.changes.load_for_apply,
                workspace_id=arguments.workspace_id,
                base_revision=arguments.expected_revision,
                change_set_id=arguments.change_set_id,
                digest=arguments.digest,
            )
            if (
                change_set.preimage.revision != revision.revision
                or change_set.preimage.database_sha256 != revision.database_sha256
                or change_set.preimage.component_hashes != dict(revision.component_hashes)
            ):
                raise RevisionConflictError("ChangeSet preimage 与当前冷 revision 不一致")

            temporary = Path(
                tempfile.mkdtemp(
                    prefix="change-apply-",
                    dir=self.storage.paths.temp_root,
                )
            ).resolve()
            try:
                materializations = await asyncio.to_thread(
                    self._materialize_change_artifacts,
                    change_set.operations,
                    temporary,
                )
                execution = build_mutation_execution(
                    change_set.operations,
                    context,
                    artifacts=materializations,
                )
                staging = await self._begin_revision_staging(
                    arguments.workspace_id,
                    expected_revision=arguments.expected_revision,
                    source_revision=execution.restore_revision,
                )
                try:
                    if execution.mode == "worker":
                        raw = await self.backend.mutate(
                            staging_path=staging.database_path,
                            operations=execution.worker_operations,
                            timeout_seconds=_WORKER_TIMEOUT_SECONDS,
                        )
                        parse_worker_impact(change_set.operations, raw)
                    receipt = await self._cold_validate(staging, expected=cold_identity)
                    change_id = f"change_{uuid.uuid4().hex}"
                    published = await _complete_thread_call(
                        lambda: self.storage.workspaces.publish_staging(
                            staging,
                            receipt=receipt,
                            change_id=change_id,
                        )
                    )
                except BaseException:
                    if staging.path.exists():
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.abort_staging(staging)
                        )
                    raise
            finally:
                await _complete_thread_call(
                    lambda: _safe_remove_temp_directory(
                        temporary,
                        self.storage.paths.temp_root,
                    )
                )
            return ChangeApplyOutput(
                workspace_id=arguments.workspace_id,
                previous_revision=arguments.expected_revision,
                revision=published.revision,
                change_id=change_id,
            )

    async def _change_context_unlocked(
        self,
        workspace_id: str,
        base_revision: str,
    ) -> tuple[
        WorkspaceSnapshot,
        RevisionSnapshot,
        ChangeContext,
        _ColdImageIdentity,
    ]:
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace_id,
        )
        if workspace.current_revision != base_revision:
            raise RevisionConflictError("base revision 不是 workspace 当前 HEAD")
        revision = await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            workspace_id,
            base_revision,
        )
        overview = cast(
            ProgramOverviewOutput,
            await self._static_query_unlocked(
                "program.overview",
                ProgramOverviewInput(
                    workspace_id=workspace_id,
                    revision=base_revision,
                    include=[],
                ),
            ),
        )
        native = await asyncio.to_thread(
            _native_binding,
            workspace,
            overview,
        )
        return (
            workspace,
            revision,
            ChangeContext(
                workspace_id=workspace_id,
                base_revision=base_revision,
                image_id=overview.image.image_id,
                sample_sha256=workspace.sample_sha256,
                database_sha256=revision.database_sha256,
                component_hashes=dict(revision.component_hashes),
                native=native,
            ),
            _ColdImageIdentity.from_overview(workspace.sample_sha256, overview),
        )

    def _materialize_change_artifacts(
        self,
        operations: tuple[StoredChangeOperation, ...],
        temporary: Path,
    ) -> tuple[ArtifactMaterialization, ...]:
        materialized: dict[str, ArtifactMaterialization] = {}
        for operation in operations:
            if not isinstance(operation, StoredImportIl2CppBundleOperation):
                continue
            references = (
                (
                    operation.bundle_artifact_uri,
                    operation.bundle_sha256,
                    operation.bundle_size,
                    ".ndjson",
                ),
                (
                    operation.metadata_artifact_uri,
                    operation.metadata_sha256,
                    operation.metadata_size,
                    ".metadata",
                ),
            )
            for uri, expected_sha256, expected_size, suffix in references:
                if uri in materialized:
                    continue
                target = temporary / f"source-{len(materialized)}{suffix}"
                metadata = self.storage.artifacts.materialize_uri(uri, target)
                if metadata.content_sha256 != expected_sha256 or metadata.size != expected_size:
                    raise ChangeSetError("ChangeSet artifact 身份与不可变计划不一致")
                materialized[uri] = ArtifactMaterialization(
                    artifact_uri=uri,
                    content_sha256=metadata.content_sha256,
                    size=metadata.size,
                    path=target,
                )
        return tuple(materialized.values())

    async def _debug_tool(self, name: str, arguments: StrictModel) -> StrictModel:
        if name == "debug.establish":
            return await self._debug_establish(cast(DebugEstablishInput, arguments))
        if name == "debug.control":
            request = cast(DebugControlInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.events":
            request = cast(DebugEventsInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.inspect":
            request = cast(DebugInspectInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.breakpoints":
            request = cast(DebugBreakpointsInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.finish":
            request = cast(DebugFinishInput, arguments)
            session_id = request.debug_session_id
        else:
            raise ToolExecutionError(BusinessErrorCode.UNSUPPORTED, f"未知调试工具: {name}")
        session = self._debug_sessions.get(session_id)
        if session is None:
            raise ToolExecutionError(
                BusinessErrorCode.DEBUG_STATE_CONFLICT,
                "debug_session_id 不存在或已经结束",
            )
        self._cancel_debug_idle(session)
        try:
            if name == "debug.control":
                typed = cast(DebugControlInput, request)
                raw = await self._execute_debug(
                    session,
                    prepare_debug_control(session.context, typed),
                    timeout_seconds=typed.timeout_ms / 1000 + 5,
                )
                adapted = adapt_debug_control(session.context, raw)
                session.context = adapted.context
                return adapted.output
            if name == "debug.events":
                typed = cast(DebugEventsInput, request)
                raw = await self._execute_debug(
                    session,
                    prepare_debug_events(session.context, typed),
                    timeout_seconds=typed.wait_ms / 1000 + 5,
                )
                adapted = adapt_debug_events(session.context, typed, raw)
                session.context = adapted.context
                return adapted.output
            if name == "debug.inspect":
                typed = cast(DebugInspectInput, request)
                raw_results = [
                    await self._execute_debug(session, command, timeout_seconds=35)
                    for command in prepare_debug_inspect(session.context, typed)
                ]
                adapted = adapt_debug_inspect(session.context, typed, raw_results)
                session.context = adapted.context
                output = adapted.output
                if _inline_model_size(output) > MAX_INLINE_RESULT_BYTES:
                    if output.memory_bytes is not None:
                        memory = bytes.fromhex(output.memory_bytes)
                        artifact = await asyncio.to_thread(
                            self.storage.artifacts.put_bytes,
                            workspace_id=session.checkout.workspace_id,
                            revision=session.checkout.revision,
                            data=memory,
                            media_type="application/octet-stream",
                            name=f"debug-memory-{typed.stop_id}.bin",
                        )
                        output = output.model_copy(
                            update={
                                "memory_bytes": None,
                                "memory_artifact": ArtifactReference(
                                    uri=artifact.uri,
                                    sha256=artifact.content_sha256,
                                    size=artifact.size,
                                    media_type=artifact.media_type,
                                ),
                            }
                        )
                    if _inline_model_size(output) > MAX_INLINE_RESULT_BYTES:
                        snapshot_data = json.dumps(
                            output.model_dump(mode="json"),
                            ensure_ascii=False,
                            separators=(",", ":"),
                            allow_nan=False,
                            sort_keys=True,
                        ).encode("utf-8")
                        snapshot = await self._put_public_artifact(
                            workspace_id=session.checkout.workspace_id,
                            revision=session.checkout.revision,
                            data=snapshot_data,
                            media_type="application/vnd.ida-re.debug-snapshot+json",
                            name=f"debug-snapshot-{typed.stop_id}.json",
                        )
                        output = type(output)(
                            debug_session_id=output.debug_session_id,
                            stop_id=output.stop_id,
                            state="suspended",
                            modules=[],
                            threads=[],
                            registers=[],
                            stack=[],
                            snapshot_artifact=ArtifactReference(
                                uri=snapshot.uri,
                                sha256=snapshot.content_sha256,
                                size=snapshot.size,
                                media_type=snapshot.media_type,
                            ),
                        )
                return output
            if name == "debug.breakpoints":
                return await self._debug_replace_breakpoints(
                    session,
                    cast(DebugBreakpointsInput, request),
                )

            typed = cast(DebugFinishInput, request)
            if typed.action == "terminate" and not session.owned_target:
                raise ToolExecutionError(
                    BusinessErrorCode.POLICY_DENIED,
                    "只能终止由本服务启动并纳入 Job Object 的目标",
                )
            if typed.action == "detach" and session.owned_target:
                raise ToolExecutionError(
                    BusinessErrorCode.POLICY_DENIED,
                    "本服务启动的目标必须使用 terminate 结束",
                )
            raw = await self._execute_debug(
                session,
                prepare_debug_finish(session.context, typed),
                timeout_seconds=typed.timeout_ms / 1000 + 5,
            )
            adapted = adapt_debug_finish(session.context, raw)
            session.context = adapted.context
            await self._close_debug_session(session)
            return adapted.output
        except WorkerProcessError:
            await self._close_debug_session(session)
            raise
        except DebugRequestCancelled as cancellation:
            if isinstance(cancellation.failure, WorkerProcessError) or session.context.state in {
                "exited",
                "detached",
                "lost",
                "failed",
            }:
                await self._close_debug_session(session)
            raise
        finally:
            if self._debug_sessions.get(session_id) is session:
                self._arm_debug_idle(session)

    async def _debug_establish(
        self,
        arguments: DebugEstablishInput,
    ) -> DebugEstablishOutput:
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            arguments.workspace_id,
        )
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        target_kind = arguments.target.kind
        if target_kind == "launch" and not self.config.policy.debug_launch:
            raise ToolExecutionError(
                BusinessErrorCode.POLICY_DENIED,
                "策略禁止 launch",
            )
        if target_kind == "attach" and not self.config.policy.debug_attach:
            raise ToolExecutionError(
                BusinessErrorCode.POLICY_DENIED,
                "策略禁止 attach",
            )
        runtime_sample_name = (
            workspace.sample_path.name
            if isinstance(arguments.target, DebugLaunchTarget)
            else workspace.sample_name
        )
        workspace_lock = self._workspace_lock(workspace.workspace_id)
        await workspace_lock.acquire()
        debug_slot_acquired = False
        checkout: RevisionCheckout | None = None
        backend: DebugBackend | None = None
        try:
            await self._debug_slots.acquire()
            debug_slot_acquired = True
            checkout = await asyncio.to_thread(
                self.storage.workspaces.create_checkout,
                workspace.workspace_id,
                arguments.revision,
                purpose="debug",
            )
            backend = await self.backend.open_debug(
                checkout_path=checkout.database_path,
                sample_path=workspace.sample_path,
                revision=arguments.revision,
                allow_attach=self.config.policy.debug_attach,
            )
            command = prepare_debug_establish(arguments)
            try:
                raw = await backend.execute(
                    command.operation,
                    command.input,
                    timeout_seconds=arguments.timeout_ms / 1000 + 5,
                )
            except DebugRequestCancelled as cancellation:
                if cancellation.result is not None:
                    # 确认 worker 在取消完成前确实观察到了合法运行态或停点。
                    adapt_debug_establish(
                        arguments,
                        cancellation.result,
                        sample_name=runtime_sample_name,
                        image_id=f"image~{workspace.sample_sha256}",
                    )
                raise
            adapted = adapt_debug_establish(
                arguments,
                raw,
                sample_name=runtime_sample_name,
                image_id=f"image~{workspace.sample_sha256}",
            )
            session = _DebugSession(
                checkout=checkout,
                backend=backend,
                context=adapted.context,
                workspace_lock=workspace_lock,
                owned_target=isinstance(arguments.target, DebugLaunchTarget),
            )
            # 读取一次不可消费的事件快照, 以建立 module/RVA 映射事实。
            event_request = DebugEventsInput(
                debug_session_id=adapted.context.debug_session_id,
                after_sequence=0,
                wait_ms=0,
                limit=200,
            )
            event_command = prepare_debug_events(session.context, event_request)
            event_raw = await self._execute_debug(session, event_command, timeout_seconds=5)
            session.context = adapt_debug_events(
                session.context,
                event_request,
                event_raw,
            ).context
            self._debug_sessions[session.context.debug_session_id] = session
            self._arm_debug_idle(session)
            return adapted.output
        except BaseException:
            if backend is not None:
                await backend.close()
            if checkout is not None:
                await asyncio.to_thread(
                    self.storage.workspaces.discard_checkout,
                    checkout,
                )
            if debug_slot_acquired:
                self._debug_slots.release()
            await workspace_lock.release()
            raise

    async def _execute_debug(
        self,
        session: _DebugSession,
        command: WorkerDebugCommand,
        *,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        try:
            return await session.backend.execute(
                command.operation,
                command.input,
                timeout_seconds=timeout_seconds,
            )
        except DebugRequestCancelled as cancellation:
            if cancellation.result is not None:
                session.context = adapt_debug_cancelled(
                    session.context,
                    cancellation.result,
                )
            raise

    async def _debug_replace_breakpoints(
        self,
        session: _DebugSession,
        request: DebugBreakpointsInput,
    ) -> StrictModel:
        current = await self._execute_debug(
            session,
            prepare_debug_breakpoint_list(session.context, request),
            timeout_seconds=35,
        )
        replacement = build_debug_breakpoint_replacement(
            session.context,
            request,
            current,
        )
        try:
            final = await self._apply_breakpoint_plan(session, replacement)
            output = adapt_debug_breakpoints(session.context, request, final)
            if _inline_model_size(output) <= MAX_INLINE_RESULT_BYTES:
                return output
            payload = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
                sort_keys=True,
            ).encode("utf-8")
            artifact = await self._put_public_artifact(
                workspace_id=session.checkout.workspace_id,
                revision=session.checkout.revision,
                data=payload,
                media_type="application/vnd.ida-re.debug-breakpoints+json",
                name=f"debug-breakpoints-{request.stop_id}.json",
            )
            compact = output.model_copy(
                update={
                    "breakpoints": [],
                    "result_artifact": ArtifactReference(
                        uri=artifact.uri,
                        sha256=artifact.content_sha256,
                        size=artifact.size,
                        media_type=artifact.media_type,
                    ),
                }
            )
            if _inline_model_size(compact) > MAX_INLINE_RESULT_BYTES:
                raise RuntimeError("debug.breakpoints artifact 引用结果仍超过 inline 上限")
            return compact
        except BaseException as original:
            try:
                current_after_failure = await self._execute_debug(
                    session,
                    replacement.verify_command,
                    timeout_seconds=35,
                )
                rollback = build_debug_breakpoint_rollback(
                    session.context,
                    replacement,
                    current_after_failure,
                )
                await self._apply_breakpoint_plan(session, rollback)
            except BaseException as rollback_error:
                raise ToolExecutionError(
                    BusinessErrorCode.EXECUTION_FAILED,
                    "断点替换失败且无法恢复原断点集合",
                    details={
                        "failure": type(original).__name__,
                        "rollback_failure": type(rollback_error).__name__,
                    },
                ) from rollback_error
            raise

    async def _apply_breakpoint_plan(
        self,
        session: _DebugSession,
        plan: BreakpointReplacementPlan,
    ) -> Mapping[str, object]:
        for command in plan.remove_commands:
            await self._execute_debug(session, command, timeout_seconds=35)
        for step in plan.add_steps:
            add_result = await self._execute_debug(
                session,
                step.command,
                timeout_seconds=35,
            )
            enable = prepare_debug_breakpoint_enable(
                add_result,
                enabled=step.enabled,
            )
            if enable is not None:
                await self._execute_debug(session, enable, timeout_seconds=35)
        return await self._execute_debug(
            session,
            plan.verify_command,
            timeout_seconds=35,
        )

    async def _close_debug_session(self, session: _DebugSession) -> None:
        self._debug_sessions.pop(session.context.debug_session_id, None)
        self._cancel_debug_idle(session)
        try:
            await session.backend.close()
        finally:
            try:
                await asyncio.to_thread(
                    self.storage.workspaces.discard_checkout,
                    session.checkout,
                )
            finally:
                try:
                    await session.workspace_lock.release()
                finally:
                    self._debug_slots.release()

    def _cancel_debug_idle(self, session: _DebugSession) -> None:
        task = session.idle_task
        session.idle_task = None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()

    def _arm_debug_idle(self, session: _DebugSession) -> None:
        self._cancel_debug_idle(session)

        async def expire() -> None:
            try:
                await asyncio.sleep(self.config.workers.idle_seconds)
                if self._debug_sessions.get(session.context.debug_session_id) is session:
                    await self._close_debug_session(session)
            except asyncio.CancelledError:
                return

        session.idle_task = asyncio.create_task(
            expire(),
            name=f"debug-idle:{session.context.debug_session_id}",
        )

    async def _expert_execute(
        self,
        arguments: ExpertExecuteInput,
    ) -> ExpertExecuteOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            cold_identity = await self._revision_cold_identity_unlocked(
                arguments.workspace_id,
                arguments.revision,
            )
            staging = await self._begin_revision_staging(
                arguments.workspace_id,
                expected_revision=arguments.revision,
            )
            try:
                raw = await self.backend.expert(
                    staging_path=staging.database_path,
                    code=arguments.code,
                    timeout_seconds=float(arguments.timeout_seconds),
                )
                result = adapt_expert_worker_result(raw, staging.database_path)
                receipt = await self._cold_validate(staging, expected=cold_identity)
                output = ExpertExecuteOutput(
                    workspace_id=arguments.workspace_id,
                    base_revision=arguments.revision,
                    revision=staging.candidate_revision,
                    output_mode="inline",
                    stdout=result.stdout,
                    stderr=result.stderr,
                    result_repr=result.result_repr,
                )
                output_artifact: ArtifactMetadata | None = None
                if _inline_model_size(output) > MAX_INLINE_RESULT_BYTES:
                    payload = json.dumps(
                        {
                            "result_repr": result.result_repr,
                            "stderr": result.stderr,
                            "stdout": result.stdout,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                        allow_nan=False,
                        sort_keys=True,
                    ).encode("utf-8")
                    output_artifact = await _complete_thread_call(
                        lambda: self.storage.artifacts.put_bytes(
                            workspace_id=arguments.workspace_id,
                            revision=staging.candidate_revision,
                            data=payload,
                            media_type="application/vnd.ida-re.expert-output+json",
                            name="expert-output.json",
                        )
                    )
                    output = ExpertExecuteOutput(
                        workspace_id=arguments.workspace_id,
                        base_revision=arguments.revision,
                        revision=staging.candidate_revision,
                        output_mode="artifact",
                        artifact=ArtifactReference(
                            uri=output_artifact.uri,
                            sha256=output_artifact.content_sha256,
                            size=output_artifact.size,
                            media_type=output_artifact.media_type,
                        ),
                    )
                try:
                    revision = await _complete_thread_call(
                        lambda: self.storage.workspaces.publish_staging(
                            staging,
                            receipt=receipt,
                            change_id=f"expert_{uuid.uuid4().hex}",
                        )
                    )
                except BaseException:
                    if output_artifact is not None:
                        await _complete_thread_call(
                            lambda: self.storage.artifacts.discard_unpublished(output_artifact)
                        )
                    raise
                if revision.revision != output.revision:
                    raise RuntimeError("expert 发布的 revision 与候选身份不一致")
                return output
            except BaseException:
                if staging.path.exists():
                    await _complete_thread_call(
                        lambda: self.storage.workspaces.abort_staging(staging)
                    )
                raise

    async def _refine_workspace(
        self,
        arguments: AnalysisRefineInput,
        *,
        operation_id: str,
    ) -> JsonObject:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            cold_identity = await self._revision_cold_identity_unlocked(
                arguments.workspace_id,
                arguments.revision,
            )
            staging = await self._begin_revision_staging(
                arguments.workspace_id,
                expected_revision=arguments.revision,
            )
            try:
                request = build_refine_worker_request(arguments, staging.database_path)
                raw = await self.backend.refine(
                    staging_path=staging.database_path,
                    input=request.input,
                    timeout_seconds=_WORKER_TIMEOUT_SECONDS,
                )
                result = adapt_refine_worker_result(
                    arguments,
                    raw,
                    staging.database_path,
                )
                receipt = await self._cold_validate(staging, expected=cold_identity)
                operation_result: JsonObject = {
                    "workspace_id": arguments.workspace_id,
                    "previous_revision": arguments.revision,
                    "revision": staging.candidate_revision,
                    "actions": [item.model_dump(mode="json") for item in result.actions],
                }
                revision = await _complete_thread_call(
                    lambda: self.storage.workspaces.publish_staging(
                        staging,
                        receipt=receipt,
                        change_id=f"refine_{uuid.uuid4().hex}",
                        operation_id=operation_id,
                        operation_result=operation_result,
                    )
                )
                if revision.revision != staging.candidate_revision:
                    raise RuntimeError("refine 发布的 revision 与候选身份不一致")
                return operation_result
            except BaseException:
                if staging.path.exists():
                    await _complete_thread_call(
                        lambda: self.storage.workspaces.abort_staging(staging)
                    )
                raise

    async def _initialize_workspace(
        self,
        workspace: WorkspaceSnapshot,
        *,
        operation_id: str,
        native_identity: NativeImageIdentity,
    ) -> JsonObject:
        async with (
            self._workspace_lock(workspace.workspace_id),
            self._analysis_slots,
        ):
            return await self._initialize_workspace_unlocked(
                workspace,
                operation_id=operation_id,
                native_identity=native_identity,
            )

    async def _initialize_workspace_unlocked(
        self,
        workspace: WorkspaceSnapshot,
        *,
        operation_id: str,
        native_identity: NativeImageIdentity,
    ) -> JsonObject:
        current_workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace.workspace_id,
        )
        current_identity = await asyncio.to_thread(
            inspect_native_image,
            current_workspace.sample_path,
        )
        if (
            current_workspace.sample_sha256 != workspace.sample_sha256
            or current_identity != native_identity
        ):
            raise RuntimeError("workspace 样本身份在 Native 预检后发生变化")
        workspace = current_workspace
        staging = await self._begin_revision_staging(
            workspace.workspace_id,
            expected_revision=None,
        )
        try:
            result = await self.backend.bootstrap(
                sample_path=workspace.sample_path,
                staging_path=staging.database_path,
                timeout_seconds=_WORKER_TIMEOUT_SECONDS,
            )
            if result.get("input_sha256") != workspace.sample_sha256:
                raise RuntimeError("bootstrap worker 返回的样本摘要不一致")
            receipt = await self._cold_validate(
                staging,
                expected=_ColdImageIdentity(
                    sample_sha256=workspace.sample_sha256,
                    architecture=native_identity.architecture,
                    bitness=native_identity.bitness,
                    endianness=native_identity.endian,
                ),
            )
            operation_result: JsonObject = {
                "workspace_id": workspace.workspace_id,
                "revision": staging.candidate_revision,
                "sample_sha256": workspace.sample_sha256,
            }
            revision = await _complete_thread_call(
                lambda: self.storage.workspaces.publish_staging(
                    staging,
                    receipt=receipt,
                    operation_id=operation_id,
                    operation_result=operation_result,
                )
            )
            if revision.revision != staging.candidate_revision:
                raise RuntimeError("bootstrap 发布的 revision 与候选身份不一致")
            return operation_result
        except BaseException:
            if staging.path.exists():
                await _complete_thread_call(lambda: self.storage.workspaces.abort_staging(staging))
            raise

    async def _begin_revision_staging(
        self,
        workspace_id: str,
        *,
        expected_revision: str | None,
        source_revision: str | None = None,
    ) -> RevisionStaging:
        """取消若撞上 staging 创建; 先取得句柄并完整回滚再传播取消。"""

        future = asyncio.create_task(
            asyncio.to_thread(
                self.storage.workspaces.begin_staging,
                workspace_id,
                expected_revision=expected_revision,
                source_revision=source_revision,
            )
        )
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError as cancellation:
            staging = await _await_task_without_cancellation(future)
            await _complete_thread_call(lambda: self.storage.workspaces.abort_staging(staging))
            raise cancellation

    async def _revision_cold_identity_unlocked(
        self,
        workspace_id: str,
        revision: str,
    ) -> _ColdImageIdentity:
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace_id,
        )
        overview = cast(
            ProgramOverviewOutput,
            await self._static_query_unlocked(
                "program.overview",
                ProgramOverviewInput(
                    workspace_id=workspace_id,
                    revision=revision,
                    include=[],
                ),
            ),
        )
        return _ColdImageIdentity.from_overview(workspace.sample_sha256, overview)

    async def _cold_validate(
        self,
        staging: RevisionStaging,
        *,
        expected: _ColdImageIdentity,
    ) -> ColdValidationReceipt:
        backend = await self._open_transient_analysis(
            staging.database_path,
            staging.candidate_revision,
        )
        try:
            overview = await backend.execute(
                operation="program.overview",
                input={"limit": 1},
                timeout_seconds=_WORKER_TIMEOUT_SECONDS,
            )
        finally:
            await backend.close()
        image = overview.get("image")
        if not isinstance(image, dict):
            raise RuntimeError("冷验证未返回可信镜像身份")
        if image.get("sha256") != expected.sample_sha256:
            raise RuntimeError("冷验证原样本 SHA-256 与 workspace 身份不一致")
        architecture = image.get("architecture")
        bitness = image.get("bitness")
        endianness = image.get("endianness")
        image_size = image.get("image_size")
        if (
            architecture not in {"x86_64", "aarch64"}
            or isinstance(bitness, bool)
            or bitness != 64
            or endianness != "little"
            or isinstance(image_size, bool)
            or not isinstance(image_size, int)
            or image_size < 1
        ):
            raise RuntimeError("冷验证镜像不满足当前 Native 产品边界")
        if (
            (expected.architecture is not None and architecture != expected.architecture)
            or (expected.bitness is not None and bitness != expected.bitness)
            or (expected.endianness is not None and endianness != expected.endianness)
            or (expected.image_size is not None and image_size != expected.image_size)
        ):
            raise RuntimeError("冷验证镜像身份与 base revision 不一致")
        hashes = await asyncio.to_thread(hash_staging_payload, staging)
        return ColdValidationReceipt.create(
            validator="ida_9_3_headless",
            component_hashes=hashes,
        )

    async def _export_workspace(
        self,
        arguments: WorkspaceExportInput,
    ) -> JsonObject:
        async with self._workspace_lock(arguments.workspace_id):
            revision = await asyncio.to_thread(
                self.storage.workspaces.get_revision,
                arguments.workspace_id,
                arguments.revision,
            )
            added_pin = not revision.pinned
            if added_pin:
                await _complete_thread_call(
                    lambda: self.storage.workspaces.pin_revision(
                        arguments.workspace_id,
                        arguments.revision,
                        pinned=True,
                    )
                )
            try:
                artifact = await _complete_thread_call(
                    lambda: self.storage.artifacts.put_chunked_file(
                        workspace_id=arguments.workspace_id,
                        revision=arguments.revision,
                        source=revision.database_path,
                        media_type="application/vnd.hex-rays.idb",
                        name=f"{arguments.workspace_id}-{arguments.revision}.i64",
                    )
                )
            except BaseException:
                if added_pin:
                    try:
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.pin_revision(
                                arguments.workspace_id,
                                arguments.revision,
                                pinned=False,
                            )
                        )
                    except BaseException as rollback_failure:
                        raise RuntimeError(
                            "workspace export 失败且无法撤销新增 revision pin"
                        ) from rollback_failure
                raise
        return {
            "artifact_uri": artifact.index.uri,
            "sha256": artifact.content_sha256,
            "size": artifact.size,
            "media_type": artifact.media_type,
            "encoding": "chunked_artifact_index",
            "chunk_count": len(artifact.chunks),
        }

    async def _build_report(self, arguments: ReportBuildInput) -> JsonObject:
        include: list[JsonValue] = []
        if "entry_points" in arguments.sections:
            include.append("entry_points")
        if "imports_exports" in arguments.sections:
            include.extend(("imports", "exports"))
        overview = cast(
            ProgramOverviewOutput,
            await self._static_query_by_ids(
                "program.overview",
                arguments.workspace_id,
                arguments.revision,
                {"include": include},
            ),
        )
        if overview.result_artifact is not None:
            artifact_ref = overview.result_artifact
            artifact_workspace, artifact_revision, artifact_id = parse_artifact_uri(
                artifact_ref.uri
            )
            metadata = await asyncio.to_thread(
                self.storage.artifacts.get,
                artifact_workspace,
                artifact_revision,
                artifact_id,
            )
            if (
                artifact_workspace != arguments.workspace_id
                or artifact_revision != arguments.revision
                or metadata.content_sha256 != artifact_ref.sha256
                or metadata.size != artifact_ref.size
            ):
                raise RuntimeError("report.build 的静态 artifact 身份不一致")
            overview = ProgramOverviewOutput.model_validate_json(
                await asyncio.to_thread(
                    self.storage.artifacts.read_all,
                    artifact_workspace,
                    artifact_revision,
                    artifact_id,
                ),
                strict=True,
            )
        document: dict[str, object] = {
            "title": arguments.title or "Reverse Engineering Report",
            "workspace_id": arguments.workspace_id,
            "revision": arguments.revision,
            "sections": arguments.sections,
        }
        overview_json = overview.model_dump(mode="json")
        if "overview" in arguments.sections:
            document["overview"] = {
                "image": overview_json["image"],
                "counts": overview_json["counts"],
                "coverage": overview_json["coverage"],
                "provenance": overview_json["provenance"],
            }
        if "entry_points" in arguments.sections:
            document["entry_points"] = overview_json["entry_points"]
        if "imports_exports" in arguments.sections:
            document["imports"] = overview_json["imports"]
            document["exports"] = overview_json["exports"]
        if arguments.format == "json":
            data = json.dumps(
                document,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            media_type = "application/json"
            name = "report.json"
        else:
            lines = [
                f"# {document['title']}\n\n"
                f"- Workspace: `{arguments.workspace_id}`\n"
                f"- Revision: `{arguments.revision}`\n"
            ]
            if "overview" in arguments.sections:
                lines.extend(
                    (
                        "\n## Overview\n\n",
                        f"- Architecture: `{overview.image.architecture}`\n",
                        f"- Format: `{overview.image.format}`\n",
                        f"- Image base: `{overview.image.image_base}`\n",
                        f"- Image size: `{overview.image.image_size}`\n",
                        f"- SHA-256: `{overview.image.sha256}`\n",
                        f"- Functions: `{overview.counts.functions}`\n",
                        f"- Strings: `{overview.counts.strings}`\n",
                    )
                )
            if "entry_points" in arguments.sections:
                lines.append("\n## Entry points\n\n")
                lines.extend(
                    f"- `{item.name}` at `{_address_text(item.address.model_dump(mode='json'))}`\n"
                    for item in overview.entry_points
                )
            if "imports_exports" in arguments.sections:
                for heading, items in (
                    ("Imports", overview.imports),
                    ("Exports", overview.exports),
                ):
                    lines.append(f"\n## {heading}\n\n")
                    lines.extend(
                        f"- `{item.name}` at "
                        f"`{_address_text(item.address.model_dump(mode='json'))}`\n"
                        for item in items
                    )
            data = "".join(lines).encode("utf-8")
            media_type = "text/markdown"
            name = "report.md"
        artifact = await self._put_public_artifact(
            workspace_id=arguments.workspace_id,
            revision=arguments.revision,
            data=data,
            media_type=media_type,
            name=name,
        )
        return {
            "artifact_uri": artifact.uri,
            "sha256": artifact.content_sha256,
            "size": artifact.size,
        }

    def _workspace_summary(self, workspace: WorkspaceSnapshot) -> WorkspaceSummary:
        state = "ready"
        if workspace.current_revision is None:
            state = "analyzing"
            operation_id = self._workspace_operations.get(workspace.workspace_id)
            operation = None
            if operation_id is not None:
                try:
                    operation = self.storage.operations.get(operation_id)
                except OperationNotFoundError:
                    pass
            if operation is None:
                operation = self.storage.operations.latest(
                    workspace_id=workspace.workspace_id,
                    kind="workspace_create",
                )
            if operation is not None and operation.state in {
                OperationState.FAILED,
                OperationState.CANCELLED,
            }:
                state = "failed"
        return WorkspaceSummary(
            workspace_id=workspace.workspace_id,
            revision=workspace.current_revision,
            sample_name=workspace.sample_name,
            sample_sha256=workspace.sample_sha256,
            architecture=None,
            state=state,
        )

    def _schedule_operation(
        self,
        kind: str,
        workspace_id: str,
        work: Callable[[str], Awaitable[JsonObject]],
        *,
        discard_workspace_on_failure: bool = False,
        cancellable: bool = False,
    ) -> str:
        snapshot = self.storage.operations.create(kind, workspace_id=workspace_id)

        async def run() -> None:
            try:
                current = self.storage.operations.get(snapshot.operation_id)
                if current.state is OperationState.CANCELLED:
                    if discard_workspace_on_failure:
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.discard_uninitialized(workspace_id)
                        )
                    return
                self.storage.operations.start(snapshot.operation_id)
                result = await work(snapshot.operation_id)
                # Worker 调用一旦进入不可中断区, 只能在真实完成后报告成功;
                # 已迟到的取消请求不能把已经发布的副作用伪装成 cancelled。
                self.storage.operations.succeed(snapshot.operation_id, result)
            except asyncio.CancelledError:
                try:
                    state = self.storage.operations.get(snapshot.operation_id).state
                    if state is OperationState.CANCEL_REQUESTED:
                        self.storage.operations.acknowledge_cancel(snapshot.operation_id)
                    elif state is OperationState.RUNNING:
                        self.storage.operations.fail(
                            snapshot.operation_id,
                            code="worker_crashed",
                            message="操作因服务关闭而中止",
                        )
                except SupervisorError:
                    pass
                finally:
                    if discard_workspace_on_failure:
                        try:
                            await _complete_thread_call(
                                lambda: self.storage.workspaces.discard_uninitialized(workspace_id)
                            )
                        except SupervisorError:
                            pass
            except Exception as exc:
                try:
                    code, message, details = _operation_failure(exc)
                    self.storage.operations.fail(
                        snapshot.operation_id,
                        code=code,
                        message=message,
                        details=details,
                    )
                finally:
                    if discard_workspace_on_failure:
                        try:
                            await _complete_thread_call(
                                lambda: self.storage.workspaces.discard_uninitialized(workspace_id)
                            )
                        except SupervisorError:
                            pass

        task = asyncio.create_task(run(), name=f"{kind}:{snapshot.operation_id}")
        self._operation_tasks[snapshot.operation_id] = task
        if cancellable:
            self._cancellable_operations.add(snapshot.operation_id)

        def forget_operation(_task: asyncio.Task[None]) -> None:
            self._operation_tasks.pop(snapshot.operation_id, None)
            self._cancellable_operations.discard(snapshot.operation_id)

        task.add_done_callback(forget_operation)
        return snapshot.operation_id

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("Application 已关闭")

    def _workspace_lock(self, workspace_id: str) -> AsyncInterprocessFileLock:
        lock = self._workspace_locks.get(workspace_id)
        if lock is None:
            lock = AsyncInterprocessFileLock(
                self.storage.workspaces.workspace_lease_lock(workspace_id)
            )
            self._workspace_locks[workspace_id] = lock
        return lock


def _operation_output(snapshot: OperationSnapshot) -> OperationWaitOutput:
    failure = snapshot.failure
    return OperationWaitOutput(
        operation_id=snapshot.operation_id,
        state=snapshot.state.value,
        result=cast(JsonValue, snapshot.result),
        failure=(
            OperationFailure(
                code=failure.code,
                message=failure.message,
                retryable=failure.code in {"worker_crashed", "worker_timeout"},
            )
            if failure is not None
            else None
        ),
    )


def _empty_change_impact() -> ChangeImpact:
    return ChangeImpact(
        renamed_entities=0,
        comments_changed=0,
        types_changed=0,
        patched_bytes=0,
        imported_symbols=0,
        conflicts=[],
    )


def _inline_model_size(value: StrictModel) -> int:
    return len(
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _address_text(value: Mapping[str, object]) -> str:
    kind = value.get("kind")
    if kind == "image":
        return f"{value.get('image_id')}+{value.get('rva')}"
    if kind == "database":
        return str(value.get("ea"))
    if kind == "file":
        return f"file+{value.get('offset')}"
    if kind == "runtime":
        return f"{value.get('module_id')}@{value.get('va')}"
    raise RuntimeError("报告收到未知 AddressRef")


def _native_binding(
    workspace: WorkspaceSnapshot,
    overview: ProgramOverviewOutput,
) -> NativeBinding | None:
    image = overview.image
    if image.bitness != 64 or image.endian != "little":
        return None
    with workspace.sample_path.open("rb") as stream:
        header = stream.read(64)
    abi: str | None = None
    if header.startswith(b"MZ") and image.architecture == "x86_64":
        abi = "msvc-x64"
    elif header.startswith(b"\x7fELF") and len(header) >= 20 and header[4] == 2 and header[5] == 1:
        machine = int.from_bytes(header[18:20], "little")
        if machine == 0x3E and image.architecture == "x86_64":
            abi = "sysv-x64"
        elif machine == 0xB7 and image.architecture == "aarch64":
            abi = "aapcs64"
    if abi is None:
        return None
    return NativeBinding.model_validate(
        {
            "sha256": workspace.sample_sha256,
            "size": workspace.sample_size,
            "image_size": image.image_size,
            "architecture": image.architecture,
            "abi": abi,
            "pointer_width": 64,
            "endianness": "little",
        },
        strict=True,
    )


def _cancel_idle_task(task: asyncio.Task[None] | None) -> None:
    if task is not None and task is not asyncio.current_task() and not task.done():
        task.cancel()


async def _complete_thread_call[T](call: Callable[[], T]) -> T:
    """线程中的存储提交一旦开始; 调用方取消也必须等待确定结果。"""

    future = asyncio.create_task(asyncio.to_thread(call))
    return await _await_task_without_cancellation(future)


async def _await_task_without_cancellation[T](task: asyncio.Task[T]) -> T:
    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            continue


def _safe_remove_temp_directory(path: Path, root: Path) -> None:
    if not path.exists():
        return
    resolved = path.resolve()
    root_resolved = root.resolve()
    try:
        relative = resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise RuntimeError(f"拒绝清理临时目录边界外路径: {resolved}") from exc
    if not relative.parts:
        raise RuntimeError(f"拒绝清理临时目录根: {resolved}")
    shutil.rmtree(resolved)


def _operation_failure(exc: Exception) -> tuple[str, str, JsonValue]:
    if isinstance(exc, ToolExecutionError):
        return exc.code.value, exc.message, cast(JsonValue, exc.details)
    if isinstance(exc, WorkerProcessError):
        details = dict(exc.details)
        if exc.code == "worker_timeout":
            details["reason"] = "timeout"
            message = "worker 操作超时并已终止"
        else:
            message = "worker 进程崩溃或失联"
        return (
            BusinessErrorCode.WORKER_CRASHED.value,
            message,
            cast(JsonValue, details),
        )
    translated = _tool_error(exc)
    if translated is not None:
        return (
            translated.code.value,
            translated.message,
            cast(JsonValue, translated.details),
        )
    return "execution_failed", "长操作失败", None


def _tool_error(exc: Exception) -> ToolExecutionError | None:
    if isinstance(exc, WorkspaceNotFoundError):
        return ToolExecutionError(BusinessErrorCode.WORKSPACE_NOT_FOUND, str(exc))
    if isinstance(exc, (RevisionNotFoundError, RevisionConflictError)):
        return ToolExecutionError(BusinessErrorCode.REVISION_CONFLICT, str(exc))
    if isinstance(exc, OperationNotFoundError):
        return ToolExecutionError(BusinessErrorCode.OPERATION_NOT_FOUND, str(exc))
    if isinstance(exc, ArtifactNotFoundError):
        return ToolExecutionError(BusinessErrorCode.RESOURCE_NOT_FOUND, str(exc))
    if isinstance(exc, CursorError):
        return ToolExecutionError(BusinessErrorCode.CURSOR_STALE, str(exc))
    if isinstance(exc, (WorkerProcessError, WorkerError)):
        code = getattr(exc, "code", "worker_crashed")
        business = _WORKER_BUSINESS_ERRORS.get(
            code,
            BusinessErrorCode.EXECUTION_FAILED,
        )
        details = cast(dict[str, JsonValue], getattr(exc, "details", {}))
        return ToolExecutionError(business, str(exc), details=details)
    if isinstance(
        exc,
        (
            ChangeAdapterInputError,
            ChangeSourceError,
            ChangeSetError,
        ),
    ):
        return ToolExecutionError(BusinessErrorCode.CHANGE_SET_INVALID, str(exc))
    if isinstance(exc, StaticAdapterCapabilityError):
        return ToolExecutionError(BusinessErrorCode.CAPABILITY_UNAVAILABLE, str(exc))
    if isinstance(exc, StaticAdapterInputError):
        return ToolExecutionError(BusinessErrorCode.UNSUPPORTED, str(exc))
    if isinstance(exc, DebugAdapterError):
        return ToolExecutionError(BusinessErrorCode.DEBUG_STATE_CONFLICT, str(exc))
    if isinstance(exc, RefineAdapterInputError):
        return ToolExecutionError(BusinessErrorCode.UNSUPPORTED, str(exc))
    if isinstance(
        exc,
        (
            ChangeAdapterResultError,
            StaticAdapterResultError,
            RefineAdapterResultError,
            ExpertAdapterError,
        ),
    ):
        return ToolExecutionError(BusinessErrorCode.WORKER_CRASHED, "worker 结果不可信")
    if isinstance(
        exc,
        (
            ArtifactIntegrityError,
            InvalidIdentifierError,
            OperationStateError,
            StagingIntegrityError,
            StorageCorruptionError,
        ),
    ):
        return ToolExecutionError(
            BusinessErrorCode.EXECUTION_FAILED,
            "持久化状态未通过完整性校验",
        )
    return None
