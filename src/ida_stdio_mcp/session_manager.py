"""纯实现的多会话 IDA 管理器。"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock
from time import perf_counter

from .errors import SessionNotFoundError, SessionRequiredError
from .ida_bootstrap import ensure_ida_environment
from .models import BinarySummary, JsonObject, JsonValue
from .runtime_workspace import get_runtime_workspace_paths, symbol_cache_scope

ensure_ida_environment()

import ida_auto  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_entry  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_loader  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_segment  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import idapro
from loguru import logger


@dataclass(slots=True)
class IdaSession:
    """表示一个打开的 IDA 数据库会话。"""

    session_id: str
    source_path: Path
    working_idb_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False
    dirty: bool = False
    writeback_kind: str | None = None
    persistent_after_save: bool = False
    saved_path: str = ""
    undo_supported: bool = False
    last_active_tool: str = ""
    recent_targets: list[str] = field(default_factory=list)
    recommended_next_tools: list[str] = field(default_factory=lambda: ["triage_binary"])
    metadata: JsonObject = field(default_factory=dict)

    def to_summary(
        self,
        *,
        is_active: bool,
        is_current_context: bool,
        bound_contexts: int,
    ) -> BinarySummary:
        """把会话转换成统一摘要。

        `metadata` 记录打开阶段已经真实完成的事项，以及未等待全库
        自动分析时的可信边界，避免 AI 把轻量打开误解成完整分析完成。
        """
        return {
            "session_id": self.session_id,
            "source_path": str(self.source_path),
            "working_idb_path": str(self.working_idb_path),
            "filename": self.source_path.name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": dict(self.metadata),
            "is_active": is_active,
            "is_current_context": is_current_context,
            "bound_contexts": bound_contexts,
            "dirty": self.dirty,
            "writeback_kind": self.writeback_kind,
            "persistent_after_save": self.persistent_after_save,
            "saved_path": self.saved_path,
            "undo_supported": self.undo_supported,
            "last_active_tool": self.last_active_tool,
            "recent_targets": list(self.recent_targets),
            "recommended_next_tools": list(self.recommended_next_tools),
        }


class SessionManager:
    """管理 headless 模式下的多会话与上下文绑定。"""

    def __init__(self) -> None:
        self._sessions: dict[str, IdaSession] = {}
        self._context_bindings: dict[str, str] = {}
        self._context_sessions: dict[str, set[str]] = {}
        self._active_session_id: str | None = None
        self._lock = RLock()

    def open_target(
        self,
        source_path: Path,
        *,
        run_auto_analysis: bool,
        session_id: str | None,
        context_id: str | None = None,
        isolated_contexts: bool = False,
    ) -> str:
        """打开样本并创建会话。

        `run_auto_analysis=False` 仍然会完整执行 IDA loader 与调试符号加载，
        并保存隔离 working IDB；它只是不等待全库自动分析完成。这样能够
        保持 UE 等大型样本的打开体验接近 GUI，后续按函数或字符串定点分析。
        """
        resolved = source_path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"样本不存在：{resolved}")

        with self._lock:
            visible_session_ids: list[str]
            if isolated_contexts:
                if context_id is None:
                    raise SessionRequiredError("当前启用了会话隔离，open_target 必须显式提供 context_id")
                visible_session_ids = list(self._context_sessions.get(context_id, set()))
            else:
                visible_session_ids = list(self._sessions.keys())

            for existing_id in visible_session_ids:
                session = self._sessions.get(existing_id)
                if session is None:
                    continue
                if session.source_path == resolved:
                    session.last_accessed = datetime.now()
                    self._activate_session_locked(existing_id)
                    return existing_id

            created_id = session_id or str(uuid.uuid4())[:8]
            if created_id in self._sessions:
                raise ValueError(f"会话已存在：{created_id}")

            logger.info(
                "准备创建会话：session_id={} source={} open_mode={}",
                created_id,
                resolved,
                "full-auto-analysis" if run_auto_analysis else "light-open",
            )
            source_open_duration_ms = self._open_database_locked(resolved, run_auto_analysis=run_auto_analysis)
            working_idb_path = self._working_idb_path(created_id)
            working_idb_path.parent.mkdir(parents=True, exist_ok=True)
            save_duration_ms = self._save_database_locked(working_idb_path)
            idapro.close_database(False)
            working_open_duration_ms = self._open_database_locked(working_idb_path, run_auto_analysis=False)
            metadata = self._build_open_metadata_locked(
                source_path=resolved,
                working_idb_path=working_idb_path,
                run_auto_analysis=run_auto_analysis,
                source_open_duration_ms=source_open_duration_ms,
                save_duration_ms=save_duration_ms,
                working_open_duration_ms=working_open_duration_ms,
            )
            session = IdaSession(
                session_id=created_id,
                source_path=resolved,
                working_idb_path=working_idb_path,
                is_analyzing=run_auto_analysis,
                saved_path=str(working_idb_path),
                metadata=metadata,
            )
            self._sessions[created_id] = session
            if isolated_contexts and context_id is not None:
                self._context_sessions.setdefault(context_id, set()).add(created_id)
            self._active_session_id = created_id
            if run_auto_analysis:
                analysis_started_at = perf_counter()
                logger.info("开始等待 IDA 自动分析：session_id={} path={}", created_id, resolved)
                ida_auto.auto_wait()
                session.is_analyzing = False
                session.metadata["analysis_wait_duration_ms"] = round((perf_counter() - analysis_started_at) * 1000.0, 3)
                session.metadata["analysis_completeness"] = "full_auto_analysis_waited"
                logger.info(
                    "IDA 自动分析完成：session_id={} duration_ms={:.1f} path={}",
                    created_id,
                    (perf_counter() - analysis_started_at) * 1000.0,
                    resolved,
                )
            logger.info("已创建会话：{} -> {}", created_id, resolved)
            return created_id

    def bind_context(self, context_id: str, session_id: str, *, activate: bool, isolated_contexts: bool = False) -> IdaSession:
        """把上下文绑定到指定会话。"""
        with self._lock:
            session = self._require_session_locked(session_id)
            if isolated_contexts:
                self._require_context_owns_session_locked(context_id, session_id)
            self._context_bindings[context_id] = session_id
            session.last_accessed = datetime.now()
            if activate:
                self._activate_session_locked(session_id)
            return session

    def activate_context(self, context_id: str) -> IdaSession:
        """激活指定上下文绑定的会话。"""
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                raise SessionRequiredError("当前没有绑定会话，请先调用 open_target 或 get_workspace_state")
            session = self._require_session_locked(session_id)
            self._activate_session_locked(session.session_id)
            session.last_accessed = datetime.now()
            return session

    def unbind_context(self, context_id: str) -> bool:
        """解除上下文绑定。"""
        with self._lock:
            removed = self._context_bindings.pop(context_id, None)
            return removed is not None

    def get_context_session(self, context_id: str) -> IdaSession | None:
        """返回上下文绑定的会话。"""
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                return None
            return self._sessions.get(session_id)

    def list_sessions(self, context_id: str | None = None, *, isolated_contexts: bool = False) -> list[BinarySummary]:
        """列出所有会话。"""
        with self._lock:
            current_context_session_id = self._context_bindings.get(context_id) if context_id is not None else None
            binding_count: dict[str, int] = {}
            for bound_session_id in self._context_bindings.values():
                binding_count[bound_session_id] = binding_count.get(bound_session_id, 0) + 1

            result: list[BinarySummary] = []
            if isolated_contexts and context_id is not None:
                visible_session_ids = self._context_sessions.get(context_id, set())
                sessions = [self._sessions[session_id] for session_id in visible_session_ids if session_id in self._sessions]
            else:
                sessions = list(self._sessions.values())
            for session in sessions:
                result.append(
                    session.to_summary(
                        is_active=session.session_id == self._active_session_id,
                        is_current_context=session.session_id == current_context_session_id,
                        bound_contexts=binding_count.get(session.session_id, 0),
                    )
                )
            return result

    def close_session(self, session_id: str, *, context_id: str | None = None, isolated_contexts: bool = False) -> bool:
        """关闭指定会话。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if isolated_contexts:
                if context_id is None:
                    raise SessionRequiredError("当前启用了会话隔离，close_session 必须显式提供 context_id")
                self._require_context_owns_session_locked(context_id, session_id)
            if self._active_session_id == session_id:
                idapro.close_database(True)
                self._active_session_id = None
            del self._sessions[session_id]
            for context_id, bound_session_id in list(self._context_bindings.items()):
                if bound_session_id == session_id:
                    del self._context_bindings[context_id]
            for owned_sessions in self._context_sessions.values():
                owned_sessions.discard(session_id)
            logger.info("已关闭会话：{}", session_id)
            return True

    def close_all_sessions(self) -> None:
        """关闭所有会话。"""
        with self._lock:
            if self._active_session_id is not None:
                idapro.close_database(True)
                self._active_session_id = None
            self._sessions.clear()
            self._context_bindings.clear()
            self._context_sessions.clear()

    def mark_dirty(self, session_id: str, *, writeback_kind: str) -> IdaSession:
        """把会话标记为存在未持久化写回。"""
        with self._lock:
            session = self._require_session_locked(session_id)
            session.last_accessed = datetime.now()
            session.dirty = True
            session.writeback_kind = writeback_kind
            session.persistent_after_save = False
            return session

    def mark_saved(self, session_id: str, *, saved_path: str) -> IdaSession:
        """把会话标记为已保存。"""
        with self._lock:
            session = self._require_session_locked(session_id)
            session.last_accessed = datetime.now()
            session.dirty = False
            session.persistent_after_save = True
            session.saved_path = saved_path
            return session

    def record_activity(self, session_id: str, *, tool_name: str, target: str = "") -> IdaSession:
        """记录会话最近操作，给 AI 提供可恢复的工作流状态。"""
        with self._lock:
            session = self._require_session_locked(session_id)
            session.last_accessed = datetime.now()
            session.last_active_tool = tool_name
            normalized_target = target.strip()
            if normalized_target:
                session.recent_targets = [item for item in session.recent_targets if item != normalized_target]
                session.recent_targets.insert(0, normalized_target)
                session.recent_targets = session.recent_targets[:12]
            session.recommended_next_tools = self._recommended_tools_for_activity(tool_name, bool(normalized_target))
            return session

    def _activate_session_locked(self, session_id: str) -> None:
        if self._active_session_id == session_id:
            return
        session = self._require_session_locked(session_id)
        if not session.working_idb_path.exists():
            raise FileNotFoundError(f"工作 IDB 不存在：{session.working_idb_path}")
        self._open_database_locked(session.working_idb_path, run_auto_analysis=False)
        self._active_session_id = session_id

    def _open_database_locked(self, input_path: Path, *, run_auto_analysis: bool) -> float:
        if self._active_session_id is not None:
            idapro.close_database(True)
            self._active_session_id = None
        started_at = perf_counter()
        logger.info("开始打开 IDA 数据库：path={} run_auto_analysis={}", input_path, run_auto_analysis)
        with symbol_cache_scope():
            if idapro.open_database(str(input_path), run_auto_analysis=run_auto_analysis):
                sidecars = self._existing_database_sidecars(input_path)
                sidecar_hint = ""
                if sidecars:
                    sidecar_hint = f"；检测到 IDA 伴生文件：{', '.join(str(path) for path in sidecars)}"
                raise RuntimeError(
                    f"打开数据库失败：{input_path}{sidecar_hint}；"
                    "如果上一次打开被中断，建议先备份或清理这些伴生文件后重试"
                )
        duration_ms = (perf_counter() - started_at) * 1000.0
        logger.info(
            "IDA 数据库打开完成：duration_ms={:.1f} path={}",
            duration_ms,
            input_path,
        )
        return duration_ms

    @staticmethod
    def _save_database_locked(path: Path) -> float:
        """保存当前 IDB 到会话工作库，避免隐式污染原始样本旁的数据库。"""
        started_at = perf_counter()
        if not ida_loader.save_database(str(path), 0):
            raise RuntimeError(f"保存工作 IDB 失败：{path}")
        duration_ms = (perf_counter() - started_at) * 1000.0
        logger.info("工作 IDB 保存完成：duration_ms={:.1f} path={}", duration_ms, path)
        return duration_ms

    def _build_open_metadata_locked(
        self,
        *,
        source_path: Path,
        working_idb_path: Path,
        run_auto_analysis: bool,
        source_open_duration_ms: float,
        save_duration_ms: float,
        working_open_duration_ms: float,
    ) -> JsonObject:
        """生成给 AI 使用的真实打开结果报告。"""
        exact_pdb = source_path.with_suffix(".pdb")
        analysis_limitations: list[JsonValue] = []
        if not run_auto_analysis:
            analysis_limitations.append("未等待全库自动分析队列清空；函数级和字符串级工具会按目标继续触发定点分析。")
        sibling_pdb_files: list[JsonValue] = [name for name in self._sibling_pdb_names(source_path)]
        return {
            "open_mode": "full_auto_analysis" if run_auto_analysis else "light_open",
            "database_loaded": True,
            "working_idb_ready": working_idb_path.exists(),
            "auto_analysis_waited": run_auto_analysis,
            "analysis_completeness": "full_auto_analysis_waited" if run_auto_analysis else "loader_symbols_and_working_idb_ready",
            "analysis_limitations": analysis_limitations,
            "source_size_bytes": source_path.stat().st_size,
            "working_idb_size_bytes": working_idb_path.stat().st_size if working_idb_path.exists() else 0,
            "source_open_duration_ms": round(source_open_duration_ms, 3),
            "working_idb_save_duration_ms": round(save_duration_ms, 3),
            "working_idb_open_duration_ms": round(working_open_duration_ms, 3),
            "exact_pdb_path": str(exact_pdb) if exact_pdb.exists() else "",
            "sibling_pdb_files": sibling_pdb_files,
            "database_snapshot": self._database_snapshot_locked(),
            "trust_contract": "样本、调试符号和 working IDB 已真实加载；未等待全库自动分析时，后续结论应来自 triage/explain/investigate 的定点结果。",
        }

    @staticmethod
    def _database_snapshot_locked() -> JsonObject:
        """读取无需全库自动分析即可稳定获得的 IDB 快照。"""
        segment_count = int(ida_segment.get_segm_qty())
        segments: list[JsonValue] = []
        for index in range(min(segment_count, 16)):
            segment = ida_segment.getnseg(index)
            if segment is None:
                continue
            name = ida_segment.get_segm_name(segment)
            start = int(segment.start_ea)
            end = int(segment.end_ea)
            segments.append(
                {
                    "name": name,
                    "start": hex(start),
                    "end": hex(end),
                    "size": end - start,
                }
            )
        return {
            "entry_count": int(ida_entry.get_entry_qty()),
            "segment_count": segment_count,
            "segments_preview": segments,
        }

    @staticmethod
    def _sibling_pdb_names(source_path: Path) -> list[str]:
        """列出同目录 PDB，帮助 AI 判断调试符号上下文。"""
        if not source_path.parent.exists():
            return []
        names: list[str] = []
        for candidate in source_path.parent.glob("*.pdb"):
            names.append(candidate.name)
            if len(names) >= 12:
                break
        return names

    @staticmethod
    def _working_idb_path(session_id: str) -> Path:
        """返回会话隔离工作库路径。"""
        return get_runtime_workspace_paths().sessions_directory / session_id / "working.i64"

    @staticmethod
    def _recommended_tools_for_activity(tool_name: str, has_target: bool) -> list[str]:
        """根据最近工具给出下一步建议。"""
        if tool_name in {"open_target", "save_workspace"}:
            return ["triage_binary", "investigate_string", "explain_function"]
        if tool_name == "triage_binary":
            return ["investigate_string", "explain_function", "export_report"]
        if tool_name == "investigate_string":
            return ["explain_function", "trace_input_to_check", "export_report"]
        if tool_name in {"explain_function", "decompile_function"}:
            return ["trace_input_to_check", "investigate_string", "export_report"] if has_target else ["investigate_string", "export_report"]
        if tool_name == "trace_input_to_check":
            return ["explain_function", "export_report"]
        return ["triage_binary", "investigate_string", "explain_function"]

    @staticmethod
    def _existing_database_sidecars(input_path: Path) -> list[Path]:
        """列出 IDA 可能遗留在样本旁边的数据库伴生文件。"""
        suffixes = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")
        sidecars: list[Path] = []
        for suffix in suffixes:
            candidate = input_path.with_name(f"{input_path.name}{suffix}")
            if candidate.exists():
                sidecars.append(candidate)
        return sidecars

    def _require_session_locked(self, session_id: str) -> IdaSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(f"找不到会话：{session_id}")
        return session

    def _require_context_owns_session_locked(self, context_id: str, session_id: str) -> None:
        owned_sessions = self._context_sessions.get(context_id, set())
        if session_id not in owned_sessions:
            raise SessionNotFoundError(f"上下文 {context_id} 不拥有会话：{session_id}")


_session_manager_singleton: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """返回全局会话管理器。"""
    global _session_manager_singleton
    if _session_manager_singleton is None:
        _session_manager_singleton = SessionManager()
    return _session_manager_singleton
