"""纯实现的多会话 IDA 管理器。"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock

from .ida_bootstrap import ensure_ida_environment

ensure_ida_environment()

import ida_auto
import idapro
from loguru import logger


@dataclass(slots=True)
class IdaSession:
    """表示一个打开的 IDA 数据库会话。"""

    session_id: str
    input_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False

    def to_dict(self) -> dict[str, object]:
        """把会话转换为可序列化字典。"""
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
        }


class SessionManager:
    """管理 headless 模式下的多会话与上下文绑定。"""

    def __init__(self) -> None:
        self._sessions: dict[str, IdaSession] = {}
        self._context_bindings: dict[str, str] = {}
        self._active_session_id: str | None = None
        self._lock = RLock()

    def open_binary(self, input_path: Path, *, run_auto_analysis: bool, session_id: str | None) -> str:
        """打开样本并创建会话。"""
        resolved = input_path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"样本不存在：{resolved}")

        with self._lock:
            for existing_id, session in self._sessions.items():
                if session.input_path == resolved:
                    session.last_accessed = datetime.now()
                    self._activate_session_locked(existing_id)
                    return existing_id

            created_id = session_id or str(uuid.uuid4())[:8]
            if created_id in self._sessions:
                raise ValueError(f"会话已存在：{created_id}")

            self._open_database_locked(resolved, run_auto_analysis=run_auto_analysis)
            session = IdaSession(session_id=created_id, input_path=resolved, is_analyzing=run_auto_analysis)
            self._sessions[created_id] = session
            self._active_session_id = created_id
            if run_auto_analysis:
                ida_auto.auto_wait()
                session.is_analyzing = False
            logger.info("已创建会话：{} -> {}", created_id, resolved)
            return created_id

    def bind_context(self, context_id: str, session_id: str, *, activate: bool) -> IdaSession:
        """把上下文绑定到指定会话。"""
        with self._lock:
            session = self._require_session_locked(session_id)
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
                raise RuntimeError("当前没有绑定会话，请先调用 open_binary 或 switch_binary")
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

    def list_sessions(self, context_id: str | None = None) -> list[dict[str, object]]:
        """列出所有会话。"""
        with self._lock:
            current_context_session_id = self._context_bindings.get(context_id) if context_id is not None else None
            binding_count: dict[str, int] = {}
            for bound_session_id in self._context_bindings.values():
                binding_count[bound_session_id] = binding_count.get(bound_session_id, 0) + 1

            result: list[dict[str, object]] = []
            for session in self._sessions.values():
                item = session.to_dict()
                item["is_active"] = session.session_id == self._active_session_id
                item["is_current_context"] = session.session_id == current_context_session_id
                item["bound_contexts"] = binding_count.get(session.session_id, 0)
                result.append(item)
            return result

    def close_session(self, session_id: str) -> bool:
        """关闭指定会话。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if self._active_session_id == session_id:
                idapro.close_database()
                self._active_session_id = None
            del self._sessions[session_id]
            for context_id, bound_session_id in list(self._context_bindings.items()):
                if bound_session_id == session_id:
                    del self._context_bindings[context_id]
            logger.info("已关闭会话：{}", session_id)
            return True

    def close_all_sessions(self) -> None:
        """关闭所有会话。"""
        with self._lock:
            if self._active_session_id is not None:
                idapro.close_database()
                self._active_session_id = None
            self._sessions.clear()
            self._context_bindings.clear()

    def _activate_session_locked(self, session_id: str) -> None:
        if self._active_session_id == session_id:
            return
        session = self._require_session_locked(session_id)
        self._open_database_locked(session.input_path, run_auto_analysis=False)
        self._active_session_id = session_id

    def _open_database_locked(self, input_path: Path, *, run_auto_analysis: bool) -> None:
        if self._active_session_id is not None:
            idapro.close_database()
            self._active_session_id = None
        if idapro.open_database(str(input_path), run_auto_analysis=run_auto_analysis):
            raise RuntimeError(f"打开数据库失败：{input_path}")

    def _require_session_locked(self, session_id: str) -> IdaSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise ValueError(f"找不到会话：{session_id}")
        return session


_SESSION_MANAGER: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """返回全局会话管理器。"""
    global _SESSION_MANAGER
    if _SESSION_MANAGER is None:
        _SESSION_MANAGER = SessionManager()
    return _SESSION_MANAGER
