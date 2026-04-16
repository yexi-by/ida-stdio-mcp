"""多会话 headless 运行时。"""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

from loguru import logger

from .errors import BinaryNotOpenError, RuntimeNotReadyError
from .models import BinarySummary, JsonValue
from .session_manager import get_session_manager

STDIO_CONTEXT_ID = "stdio:default"


def _to_json_value(value: object) -> JsonValue:
    """把运行时对象收敛到项目 JSON 类型。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_to_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_to_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _to_json_value(item) for key, item in value.items()}
    return str(value)


class HeadlessRuntime:
    """封装 stdio-only 的多会话运行时。"""

    def __init__(self) -> None:
        self._manager = get_session_manager()

    def require_ida_dir(self) -> Path:
        """校验 IDADIR。"""
        ida_dir = os.environ.get("IDADIR", "").strip()
        if not ida_dir:
            raise RuntimeNotReadyError("缺少 IDADIR 环境变量")
        path = Path(ida_dir)
        if not path.exists():
            raise RuntimeNotReadyError(f"IDADIR 路径不存在：{path}")
        if not (path / "idalib.dll").exists():
            raise RuntimeNotReadyError(f"IDADIR 下缺少 idalib.dll：{path}")
        return path

    def open_binary(
        self,
        input_path: Path,
        *,
        run_auto_analysis: bool = True,
        session_id: str | None = None,
    ) -> BinarySummary:
        """打开二进制并绑定到 stdio 默认上下文。"""
        opened_session_id = self._manager.open_binary(
            input_path=input_path,
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
        )
        self._manager.bind_context(STDIO_CONTEXT_ID, opened_session_id, activate=True)
        logger.info("已打开并绑定会话：{} -> {}", opened_session_id, input_path)
        return self.current_binary()

    def switch_binary(self, session_id: str) -> BinarySummary:
        """切换当前激活会话。"""
        self._manager.bind_context(STDIO_CONTEXT_ID, session_id, activate=True)
        logger.info("已切换到会话：{}", session_id)
        return self.current_binary()

    def deactivate_binary(self) -> bool:
        """解除当前默认上下文与会话的绑定。"""
        removed = self._manager.unbind_context(STDIO_CONTEXT_ID)
        if removed:
            logger.info("已解除默认上下文绑定")
        return removed

    def list_binaries(self) -> list[BinarySummary]:
        """列出所有打开的会话。"""
        sessions = self._manager.list_sessions(context_id=STDIO_CONTEXT_ID)
        return [self._normalize_session(item) for item in sessions]

    def current_binary(self) -> BinarySummary:
        """返回当前绑定会话。"""
        session = self._manager.get_context_session(STDIO_CONTEXT_ID)
        if session is None:
            raise BinaryNotOpenError("当前没有绑定任何会话，请先调用 open_binary 或 switch_binary")
        listed = self._manager.list_sessions(context_id=STDIO_CONTEXT_ID)
        for item in listed:
            if item.get("session_id") == session.session_id:
                return self._normalize_session(item)
        raise BinaryNotOpenError("当前上下文绑定的会话不存在")

    def activate_for_request(self, session_id: str | None = None) -> BinarySummary:
        """按请求可选切换会话，并确保底层 IDB 已激活。"""
        if session_id:
            self._manager.bind_context(STDIO_CONTEXT_ID, session_id, activate=True)
        else:
            self._manager.activate_context(STDIO_CONTEXT_ID)
        return self.current_binary()

    def close_binary(self, session_id: str | None = None) -> bool:
        """关闭指定会话；未指定则关闭当前绑定会话。"""
        target_session_id = session_id
        if target_session_id is None:
            session = self._manager.get_context_session(STDIO_CONTEXT_ID)
            if session is None:
                raise BinaryNotOpenError("当前没有可关闭的会话")
            target_session_id = session.session_id
        closed = self._manager.close_session(target_session_id)
        if not closed:
            raise BinaryNotOpenError(f"找不到会话：{target_session_id}")
        return True

    def save_binary(self, path: str = "", session_id: str | None = None) -> dict[str, JsonValue]:
        """保存当前或指定会话对应的 IDB。"""
        self.activate_for_request(session_id)
        import ida_loader

        save_path = path.strip() if path else ""
        if not save_path:
            save_path = str(ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "")
        if not save_path:
            raise RuntimeNotReadyError("无法解析当前 IDB 路径")
        ok = bool(ida_loader.save_database(save_path, 0))
        return {"ok": ok, "path": save_path, "error": None if ok else "save_database returned false"}

    def shutdown(self) -> None:
        """关闭所有会话。"""
        self._manager.close_all_sessions()

    @staticmethod
    def _normalize_session(raw: dict[str, object]) -> BinarySummary:
        metadata_raw = raw.get("metadata")
        metadata = cast(dict[str, JsonValue], _to_json_value(metadata_raw if isinstance(metadata_raw, dict) else {}))
        return {
            "session_id": str(raw.get("session_id", "")),
            "input_path": str(raw.get("input_path", "")),
            "filename": str(raw.get("filename", "")),
            "created_at": str(raw.get("created_at", "")),
            "last_accessed": str(raw.get("last_accessed", "")),
            "is_analyzing": bool(raw.get("is_analyzing", False)),
            "metadata": metadata,
            "is_active": bool(raw.get("is_active", False)),
            "is_current_context": bool(raw.get("is_current_context", False)),
            "bound_contexts": int(raw.get("bound_contexts", 0)),
        }
