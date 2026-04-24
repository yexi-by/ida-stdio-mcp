"""多会话 headless 运行时。"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from loguru import logger

from .errors import RuntimeNotReadyError, SessionNotFoundError, SessionRequiredError
from .ida_bootstrap import get_ida_runtime_info
from .models import BinarySummary, JsonObject, JsonValue

if TYPE_CHECKING:
    from .session_manager import SessionManager

DEFAULT_CONTEXT_ID = "stdio:default"


class HeadlessRuntime:
    """封装 stdio-only 的多会话运行时。"""

    def __init__(self, *, isolated_contexts: bool = False) -> None:
        self._manager_instance: SessionManager | None = None
        self._isolated_contexts = isolated_contexts

    @property
    def isolated_contexts(self) -> bool:
        """返回当前是否启用了上下文隔离。"""
        return self._isolated_contexts

    @property
    def _manager(self) -> "SessionManager":
        """惰性加载会话管理器，避免协议单测导入阶段强制加载 IDA。"""
        if self._manager_instance is None:
            from .session_manager import get_session_manager

            self._manager_instance = get_session_manager()
        return self._manager_instance

    def _resolve_context_id(self, context_id: str | None) -> str:
        """把请求中的上下文标识解析成运行时上下文。"""
        if self._isolated_contexts:
            normalized = context_id.strip() if isinstance(context_id, str) else ""
            if not normalized:
                raise SessionRequiredError("当前启用了 --isolated-contexts，必须显式提供 context_id")
            return normalized
        return DEFAULT_CONTEXT_ID

    def require_ida_dir(self) -> Path:
        """返回 IDA 安装目录诊断信息。

        V2 已不再把 `IDADIR/idalib.dll` 作为唯一入口；此方法只保留给
        运行时诊断读取。如果运行时通过 9.3 wheel 激活且无法定位
        安装目录，会显式报错而不是伪造路径。
        """
        install_dir = get_ida_runtime_info().install_dir
        if install_dir is None:
            raise RuntimeNotReadyError("当前 IDA 运行时未暴露安装目录，但版本校验已通过")
        return install_dir

    def ida_runtime_info(self) -> JsonObject:
        """返回已校验的 IDA 9.3+ 运行时信息。"""
        return cast(JsonObject, get_ida_runtime_info().to_json())

    def workspace_state(self, *, context_id: str | None = None) -> JsonObject:
        """返回面向 AI 工作流的运行时状态摘要。"""
        resolved_context_id = self._resolve_context_id(context_id)
        current: BinarySummary | None = None
        try:
            current = self.current_target(context_id=resolved_context_id)
        except SessionRequiredError:
            current = None
        sessions = self.list_targets(context_id=resolved_context_id)
        recommended_next_tools: list[str]
        if current is None:
            recommended_next_tools = ["open_target"]
        else:
            recommended_next_tools = current["recommended_next_tools"]
        runtime_ready = True
        ida_runtime: JsonValue
        try:
            ida_runtime = self.ida_runtime_info()
        except RuntimeNotReadyError as exc:
            runtime_ready = False
            ida_runtime = {
                "error": str(exc),
                "minimum_version": "9.3.0",
            }
        return cast(JsonObject, {
            "runtime_ready": runtime_ready,
            "ida_runtime": ida_runtime,
            "isolated_contexts": self._isolated_contexts,
            "context_id": resolved_context_id,
            "current_session": current,
            "sessions": sessions,
            "recommended_next_tools": recommended_next_tools,
            "workflow_order": [
                "get_workspace_state",
                "open_target",
                "triage_binary",
                "investigate_string",
                "explain_function",
                "export_report",
            ],
        })

    def open_target(
        self,
        source_path: Path,
        *,
        run_auto_analysis: bool = False,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> BinarySummary:
        """打开样本并绑定到当前工作流上下文。

        默认采用与 GUI 交互体验一致的轻量打开：完整加载输入文件、
        导入表、调试符号与工作 IDB，但不等待全库自动分析队列清空。
        大型 UE/Chrome/游戏样本的全库分析应由后续定点工具按需触发。
        """
        resolved_context_id = self._resolve_context_id(context_id)
        opened_session_id = self._manager.open_target(
            source_path=source_path,
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
            context_id=resolved_context_id,
            isolated_contexts=self._isolated_contexts,
        )
        self._manager.bind_context(
            resolved_context_id,
            opened_session_id,
            activate=True,
            isolated_contexts=self._isolated_contexts,
        )
        self._manager.record_activity(opened_session_id, tool_name="open_target", target=str(source_path))
        logger.info("已打开并绑定会话：{} -> {}", opened_session_id, source_path)
        return self.current_target(context_id=resolved_context_id)

    def list_targets(self, *, context_id: str | None = None) -> list[BinarySummary]:
        """列出当前上下文可见的样本会话。"""
        if self._manager_instance is None:
            self._resolve_context_id(context_id)
            return []
        return self._manager.list_sessions(
            context_id=self._resolve_context_id(context_id),
            isolated_contexts=self._isolated_contexts,
        )

    def current_target(self, *, context_id: str | None = None) -> BinarySummary:
        """返回当前工作流绑定的样本会话。"""
        resolved_context_id = self._resolve_context_id(context_id)
        if self._manager_instance is None:
            raise SessionRequiredError("当前没有绑定任何会话，请先调用 open_target")
        session = self._manager.get_context_session(resolved_context_id)
        if session is None:
            raise SessionRequiredError("当前没有绑定任何会话，请先调用 open_target 或 get_workspace_state")
        listed = self._manager.list_sessions(
            context_id=resolved_context_id,
            isolated_contexts=self._isolated_contexts,
        )
        for item in listed:
            if item["session_id"] == session.session_id:
                return item
        raise SessionNotFoundError("当前上下文绑定的会话不存在")

    def activate_for_request(self, session_id: str | None = None, *, context_id: str | None = None) -> BinarySummary:
        """按请求可选切换会话，并确保底层 IDB 已激活。"""
        resolved_context_id = self._resolve_context_id(context_id)
        if self._manager_instance is None:
            raise SessionRequiredError("当前没有绑定任何会话，请先调用 open_target")
        if session_id:
            self._manager.bind_context(
                resolved_context_id,
                session_id,
                activate=True,
                isolated_contexts=self._isolated_contexts,
            )
        else:
            self._manager.activate_context(resolved_context_id)
        return self.current_target(context_id=resolved_context_id)

    def close_target(self, session_id: str | None = None, *, context_id: str | None = None) -> bool:
        """关闭指定样本会话；未指定则关闭当前绑定会话。"""
        resolved_context_id = self._resolve_context_id(context_id)
        if self._manager_instance is None:
            raise SessionRequiredError("当前没有可关闭的会话")
        target_session_id = session_id
        if target_session_id is None:
            session = self._manager.get_context_session(resolved_context_id)
            if session is None:
                raise SessionRequiredError("当前没有可关闭的会话")
            target_session_id = session.session_id
        closed = self._manager.close_session(
            target_session_id,
            context_id=resolved_context_id,
            isolated_contexts=self._isolated_contexts,
        )
        if not closed:
            raise SessionNotFoundError(f"找不到会话：{target_session_id}")
        return True

    def save_workspace(self, path: str = "", session_id: str | None = None, *, context_id: str | None = None) -> JsonObject:
        """保存当前或指定样本会话对应的工作 IDB。"""
        summary = self.activate_for_request(session_id, context_id=context_id)
        import ida_loader  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。

        save_path = path.strip() if path else ""
        if not save_path:
            save_path = summary["working_idb_path"]
        if not save_path:
            raise RuntimeNotReadyError("无法解析当前 IDB 路径")
        ok = bool(ida_loader.save_database(save_path, 0))
        if ok:
            self._manager.mark_saved(summary["session_id"], saved_path=save_path)
            self._manager.record_activity(summary["session_id"], tool_name="save_workspace", target=save_path)
        refreshed = self.current_target(context_id=context_id)
        return {
            "ok": ok,
            "path": save_path,
            "source_path": refreshed["source_path"],
            "working_idb_path": refreshed["working_idb_path"],
            "error": None if ok else "save_database returned false",
            "dirty": refreshed["dirty"],
            "writeback_kind": refreshed["writeback_kind"],
            "persistent_after_save": refreshed["persistent_after_save"],
            "saved_path": refreshed["saved_path"],
            "undo_supported": refreshed["undo_supported"],
        }

    def mark_writeback(
        self,
        *,
        writeback_kind: str,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> BinarySummary:
        """把当前或指定会话标记为已发生写回。"""
        summary = self.activate_for_request(session_id, context_id=context_id)
        self._manager.mark_dirty(summary["session_id"], writeback_kind=writeback_kind)
        return self.current_target(context_id=context_id)

    def record_activity(
        self,
        tool_name: str,
        *,
        target: str = "",
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> None:
        """记录当前工作流活动。"""
        summary = self.activate_for_request(session_id, context_id=context_id)
        self._manager.record_activity(summary["session_id"], tool_name=tool_name, target=target)

    def shutdown(self) -> None:
        """关闭所有会话。"""
        if self._manager_instance is None:
            return
        self._manager.close_all_sessions()
