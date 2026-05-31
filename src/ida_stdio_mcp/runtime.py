"""多会话 headless 运行时。"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from loguru import logger

from .analysis_artifacts import external_analyzer_health
from .capabilities import CapabilityState, capability_map, dependent_capability
from .errors import RuntimeNotReadyError, SessionNotFoundError, SessionRequiredError
from .ida_bootstrap import get_ida_runtime_info, probe_ida_runtime
from .managed_decompiler import configure_managed_decompiler, managed_decompiler_health
from .models import BinarySummary, JsonObject, JsonValue
from .open_options import HeadlessOpenOptions

if TYPE_CHECKING:
    from .config import AppConfig
    from .session_manager import SessionManager

DEFAULT_CONTEXT_ID = "stdio:default"


class HeadlessRuntime:
    """封装 stdio-only 的多会话运行时。"""

    def __init__(self, *, isolated_contexts: bool = False, config: AppConfig | None = None) -> None:
        """创建运行时并记录是否启用上下文隔离。"""
        self._manager_instance: SessionManager | None = None
        self._isolated_contexts = isolated_contexts
        self._config = config
        if config is not None:
            configure_managed_decompiler(
                enabled=config.managed_decompiler.enabled,
                command=config.managed_decompiler.command,
                timeout_sec=config.managed_decompiler.timeout_sec,
            )

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

        该路径用于展示和排障，不参与运行时准入判断。如果当前
        `idapro` 运行时没有暴露安装目录，方法会显式报错，避免
        让调用方拿到伪造路径后继续执行。
        """
        install_dir = get_ida_runtime_info().install_dir
        if install_dir is None:
            raise RuntimeNotReadyError("当前 IDA 运行时未暴露安装目录，但版本校验已通过")
        return install_dir

    def ida_runtime_info(self) -> JsonObject:
        """返回已校验的 IDA 9.3+ 运行时信息。"""
        return cast(JsonObject, get_ida_runtime_info().to_json())

    def runtime_health(self) -> JsonObject:
        """返回 IDA runtime 的分层诊断。"""
        return probe_ida_runtime().to_json()

    def debugger_backend_candidates(self) -> tuple[str, ...]:
        """返回配置中的调试器后端候选。"""
        if self._config is None:
            return ()
        return self._config.debugger.backend_candidates

    def debugger_wait_for_suspend_ms(self) -> int:
        """返回调试启动后的默认可观测等待时间。"""
        if self._config is None:
            return 1500
        return self._config.debugger.wait_for_suspend_ms

    def debugger_launch_use_request_default(self) -> bool:
        """返回 debug_launch 是否默认使用 request 队列。"""
        if self._config is None:
            return True
        return self._config.debugger.launch_use_request_default

    def capability_snapshot(self, *, context_id: str | None = None) -> JsonObject:
        """返回当前 headless 能力初始化状态。"""
        resolved_context_id = self._resolve_context_id(context_id)
        runtime_state = probe_ida_runtime()
        current_session: JsonValue = None
        try:
            current_session = cast(JsonValue, self.current_target(context_id=resolved_context_id))
        except SessionRequiredError:
            current_session = None

        open_target_state = dependent_capability(
            name="open_target",
            dependency=runtime_state,
            reason="等待按样本和 headless 参数打开工作 IDB。",
            source="runtime.open_target",
        )
        if runtime_state.status == "available":
            open_target_state = CapabilityState(
                name="open_target",
                status="available",
                reason="IDA runtime 可用，open_target 可尝试打开样本。",
                source="runtime.open_target",
                details={"requires_file": True, "headless_only": True},
            )

        debug_state = dependent_capability(
            name="debugger",
            dependency=runtime_state,
            reason="等待 debug_health 或 debug_launch 进行调试器后端实时探测。",
            source="runtime.debugger",
        )
        if runtime_state.status == "available":
            debug_state = CapabilityState(
                name="debugger",
                status="uninitialized",
                reason="等待 debug_health 或 debug_launch 进行调试器后端实时探测。",
                source="runtime.debugger",
                actionable_fix=("先调用 debug_health；本机 launch 验证通过后再调用寄存器、栈、内存读取类工具。",),
                details={
                    "backend_candidates": [item for item in self.debugger_backend_candidates()],
                    "wait_for_suspend_ms": self.debugger_wait_for_suspend_ms(),
                    "launch_use_request_default": self.debugger_launch_use_request_default(),
                    "remote_enabled": bool(self._config.debugger.remote_enabled) if self._config is not None else False,
                    "remote_status": "unsupported_unless_configured_and_verified",
                },
            )
        hexrays_state = dependent_capability(
            name="hexrays",
            dependency=runtime_state,
            reason="等待活动 IDB 后探测 Hex-Rays 插件和 license 状态。",
            source="runtime.hexrays",
        )
        managed_state = managed_decompiler_health()
        analyzer_state = CapabilityState.from_json(
            external_analyzer_health(self._config.external_analyzers if self._config is not None else ())
        )

        states = (runtime_state, open_target_state, debug_state, hexrays_state, managed_state, analyzer_state)
        return cast(JsonObject, {
            "runtime_ready": runtime_state.status == "available",
            "headless_only": True,
            "context_id": resolved_context_id,
            "current_session": current_session,
            "capabilities": capability_map(states),
        })

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
        capability_snapshot = self.capability_snapshot(context_id=resolved_context_id)
        runtime_capabilities = capability_snapshot.get("capabilities")
        runtime_state: JsonValue = None
        if isinstance(runtime_capabilities, dict):
            runtime_state = runtime_capabilities.get("ida_runtime")
        runtime_ready = bool(capability_snapshot.get("runtime_ready"))
        ida_runtime: JsonValue = runtime_state if runtime_state is not None else self.runtime_health()
        return cast(JsonObject, {
            "runtime_ready": runtime_ready,
            "ida_runtime": ida_runtime,
            "capabilities": capability_snapshot.get("capabilities", {}),
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
        loader: str = "",
        processor: str = "",
        plugin_options: tuple[str, ...] | None = None,
        session_id: str | None = None,
        context_id: str | None = None,
    ) -> BinarySummary:
        """打开样本并绑定到当前工作流上下文。

        默认采用与 GUI 交互体验一致的轻量打开：完整加载输入文件、
        导入表、调试符号与工作 IDB，但不等待全库自动分析队列清空。
        大型 UE/Chrome/游戏样本的全库分析应由后续定点工具按需触发。
        """
        resolved_context_id = self._resolve_context_id(context_id)
        default_options = self._config.open_target if self._config is not None else None
        effective_options = HeadlessOpenOptions(
            loader=loader.strip() or (default_options.loader if default_options is not None else ""),
            processor=processor.strip() or (default_options.processor if default_options is not None else ""),
            plugin_options=plugin_options if plugin_options is not None else (default_options.plugin_options if default_options is not None else ()),
        )
        opened_session_id = self._manager.open_target(
            source_path=source_path,
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
            open_options=effective_options,
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
        if not ok:
            raise RuntimeError(f"保存工作 IDB 失败：{save_path}")
        self._manager.mark_saved(summary["session_id"], saved_path=save_path)
        self._manager.record_activity(summary["session_id"], tool_name="save_workspace", target=save_path)
        refreshed = self.current_target(context_id=context_id)
        return {
            "ok": True,
            "path": save_path,
            "source_path": refreshed["source_path"],
            "working_idb_path": refreshed["working_idb_path"],
            "error": None,
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
