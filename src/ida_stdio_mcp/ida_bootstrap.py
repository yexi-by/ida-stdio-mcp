"""IDA 9.3+ 运行时引导与版本校验。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
from types import ModuleType
from typing import cast

from .capabilities import CapabilityState
from .errors import RuntimeNotReadyError
from .models import JsonObject

MINIMUM_IDA_VERSION = (9, 3, 0)


@dataclass(slots=True, frozen=True)
class IdaRuntimeInfo:
    """当前加载的 IDA 运行时信息。"""

    version: tuple[int, int, int]
    install_dir: Path | None
    source: str

    def to_json(self) -> dict[str, str | int | list[int] | None]:
        """转换成可写入工具结果的 JSON 结构。"""
        return {
            "version": [self.version[0], self.version[1], self.version[2]],
            "version_text": ".".join(str(item) for item in self.version),
            "minimum_version": ".".join(str(item) for item in MINIMUM_IDA_VERSION),
            "install_dir": str(self.install_dir) if self.install_dir is not None else None,
            "source": self.source,
        }


_idapro_module: ModuleType | None = None
_runtime_info: IdaRuntimeInfo | None = None
_runtime_probe: CapabilityState | None = None


def ensure_ida_environment() -> ModuleType:
    """加载 `idapro` 并确认当前 IDA 运行时不低于 9.3。

    准入条件由运行时自身提供：`idapro` 必须可以导入，并且
    `get_library_version()` 必须返回 9.3 或更新版本。`IDADIR`
    只作为定位运行时和诊断安装目录的输入，不作为唯一可信依据。
    """
    global _idapro_module
    if _idapro_module is not None:
        return _idapro_module

    state = probe_ida_runtime(refresh=True)
    if state.status != "available":
        fixes = "；".join(state.actionable_fix)
        suffix = f"；修复建议：{fixes}" if fixes else ""
        raise RuntimeNotReadyError(f"无法加载 IDA 运行时：{state.reason}{suffix}")

    module = _idapro_module
    if module is None:
        raise RuntimeNotReadyError("无法加载 IDA 运行时：探测显示可用但未缓存 idapro 模块")
    info = _read_runtime_info(module)
    if info.version < MINIMUM_IDA_VERSION:
        version_text = ".".join(str(item) for item in info.version)
        minimum_text = ".".join(str(item) for item in MINIMUM_IDA_VERSION)
        raise RuntimeNotReadyError(f"当前 IDA 版本为 {version_text}，本项目仅支持 IDA {minimum_text}+")

    _idapro_module = module
    return module


def get_ida_runtime_info() -> IdaRuntimeInfo:
    """返回已校验的 IDA 运行时信息。"""
    module = ensure_ida_environment()
    return _read_runtime_info(module)


def probe_ida_runtime(*, refresh: bool = False) -> CapabilityState:
    """分层探测 IDA headless runtime。"""
    global _idapro_module, _runtime_probe
    if _runtime_probe is not None and not refresh:
        return _runtime_probe
    if _idapro_module is not None:
        try:
            info = _read_runtime_info(_idapro_module)
        except RuntimeNotReadyError as exc:
            _runtime_probe = CapabilityState(
                name="ida_runtime",
                status="misconfigured",
                reason=str(exc),
                source="cached_idapro",
                actionable_fix=("确认 IDA 安装完整且版本不低于 9.3。",),
            )
            return _runtime_probe
        _runtime_probe = _available_runtime_state(info)
        return _runtime_probe

    spec = find_spec("idapro")
    if spec is None:
        _runtime_probe = CapabilityState(
            name="ida_runtime",
            status="misconfigured",
            reason="当前 Python 环境找不到 idapro 包。",
            source="python_import:idapro",
            actionable_fix=(
                "使用 IDA 9.3+ 附带的 Python 环境启动服务。",
                "或安装/激活 Hex-Rays 官方 idapro 包。",
                "必要时设置 IDADIR 指向有效 IDA 9.3+ 安装目录。",
            ),
        )
        return _runtime_probe

    try:
        module = import_module("idapro")
    except ImportError as exc:
        _runtime_probe = CapabilityState(
            name="ida_runtime",
            status="misconfigured",
            reason=f"idapro 包存在但导入失败：{exc}",
            source=str(spec.origin or "python_import:idapro"),
            actionable_fix=(
                "确认当前 Python 与 IDA 位数/版本匹配。",
                "确认 IDADIR 指向有效 IDA 9.3+ 安装目录。",
                "确认 IDA 安装目录内存在 idalib.dll 或对应平台库文件。",
            ),
            details={"exception_type": type(exc).__name__},
        )
        return _runtime_probe
    except Exception as exc:
        _runtime_probe = CapabilityState(
            name="ida_runtime",
            status="misconfigured",
            reason=f"idapro 包存在，但加载 IDA 动态库失败：{exc}",
            source=str(spec.origin or "python_import:idapro"),
            actionable_fix=(
                "设置 IDADIR 指向有效 IDA 9.3+ 安装目录。",
                "确认安装目录内存在 idalib.dll 或对应平台库文件。",
                "确认当前进程能读取 IDA 安装目录和许可证相关文件。",
            ),
            details={"exception_type": type(exc).__name__},
        )
        return _runtime_probe

    try:
        info = _read_runtime_info(module)
    except RuntimeNotReadyError as exc:
        _runtime_probe = CapabilityState(
            name="ida_runtime",
            status="misconfigured",
            reason=str(exc),
            source=str(spec.origin or "python_import:idapro"),
            actionable_fix=("确认 IDA 运行时暴露 get_library_version，并且安装完整。",),
        )
        return _runtime_probe
    except Exception as exc:
        _runtime_probe = CapabilityState(
            name="ida_runtime",
            status="misconfigured",
            reason=f"读取 IDA 运行时信息失败：{exc}",
            source=str(spec.origin or "python_import:idapro"),
            actionable_fix=("确认 IDA 运行时安装完整，并查看文件日志中的异常上下文。",),
            details={"exception_type": type(exc).__name__},
        )
        return _runtime_probe

    if info.version < MINIMUM_IDA_VERSION:
        version_text = ".".join(str(item) for item in info.version)
        minimum_text = ".".join(str(item) for item in MINIMUM_IDA_VERSION)
        _runtime_probe = CapabilityState(
            name="ida_runtime",
            status="unsupported",
            reason=f"当前 IDA 版本为 {version_text}，低于项目要求的 {minimum_text}。",
            source=info.source,
            actionable_fix=(f"升级到 IDA {minimum_text}+。",),
            details=cast(JsonObject, info.to_json()),
        )
        return _runtime_probe

    _idapro_module = module
    _runtime_probe = _available_runtime_state(info)
    return _runtime_probe


def reset_ida_runtime_cache_for_tests() -> None:
    """清理运行时缓存，仅供单元测试隔离不同启动路径。"""
    global _idapro_module, _runtime_info, _runtime_probe
    _idapro_module = None
    _runtime_info = None
    _runtime_probe = None


def _available_runtime_state(info: IdaRuntimeInfo) -> CapabilityState:
    """构造可用运行时状态。"""
    return CapabilityState(
        name="ida_runtime",
        status="available",
        reason="IDA headless runtime 已加载并满足最低版本要求。",
        source=info.source,
        details=cast(JsonObject, info.to_json()),
    )


def _read_runtime_info(module: ModuleType) -> IdaRuntimeInfo:
    """从 `idapro` 模块读取版本与来源信息。"""
    global _runtime_info
    if _runtime_info is not None:
        return _runtime_info

    raw_version = getattr(module, "get_library_version", lambda: None)()
    if raw_version is None:
        raise RuntimeNotReadyError("当前 idapro 运行时无法返回 IDA 版本，无法确认是否满足 9.3+ 要求")
    version_items = tuple(int(item) for item in cast(tuple[int, int, int], raw_version))
    if len(version_items) < 3:
        raise RuntimeNotReadyError(f"当前 idapro 返回了非法版本号：{raw_version}")

    install_dir = _detect_install_dir(module)
    source = "IDADIR" if os.environ.get("IDADIR", "").strip() else "idapro_config_or_wheel"
    _runtime_info = IdaRuntimeInfo(
        version=(version_items[0], version_items[1], version_items[2]),
        install_dir=install_dir,
        source=source,
    )
    return _runtime_info


def _detect_install_dir(module: ModuleType) -> Path | None:
    """尽力识别 IDA 安装目录，仅作为诊断信息。"""
    idadir = os.environ.get("IDADIR", "").strip()
    if idadir:
        return Path(idadir).resolve()
    config_module = getattr(module, "config", None)
    get_dir = getattr(config_module, "get_ida_install_dir", None)
    if callable(get_dir):
        raw_path = str(get_dir() or "").strip()
        if raw_path:
            return Path(raw_path).resolve()
    return None
