"""IDA 9.3+ 运行时引导与版本校验。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import cast

from .errors import RuntimeNotReadyError

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


def ensure_ida_environment() -> ModuleType:
    """加载 `idapro` 并确认当前 IDA 运行时不低于 9.3。

    IDA 9.3 开始提供更灵活的 `idapro` wheel/激活方式，因此这里不再
    直接检查 `IDADIR/idalib.dll`。真正可靠的准入条件是 `idapro` 能加载
    运行时，并且 `get_library_version()` 返回 9.3 或更新版本。
    """
    global _idapro_module
    if _idapro_module is not None:
        return _idapro_module

    try:
        module = import_module("idapro")
    except ImportError as exc:
        raise RuntimeNotReadyError(
            "无法加载 IDA 运行时：请安装/激活 IDA 9.3+ 的 idapro 包，"
            "或设置 IDADIR 指向有效的 IDA 9.3+ 安装目录"
        ) from exc

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


def reset_ida_runtime_cache_for_tests() -> None:
    """清理运行时缓存，仅供单元测试隔离不同启动路径。"""
    global _idapro_module, _runtime_info
    _idapro_module = None
    _runtime_info = None


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
