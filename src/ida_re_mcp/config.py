"""当前产品配置与工作树外运行目录。"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from platformdirs import PlatformDirs
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ida_re_mcp.constants import (
    DEFAULT_RETAINED_REVISIONS,
    DEFAULT_STORAGE_GIB,
    DEFAULT_WORKER_IDLE_SECONDS,
    PRODUCT_NAME,
    PROTOCOL_VERSION,
)


class ConfigError(ValueError):
    """配置不符合当前 schema。"""


class RuntimePathError(ValueError):
    """运行目录落入工作树或无法安全解析。"""


class PolicyConfig(BaseModel):
    """公开能力策略。

    默认策略允许事务化写回和本机启动调试目标; 进程附加与
    开放式 IDAPython 必须由操作者显式开启。
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    authoring: bool = True
    debug_launch: bool = True
    debug_attach: bool = False
    expert: bool = False


class WorkerConfig(BaseModel):
    """进程隔离 worker 的并发与回收限制。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    analysis_limit: int = Field(default=1, ge=1, le=64)
    debug_limit: int = Field(default=1, ge=1, le=64)
    idle_seconds: int = Field(default=DEFAULT_WORKER_IDLE_SECONDS, ge=1, le=86_400)


class StorageConfig(BaseModel):
    """不可变 revision 与 artifact 的保留策略。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    quota_gib: int = Field(default=DEFAULT_STORAGE_GIB, ge=1, le=16_384)
    retained_revisions: int = Field(default=DEFAULT_RETAINED_REVISIONS, ge=0, le=1_000)


class AppConfig(BaseModel):
    """服务当前版本的完整配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["2026-07-28"] = PROTOCOL_VERSION
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    workers: WorkerConfig = Field(default_factory=WorkerConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """平台用户目录下的运行数据布局。"""

    data_root: Path
    log_root: Path
    workspace_root: Path
    artifact_root: Path
    checkout_root: Path
    temp_root: Path

    @classmethod
    def discover(cls, *, working_tree: Path | None = None) -> Self:
        """解析平台目录, 并拒绝把运行数据放入当前 Git 工作树。"""

        dirs = PlatformDirs(PRODUCT_NAME, appauthor=False, roaming=False)
        data_root = dirs.user_data_path.resolve()
        log_root = dirs.user_log_path.resolve()
        tree = (
            working_tree.resolve()
            if working_tree is not None
            else _find_working_tree(Path.cwd().resolve())
        )
        if tree is not None:
            for candidate in (data_root, log_root):
                if _is_within(candidate, tree):
                    raise RuntimePathError(f"运行目录不得位于工作树内: {candidate}")

        return cls(
            data_root=data_root,
            log_root=log_root,
            workspace_root=data_root / "workspaces",
            artifact_root=data_root / "artifacts",
            checkout_root=data_root / "checkouts",
            temp_root=data_root / "temp",
        )

    def ensure(self) -> Self:
        """创建当前系统需要的运行目录。"""

        for path in (
            self.data_root,
            self.log_root,
            self.workspace_root,
            self.artifact_root,
            self.checkout_root,
            self.temp_root,
        ):
            path.mkdir(parents=True, exist_ok=True)
        return self


def default_config_path() -> Path:
    """返回当前产品的平台配置文件路径。"""

    dirs = PlatformDirs(PRODUCT_NAME, appauthor=False, roaming=False)
    return dirs.user_config_path / "config.toml"


def load_config(path: Path | None = None) -> AppConfig:
    """读取严格 TOML; 没有平台默认配置时使用安全默认值。"""

    source = (path or default_config_path()).resolve()
    if not source.exists():
        if path is not None:
            raise ConfigError(f"配置文件不存在: {source}")
        return AppConfig()
    if not source.is_file():
        raise ConfigError(f"配置路径不是普通文件: {source}")

    try:
        with source.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"无法读取配置 {source}: {exc}") from exc

    if "schema_version" not in raw:
        raise ConfigError("配置必须显式声明 schema_version")
    try:
        return AppConfig.model_validate(raw, strict=True)
    except ValidationError as exc:
        raise ConfigError(f"配置不符合当前 schema: {exc}") from exc


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
