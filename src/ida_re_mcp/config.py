"""当前产品配置与工作树外运行目录。"""

from __future__ import annotations

import os
import tomllib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from platformdirs import PlatformDirs
from pydantic import BaseModel, ConfigDict, Field, ValidationError, ValidationInfo, field_validator

from ida_re_mcp.constants import (
    CONFIG_SCHEMA_VERSION,
    DEFAULT_RETAINED_REVISIONS,
    DEFAULT_STORAGE_GIB,
    DEFAULT_WORKER_IDLE_SECONDS,
    PRODUCT_NAME,
)

DATA_ROOT_ENV = "IDA_RE_MCP_DATA_ROOT"
LOG_ROOT_ENV = "IDA_RE_MCP_LOG_ROOT"
_DATA_ROOT_RESERVED_TREES = frozenset(
    {
        "artifacts",
        "session-leases",
        "sessions",
        "worker-slots",
        "workspaces",
    }
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


class RuntimeConfig(BaseModel):
    """跨 MCP host 共享的本机运行时入口。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    data_root: str | None = None
    log_root: str | None = None
    ida_dir: str | None = None

    @field_validator("data_root", "log_root", "ida_dir")
    @classmethod
    def validate_absolute_path(
        cls,
        value: str | None,
        info: ValidationInfo,
    ) -> str | None:
        if value is None:
            return None
        if not value.strip():
            raise ValueError(f"runtime.{info.field_name} 不能为空")
        if not Path(value).is_absolute():
            raise ValueError(f"runtime.{info.field_name} 必须是绝对路径")
        return value


class AppConfig(BaseModel):
    """服务当前版本的完整配置。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1"] = CONFIG_SCHEMA_VERSION
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
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
    session_root: Path | None = None

    @property
    def session_data_root(self) -> Path:
        """返回仅属于当前 MCP stdio 连接的运行目录。"""

        return self.session_root or self.data_root

    @property
    def operation_root(self) -> Path:
        return self.session_data_root / "operations"

    @property
    def change_root(self) -> Path:
        return self.session_data_root / "change-sets"

    @property
    def cursor_key_path(self) -> Path:
        return self.session_data_root / "cursor.key"

    @property
    def session_lease_root(self) -> Path:
        return self.data_root / "session-leases"

    @property
    def session_lease_path(self) -> Path:
        if self.session_root is None:
            return self.data_root / ".session.lease.lock"
        return self.session_lease_root / f"{self.session_root.name}.lease.lock"

    @classmethod
    def discover(
        cls,
        *,
        runtime: RuntimeConfig | None = None,
        working_tree: Path | None = None,
        environment: Mapping[str, str] | None = None,
        session_id: str | None = None,
    ) -> Self:
        """解析共享平台目录和当前连接私有目录, 并拒绝写入 Git 工作树。"""

        dirs = PlatformDirs(PRODUCT_NAME, appauthor=False, roaming=False)
        runtime_config = runtime or RuntimeConfig()
        selected_environment = os.environ if environment is None else environment
        data_override = selected_environment.get(DATA_ROOT_ENV, runtime_config.data_root)
        log_override = selected_environment.get(LOG_ROOT_ENV, runtime_config.log_root)
        data_root = _absolute_override(data_override, name=DATA_ROOT_ENV) or (
            dirs.user_data_path.resolve()
        )
        log_root = _absolute_override(log_override, name=LOG_ROOT_ENV) or (
            data_root / "logs" if data_override is not None else dirs.user_log_path.resolve()
        )
        _validate_runtime_layout(data_root=data_root, log_root=log_root)
        selected_session_id = session_id or f"session_{uuid.uuid4().hex}"
        _validate_session_id(selected_session_id)
        session_root = data_root / "sessions" / selected_session_id
        session_log_root = log_root / "sessions" / selected_session_id
        tree = (
            working_tree.resolve()
            if working_tree is not None
            else _find_working_tree(Path.cwd().resolve())
        )
        if tree is not None:
            for name, candidate in (
                (DATA_ROOT_ENV, data_root),
                (LOG_ROOT_ENV, log_root),
            ):
                _validate_runtime_root(candidate, name=name, working_tree=tree)
        else:
            for name, candidate in (
                (DATA_ROOT_ENV, data_root),
                (LOG_ROOT_ENV, log_root),
            ):
                _validate_runtime_root(candidate, name=name, working_tree=None)

        return cls(
            data_root=data_root,
            log_root=session_log_root,
            workspace_root=data_root / "workspaces",
            artifact_root=data_root / "artifacts",
            checkout_root=session_root / "checkouts",
            temp_root=session_root / "temp",
            session_root=session_root,
        )

    def ensure(self) -> Self:
        """创建当前系统需要的运行目录。"""

        for path in (
            self.data_root,
            self.log_root,
            self.session_data_root,
            self.session_lease_root,
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


def _validate_session_id(value: str) -> None:
    if (
        not value.startswith("session_")
        or len(value) > 128
        or not value.replace("_", "").isalnum()
        or not value.isascii()
    ):
        raise RuntimePathError("session_id 必须是 session_ 开头的 ASCII 路径标识符")


def _absolute_override(value: str | None, *, name: str) -> Path | None:
    if value is None:
        return None
    if not value.strip():
        raise RuntimePathError(f"{name} 不能为空")
    candidate = Path(value)
    if not candidate.is_absolute():
        raise RuntimePathError(f"{name} 必须是绝对路径")
    return candidate.resolve()


def _validate_runtime_root(
    candidate: Path,
    *,
    name: str,
    working_tree: Path | None,
) -> None:
    if candidate == Path(candidate.anchor):
        raise RuntimePathError(f"{name} 不得指向文件系统根目录")
    if working_tree is not None and (
        _is_within(candidate, working_tree) or _is_within(working_tree, candidate)
    ):
        raise RuntimePathError(f"{name} 不得与工作树形成包含关系: {candidate}")


def _validate_runtime_layout(*, data_root: Path, log_root: Path) -> None:
    if log_root == data_root:
        raise RuntimePathError(f"{LOG_ROOT_ENV} 不得与 {DATA_ROOT_ENV} 相同")
    try:
        relative_log_root = log_root.relative_to(data_root)
    except ValueError:
        return
    if (
        relative_log_root.parts
        and relative_log_root.parts[0].casefold() in _DATA_ROOT_RESERVED_TREES
    ):
        reserved_root = data_root / relative_log_root.parts[0]
        raise RuntimePathError(
            f"{LOG_ROOT_ENV} 不得位于 {DATA_ROOT_ENV} 的保留树内: {reserved_root}"
        )


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True
