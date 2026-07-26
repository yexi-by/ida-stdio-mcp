from __future__ import annotations

import os
from pathlib import Path

import pytest

import ida_re_mcp.config as config_module
from ida_re_mcp.config import (
    DATA_ROOT_ENV,
    LOG_ROOT_ENV,
    AppConfig,
    ConfigError,
    RuntimeConfig,
    RuntimePathError,
    RuntimePaths,
    load_config,
)
from ida_re_mcp.supervisor import SupervisorStorage


def test_default_policy_is_constrained_autonomy() -> None:
    config = AppConfig()

    assert config.policy.authoring is True
    assert config.policy.debug_launch is True
    assert config.policy.debug_attach is False
    assert config.policy.expert is False
    assert config.workers.analysis_limit == 1
    assert config.workers.debug_limit == 1
    assert config.storage.retained_revisions == 3
    assert config.storage.quota_gib == 20


def test_load_toml_schema(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
schema_version = "1"

[policy]
authoring = true
debug_launch = true
debug_attach = true
expert = false

[workers]
analysis_limit = 2
debug_limit = 1
idle_seconds = 120

[storage]
quota_gib = 40
retained_revisions = 5

[runtime]
data_root = "C:/runtime/ida-re-mcp/data"
log_root = "C:/runtime/ida-re-mcp/logs"
ida_dir = "C:/Program Files/IDA Professional 9.3"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.policy.debug_attach is True
    assert config.workers.analysis_limit == 2
    assert config.storage.quota_gib == 40
    assert config.runtime.data_root == "C:/runtime/ida-re-mcp/data"
    assert config.runtime.ida_dir == "C:/Program Files/IDA Professional 9.3"


def test_shipped_config_is_valid() -> None:
    project_root = Path(__file__).resolve().parents[2]

    config = load_config(project_root / "config.toml")

    assert isinstance(config, AppConfig)
    assert config.schema_version == "1"
    assert config.runtime.data_root is not None
    assert config.runtime.log_root is not None
    assert config.runtime.ida_dir is not None


@pytest.mark.parametrize(
    "content",
    [
        'schema_version = "1"\nunknown = true\n',
        'schema_version = "1"\n[workers]\nanalysis_limit = "1"\n',
        "[policy]\nauthoring = true\n",
    ],
)
def test_config_rejects_everything_outside_schema(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(path)


def test_explicit_missing_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="不存在"):
        load_config(tmp_path / "missing.toml")


def test_runtime_paths_reject_working_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InsideDirs:
        user_data_path = tmp_path / "runtime"
        user_log_path = tmp_path / "logs"
        user_config_path = tmp_path / "config"

    def inside_dirs(
        _application: str,
        *,
        appauthor: bool,
        roaming: bool,
    ) -> InsideDirs:
        assert appauthor is False
        assert roaming is False
        return InsideDirs()

    monkeypatch.setattr(config_module, "PlatformDirs", inside_dirs)

    with pytest.raises(RuntimePathError, match="工作树"):
        RuntimePaths.discover(working_tree=tmp_path)


def test_runtime_paths_reject_working_tree_ancestor(tmp_path: Path) -> None:
    working_tree = tmp_path / "repository"

    with pytest.raises(RuntimePathError, match="包含关系"):
        RuntimePaths.discover(
            working_tree=working_tree,
            environment={
                DATA_ROOT_ENV: str(tmp_path),
                LOG_ROOT_ENV: str(tmp_path / "logs"),
            },
        )


def test_runtime_paths_reject_filesystem_anchor(tmp_path: Path) -> None:
    with pytest.raises(RuntimePathError, match="根目录"):
        RuntimePaths.discover(
            working_tree=tmp_path / "repository",
            environment={
                DATA_ROOT_ENV: tmp_path.anchor,
                LOG_ROOT_ENV: str(tmp_path / "logs"),
            },
        )


def test_runtime_paths_create_only_declared_directories(tmp_path: Path) -> None:
    paths = RuntimePaths(
        data_root=tmp_path / "data",
        log_root=tmp_path / "logs",
        workspace_root=tmp_path / "data" / "workspaces",
        artifact_root=tmp_path / "data" / "artifacts",
        checkout_root=tmp_path / "data" / "checkouts",
        temp_root=tmp_path / "data" / "temp",
    )

    assert paths.ensure() is paths
    assert all(
        path.is_dir()
        for path in (
            paths.data_root,
            paths.log_root,
            paths.workspace_root,
            paths.artifact_root,
            paths.checkout_root,
            paths.temp_root,
        )
    )


def test_runtime_paths_accept_explicit_host_roots(tmp_path: Path) -> None:
    working_tree = tmp_path / "repository"
    data_root = tmp_path / "hosts" / "codex"
    log_root = tmp_path / "logs" / "codex"

    paths = RuntimePaths.discover(
        working_tree=working_tree,
        environment={
            DATA_ROOT_ENV: str(data_root),
            LOG_ROOT_ENV: str(log_root),
        },
        session_id="session_test",
    )

    assert paths.data_root == data_root.resolve()
    assert paths.log_root == log_root.resolve() / "sessions" / "session_test"
    assert paths.workspace_root == data_root.resolve() / "workspaces"
    assert paths.session_data_root == data_root.resolve() / "sessions" / "session_test"
    assert paths.checkout_root == paths.session_data_root / "checkouts"
    assert paths.operation_root == paths.session_data_root / "operations"
    assert paths.change_root == paths.session_data_root / "change-sets"


def test_runtime_paths_share_persistent_roots_and_isolate_sessions(tmp_path: Path) -> None:
    working_tree = tmp_path / "repository"
    runtime = RuntimeConfig(
        data_root=str(tmp_path / "runtime" / "data"),
        log_root=str(tmp_path / "runtime" / "logs"),
    )

    first = RuntimePaths.discover(
        runtime=runtime,
        working_tree=working_tree,
        environment={},
        session_id="session_first",
    )
    second = RuntimePaths.discover(
        runtime=runtime,
        working_tree=working_tree,
        environment={},
        session_id="session_second",
    )

    assert first.data_root == second.data_root
    assert first.workspace_root == second.workspace_root
    assert first.artifact_root == second.artifact_root
    assert first.session_data_root != second.session_data_root
    assert first.checkout_root != second.checkout_root
    assert first.temp_root != second.temp_root
    assert first.log_root != second.log_root
    assert first.cursor_key_path != second.cursor_key_path


@pytest.mark.parametrize(
    "log_relative",
    [
        None,
        "artifacts",
        "artifacts/reports",
        "session-leases",
        "sessions/session_other",
        "worker-slots/analysis",
        "workspaces/ws_other",
    ],
)
def test_runtime_paths_reject_log_root_in_reserved_data_tree(
    tmp_path: Path,
    log_relative: str | None,
) -> None:
    data_root = tmp_path / "runtime" / "data"
    log_root = data_root if log_relative is None else data_root / log_relative

    with pytest.raises(RuntimePathError, match=r"相同|保留树"):
        RuntimePaths.discover(
            runtime=RuntimeConfig(
                data_root=str(data_root),
                log_root=str(log_root),
            ),
            working_tree=tmp_path / "repository",
            environment={},
        )


def test_runtime_paths_allow_dedicated_log_tree_inside_data_root(tmp_path: Path) -> None:
    data_root = tmp_path / "runtime" / "data"

    paths = RuntimePaths.discover(
        runtime=RuntimeConfig(data_root=str(data_root)),
        working_tree=tmp_path / "repository",
        environment={},
        session_id="session_test",
    )

    assert paths.log_root == data_root.resolve() / "logs" / "sessions" / "session_test"


@pytest.mark.parametrize("field", ["data_root", "log_root", "ida_dir"])
def test_runtime_config_paths_must_be_absolute(field: str) -> None:
    with pytest.raises(ValueError, match="绝对路径"):
        RuntimeConfig.model_validate({field: "relative/path"}, strict=True)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (DATA_ROOT_ENV, ""),
        (DATA_ROOT_ENV, "relative/data"),
        (LOG_ROOT_ENV, "relative/logs"),
    ],
)
def test_runtime_path_overrides_must_be_absolute(
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    with pytest.raises(RuntimePathError):
        RuntimePaths.discover(
            working_tree=tmp_path / "repository",
            environment={name: value},
        )


def test_supervisor_storage_opens_with_soft_quota(tmp_path: Path) -> None:
    paths = RuntimePaths(
        data_root=tmp_path / "data",
        log_root=tmp_path / "logs",
        workspace_root=tmp_path / "data" / "workspaces",
        artifact_root=tmp_path / "data" / "artifacts",
        checkout_root=tmp_path / "data" / "checkouts",
        temp_root=tmp_path / "data" / "temp",
    )

    storage = SupervisorStorage.open(config=AppConfig(), paths=paths)
    usage = storage.usage()

    assert storage.paths == paths
    assert usage.total_bytes == 0
    assert usage.quota_bytes == 20 * 1024**3
    assert usage.over_soft_quota is False


def test_storage_usage_ignores_file_removed_between_enumeration_and_stat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = RuntimePaths(
        data_root=tmp_path / "data",
        log_root=tmp_path / "logs",
        workspace_root=tmp_path / "data" / "workspaces",
        artifact_root=tmp_path / "data" / "artifacts",
        checkout_root=tmp_path / "data" / "checkouts",
        temp_root=tmp_path / "data" / "temp",
    )
    storage = SupervisorStorage.open(config=AppConfig(), paths=paths)
    disappearing = paths.temp_root / "vanishing.tmp"
    disappearing.write_bytes(b"temporary")
    original_stat = Path.stat
    calls = 0

    def disappearing_stat(
        path: Path,
        *,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal calls
        if path == disappearing:
            calls += 1
            if calls >= 2:
                raise FileNotFoundError(path)
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", disappearing_stat)
    usage = storage.usage()

    assert calls >= 2
    assert usage.total_bytes == 0
