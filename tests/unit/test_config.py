from __future__ import annotations

import os
from pathlib import Path

import pytest

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
    assert config.workers.operation_timeout_seconds == 120
    assert config.workers.initial_analysis_timeout_seconds == 3_600
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
operation_timeout_seconds = 90
initial_analysis_timeout_seconds = 7200

[storage]
quota_gib = 40
retained_revisions = 5

[runtime]
data_root = "data"
log_root = "logs"
ida_dir = "C:/Program Files/IDA Professional 9.3"
""".strip(),
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.policy.debug_attach is True
    assert config.workers.analysis_limit == 2
    assert config.workers.operation_timeout_seconds == 90
    assert config.workers.initial_analysis_timeout_seconds == 7_200
    assert config.storage.quota_gib == 40
    assert config.runtime.data_root == str((tmp_path / "data").resolve())
    assert config.runtime.log_root == str((tmp_path / "logs").resolve())
    assert config.runtime.ida_dir == "C:/Program Files/IDA Professional 9.3"


def test_relative_runtime_roots_use_config_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_dir = tmp_path / "repository"
    unrelated_cwd = tmp_path / "elsewhere"
    config_dir.mkdir()
    unrelated_cwd.mkdir()
    path = config_dir / "config.toml"
    path.write_text(
        """
schema_version = "1"

[runtime]
data_root = "data"
log_root = "logs"
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.chdir(unrelated_cwd)

    config = load_config(path)

    assert config.runtime.data_root == str((config_dir / "data").resolve())
    assert config.runtime.log_root == str((config_dir / "logs").resolve())


def test_shipped_config_is_valid() -> None:
    project_root = Path(__file__).resolve().parents[2]

    config = load_config(project_root / "config.toml")

    assert isinstance(config, AppConfig)
    assert config.schema_version == "1"
    assert config.runtime.data_root == str((project_root / "data").resolve())
    assert config.runtime.log_root == str((project_root / "logs").resolve())
    assert config.runtime.ida_dir is not None
    assert config.policy.debug_attach is True
    assert config.policy.expert is True
    assert config.workers.operation_timeout_seconds == 120
    assert config.workers.initial_analysis_timeout_seconds == 3_600


@pytest.mark.parametrize(
    "content",
    [
        'schema_version = "1"\nunknown = true\n',
        'schema_version = "1"\n[workers]\nanalysis_limit = "1"\n',
        'schema_version = "1"\n[workers]\ninitial_analysis_timeout_seconds = 0\n',
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


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ('schema_version = "1"\nunknown = true\n', "unknown：此项不受支持"),
        (
            'schema_version = "1"\n[workers]\nanalysis_limit = "1"\n',
            "workers.analysis_limit：必须填写整数",
        ),
        ('schema_version = "2"\n', 'schema_version：只能填写 "1"'),
    ],
)
def test_config_validation_error_uses_plain_chinese(
    tmp_path: Path,
    content: str,
    expected: str,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigError) as caught:
        load_config(path)

    message = str(caught.value)
    assert expected in message
    assert "Input should" not in message
    assert "validation error" not in message
    assert "配置不符合当前 schema" not in message


def test_invalid_toml_error_explains_what_to_check(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[runtime\n", encoding="utf-8")

    with pytest.raises(ConfigError) as caught:
        load_config(path)

    assert str(caught.value) == ("config.toml 内容不是有效的 TOML。请检查表名、引号和等号")


def test_explicit_missing_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="不存在"):
        load_config(tmp_path / "missing.toml")


def test_runtime_paths_create_configured_directories_inside_working_tree(
    tmp_path: Path,
) -> None:
    working_tree = tmp_path / "repository"
    working_tree.mkdir()
    config_path = working_tree / "config.toml"
    config_path.write_text(
        """
schema_version = "1"

[runtime]
data_root = "data"
log_root = "logs"
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)
    data_root = working_tree / "data"
    log_root = working_tree / "logs"

    assert not data_root.exists()
    assert not log_root.exists()

    paths = RuntimePaths.discover(
        runtime=config.runtime,
        working_tree=working_tree,
        environment={},
        session_id="session_test",
    )
    paths.ensure()

    assert paths.data_root == data_root.resolve()
    assert paths.log_root == (log_root / "sessions" / "session_test").resolve()
    assert paths.shared_log_root == log_root.resolve()
    assert paths.workspace_root.is_dir()
    assert paths.artifact_root.is_dir()
    assert paths.session_data_root.is_dir()
    assert paths.log_root.is_dir()


def test_runtime_paths_reject_working_tree_ancestor(tmp_path: Path) -> None:
    working_tree = tmp_path / "repository"

    with pytest.raises(RuntimePathError, match="项目目录"):
        RuntimePaths.discover(
            working_tree=working_tree,
            environment={
                DATA_ROOT_ENV: str(tmp_path),
                LOG_ROOT_ENV: str(tmp_path / "logs"),
            },
        )


@pytest.mark.parametrize("data_root", [".", ".."])
def test_config_working_tree_is_checked_from_unrelated_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data_root: str,
) -> None:
    working_tree = tmp_path / "repository"
    unrelated_cwd = tmp_path / "elsewhere"
    (working_tree / ".git").mkdir(parents=True)
    unrelated_cwd.mkdir()
    config_path = working_tree / "config.toml"
    config_path.write_text(
        (f'schema_version = "1"\n[runtime]\ndata_root = "{data_root}"\nlog_root = "logs"\n'),
        encoding="utf-8",
    )
    monkeypatch.chdir(unrelated_cwd)
    config = load_config(config_path)

    with pytest.raises(RuntimePathError, match="项目目录"):
        RuntimePaths.discover(
            runtime=config.runtime,
            config_directory=config_path.parent,
            environment={},
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
    assert paths.shared_log_root == log_root.resolve()
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

    with pytest.raises(RuntimePathError, match=r"相同|内部数据目录"):
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


def test_runtime_config_ida_dir_must_be_absolute() -> None:
    with pytest.raises(ValueError, match="绝对路径"):
        RuntimeConfig.model_validate({"ida_dir": "relative/path"}, strict=True)


@pytest.mark.parametrize("field", ["data_root", "log_root"])
def test_runtime_config_roots_accept_relative_paths(field: str) -> None:
    runtime = RuntimeConfig.model_validate({field: "relative/path"}, strict=True)

    assert getattr(runtime, field) == "relative/path"


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
