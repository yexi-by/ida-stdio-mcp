from __future__ import annotations

from pathlib import Path

import pytest

import ida_re_mcp.config as config_module
from ida_re_mcp.config import (
    AppConfig,
    ConfigError,
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


def test_load_current_toml_schema(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
schema_version = "2026-07-28"

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
""".strip(),
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.policy.debug_attach is True
    assert config.workers.analysis_limit == 2
    assert config.storage.quota_gib == 40


def test_shipped_example_is_valid_current_config() -> None:
    project_root = Path(__file__).resolve().parents[2]

    config = load_config(project_root / "config.example.toml")

    assert config == AppConfig()


@pytest.mark.parametrize(
    "content",
    [
        'schema_version = "2026-07-28"\nunknown = true\n',
        'schema_version = "2026-07-28"\n[workers]\nanalysis_limit = "1"\n',
        "[policy]\nauthoring = true\n",
    ],
)
def test_config_rejects_everything_outside_current_schema(
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
