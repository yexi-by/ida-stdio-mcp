from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.worker import expert as expert_module
from ida_re_mcp.worker._ida import IdaModules
from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.expert import ExpertWorker


class _FakeAuto:
    def __init__(self, results: list[bool] | None = None) -> None:
        self.results = list(results or [True, True])
        self.calls = 0

    def auto_wait(self) -> bool:
        self.calls += 1
        return self.results.pop(0)


class _FakeLoader:
    DBFL_COMP = 1
    PATH_TYPE_IDB = 2

    def __init__(self, staging_path: Path, *, save_result: bool = True) -> None:
        self.staging_path = staging_path
        self.save_result = save_result
        self.save_calls: list[tuple[str, int]] = []

    def get_path(self, path_type: int) -> str:
        assert path_type == self.PATH_TYPE_IDB
        return str(self.staging_path)

    def save_database(self, path: str, flags: int) -> bool:
        self.save_calls.append((path, flags))
        if self.save_result:
            Path(path).write_bytes(Path(path).read_bytes() + b"-saved")
        return self.save_result


class _FakeApi:
    def __init__(
        self,
        staging_path: Path,
        *,
        wait_results: list[bool] | None = None,
        save_result: bool = True,
    ) -> None:
        self.ida_auto = _FakeAuto(wait_results)
        self.ida_loader = _FakeLoader(staging_path, save_result=save_result)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _worker(
    monkeypatch: pytest.MonkeyPatch,
    staging_path: Path,
    *,
    wait_results: list[bool] | None = None,
    save_result: bool = True,
) -> tuple[ExpertWorker, _FakeApi]:
    api = _FakeApi(
        staging_path,
        wait_results=wait_results,
        save_result=save_result,
    )

    def fake_require_ida(*_module_names: str) -> IdaModules:
        return cast(IdaModules, api)

    monkeypatch.setattr(expert_module, "require_ida", fake_require_ida)
    return ExpertWorker(), api


def test_execute_captures_streams_and_last_expression_then_saves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging.i64"
    staging.write_bytes(b"idb")
    worker, api = _worker(monkeypatch, staging)

    result = worker.execute(
        "expert.execute",
        {
            "staging_path": str(staging),
            "code": ("print('你好')\nimport sys\nprint('diagnostic', file=sys.stderr)\n21 * 2"),
        },
    )

    assert result == {
        "staging_path": str(staging),
        "staging_sha256": _sha256(staging),
        "saved": True,
        "stdout": "你好\n",
        "stderr": "diagnostic\n",
        "result_repr": "42",
        "cold_verification_required": True,
    }
    assert api.ida_auto.calls == 2
    assert api.ida_loader.save_calls == [(str(staging), api.ida_loader.DBFL_COMP)]


@pytest.mark.parametrize(
    ("code", "expected_code"),
    [
        ("if", "expert_compile_failed"),
        ("raise RuntimeError('private')", "expert_execution_failed"),
        ("raise SystemExit(7)", "expert_execution_failed"),
        ("print('x' * 65537, end='')", "expert_output_too_large"),
        ("'x' * 65537", "expert_result_too_large"),
    ],
)
def test_failure_never_invokes_database_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    expected_code: str,
) -> None:
    staging = tmp_path / "staging.i64"
    staging.write_bytes(b"unchanged")
    before = _sha256(staging)
    worker, api = _worker(monkeypatch, staging)

    with pytest.raises(WorkerError) as raised:
        worker.execute(
            "expert.execute",
            {"staging_path": str(staging), "code": code},
        )

    assert raised.value.code == expected_code
    assert api.ida_loader.save_calls == []
    assert _sha256(staging) == before


def test_stdout_and_stderr_share_one_64_kib_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging.i64"
    staging.write_bytes(b"unchanged")
    worker, api = _worker(monkeypatch, staging)

    with pytest.raises(WorkerError) as raised:
        worker.execute(
            "expert.execute",
            {
                "staging_path": str(staging),
                "code": (
                    "import sys\n"
                    "print('a' * 32768, end='')\n"
                    "print('b' * 32769, end='', file=sys.stderr)"
                ),
            },
        )

    assert raised.value.code == "expert_output_too_large"
    assert api.ida_loader.save_calls == []


def test_exact_64_kib_stdout_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging.i64"
    staging.write_bytes(b"idb")
    worker, api = _worker(monkeypatch, staging)

    result = worker.execute(
        "expert.execute",
        {
            "staging_path": str(staging),
            "code": "print('x' * 65536, end='')",
        },
    )

    assert result["stdout"] == "x" * 65536
    assert api.ida_loader.save_calls


def test_autoanalysis_cancellation_after_execution_does_not_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging.i64"
    staging.write_bytes(b"unchanged")
    worker, api = _worker(monkeypatch, staging, wait_results=[True, False])

    with pytest.raises(WorkerError) as raised:
        worker.execute(
            "expert.execute",
            {"staging_path": str(staging), "code": "1 + 1"},
        )

    assert raised.value.code == "cancelled"
    assert api.ida_loader.save_calls == []


def test_worker_rejects_wrong_operation_and_non_exact_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging.i64"
    staging.write_bytes(b"idb")
    worker, _ = _worker(monkeypatch, staging)

    with pytest.raises(WorkerError) as wrong_operation:
        worker.execute("program.overview", {})
    assert wrong_operation.value.code == "invalid_worker_input"

    with pytest.raises(WorkerError) as extra_key:
        worker.execute(
            "expert.execute",
            {
                "staging_path": str(staging),
                "code": "None",
                "timeout_seconds": 1,
            },
        )
    assert extra_key.value.code == "invalid_worker_input"


def test_database_mismatch_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / "staging.i64"
    other = tmp_path / "other.i64"
    staging.write_bytes(b"idb")
    other.write_bytes(b"idb")
    worker, api = _worker(monkeypatch, other)

    with pytest.raises(WorkerError) as raised:
        worker.execute(
            "expert.execute",
            {"staging_path": str(staging), "code": "None"},
        )

    assert raised.value.code == "staging_mismatch"
    assert api.ida_loader.save_calls == []
