"""使用真实 IDALib 验证 Expert staging 的保存边界。"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest

from ida_re_mcp.supervisor.workers import WorkerProcess, WorkerProcessError
from ida_re_mcp.worker.errors import WorkerError


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _bootstrap(tmp_path: Path, sample: Path) -> Path:
    staging = tmp_path / "base.i64"
    worker = WorkerProcess.launch(
        kind="bootstrap",
        log_root=tmp_path / "logs",
        sample=sample,
        connect_timeout_seconds=60,
    )
    try:
        result = worker.execute(
            "workspace.bootstrap",
            {"staging_path": str(staging)},
            timeout_seconds=120,
        )
        assert result["saved"] is True
    finally:
        worker.close()
    return staging


@pytest.mark.ida
def test_expert_saves_only_successful_disposable_staging(
    tmp_path: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    assert ida_environment["IDADIR"]
    sample = fixture_directory / "native_pe_x64.dll"
    base = _bootstrap(tmp_path, sample)
    base_hash = _sha256(base)

    failed_staging = tmp_path / "failed.i64"
    shutil.copy2(base, failed_staging)
    failed_worker = WorkerProcess.launch(
        kind="expert",
        log_root=tmp_path / "logs",
        checkout=failed_staging,
        connect_timeout_seconds=60,
    )
    try:
        with pytest.raises(WorkerError) as raised:
            failed_worker.execute(
                "expert.execute",
                {
                    "staging_path": str(failed_staging),
                    "code": (
                        "import ida_name, ida_nalt\n"
                        "ea = ida_nalt.get_imagebase() + 0x1020\n"
                        "ida_name.set_name(ea, 'must_not_persist', ida_name.SN_NOCHECK)\n"
                        "raise RuntimeError('abort')"
                    ),
                },
                timeout_seconds=30,
            )
        assert raised.value.code == "expert_execution_failed"
    finally:
        failed_worker.close()
    assert _sha256(failed_staging) == base_hash

    timed_out_staging = tmp_path / "timed-out.i64"
    shutil.copy2(base, timed_out_staging)
    timed_out_worker = WorkerProcess.launch(
        kind="expert",
        log_root=tmp_path / "logs",
        checkout=timed_out_staging,
        connect_timeout_seconds=60,
    )
    try:
        with pytest.raises(WorkerProcessError) as timed_out:
            timed_out_worker.execute(
                "expert.execute",
                {
                    "staging_path": str(timed_out_staging),
                    "code": "while True:\n    pass",
                },
                timeout_seconds=0.5,
            )
        assert timed_out.value.code == "worker_timeout"
    finally:
        timed_out_worker.close()
    assert _sha256(timed_out_staging) == base_hash

    successful_staging = tmp_path / "successful.i64"
    shutil.copy2(base, successful_staging)
    successful_worker = WorkerProcess.launch(
        kind="expert",
        log_root=tmp_path / "logs",
        checkout=successful_staging,
        connect_timeout_seconds=60,
    )
    try:
        result = successful_worker.execute(
            "expert.execute",
            {
                "staging_path": str(successful_staging),
                "code": (
                    "import sys\n"
                    "import ida_name, ida_nalt\n"
                    "ea = ida_nalt.get_imagebase() + 0x1020\n"
                    "assert ida_name.set_name("
                    "ea, 'expert_verified', ida_name.SN_NOCHECK"
                    ")\n"
                    "print('expert stdout')\n"
                    "print('expert stderr', file=sys.stderr)\n"
                    "{'ea': hex(ea), 'name': ida_name.get_name(ea)}"
                ),
            },
            timeout_seconds=30,
        )
        assert result["saved"] is True
        assert result["cold_verification_required"] is True
        assert result["stdout"] == "expert stdout\n"
        assert result["stderr"] == "expert stderr\n"
        assert result["result_repr"] == ("{'ea': '0x180001020', 'name': 'expert_verified'}")
        assert result["staging_sha256"] == _sha256(successful_staging)
    finally:
        successful_worker.close()

    assert _sha256(base) == base_hash
    assert _sha256(successful_staging) != base_hash
    verifier = WorkerProcess.launch(
        kind="analysis",
        log_root=tmp_path / "logs",
        checkout=successful_staging,
        connect_timeout_seconds=60,
    )
    try:
        inspected = verifier.execute(
            "address.inspect",
            {
                "address": {"space": "image", "rva": "0x1020"},
                "byte_count": 1,
            },
            timeout_seconds=30,
        )
        assert inspected["name"] == "expert_verified"
    finally:
        verifier.close()
