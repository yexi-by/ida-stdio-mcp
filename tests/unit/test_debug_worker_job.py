"""Windows Job Object 的强清理门禁。"""

from __future__ import annotations

import os
import subprocess
import sys
from ctypes import c_void_p, sizeof
from pathlib import Path

import pytest

from ida_re_mcp.worker.errors import CapabilityError, WorkerError
from ida_re_mcp.worker.job import WindowsJob, verify_process_architecture

_FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "bin"


def test_job_close_terminates_assigned_process() -> None:
    if os.name != "nt":
        pytest.fail("动态调试单元门禁要求 Windows runner")
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    job = WindowsJob()
    try:
        job.assign(process.pid)
        job.close()
        process.wait(timeout=5)
        assert process.returncode is not None
    finally:
        job.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_closed_job_rejects_assignment() -> None:
    job = WindowsJob()
    job.close()

    with pytest.raises(WorkerError) as rejected:
        job.assign(os.getpid())

    assert rejected.value.code == "job_object_closed"


def test_current_worker_process_matches_idb_bitness() -> None:
    verify_process_architecture(os.getpid(), bitness=sizeof(c_void_p) * 8)


def test_process_architecture_verification_rejects_invalid_pid() -> None:
    with pytest.raises(WorkerError) as rejected:
        verify_process_architecture(0, bitness=sizeof(c_void_p) * 8)

    assert rejected.value.code == "debug_process_query_failed"


def test_process_architecture_verification_rejects_idb_mismatch() -> None:
    process_bitness = sizeof(c_void_p) * 8
    mismatched_bitness = 32 if process_bitness == 64 else 64

    with pytest.raises(CapabilityError) as rejected:
        verify_process_architecture(os.getpid(), bitness=mismatched_bitness)

    assert rejected.value.code == "capability_unavailable"
    assert rejected.value.details["idb_bitness"] == mismatched_bitness


def test_wow64_process_matches_32_bit_idb() -> None:
    process = subprocess.Popen(
        [str(_FIXTURE_ROOT / "debug_target_x86.exe"), "--ida-re-hold"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        verify_process_architecture(process.pid, bitness=32)
        with pytest.raises(CapabilityError) as rejected:
            verify_process_architecture(process.pid, bitness=64)
        assert rejected.value.code == "capability_unavailable"
        assert rejected.value.details["process_machine"] == "0x014c"
    finally:
        process.terminate()
        process.wait(timeout=5)
