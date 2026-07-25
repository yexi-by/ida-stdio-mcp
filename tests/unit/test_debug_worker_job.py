"""Windows Job Object 的强清理门禁。"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.job import WindowsJob, verify_x64_process


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


def test_current_worker_process_is_verified_as_x64() -> None:
    verify_x64_process(os.getpid())


def test_x64_verification_rejects_invalid_pid() -> None:
    with pytest.raises(WorkerError) as rejected:
        verify_x64_process(0)

    assert rejected.value.code == "debug_process_query_failed"
