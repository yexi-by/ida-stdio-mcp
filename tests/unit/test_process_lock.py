from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

import pytest

from ida_re_mcp.supervisor._process_lock import (
    AsyncInterprocessFileLock,
    exclusive_process_lease,
    interprocess_file_lock,
)


def test_exclusive_process_leases_are_not_reentrant_across_instances(
    tmp_path: Path,
) -> None:
    path = tmp_path / "supervisor.lease.lock"
    first = exclusive_process_lease(path)
    second = exclusive_process_lease(path)

    assert first.try_acquire()
    assert not second.try_acquire()
    first.release()

    assert second.try_acquire()
    second.release()


def test_async_file_lock_wait_is_nonblocking_and_cancellation_safe(tmp_path: Path) -> None:
    process_lock = interprocess_file_lock(tmp_path / "workspace.lease.lock")
    holder_entered = threading.Event()
    holder_release = threading.Event()

    def hold() -> None:
        with process_lock:
            holder_entered.set()
            holder_release.wait(timeout=5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert holder_entered.wait(timeout=1)
    emergency_release = threading.Timer(2, holder_release.set)
    emergency_release.start()

    async def scenario() -> None:
        lock = AsyncInterprocessFileLock(process_lock)
        waiter = asyncio.create_task(lock.acquire())
        started = time.monotonic()
        await asyncio.sleep(0.05)
        assert not waiter.done()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(waiter, timeout=1)
        assert time.monotonic() - started < 1

        holder_release.set()
        await asyncio.to_thread(holder.join, 1)
        assert not holder.is_alive()
        assert await lock.acquire()
        await asyncio.create_task(lock.release())
        await lock.aclose()

    try:
        asyncio.run(scenario())
    finally:
        holder_release.set()
        emergency_release.cancel()
        holder.join(timeout=1)
