from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ida_re_mcp.supervisor._process_lock import (
    AsyncInterprocessFileLock,
    AsyncInterprocessSlotPool,
    exclusive_process_lease,
    interprocess_file_lock,
)

_SLOT_PROBE = """
import asyncio
from pathlib import Path
import sys

from ida_re_mcp.supervisor._process_lock import AsyncInterprocessSlotPool

async def main():
    pool = AsyncInterprocessSlotPool(Path(sys.argv[1]), limit=1)
    lease = await pool.acquire()
    Path(sys.argv[2]).write_text("ready", encoding="ascii")
    release = Path(sys.argv[3])
    while not release.is_file():
        await asyncio.sleep(0.01)
    await lease.release()
    await pool.aclose()

asyncio.run(main())
"""


def _start_slot_probe(root: Path, ready: Path, release: Path) -> subprocess.Popen[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path.cwd() / "src")
    environment["PYTHONUTF8"] = "1"
    return subprocess.Popen(
        [sys.executable, "-c", _SLOT_PROBE, str(root), str(ready), str(release)],
        cwd=Path.cwd(),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


def _wait_for_slot_probe(ready: Path, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 5
    while not ready.is_file():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"slot probe 提前退出: {stdout!r}, {stderr!r}")
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            raise AssertionError(f"slot probe 启动超时: {stdout!r}, {stderr!r}")
        time.sleep(0.01)


class _DelayedAcquireSlotPool(AsyncInterprocessSlotPool):
    def __init__(
        self,
        root: Path,
        *,
        entered: threading.Event,
        proceed: threading.Event,
    ) -> None:
        super().__init__(root, limit=1)
        self._entered = entered
        self._proceed = proceed

    def _try_acquire_any(self, start_index: int) -> int | None:
        self._entered.set()
        assert self._proceed.wait(timeout=2)
        return super()._try_acquire_any(start_index)


class _DelayedWaiterCleanupSlotPool(AsyncInterprocessSlotPool):
    def __init__(
        self,
        root: Path,
        *,
        cleanup_entered: asyncio.Event,
        cleanup_release: asyncio.Event,
    ) -> None:
        super().__init__(root, limit=1)
        self._cleanup_entered = cleanup_entered
        self._cleanup_release = cleanup_release

    async def _unregister_waiter(self, token: str) -> None:
        await super()._unregister_waiter(token)
        self._cleanup_entered.set()
        await self._cleanup_release.wait()


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


def test_async_file_lock_try_acquire_returns_without_waiting(tmp_path: Path) -> None:
    first_process_lock = interprocess_file_lock(tmp_path / "workspace.lease.lock")
    second_process_lock = interprocess_file_lock(tmp_path / "workspace.lease.lock")

    async def scenario() -> None:
        first = AsyncInterprocessFileLock(first_process_lock)
        second = AsyncInterprocessFileLock(second_process_lock)
        assert await first.try_acquire()
        started = time.monotonic()
        assert not await second.try_acquire()
        assert time.monotonic() - started < 0.5
        assert not await first.try_acquire()

        await first.release()
        assert await second.try_acquire()
        await second.release()
        await asyncio.gather(first.aclose(), second.aclose())

    asyncio.run(scenario())


def test_async_file_lock_try_acquire_cancellation_releases_late_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process_lock = interprocess_file_lock(tmp_path / "workspace.lease.lock")
    entered = threading.Event()
    proceed = threading.Event()
    original_try_acquire = process_lock.try_acquire

    def delayed_try_acquire() -> bool:
        entered.set()
        assert proceed.wait(timeout=2)
        return original_try_acquire()

    monkeypatch.setattr(process_lock, "try_acquire", delayed_try_acquire)

    async def scenario() -> None:
        lock = AsyncInterprocessFileLock(process_lock)
        attempt = asyncio.create_task(lock.try_acquire())
        assert await asyncio.to_thread(entered.wait, 1)
        attempt.cancel()
        proceed.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(attempt, timeout=1)

        assert await lock.try_acquire()
        await lock.release()
        await lock.aclose()

    try:
        asyncio.run(scenario())
    finally:
        proceed.set()


def test_async_slot_pool_enforces_limit_across_supervisor_instances(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        root = tmp_path / "worker-slots" / "analysis"
        first_pool = AsyncInterprocessSlotPool(root, limit=1)
        second_pool = AsyncInterprocessSlotPool(root, limit=1)
        first = await first_pool.acquire()
        waiter = asyncio.create_task(second_pool.acquire())
        await asyncio.sleep(0.05)
        assert not waiter.done()
        assert await first_pool.has_waiters()

        await first.release()
        second = await asyncio.wait_for(waiter, timeout=1)
        assert second.index == 0
        assert not await first_pool.has_waiters()
        await second.release()

        await asyncio.gather(first_pool.aclose(), second_pool.aclose())

    asyncio.run(scenario())


def test_async_slot_pool_cancellation_does_not_leave_orphan_lease(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        root = tmp_path / "worker-slots" / "debug"
        first_pool = AsyncInterprocessSlotPool(root, limit=1)
        second_pool = AsyncInterprocessSlotPool(root, limit=1)
        first = await first_pool.acquire()
        waiter = asyncio.create_task(second_pool.acquire())
        await asyncio.sleep(0.05)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not await first_pool.has_waiters()

        await first.release()
        second = await asyncio.wait_for(second_pool.acquire(), timeout=1)
        await second.release()
        await asyncio.gather(first_pool.aclose(), second_pool.aclose())

    asyncio.run(scenario())


def test_async_slot_pool_serializes_other_process_and_recovers_after_crash(
    tmp_path: Path,
) -> None:
    root = tmp_path / "worker-slots" / "analysis"
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    process = _start_slot_probe(root, ready, release)
    _wait_for_slot_probe(ready, process)

    async def blocked_then_released() -> None:
        pool = AsyncInterprocessSlotPool(root, limit=1)
        waiter = asyncio.create_task(pool.acquire())
        await asyncio.sleep(0.05)
        assert not waiter.done()
        release.write_text("release", encoding="ascii")
        lease = await asyncio.wait_for(waiter, timeout=2)
        await lease.release()
        await pool.aclose()

    asyncio.run(blocked_then_released())
    stdout, stderr = process.communicate(timeout=2)
    assert process.returncode == 0, (stdout, stderr)

    crash_ready = tmp_path / "crash-ready"
    never_release = tmp_path / "never-release"
    crashed = _start_slot_probe(root, crash_ready, never_release)
    _wait_for_slot_probe(crash_ready, crashed)
    crashed.kill()
    crashed.communicate(timeout=2)

    async def acquire_after_crash() -> None:
        pool = AsyncInterprocessSlotPool(root, limit=1)
        lease = await asyncio.wait_for(pool.acquire(), timeout=2)
        await lease.release()
        await pool.aclose()

    asyncio.run(acquire_after_crash())


def test_async_slot_pool_close_cannot_overtake_inflight_acquire(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        entered = threading.Event()
        proceed = threading.Event()
        pool = _DelayedAcquireSlotPool(
            tmp_path / "worker-slots" / "analysis",
            entered=entered,
            proceed=proceed,
        )
        acquiring = asyncio.create_task(pool.try_acquire())
        assert await asyncio.to_thread(entered.wait, 1)
        closing = asyncio.create_task(pool.aclose())
        await asyncio.sleep(0.05)
        assert not closing.done()

        proceed.set()
        lease = await asyncio.wait_for(acquiring, timeout=1)
        assert lease is not None
        with pytest.raises(RuntimeError, match="仍持有槽位"):
            await asyncio.wait_for(closing, timeout=1)

        await lease.release()
        await pool.aclose()

    asyncio.run(scenario())


def test_async_slot_pool_releases_acquired_slot_if_waiter_cleanup_is_cancelled(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        root = tmp_path / "worker-slots" / "analysis"
        holder_pool = AsyncInterprocessSlotPool(root, limit=1)
        cleanup_entered = asyncio.Event()
        cleanup_release = asyncio.Event()
        waiter_pool = _DelayedWaiterCleanupSlotPool(
            root,
            cleanup_entered=cleanup_entered,
            cleanup_release=cleanup_release,
        )
        verifier_pool = AsyncInterprocessSlotPool(root, limit=1)
        held = await holder_pool.acquire()
        waiter = asyncio.create_task(waiter_pool.acquire())
        await asyncio.sleep(0.05)
        await held.release()
        await asyncio.wait_for(cleanup_entered.wait(), timeout=1)
        waiter.cancel()
        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await waiter

        verified = await asyncio.wait_for(verifier_pool.acquire(), timeout=1)
        await verified.release()
        await asyncio.gather(
            holder_pool.aclose(),
            waiter_pool.aclose(),
            verifier_pool.aclose(),
        )

    asyncio.run(scenario())
