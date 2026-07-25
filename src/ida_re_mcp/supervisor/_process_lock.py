"""按路径隔离、进程内可重入的操作系统文件锁。"""

from __future__ import annotations

import asyncio
import errno
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Literal, Self

if TYPE_CHECKING:
    import fcntl
    import msvcrt
elif os.name == "nt":
    import msvcrt
else:
    import fcntl

_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, InterprocessFileLock] = {}


class InterprocessFileLock:
    """组合线程可重入锁与随进程退出自动释放的文件锁。"""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._thread_lock = threading.RLock()
        self._depth = 0
        self._descriptor: int | None = None
        self._owner_thread: int | None = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_type, exc_value, traceback
        self.release()
        return False

    def acquire(self) -> None:
        """阻塞到当前线程同时持有进程内锁和操作系统锁。"""

        while not self.try_acquire():
            time.sleep(0.01)

    def try_acquire(self) -> bool:
        """尝试一次加锁, 不等待进程内或操作系统中的其他持有者。"""

        if not self._thread_lock.acquire(blocking=False):
            return False
        try:
            if self._depth == 0:
                descriptor = _open_and_try_lock(self.path)
                if descriptor is None:
                    self._thread_lock.release()
                    return False
                self._descriptor = descriptor
                self._owner_thread = threading.get_ident()
            self._depth += 1
        except BaseException:
            self._thread_lock.release()
            raise
        return True

    def release(self) -> None:
        """释放一层锁, 最外层退出时关闭文件描述符。"""

        if self._depth <= 0 or self._owner_thread != threading.get_ident():
            raise RuntimeError("文件锁未被当前线程持有")
        self._depth -= 1
        try:
            if self._depth == 0:
                descriptor = self._descriptor
                self._descriptor = None
                self._owner_thread = None
                if descriptor is None:
                    raise RuntimeError("文件锁描述符缺失")
                try:
                    _unlock_descriptor(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            self._thread_lock.release()


class AsyncInterprocessFileLock:
    """不阻塞事件循环且可跨 asyncio task 交接释放的进程锁。"""

    def __init__(self, process_lock: InterprocessFileLock) -> None:
        self.path = process_lock.path
        self._process_lock = process_lock
        self._local_lock = asyncio.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix=f"workspace-lease-{self.path.stem}",
        )
        self._held = False
        self._closed = False

    async def __aenter__(self) -> Self:
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_type, exc_value, traceback
        await self.release()
        return False

    async def acquire(self) -> bool:
        """异步等待锁; 取消时不会遗留稍后才取得的孤儿锁。"""

        if self._closed:
            raise RuntimeError("异步文件锁已经关闭")
        await self._local_lock.acquire()
        try:
            loop = asyncio.get_running_loop()
            while True:
                attempt = loop.run_in_executor(
                    self._executor,
                    self._process_lock.try_acquire,
                )
                try:
                    acquired = await asyncio.shield(attempt)
                except asyncio.CancelledError:
                    acquired = await _await_without_cancellation(attempt)
                    if acquired:
                        release = loop.run_in_executor(
                            self._executor,
                            self._process_lock.release,
                        )
                        await _await_without_cancellation(release)
                    raise
                if acquired:
                    self._held = True
                    return True
                await asyncio.sleep(0.01)
        except BaseException:
            self._local_lock.release()
            raise

    async def release(self) -> None:
        """完整释放进程锁后才允许本进程内的下一位等待者进入。"""

        if not self._held:
            raise RuntimeError("异步文件锁尚未持有")
        loop = asyncio.get_running_loop()
        release = loop.run_in_executor(
            self._executor,
            self._process_lock.release,
        )
        cancellation: asyncio.CancelledError | None = None
        try:
            await asyncio.shield(release)
        except asyncio.CancelledError as exc:
            cancellation = exc
            await _await_without_cancellation(release)
        finally:
            self._held = False
            self._local_lock.release()
        if cancellation is not None:
            raise cancellation

    async def aclose(self) -> None:
        """关闭该 workspace 的专用锁线程。"""

        if self._closed:
            return
        if self._held or self._local_lock.locked():
            raise RuntimeError("不得关闭仍被持有或等待的异步文件锁")
        self._closed = True
        await asyncio.to_thread(
            self._executor.shutdown,
            wait=True,
            cancel_futures=True,
        )


class AsyncInterprocessSlotLease:
    """一个已取得的跨进程容量槽位。"""

    def __init__(self, pool: AsyncInterprocessSlotPool, index: int) -> None:
        self._pool = pool
        self.index = index
        self._released = False

    async def release(self) -> None:
        """释放槽位; 重复调用不产生副作用。"""

        if self._released:
            return
        try:
            await self._pool.release(self.index)
        finally:
            self._released = True


class AsyncInterprocessSlotPool:
    """由文件 lease 组成的跨 Supervisor 异步容量池。"""

    def __init__(self, root: Path, *, limit: int) -> None:
        if isinstance(limit, bool) or limit < 1:
            raise ValueError("slot pool limit 必须是正整数")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.limit = limit
        self._locks = tuple(
            exclusive_process_lease(self.root / f"slot_{index:03d}.lease.lock")
            for index in range(limit)
        )
        self._held_indices: set[int] = set()
        self._waiter_root = self.root / "waiters"
        self._waiter_lease_root = self.root / "waiter-leases"
        self._waiter_root.mkdir(exist_ok=True)
        self._waiter_lease_root.mkdir(exist_ok=True)
        self._waiter_registry = interprocess_file_lock(self.root / "waiters.registry.lease.lock")
        self._waiter_leases: dict[str, InterprocessFileLock] = {}
        self._next_index = 0
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix=f"worker-slot-{self.root.name}",
        )
        self._state_guard = asyncio.Lock()
        self._close_guard = asyncio.Lock()
        self._closing = False
        self._closed = False

    async def acquire(self) -> AsyncInterprocessSlotLease:
        """等待任意全局槽位, 取消时不会留下孤儿 lease。"""

        immediate = await self.try_acquire()
        if immediate is not None:
            return immediate

        waiter_token = await self._register_waiter()
        lease: AsyncInterprocessSlotLease | None = None
        try:
            while lease is None:
                lease = await self.try_acquire()
                if lease is None:
                    await asyncio.sleep(0.01)
        except BaseException:
            cleanup = asyncio.create_task(self._unregister_waiter(waiter_token))
            await _await_without_cancellation(cleanup)
            raise
        try:
            await self._unregister_waiter(waiter_token)
        except BaseException:
            release = asyncio.create_task(lease.release())
            await _await_without_cancellation(release)
            raise
        return lease

    async def try_acquire(self) -> AsyncInterprocessSlotLease | None:
        """非阻塞尝试一次任意全局槽位。"""

        async with self._state_guard:
            self._require_open()
            start_index = self._next_index
            self._next_index = (self._next_index + 1) % self.limit
            loop = asyncio.get_running_loop()
            attempt = loop.run_in_executor(
                self._executor,
                self._try_acquire_any,
                start_index,
            )
        try:
            index = await asyncio.shield(attempt)
        except asyncio.CancelledError:
            index = await _await_without_cancellation(attempt)
            if index is not None:
                release = loop.run_in_executor(
                    self._executor,
                    self._release_sync,
                    index,
                )
                await _await_without_cancellation(release)
            raise
        if index is None:
            return None
        if self._closed:
            release = loop.run_in_executor(
                self._executor,
                self._release_sync,
                index,
            )
            await _await_without_cancellation(release)
            raise RuntimeError("跨进程容量池已经关闭")
        return AsyncInterprocessSlotLease(self, index)

    async def release(self, index: int) -> None:
        """释放由本 pool 分配的指定槽位。"""

        async with self._state_guard:
            if self._closed:
                raise RuntimeError("跨进程容量池已经关闭")
            loop = asyncio.get_running_loop()
            release = loop.run_in_executor(
                self._executor,
                self._release_sync,
                index,
            )
        cancellation: asyncio.CancelledError | None = None
        try:
            await asyncio.shield(release)
        except asyncio.CancelledError as exc:
            cancellation = exc
            await _await_without_cancellation(release)
        if cancellation is not None:
            raise cancellation

    async def has_waiters(self) -> bool:
        """返回是否存在仍持有 waiter lease 的本进程或外部进程。"""

        async with self._state_guard:
            if self._closed or self._closing:
                return False
            loop = asyncio.get_running_loop()
            probe = loop.run_in_executor(
                self._executor,
                self._has_waiters_sync,
            )
        return await probe

    async def _register_waiter(self) -> str:
        token = f"waiter_{os.getpid()}_{uuid.uuid4().hex}"
        async with self._state_guard:
            self._require_open()
            loop = asyncio.get_running_loop()
            registration = loop.run_in_executor(
                self._executor,
                self._register_waiter_sync,
                token,
            )
        try:
            return await asyncio.shield(registration)
        except asyncio.CancelledError:
            registered = await _await_without_cancellation(registration)
            cleanup = loop.run_in_executor(
                self._executor,
                self._unregister_waiter_sync,
                registered,
            )
            await _await_without_cancellation(cleanup)
            raise

    async def _unregister_waiter(self, token: str) -> None:
        async with self._state_guard:
            if self._closed:
                raise RuntimeError("跨进程容量池已经关闭")
            loop = asyncio.get_running_loop()
            cleanup = loop.run_in_executor(
                self._executor,
                self._unregister_waiter_sync,
                token,
            )
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as cancellation:
            await _await_without_cancellation(cleanup)
            raise cancellation

    def _register_waiter_sync(self, token: str) -> str:
        with self._waiter_registry:
            lease_path = self._waiter_lease_root / f"{token}.lease.lock"
            lease = exclusive_process_lease(lease_path)
            if not lease.try_acquire():
                raise RuntimeError("唯一 waiter lease 被意外占用")
            marker = self._waiter_root / token
            try:
                marker.write_bytes(b"\0")
            except BaseException:
                lease.release()
                raise
            self._waiter_leases[token] = lease
        return token

    def _unregister_waiter_sync(self, token: str) -> None:
        with self._waiter_registry:
            lease = self._waiter_leases.pop(token, None)
            if lease is None:
                return
            marker = self._waiter_root / token
            lease_path = self._waiter_lease_root / f"{token}.lease.lock"
            marker.unlink(missing_ok=True)
            lease.release()
            lease_path.unlink(missing_ok=True)

    def _has_waiters_sync(self) -> bool:
        with self._waiter_registry:
            for marker in sorted(self._waiter_root.iterdir(), key=lambda item: item.name):
                if (
                    marker.is_symlink()
                    or not marker.is_file()
                    or not marker.name.startswith("waiter_")
                    or not marker.name.replace("_", "").isalnum()
                    or not marker.name.isascii()
                ):
                    raise RuntimeError(f"worker slot waiter 目录包含非法条目: {marker}")
                if marker.name in self._waiter_leases:
                    return True
                lease_path = self._waiter_lease_root / f"{marker.name}.lease.lock"
                probe = exclusive_process_lease(lease_path)
                if not probe.try_acquire():
                    return True
                probe.release()
                marker.unlink(missing_ok=True)
                lease_path.unlink(missing_ok=True)
        return False

    def _try_acquire_any(self, start_index: int) -> int | None:
        for offset in range(self.limit):
            index = (start_index + offset) % self.limit
            if index in self._held_indices:
                continue
            if self._locks[index].try_acquire():
                self._held_indices.add(index)
                return index
        return None

    def _release_sync(self, index: int) -> None:
        if index not in self._held_indices:
            raise RuntimeError("跨进程容量槽位未被当前 pool 持有")
        self._locks[index].release()
        self._held_indices.remove(index)

    async def aclose(self) -> None:
        """确认无活动槽位后关闭专用锁线程。"""

        cancellation: asyncio.CancelledError | None = None
        async with self._close_guard:
            if self._closed:
                return
            async with self._state_guard:
                if self._closing:
                    raise RuntimeError("跨进程容量池正在关闭")
                self._closing = True
                loop = asyncio.get_running_loop()
                held = loop.run_in_executor(
                    self._executor,
                    lambda: len(self._held_indices) + len(self._waiter_leases),
                )
            try:
                try:
                    held_count = await asyncio.shield(held)
                except asyncio.CancelledError as exc:
                    cancellation = exc
                    held_count = await _await_without_cancellation(held)
                if held_count:
                    raise RuntimeError("不得关闭仍持有槽位的跨进程容量池")
                shutdown = asyncio.create_task(
                    asyncio.to_thread(
                        self._executor.shutdown,
                        wait=True,
                        cancel_futures=False,
                    )
                )
                try:
                    await asyncio.shield(shutdown)
                except asyncio.CancelledError as exc:
                    cancellation = cancellation or exc
                    await _await_without_cancellation(shutdown)
            except BaseException:
                async with self._state_guard:
                    self._closing = False
                raise
            async with self._state_guard:
                self._closed = True
                self._closing = False
        if cancellation is not None:
            raise cancellation

    def _require_open(self) -> None:
        if self._closed or self._closing:
            raise RuntimeError("跨进程容量池已经或正在关闭")


def interprocess_file_lock(path: Path) -> InterprocessFileLock:
    """返回同一进程内按规范绝对路径共享的锁对象。"""

    resolved = path.resolve()
    key = os.path.normcase(os.fspath(resolved))
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = InterprocessFileLock(resolved)
            _LOCKS[key] = lock
        return lock


def exclusive_process_lease(path: Path) -> InterprocessFileLock:
    """创建不参与进程内路径缓存的独立进程所有权 lease。"""

    return InterprocessFileLock(path)


async def _await_without_cancellation[T](future: asyncio.Future[T]) -> T:
    while True:
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            continue


def _open_and_try_lock(path: Path) -> int | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if not _try_lock_descriptor(descriptor):
            os.close(descriptor)
            return None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _try_lock_descriptor(descriptor: int) -> bool:
    if os.name == "nt":
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            raise
        return True
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            return False
        raise
    return True


def _unlock_descriptor(descriptor: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
