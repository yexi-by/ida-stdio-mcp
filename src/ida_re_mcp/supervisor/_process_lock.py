"""按路径隔离、进程内可重入的操作系统文件锁。"""

from __future__ import annotations

import asyncio
import errno
import os
import threading
import time
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
