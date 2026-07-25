"""Supervisor 与隔离 IDA 子进程之间的窄编排接口。"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol, cast

from ida_re_mcp.supervisor.workers import WorkerKind, WorkerProcess
from ida_re_mcp.worker.ipc import JsonObject, JsonValue

_PROBE_TIMEOUT_SECONDS = 30.0
_PROBE_TERMINATE_SECONDS = 2.0


class DebugRequestCancelled(asyncio.CancelledError):
    """调用方取消后, 携带 DebugWorker 最终观察到的真实状态。"""

    def __init__(
        self,
        operation: str,
        result: JsonObject | None,
        failure: BaseException | None = None,
    ) -> None:
        super().__init__(f"debug request cancelled: {operation}")
        self.operation = operation
        self.result = result
        self.failure = failure


class DebugBackend(Protocol):
    """一个持久 DebugWorker 子进程。"""

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject: ...

    async def close(self) -> None: ...


class AnalysisBackend(Protocol):
    """一个持久 AnalysisWorker 子进程。"""

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject: ...

    async def close(self) -> None: ...


class IdaBackend(Protocol):
    """Application 所需的全部 worker 能力。"""

    async def bootstrap(
        self,
        *,
        sample_path: Path,
        staging_path: Path,
        timeout_seconds: float,
    ) -> JsonObject: ...

    async def open_analysis(
        self,
        *,
        checkout_path: Path,
        revision: str,
    ) -> AnalysisBackend: ...

    async def mutate(
        self,
        *,
        staging_path: Path,
        operations: Sequence[Mapping[str, JsonValue]],
        timeout_seconds: float,
    ) -> JsonObject: ...

    async def refine(
        self,
        *,
        staging_path: Path,
        input: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> JsonObject: ...

    async def expert(
        self,
        *,
        staging_path: Path,
        code: str,
        timeout_seconds: float,
    ) -> JsonObject: ...

    async def open_debug(
        self,
        *,
        checkout_path: Path,
        sample_path: Path,
        revision: str,
        allow_attach: bool,
    ) -> DebugBackend: ...

    async def doctor(self) -> JsonObject: ...


class _ProcessAnalysisBackend:
    def __init__(self, process: WorkerProcess) -> None:
        self._process = process

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject:
        execution = asyncio.create_task(
            asyncio.to_thread(
                self._process.execute,
                operation,
                input,
                timeout_seconds=timeout_seconds,
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            cleanup = asyncio.create_task(_abort_worker_and_wait(self._process, execution))
            await _await_cleanup(cleanup)
            raise

    async def close(self) -> None:
        closing = asyncio.create_task(asyncio.to_thread(self._process.close))
        await _await_cleanup(closing)


class _ProcessDebugBackend:
    def __init__(self, process: WorkerProcess) -> None:
        self._process = process

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject:
        request_id = uuid.uuid4().hex
        execution = asyncio.create_task(
            asyncio.to_thread(
                self._process.execute,
                operation,
                input,
                timeout_seconds=timeout_seconds,
                request_id=request_id,
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError as cancellation:
            try:
                await asyncio.to_thread(self._process.cancel, request_id)
            except Exception:
                # IPC 失联会由原调用给出稳定 worker 错误; 调试取消绝不以杀进程兜底。
                pass
            while not execution.done():
                try:
                    await asyncio.shield(execution)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            try:
                result = execution.result()
            except BaseException as failure:
                raise DebugRequestCancelled(operation, None, failure) from cancellation
            raise DebugRequestCancelled(operation, result) from cancellation

    async def close(self) -> None:
        closing = asyncio.create_task(asyncio.to_thread(self._process.close))
        await _await_cleanup(closing)


class SubprocessIdaBackend:
    """使用认证本机 IPC 的默认 worker 后端。"""

    def __init__(
        self,
        *,
        log_root: Path,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._log_root = log_root.resolve()
        self._log_root.mkdir(parents=True, exist_ok=True)
        self._environment = dict(environment or {})

    async def bootstrap(
        self,
        *,
        sample_path: Path,
        staging_path: Path,
        timeout_seconds: float,
    ) -> JsonObject:
        return await self._one_shot(
            kind="bootstrap",
            operation="workspace.bootstrap",
            input={"staging_path": str(staging_path)},
            sample=sample_path,
            timeout_seconds=timeout_seconds,
        )

    async def open_analysis(
        self,
        *,
        checkout_path: Path,
        revision: str,
    ) -> AnalysisBackend:
        process = await self._launch(
            kind="analysis",
            checkout=checkout_path,
            revision=revision,
        )
        return _ProcessAnalysisBackend(process)

    async def mutate(
        self,
        *,
        staging_path: Path,
        operations: Sequence[Mapping[str, JsonValue]],
        timeout_seconds: float,
    ) -> JsonObject:
        return await self._one_shot(
            kind="mutation",
            operation="mutation.apply",
            input={
                "staging_path": str(staging_path),
                "operations": [dict(item) for item in operations],
            },
            checkout=staging_path,
            timeout_seconds=timeout_seconds,
        )

    async def refine(
        self,
        *,
        staging_path: Path,
        input: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> JsonObject:
        return await self._one_shot(
            kind="mutation",
            operation="analysis.refine",
            input=input,
            checkout=staging_path,
            timeout_seconds=timeout_seconds,
        )

    async def expert(
        self,
        *,
        staging_path: Path,
        code: str,
        timeout_seconds: float,
    ) -> JsonObject:
        return await self._one_shot(
            kind="expert",
            operation="expert.execute",
            input={"staging_path": str(staging_path), "code": code},
            checkout=staging_path,
            timeout_seconds=timeout_seconds,
        )

    async def open_debug(
        self,
        *,
        checkout_path: Path,
        sample_path: Path,
        revision: str,
        allow_attach: bool,
    ) -> DebugBackend:
        process = await self._launch(
            kind="debug",
            checkout=checkout_path,
            sample=sample_path,
            allow_attach=allow_attach,
        )
        return _ProcessDebugBackend(process)

    async def doctor(self) -> JsonObject:
        environment = os.environ.copy()
        environment.update(self._environment)
        launch = asyncio.create_task(
            asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "ida_re_mcp.worker",
                "probe",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
        )
        try:
            process = await asyncio.shield(launch)
        except asyncio.CancelledError:
            process = await _settle_cancelled_probe_launch(launch)
            if process is not None:
                communication = asyncio.create_task(process.communicate())
                cleanup = asyncio.create_task(_terminate_and_reap_probe(process, communication))
                await _await_cleanup(cleanup)
            raise
        communication = asyncio.create_task(process.communicate())
        try:
            stdout, stderr = await asyncio.wait_for(
                asyncio.shield(communication),
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
        except BaseException:
            cleanup = asyncio.create_task(_terminate_and_reap_probe(process, communication))
            await _await_cleanup(cleanup)
            raise
        if process.returncode != 0:
            return {
                "available": False,
                "code": "worker_probe_failed",
                "returncode": process.returncode,
                "stderr": stderr.decode("utf-8", errors="replace")[:2_048],
            }
        try:
            value: object = json.loads(stdout.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {
                "available": False,
                "code": "worker_probe_invalid_output",
            }
        if not isinstance(value, dict):
            return {
                "available": False,
                "code": "worker_probe_invalid_output",
            }
        return cast(JsonObject, cast(dict[str, object], value))

    async def _one_shot(
        self,
        *,
        kind: WorkerKind,
        operation: str,
        input: Mapping[str, JsonValue],
        timeout_seconds: float,
        checkout: Path | None = None,
        sample: Path | None = None,
        revision: str | None = None,
    ) -> JsonObject:
        process = await self._launch(
            kind=kind,
            checkout=checkout,
            sample=sample,
            revision=revision,
        )
        execution = asyncio.create_task(
            asyncio.to_thread(
                process.execute,
                operation,
                input,
                timeout_seconds=timeout_seconds,
            )
        )
        try:
            return await asyncio.shield(execution)
        except asyncio.CancelledError:
            cleanup = asyncio.create_task(_abort_worker_and_wait(process, execution))
            await _await_cleanup(cleanup)
            raise
        finally:
            closing = asyncio.create_task(asyncio.to_thread(process.close))
            await _await_cleanup(closing)

    async def _launch(
        self,
        *,
        kind: WorkerKind,
        checkout: Path | None = None,
        sample: Path | None = None,
        revision: str | None = None,
        allow_attach: bool = False,
    ) -> WorkerProcess:
        """取消若撞上进程启动, 等待句柄产生并立即终止, 避免遗失 worker。"""

        launch = asyncio.create_task(
            asyncio.to_thread(
                WorkerProcess.launch,
                kind=kind,
                log_root=self._log_root,
                checkout=checkout,
                sample=sample,
                revision=revision,
                allow_attach=allow_attach,
                environment=self._environment,
            )
        )
        try:
            return await asyncio.shield(launch)
        except asyncio.CancelledError:
            outcome = await _settle_cancelled_worker_launch(launch)
            if outcome is not None:
                cleanup = asyncio.create_task(asyncio.to_thread(outcome.abort))
                await _await_cleanup(cleanup)
            raise


async def _settle_cancelled_worker_launch(
    launch: asyncio.Task[WorkerProcess],
) -> WorkerProcess | None:
    """等待取消窗口中的 IDA worker 启动落定, 并吸收启动自身的失败。"""

    while not launch.done():
        try:
            await asyncio.shield(launch)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    if launch.cancelled():
        return None
    try:
        return launch.result()
    except BaseException:
        return None


async def _settle_cancelled_probe_launch(
    launch: asyncio.Task[asyncio.subprocess.Process],
) -> asyncio.subprocess.Process | None:
    """等待取消窗口中的 probe 启动落定, 并吸收启动自身的失败。"""

    while not launch.done():
        try:
            await asyncio.shield(launch)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    if launch.cancelled():
        return None
    try:
        return launch.result()
    except BaseException:
        return None


async def _terminate_and_reap_probe(
    process: asyncio.subprocess.Process,
    communication: asyncio.Task[tuple[bytes, bytes]],
) -> None:
    """终止并回收被取消或超时的 probe, 确保调用方不会先释放 worker slot。"""

    if process.returncode is None:
        try:
            process.terminate()
        except OSError:
            pass
    reaping = asyncio.create_task(process.wait())
    try:
        await asyncio.wait_for(
            asyncio.shield(reaping),
            timeout=_PROBE_TERMINATE_SECONDS,
        )
    except TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except OSError:
                pass
        await reaping
    finally:
        await asyncio.gather(communication, return_exceptions=True)


async def _abort_worker_and_wait(
    process: WorkerProcess,
    execution: asyncio.Task[JsonObject],
) -> None:
    """终止 worker 并等待阻塞执行线程观察到进程退出。"""

    try:
        await asyncio.to_thread(process.abort)
    finally:
        await asyncio.gather(execution, return_exceptions=True)


async def _await_cleanup(cleanup: asyncio.Task[None]) -> None:
    """记录重复取消, 等清理真正完成后再向调用方传播。"""

    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            await asyncio.shield(cleanup)
            break
        except asyncio.CancelledError as exc:
            if cleanup.cancelled():
                raise
            cancellation = exc
            continue
    if cancellation is not None:
        raise cancellation
