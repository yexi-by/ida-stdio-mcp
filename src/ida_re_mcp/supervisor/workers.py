"""Supervisor 安全的 IDA worker 子进程边界。"""

import base64
import math
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from typing import BinaryIO, Final, Literal, Protocol, Self, cast

from ida_re_mcp.supervisor.errors import SupervisorError
from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.ipc import IpcEndpoint, JsonObject, JsonValue, WorkerClient

type WorkerKind = Literal["bootstrap", "analysis", "mutation", "debug", "expert"]
type WorkerProcessErrorCode = Literal["worker_crashed", "worker_timeout"]

_AUTH_ENV_PREFIX: Final = "IDA_RE_MCP_WORKER_AUTH_"
_CONNECT_RETRY_SECONDS: Final = 0.025
_DEFAULT_OPERATION_TIMEOUT_SECONDS: Final = 30.0
_GRACEFUL_CLOSE_SECONDS: Final = 2.0
_TERMINATE_SECONDS: Final = 1.0
_KILL_SECONDS: Final = 1.0
_TRANSPORT_ERROR_CODES: Final = frozenset(
    {
        "ipc_disconnected",
        "ipc_not_connected",
        "ipc_protocol_error",
    }
)


class WorkerProcessError(SupervisorError):
    """worker 进程超时或失联后的稳定 Supervisor 错误。"""

    def __init__(
        self,
        code: WorkerProcessErrorCode,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"code": self.code, "message": str(self)}
        if self.details:
            result["details"] = self.details
        return result


class WorkerClientLike(Protocol):
    def connect(self) -> None: ...

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        request_id: str | None = None,
    ) -> JsonObject: ...

    def cancel(self, request_id: str) -> None: ...

    def close(self) -> None: ...


class ProcessHandle(Protocol):
    @property
    def pid(self) -> int: ...

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ProcessLaunch:
    command: tuple[str, ...]
    environment: Mapping[str, str]
    working_directory: Path
    creation_flags: int


class ProcessLauncher(Protocol):
    def __call__(
        self,
        launch: ProcessLaunch,
        *,
        stdout: BinaryIO,
        stderr: BinaryIO,
    ) -> ProcessHandle: ...


@dataclass(frozen=True, slots=True)
class _WorkerInputs:
    kind: WorkerKind
    checkout: Path | None
    sample: Path | None
    revision: str | None
    allow_attach: bool


@dataclass(frozen=True, slots=True)
class _ExecutionOutcome:
    result: JsonObject | None = None
    error: BaseException | None = None


def _default_process_launcher(
    launch: ProcessLaunch,
    *,
    stdout: BinaryIO,
    stderr: BinaryIO,
) -> ProcessHandle:
    process = subprocess.Popen(
        list(launch.command),
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        cwd=launch.working_directory,
        env=dict(launch.environment),
        creationflags=launch.creation_flags,
        close_fds=True,
    )
    return cast(ProcessHandle, process)


def _default_endpoint_factory(directory: Path) -> IpcEndpoint:
    return IpcEndpoint.create(directory=directory)


def _default_client_factory(endpoint: IpcEndpoint) -> WorkerClientLike:
    return WorkerClient(endpoint)


def _find_working_tree(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
    except ValueError:
        return False
    return True


def _prepare_log_root(log_root: Path, working_tree: Path | None) -> Path:
    root = log_root.resolve()
    tree = (
        working_tree.resolve()
        if working_tree is not None
        else (_find_working_tree(Path.cwd().resolve()) or _find_working_tree(root))
    )
    if tree is not None and _is_within(root, tree):
        raise ValueError(f"worker 日志目录不得位于工作树内: {root}")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _open_private_log(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    return os.fdopen(descriptor, "wb", buffering=0)


def _safe_client_close(client: WorkerClientLike) -> None:
    try:
        client.close()
    except Exception:
        pass


def _resolve_inputs(
    *,
    kind: WorkerKind,
    checkout: Path | None,
    sample: Path | None,
    revision: str | None,
    allow_attach: bool,
) -> _WorkerInputs:
    resolved_checkout = checkout.resolve(strict=True) if checkout is not None else None
    resolved_sample = sample.resolve(strict=True) if sample is not None else None
    if resolved_checkout is not None and not resolved_checkout.is_file():
        raise ValueError(f"checkout 必须是普通文件: {resolved_checkout}")
    if resolved_sample is not None and not resolved_sample.is_file():
        raise ValueError(f"sample 必须是普通文件: {resolved_sample}")
    if revision == "":
        raise ValueError("revision 不能为空")

    if kind == "bootstrap":
        if resolved_sample is None or resolved_checkout is not None:
            raise ValueError("bootstrap worker 只接受必需的 sample")
        if revision is not None or allow_attach:
            raise ValueError("bootstrap worker 不接受 revision 或 allow_attach")
    elif kind == "analysis":
        if resolved_checkout is None or resolved_sample is not None:
            raise ValueError("analysis worker 只接受必需的 checkout")
        if allow_attach:
            raise ValueError("analysis worker 不接受 allow_attach")
    elif kind in {"mutation", "expert"}:
        if resolved_checkout is None or resolved_sample is not None:
            raise ValueError(f"{kind} worker 只接受必需的 checkout")
        if revision is not None or allow_attach:
            raise ValueError(f"{kind} worker 不接受 revision 或 allow_attach")
    elif kind == "debug":
        if resolved_checkout is None or resolved_sample is None:
            raise ValueError("debug worker 必须同时指定 checkout 与 sample")
        if revision is not None:
            raise ValueError("debug worker 不接受 revision")
    else:
        raise AssertionError(kind)

    return _WorkerInputs(
        kind=kind,
        checkout=resolved_checkout,
        sample=resolved_sample,
        revision=revision,
        allow_attach=allow_attach,
    )


def _build_command(
    inputs: _WorkerInputs,
    endpoint: IpcEndpoint,
    auth_environment_name: str,
) -> tuple[str, ...]:
    command = [
        sys.executable,
        "-m",
        "ida_re_mcp.worker",
        "serve",
        "--kind",
        inputs.kind,
        "--family",
        endpoint.family,
        "--address",
        endpoint.address,
        "--authkey-env",
        auth_environment_name,
    ]
    if inputs.checkout is not None:
        command.extend(("--checkout", str(inputs.checkout)))
    if inputs.revision is not None:
        command.extend(("--revision", inputs.revision))
    if inputs.sample is not None:
        command.extend(("--sample", str(inputs.sample)))
    if inputs.allow_attach:
        command.append("--allow-attach")
    return tuple(command)


class WorkerProcess:
    """一个私有 checkout 对应的同步、经过认证的 worker 进程。"""

    def __init__(
        self,
        *,
        inputs: _WorkerInputs,
        process: ProcessHandle,
        client: WorkerClientLike,
        stdout_log_path: Path,
        stderr_log_path: Path,
        stdout_log: BinaryIO,
        stderr_log: BinaryIO,
    ) -> None:
        self._inputs = inputs
        self._process = process
        self._client = client
        self._stdout_log = stdout_log
        self._stderr_log = stderr_log
        self._execute_lock = threading.Lock()
        self._closed = False
        self.stdout_log_path = stdout_log_path
        self.stderr_log_path = stderr_log_path

    @classmethod
    def launch(
        cls,
        *,
        kind: WorkerKind,
        log_root: Path,
        checkout: Path | None = None,
        sample: Path | None = None,
        revision: str | None = None,
        allow_attach: bool = False,
        connect_timeout_seconds: float = 10.0,
        working_tree: Path | None = None,
        environment: Mapping[str, str] | None = None,
        process_launcher: ProcessLauncher = _default_process_launcher,
        endpoint_factory: Callable[[Path], IpcEndpoint] = _default_endpoint_factory,
        client_factory: Callable[[IpcEndpoint], WorkerClientLike] = _default_client_factory,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> Self:
        """启动进程并在有限重试内建立认证 IPC。"""

        if not math.isfinite(connect_timeout_seconds) or connect_timeout_seconds <= 0:
            raise ValueError("connect_timeout_seconds 必须大于 0")
        inputs = _resolve_inputs(
            kind=kind,
            checkout=checkout,
            sample=sample,
            revision=revision,
            allow_attach=allow_attach,
        )
        resolved_log_root = _prepare_log_root(log_root, working_tree)
        endpoint_root = resolved_log_root / "ipc"
        endpoint_root.mkdir(mode=0o700, exist_ok=True)
        endpoint = endpoint_factory(endpoint_root)
        try:
            client = client_factory(endpoint)
        except Exception as exc:
            raise WorkerProcessError(
                "worker_crashed",
                "无法创建 worker IPC 客户端",
                details={"kind": kind, "reason": type(exc).__name__},
            ) from exc

        identifier = uuid.uuid4().hex
        stdout_log_path = resolved_log_root / f"worker-{kind}-{identifier}.stdout.log"
        stderr_log_path = resolved_log_root / f"worker-{kind}-{identifier}.stderr.log"
        try:
            stdout_log = _open_private_log(stdout_log_path)
        except BaseException:
            _safe_client_close(client)
            raise
        try:
            stderr_log = _open_private_log(stderr_log_path)
        except BaseException:
            _safe_client_close(client)
            stdout_log.close()
            raise

        auth_environment_name = f"{_AUTH_ENV_PREFIX}{secrets.token_hex(16).upper()}"
        worker_environment = os.environ.copy()
        worker_environment.update(environment or {})
        worker_environment[auth_environment_name] = base64.b64encode(endpoint.authkey).decode(
            "ascii"
        )
        command = _build_command(inputs, endpoint, auth_environment_name)
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        launch = ProcessLaunch(
            command=command,
            environment=worker_environment,
            working_directory=resolved_log_root,
            creation_flags=creation_flags,
        )
        try:
            process = process_launcher(launch, stdout=stdout_log, stderr=stderr_log)
        except BaseException as exc:
            _safe_client_close(client)
            stdout_log.close()
            stderr_log.close()
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise WorkerProcessError(
                "worker_crashed",
                "worker 进程启动失败",
                details={"kind": kind, "reason": type(exc).__name__},
            ) from exc
        finally:
            worker_environment.pop(auth_environment_name, None)

        worker = cls(
            inputs=inputs,
            process=process,
            client=client,
            stdout_log_path=stdout_log_path,
            stderr_log_path=stderr_log_path,
            stdout_log=stdout_log,
            stderr_log=stderr_log,
        )
        try:
            worker._connect(
                timeout_seconds=connect_timeout_seconds,
                monotonic=monotonic,
                sleeper=sleeper,
            )
        except BaseException:
            worker._abort()
            raise
        return worker

    @property
    def kind(self) -> WorkerKind:
        return self._inputs.kind

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def closed(self) -> bool:
        return self._closed

    def _connect(
        self,
        *,
        timeout_seconds: float,
        monotonic: Callable[[], float],
        sleeper: Callable[[float], None],
    ) -> None:
        deadline = monotonic() + timeout_seconds
        last_error: Exception | None = None
        while True:
            exit_code = self._process.poll()
            if exit_code is not None:
                raise WorkerProcessError(
                    "worker_crashed",
                    "worker 在 IPC 连接建立前退出",
                    details={
                        **self._diagnostic_details(),
                        "exit_code": exit_code,
                    },
                )
            try:
                self._client.connect()
                return
            except Exception as exc:
                last_error = exc
                _safe_client_close(self._client)
            remaining = deadline - monotonic()
            if remaining <= 0:
                details: dict[str, object] = {
                    **self._diagnostic_details(),
                    "timeout_seconds": timeout_seconds,
                }
                details["reason"] = type(last_error).__name__
                raise WorkerProcessError(
                    "worker_timeout",
                    "worker IPC 连接超时",
                    details=details,
                )
            sleeper(min(_CONNECT_RETRY_SECONDS, remaining))

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float = _DEFAULT_OPERATION_TIMEOUT_SECONDS,
        request_id: str | None = None,
    ) -> JsonObject:
        """在 daemon 调用线程中执行同步 IPC; 并以进程终止处理超时。"""

        if not operation:
            raise ValueError("operation 不能为空")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds 必须大于 0")
        if request_id == "":
            raise ValueError("request_id 不能为空")
        with self._execute_lock:
            if self._closed:
                raise WorkerProcessError(
                    "worker_crashed",
                    "worker 已关闭",
                    details=self._diagnostic_details(),
                )
            exit_code = self._process.poll()
            if exit_code is not None:
                self._abort()
                raise WorkerProcessError(
                    "worker_crashed",
                    "worker 已意外退出",
                    details={
                        **self._diagnostic_details(),
                        "exit_code": exit_code,
                    },
                )

            outcomes: Queue[_ExecutionOutcome] = Queue(maxsize=1)

            def call_worker() -> None:
                try:
                    result = self._client.execute(
                        operation,
                        input,
                        request_id=request_id,
                    )
                    outcomes.put(_ExecutionOutcome(result=result))
                except BaseException as exc:
                    outcomes.put(_ExecutionOutcome(error=exc))

            thread = threading.Thread(
                target=call_worker,
                name=f"ida-re-{self.kind}-call",
                daemon=True,
            )
            thread.start()
            thread.join(timeout_seconds)
            if thread.is_alive():
                self._abort()
                thread.join(timeout=_TERMINATE_SECONDS)
                raise WorkerProcessError(
                    "worker_timeout",
                    "worker 操作超时并已终止",
                    details={
                        **self._diagnostic_details(),
                        "operation": operation,
                        "timeout_seconds": timeout_seconds,
                    },
                )
            try:
                outcome = outcomes.get_nowait()
            except Empty as exc:
                self._abort()
                raise WorkerProcessError(
                    "worker_crashed",
                    "worker 调用线程未返回结果",
                    details={
                        **self._diagnostic_details(),
                        "operation": operation,
                    },
                ) from exc
            if outcome.error is None:
                if outcome.result is None:
                    self._abort()
                    raise WorkerProcessError("worker_crashed", "worker 返回了空结果")
                return outcome.result
            self._raise_execution_error(outcome.error, operation)
            raise AssertionError("unreachable")

    def cancel(self, request_id: str) -> None:
        """向活动命令转发取消标志, 不终止持久 DebugWorker 或目标进程。"""

        if not request_id:
            raise ValueError("request_id 不能为空")
        if self._closed:
            return
        self._client.cancel(request_id)

    def abort(self) -> None:
        """立即切断 IPC 并终止一次性 worker, 用于不可中断调用的取消。"""

        self._abort()

    def _raise_execution_error(self, error: BaseException, operation: str) -> None:
        exit_code = self._process.poll()
        transport_failed = isinstance(error, WorkerError) and error.code in _TRANSPORT_ERROR_CODES
        if exit_code is not None or transport_failed or isinstance(error, (EOFError, OSError)):
            self._abort()
            details: dict[str, object] = {
                **self._diagnostic_details(),
                "operation": operation,
                "reason": type(error).__name__,
            }
            if exit_code is not None:
                details["exit_code"] = exit_code
            raise WorkerProcessError(
                "worker_crashed",
                "worker 进程崩溃或 IPC 失联",
                details=details,
            ) from error
        if isinstance(error, WorkerError):
            raise error
        self._abort()
        raise WorkerProcessError(
            "worker_crashed",
            "worker 客户端发生未预期错误",
            details={
                **self._diagnostic_details(),
                "operation": operation,
                "reason": type(error).__name__,
            },
        ) from error

    def close(self) -> None:
        """先关闭 IPC 形成正常 EOF; 再逐级 terminate/kill。"""

        with self._execute_lock:
            if self._closed:
                return
            self._closed = True
            _safe_client_close(self._client)
            try:
                self._process.wait(timeout=_GRACEFUL_CLOSE_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                self._terminate_then_kill()
            finally:
                self._close_logs()

    def _abort(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _safe_client_close(self._client)
        finally:
            self._terminate_then_kill()
            self._close_logs()

    def _terminate_then_kill(self) -> None:
        if self._process.poll() is not None:
            return
        try:
            self._process.terminate()
        except OSError:
            pass
        try:
            self._process.wait(timeout=_TERMINATE_SECONDS)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        if self._process.poll() is None:
            try:
                self._process.kill()
            except OSError:
                pass
        try:
            self._process.wait(timeout=_KILL_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _close_logs(self) -> None:
        for stream in (self._stdout_log, self._stderr_log):
            if not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass

    def _diagnostic_details(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "stdout_log": str(self.stdout_log_path),
            "stderr_log": str(self.stderr_log_path),
        }

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()
