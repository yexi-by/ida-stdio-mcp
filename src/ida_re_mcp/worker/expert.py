# pyright: reportAny=false, reportAttributeAccessIssue=false, reportUnknownMemberType=false
"""在 disposable staging IDB 中执行开放世界 IDAPython。"""

from __future__ import annotations

import ast
import contextlib
import hashlib
from collections.abc import Mapping
from pathlib import Path
from types import CodeType
from typing import Final, cast

from ida_re_mcp.worker._ida import IdaModules, OwnerThreadBound, require_ida
from ida_re_mcp.worker.errors import WorkerError, WorkerInputError

_INPUT_KEYS: Final = frozenset({"staging_path", "code"})
_OUTPUT_LIMIT_BYTES: Final = 64 * 1024
_FILENAME: Final = "<expert.execute>"


def _as_nonempty_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkerInputError(f"{label} 必须是非空字符串")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _OutputBudget:
    """在 stdout 与 stderr 之间共享严格的 UTF-8 字节预算。"""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used = 0

    def consume(self, size: int) -> None:
        if size > self._limit - self._used:
            raise WorkerError(
                "expert_output_too_large",
                "Expert stdout 与 stderr 的 UTF-8 总量超过 64 KiB",
                details={"limit_bytes": self._limit},
            )
        self._used += size


class _BoundedTextCapture:
    """只接受文本写入并同时执行单流与共享预算校验。"""

    def __init__(self, budget: _OutputBudget, *, stream_name: str) -> None:
        self._budget = budget
        self._stream_name = stream_name
        self._parts: list[str] = []
        self._used = 0

    def write(self, value: str) -> int:
        encoded_size = len(value.encode("utf-8"))
        if encoded_size > _OUTPUT_LIMIT_BYTES - self._used:
            raise WorkerError(
                "expert_output_too_large",
                f"Expert {self._stream_name} 的 UTF-8 输出超过 64 KiB",
                details={
                    "stream": self._stream_name,
                    "limit_bytes": _OUTPUT_LIMIT_BYTES,
                },
            )
        self._budget.consume(encoded_size)
        self._used += encoded_size
        self._parts.append(value)
        return len(value)

    def flush(self) -> None:
        return

    def getvalue(self) -> str:
        return "".join(self._parts)


def _compile_inline(code: str) -> tuple[CodeType, CodeType | None]:
    """编译语句, 并把最后一个表达式作为可展示结果。"""

    module = ast.parse(code, filename=_FILENAME, mode="exec")
    if module.body and isinstance(module.body[-1], ast.Expr):
        final_expression = cast(ast.Expr, module.body.pop())
        ast.fix_missing_locations(module)
        expression = ast.Expression(final_expression.value)
        ast.fix_missing_locations(expression)
        return (
            compile(module, _FILENAME, "exec", dont_inherit=True),
            compile(expression, _FILENAME, "eval", dont_inherit=True),
        )
    return compile(module, _FILENAME, "exec", dont_inherit=True), None


class ExpertWorker(OwnerThreadBound):
    """执行不声称文件、网络或子进程隔离的 Expert 代码。"""

    def __init__(self) -> None:
        super().__init__()
        self._api: IdaModules | None = None

    def execute(
        self,
        operation: str,
        input: Mapping[str, object],
    ) -> dict[str, object]:
        """成功执行后保存 staging; 任何失败都不由本 worker 保存。"""

        self._assert_owner_thread()
        if operation != "expert.execute":
            raise WorkerInputError("expert worker 只接受 expert.execute")
        input_keys = frozenset(input)
        if input_keys != _INPUT_KEYS:
            raise WorkerInputError(
                "expert.execute input 字段集合不匹配",
                details={
                    "unknown": sorted(input_keys - _INPUT_KEYS),
                    "missing": sorted(_INPUT_KEYS - input_keys),
                },
            )

        staging_path = Path(_as_nonempty_text(input.get("staging_path"), "staging_path")).resolve(
            strict=True
        )
        code = _as_nonempty_text(input.get("code"), "code")
        api = self._require_runtime(staging_path)
        if not api.ida_auto.auto_wait():
            raise WorkerError("cancelled", "IDA autoanalysis 在 Expert 执行前被取消")

        try:
            statements, final_expression = _compile_inline(code)
        except (SyntaxError, ValueError, TypeError) as exc:
            raise WorkerError(
                "expert_compile_failed",
                "Expert IDAPython 无法编译",
                details={"exception_type": type(exc).__name__},
            ) from exc

        budget = _OutputBudget(_OUTPUT_LIMIT_BYTES)
        stdout = _BoundedTextCapture(budget, stream_name="stdout")
        stderr = _BoundedTextCapture(budget, stream_name="stderr")
        namespace: dict[str, object] = {
            "__name__": "__ida_re_expert__",
            "__package__": None,
        }
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exec(statements, namespace, namespace)
                result = (
                    eval(final_expression, namespace, namespace)
                    if final_expression is not None
                    else None
                )
                result_repr = repr(result)
                stdout_value = stdout.getvalue()
                stderr_value = stderr.getvalue()
        except WorkerError:
            raise
        except BaseException as exc:
            raise WorkerError(
                "expert_execution_failed",
                "Expert IDAPython 执行失败",
                details={"exception_type": type(exc).__name__},
            ) from exc

        stdout_size = len(stdout_value.encode("utf-8"))
        stderr_size = len(stderr_value.encode("utf-8"))
        if (
            stdout_size > _OUTPUT_LIMIT_BYTES
            or stderr_size > _OUTPUT_LIMIT_BYTES
            or stdout_size + stderr_size > _OUTPUT_LIMIT_BYTES
        ):
            raise WorkerError(
                "expert_output_too_large",
                "Expert 捕获输出超过严格的 64 KiB 限制",
                details={"limit_bytes": _OUTPUT_LIMIT_BYTES},
            )
        result_size = len(result_repr.encode("utf-8"))
        if result_size > _OUTPUT_LIMIT_BYTES:
            raise WorkerError(
                "expert_result_too_large",
                "Expert result_repr 的 UTF-8 输出超过 64 KiB",
                details={"limit_bytes": _OUTPUT_LIMIT_BYTES},
            )
        if not api.ida_auto.auto_wait():
            raise WorkerError("cancelled", "IDA autoanalysis 在 Expert 保存前被取消")
        self._assert_current_database(api, staging_path)
        if not api.ida_loader.save_database(str(staging_path), api.ida_loader.DBFL_COMP):
            raise WorkerError(
                "expert_save_failed",
                "IDA 无法保存 Expert staging 数据库; staging 必须丢弃",
            )
        return {
            "staging_path": str(staging_path),
            "staging_sha256": _file_sha256(staging_path),
            "saved": True,
            "stdout": stdout_value,
            "stderr": stderr_value,
            "result_repr": result_repr,
            "cold_verification_required": True,
        }

    def _require_runtime(self, staging_path: Path) -> IdaModules:
        if self._api is None:
            self._api = require_ida("ida_auto", "ida_loader")
        self._assert_current_database(self._api, staging_path)
        return self._api

    @staticmethod
    def _assert_current_database(api: IdaModules, staging_path: Path) -> None:
        current = Path(api.ida_loader.get_path(api.ida_loader.PATH_TYPE_IDB)).resolve(strict=False)
        if current != staging_path:
            raise WorkerError(
                "staging_mismatch",
                "IDA 当前数据库不是指定 Expert staging",
                details={"expected": str(staging_path), "actual": str(current)},
            )
