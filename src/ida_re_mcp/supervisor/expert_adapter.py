"""ExpertWorker 结果的严格 Supervisor 适配边界。"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError

from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.tools import Sha256

_OUTPUT_LIMIT_BYTES = 64 * 1024


class ExpertAdapterError(RuntimeError):
    """ExpertWorker 返回了无法发布的结果。"""


class ExpertWorkerResult(StrictModel):
    staging_path: str = Field(min_length=1, max_length=32_767)
    staging_sha256: Sha256
    saved: Literal[True]
    stdout: str
    stderr: str
    result_repr: str | None
    cold_verification_required: Literal[True]


def adapt_expert_worker_result(
    raw_result: Mapping[str, object],
    staging_path: Path,
) -> ExpertWorkerResult:
    """验证 staging 身份及三个可公开文本字段的 UTF-8 字节上限。"""

    try:
        result = ExpertWorkerResult.model_validate(raw_result, strict=True)
    except ValidationError as exc:
        raise ExpertAdapterError("ExpertWorker 结果不符合严格契约") from exc
    expected = str(staging_path.resolve(strict=False))
    if result.staging_path != expected:
        raise ExpertAdapterError("ExpertWorker 返回的 staging_path 不匹配")
    stdout_size = len(result.stdout.encode())
    stderr_size = len(result.stderr.encode())
    if (
        stdout_size > _OUTPUT_LIMIT_BYTES
        or stderr_size > _OUTPUT_LIMIT_BYTES
        or stdout_size + stderr_size > _OUTPUT_LIMIT_BYTES
    ):
        raise ExpertAdapterError("ExpertWorker 捕获输出超过 64 KiB")
    if result.result_repr is not None and len(result.result_repr.encode()) > _OUTPUT_LIMIT_BYTES:
        raise ExpertAdapterError("ExpertWorker result_repr 超过 64 KiB")
    return result
