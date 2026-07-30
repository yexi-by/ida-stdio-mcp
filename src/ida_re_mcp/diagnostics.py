"""把只供排错使用的异常详情写入当前会话日志。"""

from __future__ import annotations

import os
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

_SERVICE_ERROR_LOG: Final = "service-errors.log"
_MAX_DETAIL_CHARS: Final = 262_144


def write_exception_log(
    log_root: Path | None,
    *,
    context: str,
    error: BaseException,
    details: object | None = None,
) -> Path | None:
    """记录完整异常；写日志本身失败时不掩盖原来的错误。"""

    if log_root is None:
        return None
    try:
        root = log_root.resolve()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = root / _SERVICE_ERROR_LOG
        timestamp = datetime.now(UTC).isoformat()
        detail = "".join(traceback.format_exception(error))
        extra = ""
        if details is not None:
            extra = f"内部详情：{details!r}"[:_MAX_DETAIL_CHARS] + "\n"
        payload = f"[{timestamp}] {context}\n{extra}{detail}\n".encode(
            "utf-8",
            errors="replace",
        )
        descriptor = os.open(
            path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "ab", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
        finally:
            os.close(descriptor)
    except OSError:
        return None
    return path
