# pyright: reportAny=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""从 workspace 原样本建立首个 staging IDB。"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from ida_re_mcp.worker._ida import OwnerThreadBound, require_ida
from ida_re_mcp.worker.errors import WorkerError, WorkerInputError


class BootstrapWorker(OwnerThreadBound):
    """仅负责完整分析当前已打开样本并保存新的 staging IDB。"""

    def __init__(self, sample_path: Path) -> None:
        super().__init__()
        self.sample_path = sample_path.resolve(strict=True)

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        self._assert_owner_thread()
        if operation != "workspace.bootstrap":
            raise WorkerInputError("bootstrap worker 只接受 workspace.bootstrap")
        if set(input) != {"staging_path"}:
            raise WorkerInputError("bootstrap input 必须严格包含 staging_path")
        raw_staging = input.get("staging_path")
        if not isinstance(raw_staging, str) or not raw_staging:
            raise WorkerInputError("staging_path 必须是非空字符串")
        staging_path = Path(raw_staging).resolve(strict=False)
        if staging_path.exists():
            raise WorkerError("staging_exists", "bootstrap 不允许覆盖已有 staging IDB")
        if not staging_path.parent.is_dir():
            raise WorkerError("staging_parent_missing", "staging 父目录不存在")
        api = require_ida("ida_auto", "ida_loader", "ida_nalt")
        opened_input = Path(str(api.ida_nalt.get_input_file_path())).resolve(strict=True)
        if opened_input != self.sample_path:
            raise WorkerError(
                "sample_mismatch",
                "IDALib 当前打开的输入不是 workspace 原样本副本",
                details={"expected": str(self.sample_path), "actual": str(opened_input)},
            )
        api.ida_auto.auto_wait()
        if not api.ida_loader.save_database(str(staging_path), api.ida_loader.DBFL_COMP):
            raise WorkerError("bootstrap_save_failed", "IDA 无法保存首个 staging IDB")
        return {
            "staging_path": str(staging_path),
            "staging_sha256": _file_sha256(staging_path),
            "input_sha256": _file_sha256(self.sample_path),
            "cold_verification_required": True,
            "saved": True,
        }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
