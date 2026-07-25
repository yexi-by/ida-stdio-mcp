"""IDA 自托管 E2E 的环境夹具。"""

from __future__ import annotations

import hashlib
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest


def _fixture_source_root() -> Path:
    return Path(__file__).parents[1] / "fixtures"


def _tree_identity(root: Path) -> dict[str, str]:
    identity: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        identity[path.relative_to(root).as_posix()] = digest.hexdigest()
    return identity


@pytest.fixture(autouse=True)
def preserve_committed_fixture_tree() -> Iterator[None]:
    """每个 IDA E2E 前后都校验仓库内 fixture 的文件集合与内容。"""

    source_root = _fixture_source_root()
    before = _tree_identity(source_root)
    yield
    assert _tree_identity(source_root) == before


@pytest.fixture
def ida_environment() -> dict[str, str]:
    """要求调用方明确提供受许可 IDA 安装目录, 不以 skip 冒充通过。"""

    install_dir = os.environ.get("IDADIR")
    if install_dir is None:
        pytest.fail("IDA E2E 要求设置 IDADIR")
    path = Path(install_dir).resolve(strict=True)
    if not (path / "idalib.dll").is_file():
        pytest.fail("IDADIR 不包含 IDA 9.3 idalib.dll")
    environment = os.environ.copy()
    environment["IDADIR"] = str(path)
    return environment


@pytest.fixture
def fixture_directory(tmp_path: Path) -> Path:
    """为当前测试复制私有 fixture 树; 禁止 IDA 直接打开仓库输入。"""

    private_root = tmp_path / "fixtures"
    shutil.copytree(_fixture_source_root(), private_root)
    return private_root / "bin"
