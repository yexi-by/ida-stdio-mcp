"""目录扫描、候选识别与批量分析辅助逻辑。"""

from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path

from .models import BinaryKind, CandidateFile

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
}


def detect_binary_kind(path: Path) -> BinaryKind:
    """根据文件头和扩展名识别候选二进制类型。"""
    try:
        header = path.read_bytes()[:4]
    except OSError:
        return "unknown"

    if header.startswith(b"MZ"):
        return "pe"
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header in MACHO_MAGICS:
        return "macho"

    suffix = path.suffix.lower()
    if suffix in {".exe", ".dll", ".sys"}:
        return "pe"
    if suffix in {".elf", ".so"}:
        return "elf"
    if suffix in {".dylib"}:
        return "macho"
    return "unknown"


def _score_candidate(path: Path, binary_kind: BinaryKind, size: int) -> tuple[int, tuple[str, ...]]:
    """给候选文件打分，便于 triage 排序。"""
    score = 0
    reasons: list[str] = []
    name = path.name.lower()

    if binary_kind != "unknown":
        score += 50
        reasons.append(f"识别为 {binary_kind}")
    if path.suffix.lower() in {".exe", ".elf"}:
        score += 20
        reasons.append("主可执行扩展名")
    if path.suffix.lower() in {".dll", ".so", ".dylib"}:
        score -= 10
        reasons.append("更像共享库")
    if 4_096 <= size <= 20_000_000:
        score += 10
        reasons.append("大小处于可分析区间")
    if any(keyword in name for keyword in ("main", "app", "server", "client", "loader", "crackme")):
        score += 15
        reasons.append("文件名包含高价值关键词")
    return score, tuple(reasons)


def iter_candidate_files(
    root: Path,
    *,
    recursive: bool,
    include_extensions: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
) -> list[CandidateFile]:
    """扫描目录并返回去重后的候选文件。"""
    iterator = root.rglob("*") if recursive else root.glob("*")
    seen_hashes: set[str] = set()
    results: list[CandidateFile] = []

    for path in iterator:
        if not path.is_file():
            continue
        if any(fnmatch.fnmatch(path.name, pattern) for pattern in exclude_patterns):
            continue
        if include_extensions and path.suffix.lower() not in include_extensions:
            continue

        binary_kind = detect_binary_kind(path)
        if binary_kind == "unknown":
            continue

        content = path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        if sha256 in seen_hashes:
            continue
        seen_hashes.add(sha256)
        score, reasons = _score_candidate(path, binary_kind, len(content))
        results.append(
            CandidateFile(
                path=path,
                binary_kind=binary_kind,
                score=score,
                size=len(content),
                sha256=sha256,
                reasons=reasons,
            )
        )

    return sorted(results, key=lambda item: item.score, reverse=True)
