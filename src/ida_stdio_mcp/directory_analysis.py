"""目录扫描、候选识别与批量分析辅助逻辑。

这里不再使用“固定打分 + 扩展名猜测”的松散策略，而是显式建模目录分析策略：

- 项目形态识别：例如 Unity / Managed 目录优先级
- 候选角色识别：入口二进制、用户代码、插件/运行库
- 策略偏好：prefer_managed / prefer_native / prefer_entry_binary / prefer_user_code
- 评分档位：通过 scoring_profile 暴露给外部，而不是把策略写死在实现里
"""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .models import BinaryKind, CandidateFile

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
}

UNITY_USER_CODE_NAMES = {
    "assembly-csharp.dll",
    "assembly-csharp-firstpass.dll",
    "gameassembly.dll",
}


@dataclass(slots=True, frozen=True)
class DirectoryAnalysisPolicy:
    """目录分析策略。"""

    prefer_managed: bool
    prefer_native: bool
    prefer_entry_binary: bool
    prefer_user_code: bool
    scoring_profile: str


@dataclass(slots=True, frozen=True)
class CandidateAssessment:
    """候选评分结果。"""

    score: int
    reasons: tuple[str, ...]


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


def detect_project_profile(root: Path) -> str:
    """根据目录结构识别工程画像。"""
    lowered_paths = {str(path).lower() for path in root.rglob("*") if path.is_file()}
    if any("managed\\assembly-csharp.dll" in path or "managed/assembly-csharp.dll" in path for path in lowered_paths):
        return "unity_managed"
    if any(path.endswith("gameassembly.dll") for path in lowered_paths):
        return "unity_native"
    return "generic"


def iter_candidate_files(
    root: Path,
    *,
    recursive: bool,
    include_extensions: tuple[str, ...],
    exclude_patterns: tuple[str, ...],
    policy: DirectoryAnalysisPolicy,
) -> list[CandidateFile]:
    """扫描目录并返回去重后的候选文件。"""
    iterator = root.rglob("*") if recursive else root.glob("*")
    seen_hashes: set[str] = set()
    results: list[CandidateFile] = []
    project_profile = detect_project_profile(root)

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

        assessment = _score_candidate(
            path=path,
            binary_kind=binary_kind,
            size=len(content),
            root=root,
            project_profile=project_profile,
            policy=policy,
        )
        results.append(
            CandidateFile(
                path=path,
                binary_kind=binary_kind,
                score=assessment.score,
                size=len(content),
                sha256=sha256,
                reasons=assessment.reasons,
            )
        )

    return sorted(results, key=lambda item: (item.score, -item.size), reverse=True)


def _score_candidate(
    *,
    path: Path,
    binary_kind: BinaryKind,
    size: int,
    root: Path,
    project_profile: str,
    policy: DirectoryAnalysisPolicy,
) -> CandidateAssessment:
    """给候选文件打分。"""
    score = 0
    reasons: list[str] = []
    name = path.name.lower()
    relative = str(path.relative_to(root)).replace("\\", "/").lower()

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

    if policy.prefer_native and binary_kind in {"pe", "elf", "macho"}:
        score += 15
        reasons.append("策略偏好 native")
    if policy.prefer_managed and name.endswith(".dll"):
        score += 15
        reasons.append("策略偏好 managed")
    if policy.prefer_entry_binary and path.suffix.lower() in {".exe", ".elf"}:
        score += 20
        reasons.append("策略优先入口二进制")
    if policy.prefer_user_code and _is_user_code_candidate(name, relative):
        score += 25
        reasons.append("策略优先用户代码")

    if project_profile == "unity_managed":
        score += _score_unity_managed(name=name, relative=relative, reasons=reasons)
    elif project_profile == "unity_native":
        score += _score_unity_native(name=name, reasons=reasons)

    if policy.scoring_profile == "managed_first" and name.endswith(".dll"):
        score += 20
        reasons.append("评分档位 managed_first")
    if policy.scoring_profile == "entry_only" and path.suffix.lower() in {".exe", ".elf"}:
        score += 20
        reasons.append("评分档位 entry_only")

    return CandidateAssessment(score=score, reasons=tuple(reasons))


def _is_user_code_candidate(name: str, relative: str) -> bool:
    """判断是否更像用户代码。"""
    if name in UNITY_USER_CODE_NAMES:
        return True
    return not any(
        marker in relative
        for marker in (
            "plugins/",
            "plugins\\",
            "unityengine.",
            "microsoft.",
            "system.",
            "stub.dll",
        )
    )


def _score_unity_managed(*, name: str, relative: str, reasons: list[str]) -> int:
    """Unity Managed 项目专项打分。"""
    if name == "assembly-csharp.dll":
        reasons.append("Unity 用户主脚本程序集")
        return 120
    if name == "assembly-csharp-firstpass.dll":
        reasons.append("Unity firstpass 用户脚本程序集")
        return 90
    if name == "gameassembly.dll":
        reasons.append("Unity 原生桥接组件")
        return 70
    score = 0
    if "managed/" in relative:
        score += 10
        reasons.append("Unity Managed 目录内")
    if "unityengine." in name or name.endswith("stub.dll"):
        reasons.append("Unity 运行库/Stub，默认降低优先级")
        return score - 90
    if name.startswith("system.") or name.startswith("microsoft."):
        reasons.append(".NET 基础库，默认降低优先级")
        return score - 70
    return score


def _score_unity_native(*, name: str, reasons: list[str]) -> int:
    """Unity Native 项目专项打分。"""
    if name == "gameassembly.dll":
        reasons.append("Unity Native 主程序集")
        return 140
    if name.endswith(".dll") and "unityplayer" in name:
        reasons.append("UnityPlayer 相关组件")
        return 30
    return 0
