"""公共 analysis.refine 与 mutation worker JSON 契约之间的纯适配层。"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, JsonValue, ValidationError

from ida_re_mcp.domain.address import ImageAddress
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.tools import AnalysisRefineInput, Sha256

type RefineAction = Literal[
    "autoanalysis",
    "reanalyze_function",
    "rebuild_xrefs",
    "decompile",
]

_ACTION_ORDER: Final[tuple[RefineAction, ...]] = (
    "autoanalysis",
    "rebuild_xrefs",
    "reanalyze_function",
    "decompile",
)


class RefineAdapterError(RuntimeError):
    """refine 适配层的稳定失败基类。"""


class RefineAdapterInputError(RefineAdapterError):
    """公共参数不能无损映射到 refine worker。"""


class RefineAdapterResultError(RefineAdapterError):
    """worker 结果不满足严格 refine 结果契约。"""


@dataclass(frozen=True, slots=True)
class RefineWorkerRequest:
    """可直接交给 mutation worker 的单个请求。"""

    operation: Literal["analysis.refine"]
    input: Mapping[str, JsonValue]


class RefineActionResult(StrictModel):
    """一个已由 worker 完成的真实 refine 动作。"""

    action: RefineAction
    target_count: int = Field(ge=0, le=256)
    function_count: int = Field(ge=0, le=256)


class RefineWorkerResult(StrictModel):
    """成功保存但仍需冷验证的 staging 结果。"""

    staging_path: str = Field(min_length=1)
    staging_sha256: Sha256
    actions: list[RefineActionResult] = Field(min_length=1, max_length=4)
    database_change_count_before: int = Field(ge=0)
    database_change_count_after: int = Field(ge=0)
    cold_verification_required: Literal[True]
    saved: Literal[True]


def build_refine_worker_request(
    args: AnalysisRefineInput,
    staging_path: Path,
) -> RefineWorkerRequest:
    """生成确定性的 ``analysis.refine`` worker 请求。"""

    resolved_staging = staging_path.resolve(strict=False)
    actions = _canonical_actions(args.actions)
    if set(actions) - {"autoanalysis"} and not args.targets:
        raise RefineAdapterInputError(
            "reanalyze_function、rebuild_xrefs 与 decompile 至少需要一个 target"
        )

    targets: list[JsonValue] = []
    seen_targets: set[tuple[str, str]] = set()
    for target in args.targets:
        if isinstance(target, ImageAddress):
            encoded: dict[str, JsonValue] = {
                "space": "image",
                "rva": target.rva,
            }
            key = ("image", target.rva)
        else:
            encoded = {
                "space": "database",
                "ea": target.ea,
            }
            key = ("database", target.ea)
        if key in seen_targets:
            raise RefineAdapterInputError("analysis.refine targets 不允许重复")
        seen_targets.add(key)
        targets.append(encoded)

    worker_input: dict[str, JsonValue] = {
        "staging_path": str(resolved_staging),
        "targets": targets,
        "actions": list(actions),
    }
    return RefineWorkerRequest(
        operation="analysis.refine",
        input=worker_input,
    )


def adapt_refine_worker_result(
    args: AnalysisRefineInput,
    raw_result: Mapping[str, object],
    staging_path: Path,
) -> RefineWorkerResult:
    """验证 worker 成功结果与原请求、staging 身份完全一致。"""

    request = build_refine_worker_request(args, staging_path)
    try:
        result = RefineWorkerResult.model_validate(raw_result)
    except ValidationError as exc:
        raise RefineAdapterResultError("analysis.refine worker 结果无法通过严格 schema") from exc

    expected_staging = request.input["staging_path"]
    if result.staging_path != expected_staging:
        raise RefineAdapterResultError("analysis.refine worker 返回了不匹配的 staging_path")
    expected_actions = request.input["actions"]
    actual_actions = [item.action for item in result.actions]
    if actual_actions != expected_actions:
        raise RefineAdapterResultError("analysis.refine worker 返回的动作集合或顺序不匹配")
    expected_target_count = len(args.targets)
    if any(item.target_count != expected_target_count for item in result.actions):
        raise RefineAdapterResultError("analysis.refine worker 返回的 target_count 不匹配")
    if any(item.function_count > item.target_count for item in result.actions):
        raise RefineAdapterResultError("analysis.refine worker 返回了不可能的 function_count")
    return result


def _canonical_actions(actions: list[RefineAction]) -> tuple[RefineAction, ...]:
    if len(set(actions)) != len(actions):
        raise RefineAdapterInputError("analysis.refine actions 不允许重复")
    selected = set(actions)
    return tuple(action for action in _ACTION_ORDER if action in selected)
