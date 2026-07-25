# pyright: reportAny=false, reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""在 disposable staging IDB 上执行可验证的增量分析。"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from ida_re_mcp.worker._ida import IdaModules, OwnerThreadBound, require_ida
from ida_re_mcp.worker.errors import CapabilityError, WorkerError, WorkerInputError

type RefineAction = Literal[
    "autoanalysis",
    "reanalyze_function",
    "rebuild_xrefs",
    "decompile",
]

_CANONICAL_HEX: Final = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_ACTION_ORDER: Final[tuple[RefineAction, ...]] = (
    "autoanalysis",
    "rebuild_xrefs",
    "reanalyze_function",
    "decompile",
)
_INPUT_KEYS: Final = frozenset({"staging_path", "targets", "actions"})


@dataclass(frozen=True, slots=True)
class _Target:
    ea: int
    function_entry: int | None


@dataclass(frozen=True, slots=True)
class _FunctionRange:
    entry: int
    chunks: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class _PreparedRefine:
    staging_path: Path
    actions: tuple[RefineAction, ...]
    targets: tuple[_Target, ...]
    functions: tuple[_FunctionRange, ...]


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _as_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise WorkerInputError(f"{label} 必须是字符串键对象")
    return cast(Mapping[str, object], value)


def _as_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkerInputError(f"{label} 必须是非空字符串")
    return value


def _canonical_address(value: object, label: str) -> int:
    text = _as_text(value, label)
    if _CANONICAL_HEX.fullmatch(text) is None:
        raise WorkerInputError(f"{label} 必须是规范小写十六进制")
    return int(text, 16)


class RefineWorker(OwnerThreadBound):
    """只在当前 mutation worker 打开的 staging 数据库中执行增量分析。"""

    def __init__(self) -> None:
        super().__init__()
        self._api: IdaModules | None = None

    def execute(
        self,
        operation: str,
        input: Mapping[str, object],
    ) -> dict[str, object]:
        """执行严格的 ``analysis.refine`` worker 操作并保存 staging。"""

        self._assert_owner_thread()
        if operation != "analysis.refine":
            raise WorkerInputError("refine worker 只接受 analysis.refine")
        input_keys = frozenset(input)
        if input_keys != _INPUT_KEYS:
            raise WorkerInputError(
                "analysis.refine input 字段集合不匹配",
                details={
                    "unknown": sorted(input_keys - _INPUT_KEYS),
                    "missing": sorted(_INPUT_KEYS - input_keys),
                },
            )

        staging_path = Path(_as_text(input.get("staging_path"), "staging_path")).resolve(
            strict=True
        )
        api = self._require_runtime(staging_path)
        if not api.ida_auto.auto_wait():
            raise WorkerError("cancelled", "IDA autoanalysis 在 refine 预检前被取消")
        prepared = self._preflight(api, staging_path, input)
        change_count_before = int(api.ida_ida.inf_get_database_change_count())
        action_results = self._apply(api, prepared)
        if not api.ida_auto.auto_wait():
            raise WorkerError("cancelled", "IDA autoanalysis 在 refine 保存前被取消")
        change_count_after = int(api.ida_ida.inf_get_database_change_count())
        if not api.ida_loader.save_database(str(staging_path), api.ida_loader.DBFL_COMP):
            raise WorkerError(
                "refine_save_failed",
                "IDA 无法保存 refine staging 数据库; staging 必须丢弃",
            )
        return {
            "staging_path": str(staging_path),
            "staging_sha256": _file_sha256(staging_path),
            "actions": action_results,
            "database_change_count_before": change_count_before,
            "database_change_count_after": change_count_after,
            "cold_verification_required": True,
            "saved": True,
        }

    def _require_runtime(self, staging_path: Path) -> IdaModules:
        if self._api is None:
            self._api = require_ida(
                "ida_auto",
                "ida_bytes",
                "ida_funcs",
                "ida_hexrays",
                "ida_ida",
                "ida_idaapi",
                "ida_loader",
                "ida_nalt",
                "ida_segment",
                "idautils",
            )
        current = Path(self._api.ida_loader.get_path(self._api.ida_loader.PATH_TYPE_IDB)).resolve(
            strict=False
        )
        if current != staging_path:
            raise WorkerError(
                "staging_mismatch",
                "IDA 当前数据库不是指定 refine staging",
                details={"expected": str(staging_path), "actual": str(current)},
            )
        return self._api

    def _preflight(
        self,
        api: IdaModules,
        staging_path: Path,
        input: Mapping[str, object],
    ) -> _PreparedRefine:
        actions = self._parse_actions(input.get("actions"))
        targets = self._parse_targets(api, input.get("targets"))
        targeted_actions = set(actions) - {"autoanalysis"}
        if targeted_actions and not targets:
            raise WorkerInputError(
                "reanalyze_function、rebuild_xrefs 与 decompile 至少需要一个 target"
            )

        function_entries = {
            target.function_entry for target in targets if target.function_entry is not None
        }
        if targeted_actions and any(target.function_entry is None for target in targets):
            missing = [_hex(target.ea) for target in targets if target.function_entry is None]
            raise WorkerError(
                "unsupported",
                "目标不属于已识别函数, 无法执行函数级 refine",
                details={"addresses": missing, "actions": sorted(targeted_actions)},
            )

        functions = tuple(self._function_range(api, entry) for entry in sorted(function_entries))
        if "decompile" in actions and not api.ida_hexrays.init_hexrays_plugin():
            raise CapabilityError(
                "当前 IDA 许可证或架构没有可用 Hex-Rays decompiler",
                capability="hexrays",
            )
        return _PreparedRefine(staging_path, actions, targets, functions)

    def _parse_actions(self, raw: object) -> tuple[RefineAction, ...]:
        if not isinstance(raw, list) or not raw or len(raw) > len(_ACTION_ORDER):
            raise WorkerInputError("actions 必须是 1 到 4 个动作组成的数组")
        candidates = cast(list[object], raw)
        if any(not isinstance(item, str) or item not in _ACTION_ORDER for item in candidates):
            raise WorkerInputError("actions 包含未知动作")
        text_actions = cast(list[str], candidates)
        if len(set(text_actions)) != len(text_actions):
            raise WorkerInputError("actions 不允许重复")
        selected = set(text_actions)
        return tuple(action for action in _ACTION_ORDER if action in selected)

    def _parse_targets(self, api: IdaModules, raw: object) -> tuple[_Target, ...]:
        if not isinstance(raw, list) or len(raw) > 256:
            raise WorkerInputError("targets 必须是不超过 256 项的数组")
        candidates = cast(list[object], raw)
        targets: list[_Target] = []
        seen: set[int] = set()
        for index, candidate in enumerate(candidates):
            ea = self._resolve_address(api, candidate, index)
            if ea in seen:
                raise WorkerInputError(
                    "targets 不允许重复地址",
                    details={"index": index, "address": _hex(ea)},
                )
            seen.add(ea)
            function = api.ida_funcs.get_func(ea)
            targets.append(
                _Target(
                    ea=ea,
                    function_entry=int(function.start_ea) if function is not None else None,
                )
            )
        return tuple(targets)

    def _resolve_address(self, api: IdaModules, value: object, index: int) -> int:
        ref = _as_mapping(value, f"targets[{index}]")
        keys = set(ref)
        space = _as_text(ref.get("space"), f"targets[{index}].space")
        if space == "database" and keys == {"space", "ea"}:
            ea = _canonical_address(ref.get("ea"), f"targets[{index}].ea")
        elif space == "image" and keys == {"space", "rva"}:
            ea = int(api.ida_nalt.get_imagebase()) + _canonical_address(
                ref.get("rva"), f"targets[{index}].rva"
            )
        else:
            raise WorkerInputError(
                "refine target 必须是严格的 database 或 image 判别联合",
                details={"index": index},
            )
        if ea == int(api.ida_idaapi.BADADDR) or api.ida_segment.getseg(ea) is None:
            raise WorkerError(
                "address_unmapped",
                "refine 地址未映射到 IDB",
                details={"index": index},
            )
        return ea

    def _function_range(self, api: IdaModules, entry: int) -> _FunctionRange:
        chunks = tuple(
            sorted(
                {
                    (int(start), int(end))
                    for start, end in api.idautils.Chunks(entry)
                    if int(end) > int(start)
                }
            )
        )
        if not chunks:
            raise WorkerError(
                "unsupported",
                "IDA 没有提供目标函数的有效 chunk 范围",
                details={"entry": _hex(entry)},
            )
        return _FunctionRange(entry=entry, chunks=chunks)

    def _apply(
        self,
        api: IdaModules,
        prepared: _PreparedRefine,
    ) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        for action in prepared.actions:
            if action == "autoanalysis":
                self._autoanalysis(api, prepared)
                function_count = len(prepared.functions)
            elif action == "rebuild_xrefs":
                self._rebuild_xrefs(api, prepared.functions)
                function_count = len(prepared.functions)
            elif action == "reanalyze_function":
                self._reanalyze_functions(api, prepared.functions)
                function_count = len(prepared.functions)
            else:
                self._decompile(api, prepared.functions)
                function_count = len(prepared.functions)
            results.append(
                {
                    "action": action,
                    "target_count": len(prepared.targets),
                    "function_count": function_count,
                }
            )
        return results

    def _autoanalysis(self, api: IdaModules, prepared: _PreparedRefine) -> None:
        if not prepared.targets:
            if not api.ida_auto.auto_wait():
                raise WorkerError("cancelled", "IDA autoanalysis 被取消")
            return
        ranges = {chunk for function in prepared.functions for chunk in function.chunks}
        function_entries = {function.entry for function in prepared.functions}
        for target in prepared.targets:
            if target.function_entry in function_entries:
                continue
            segment = api.ida_segment.getseg(target.ea)
            assert segment is not None
            item_end = int(api.ida_bytes.get_item_end(target.ea))
            end = min(max(item_end, target.ea + 1), int(segment.end_ea))
            ranges.add((target.ea, end))
        self._analyze_ranges(api, ranges, action="autoanalysis")

    def _reanalyze_functions(
        self,
        api: IdaModules,
        functions: Sequence[_FunctionRange],
    ) -> None:
        ranges = {chunk for function in functions for chunk in function.chunks}
        self._analyze_ranges(api, ranges, action="reanalyze_function")

    def _rebuild_xrefs(
        self,
        api: IdaModules,
        functions: Sequence[_FunctionRange],
    ) -> None:
        ranges = sorted({chunk for function in functions for chunk in function.chunks})
        for start, end in ranges:
            api.ida_auto.revert_ida_decisions(start, end)
        self._analyze_ranges(api, ranges, action="rebuild_xrefs")

    def _analyze_ranges(
        self,
        api: IdaModules,
        ranges: Sequence[tuple[int, int]] | set[tuple[int, int]],
        *,
        action: RefineAction,
    ) -> None:
        for start, end in sorted(ranges):
            if not api.ida_auto.plan_and_wait(start, end, True):
                raise WorkerError(
                    "refine_failed",
                    "IDA 无法完成指定范围的增量分析",
                    details={
                        "action": action,
                        "start": _hex(start),
                        "end": _hex(end),
                    },
                )

    def _decompile(
        self,
        api: IdaModules,
        functions: Sequence[_FunctionRange],
    ) -> None:
        for function in functions:
            api.ida_hexrays.mark_cfunc_dirty(function.entry, False)
            try:
                cfunc = api.ida_hexrays.decompile(function.entry)
                if cfunc is None:
                    raise RuntimeError("empty decompilation")
                tuple(cfunc.get_pseudocode())
            except Exception as exc:
                raise CapabilityError(
                    "Hex-Rays 无法反编译 refine 目标函数",
                    capability="hexrays_decompile",
                    details={
                        "entry": _hex(function.entry),
                        "reason": type(exc).__name__,
                    },
                ) from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
