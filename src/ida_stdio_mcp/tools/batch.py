"""批量目录分析工具。"""

from __future__ import annotations

from pathlib import Path

from ..config import AppConfig
from ..directory_analysis import iter_candidate_files
from ..models import JsonObject
from ..result import build_result
from ..runtime import HeadlessRuntime
from ..tool_registry import ToolRegistry, ToolSpec


def _read_string_list_argument(arguments: JsonObject, key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """读取字符串列表参数，遇到非法类型时回退到默认值。"""
    raw_value = arguments.get(key)
    if raw_value is None:
        return default
    if not isinstance(raw_value, list):
        return default
    return tuple(str(item) for item in raw_value)


def register_batch_tools(
    registry: ToolRegistry,
    runtime: HeadlessRuntime,
    config: AppConfig,
) -> None:
    """注册批处理总入口工具。"""

    def analyze_directory(arguments: JsonObject):
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str):
            return build_result(status="error", source="filesystem", data=None, error="path 必须是字符串")

        root = Path(raw_path)
        if not root.exists():
            return build_result(status="error", source="filesystem", data=None, error=f"目录不存在：{root}")
        if not root.is_dir():
            return build_result(status="error", source="filesystem", data=None, error=f"不是目录：{root}")

        recursive = bool(arguments.get("recursive", config.directory_analysis.recursive))
        max_candidates = int(arguments.get("max_candidates", config.directory_analysis.max_candidates))
        max_deep_analysis = int(arguments.get("max_deep_analysis", config.directory_analysis.max_deep_analysis))
        include_extensions = tuple(
            item.lower()
            for item in _read_string_list_argument(
                arguments,
                "include_extensions",
                config.directory_analysis.include_extensions,
            )
        )
        exclude_patterns = _read_string_list_argument(
            arguments,
            "exclude_patterns",
            config.directory_analysis.exclude_patterns,
        )

        previous = runtime.current_binary_summary()
        candidates = iter_candidate_files(
            root,
            recursive=recursive,
            include_extensions=include_extensions,
            exclude_patterns=exclude_patterns,
        )
        selected = candidates[:max_candidates]
        analyzed: list[dict[str, object]] = []
        skipped: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []

        for index, candidate in enumerate(selected):
            if index >= max_deep_analysis:
                skipped.append(
                    {
                        "path": str(candidate.path),
                        "reason": "超出 max_deep_analysis 限制",
                        "score": candidate.score,
                    }
                )
                continue

            try:
                runtime.open_binary(candidate.path)
                survey = runtime.survey_binary()
                focus_query = "main"
                focus_summary = None
                try:
                    focus_summary = runtime.decompile_function(focus_query)
                except Exception:
                    interesting = survey.get("interesting_functions")
                    if isinstance(interesting, list) and interesting:
                        first = interesting[0]
                        if isinstance(first, dict):
                            addr = first.get("addr")
                            if isinstance(addr, str):
                                focus_summary = runtime.decompile_function(addr)
                                focus_query = addr
                analyzed.append(
                    {
                        "path": str(candidate.path),
                        "binary_kind": candidate.binary_kind,
                        "score": candidate.score,
                        "reasons": list(candidate.reasons),
                        "survey": survey,
                        "focus_function": focus_query if focus_summary is not None else None,
                        "focus_summary": focus_summary,
                    }
                )
            except Exception as exc:
                errors.append({"path": str(candidate.path), "error": str(exc)})
            finally:
                runtime.close_binary()

        if previous is not None:
            try:
                runtime.open_binary(Path(previous["input_path"]))
            except Exception:
                errors.append(
                    {
                        "path": previous["input_path"],
                        "error": "批处理完成后恢复原数据库失败",
                    }
                )

        data = {
            "summary": {
                "root": str(root),
                "candidate_count": len(candidates),
                "selected_count": len(selected),
                "analyzed_count": len(analyzed),
                "skipped_count": len(skipped),
                "error_count": len(errors),
            },
            "candidates": [
                {
                    "path": str(item.path),
                    "binary_kind": item.binary_kind,
                    "score": item.score,
                    "size": item.size,
                    "reasons": list(item.reasons),
                }
                for item in candidates
            ],
            "selected": [str(item.path) for item in selected],
            "analyzed": analyzed,
            "skipped": skipped,
            "errors": errors,
        }
        status = "ok" if not errors else "degraded"
        return build_result(
            status=status,
            source="directory_analysis",
            data=data,
            warnings=["部分候选可能因分析失败被降级"] if errors else [],
        )

    common_schema: JsonObject = {
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "source": {"type": "string"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "error": {"type": ["string", "null"]},
            "data": {},
        },
        "required": ["status", "source", "warnings", "error", "data"],
    }

    registry.register(
        ToolSpec(
            "analyze_directory",
            "扫描目录、做 triage、选择高价值样本深度分析并返回汇总结果。",
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "recursive": {"type": "boolean"},
                    "max_candidates": {"type": "integer"},
                    "max_deep_analysis": {"type": "integer"},
                    "include_extensions": {"type": "array", "items": {"type": "string"}},
                    "exclude_patterns": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["path"],
            },
            common_schema,
            analyze_directory,
        )
    )
