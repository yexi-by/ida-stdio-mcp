"""IDAPython 脚本执行能力。"""

from __future__ import annotations

import hashlib
import json
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from time import perf_counter, time_ns
from typing import Iterable, cast

from ..models import JsonObject, JsonValue
from ..runtime_workspace import get_runtime_workspace_paths

SCRIPT_TEXT_LIMIT_DEFAULT = 120_000
SCRIPT_TEXT_LIMIT_HARD = 1_000_000
SCRIPT_ARTIFACT_AUTO_LIMIT = 64_000
SCRIPT_VALUE_ITEM_LIMIT = 80
SCRIPT_VALUE_DEPTH_LIMIT = 4
SCRIPT_LOCALS_SUMMARY_LIMIT = 48
SCRIPT_LOCALS_SAMPLE_LIMIT = 8
SCRIPT_ARTIFACT_VALUE_ITEM_LIMIT = 20_000
SCRIPT_ARTIFACT_VALUE_DEPTH_LIMIT = 12


class ScriptCoreMixin:
    """提供脚本执行、结果裁剪与局部变量摘要能力。"""

    def _json_object(self, value: object) -> JsonObject:
        """由核心类提供 JSON 对象收窄。"""
        raise NotImplementedError

    def jsonify(self, value: object) -> JsonValue:
        """由核心类提供 JSON 值转换。"""
        raise NotImplementedError

    def _clip_text(self, text: str, *, limit: int) -> tuple[str, bool]:
        """按字符数裁剪文本，并返回是否发生截断。"""
        if len(text) <= limit:
            return text, False
        return text[:limit], True

    def _tool_safe_value(self, value: object, *, max_items: int = SCRIPT_VALUE_ITEM_LIMIT, depth: int = SCRIPT_VALUE_DEPTH_LIMIT) -> JsonValue:
        """把脚本结果压缩成不会淹没 MCP 客户端的 JSON 值。"""
        if value is None or isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, str):
            clipped, truncated = self._clip_text(value, limit=SCRIPT_TEXT_LIMIT_DEFAULT)
            if truncated:
                return self._json_object({"type": "str", "text": clipped, "truncated": True, "original_length": len(value)})
            return clipped
        if depth <= 0:
            return self._json_object({"type": type(value).__name__, "repr": str(type(value))})
        if isinstance(value, list):
            list_value = cast(list[object], value)
            return self._tool_safe_sequence("list", list_value, max_items=max_items, depth=depth)
        if isinstance(value, tuple):
            tuple_value = cast(tuple[object, ...], value)
            return self._tool_safe_sequence("tuple", tuple_value, max_items=max_items, depth=depth)
        if isinstance(value, set):
            set_value = cast(set[object], value)
            return self._tool_safe_sequence("set", set_value, max_items=max_items, depth=depth)
        if isinstance(value, dict):
            dict_value = cast(dict[object, object], value)
            return self._tool_safe_mapping(dict_value, max_items=max_items, depth=depth)
        text = str(value)
        clipped, truncated = self._clip_text(text, limit=SCRIPT_TEXT_LIMIT_DEFAULT)
        payload: JsonObject = {"type": type(value).__name__, "repr": clipped}
        if truncated:
            payload["truncated"] = True
            payload["original_length"] = len(text)
        return self._json_object(payload)

    def _tool_safe_sequence(self, kind: str, values: Iterable[object], *, max_items: int, depth: int) -> JsonValue:
        """压缩脚本返回的序列，避免返回全量巨大列表。"""
        samples: list[JsonValue] = []
        total = 0
        for total, item in enumerate(values, start=1):
            if len(samples) < max_items:
                samples.append(self._tool_safe_value(item, max_items=max_items, depth=depth - 1))
        if total <= max_items:
            return samples
        return self._json_object({"type": kind, "count": total, "sample": samples, "truncated": True})

    def _tool_safe_mapping(self, value: dict[object, object], *, max_items: int, depth: int) -> JsonValue:
        """压缩脚本返回的映射，保留少量键值样本。"""
        sample: JsonObject = {}
        total = 0
        for total, (key, item) in enumerate(value.items(), start=1):
            if len(sample) < max_items:
                sample[str(key)] = self._tool_safe_value(item, max_items=max_items, depth=depth - 1)
        if total <= max_items:
            return sample
        return self._json_object({"type": "dict", "count": total, "sample": sample, "truncated": True})

    def _script_local_keys(self, scope: dict[str, object]) -> list[str]:
        """列出脚本产生的公开局部变量名。"""
        return [key for key in scope if not key.startswith("__")][:SCRIPT_LOCALS_SUMMARY_LIMIT]

    def _script_locals_summary(self, scope: dict[str, object]) -> list[JsonObject]:
        """返回脚本局部变量的可序列化摘要，不返回完整大对象。"""
        summaries: list[JsonObject] = []
        for key, value in scope.items():
            if key.startswith("__"):
                continue
            summaries.append(
                self._json_object(
                    {
                        "name": key,
                        "type": type(value).__name__,
                        "preview": self._tool_safe_value(value, max_items=SCRIPT_LOCALS_SAMPLE_LIMIT, depth=2),
                    }
                )
            )
            if len(summaries) >= SCRIPT_LOCALS_SUMMARY_LIMIT:
                break
        return summaries

    def _json_schema_summary(self, value: JsonValue) -> JsonObject:
        """生成轻量 JSON 结构摘要，便于调用方判断落盘内容形态。"""
        if value is None:
            return {"type": "null"}
        if isinstance(value, bool):
            return {"type": "boolean"}
        if isinstance(value, int):
            return {"type": "integer"}
        if isinstance(value, float):
            return {"type": "number"}
        if isinstance(value, str):
            return {"type": "string", "length": len(value)}
        if isinstance(value, list):
            item_schema: JsonObject = {"type": "unknown"}
            if value:
                item_schema = self._json_schema_summary(value[0])
            return {"type": "array", "length": len(value), "items": item_schema}
        properties: JsonObject = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 24:
                properties["<truncated>"] = {"type": "remaining", "count": len(value) - index}
                break
            properties[str(key)] = self._json_schema_summary(item)
        return {"type": "object", "keys": len(value), "properties": properties}

    def _script_artifact_directory(self) -> Path:
        """返回脚本结果落盘目录。"""
        directory = get_runtime_workspace_paths().directory / "script-results"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _write_script_artifact(self, *, name: str, content: str, schema: JsonObject, suffix: str) -> JsonObject:
        """保存脚本大结果并返回路径、哈希、大小与 schema。"""
        encoded = content.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        filename = f"{time_ns()}-{name}-{digest[:12]}.{suffix}"
        path = self._script_artifact_directory() / filename
        path.write_bytes(encoded)
        return {
            "path": str(path),
            "sha256": digest,
            "size": len(encoded),
            "schema": schema,
        }

    def _maybe_write_text_artifact(self, *, name: str, text: str, truncated: bool) -> JsonObject | None:
        """在文本被截断或超过阈值时落盘完整内容。"""
        if not truncated and len(text.encode("utf-8")) <= SCRIPT_ARTIFACT_AUTO_LIMIT:
            return None
        return self._write_script_artifact(
            name=name,
            content=text,
            schema={"type": "string", "length": len(text)},
            suffix="txt",
        )

    def _maybe_write_result_artifact(self, value: object | None, *, result_present: bool, output_limit: int) -> tuple[JsonObject | None, JsonValue | None]:
        """在 result 的可序列化形态过大时落盘 JSON。"""
        if not result_present:
            return None, None
        serialized_value = self._tool_safe_value(
            value,
            max_items=SCRIPT_ARTIFACT_VALUE_ITEM_LIMIT,
            depth=SCRIPT_ARTIFACT_VALUE_DEPTH_LIMIT,
        )
        content = json.dumps(serialized_value, ensure_ascii=False, indent=2, sort_keys=True)
        if len(content.encode("utf-8")) <= min(output_limit, SCRIPT_ARTIFACT_AUTO_LIMIT):
            return None, serialized_value
        schema = self._json_schema_summary(serialized_value)
        artifact = self._write_script_artifact(name="result", content=content, schema=schema, suffix="json")
        return artifact, serialized_value

    def evaluate_python(self, code: str, *, include_locals: bool = False, max_output_chars: int = SCRIPT_TEXT_LIMIT_DEFAULT) -> JsonObject:
        """执行 Python 代码，并返回受控大小的 stdout/result。"""
        output_limit = max(1_000, min(max_output_chars, SCRIPT_TEXT_LIMIT_HARD))
        scope: dict[str, object] = {}
        stdout_buffer = StringIO()
        stderr_buffer = StringIO()
        started_at = perf_counter()
        mode = "exec"
        result_present = False
        result_value: object | None = None

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                result_value = eval(code, scope, scope)
                result_present = True
                mode = "eval"
            except SyntaxError:
                exec(code, scope, scope)
                result_present = "result" in scope
                if result_present:
                    result_value = scope["result"]

        stdout_text, stdout_truncated = self._clip_text(stdout_buffer.getvalue(), limit=output_limit)
        stderr_text, stderr_truncated = self._clip_text(stderr_buffer.getvalue(), limit=output_limit)
        stdout_artifact = self._maybe_write_text_artifact(name="stdout", text=stdout_buffer.getvalue(), truncated=stdout_truncated)
        stderr_artifact = self._maybe_write_text_artifact(name="stderr", text=stderr_buffer.getvalue(), truncated=stderr_truncated)
        result_artifact, serialized_result = self._maybe_write_result_artifact(result_value, result_present=result_present, output_limit=output_limit)
        payload: dict[str, object] = {
            "mode": mode,
            "duration_ms": round((perf_counter() - started_at) * 1000.0, 3),
            "stdout": stdout_text,
            "stderr": stderr_text,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "result_present": result_present,
            "result": self._tool_safe_value(result_value) if result_present else None,
            "local_keys": self._script_local_keys(scope),
            "locals_returned": include_locals,
            "output_contract": "exec 默认返回 stdout/stderr/result 与局部变量名；大 stdout/stderr/result 会自动落盘并返回 path/sha256/size/schema。",
            "recommended_next_tools": ["explain_function", "decompile_function", "find_strings", "search_regex"],
        }
        artifacts: JsonObject = {}
        if stdout_artifact is not None:
            artifacts["stdout"] = stdout_artifact
        if stderr_artifact is not None:
            artifacts["stderr"] = stderr_artifact
        if result_artifact is not None:
            artifacts["result"] = result_artifact
        if artifacts:
            payload["artifacts"] = artifacts
        if result_artifact is not None and serialized_result is not None:
            payload["result_schema"] = result_artifact["schema"]
        if include_locals:
            payload["locals_summary"] = self._script_locals_summary(scope)
        return self._json_object(payload)

    def execute_python_file(self, path: str) -> JsonObject:
        """执行 Python 文件。"""
        return self.evaluate_python(Path(path).read_text(encoding="utf-8"))
