"""外部分析器执行与 JSON artifact 管理。"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter, time_ns
from typing import cast

from .capabilities import CapabilityState
from .config import ExternalAnalyzerConfig
from .models import JsonObject, JsonValue
from .runtime_workspace import get_runtime_workspace_paths

ARTIFACT_ENTITY_LIMIT = 2_000
ARTIFACT_TEXT_LIMIT = 2_000_000
COMMAND_PLACEHOLDERS = ("{input}", "{input_name}", "{input_dir}", "{output}", "{workspace}")


@dataclass(slots=True, frozen=True)
class AnalysisArtifactRecord:
    """已导入分析 artifact 的索引记录。"""

    artifact_id: str
    path: Path
    sha256: str
    size: int
    schema: JsonObject

    def to_json(self) -> JsonObject:
        """返回可序列化记录。"""
        return {
            "artifact_id": self.artifact_id,
            "path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "schema": self.schema,
        }


_ARTIFACTS: dict[str, tuple[AnalysisArtifactRecord, JsonValue]] = {}


def _json_value(value: object) -> JsonValue:
    """把 json.loads 的结果收窄为项目 JSON 值。"""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        values = cast(list[object], value)
        return [_json_value(item) for item in values]
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        return {str(key): _json_value(item) for key, item in mapping.items()}
    return str(value)


def _json_schema_summary(value: JsonValue, *, depth: int = 0) -> JsonObject:
    """生成轻量 JSON 结构摘要。"""
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
        if value and depth < 4:
            item_schema = _json_schema_summary(value[0], depth=depth + 1)
        return {"type": "array", "length": len(value), "items": item_schema}
    properties: JsonObject = {}
    if depth < 4:
        for index, (key, item) in enumerate(value.items()):
            if index >= 24:
                properties["<truncated>"] = {"type": "remaining", "count": len(value) - index}
                break
            properties[str(key)] = _json_schema_summary(item, depth=depth + 1)
    return {"type": "object", "keys": len(value), "properties": properties}


def _artifact_directory() -> Path:
    """返回外部分析 artifact 目录。"""
    directory = get_runtime_workspace_paths().directory / "external-analysis"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _safe_name(value: str) -> str:
    """把分析器名称转换成文件名片段。"""
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return normalized.strip("-") or "analyzer"


def _sha256_bytes(data: bytes) -> str:
    """计算字节哈希。"""
    return hashlib.sha256(data).hexdigest()


def _artifact_id(path: Path, digest: str, explicit: str = "") -> str:
    """生成稳定 artifact ID。"""
    if explicit.strip():
        return explicit.strip()
    return f"{path.stem}-{digest[:12]}"


def import_analysis_artifact(path: str | Path, *, artifact_id: str = "") -> JsonObject:
    """导入外部 JSON 分析 artifact。"""
    artifact_path = Path(path).expanduser().resolve()
    if not artifact_path.is_file():
        raise FileNotFoundError(f"analysis artifact 不存在：{artifact_path}")
    raw = artifact_path.read_bytes()
    if len(raw) > ARTIFACT_TEXT_LIMIT:
        raise ValueError(f"analysis artifact 过大：{artifact_path}")
    payload = _json_value(json.loads(raw.decode("utf-8")))
    digest = _sha256_bytes(raw)
    record = AnalysisArtifactRecord(
        artifact_id=_artifact_id(artifact_path, digest, artifact_id),
        path=artifact_path,
        sha256=digest,
        size=len(raw),
        schema=_json_schema_summary(payload),
    )
    _ARTIFACTS[record.artifact_id] = (record, payload)
    return {"record": record.to_json(), "entities": extract_artifact_entities(payload, max_items=ARTIFACT_ENTITY_LIMIT)}


def list_analysis_artifacts() -> JsonObject:
    """列出已导入的外部分析 artifact。"""
    return {"count": len(_ARTIFACTS), "items": [record.to_json() for record, _ in _ARTIFACTS.values()]}


def get_analysis_artifact(*, artifact_id: str = "", path: str = "") -> tuple[AnalysisArtifactRecord, JsonValue]:
    """按 ID 或路径读取已导入 artifact；路径未导入时自动导入。"""
    normalized_id = artifact_id.strip()
    if normalized_id:
        pair = _ARTIFACTS.get(normalized_id)
        if pair is None:
            raise KeyError(f"找不到 analysis artifact：{normalized_id}")
        return pair
    if not path.strip():
        raise ValueError("必须提供 artifact_id 或 path")
    imported = import_analysis_artifact(path)
    record_value = imported.get("record")
    if not isinstance(record_value, dict):
        raise RuntimeError("artifact 导入结果缺少 record")
    imported_id = record_value.get("artifact_id")
    if not isinstance(imported_id, str):
        raise RuntimeError("artifact 导入结果缺少 artifact_id")
    return get_analysis_artifact(artifact_id=imported_id)


def _write_bytes_artifact(*, name: str, suffix: str, data: bytes) -> JsonObject:
    """保存外部分析副产物并返回元数据。"""
    digest = _sha256_bytes(data)
    path = _artifact_directory() / f"{time_ns()}-{_safe_name(name)}-{digest[:12]}.{suffix}"
    path.write_bytes(data)
    return {"path": str(path), "sha256": digest, "size": len(data)}


def _write_json_artifact(*, name: str, payload: JsonValue) -> JsonObject:
    """保存规范化 JSON artifact 并导入索引。"""
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    metadata = _write_bytes_artifact(name=name, suffix="json", data=content)
    path_value = metadata.get("path")
    if not isinstance(path_value, str):
        raise RuntimeError("写入 JSON artifact 后缺少路径")
    imported = import_analysis_artifact(path_value)
    record = imported.get("record")
    if isinstance(record, dict):
        metadata["artifact_id"] = record.get("artifact_id")
        metadata["schema"] = record.get("schema")
    return metadata


def _render_command(command: tuple[str, ...], *, input_path: Path, output_path: Path, workspace: Path) -> list[str]:
    """替换外部分析器命令占位符。"""
    replacements = {
        "{input}": str(input_path),
        "{input_name}": input_path.name,
        "{input_dir}": str(input_path.parent),
        "{output}": str(output_path),
        "{workspace}": str(workspace),
    }
    rendered: list[str] = []
    for item in command:
        value = item
        for key, replacement in replacements.items():
            value = value.replace(key, replacement)
        rendered.append(value)
    return rendered


def _command_health(command: Sequence[str]) -> JsonObject:
    """检查外部分析器命令入口是否存在。"""
    if not command:
        return {"status": "misconfigured", "reason": "命令为空", "entry": "", "resolved": ""}
    entry = command[0].strip()
    if not entry:
        return {"status": "misconfigured", "reason": "命令入口为空字符串", "entry": "", "resolved": ""}
    if any(placeholder in entry for placeholder in COMMAND_PLACEHOLDERS):
        return {"status": "uninitialized", "reason": "命令入口包含运行时占位符，需渲染后检查。", "entry": entry, "resolved": ""}
    expanded = Path(entry).expanduser()
    if expanded.is_absolute() or any(separator in entry for separator in ("\\", "/")):
        if expanded.is_file():
            return {"status": "available", "reason": "命令入口文件存在", "entry": entry, "resolved": str(expanded.resolve())}
        return {"status": "misconfigured", "reason": "命令入口文件不存在", "entry": entry, "resolved": str(expanded)}
    resolved = shutil.which(entry)
    if resolved:
        return {"status": "available", "reason": "命令入口可从 PATH 解析", "entry": entry, "resolved": resolved}
    return {"status": "misconfigured", "reason": "命令入口不在 PATH 中", "entry": entry, "resolved": ""}


def external_analyzer_health(analyzers: tuple[ExternalAnalyzerConfig, ...]) -> JsonObject:
    """返回外部分析器配置的统一能力状态。"""
    if not analyzers:
        return CapabilityState(
            name="external_analyzers",
            status="unavailable",
            reason="未配置 external analyzer。",
            source="setting.toml:external_analyzers",
            actionable_fix=("在 setting.toml 的 external_analyzers 中配置 name、command 和 timeout_sec。",),
            details={"configured_count": 0, "analyzers": []},
        ).to_json()

    rows: list[JsonValue] = []
    missing: list[str] = []
    unresolved: list[str] = []
    for spec in analyzers:
        command_state = _command_health(spec.command)
        status_value = command_state.get("status")
        if status_value == "uninitialized":
            unresolved.append(spec.name)
        elif status_value != "available":
            missing.append(spec.name)
        rows.append(
            {
                "name": spec.name,
                "status": status_value,
                "reason": command_state.get("reason"),
                "command_entry": command_state.get("entry"),
                "resolved": command_state.get("resolved"),
                "timeout_sec": spec.timeout_sec,
            }
        )

    if missing:
        missing_values: list[JsonValue] = [item for item in missing]
        details: JsonObject = {"configured_count": len(analyzers), "misconfigured": missing_values, "analyzers": rows}
        return CapabilityState(
            name="external_analyzers",
            status="misconfigured",
            reason="部分 external analyzer 命令不可执行。",
            source="setting.toml:external_analyzers",
            actionable_fix=("修正缺失命令的绝对路径，或把命令入口加入 PATH。",),
            details=details,
        ).to_json()
    if unresolved:
        unresolved_values: list[JsonValue] = [item for item in unresolved]
        details = {"configured_count": len(analyzers), "uninitialized": unresolved_values, "analyzers": rows}
        return CapabilityState(
            name="external_analyzers",
            status="uninitialized",
            reason="部分 external analyzer 命令入口包含运行时占位符，需执行时渲染后确认。",
            source="setting.toml:external_analyzers",
            actionable_fix=("调用 run_external_analyzer，让服务按 input/output/workspace 渲染命令后再检查。",),
            details=details,
        ).to_json()

    return CapabilityState(
        name="external_analyzers",
        status="available",
        reason="所有已配置 external analyzer 命令入口均可解析。",
        source="setting.toml:external_analyzers",
        details={"configured_count": len(analyzers), "analyzers": rows},
    ).to_json()


def run_external_analyzer(
    analyzers: tuple[ExternalAnalyzerConfig, ...],
    *,
    name: str,
    input_path: str,
    output_path: str = "",
    timeout_sec: int | None = None,
) -> JsonObject:
    """执行配置中的外部分析器，并导入其 JSON 结果。"""
    by_name = {item.name: item for item in analyzers}
    spec = by_name.get(name)
    if spec is None:
        return cast(JsonObject, {
            "status": "unsupported",
            "data": {"reason": "未配置该外部分析器", "requested": name, "available": sorted(by_name)},
            "warnings": ["请在 setting.toml 的 external_analyzers 中配置命令。"],
        })
    raw_command_state = _command_health(spec.command)
    if raw_command_state.get("status") not in {"available", "uninitialized"}:
        return cast(JsonObject, {
            "status": "unsupported",
            "data": {
                "reason": "外部分析器命令不可执行",
                "analyzer": name,
                "capability_status": raw_command_state.get("status"),
                "command": list(spec.command),
                "command_health": raw_command_state,
            },
            "warnings": [str(raw_command_state.get("reason") or "外部分析器命令不可执行。")],
        })
    source_path = Path(input_path).expanduser().resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"输入文件不存在：{source_path}")
    workspace = _artifact_directory()
    output = Path(output_path).expanduser().resolve() if output_path.strip() else workspace / f"{time_ns()}-{_safe_name(name)}-analysis.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    command = _render_command(spec.command, input_path=source_path, output_path=output, workspace=workspace)
    command_state = _command_health(command)
    if command_state.get("status") != "available":
        return cast(JsonObject, {
            "status": "unsupported",
            "data": {
                "reason": "外部分析器命令不可执行",
                "analyzer": name,
                "capability_status": command_state.get("status"),
                "command": command,
                "command_health": command_state,
            },
            "warnings": [str(command_state.get("reason") or "外部分析器命令不可执行。")],
        })
    started_at = perf_counter()
    effective_timeout = timeout_sec if timeout_sec is not None else spec.timeout_sec
    try:
        completed = subprocess.run(
            command,
            cwd=workspace,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=effective_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((perf_counter() - started_at) * 1000.0, 3)
        stdout_text = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr_text = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        stdout_artifact = _write_bytes_artifact(name=f"{name}-stdout-timeout", suffix="txt", data=stdout_text.encode("utf-8")) if stdout_text else None
        stderr_artifact = _write_bytes_artifact(name=f"{name}-stderr-timeout", suffix="txt", data=stderr_text.encode("utf-8")) if stderr_text else None
        return cast(JsonObject, {
            "status": "error",
            "data": {
                "analyzer": name,
                "input_path": str(source_path),
                "output_path": str(output),
                "command": command,
                "duration_ms": duration_ms,
                "timeout_sec": effective_timeout,
                "reason": "timeout",
                "stdout_artifact": stdout_artifact,
                "stderr_artifact": stderr_artifact,
            },
            "warnings": [f"外部分析器执行超时：{effective_timeout}s"],
        })
    duration_ms = round((perf_counter() - started_at) * 1000.0, 3)
    stdout_bytes = completed.stdout.encode("utf-8")
    stderr_bytes = completed.stderr.encode("utf-8")
    stdout_artifact = _write_bytes_artifact(name=f"{name}-stdout", suffix="txt", data=stdout_bytes) if stdout_bytes else None
    stderr_artifact = _write_bytes_artifact(name=f"{name}-stderr", suffix="txt", data=stderr_bytes) if stderr_bytes else None

    warnings: list[JsonValue] = []
    json_artifact: JsonObject | None = None
    json_source = "none"
    if output.is_file() and output.stat().st_size > 0:
        try:
            imported = import_analysis_artifact(output)
            record = imported.get("record")
            if isinstance(record, dict):
                json_artifact = record
                json_source = "output_path"
        except json.JSONDecodeError:
            warnings.append("output_path 不是合法 JSON，未导入 analysis artifact。")
    elif completed.stdout.strip():
        try:
            payload = _json_value(json.loads(completed.stdout))
            json_artifact = _write_json_artifact(name=f"{name}-stdout-json", payload=payload)
            json_source = "stdout"
        except json.JSONDecodeError:
            warnings.append("stdout 不是 JSON，未导入 analysis artifact。")
    else:
        warnings.append("外部分析器未产生 JSON 输出。")

    status = "ok" if completed.returncode == 0 and json_artifact is not None else "degraded"
    if completed.returncode != 0:
        warnings.append(f"外部分析器退出码非零：{completed.returncode}")
    return cast(JsonObject, {
        "status": status,
        "data": {
            "analyzer": name,
            "input_path": str(source_path),
            "output_path": str(output),
            "command": command,
            "returncode": completed.returncode,
            "duration_ms": duration_ms,
            "json_source": json_source,
            "json_artifact": json_artifact,
            "stdout_artifact": stdout_artifact,
            "stderr_artifact": stderr_artifact,
        },
        "warnings": warnings,
    })


def extract_artifact_entities(value: JsonValue, *, max_items: int = ARTIFACT_ENTITY_LIMIT) -> JsonObject:
    """从通用 JSON artifact 中抽取地址、hash、路径和文本候选。"""
    addresses: list[JsonObject] = []
    hashes: list[JsonObject] = []
    paths: list[JsonObject] = []
    texts: list[JsonObject] = []

    def add_unique(target: list[JsonObject], item: JsonObject, key: str) -> None:
        """按指定字段去重追加实体。"""
        item_value = item.get(key)
        if any(existing.get(key) == item_value for existing in target):
            return
        if len(target) < max_items:
            target.append(item)

    def visit(node: JsonValue, path: str) -> None:
        """递归访问 JSON 节点。"""
        if isinstance(node, dict):
            for key, item in node.items():
                visit(item, f"{path}.{key}" if path else str(key))
            return
        if isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]")
            return
        if isinstance(node, bool) or node is None:
            return
        if isinstance(node, int):
            if 0x1000 <= node <= 0xFFFFFFFFFFFFFFFF:
                add_unique(addresses, {"value": hex(node), "source_path": path, "kind": "integer"}, "value")
            if 0 <= node <= 0xFFFFFFFF:
                add_unique(hashes, {"value": hex(node), "source_path": path, "kind": "integer"}, "value")
            return
        if isinstance(node, float):
            return
        text = node.strip()
        if not text:
            return
        lowered_path = path.lower()
        if re.fullmatch(r"0x[0-9a-fA-F]{4,16}", text):
            add_unique(addresses, {"value": text.lower(), "source_path": path, "kind": "hex_string"}, "value")
            add_unique(hashes, {"value": text.lower(), "source_path": path, "kind": "hex_string"}, "value")
            return
        if re.fullmatch(r"[0-9a-fA-F]{8,16}", text) or "hash" in lowered_path:
            add_unique(hashes, {"value": text, "source_path": path, "kind": "string"}, "value")
        if "\\" in text or "/" in text or re.search(r"\.[A-Za-z0-9]{2,5}$", text):
            add_unique(paths, {"value": text, "source_path": path}, "value")
        if 3 <= len(text) <= 256:
            add_unique(texts, {"value": text, "source_path": path}, "value")

    visit(value, "")
    return cast(JsonObject, {
        "addresses": addresses,
        "hashes": hashes,
        "paths": paths,
        "texts": texts,
        "counts": {
            "addresses": len(addresses),
            "hashes": len(hashes),
            "paths": len(paths),
            "texts": len(texts),
        },
    })
