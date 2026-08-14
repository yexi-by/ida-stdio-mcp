"""MCP 客户端可见的中文说明和确定性结果摘要。"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Final, cast

from pydantic import JsonValue

from ida_re_mcp.domain.base import JsonObject

_MAX_SUMMARY_CHARS: Final = 2_048
_MAX_ERROR_REASON_CHARS: Final = 768
_FULL_RESULT_NOTE: Final = (
    "字段、地址、ID、哈希值和其他完整数据请读取 structuredContent；本段文字只说明结果和下一步。"
)
_SENSITIVE_DETAIL_KEYS: Final = frozenset(
    {
        "exception",
        "exception_type",
        "failure",
        "rollback_failure",
        "stack_trace",
        "stderr_log",
        "stdout_log",
        "traceback",
    }
)
_EXCEPTION_NAME = re.compile(r"\b[A-Z][A-Za-z0-9_]*(?:Error|Exception)\b")
_PATH_PREFIX = r"(?:^|[\s\"'`(（=：，；。])"
_WINDOWS_ABSOLUTE_PATH = re.compile(rf"(?i){_PATH_PREFIX}(?:[a-z]:[\\/]|\\\\)")
_POSIX_ABSOLUTE_PATH = re.compile(rf"{_PATH_PREFIX}/(?!/)\S+")
_ERROR_NEXT_STEPS: Final = MappingProxyType(
    {
        "invalid_arguments": "按照 tools/list 返回的 inputSchema 修改参数后重试。",
        "revision_conflict": "调用 workspace.get 获取 current_revision，再根据最新版本重新执行。",
        "revision_not_found": "调用 workspace.get 查看仍然存在的 revision，并改用其中一个版本。",
        "cursor_stale": "去掉 cursor，从第一页重新读取。",
        "ambiguous_reference": "从 details 中选择明确的实体编号或地址后重试。",
        "capability_unavailable": "运行 doctor 检查 IDA 能力和配置，再决定是否重试。",
        "unsupported": "检查工具说明、参数和样本格式，改用当前支持的操作。",
        "debug_state_conflict": ("调用 debug.events 查看最新状态；进程暂停时改用最新的 stop_id。"),
        "policy_denied": "检查 config.toml 中的 policy 设置；只有确认风险后才修改策略。",
        "worker_crashed": "可以重试一次；再次失败时运行 doctor 并查看日志。",
        "workspace_not_found": "调用 workspace.list 查找正确的 workspace_id。",
        "operation_not_found": "检查 operation_id；找不到时重新发起原操作。",
        "change_set_invalid": "重新调用 change.prepare，并把新返回的字段原样传给 change.apply。",
        "precondition_failed": "根据 message 和 details 修正前置条件后重试。",
        "resource_not_found": "重新调用生成文件的工具，并使用它新返回的完整文件地址。",
        "execution_failed": "运行 doctor 检查配置并查看日志，再根据原因决定是否重试。",
    }
)


def build_server_instructions(
    *,
    data_root: Path | None,
    log_root: Path | None,
) -> str:
    """说明新建分析和接手已有分析时的固定调用顺序。"""

    lines = [
        "这是 IDA 分析服务。",
        (
            "接手已有分析时，先调用 workspace.list 查找 workspace_id，"
            "再调用 workspace.get 读取 current_revision 和已有版本；"
            "不要重复导入或重新分析已经存在的样本。"
        ),
        (
            "分析新样本时，调用 workspace.create，然后把返回的 analysis_operation_id "
            "作为 operation_id 调用 operation.wait，直到首次分析完成。"
        ),
        (
            "workspace.list 显示 state=failed 且 revision 为空时，调用 workspace.retry "
            "重新分析已有样本；不要再次调用 workspace.create 导入同一文件。"
        ),
        (
            "所有静态查询都必须提供 workspace_id 和 revision。修改分析数据库时，"
            "先调用 change.prepare 检查修改，再调用 change.apply 保存；"
            "保存后，后续查询必须改用返回的新 revision。"
        ),
        (
            "每个工具的完整结果都在 structuredContent 中。text 只含代码生成的中文摘要，"
            "不能代替完整结果；只读取 text 的客户端会漏掉字段、地址、ID 或哈希值。"
        ),
    ]
    if data_root is not None:
        lines.append(
            f"分析数据保存在 `{data_root}`。不同 Agent 接手同一任务时应先读取这里的已有分析。"
        )
    else:
        lines.append("分析数据目录由启动配置决定；可用 workspace.list 查看已经保存的分析。")
    if log_root is not None:
        lines.append(f"运行日志保存在 `{log_root}`。工具失败时先查看这里的日志。")
    else:
        lines.append("日志目录由启动配置决定；工具反复失败时运行 doctor 检查配置。")
    return "\n".join(lines)


def validation_issue_message(error_type: str) -> str:
    """把 Pydantic 错误类型转换为不依赖英文原文的中文提示。"""

    exact = {
        "missing": "缺少必填参数",
        "extra_forbidden": "参数未在工具定义中",
        "literal_error": "参数值不在允许列表中",
        "string_pattern_mismatch": "参数格式不正确",
        "greater_than": "数值必须大于允许的下限",
        "greater_than_equal": "数值小于允许的最小值",
        "less_than": "数值必须小于允许的上限",
        "less_than_equal": "数值大于允许的最大值",
        "multiple_of": "数值不符合步长要求",
        "finite_number": "数值必须是有限数字",
        "value_error": "参数取值或参数组合不符合要求",
        "frozen_instance": "这个参数不能修改",
        "frozen_field": "这个参数不能修改",
    }
    if error_type in exact:
        return exact[error_type]
    if error_type.endswith("_type") or error_type in {
        "bool_parsing",
        "int_parsing",
        "float_parsing",
        "string_sub_type",
    }:
        return "参数类型不正确"
    if error_type.endswith("_too_short"):
        return "参数内容少于允许的最小长度或数量"
    if error_type.endswith("_too_long"):
        return "参数内容超过允许的最大长度或数量"
    if error_type.startswith("union_tag_"):
        return "参数的类型标记缺失或不正确"
    if error_type.startswith("json_"):
        return "参数不是有效的 JSON 数据"
    return "参数值不符合工具要求"


def safe_error_message(message: str) -> str:
    """隐藏异常类型、堆栈和本机路径。保留正常业务提示。"""

    if _contains_sensitive_text(message):
        return (
            "工具执行失败。内部诊断信息已经写入日志。"
            "请运行 doctor 检查配置，并查看服务说明中列出的日志目录。"
        )
    return message


def sanitize_error_details(details: JsonObject) -> JsonObject:
    """保留可供程序处理的错误字段。隐藏内部诊断信息。"""

    return {key: _sanitize_error_value(value, key=key) for key, value in details.items()}


def error_summary(code: str, message: str) -> str:
    """生成可直接阅读的错误说明。机器错误对象由下一段文本保留。"""

    action = _ERROR_NEXT_STEPS.get(
        code,
        "检查工具说明和当前状态后重试；反复失败时运行 doctor 并查看日志。",
    )
    body = (
        f"操作失败：{_short(message, _MAX_ERROR_REASON_CHARS)}\n"
        f"错误代码：`{code}`。\n"
        f"下一步：{action}\n"
        "下一段文本保留完整的机器错误对象 `{code,message,details}`。"
    )
    return body[:_MAX_SUMMARY_CHARS]


def success_summary(tool_name: str, result: JsonObject) -> str:
    """根据已经校验的工具结果生成简短中文说明。不会复制完整 JSON。"""

    builder = _SUMMARY_BUILDERS.get(tool_name)
    if builder is None:
        body = f"工具 {tool_name} 已执行成功。"
    else:
        body = builder(result)
    available = _MAX_SUMMARY_CHARS - len(_FULL_RESULT_NOTE) - 1
    return f"{body[:available]}\n{_FULL_RESULT_NOTE}"


def _contains_sensitive_text(value: str) -> bool:
    return (
        bool(_EXCEPTION_NAME.search(value))
        or bool(_WINDOWS_ABSOLUTE_PATH.search(value))
        or bool(_POSIX_ABSOLUTE_PATH.search(value))
        or value.startswith(("/", "file://"))
        or "Traceback (most recent call last)" in value
        or '\n  File "' in value
    )


def _sanitize_error_value(value: JsonValue, *, key: str | None = None) -> JsonValue:
    normalized_key = key.casefold() if key is not None else None
    if normalized_key == "path" and isinstance(value, str):
        return "已隐藏内部诊断信息"
    if normalized_key is not None and (
        normalized_key in _SENSITIVE_DETAIL_KEYS
        or normalized_key.endswith("_path")
        or normalized_key.endswith("_log")
    ):
        return "已隐藏内部诊断信息"
    if isinstance(value, str):
        return "已隐藏内部诊断信息" if _contains_sensitive_text(value) else value
    if isinstance(value, list):
        return [_sanitize_error_value(item) for item in value]
    if isinstance(value, dict):
        mapping = cast(dict[str, JsonValue], value)
        return {
            child_key: _sanitize_error_value(child_value, key=child_key)
            for child_key, child_value in mapping.items()
        }
    return value


def _text(result: JsonObject, key: str, default: str = "未返回") -> str:
    value = result.get(key)
    return value if isinstance(value, str) else default


def _optional_text(result: JsonObject, key: str) -> str | None:
    value = result.get(key)
    return value if isinstance(value, str) else None


def _integer(result: JsonObject, key: str) -> int:
    value = result.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _items(result: JsonObject, key: str) -> list[object]:
    value = result.get(key)
    return list(value) if isinstance(value, list) else []


def _short(value: str, limit: int = 96) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _nested_text(result: JsonObject, key: str, child_key: str) -> str | None:
    value = result.get(key)
    if not isinstance(value, dict):
        return None
    child = value.get(child_key)
    return child if isinstance(child, str) else None


def _artifact_uri(result: JsonObject, key: str = "result_artifact") -> str | None:
    return _nested_text(result, key, "uri")


def _artifact_result(result: JsonObject) -> str | None:
    uri = _artifact_uri(result)
    if uri is None:
        return None
    return f"结果较大，已保存为工具生成的文件：{uri}。请使用这个地址读取完整文件。"


def _coverage_note(result: JsonObject) -> str:
    coverage = result.get("coverage")
    if not isinstance(coverage, dict):
        return ""
    status = coverage.get("status")
    sampled = coverage.get("sampled") is True
    truncated = coverage.get("truncated") is True
    if status == "complete" and not sampled and not truncated:
        return "结果完整。"
    return "结果未覆盖全部请求范围，具体原因见 structuredContent.coverage。"


def _page_note(result: JsonObject, *, tool_name: str) -> str:
    cursor = _optional_text(result, "next_cursor")
    if cursor is None:
        return "已经读完，没有下一页。"
    return f"还有下一页；再次调用 {tool_name} 并传入 next_cursor `{cursor}`。"


def _address_text(value: object) -> str:
    if not isinstance(value, dict):
        return "未返回地址"
    address_value = cast(dict[object, object], value)
    kind = address_value.get("kind")
    for key in ("rva", "ea", "offset", "va"):
        address = address_value.get(key)
        if isinstance(address, str):
            return f"{kind or 'address'}:{address}"
    return str(kind) if isinstance(kind, str) else "未返回地址"


def _workspace_create(result: JsonObject) -> str:
    revision = _optional_text(result, "revision")
    revision_note = f" 当前分析版本为 `{revision}`。" if revision is not None else ""
    return (
        f"样本已复制到分析项目 `{_text(result, 'workspace_id')}`，"
        f"SHA-256 为 `{_text(result, 'sample_sha256')}`。{revision_note}"
        f"首次分析任务是 `{_text(result, 'analysis_operation_id')}`；"
        "现在调用 operation.wait 等待完成。"
    )


def _workspace_retry(result: JsonObject) -> str:
    return (
        f"分析项目 `{_text(result, 'workspace_id')}` 的首次分析已重新开始，"
        f"样本 SHA-256 为 `{_text(result, 'sample_sha256')}`。"
        f"后台任务是 `{_text(result, 'analysis_operation_id')}`；"
        "现在调用 operation.wait 等待完成。"
    )


def _workspace_list(result: JsonObject) -> str:
    workspaces = _items(result, "workspaces")
    if not workspaces:
        return (
            "没有找到已经保存的分析项目。"
            "如果要分析新样本，请调用 workspace.create；"
            "如果原本应该有数据，请确认正在使用同一个项目目录和 config.toml。"
        )
    return (
        f"本页找到 {len(workspaces)} 个已保存的分析项目。"
        "请从 structuredContent.workspaces 读取完整列表：ready 项目调用 workspace.get，"
        "failed 且没有 revision 的项目调用 workspace.retry。"
        f"{_page_note(result, tool_name='workspace.list')}"
    )


def _workspace_get(result: JsonObject) -> str:
    history_note = (
        "更早的版本记录已经清理。"
        if result.get("history_truncated") is True
        else "当前返回的版本记录没有被截断。"
    )
    return (
        f"分析项目 `{_text(result, 'workspace_id')}` 的当前版本是 "
        f"`{_text(result, 'current_revision')}`，样本为 "
        f"`{_short(_text(result, 'sample_name'))}`，"
        f"架构为 `{_text(result, 'architecture')}`。"
        f"本页包含 {len(_items(result, 'revisions'))} 条版本记录；{history_note}"
        "后续静态查询使用这个 workspace_id 和 current_revision。"
        f"{_page_note(result, tool_name='workspace.get')}"
    )


def _queued_operation(result: JsonObject, action: str) -> str:
    return (
        f"{action}已经开始，后台任务编号为 `{_text(result, 'operation_id')}`。"
        "调用 operation.wait 并传入这个 operation_id，直到任务成功、失败或取消。"
    )


def _workspace_export(result: JsonObject) -> str:
    return _queued_operation(result, "导出分析数据库")


def _report_build(result: JsonObject) -> str:
    return _queued_operation(result, "生成报告")


def _analysis_refine(result: JsonObject) -> str:
    return (
        _queued_operation(result, "重新分析")
        + f"当前基础版本是 `{_text(result, 'base_revision')}`；"
        "任务成功后改用 operation.wait 结果中的新 revision。"
    )


def _operation_wait(result: JsonObject) -> str:
    operation_id = _text(result, "operation_id")
    state = _text(result, "state")
    if state == "queued":
        return (
            f"后台任务 `{operation_id}` 正在等待执行。"
            "继续调用 operation.wait；可以设置 wait_ms，单次最多等待 30 秒。"
        )
    if state == "running":
        progress = result.get("progress")
        progress_note = (
            f"当前进度约为 {float(progress) * 100:.0f}%。"
            if isinstance(progress, int | float) and not isinstance(progress, bool)
            else "当前任务没有可报告的百分比进度。"
        )
        return f"后台任务 `{operation_id}` 正在执行。{progress_note}继续调用 operation.wait。"
    if state == "cancel_requested":
        return (
            f"后台任务 `{operation_id}` 已收到取消请求，但尚未结束。"
            "继续调用 operation.wait，等待最终状态。"
        )
    if state == "cancelled":
        return f"后台任务 `{operation_id}` 已取消，不会再产生结果。"
    if state == "failed":
        failure = result.get("failure")
        failure_value = cast(dict[str, JsonValue], failure) if isinstance(failure, dict) else {}
        failure_code = failure_value.get("code")
        code = failure_code if isinstance(failure_code, str) else "未返回"
        failure_message = failure_value.get("message")
        message = (
            safe_error_message(failure_message)
            if isinstance(failure_message, str)
            else "后台任务没有返回失败原因。"
        )
        message = _short(message, _MAX_ERROR_REASON_CHARS)
        retryable = failure_value.get("retryable") is True
        next_note = (
            "该错误标记为可以重试；可以重新发起原操作。"
            if retryable
            else "该错误未标记为可以重试；请先按失败原因修正问题。"
        )
        return (
            f"后台任务 `{operation_id}` 执行失败，错误代码为 `{code}`。"
            f"失败原因：{message}{next_note}"
        )
    if state == "succeeded":
        operation_result = result.get("result")
        facts: list[str] = []
        if isinstance(operation_result, dict):
            for key, label in (
                ("workspace_id", "workspace_id"),
                ("revision", "新 revision"),
                ("artifact_uri", "文件地址"),
                ("sha256", "SHA-256"),
            ):
                value = operation_result.get(key)
                if isinstance(value, str):
                    facts.append(f"{label} `{value}`")
        fact_note = f" 关键结果：{'，'.join(facts)}。" if facts else ""
        next_note = (
            "如果结果包含 artifact_uri，请使用该地址读取生成的文件。"
            if isinstance(operation_result, dict)
            and isinstance(operation_result.get("artifact_uri"), str)
            else "后续操作使用结果中的 workspace_id 和 revision。"
        )
        return f"后台任务 `{operation_id}` 已成功完成。{fact_note}{next_note}"
    return f"后台任务 `{operation_id}` 返回了状态 `{state}`。请根据 structuredContent 处理。"


def _operation_cancel(result: JsonObject) -> str:
    requested = result.get("cancellation_requested") is True
    if requested:
        return (
            f"后台任务 `{_text(result, 'operation_id')}` 已收到取消请求，"
            f"当前状态为 `{_text(result, 'state')}`。"
            "取消并不代表任务已经结束；请调用 operation.wait 等待最终状态。"
        )
    return (
        f"后台任务 `{_text(result, 'operation_id')}` 未接受新的取消请求，"
        f"当前状态为 `{_text(result, 'state')}`。"
        "调用 operation.wait 查看最终结果。"
    )


def _program_overview(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    counts = result.get("counts")
    functions = strings = imports = exports = 0
    if isinstance(counts, dict):
        functions = counts.get("functions") if isinstance(counts.get("functions"), int) else 0
        strings = counts.get("strings") if isinstance(counts.get("strings"), int) else 0
        imports = counts.get("imports") if isinstance(counts.get("imports"), int) else 0
        exports = counts.get("exports") if isinstance(counts.get("exports"), int) else 0
    return (
        f"程序概览读取完成：函数 {functions} 个、字符串 {strings} 个、"
        f"导入项 {imports} 个、导出项 {exports} 个。{_coverage_note(result)}"
        "需要具体内容时继续调用 program.search、function.inspect 或 address.inspect。"
    )


def _program_search(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    return (
        f"本页找到 {len(_items(result, 'matches'))} 条结果。{_coverage_note(result)}"
        f"{_page_note(result, tool_name='program.search')}"
    )


def _address_inspect(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    facts: list[str] = []
    if _optional_text(result, "symbol") is not None:
        facts.append("符号")
    if result.get("instruction") is not None:
        facts.append("指令")
    if _optional_text(result, "function_id") is not None:
        facts.append("所属函数")
    fact_note = f" 已返回{'、'.join(facts)}。" if facts else ""
    return (
        f"地址 `{_address_text(result.get('address'))}` 已检查；"
        f"找到 {len(_items(result, 'xrefs'))} 条交叉引用。{fact_note}"
        f"{_coverage_note(result)}需要函数详情时调用 function.inspect。"
    )


def _function_inspect(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    return (
        f"函数 `{_short(_text(result, 'name'))}`（entity_id "
        f"`{_text(result, 'entity_id')}`）已读取："
        f"指令 {len(_items(result, 'instructions'))} 条、"
        f"伪代码 {len(_items(result, 'pseudocode'))} 行、"
        f"基本块 {len(_items(result, 'blocks'))} 个、"
        f"调用关系 {len(_items(result, 'calls'))} 条。"
        f"{_coverage_note(result)}{_page_note(result, tool_name='function.inspect')}"
    )


def _graph_query(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    unresolved = result.get("unresolved_indirect_edges")
    unresolved_note = (
        f"另有 {unresolved} 条间接关系未能解析。"
        if isinstance(unresolved, int)
        else "间接关系的未解析数量未知。"
    )
    return (
        f"关系图包含 {len(_items(result, 'nodes'))} 个节点和 "
        f"{len(_items(result, 'edges'))} 条边。{unresolved_note}{_coverage_note(result)}"
    )


def _dataflow_slice(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    semantics = "必然数据流" if _text(result, "semantics") == "must" else "可能数据流"
    return (
        f"{semantics}查询完成：节点 {len(_items(result, 'nodes'))} 个、"
        f"边 {len(_items(result, 'edges'))} 条、"
        f"无法继续判断的位置 {len(_items(result, 'barriers'))} 个。"
        f"{_coverage_note(result)}"
    )


def _type_inspect(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        return artifact
    size = result.get("size")
    size_note = f"，大小 {size} 字节" if isinstance(size, int) else ""
    return (
        f"类型 `{_short(_text(result, 'name'))}` 已读取，种类为 "
        f"`{_text(result, 'kind')}`{size_note}，"
        f"本页包含 {len(_items(result, 'fields'))} 个字段。"
        f"{_coverage_note(result)}{_page_note(result, tool_name='type.inspect')}"
    )


def _change_prepare(result: JsonObject) -> str:
    return (
        f"已检查 {_integer(result, 'operation_count')} 项修改。"
        f"change_set_id 为 `{_text(result, 'change_set_id')}`，"
        f"digest 为 `{_text(result, 'digest')}`，"
        f"基础 revision 为 `{_text(result, 'base_revision')}`。"
        "先检查 structuredContent.impact；确认无误后调用 change.apply，并原样传入"
        " workspace_id、base_revision（作为 expected_revision）、change_set_id 和 digest。"
    )


def _change_apply(result: JsonObject) -> str:
    return (
        f"修改已经保存。分析项目 `{_text(result, 'workspace_id')}`"
        f"从 revision `{_text(result, 'previous_revision')}` 更新到 "
        f"`{_text(result, 'revision')}`，change_id 为 `{_text(result, 'change_id')}`。"
        "后续查询必须使用新的 revision。"
    )


def _debug_establish(result: JsonObject) -> str:
    state = _text(result, "state")
    base = (
        f"调试会话 `{_text(result, 'debug_session_id')}` 已建立，"
        f"进程号为 {_integer(result, 'process_id')}，当前状态为 `{state}`。"
    )
    if state == "suspended":
        return (
            base + f"当前 stop_id 是 `{_text(result, 'stop_id')}`；"
            "检查暂停状态或继续执行时必须使用这个 stop_id。"
        )
    return base + "调用 debug.events 等待停止或退出事件。"


def _debug_control(result: JsonObject) -> str:
    state = _text(result, "state")
    session_id = _text(result, "debug_session_id")
    if state == "suspended":
        return (
            f"调试会话 `{session_id}` 已暂停，新的 stop_id 是 "
            f"`{_text(result, 'stop_id')}`。"
            "后续 debug.inspect、debug.breakpoints 或 debug.control 必须使用这个 stop_id。"
        )
    if state == "running":
        return f"调试会话 `{session_id}` 正在运行。调用 debug.events 等待下一个事件。"
    return f"调试会话 `{session_id}` 中的进程已经退出，不要再使用这个会话。"


def _debug_events(result: JsonObject) -> str:
    count = len(_items(result, "events"))
    last_sequence = _integer(result, "last_sequence")
    if result.get("has_more") is True:
        next_note = (
            f"还有事件未返回；再次调用 debug.events，并将 after_sequence 设为 {last_sequence}。"
        )
    else:
        next_note = (
            f"当前事件已经读完；需要继续等待时再次调用 debug.events，将 after_sequence "
            f"设为 {last_sequence} 并设置 wait_ms。"
        )
    return f"调试会话 `{_text(result, 'debug_session_id')}` 本次返回 {count} 个事件。{next_note}"


def _debug_inspect(result: JsonObject) -> str:
    artifact = _artifact_uri(result, "snapshot_artifact")
    if artifact is not None:
        body = f"暂停状态快照已保存为工具生成的文件：{artifact}。请使用这个地址读取。"
    else:
        memory_bytes = _optional_text(result, "memory_bytes")
        memory_note = f"、内存 {len(memory_bytes) // 2} 字节" if memory_bytes is not None else ""
        memory_artifact = _artifact_uri(result, "memory_artifact")
        if memory_artifact is not None:
            memory_note = f"、内存文件 {memory_artifact}"
        body = (
            f"暂停状态已读取：模块 {len(_items(result, 'modules'))} 个、"
            f"线程 {len(_items(result, 'threads'))} 个、"
            f"寄存器 {len(_items(result, 'registers'))} 个、"
            f"调用栈 {len(_items(result, 'stack'))} 帧{memory_note}。"
        )
    return body + f"这些结果只对应 stop_id `{_text(result, 'stop_id')}`；进程继续执行后不要复用。"


def _debug_breakpoints(result: JsonObject) -> str:
    artifact = _artifact_result(result)
    if artifact is not None:
        body = artifact
    else:
        body = f"断点集合已经替换，共返回 {len(_items(result, 'breakpoints'))} 个断点状态。"
    return (
        body + f"结果对应 stop_id `{_text(result, 'stop_id')}`；"
        "检查无误后可调用 debug.control 继续执行。"
    )


def _debug_finish(result: JsonObject) -> str:
    state = _text(result, "state")
    action = "已经与目标分离" if state == "detached" else "目标进程已经退出"
    return f"调试会话 `{_text(result, 'debug_session_id')}` 已结束，{action}。"


def _expert_execute(result: JsonObject) -> str:
    artifact = _artifact_uri(result, "artifact")
    output_note = (
        f"执行输出已保存为工具生成的文件：{artifact}。"
        if artifact is not None
        else "stdout、stderr 和表达式结果保留在 structuredContent 中，摘要不会复制这些内容。"
    )
    return (
        f"IDAPython 已执行并保存分析版本。基础 revision 为 "
        f"`{_text(result, 'base_revision')}`，新 revision 为 `{_text(result, 'revision')}`。"
        f"{output_note}后续查询必须使用新 revision。"
    )


type _SummaryBuilder = Callable[[JsonObject], str]

_SUMMARY_BUILDERS: Final = MappingProxyType(
    {
        "address.inspect": _address_inspect,
        "analysis.refine": _analysis_refine,
        "change.apply": _change_apply,
        "change.prepare": _change_prepare,
        "dataflow.slice": _dataflow_slice,
        "debug.breakpoints": _debug_breakpoints,
        "debug.control": _debug_control,
        "debug.establish": _debug_establish,
        "debug.events": _debug_events,
        "debug.finish": _debug_finish,
        "debug.inspect": _debug_inspect,
        "expert.execute": _expert_execute,
        "function.inspect": _function_inspect,
        "graph.query": _graph_query,
        "operation.cancel": _operation_cancel,
        "operation.wait": _operation_wait,
        "program.overview": _program_overview,
        "program.search": _program_search,
        "report.build": _report_build,
        "type.inspect": _type_inspect,
        "workspace.create": _workspace_create,
        "workspace.export": _workspace_export,
        "workspace.get": _workspace_get,
        "workspace.list": _workspace_list,
        "workspace.retry": _workspace_retry,
    }
)

SUPPORTED_SUCCESS_SUMMARIES: Final = frozenset(_SUMMARY_BUILDERS)
