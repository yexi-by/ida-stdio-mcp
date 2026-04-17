"""托管程序集的外部反编译支持。"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(slots=True, frozen=True)
class ManagedDecompileResult:
    """托管方法反编译结果。"""

    command: str
    type_source: str
    method_source: str
    extracted_exact: bool


def managed_decompiler_command() -> str | None:
    """定位可用的 `ilspycmd` 命令。"""
    override = os.environ.get("IDA_STDIO_MCP_ILSPYCMD", "").strip()
    if override:
        return override
    discovered = shutil.which("ilspycmd")
    if discovered:
        return discovered
    return None


def managed_decompiler_available() -> bool:
    """判断是否存在可用的托管反编译后端。"""
    return managed_decompiler_command() is not None


@lru_cache(maxsize=128)
def _decompile_type_source(assembly_path: str, full_type: str) -> tuple[str, str] | None:
    """调用 `ilspycmd` 反编译整个类型。"""
    command = managed_decompiler_command()
    if command is None:
        return None

    assembly = Path(assembly_path)
    completed = subprocess.run(
        [
            command,
            "--disable-updatecheck",
            "--languageversion",
            "Latest",
            "--referencepath",
            str(assembly.parent),
            "--type",
            full_type,
            str(assembly),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    stdout_text = completed.stdout.strip()
    if completed.returncode != 0 or not stdout_text:
        return None
    return command, stdout_text


def decompile_managed_method(assembly_path: Path, full_type: str, method_name: str) -> ManagedDecompileResult | None:
    """反编译指定托管方法。"""
    payload = _decompile_type_source(str(assembly_path), full_type)
    if payload is None:
        return None
    command, type_source = payload
    method_source = extract_method_source(type_source, method_name)
    if method_source is None:
        return ManagedDecompileResult(
            command=command,
            type_source=type_source,
            method_source=type_source,
            extracted_exact=False,
        )
    return ManagedDecompileResult(
        command=command,
        type_source=type_source,
        method_source=method_source,
        extracted_exact=True,
    )


def extract_method_source(type_source: str, method_name: str) -> str | None:
    """从类型源码中截取某个方法。"""
    marker = f"{method_name}("
    match_index = type_source.find(marker)
    if match_index < 0:
        return None

    signature_start = type_source.rfind("\n", 0, match_index)
    signature_start = 0 if signature_start < 0 else signature_start + 1
    signature_start = _expand_attribute_block(type_source, signature_start)

    expression_end = _try_extract_expression_bodied_method(type_source, match_index)
    if expression_end is not None:
        return type_source[signature_start:expression_end].strip()

    body_start = type_source.find("{", match_index)
    if body_start < 0:
        return None
    body_end = _find_matching_brace(type_source, body_start)
    if body_end is None:
        return None
    return type_source[signature_start : body_end + 1].strip()


def _expand_attribute_block(type_source: str, signature_start: int) -> int:
    """把方法前面的 attribute 一起纳入结果。"""
    current_start = signature_start
    while current_start > 0:
        previous_break = type_source.rfind("\n", 0, current_start - 1)
        line_start = 0 if previous_break < 0 else previous_break + 1
        line_end = current_start - 1 if current_start > 0 else 0
        line_text = type_source[line_start:line_end].strip()
        if not line_text.startswith("["):
            break
        current_start = line_start
    return current_start


def _try_extract_expression_bodied_method(type_source: str, match_index: int) -> int | None:
    """尝试提取表达式体方法。"""
    expression_index = type_source.find("=>", match_index)
    body_index = type_source.find("{", match_index)
    if expression_index < 0:
        return None
    if body_index >= 0 and body_index < expression_index:
        return None

    current = expression_index + 2
    in_string = False
    while current < len(type_source):
        char = type_source[current]
        previous = type_source[current - 1] if current > 0 else ""
        if char == '"' and previous != "\\":
            in_string = not in_string
        if char == ";" and not in_string:
            return current + 1
        current += 1
    return None


def _find_matching_brace(text: str, start_index: int) -> int | None:
    """寻找与起始大括号配对的结束位置。"""
    depth = 0
    index = start_index
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        previous = text[index - 1] if index > 0 else ""

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
            index += 1
            continue

        if in_block_comment:
            if previous == "*" and char == "/":
                in_block_comment = False
            index += 1
            continue

        if not in_string and not in_char:
            if char == "/" and next_char == "/":
                in_line_comment = True
                index += 2
                continue
            if char == "/" and next_char == "*":
                in_block_comment = True
                index += 2
                continue

        if char == '"' and previous != "\\" and not in_char:
            in_string = not in_string
            index += 1
            continue

        if char == "'" and previous != "\\" and not in_string:
            in_char = not in_char
            index += 1
            continue

        if in_string or in_char:
            index += 1
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1

    return None
