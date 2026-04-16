"""IDA Headless 运行时封装。"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from loguru import logger

from .errors import BinaryNotOpenError, RuntimeNotReadyError
from .models import AnalysisDomain, BinaryKind, BinarySummary, CallEdgeRecord, FunctionRecord, StringRecord


@dataclass(slots=True)
class ActiveDatabase:
    """当前激活数据库的摘要。"""

    input_path: Path
    idb_path: Path
    module: str
    binary_kind: BinaryKind
    analysis_domain: AnalysisDomain
    imagebase: str


@dataclass(slots=True)
class RuntimeCache:
    """按当前数据库隔离的运行时缓存。"""

    strings: list[StringRecord] | None = None
    functions: list[FunctionRecord] | None = None
    survey: dict[str, object] | None = None
    disassembly: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    decompile: dict[str, dict[str, object]] = field(default_factory=dict)
    callers: dict[str, list[CallEdgeRecord]] = field(default_factory=dict)
    callees: dict[str, list[CallEdgeRecord]] = field(default_factory=dict)


class HeadlessRuntime:
    """单样本 headless 运行时。"""

    def __init__(self) -> None:
        self._idapro = None
        self._active: ActiveDatabase | None = None
        self._cache = RuntimeCache()

    def _require_ida_dir(self) -> Path:
        ida_dir = os.environ.get("IDADIR", "").strip()
        if not ida_dir:
            raise RuntimeNotReadyError("缺少 IDADIR 环境变量")
        path = Path(ida_dir)
        if not path.exists():
            raise RuntimeNotReadyError(f"IDADIR 路径不存在：{path}")
        if not (path / "idalib.dll").exists():
            raise RuntimeNotReadyError(f"IDADIR 下缺少 idalib.dll：{path}")
        return path

    def _load_idapro(self):
        if self._idapro is None:
            _ = self._require_ida_dir()
            self._idapro = importlib.import_module("idapro")
            self._idapro.enable_console_messages(False)
            logger.info("已加载 idapro / idalib 运行时")
        return self._idapro

    def _invalidate(self) -> None:
        self._cache = RuntimeCache()

    def has_binary(self) -> bool:
        """判断当前是否已打开数据库。"""
        return self._active is not None

    def current_binary_summary(self) -> BinarySummary | None:
        """返回当前数据库摘要。"""
        if self._active is None:
            return None
        return {
            "input_path": str(self._active.input_path),
            "idb_path": str(self._active.idb_path),
            "module": self._active.module,
            "binary_kind": self._active.binary_kind,
            "analysis_domain": self._active.analysis_domain,
            "imagebase": self._active.imagebase,
        }

    def open_binary(self, input_path: Path, *, wait_auto_analysis: bool = True) -> BinarySummary:
        """打开一个二进制并刷新缓存。"""
        if not input_path.exists():
            raise FileNotFoundError(f"目标文件不存在：{input_path}")

        idapro = self._load_idapro()
        if self._active is not None:
            self.close_binary()

        if idapro.open_database(str(input_path), run_auto_analysis=wait_auto_analysis):
            raise RuntimeNotReadyError(f"打开数据库失败：{input_path}")

        if wait_auto_analysis:
            ida_auto = importlib.import_module("ida_auto")
            ida_auto.auto_wait()

        ida_nalt = importlib.import_module("ida_nalt")
        idaapi = importlib.import_module("idaapi")
        module = str(ida_nalt.get_root_filename() or input_path.name)
        idb_path = Path(str(importlib.import_module("idc").get_idb_path()))
        imagebase = hex(cast(int, idaapi.get_imagebase()))
        binary_kind = self._detect_binary_kind(input_path)
        analysis_domain = self._detect_analysis_domain(binary_kind)

        self._active = ActiveDatabase(
            input_path=input_path.resolve(),
            idb_path=idb_path.resolve(),
            module=module,
            binary_kind=binary_kind,
            analysis_domain=analysis_domain,
            imagebase=imagebase,
        )
        self._invalidate()
        logger.info("已打开数据库：{}", input_path)
        summary = self.current_binary_summary()
        if summary is None:
            raise RuntimeNotReadyError("数据库已打开，但无法构造摘要")
        return summary

    def close_binary(self) -> None:
        """关闭当前数据库。"""
        if self._active is None:
            return
        idapro = self._load_idapro()
        idapro.close_database()
        logger.info("已关闭数据库：{}", self._active.input_path)
        self._active = None
        self._invalidate()

    def ensure_binary(self) -> ActiveDatabase:
        """确保当前有激活数据库。"""
        if self._active is None:
            raise BinaryNotOpenError("当前没有打开任何二进制，请先调用 open_binary")
        return self._active

    def _detect_binary_kind(self, path: Path) -> BinaryKind:
        from .directory_analysis import detect_binary_kind

        return detect_binary_kind(path)

    def _detect_analysis_domain(self, binary_kind: BinaryKind) -> AnalysisDomain:
        if binary_kind in {"pe", "elf", "macho"}:
            return "native"
        return "unknown"

    def warmup(self, *, build_caches: bool, init_hexrays: bool) -> dict[str, object]:
        """预热核心子系统。"""
        self.ensure_binary()
        steps: list[dict[str, object]] = []

        if build_caches:
            _ = self.list_functions()
            _ = self.list_strings()
            _ = self.survey_binary()
            steps.append({"step": "build_caches", "ok": True})

        if init_hexrays:
            ida_hexrays = importlib.import_module("ida_hexrays")
            ok = bool(ida_hexrays.init_hexrays_plugin())
            step: dict[str, object] = {"step": "init_hexrays", "ok": ok}
            if not ok:
                step["error"] = "Hex-Rays 不可用"
            steps.append(step)

        return {"steps": steps}

    def health(self) -> dict[str, object]:
        """返回运行时健康状态。"""
        ready = self._active is not None
        active = self.current_binary_summary()
        decompiler_state = "unavailable"
        if ready:
            ida_hexrays = importlib.import_module("ida_hexrays")
            decompiler_state = "hexrays" if bool(ida_hexrays.init_hexrays_plugin()) else "asm_fallback"
        return {
            "runtime_ready": True,
            "binary_open": ready,
            "active": active,
            "capabilities": {
                "binary_kind": active["binary_kind"] if active else "unknown",
                "analysis_domain": active["analysis_domain"] if active else "unknown",
                "representations": ["hexrays", "asm_fallback"] if ready else [],
                "decompiler_state": decompiler_state,
            },
        }

    def list_functions(self) -> list[FunctionRecord]:
        """列出当前数据库中的函数。"""
        self.ensure_binary()
        if self._cache.functions is not None:
            return self._cache.functions

        ida_funcs = importlib.import_module("ida_funcs")
        idautils = importlib.import_module("idautils")
        ida_segment = importlib.import_module("ida_segment")
        idaapi = importlib.import_module("idaapi")

        results: list[FunctionRecord] = []
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if func is None:
                continue
            segment = idaapi.getseg(func.start_ea)
            results.append(
                {
                    "addr": hex(func.start_ea),
                    "name": str(ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)),
                    "size": cast(int, func.end_ea - func.start_ea),
                    "size_hex": hex(cast(int, func.end_ea - func.start_ea)),
                    "segment": str(ida_segment.get_segm_name(segment) if segment is not None else ""),
                }
            )

        self._cache.functions = results
        return results

    def resolve_function(self, query: str) -> FunctionRecord:
        """按地址或名称解析函数。"""
        functions = self.list_functions()
        normalized = query.strip()
        by_addr = next((item for item in functions if item["addr"].lower() == normalized.lower()), None)
        if by_addr is not None:
            return by_addr
        by_name = next((item for item in functions if item["name"] == normalized), None)
        if by_name is not None:
            return by_name
        raise ValueError(f"找不到函数：{query}")

    def list_strings(self) -> list[StringRecord]:
        """列出当前数据库中的字符串。"""
        self.ensure_binary()
        if self._cache.strings is not None:
            return self._cache.strings

        idautils = importlib.import_module("idautils")
        results: list[StringRecord] = []
        for item in idautils.Strings():
            results.append(
                {
                    "addr": hex(cast(int, item.ea)),
                    "length": len(str(item)),
                    "text": str(item),
                }
            )
        self._cache.strings = results
        return results

    def find_strings(self, pattern: str) -> list[StringRecord]:
        """按子串查找字符串。"""
        lowered = pattern.lower()
        return [item for item in self.list_strings() if lowered in item["text"].lower()]

    def read_bytes(self, addr: int, size: int) -> dict[str, object]:
        """读取字节。"""
        self.ensure_binary()
        ida_bytes = importlib.import_module("ida_bytes")
        data = ida_bytes.get_bytes(addr, size)
        if data is None:
            raise ValueError(f"读取失败：{hex(addr)} 大小 {size}")
        return {
            "addr": hex(addr),
            "size": size,
            "hex": data.hex(),
        }

    def disassemble_function(self, query: str, *, max_lines: int = 200) -> list[dict[str, str]]:
        """返回函数反汇编文本。"""
        record = self.resolve_function(query)
        if record["addr"] in self._cache.disassembly:
            return self._cache.disassembly[record["addr"]]

        ida_funcs = importlib.import_module("ida_funcs")
        ida_lines = importlib.import_module("ida_lines")
        idautils = importlib.import_module("idautils")
        func = ida_funcs.get_func(int(record["addr"], 16))
        if func is None:
            raise ValueError(f"函数不存在：{query}")

        lines: list[dict[str, str]] = []
        for index, item_ea in enumerate(idautils.FuncItems(func.start_ea)):
            if index >= max_lines:
                break
            raw_line = ida_lines.generate_disasm_line(item_ea, 0)
            text = ida_lines.tag_remove(raw_line).strip() if raw_line else ""
            lines.append({"addr": hex(cast(int, item_ea)), "text": " ".join(text.split())})

        self._cache.disassembly[record["addr"]] = lines
        return lines

    def _collect_call_edges(self, record: FunctionRecord) -> tuple[list[CallEdgeRecord], list[CallEdgeRecord]]:
        if record["addr"] in self._cache.callers and record["addr"] in self._cache.callees:
            return self._cache.callers[record["addr"]], self._cache.callees[record["addr"]]

        ida_funcs = importlib.import_module("ida_funcs")
        ida_name = importlib.import_module("ida_name")
        idaapi = importlib.import_module("idaapi")
        idautils = importlib.import_module("idautils")
        func = ida_funcs.get_func(int(record["addr"], 16))
        if func is None:
            raise ValueError(f"函数不存在：{record['name']}")

        callers: list[CallEdgeRecord] = []
        caller_seen: set[int] = set()
        for caller_site in idautils.CodeRefsTo(func.start_ea, False):
            caller_func = idaapi.get_func(caller_site)
            if caller_func is None or caller_func.start_ea in caller_seen:
                continue
            caller_seen.add(caller_func.start_ea)
            callers.append(
                {
                    "caller_addr": hex(cast(int, caller_func.start_ea)),
                    "caller_name": str(ida_funcs.get_func_name(caller_func.start_ea) or hex(cast(int, caller_func.start_ea))),
                    "callee_addr": record["addr"],
                    "callee_name": record["name"],
                    "source": "coderefs",
                }
            )

        callees: list[CallEdgeRecord] = []
        callee_seen: set[int] = set()
        for item_ea in idautils.FuncItems(func.start_ea):
            for target in idautils.CodeRefsFrom(item_ea, False):
                target_func = idaapi.get_func(target)
                callee_ea = cast(int, target_func.start_ea if target_func is not None else target)
                if callee_ea in callee_seen:
                    continue
                callee_seen.add(callee_ea)
                callees.append(
                    {
                        "caller_addr": record["addr"],
                        "caller_name": record["name"],
                        "callee_addr": hex(callee_ea),
                        "callee_name": str(
                            ida_funcs.get_func_name(callee_ea)
                            or ida_name.get_name(callee_ea)
                            or hex(callee_ea)
                        ),
                        "source": "coderefs",
                    }
                )

        self._cache.callers[record["addr"]] = callers
        self._cache.callees[record["addr"]] = callees
        return callers, callees

    def get_callers(self, query: str) -> list[CallEdgeRecord]:
        """返回调用当前函数的调用者。"""
        record = self.resolve_function(query)
        callers, _ = self._collect_call_edges(record)
        return callers

    def get_callees(self, query: str) -> list[CallEdgeRecord]:
        """返回当前函数调用的目标。"""
        record = self.resolve_function(query)
        _, callees = self._collect_call_edges(record)
        return callees

    def decompile_function(self, query: str) -> dict[str, object]:
        """返回函数最优高层表示。"""
        record = self.resolve_function(query)
        if record["addr"] in self._cache.decompile:
            return self._cache.decompile[record["addr"]]

        ida_hexrays = importlib.import_module("ida_hexrays")
        if bool(ida_hexrays.init_hexrays_plugin()):
            cfunc = ida_hexrays.decompile(int(record["addr"], 16))
            if cfunc is not None:
                result = {
                    "representation": "hexrays",
                    "language": "c",
                    "text": str(cfunc),
                    "warnings": [],
                }
                self._cache.decompile[record["addr"]] = result
                return result

        result = {
            "representation": "asm_fallback",
            "language": "asm",
            "text": "\n".join(line["text"] for line in self.disassemble_function(query)),
            "warnings": ["Hex-Rays 不可用，已回退到汇编文本"],
        }
        self._cache.decompile[record["addr"]] = result
        return result

    def survey_binary(self) -> dict[str, object]:
        """返回当前数据库的紧凑概览。"""
        self.ensure_binary()
        if self._cache.survey is not None:
            return self._cache.survey

        idaapi = importlib.import_module("idaapi")
        ida_entry = importlib.import_module("ida_entry")
        ida_segment = importlib.import_module("ida_segment")
        idautils = importlib.import_module("idautils")

        functions = self.list_functions()
        strings = self.list_strings()
        segments: list[dict[str, str]] = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg is None:
                continue
            segments.append(
                {
                    "name": str(ida_segment.get_segm_name(seg)),
                    "start": hex(cast(int, seg.start_ea)),
                    "end": hex(cast(int, seg.end_ea)),
                }
            )

        entrypoints: list[dict[str, object]] = []
        for index in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(index)
            entrypoints.append(
                {
                    "ordinal": ordinal,
                    "addr": hex(cast(int, ida_entry.get_entry(ordinal))),
                    "name": str(ida_entry.get_entry_name(ordinal)),
                }
            )

        interesting_functions = sorted(functions, key=lambda item: item["size"], reverse=True)[:10]
        interesting_strings = sorted(strings, key=lambda item: item["length"], reverse=True)[:10]
        summary = self.current_binary_summary()
        if summary is None:
            raise RuntimeNotReadyError("survey_binary 缺少激活数据库")

        self._cache.survey = {
            "metadata": summary,
            "statistics": {
                "function_count": len(functions),
                "string_count": len(strings),
                "segment_count": len(segments),
                "entrypoint_count": len(entrypoints),
            },
            "segments": segments,
            "entrypoints": entrypoints,
            "interesting_functions": interesting_functions,
            "interesting_strings": interesting_strings,
        }
        return self._cache.survey
