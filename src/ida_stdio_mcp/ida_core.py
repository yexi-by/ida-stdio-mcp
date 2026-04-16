"""项目自己的 IDA 访问层。

这里集中封装对 `ida_*` / `idautils` / `idc` 的访问。
设计目标不是追求花哨抽象，而是把所有 headless 能力收口到一层，
让外面的 MCP 工具层不再直接依赖分散的 IDA API。
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path

from .ida_bootstrap import ensure_ida_environment

ensure_ida_environment()

import ida_auto
import ida_bytes
import ida_dbg
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idd
import ida_idp
import ida_lines
import ida_loader
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from .models import AnalysisDomain, BinaryKind, JsonObject, JsonValue, ToolStatus

try:
    import ida_entry
except ImportError:  # pragma: no cover - IDA 环境里通常可用
    ida_entry = None  # type: ignore[assignment]

BADADDR = ida_idaapi.BADADDR
PE_SUFFIXES = {".exe", ".dll", ".sys"}
ELF_SUFFIXES = {".elf", ".so"}
MACHO_SUFFIXES = {".dylib", ".macho"}


class ToolEnvelope(dict[str, JsonValue]):
    """内部工具返回包装。

    这里使用字典而不是 dataclass，是为了直接复用到最终的 MCP 输出结构。
    """


class IdaCore:
    """纯 headless 的 IDA 访问层。"""

    def wait_auto_analysis(self) -> JsonObject:
        """等待自动分析结束。"""
        ida_auto.auto_wait()
        return {"waited": True}

    def capabilities(self) -> JsonObject:
        """返回当前数据库的能力矩阵。"""
        analysis_domain = self.get_analysis_domain()
        representations: list[str] = ["asm_fallback"]
        if analysis_domain == "managed":
            representations.insert(0, "il")
        if self.hexrays_available():
            representations.insert(0, "hexrays")
        catalogs: list[str] = ["local_types"]
        if analysis_domain == "managed":
            catalogs.append("managed_types")
        return {
            "binary_kind": self.get_binary_kind(),
            "analysis_domain": analysis_domain,
            "active_backend": analysis_domain,
            "representations": representations,
            "catalogs": catalogs,
            "callgraph_quality": "coderefs",
            "decompiler_state": "hexrays" if self.hexrays_available() else "asm_fallback",
            "managed_support": self._managed_support_matrix(),
        }

    def health(self) -> JsonObject:
        """返回当前数据库健康状态。"""
        return {
            "metadata": self.idb_metadata(),
            "processor": ida_idp.get_idp_name(),
            "has_hexrays": self.hexrays_available(),
            "is_auto_analysis_enabled": bool(ida_auto.is_auto_enabled()),
            "entry_count": len(self.entrypoints()),
            "segment_count": len(self.segments()),
            "capabilities": self.capabilities(),
            "debugger": self.debugger_health(),
        }

    def idb_metadata(self) -> JsonObject:
        """返回当前 IDB 元数据。"""
        input_path = Path(ida_nalt.get_input_file_path() or "")
        md5_bytes = ida_nalt.retrieve_input_file_md5()
        sha256_bytes = ida_nalt.retrieve_input_file_sha256()
        return {
            "path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or "",
            "input_path": str(input_path),
            "module": input_path.name,
            "processor": ida_ida.inf_get_procname(),
            "arch": str(8 * ida_ida.inf_get_app_bitness()),
            "base_address": hex(ida_nalt.get_imagebase()),
            "image_size": hex(max(0, ida_ida.inf_get_max_ea() - ida_ida.inf_get_min_ea())),
            "md5": md5_bytes.hex() if md5_bytes else "",
            "sha256": sha256_bytes.hex() if sha256_bytes else "",
            "binary_kind": self.get_binary_kind(),
            "analysis_domain": self.get_analysis_domain(),
        }

    def get_binary_kind(self) -> BinaryKind:
        """推断当前样本类型。"""
        file_type = ida_loader.get_file_type_name().lower()
        suffix = Path(ida_nalt.get_input_file_path() or "").suffix.lower()
        if "portable executable" in file_type or suffix in PE_SUFFIXES:
            return "pe"
        if "elf" in file_type or suffix in ELF_SUFFIXES:
            return "elf"
        if "mach-o" in file_type or suffix in MACHO_SUFFIXES:
            return "macho"
        return "unknown"

    def get_analysis_domain(self) -> AnalysisDomain:
        """推断当前分析域。"""
        file_type = ida_loader.get_file_type_name().lower()
        processor = ida_idp.get_idp_name().lower()
        if "net" in file_type or "cil" in file_type or processor in {"msil", "cli"}:
            return "managed"
        if processor:
            return "native"
        return "unknown"

    def segments(self) -> list[JsonObject]:
        """列出所有段。"""
        results: list[JsonObject] = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None:
                continue
            results.append(
                {
                    "name": ida_segment.get_segm_name(seg),
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": hex(max(0, seg.end_ea - seg.start_ea)),
                    "permissions": self._segment_permissions(seg.perm),
                }
            )
        return results

    def entrypoints(self) -> list[JsonObject]:
        """列出入口点。"""
        results: list[JsonObject] = []
        if ida_entry is None:
            return results
        for index in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(index)
            ea = ida_entry.get_entry(ordinal)
            if ea == BADADDR:
                continue
            results.append(
                {
                    "addr": hex(ea),
                    "name": ida_entry.get_entry_name(ordinal) or ida_name.get_name(ea) or hex(ea),
                    "ordinal": ordinal,
                }
            )
        return results

    def survey_binary(self) -> JsonObject:
        """返回综合二进制概览。"""
        functions = self.list_functions(limit=2000)
        strings = self.list_strings(limit=2000)
        segments = self.segments()
        interesting_functions: list[JsonObject] = []
        for item in functions[:15]:
            addr_text = item.get("addr")
            if not isinstance(addr_text, str):
                continue
            try:
                callees = self.get_callees(addr_text)
                xrefs = self.get_xrefs_to(addr_text)
            except Exception:
                callees = []
                xrefs = []
            interesting_functions.append(
                {
                    "addr": addr_text,
                    "name": item.get("name", ""),
                    "size": item.get("size", 0),
                    "xref_count": len(xrefs),
                    "callee_count": len(callees),
                    "type": self._classify_function(addr_text),
                    "signature": item.get("signature", ""),
                }
            )
        return {
            "metadata": self.idb_metadata(),
            "statistics": {
                "total_functions": len(functions),
                "named_functions": len([item for item in functions if not str(item.get("name", "")).startswith("sub_")]),
                "library_functions": len([item for item in functions if bool(item.get("is_library", False))]),
                "unnamed_functions": len([item for item in functions if str(item.get("name", "")).startswith("sub_")]),
                "total_strings": len(strings),
                "total_segments": len(segments),
            },
            "capabilities": self.capabilities(),
            "segments": segments,
            "entrypoints": self.entrypoints(),
            "interesting_strings": strings[:15],
            "interesting_functions": interesting_functions,
            "imports_by_category": self._categorize_imports(),
            "call_graph_summary": self._callgraph_summary(functions),
            "managed_summary": self.managed_summary(),
        }

    def list_functions(self, *, filter_text: str = "", offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """分页列出函数。"""
        lowered = filter_text.lower()
        analysis_domain = self.get_analysis_domain()
        results: list[JsonObject] = []
        for ea in idautils.Functions():
            func = idaapi.get_func(ea)
            if func is None:
                continue
            name = ida_funcs.get_func_name(ea) or hex(ea)
            if lowered and lowered not in name.lower() and lowered not in hex(ea):
                continue
            row: JsonObject = {
                "addr": hex(ea),
                "name": name,
                "size": func.end_ea - func.start_ea,
                "flags": int(func.flags),
                "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
                "signature": self.function_signature(ea),
            }
            if analysis_domain == "managed":
                identity = self.managed_method_identity(ea)
                if identity is not None:
                    row["managed_identity"] = identity
            results.append(row)
        return results[offset : offset + limit]

    def lookup_function(self, query: str) -> JsonObject:
        """按名字或地址定位函数。"""
        text = query.strip()
        if not text:
            raise ValueError("query 不能为空")
        if self._looks_like_address(text):
            ea = self.parse_address(text)
            func = idaapi.get_func(ea)
            if func is None:
                raise ValueError(f"找不到函数：{query}")
            return {"ea": func.start_ea, "name": ida_funcs.get_func_name(func.start_ea) or hex(func.start_ea)}
        partial: JsonObject | None = None
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea) or hex(ea)
            if name == text:
                return {"ea": ea, "name": name}
            if partial is None and text.lower() in name.lower():
                partial = {"ea": ea, "name": name}
        if partial is None:
            raise ValueError(f"找不到函数：{query}")
        return partial

    def get_function(self, query: str) -> JsonObject:
        """返回单个函数详情。"""
        match = self.lookup_function(query)
        ea = self._match_ea(match)
        name = self._match_name(match)
        func = self.require_function(ea)
        return {
            "addr": hex(func.start_ea),
            "name": name,
            "size": func.end_ea - func.start_ea,
            "prototype": self.function_signature(func.start_ea),
            "flags": int(func.flags),
            "comments": self.function_comments(func.start_ea),
            "callers": self.get_callers(hex(func.start_ea)),
            "callees": self.get_callees(hex(func.start_ea)),
        }

    def get_function_profile(self, query: str, *, include_asm: bool = True) -> JsonObject:
        """返回函数画像。"""
        match = self.lookup_function(query)
        ea = self._match_ea(match)
        func = self.require_function(ea)
        result = self._json_object(
            {
                "addr": hex(func.start_ea),
                "name": self._match_name(match),
                "prototype": self.function_signature(func.start_ea),
                "size": func.end_ea - func.start_ea,
                "strings": self.function_strings(func.start_ea),
                "constants": self.function_constants(func.start_ea),
                "callees": self.get_callees(hex(func.start_ea)),
                "callers": self.get_callers(hex(func.start_ea)),
                "xrefs": {
                    "to": self.get_xrefs_to(hex(func.start_ea)),
                    "from": self.get_xrefs_from(hex(func.start_ea)),
                },
                "comments": self.function_comments(func.start_ea),
                "basic_blocks": self.get_basic_blocks(hex(func.start_ea)),
            }
        )
        if include_asm:
            result["disassembly"] = self.disassemble_function(query)["text"]
        return result

    def analyze_functions(self, queries: list[str]) -> list[JsonObject]:
        """批量分析多个函数。"""
        return [self.get_function_profile(query) for query in queries]

    def function_signature(self, ea: int) -> str:
        """读取函数签名。"""
        return idc.get_type(ea) or (ida_funcs.get_func_name(ea) or hex(ea))

    def decompile_function(self, query: str) -> JsonObject:
        """返回统一高层表示。"""
        match = self.lookup_function(query)
        ea = self._match_ea(match)
        func = self.require_function(ea)
        func_name = self._match_name(match)
        signature = self.function_signature(func.start_ea)
        analysis_domain = self.get_analysis_domain()
        managed_identity = self.managed_method_identity(func.start_ea)
        warnings: list[str] = []
        if self.hexrays_available():
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc is not None:
                    return {
                        "status": "ok",
                        "addr": hex(func.start_ea),
                        "name": func_name,
                        "signature": signature,
                        "analysis_domain": analysis_domain,
                        "representation": "hexrays",
                        "language": "c",
                        "text": str(cfunc),
                        "source": "ida_hexrays",
                        "warnings": warnings,
                        "error": None,
                        "managed_identity": managed_identity,
                    }
            except Exception as exc:
                warnings.append(f"Hex-Rays 反编译失败，已降级：{exc}")
        representation = "il" if analysis_domain == "managed" else "asm_fallback"
        if representation == "il":
            warnings.append("当前样本属于托管/IL 域，暂未提供真正托管高层反编译，已返回 IL/反汇编级表示")
        return {
            "status": "degraded",
            "addr": hex(func.start_ea),
            "name": func_name,
            "signature": signature,
            "analysis_domain": analysis_domain,
            "representation": representation,
            "language": "il" if representation == "il" else "asm",
            "text": self.render_managed_method_view(func.start_ea) if representation == "il" else self.render_function_disassembly(func.start_ea),
            "source": "ida_lines_managed" if representation == "il" else "ida_lines",
            "warnings": warnings or ["当前不可用 Hex-Rays，已回退到汇编文本"],
            "error": None,
            "managed_identity": managed_identity,
        }

    def disassemble_function(self, query: str) -> JsonObject:
        """返回函数反汇编。"""
        match = self.lookup_function(query)
        ea = self._match_ea(match)
        func = self.require_function(ea)
        lines = self.disassembly_lines(func.start_ea)
        return {
            "addr": hex(func.start_ea),
            "name": self._match_name(match),
            "text": "\n".join(str(item.get("text", "")) for item in lines),
            "lines": lines,
        }

    def list_globals(self, *, filter_text: str = "", offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """列出全局符号。"""
        lowered = filter_text.lower()
        results: list[JsonObject] = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) is not None:
                continue
            if lowered and lowered not in name.lower() and lowered not in hex(ea):
                continue
            seg = ida_segment.getseg(ea)
            results.append(
                {
                    "addr": hex(ea),
                    "name": name,
                    "segment": ida_segment.get_segm_name(seg) if seg is not None else "",
                    "size": ida_bytes.get_item_size(ea),
                }
            )
        return results[offset : offset + limit]

    def list_imports(self, *, offset: int = 0, limit: int = 200) -> list[JsonObject]:
        """列出导入表。"""
        results: list[JsonObject] = []
        for index in range(ida_nalt.get_import_module_qty()):
            module_name = ida_nalt.get_import_module_name(index) or f"module_{index}"

            def callback(ea: int, name: str | None, ordinal: int) -> bool:
                results.append(
                    {
                        "addr": hex(ea),
                        "name": name or f"ord_{ordinal}",
                        "module": module_name,
                        "ordinal": ordinal,
                    }
                )
                return True

            ida_nalt.enum_import_names(index, callback)
        return results[offset : offset + limit]

    def query_imports(self, *, module: str = "", name_filter: str = "", offset: int = 0, limit: int = 200) -> list[JsonObject]:
        """按条件查询导入。"""
        module_text = module.lower()
        name_text = name_filter.lower()
        results: list[JsonObject] = []
        for item in self.list_imports(offset=0, limit=10_000):
            item_module = str(item.get("module", ""))
            item_name = str(item.get("name", ""))
            if module_text and module_text not in item_module.lower():
                continue
            if name_text and name_text not in item_name.lower():
                continue
            results.append(item)
        return results[offset : offset + limit]

    def get_xrefs_to(self, target: str) -> list[JsonObject]:
        """读取指向目标地址的 xref。"""
        ea = self.parse_address(target)
        return [
            {
                "addr": hex(ref.frm),
                "to": hex(ref.to),
                "type": self.xref_type_name(ref.type),
            }
            for ref in idautils.XrefsTo(ea)
        ]

    def get_xrefs_from(self, source: str) -> list[JsonObject]:
        """读取从源地址发出的 xref。"""
        ea = self.parse_address(source)
        return [
            {
                "addr": hex(ref.to),
                "from": hex(ref.frm),
                "type": self.xref_type_name(ref.type),
            }
            for ref in idautils.XrefsFrom(ea)
        ]

    def query_xrefs(self, *, from_query: str = "", to_query: str = "", xref_type: str = "") -> list[JsonObject]:
        """按条件过滤 xref。"""
        if from_query:
            items = self.get_xrefs_from(from_query)
        elif to_query:
            items = self.get_xrefs_to(to_query)
        else:
            raise ValueError("from_query 与 to_query 至少提供一个")
        if not xref_type:
            return items
        return [item for item in items if xref_type.lower() in str(item.get("type", "")).lower()]

    def get_xrefs_to_field(self, struct_name: str, field_name: str) -> list[JsonObject]:
        """读取结构体字段 xref。"""
        struct_id = int(idc.get_struc_id(struct_name))
        if struct_id in (-1, BADADDR):
            raise ValueError(f"找不到结构体：{struct_name}")
        member_offset = int(idc.get_member_offset(struct_id, field_name))
        if member_offset in (-1, BADADDR):
            raise ValueError(f"找不到字段：{struct_name}.{field_name}")
        member_id = int(idc.get_member_id(struct_id, member_offset))
        if member_id in (-1, BADADDR):
            raise ValueError(f"无法解析字段 ID：{struct_name}.{field_name}")
        return self.get_xrefs_to(hex(member_id))

    def get_callees(self, query: str) -> list[JsonObject]:
        """读取函数调用目标。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        edges: dict[int, JsonObject] = {}
        for item_ea in idautils.FuncItems(func.start_ea):
            edge_kind = self.callgraph_edge_kind(item_ea, func.start_ea)
            if edge_kind is None:
                continue
            for target in idautils.CodeRefsFrom(item_ea, 0):
                callee_func = idaapi.get_func(target)
                if callee_func is None and not self._is_external_call_target(target):
                    continue
                resolved = callee_func.start_ea if callee_func is not None else target
                if resolved in edges:
                    continue
                edges[resolved] = {
                    "addr": hex(resolved),
                    "from_addr": hex(func.start_ea),
                    "to_addr": hex(resolved),
                    "name": self.best_name(resolved),
                    "type": "internal" if callee_func is not None else "external",
                    "edge_kind": edge_kind,
                    "source": "coderefs",
                    "resolution": "function_start" if callee_func is not None else "direct_address",
                }
        return list(edges.values())

    def get_callers(self, query: str) -> list[JsonObject]:
        """读取函数调用者。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        callers: dict[int, JsonObject] = {}
        for caller_site in idautils.CodeRefsTo(func.start_ea, 0):
            caller_func = idaapi.get_func(caller_site)
            if caller_func is None or caller_func.start_ea in callers:
                continue
            edge_kind = self.callgraph_edge_kind(caller_site, caller_func.start_ea)
            if edge_kind is None:
                continue
            callers[caller_func.start_ea] = {
                "addr": hex(caller_func.start_ea),
                "from_addr": hex(caller_func.start_ea),
                "to_addr": hex(func.start_ea),
                "name": self.best_name(caller_func.start_ea),
                "type": "internal",
                "edge_kind": edge_kind,
                "source": "coderefs",
                "resolution": "function_start",
            }
        return list(callers.values())

    def get_basic_blocks(self, query: str) -> JsonObject:
        """读取基本块。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        flowchart = idaapi.FlowChart(func)
        blocks: list[JsonObject] = []
        edge_count = 0
        for block in flowchart:
            succs = [hex(succ.start_ea) for succ in block.succs()]
            preds = [hex(pred.start_ea) for pred in block.preds()]
            edge_count += len(succs)
            blocks.append({"start": hex(block.start_ea), "end": hex(block.end_ea), "succs": succs, "preds": preds})
        cyclomatic = edge_count - len(blocks) + 2 if blocks else 1
        return {"count": len(blocks), "cyclomatic_complexity": cyclomatic, "blocks": blocks}

    def list_strings(self, *, offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """分页列出字符串。"""
        results: list[JsonObject] = []
        strings = idautils.Strings()
        strings.setup()
        for item in strings:
            text = str(item)
            if not text:
                continue
            results.append(
                {
                    "addr": hex(int(item.ea)),
                    "string": text,
                    "length": len(text),
                    "xref_count": len(list(idautils.XrefsTo(int(item.ea)))),
                }
            )
        return results[offset : offset + limit]

    def find_strings(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """按子串搜索字符串。"""
        lowered = pattern.lower()
        matched = [item for item in self.list_strings(offset=0, limit=10_000) if lowered in str(item.get("string", "")).lower()]
        next_offset = offset + limit if offset + limit < len(matched) else None
        return {"data": matched[offset : offset + limit], "next_offset": next_offset}

    def search_regex(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """按正则搜索字符串。"""
        compiled = re.compile(pattern)
        matched = [item for item in self.list_strings(offset=0, limit=10_000) if compiled.search(str(item.get("string", "")))]
        next_offset = offset + limit if offset + limit < len(matched) else None
        return {"data": matched[offset : offset + limit], "next_offset": next_offset}

    def find_bytes(self, pattern: str, *, max_hits: int = 100) -> list[JsonObject]:
        """按字节模式搜索。"""
        current = ida_ida.inf_get_min_ea()
        end = ida_ida.inf_get_max_ea()
        results: list[JsonObject] = []
        while current != BADADDR and current < end and len(results) < max_hits:
            found = ida_bytes.find_bytes(
                pattern,
                current,
                range_end=end,
                flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
                radix=16,
            )
            if found == BADADDR:
                break
            results.append({"addr": hex(found), "pattern": pattern})
            current = found + 1
        return results

    def find_items(self, text: str, *, max_hits: int = 100) -> list[JsonObject]:
        """在字符串与函数名中做混合搜索。"""
        lowered = text.lower()
        results: list[JsonObject] = []
        for item in self.list_strings(offset=0, limit=10_000):
            if lowered in str(item.get("string", "")).lower():
                results.append({"kind": "string", **item})
                if len(results) >= max_hits:
                    return results
        for item in self.list_functions(filter_text=text, offset=0, limit=10_000):
            if lowered in str(item.get("name", "")).lower():
                results.append({"kind": "function", **item})
                if len(results) >= max_hits:
                    return results
        return results

    def query_instructions(self, mnemonic: str, *, max_hits: int = 100) -> list[JsonObject]:
        """按助记符查询指令。"""
        results: list[JsonObject] = []
        for ea in idautils.Heads():
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                continue
            current = idc.print_insn_mnem(ea)
            if current.lower() != mnemonic.lower():
                continue
            results.append({"addr": hex(ea), "mnem": current, "text": self.line_text(ea)})
            if len(results) >= max_hits:
                break
        return results

    def read_bytes(self, addrs: list[str], *, size: int = 16) -> list[JsonObject]:
        """读取字节。"""
        results: list[JsonObject] = []
        for addr in addrs:
            ea = self.parse_address(addr)
            data = ida_bytes.get_bytes(ea, size) or b""
            results.append({"addr": hex(ea), "size": len(data), "hex": data.hex()})
        return results

    def read_ints(self, queries: list[JsonObject]) -> list[JsonObject]:
        """读取整数。"""
        results: list[JsonObject] = []
        for query in queries:
            addr_text = query.get("addr")
            size = int(query.get("size", 4))
            signed = bool(query.get("signed", False))
            if not isinstance(addr_text, str):
                raise ValueError("read_ints 的 addr 必须是字符串")
            ea = self.parse_address(addr_text)
            raw = ida_bytes.get_bytes(ea, size) or b""
            value = int.from_bytes(raw, byteorder="little", signed=signed)
            results.append({"addr": hex(ea), "size": size, "signed": signed, "value": value})
        return results

    def read_strings(self, addrs: list[str], *, max_length: int = 512) -> list[JsonObject]:
        """读取字符串。"""
        results: list[JsonObject] = []
        for addr in addrs:
            ea = self.parse_address(addr)
            raw = idc.get_strlit_contents(ea, max_length, idc.STRTYPE_C)
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else ""
            results.append({"addr": hex(ea), "string": text})
        return results

    def read_global_values(self, addrs: list[str], *, size: int = 8) -> list[JsonObject]:
        """读取全局值。"""
        return self.read_ints([{"addr": addr, "size": size, "signed": False} for addr in addrs])

    def get_stack_frame(self, query: str) -> JsonObject:
        """读取栈帧。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        frame_id = int(idc.get_frame_id(func.start_ea))
        if frame_id in (-1, BADADDR):
            return {"size": 0, "members": []}
        members: list[JsonObject] = []
        for member_offset, member_name, member_size in idautils.StructMembers(frame_id):
            members.append(
                {
                    "name": str(member_name),
                    "offset": int(member_offset),
                    "size": int(member_size),
                }
            )
        return {"size": int(idc.get_frame_size(func.start_ea)), "members": members}

    def read_struct(self, struct_name: str) -> JsonObject:
        """读取结构体。"""
        struct_id = int(idc.get_struc_id(struct_name))
        if struct_id in (-1, BADADDR):
            type_row = self.inspect_type(struct_name)
            kind = type_row.get("kind")
            if kind in {"udt", "managed_type"}:
                return {
                    "name": struct_name,
                    "size": None,
                    "members": type_row.get("members", []),
                    "catalog": type_row.get("catalog", "local_types"),
                    "source": type_row.get("source", "ida_typeinf"),
                }
            raise ValueError(f"找不到结构体：{struct_name}")
        members: list[JsonObject] = []
        for member_offset, member_name, member_size in idautils.StructMembers(struct_id):
            members.append(
                {
                    "name": str(member_name),
                    "offset": int(member_offset),
                    "size": int(member_size),
                }
            )
        return {"name": struct_name, "size": int(idc.get_struc_size(struct_id)), "members": members}

    def search_structs(self, filter_text: str = "") -> list[JsonObject]:
        """搜索结构体。"""
        lowered = filter_text.lower()
        results: list[JsonObject] = []
        seen_names: set[str] = set()
        for _, struct_id, name in idautils.Structs():
            struct_name = str(name)
            if lowered and lowered not in struct_name.lower():
                continue
            member_count = len(list(idautils.StructMembers(struct_id)))
            results.append({"name": struct_name, "size": int(idc.get_struc_size(struct_id)), "member_count": member_count, "source": "ida_structs"})
            seen_names.add(struct_name)
        for row in self.query_types(filter_text):
            kind = row.get("kind")
            name = row.get("name")
            members = row.get("members")
            if kind not in {"udt", "managed_type"} or not isinstance(name, str) or name in seen_names:
                continue
            member_count = len(members) if isinstance(members, list) else 0
            results.append(
                {
                    "name": name,
                    "size": None,
                    "member_count": member_count,
                    "source": row.get("source", "ida_typeinf"),
                    "catalog": row.get("catalog", "local_types"),
                }
            )
            seen_names.add(name)
        return results

    def query_types(self, filter_text: str = "") -> list[JsonObject]:
        """查询本地类型目录。"""
        lowered = filter_text.lower()
        results: list[JsonObject] = []
        for ordinal in range(1, ida_typeinf.get_ordinal_limit()):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(None, ordinal):
                continue
            raw_name = tif.get_type_name()
            name = raw_name if isinstance(raw_name, str) else ""
            if not name or (lowered and lowered not in name.lower()):
                continue
            results.append(self._type_row(name, tif))
        if self.get_analysis_domain() == "managed":
            results.extend(self.managed_types(filter_text=filter_text))
        return results

    def inspect_type(self, name: str) -> JsonObject:
        """读取单个类型。"""
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            if self.get_analysis_domain() == "managed":
                for row in self.managed_types(filter_text=name):
                    row_name = row.get("name")
                    full_name = row.get("declaration_or_signature")
                    if row_name == name or full_name == name:
                        return row
            raise ValueError(f"找不到类型：{name}")
        return self._type_row(name, tif)

    def export_functions(
        self,
        *,
        queries: list[str] | None = None,
        format_name: str = "json",
        limit: int = 1000,
    ) -> list[JsonObject]:
        """导出函数信息。

        这里保留 tool 层需要的三种视图：
        - `json`：富字段结构化导出，适合 AI/批处理继续消费
        - `c_header`：把函数原型拼成近似头文件
        - `prototypes`：只关心签名摘要
        """
        target_queries = self._export_function_targets(queries=queries, limit=limit)
        exported: list[JsonObject] = []
        for query in target_queries:
            match = self.lookup_function(query)
            addr_value = hex(self._match_ea(match))
            name_value = self._match_name(match)
            profile = self.get_function(addr_value)
            decompile = self.decompile_function(addr_value)
            prototype = self.function_prototype(self.parse_address(addr_value))
            signature = self.function_signature(self.parse_address(addr_value))
            row: JsonObject = {
                "addr": addr_value,
                "name": name_value,
                "size": profile.get("size"),
                "prototype": prototype,
                "signature": signature,
                "representation": "c_prototype" if prototype else "symbol_only",
                "source": "ida_typeinf" if prototype else "ida_name",
            }
            if format_name == "json":
                row["asm"] = self.render_function_disassembly(self.parse_address(addr_value))
                row["code"] = decompile.get("text")
                row["decompile_status"] = decompile.get("status")
                row["decompile_representation"] = decompile.get("representation")
                row["warnings"] = decompile.get("warnings")
                row["xrefs"] = {
                    "to": self.get_xrefs_to(addr_value),
                    "from": self.get_xrefs_from(addr_value),
                }
                row["stack_frame"] = self.get_stack_frame(addr_value)
            exported.append(row)

        if format_name == "c_header":
            lines = ["// Auto-generated by ida-stdio-mcp", ""]
            for item in exported:
                prototype = item.get("prototype")
                if isinstance(prototype, str) and prototype:
                    lines.append(prototype.rstrip(";") + ";")
            return [{"format": "c_header", "content": "\n".join(lines), "count": len(exported)}]

        if format_name == "prototypes":
            functions: list[JsonObject] = []
            for item in exported:
                signature = item.get("signature")
                if not isinstance(signature, str) or not signature:
                    continue
                functions.append(
                    {
                        "addr": item.get("addr"),
                        "name": item.get("name", ""),
                        "prototype": item.get("prototype") or signature,
                        "signature": signature,
                        "representation": item.get("representation", "symbol_only"),
                        "source": item.get("source", "ida_name"),
                    }
                )
            return [{"format": "prototypes", "functions": functions}]

        return [{"format": "json", "functions": exported}]

    def build_callgraph(self, roots: list[str], *, max_depth: int = 3) -> JsonObject:
        """构建调用图。"""
        queue: list[tuple[str, int]] = [(root, 0) for root in roots]
        visited: set[str] = set()
        nodes: dict[str, JsonObject] = {}
        edges: list[JsonObject] = []
        externals: dict[str, JsonObject] = {}
        while queue:
            query, depth = queue.pop(0)
            match = self.lookup_function(query)
            addr_text = hex(self._match_ea(match))
            if addr_text in visited:
                continue
            visited.add(addr_text)
            nodes[addr_text] = {"addr": addr_text, "name": self._match_name(match)}
            if depth >= max_depth:
                continue
            for edge in self.get_callees(addr_text):
                edges.append(edge)
                to_addr = edge.get("to_addr")
                if isinstance(to_addr, str):
                    if str(edge.get("type")) == "internal":
                        queue.append((to_addr, depth + 1))
                    else:
                        externals[to_addr] = {
                            "addr": to_addr,
                            "name": edge.get("name"),
                            "type": "external",
                        }
        return {
            "nodes": list(nodes.values()),
            "edges": edges,
            "max_depth": max_depth,
            "external_targets": list(externals.values()),
        }

    def analyze_function(self, query: str, *, include_asm: bool = False) -> JsonObject:
        """函数级综合分析。"""
        profile = self.get_function_profile(query, include_asm=include_asm)
        profile["decompile"] = self.decompile_function(query)
        return profile

    def analyze_component(self, root_query: str, *, max_depth: int = 2, include_asm: bool = False) -> JsonObject:
        """组件级综合分析。"""
        return {
            "root": self.analyze_function(root_query, include_asm=include_asm),
            "internal_call_graph": self.build_callgraph([root_query], max_depth=max_depth),
        }

    def trace_data_flow(self, addr: str, *, direction: str = "both", max_depth: int = 5) -> JsonObject:
        """按函数关系和 xref 图做增强版轻量数据流追踪。"""
        if direction not in {"forward", "backward", "both"}:
            raise ValueError(f"direction 必须为 forward/backward/both，当前为：{direction}")

        start_ea = self.parse_address(addr)
        max_depth = max(1, min(max_depth, 20))

        visited: set[int] = {start_ea}
        queue: deque[tuple[int, int]] = deque([(start_ea, 0)])
        nodes: list[JsonObject] = []
        edges: list[JsonObject] = []
        depth_reached = 0
        expanded_functions: set[int] = set()

        while queue and len(nodes) < 256:
            ea, depth = queue.popleft()
            depth_reached = max(depth_reached, depth)
            func = idaapi.get_func(ea)
            is_function_root = func is not None and func.start_ea == ea
            node_type = "function" if is_function_root else ("code" if ida_bytes.is_code(ida_bytes.get_flags(ea)) else "data")
            nodes.append(
                {
                    "addr": hex(ea),
                    "name": ida_name.get_name(ea) or None,
                    "func": ida_funcs.get_func_name(func.start_ea) if func is not None else None,
                    "instruction": self.line_text(ea) if idaapi.is_loaded(ea) else None,
                    "type": node_type,
                    "depth": depth,
                }
            )

            if depth >= max_depth:
                continue

            next_refs: list[tuple[int, int, str, int, bool]] = []
            if is_function_root and ea not in expanded_functions:
                expanded_functions.add(ea)
                if direction in {"forward", "both"}:
                    for edge in self.get_callees(hex(ea)):
                        to_addr = edge.get("to_addr")
                        if isinstance(to_addr, str):
                            target_ea = self.parse_address(to_addr)
                            next_refs.append((ea, target_ea, "forward", ida_xref.fl_CN, True))
                    for data_ref in self._function_data_refs(ea):
                        target_value = data_ref.get("to_addr")
                        if isinstance(target_value, str):
                            target_ea = self.parse_address(target_value)
                            next_refs.append((ea, target_ea, "forward", ida_xref.dr_R, False))
                if direction in {"backward", "both"}:
                    for edge in self.get_callers(hex(ea)):
                        from_addr = edge.get("from_addr")
                        if isinstance(from_addr, str):
                            source_ea = self.parse_address(from_addr)
                            next_refs.append((source_ea, ea, "backward", ida_xref.fl_CN, True))
            else:
                if direction in {"forward", "both"}:
                    next_refs.extend((ea, ref.to, "forward", ref.type, ref.iscode) for ref in idautils.XrefsFrom(ea, 0))
                if direction in {"backward", "both"}:
                    next_refs.extend((ref.frm, ea, "backward", ref.type, ref.iscode) for ref in idautils.XrefsTo(ea, 0))

            for from_ea, to_ea, edge_direction, xref_type, is_code_xref in next_refs:
                edges.append(
                    {
                        "from": hex(from_ea),
                        "to": hex(to_ea),
                        "direction": edge_direction,
                        "type": "code" if is_code_xref else "data",
                        "xref_type": self.xref_type_name(int(xref_type)),
                        "edge_kind": self.edge_kind(from_ea) if is_code_xref else "data_ref",
                        "source": "xrefs",
                        "resolution": "direct",
                        "from_name": ida_name.get_name(from_ea) or None,
                        "to_name": ida_name.get_name(to_ea) or None,
                    }
                )
                target = to_ea if edge_direction == "forward" else from_ea
                if target not in visited and len(visited) < 512:
                    visited.add(target)
                    queue.append((target, depth + 1))

        edge_kind_histogram: dict[str, int] = defaultdict(int)
        xref_histogram: dict[str, int] = defaultdict(int)
        for edge in edges:
            edge_kind = edge.get("edge_kind")
            xref_name = edge.get("xref_type")
            if isinstance(edge_kind, str):
                edge_kind_histogram[edge_kind] += 1
            if isinstance(xref_name, str):
                xref_histogram[xref_name] += 1

        return {
            "start": hex(start_ea),
            "direction": direction,
            "depth_reached": depth_reached,
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "reachable_functions": sorted(
                    {
                        str(node.get("func"))
                        for node in nodes
                        if isinstance(node.get("func"), str) and str(node.get("func"))
                    }
                ),
                "reachable_data_items": len([node for node in nodes if node.get("type") == "data"]),
                "edge_kind_histogram": dict(edge_kind_histogram),
                "xref_type_histogram": dict(xref_histogram),
            },
        }

    def convert_integer(self, value: str | int, *, width: int = 8, signed: bool = False) -> JsonObject:
        """做整数与字节序转换。"""
        integer = int(value, 0) if isinstance(value, str) else value
        byte_width = max(1, width)
        blob = int(integer).to_bytes(byte_width, byteorder="little", signed=signed)
        mask = (1 << (byte_width * 8)) - 1
        return {
            "input": value,
            "int": integer,
            "hex": hex(integer & mask),
            "little_endian_hex": blob.hex(),
            "big_endian_hex": blob[::-1].hex(),
            "signed": signed,
            "width": width,
        }

    def set_comments(self, items: list[JsonObject], *, append: bool = False) -> list[JsonObject]:
        """设置或追加注释。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            comment_text = item.get("comment")
            if not isinstance(addr_text, str) or not isinstance(comment_text, str):
                raise ValueError("set_comments 的 addr/comment 必须为字符串")
            repeatable = bool(item.get("repeatable", False))
            ea = self.parse_address(addr_text)
            final_comment = comment_text
            if append:
                existing = ida_bytes.get_cmt(ea, repeatable) or ""
                final_comment = f"{existing}\n{comment_text}".strip() if existing else comment_text
            if not ida_bytes.set_cmt(ea, final_comment, repeatable):
                raise RuntimeError(f"设置注释失败：{addr_text}")
            results.append({"addr": hex(ea)})
        return results

    def rename_symbols(self, items: list[JsonObject]) -> list[JsonObject]:
        """批量重命名。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            name_text = item.get("name")
            if not isinstance(addr_text, str) or not isinstance(name_text, str):
                raise ValueError("rename_symbols 的 addr/name 必须为字符串")
            ea = self.parse_address(addr_text)
            if not ida_name.set_name(ea, name_text, ida_name.SN_NOWARN):
                raise RuntimeError(f"重命名失败：{addr_text} -> {name_text}")
            results.append({"addr": hex(ea), "name": name_text})
        return results

    def patch_bytes(self, items: list[JsonObject]) -> list[JsonObject]:
        """直接写入字节。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            hex_text = item.get("hex")
            if not isinstance(addr_text, str) or not isinstance(hex_text, str):
                raise ValueError("patch_bytes 的 addr/hex 必须为字符串")
            ea = self.parse_address(addr_text)
            blob = bytes.fromhex(hex_text)
            ida_bytes.patch_bytes(ea, blob)
            written = ida_bytes.get_bytes(ea, len(blob)) or b""
            if written != blob:
                raise RuntimeError(f"写入字节失败：{addr_text}")
            results.append({"addr": hex(ea), "size": len(blob)})
        return results

    def write_ints(self, items: list[JsonObject]) -> list[JsonObject]:
        """按整数写入。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            value = item.get("value")
            size = int(item.get("size", 4))
            signed = bool(item.get("signed", False))
            if not isinstance(addr_text, str) or not isinstance(value, int):
                raise ValueError("write_ints 的 addr 必须为字符串，value 必须为整数")
            blob = value.to_bytes(size, byteorder="little", signed=signed)
            ea = self.parse_address(addr_text)
            ida_bytes.patch_bytes(ea, blob)
            written = ida_bytes.get_bytes(ea, len(blob)) or b""
            if written != blob:
                raise RuntimeError(f"写入整数失败：{addr_text}")
            results.append({"addr": hex(ea), "size": size, "value": value})
        return results

    def define_function(self, addrs: list[str]) -> list[JsonObject]:
        """定义函数。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not ida_funcs.add_func(ea):
                raise RuntimeError(f"定义函数失败：{addr_text}")
            results.append({"addr": hex(ea)})
        return results

    def define_code(self, addrs: list[str]) -> list[JsonObject]:
        """把地址定义为代码。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            insn = ida_ua.insn_t()
            size = ida_ua.create_insn(ea, insn)
            if size <= 0:
                raise RuntimeError(f"定义代码失败：{addr_text}")
            results.append({"addr": hex(ea), "size": size})
        return results

    def undefine_items(self, addrs: list[str]) -> list[JsonObject]:
        """取消定义。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            size = ida_bytes.get_item_size(ea)
            if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
                raise RuntimeError(f"取消定义失败：{addr_text}")
            results.append({"addr": hex(ea), "size": size})
        return results

    def declare_types(self, declarations: list[str]) -> list[JsonObject]:
        """把 C 声明写入本地类型库。"""
        results: list[JsonObject] = []
        for declaration in declarations:
            text = declaration.strip()
            if not text:
                raise ValueError("declare_types 里存在空声明")
            errors = int(idc.parse_decls(text, 0))
            if errors != 0:
                raise RuntimeError(f"类型声明解析失败：{text}")
            parsed_name = self._extract_declared_type_name(text)
            row: JsonObject = {"declaration": text}
            if parsed_name is not None:
                row["name"] = parsed_name
            results.append(row)
        return results

    def upsert_enum(self, items: list[JsonObject]) -> list[JsonObject]:
        """创建或更新枚举。"""
        results: list[JsonObject] = []
        for item in items:
            name_text = item.get("name")
            members = item.get("members")
            if not isinstance(name_text, str) or not isinstance(members, list):
                raise ValueError("upsert_enum 的 name 必须为字符串，members 必须为列表")
            enum_id = int(idc.get_enum(name_text))
            if enum_id == BADADDR:
                enum_id = int(idc.add_enum(BADADDR, name_text, 0))
            if enum_id == BADADDR:
                raise RuntimeError(f"创建枚举失败：{name_text}")
            for member in members:
                if not isinstance(member, dict):
                    continue
                member_name = member.get("name")
                member_value = member.get("value")
                if isinstance(member_name, str) and isinstance(member_value, int):
                    idc.add_enum_member(enum_id, member_name, member_value, BADADDR)
            results.append({"name": name_text})
        return results

    def set_types(self, items: list[JsonObject]) -> list[JsonObject]:
        """设置类型。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            type_text = item.get("type")
            if not isinstance(addr_text, str) or not isinstance(type_text, str):
                raise ValueError("set_types 的 addr/type 必须为字符串")
            ea = self.parse_address(addr_text)
            if idc.SetType(ea, type_text) is None:
                raise RuntimeError(f"设置类型失败：{addr_text}")
            results.append({"addr": hex(ea), "type": type_text})
        return results

    def apply_types(self, items: list[JsonObject]) -> list[JsonObject]:
        """批量应用类型。"""
        return self.set_types(items)

    def infer_types(self, queries: list[str]) -> list[JsonObject]:
        """推断地址上的可能类型并尽量写回。"""
        results: list[JsonObject] = []
        for query in queries:
            ea = self.parse_address(query)
            func = idaapi.get_func(ea)
            if func is not None:
                prototype = self.function_prototype(func.start_ea)
                if prototype is not None:
                    results.append(
                        {
                            "addr": hex(func.start_ea),
                            "inferred_type": prototype,
                            "method": "function_prototype",
                            "confidence": "high",
                            "applied": False,
                        }
                    )
                    continue

            string_decl = self._string_literal_declaration(ea)
            if string_decl is not None:
                applied = self._try_apply_decl(ea, string_decl)
                results.append(
                    {
                        "addr": hex(ea),
                        "inferred_type": string_decl,
                        "method": "string_literal",
                        "confidence": "high",
                        "applied": applied,
                    }
                )
                continue

            pointer_guess = self._infer_pointer_type(ea)
            if pointer_guess is not None:
                results.append(pointer_guess)
                continue

            pointer_chain_guess = self._infer_pointer_chain_type(ea)
            if pointer_chain_guess is not None:
                results.append(pointer_chain_guess)
                continue

            target_type_guess = self._infer_pointed_target_type(ea)
            if target_type_guess is not None:
                results.append(target_type_guess)
                continue

            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.guess_tinfo(tif, ea) > 0 and not tif.empty():
                applied = bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))
                results.append(
                    {
                        "addr": hex(ea),
                        "inferred_type": self._print_tinfo(tif),
                        "method": "guess_tinfo",
                        "confidence": "high",
                        "applied": applied,
                    }
                )
                continue

            if ida_nalt.get_tinfo(tif, ea) and not tif.empty():
                results.append(
                    {
                        "addr": hex(ea),
                        "inferred_type": self._print_tinfo(tif),
                        "method": "existing",
                        "confidence": "high",
                        "applied": False,
                    }
                )
                continue

            size = ida_bytes.get_item_size(ea)
            fallback = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size)
            if fallback is None:
                fallback = f"uint8_t[{size}]" if size > 0 else "uint8_t"
            applied = idc.SetType(ea, fallback) is not None
            results.append(
                {
                    "addr": hex(ea),
                    "inferred_type": fallback,
                    "method": "size_based",
                    "confidence": "low",
                    "applied": applied,
                }
            )
        return results

    def declare_stack_variables(self, items: list[JsonObject]) -> list[JsonObject]:
        """声明函数栈变量。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            name_text = item.get("name")
            type_text = item.get("ty") if isinstance(item.get("ty"), str) else item.get("type")
            offset_value = item.get("offset")
            if not isinstance(addr_text, str) or not isinstance(name_text, str) or not isinstance(type_text, str):
                raise ValueError("declare_stack_variables 的 addr/name/type 必须为字符串")
            if not isinstance(offset_value, (int, str)):
                raise ValueError("declare_stack_variables 的 offset 必须为整数或字符串")
            func = self.require_function(self.parse_address(addr_text))
            tif = self._parse_type_tinfo(type_text)
            offset = self._parse_signed_int(offset_value)
            if not ida_frame.define_stkvar(func, name_text, offset, tif):
                raise RuntimeError(f"定义栈变量失败：{addr_text} {name_text}")
            results.append({"addr": hex(func.start_ea), "name": name_text, "offset": offset, "type": type_text})
        return results

    def delete_stack_variables(self, items: list[JsonObject]) -> list[JsonObject]:
        """删除函数栈变量。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            name_text = item.get("name")
            if not isinstance(addr_text, str) or not isinstance(name_text, str):
                raise ValueError("delete_stack_variables 的 addr/name 必须为字符串")
            func = self.require_function(self.parse_address(addr_text))
            frame_tif = ida_typeinf.tinfo_t()
            if not ida_frame.get_func_frame(frame_tif, func):
                raise RuntimeError(f"无法获取函数栈帧：{addr_text}")
            index, udm = frame_tif.get_udm(name_text)
            if udm is None:
                raise RuntimeError(f"找不到栈变量：{name_text}")
            tid = frame_tif.get_udm_tid(index)
            if ida_frame.is_special_frame_member(tid):
                raise RuntimeError(f"禁止删除特殊栈帧成员：{name_text}")
            udm_info = ida_typeinf.udm_t()
            if not frame_tif.get_udm_by_tid(udm_info, tid):
                raise RuntimeError(f"无法读取栈变量信息：{name_text}")
            start_offset = udm_info.offset // 8
            end_offset = start_offset + (udm_info.size // 8)
            if ida_frame.is_funcarg_off(func, start_offset):
                raise RuntimeError(f"禁止删除参数成员：{name_text}")
            if not ida_frame.delete_frame_members(func, start_offset, end_offset):
                raise RuntimeError(f"删除栈变量失败：{name_text}")
            results.append({"addr": hex(func.start_ea), "name": name_text})
        return results

    def patch_assembly(self, items: list[JsonObject]) -> list[JsonObject]:
        """按汇编文本打补丁。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            asm_text = item.get("asm")
            if not isinstance(addr_text, str) or not isinstance(asm_text, str):
                raise ValueError("patch_assembly 的 addr/asm 必须为字符串")
            ea = self.parse_address(addr_text)
            current_ea = ea
            for asm_line in [segment.strip() for segment in asm_text.split(";") if segment.strip()]:
                assembled = idautils.Assemble(current_ea, asm_line)
                if not isinstance(assembled, tuple) or len(assembled) != 2:
                    raise RuntimeError(f"汇编失败：{asm_line}")
                assembled_ok, blob = assembled
                if not assembled_ok or not isinstance(blob, (bytes, bytearray)):
                    raise RuntimeError(f"汇编失败：{asm_line}")
                patch_blob = bytes(blob)
                ida_bytes.patch_bytes(current_ea, patch_blob)
                written = ida_bytes.get_bytes(current_ea, len(patch_blob)) or b""
                if written != patch_blob:
                    raise RuntimeError(f"补丁写入失败：{hex(current_ea)}")
                current_ea += len(blob)
            results.append({"addr": hex(ea), "size": current_ea - ea, "asm": asm_text})
        return results

    def evaluate_python(self, code: str) -> JsonObject:
        """执行 Python 代码。"""
        local_scope: dict[str, object] = {}
        try:
            value = eval(code, {}, local_scope)
            return {"mode": "eval", "value": self.jsonify(value)}
        except SyntaxError:
            exec(code, {}, local_scope)
            return {"mode": "exec", "locals": {key: self.jsonify(value) for key, value in local_scope.items()}}

    def execute_python_file(self, path: str) -> JsonObject:
        """执行 Python 文件。"""
        return self.evaluate_python(Path(path).read_text(encoding="utf-8"))

    def debug_start(self, path: str = "") -> ToolEnvelope:
        """启动调试会话。"""
        target = path or (ida_nalt.get_input_file_path() or "")
        if not target:
            return {"status": "unsupported", "data": {"reason": "当前没有可调试目标"}, "warnings": ["请显式提供 path"]}
        ok = bool(ida_dbg.start_process(target, "", ""))
        backend_ready = ida_idd.get_dbg() is not None
        session_active = ida_dbg.get_process_state() != -1
        if ok and backend_ready and session_active:
            return {
                "status": "ok",
                "data": {"started": True, "path": target, "backend_available": True, "session_active": True},
                "warnings": [],
            }
        if ok:
            return {
                "status": "degraded",
                "data": {
                    "started": True,
                    "path": target,
                    "backend_available": backend_ready,
                    "session_active": session_active,
                },
                "warnings": ["调试进程已尝试启动，但调试后端或会话状态未完全就绪"],
            }
        return {
            "status": "unsupported",
            "data": {"started": False, "path": target, "backend_available": backend_ready, "session_active": session_active},
            "warnings": ["当前环境未能启动调试进程"],
        }

    def debug_exit(self) -> ToolEnvelope:
        """退出调试。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        ida_dbg.exit_process()
        return {"status": "ok", "data": {"exited": True}, "warnings": []}

    def debug_continue(self) -> ToolEnvelope:
        """继续执行。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        ida_dbg.continue_process()
        return {"status": "ok", "data": {"continued": True}, "warnings": []}

    def debug_run_to(self, addr: str) -> ToolEnvelope:
        """运行到指定地址。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        ok = bool(ida_dbg.request_run_to(self.parse_address(addr)))
        return {"status": "ok" if ok else "unsupported", "data": {"requested": ok, "addr": addr}, "warnings": [] if ok else ["request_run_to 失败"]}

    def debug_step_into(self) -> ToolEnvelope:
        """单步进入。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        ida_dbg.step_into()
        return {"status": "ok", "data": {"step": "into"}, "warnings": []}

    def debug_step_over(self) -> ToolEnvelope:
        """单步越过。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        ida_dbg.step_over()
        return {"status": "ok", "data": {"step": "over"}, "warnings": []}

    def debug_breakpoints(self) -> list[JsonObject]:
        """列出断点。"""
        results: list[JsonObject] = []
        for index in range(ida_dbg.get_bpt_qty()):
            bpt = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(index, bpt):
                results.append({"addr": hex(bpt.ea), "enabled": bool(bpt.enabled), "size": bpt.size})
        return results

    def debug_add_breakpoints(self, addrs: list[str]) -> list[JsonObject]:
        """添加断点。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not ida_dbg.add_bpt(ea):
                raise RuntimeError(f"添加断点失败：{addr_text}")
            results.append({"addr": hex(ea)})
        return results

    def debug_delete_breakpoints(self, addrs: list[str]) -> list[JsonObject]:
        """删除断点。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not ida_dbg.del_bpt(ea):
                raise RuntimeError(f"删除断点失败：{addr_text}")
            results.append({"addr": hex(ea)})
        return results

    def debug_toggle_breakpoints(self, items: list[JsonObject]) -> list[JsonObject]:
        """启停断点。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            enabled = bool(item.get("enabled", True))
            if not isinstance(addr_text, str):
                raise ValueError("debug_toggle_breakpoints 的 addr 必须为字符串")
            ea = self.parse_address(addr_text)
            if not ida_dbg.exist_bpt(ea):
                raise RuntimeError(f"找不到断点：{addr_text}")
            if not idaapi.enable_bpt(ea, enabled):
                raise RuntimeError(f"更新断点失败：{addr_text}")
            results.append({"addr": hex(ea), "enabled": enabled})
        return results

    def debug_registers(self, *, thread_id: int | None = None, names: list[str] | None = None) -> JsonObject:
        """读取寄存器。"""
        if ida_dbg.get_process_state() == -1:
            raise RuntimeError("当前没有活动调试会话")
        current_thread = thread_id if thread_id is not None else int(ida_dbg.get_current_thread())
        debugger = ida_idd.get_dbg()
        if debugger is None:
            raise RuntimeError("当前没有可用调试器后端")
        regvals = ida_dbg.get_reg_vals(current_thread)
        selected = {item.lower() for item in names} if names is not None else None
        registers: dict[str, JsonValue] = {}
        for reg_index, regval in enumerate(regvals):
            reg_info = debugger.regs(reg_index)
            reg_name = str(reg_info.name)
            if selected is not None and reg_name.lower() not in selected:
                continue
            try:
                registers[reg_name] = self.jsonify(regval.pyval(reg_info.dtype))
            except Exception:
                registers[reg_name] = str(regval)
        return {"thread_id": current_thread, "registers": registers}

    def debug_registers_all_threads(self, *, names: list[str] | None = None) -> ToolEnvelope:
        """读取所有线程的寄存器快照。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}

        current_thread = int(ida_dbg.get_current_thread())
        thread_count = int(ida_dbg.get_thread_qty())
        threads: list[JsonObject] = []
        warnings: list[str] = []

        for index in range(thread_count):
            thread_id = int(ida_dbg.getn_thread(index))
            if thread_id in (BADADDR, -1):
                warnings.append(f"第 {index} 个线程句柄无效，已跳过")
                continue
            thread_name = ida_dbg.getn_thread_name(index)
            try:
                snapshot = self.debug_registers(thread_id=thread_id, names=names)
                threads.append(
                    {
                        "index": index,
                        "thread_id": thread_id,
                        "thread_name": thread_name or "",
                        "is_current": thread_id == current_thread,
                        "registers": snapshot["registers"],
                    }
                )
            except Exception as exc:
                warnings.append(f"线程 {thread_id} 寄存器读取失败：{exc}")

        if not threads:
            return {
                "status": "unsupported",
                "data": {"reason": "没有可读取的线程寄存器", "thread_count": thread_count},
                "warnings": warnings or ["调试器未返回可用线程"],
            }

        return {
            "status": "ok",
            "data": {"current_thread": current_thread, "thread_count": thread_count, "threads": threads},
            "warnings": warnings,
        }

    def debug_stacktrace(self) -> ToolEnvelope:
        """读取当前线程调用栈。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}

        thread_id = int(ida_dbg.get_current_thread())
        trace = ida_idd.call_stack_t()
        if not ida_dbg.collect_stack_trace(thread_id, trace):
            return {"status": "unsupported", "data": {"reason": "读取调用栈失败", "thread_id": thread_id}, "warnings": ["collect_stack_trace 失败"]}

        frames: list[JsonObject] = []
        for index, frame in enumerate(trace):
            call_ea = int(frame.callea)
            function_ea = int(frame.funcea) if int(frame.funcea) != BADADDR else call_ea
            module_name = "<unknown>"
            module_info = ida_idd.modinfo_t()
            if ida_dbg.get_module_info(call_ea, module_info):
                raw_module_name = module_info.name
                if isinstance(raw_module_name, str) and raw_module_name:
                    module_name = Path(raw_module_name).name

            symbol_name = ida_name.get_nice_colored_name(
                function_ea,
                ida_name.GNCN_NOCOLOR
                | ida_name.GNCN_NOLABEL
                | ida_name.GNCN_NOSEG
                | ida_name.GNCN_PREFDBG,
            )
            frames.append(
                {
                    "index": index,
                    "call_addr": hex(call_ea),
                    "function_addr": hex(function_ea),
                    "frame_pointer": hex(int(frame.fp)),
                    "function_ok": bool(frame.funcok),
                    "module": module_name,
                    "symbol": symbol_name or self.best_name(function_ea),
                }
            )

        return {"status": "ok", "data": {"thread_id": thread_id, "frames": frames}, "warnings": []}

    def debug_read_memory(self, addr: str, size: int) -> ToolEnvelope:
        """读取调试内存。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        data = ida_dbg.read_dbg_memory(self.parse_address(addr), size)
        if data is None:
            return {"status": "unsupported", "data": {"reason": "读取调试内存失败", "addr": addr}, "warnings": ["read_dbg_memory 返回 None"]}
        return {"status": "ok", "data": {"addr": addr, "size": len(data), "hex": data.hex()}, "warnings": []}

    def debug_write_memory(self, addr: str, hex_data: str) -> ToolEnvelope:
        """写入调试内存。"""
        if ida_dbg.get_process_state() == -1:
            return {"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]}
        blob = bytes.fromhex(hex_data)
        written = ida_dbg.write_dbg_memory(self.parse_address(addr), blob)
        if written != len(blob):
            return {"status": "unsupported", "data": {"reason": "写入调试内存失败", "written": written, "expected": len(blob)}, "warnings": ["write_dbg_memory 未完整写入"]}
        return {"status": "ok", "data": {"addr": addr, "size": len(blob)}, "warnings": []}

    def parse_address(self, value: str) -> int:
        """解析地址或名称。"""
        text = value.strip()
        if text.startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
        ea = ida_name.get_name_ea(BADADDR, value)
        if ea == BADADDR:
            raise ValueError(f"Address/name not found: '{value}'")
        func = idaapi.get_func(ea)
        return func.start_ea if func is not None else ea

    def require_function(self, ea: int) -> ida_funcs.func_t:
        """获取函数对象，不存在时直接失败。"""
        func = idaapi.get_func(ea)
        if func is None:
            raise ValueError(f"找不到函数：{hex(ea)}")
        return func

    def best_name(self, ea: int) -> str:
        """返回尽量可读的名字。"""
        return ida_funcs.get_func_name(ea) or ida_name.get_name(ea) or ida_name.get_ea_name(ea) or hex(ea)

    def line_text(self, ea: int) -> str:
        """读取一行反汇编。"""
        line = ida_lines.generate_disasm_line(ea, 0)
        return ida_lines.tag_remove(line).strip() if line else ""

    def disassembly_lines(self, start_ea: int) -> list[JsonObject]:
        """渲染函数每行反汇编。"""
        func = self.require_function(start_ea)
        return [{"addr": hex(item_ea), "text": self.line_text(item_ea)} for item_ea in idautils.FuncItems(func.start_ea)]

    def render_function_disassembly(self, start_ea: int) -> str:
        """渲染完整函数反汇编文本。"""
        return "\n".join(f"{item['addr']}: {item['text']}" for item in self.disassembly_lines(start_ea))

    def function_strings(self, start_ea: int) -> list[str]:
        """提取函数引用的字符串。"""
        func = self.require_function(start_ea)
        seen: set[str] = set()
        results: list[str] = []
        for item_ea in idautils.FuncItems(func.start_ea):
            for ref in idautils.DataRefsFrom(item_ea):
                raw = idc.get_strlit_contents(ref, 512, idc.STRTYPE_C)
                if not isinstance(raw, bytes):
                    continue
                text = raw.decode("utf-8", errors="replace")
                if text and text not in seen:
                    seen.add(text)
                    results.append(text)
        return results

    def function_constants(self, start_ea: int) -> list[int]:
        """提取函数中的立即数。"""
        func = self.require_function(start_ea)
        constants: list[int] = []
        for item_ea in idautils.FuncItems(func.start_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, item_ea) == 0:
                continue
            for operand in insn.ops:
                if operand.type == ida_ua.o_imm:
                    constants.append(int(operand.value))
        return constants

    def function_comments(self, start_ea: int) -> JsonObject:
        """提取函数内注释。"""
        func = self.require_function(start_ea)
        comments: JsonObject = {}
        for item_ea in idautils.FuncItems(func.start_ea):
            regular = ida_bytes.get_cmt(item_ea, False)
            repeatable = ida_bytes.get_cmt(item_ea, True)
            if regular or repeatable:
                comments[hex(item_ea)] = {"regular": regular or "", "repeatable": repeatable or ""}
        return comments

    def managed_summary(self) -> JsonObject:
        """返回托管/.NET 能力与符号级摘要。

        headless 下对 managed 的支持目前仍以“符号+IL 文本”路线为主，
        所以这里明确把能力边界暴露出来，避免客户端把它误当成完整
        的 .NET 元数据浏览器。
        """
        analysis_domain = self.get_analysis_domain()
        managed_rows = self.managed_types()
        namespace_histogram: dict[str, int] = defaultdict(int)
        sample_methods: list[JsonObject] = []
        for row in managed_rows:
            namespace = row.get("namespace")
            if isinstance(namespace, str) and namespace:
                namespace_histogram[namespace] += 1
            members = row.get("members")
            if isinstance(members, list):
                for member in members[:3]:
                    if isinstance(member, dict):
                        sample_methods.append(member)
                        if len(sample_methods) >= 10:
                            break
            if len(sample_methods) >= 10:
                break
        return {
            "analysis_domain": analysis_domain,
            "available": analysis_domain == "managed",
            "support_level": "symbolic_il" if analysis_domain == "managed" else "not_managed",
            "type_count": len(managed_rows),
            "namespace_count": len(namespace_histogram),
            "top_namespaces": sorted(namespace_histogram.items(), key=lambda item: item[1], reverse=True)[:20],
            "sample_types": managed_rows[:20],
            "sample_methods": sample_methods,
        }

    def managed_types(self, filter_text: str = "", *, limit: int = 2000) -> list[JsonObject]:
        """基于符号名推断托管类型目录。

        这里不是完整 CLR 元数据解析，而是利用 IDA 已识别的函数/名称，
        尽可能提取 `命名空间.类型.方法` 结构，给 headless 模式提供足够
        可消费的托管类型视图。
        """
        lowered = filter_text.lower()
        rows: dict[str, JsonObject] = {}
        for ea in idautils.Functions():
            if len(rows) >= limit:
                break
            identity = self.managed_method_identity(ea)
            if identity is None:
                continue
            full_type_value = identity.get("full_type")
            method_value = identity.get("method")
            type_name_value = identity.get("type_name")
            namespace_value = identity.get("namespace")
            full_name_value = identity.get("full_name")
            if not isinstance(full_type_value, str):
                continue
            if not isinstance(method_value, str):
                continue
            if not isinstance(type_name_value, str):
                continue
            if not isinstance(namespace_value, str):
                continue
            if not isinstance(full_name_value, str):
                continue
            full_type = full_type_value
            method_name = method_value
            type_name = type_name_value
            namespace = namespace_value
            full_name = full_name_value
            if lowered and lowered not in full_type.lower() and lowered not in method_name.lower():
                continue
            row = rows.setdefault(
                full_type,
                {
                    "catalog": "managed_types",
                    "kind": "managed_type",
                    "name": type_name,
                    "namespace": namespace,
                    "declaration_or_signature": full_type,
                    "members": [],
                    "source": "symbolic_names",
                },
            )
            members = row.get("members")
            if not isinstance(members, list):
                continue
            if any(isinstance(member, dict) and member.get("name") == identity["method"] for member in members):
                continue
            members.append(
                {
                    "name": method_name,
                    "kind": "method",
                    "addr": hex(ea),
                    "signature": self.function_signature(ea),
                    "full_name": full_name,
                }
            )
        return list(rows.values())

    def managed_method_identity(self, ea: int) -> JsonObject | None:
        """解析托管方法的“命名空间 / 类型 / 方法”身份。"""
        raw_name = self.best_name(ea)
        parts = self._managed_symbol_parts(raw_name)
        if parts is None:
            return None
        namespace, type_name, full_type, method_name = parts
        return {
            "namespace": namespace,
            "type_name": type_name,
            "full_type": full_type,
            "method": method_name,
            "full_name": f"{full_type}.{method_name}" if full_type else method_name,
        }

    def render_managed_method_view(self, start_ea: int) -> str:
        """渲染托管方法的 headless 视图。"""
        identity = self.managed_method_identity(start_ea)
        signature = self.function_signature(start_ea)
        lines: list[str] = []
        if identity is not None:
            lines.append(f"// Managed method: {identity['full_name']}")
        if signature:
            lines.append(f"// Signature: {signature}")
        lines.append("// Body:")
        lines.extend(f"{item['addr']}: {item['text']}" for item in self.disassembly_lines(start_ea))
        return "\n".join(lines)

    def _function_data_refs(self, start_ea: int, *, max_refs: int = 128) -> list[JsonObject]:
        """收集函数体里指向的数据引用。

        这个集合主要给 `trace_data_flow` 做函数级追踪，避免只追函数入口点，
        导致一上来就没有可用边。
        """
        func = self.require_function(start_ea)
        results: list[JsonObject] = []
        seen: set[int] = set()
        for item_ea in idautils.FuncItems(func.start_ea):
            for target in idautils.DataRefsFrom(item_ea):
                if target in seen:
                    continue
                seen.add(target)
                results.append(
                    {
                        "from_addr": hex(item_ea),
                        "to_addr": hex(target),
                        "target_name": self.best_name(target),
                    }
                )
                if len(results) >= max_refs:
                    return results
        return results

    def function_prototype(self, ea: int) -> str | None:
        """读取函数原型；拿不到时返回 `None`。"""
        func = idaapi.get_func(ea)
        if func is None:
            return None

        prototype_getter = getattr(func, "get_prototype", None)
        if callable(prototype_getter):
            try:
                prototype_tif = prototype_getter()
                if prototype_tif is not None:
                    prototype_text = str(prototype_tif)
                    if prototype_text:
                        return prototype_text
            except Exception:
                pass

        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
            prototype_text = self._print_tinfo(tif)
            if prototype_text:
                return prototype_text

        raw_type = idc.get_type(func.start_ea)
        if isinstance(raw_type, str) and raw_type.strip():
            return raw_type.strip()

        return None

    def debugger_health(self) -> JsonObject:
        """返回当前调试器后端与会话状态。

        这里单独暴露真实状态，避免上层仅凭 feature gate 误判“工具注册了就一定能调”。
        """
        debugger = ida_idd.get_dbg()
        process_state = int(ida_dbg.get_process_state())
        current_thread = int(ida_dbg.get_current_thread())
        return {
            "backend_available": debugger is not None,
            "session_active": process_state != -1,
            "process_state": process_state,
            "current_thread": current_thread if current_thread not in (-1, BADADDR) else None,
        }

    def _export_function_targets(self, *, queries: list[str] | None, limit: int) -> list[str]:
        """确定导出目标函数集合。

        这里单独收口，是为了避免 `export_functions` 里混入太多筛选细节：
        - 未显式给 `queries` 时，按当前数据库的函数列表分页导出
        - 给了 `queries` 时，允许名字/地址混用，并自动去重
        """
        if not queries:
            targets: list[str] = []
            for item in self.list_functions(offset=0, limit=limit):
                addr_value = item.get("addr")
                if isinstance(addr_value, str):
                    targets.append(addr_value)
            return targets

        targets = []
        seen: set[int] = set()
        for query in queries[:limit]:
            match = self.lookup_function(query)
            ea = self._match_ea(match)
            if ea in seen:
                continue
            seen.add(ea)
            targets.append(hex(ea))
        return targets

    def edge_kind(self, ea: int) -> str:
        """根据当前行文本粗略推断边类型。"""
        text = self.line_text(ea).lower()
        if not text:
            return "call"
        mnemonic = text.split()[0]
        if mnemonic.startswith("callvirt"):
            return "virtual_call"
        if mnemonic.startswith("call"):
            return "call"
        return mnemonic

    def callgraph_edge_kind(self, ea: int, func_start: int) -> str | None:
        """判断一条代码引用是否应进入“函数调用图”。

        当前规则：
        - 真正的 `call*` / `newobj` 进入调用图
        - thunk / wrapper 场景下的 `jmp` 作为 `tailcall`
        - 普通分支（例如 `brfalse.s` / `switch` / `jz`）不再混入函数调用图
        """
        text = self.line_text(ea).lower().strip()
        if not text:
            return None
        mnemonic = text.split()[0]
        if mnemonic.startswith("callvirt"):
            return "virtual_call"
        if mnemonic.startswith("call"):
            return "call"
        if mnemonic.startswith("newobj"):
            return "constructor_call"
        if mnemonic.startswith("jmp"):
            func = idaapi.get_func(func_start)
            if func is not None and bool(func.flags & ida_funcs.FUNC_THUNK):
                return "tailcall"
        return None

    def _is_external_call_target(self, ea: int) -> bool:
        """判断目标地址是否可视为合法的外部调用目标。"""
        seg = ida_segment.getseg(ea)
        if seg is None:
            return False
        seg_name = ida_segment.get_segm_name(seg).lower()
        if "plt" in seg_name or "idata" in seg_name or "got" in seg_name or "extern" in seg_name:
            return True
        name = self.best_name(ea).lower()
        return name.startswith("__imp_") or name.startswith("j_")

    def xref_type_name(self, value: int) -> str:
        """把 xref 常量转换为可读名字。"""
        mapping = {
            ida_xref.fl_CF: "code_far_call",
            ida_xref.fl_CN: "code_near_call",
            ida_xref.fl_JF: "jump_far",
            ida_xref.fl_JN: "jump_near",
            ida_xref.dr_R: "data_read",
            ida_xref.dr_W: "data_write",
            ida_xref.dr_O: "data_offset",
            ida_xref.dr_T: "data_text",
            ida_xref.dr_I: "data_info",
        }
        return mapping.get(value, str(value))

    def hexrays_available(self) -> bool:
        """判断 Hex-Rays 是否可用。"""
        try:
            return bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            return False

    def jsonify(self, value: object) -> JsonValue:
        """把运行时对象转换成 JSON 值。"""
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            return [self.jsonify(item) for item in value]
        if isinstance(value, tuple):
            return [self.jsonify(item) for item in value]
        if isinstance(value, dict):
            return {str(key): self.jsonify(item) for key, item in value.items()}
        return str(value)

    def _json_object(self, value: object) -> JsonObject:
        """把任意运行时对象收敛成 JSON 对象。"""
        normalized = self.jsonify(value)
        if not isinstance(normalized, dict):
            raise TypeError("内部错误：期望 JSON 对象")
        return normalized

    def _match_ea(self, match: JsonObject) -> int:
        value = match.get("ea")
        if not isinstance(value, int):
            raise ValueError("内部错误：match.ea 非整数")
        return value

    def _match_name(self, match: JsonObject) -> str:
        value = match.get("name")
        if not isinstance(value, str):
            raise ValueError("内部错误：match.name 非字符串")
        return value

    def _segment_permissions(self, perm: int) -> str:
        chars = []
        chars.append("r" if perm & ida_segment.SEGPERM_READ else "-")
        chars.append("w" if perm & ida_segment.SEGPERM_WRITE else "-")
        chars.append("x" if perm & ida_segment.SEGPERM_EXEC else "-")
        return "".join(chars)

    def _classify_function(self, addr_text: str) -> str:
        func = self.require_function(self.parse_address(addr_text))
        if func.flags & ida_funcs.FUNC_THUNK:
            return "thunk"
        block_count = sum(1 for _ in idaapi.FlowChart(func))
        if block_count <= 1:
            return "leaf"
        if block_count <= 3:
            return "wrapper"
        return "complex"

    def _callgraph_summary(self, functions: list[JsonObject]) -> JsonObject:
        total_edges = 0
        leaf_count = 0
        roots: list[str] = []
        for item in functions[:100]:
            addr_text = item.get("addr")
            if not isinstance(addr_text, str):
                continue
            callees = self.get_callees(addr_text)
            callers = self.get_callers(addr_text)
            total_edges += len(callees)
            if not callees:
                leaf_count += 1
            if not callers:
                roots.append(str(item.get("name", addr_text)))
        return {
            "total_edges": total_edges,
            "max_depth_estimate": None,
            "root_functions": roots[:25],
            "leaf_functions_count": leaf_count,
        }

    def _categorize_imports(self) -> JsonObject:
        buckets: dict[str, list[JsonObject]] = defaultdict(list)
        for item in self.list_imports(offset=0, limit=10_000):
            name_text = str(item.get("name", "")).lower()
            if any(keyword in name_text for keyword in ("crypt", "aes", "des", "md5", "sha")):
                buckets["crypto"].append(item)
            elif any(keyword in name_text for keyword in ("socket", "connect", "recv", "send", "internet", "ws2_")):
                buckets["network"].append(item)
            elif any(keyword in name_text for keyword in ("createfile", "readfile", "writefile", "fopen", "fread", "fwrite")):
                buckets["file_io"].append(item)
            elif any(keyword in name_text for keyword in ("createprocess", "fork", "exec", "winexec")):
                buckets["process"].append(item)
            elif any(keyword in name_text for keyword in ("reg", "_itm_")):
                buckets["registry"].append(item)
            else:
                buckets["other"].append(item)
        for key in ("crypto", "network", "file_io", "process", "registry", "other"):
            buckets.setdefault(key, [])
        return dict(buckets)

    def _type_row(self, name: str, tif: ida_typeinf.tinfo_t) -> JsonObject:
        return {
            "catalog": "local_types",
            "kind": self._type_kind(tif),
            "name": name,
            "namespace": "",
            "declaration_or_signature": self._print_tinfo(tif),
            "members": self._type_members(tif),
            "source": "ida_typeinf",
        }

    def _type_kind(self, tif: ida_typeinf.tinfo_t) -> str:
        if tif.is_enum():
            return "enum"
        if tif.is_udt():
            return "udt"
        if tif.is_func():
            return "func"
        if tif.is_ptr():
            return "ptr"
        return "other"

    def _type_members(self, tif: ida_typeinf.tinfo_t) -> list[JsonObject]:
        if not tif.is_udt():
            return []
        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            return []
        return [
            {
                "name": member.name,
                "offset": member.offset,
                "size": member.size,
                "type": self._print_tinfo(member.type),
            }
            for member in udt_data
        ]

    def _print_tinfo(self, tif: ida_typeinf.tinfo_t) -> str:
        try:
            return tif._print()
        except Exception:
            return str(tif)

    def _extract_declared_type_name(self, text: str) -> str | None:
        """从声明文本里提取一个最可能的类型名。"""
        normalized = re.sub(r"\s+", " ", text.strip())
        if not normalized:
            return None

        tagged_match = re.search(r"\b(?:struct|enum|union)\s+([A-Za-z_]\w*)", normalized)
        if tagged_match is not None:
            return tagged_match.group(1)

        typedef_match = re.search(r"\btypedef\b.+?\b([A-Za-z_]\w*)\s*;?$", normalized)
        if typedef_match is not None:
            return typedef_match.group(1)

        return None

    def _parse_signed_int(self, value: int | str) -> int:
        """把整数或整数字符串解析成带符号偏移。"""
        if isinstance(value, int):
            return value
        text = value.strip()
        if not text:
            raise ValueError("偏移字符串不能为空")
        return int(text, 0)

    def _parse_type_tinfo(self, type_text: str) -> ida_typeinf.tinfo_t:
        """把类型文本解析成 `tinfo_t`。"""
        candidate_texts = [type_text.strip()]
        if not candidate_texts[0]:
            raise ValueError("类型文本不能为空")
        if not candidate_texts[0].endswith(";"):
            candidate_texts.append(candidate_texts[0] + ";")

        flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
        for candidate in candidate_texts:
            tif = ida_typeinf.tinfo_t()
            try:
                parse_result = ida_typeinf.parse_decl(tif, None, candidate, flags)
            except Exception:
                continue
            if parse_result is not None and not tif.empty():
                return tif

        parsed = idc.parse_decl(type_text, flags)
        if isinstance(parsed, tuple) and len(parsed) >= 2:
            type_info = parsed[1]
            if isinstance(type_info, ida_typeinf.tinfo_t):
                return type_info

        raise ValueError(f"无法解析类型：{type_text}")

    def _managed_support_matrix(self) -> JsonObject:
        """返回托管能力矩阵。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain != "managed":
            return {
                "available": False,
                "type_catalog": "native_only",
                "decompiler": "native_only",
                "notes": ["当前样本不是托管/.NET 程序"],
            }
        return {
            "available": True,
            "type_catalog": "symbolic_managed_types",
            "decompiler": "il_symbolic_fallback",
            "notes": [
                "当前托管支持基于 IDA 已识别符号与 IL/反汇编文本。",
                "尚未实现完整 CLR 元数据解析与真正的托管高层反编译。",
            ],
        }

    def _managed_symbol_parts(self, raw_name: str) -> tuple[str, str, str, str] | None:
        """从符号名里拆出托管类型路径。

        常见托管名字形态可能是：
        - `Namespace.Type::Method`
        - `Namespace.Type.Method`
        - `Type::Method`
        """
        normalized = raw_name.strip()
        if not normalized:
            return None
        normalized = normalized.split("(", 1)[0].strip()
        normalized = normalized.replace("/", ".")

        owner = ""
        method_name = ""
        if "::" in normalized:
            owner, method_name = normalized.rsplit("::", 1)
        elif "." in normalized:
            owner, method_name = normalized.rsplit(".", 1)
        if not owner or not method_name:
            return None

        owner = owner.strip(".")
        method_name = method_name.strip(".")
        if not owner or not method_name:
            return None

        if "." in owner:
            namespace, type_name = owner.rsplit(".", 1)
        else:
            namespace = ""
            type_name = owner
        if not type_name:
            return None
        return namespace, type_name, owner, method_name

    def _string_literal_declaration(self, ea: int) -> str | None:
        """如果地址本身是字符串项，则返回对应声明。"""
        raw = idc.get_strlit_contents(ea, 512, idc.STRTYPE_C)
        if isinstance(raw, bytes) and raw:
            return "const char[]"
        raw16 = idc.get_strlit_contents(ea, 512, idc.STRTYPE_C_16)
        if isinstance(raw16, bytes) and raw16:
            return "const wchar_t[]"
        return None

    def _infer_pointer_type(self, ea: int) -> JsonObject | None:
        """尝试把数据项解释为指针。"""
        pointer_size = 8 if ida_ida.inf_get_app_bitness() >= 64 else 4
        item_size = ida_bytes.get_item_size(ea)
        if item_size < pointer_size:
            return None

        target = self._read_pointer_target(ea, pointer_size)
        if target is None:
            return None

        string_decl = self._string_literal_declaration(target)
        if string_decl is not None:
            inferred_type = "const wchar_t *" if "wchar_t" in string_decl else "const char *"
            applied = self._try_apply_decl(ea, inferred_type)
            return {
                "addr": hex(ea),
                "inferred_type": inferred_type,
                "method": "pointer_to_string",
                "confidence": "medium",
                "applied": applied,
                "target": hex(target),
                "target_name": self.best_name(target),
            }

        target_func = idaapi.get_func(target)
        if target_func is not None:
            prototype = self.function_prototype(target_func.start_ea) or "void (*)()"
            return {
                "addr": hex(ea),
                "inferred_type": prototype,
                "method": "pointer_to_function",
                "confidence": "medium",
                "applied": False,
                "target": hex(target_func.start_ea),
                "target_name": self.best_name(target_func.start_ea),
            }
        return None

    def _infer_pointer_chain_type(self, ea: int) -> JsonObject | None:
        """尝试把地址解释为“指向指针的指针”。"""
        pointer_size = 8 if ida_ida.inf_get_app_bitness() >= 64 else 4
        first_target = self._read_pointer_target(ea, pointer_size)
        if first_target is None:
            return None
        second_target = self._read_pointer_target(first_target, pointer_size)
        if second_target is None:
            return None

        string_decl = self._string_literal_declaration(second_target)
        if string_decl is not None:
            inferred_type = "const wchar_t **" if "wchar_t" in string_decl else "const char **"
            applied = self._try_apply_decl(ea, inferred_type)
            return {
                "addr": hex(ea),
                "inferred_type": inferred_type,
                "method": "pointer_chain_to_string",
                "confidence": "low",
                "applied": applied,
                "target": hex(first_target),
                "final_target": hex(second_target),
            }
        return None

    def _infer_pointed_target_type(self, ea: int) -> JsonObject | None:
        """尝试根据被指向对象已有类型反推指针类型。"""
        pointer_size = 8 if ida_ida.inf_get_app_bitness() >= 64 else 4
        target = self._read_pointer_target(ea, pointer_size)
        if target is None:
            return None

        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, target) or tif.empty():
            return None
        target_type = self._print_tinfo(tif)
        if not target_type:
            return None
        inferred_type = f"{target_type} *"
        applied = self._try_apply_decl(ea, inferred_type)
        return {
            "addr": hex(ea),
            "inferred_type": inferred_type,
            "method": "pointed_target_tinfo",
            "confidence": "medium",
            "applied": applied,
            "target": hex(target),
            "target_name": self.best_name(target),
        }

    def _read_pointer_target(self, ea: int, pointer_size: int) -> int | None:
        """读取地址中的潜在指针值。"""
        if pointer_size >= 8:
            target = int(ida_bytes.get_qword(ea))
        else:
            target = int(ida_bytes.get_dword(ea))
        if target in (0, BADADDR):
            return None
        if not ida_bytes.is_loaded(target):
            return None
        return target

    def _try_apply_decl(self, ea: int, type_text: str) -> bool:
        """尝试把声明应用到地址上。"""
        try:
            tif = self._parse_type_tinfo(type_text)
        except Exception:
            return False
        return bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))

    @staticmethod
    def _looks_like_address(text: str) -> bool:
        if text.startswith("0x"):
            return True
        return text.isdigit()
