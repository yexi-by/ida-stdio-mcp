"""项目自己的 IDA 访问层。

这里集中封装对 `ida_*` / `idautils` / `idc` 的访问。
设计目标不是追求花哨抽象，而是把所有 headless 能力收口到一层，
让外面的 MCP 工具层不再直接依赖分散的 IDA API。
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable, Iterable, Protocol, TypeAlias, cast

from .ida_bootstrap import ensure_ida_environment
from .managed_decompiler import (
    decompile_managed_method,
    managed_decompiler_available,
    managed_decompiler_command,
)

ensure_ida_environment()

import ida_auto  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_bytes  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_dbg  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_frame  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_funcs  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_hexrays  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_ida  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_idaapi  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_idd  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_idp  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_lines  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_loader  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_nalt  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_name  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_segment  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_typeinf  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_ua  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_xref  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import idaapi  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import idautils  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import idc  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。

from .models import AnalysisDomain, BinaryKind, JsonObject, JsonValue

try:
    import ida_entry  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
except ImportError:  # pragma: no cover - IDA 环境里通常可用
    ida_entry = None  # type: ignore[assignment]

BADADDR = ida_idaapi.BADADDR
PE_SUFFIXES = {".exe", ".dll", ".sys"}
ELF_SUFFIXES = {".elf", ".so"}
MACHO_SUFFIXES = {".dylib", ".macho"}
STRING_LITERAL_PATTERN = re.compile(r'"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"')


ToolEnvelope: TypeAlias = JsonObject


GET_IDB_PATH = cast(Callable[[int], str], ida_loader.get_path)
GET_APP_BITNESS = cast(Callable[[], int], ida_ida.inf_get_app_bitness)
GET_PROCNAME = ida_ida.inf_get_procname
GET_IMAGEBASE = cast(Callable[[], int], ida_nalt.get_imagebase)
GET_MAX_EA = cast(Callable[[], int], ida_ida.inf_get_max_ea)
GET_MIN_EA = cast(Callable[[], int], ida_ida.inf_get_min_ea)
GET_SEG = cast(Callable[[int], ida_segment.segment_t | None], ida_segment.getseg)
GET_SEG_NAME = cast(Callable[[ida_segment.segment_t], str], ida_segment.get_segm_name)
GET_ENTRY_QTY = ida_entry.get_entry_qty if ida_entry is not None else None
GET_ENTRY_ORDINAL = cast(Callable[[int], int], ida_entry.get_entry_ordinal) if ida_entry is not None else None
GET_ENTRY = cast(Callable[[int], int], ida_entry.get_entry) if ida_entry is not None else None
GET_ENTRY_NAME = cast(Callable[[int], str], ida_entry.get_entry_name) if ida_entry is not None else None
# IDA 9.3 的 import-by-address API 使用 SWIG 对象出参；公开存根还不稳定，
# 因此边界处先以 object 承接，再由 `_import_entry_from_runtime_object` 收窄。
IMPORT_ENTRY_T = cast(Callable[[], object] | None, getattr(ida_nalt, "import_entry_t", None))
GET_IMPORT_ENTRY = cast(Callable[[object, int], bool] | None, getattr(ida_nalt, "get_import_entry", None))
GET_FUNC = cast(Callable[[int], ida_funcs.func_t | None], ida_funcs.get_func)
GET_FUNC_NAME = cast(Callable[[int], str], ida_funcs.get_func_name)
GET_NAME = cast(Callable[[int], str], ida_name.get_name)
GET_EA_NAME = cast(Callable[[int, int], str], ida_name.get_ea_name)
GET_NAME_EA = cast(Callable[[int, str], int], ida_name.get_name_ea)
GET_ITEM_SIZE = cast(Callable[[int], int], ida_bytes.get_item_size)
GET_BYTES = cast(Callable[[int, int, int], bytes | None], ida_bytes.get_bytes)
GET_FLAGS = cast(Callable[[int], int], ida_bytes.get_flags)
IS_CODE = cast(Callable[[int], bool], ida_bytes.is_code)
GET_QWORD = cast(Callable[[int], int], ida_bytes.get_qword)
GET_DWORD = cast(Callable[[int], int], ida_bytes.get_dword)
IS_LOADED = cast(Callable[[int], bool], ida_bytes.is_loaded)
GET_IMPORT_MODULE_QTY = cast(Callable[[], int], ida_nalt.get_import_module_qty)
GET_CMT = cast(Callable[[int, bool], str], ida_bytes.get_cmt)
SET_CMT = cast(Callable[[int, str, bool], bool], ida_bytes.set_cmt)
PATCH_BYTES = cast(Callable[[int, bytes], None], ida_bytes.patch_bytes)
FIND_BYTES = cast(Callable[..., int], ida_bytes.find_bytes)
SET_NAME = cast(Callable[[int, str, int], bool], ida_name.set_name)
SET_FUNC_CMT = cast(Callable[[ida_funcs.func_t, str, bool], bool], ida_funcs.set_func_cmt)
GET_FUNC_CMT = cast(Callable[[ida_funcs.func_t, bool], str], ida_funcs.get_func_cmt)
GET_FLOW_CHART = cast(Callable[[ida_funcs.func_t], object], idaapi.FlowChart)
CREATE_INSN = cast(Callable[[int, ida_ua.insn_t], int], ida_ua.create_insn)
DECODE_INSN = cast(Callable[[ida_ua.insn_t, int], int], ida_ua.decode_insn)
DEL_ITEMS = cast(Callable[[int, int, int], bool], ida_bytes.del_items)
GUESS_TINFO = cast(Callable[[ida_typeinf.tinfo_t, int], int], ida_typeinf.guess_tinfo)
GET_TINFO = cast(Callable[[ida_typeinf.tinfo_t, int], bool], ida_nalt.get_tinfo)
APPLY_TINFO = cast(Callable[[int, ida_typeinf.tinfo_t, int], bool], ida_typeinf.apply_tinfo)
PARSE_DECL = cast(Callable[[ida_typeinf.tinfo_t, object, str, int], object], ida_typeinf.parse_decl)
DEFINE_STKVAR = cast(Callable[[ida_funcs.func_t, str, int, ida_typeinf.tinfo_t], bool], ida_frame.define_stkvar)
GET_FUNC_FRAME = cast(Callable[[ida_typeinf.tinfo_t, ida_funcs.func_t], bool], ida_frame.get_func_frame)
IS_SPECIAL_FRAME_MEMBER = cast(Callable[[int], bool], ida_frame.is_special_frame_member)
IS_FUNCARG_OFF = cast(Callable[[ida_funcs.func_t, int], bool], ida_frame.is_funcarg_off)
DELETE_FRAME_MEMBERS = cast(Callable[[ida_funcs.func_t, int, int], bool], ida_frame.delete_frame_members)
PLAN_AND_WAIT = cast(Callable[[int, int, bool], int], ida_auto.plan_and_wait)
ASSEMBLE = cast(Callable[[int, str], tuple[bool, bytes] | object], idautils.Assemble)
GENERATE_DISASM_LINE = cast(Callable[[int, int], str], ida_lines.generate_disasm_line)
START_PROCESS = cast(Callable[[str, str, str], bool], ida_dbg.start_process)
EXIT_PROCESS = cast(Callable[[], None], ida_dbg.exit_process)
CONTINUE_PROCESS = cast(Callable[[], None], ida_dbg.continue_process)
STEP_INTO = cast(Callable[[], None], ida_dbg.step_into)
STEP_OVER = cast(Callable[[], None], ida_dbg.step_over)
REQUEST_RUN_TO = cast(Callable[[int], bool], ida_dbg.request_run_to)
GET_PROCESS_STATE = ida_dbg.get_process_state
GET_BPT_QTY = ida_dbg.get_bpt_qty
GET_NTH_BPT = cast(Callable[[int, ida_dbg.bpt_t], bool], ida_dbg.getn_bpt)
ADD_BPT = cast(Callable[[int], bool], ida_dbg.add_bpt)
DEL_BPT = cast(Callable[[int], bool], ida_dbg.del_bpt)
EXIST_BPT = cast(Callable[[int], bool], ida_dbg.exist_bpt)
ENABLE_BPT = cast(Callable[[int, bool], bool], idaapi.enable_bpt)
GET_CURRENT_THREAD = cast(Callable[[], int], ida_dbg.get_current_thread)
GET_THREAD_QTY = ida_dbg.get_thread_qty
GET_NTH_THREAD = cast(Callable[[int], int], ida_dbg.getn_thread)
GET_NTH_THREAD_NAME = cast(Callable[[int], str], ida_dbg.getn_thread_name)
GET_REG_VALS = cast(Callable[[int, int], object], ida_dbg.get_reg_vals)
COLLECT_STACK_TRACE = cast(Callable[[int, ida_idd.call_stack_t], bool], ida_dbg.collect_stack_trace)
GET_MODULE_INFO = cast(Callable[[int, ida_idd.modinfo_t], bool], ida_dbg.get_module_info)
READ_DBG_MEMORY = cast(Callable[[int, int], bytes | None], ida_dbg.read_dbg_memory)
WRITE_DBG_MEMORY = cast(Callable[[int, bytes], int], ida_dbg.write_dbg_memory)
GET_NICE_COLORED_NAME = cast(Callable[[int, int], str], ida_name.get_nice_colored_name)
NEW_TINFO = cast(Callable[[], ida_typeinf.tinfo_t], ida_typeinf.tinfo_t)
NEW_INSN = cast(Callable[[], ida_ua.insn_t], ida_ua.insn_t)
NEW_BPT = cast(Callable[[], ida_dbg.bpt_t], ida_dbg.bpt_t)
NEW_UDM = cast(Callable[[], ida_typeinf.udm_t], ida_typeinf.udm_t)
NEW_CALL_STACK = cast(Callable[[], ida_idd.call_stack_t], ida_idd.call_stack_t)
NEW_MODINFO = cast(Callable[[], ida_idd.modinfo_t], ida_idd.modinfo_t)
NEW_UDT_DATA = cast(Callable[[], ida_typeinf.udt_type_data_t], ida_typeinf.udt_type_data_t)
CREATE_STRINGS = cast(Callable[[], object], idautils.Strings)


class _FlowBlock(Protocol):
    start_ea: int
    end_ea: int

    def succs(self) -> object: ...

    def preds(self) -> object: ...


class _StringItem(Protocol):
    ea: int

    def __str__(self) -> str: ...


class IdaCore:
    """纯 headless 的 IDA 访问层。"""

    def wait_auto_analysis(self) -> JsonObject:
        """等待自动分析结束。"""
        ida_auto.auto_wait()
        return self._json_object({"waited": True})

    def capabilities(self) -> JsonObject:
        """返回当前数据库的能力矩阵。"""
        analysis_domain = self.get_analysis_domain()
        string_index_status = self.string_index_status()
        representations: list[JsonValue] = ["asm_fallback"]
        if analysis_domain == "managed":
            representations.insert(0, "il")
            if self.managed_csharp_available():
                representations.insert(0, "csharp")
        if self.hexrays_available():
            representations.insert(0, "hexrays")
        catalogs: list[JsonValue] = ["local_types"]
        if analysis_domain == "managed":
            catalogs.append("managed_types")
        debugger_health = self.debugger_health()
        debugger_available = bool(debugger_health.get("backend_available"))
        if analysis_domain == "managed":
            decompiler_state = "external_csharp" if self.managed_csharp_available() else "il_fallback"
            decompile_mode = "csharp_external" if self.managed_csharp_available() else "il_fallback"
        else:
            decompiler_state = "hexrays" if self.hexrays_available() else "asm_fallback"
            decompile_mode = "hexrays" if self.hexrays_available() else "asm_fallback"
        return self._json_object({
            "binary_kind": self.get_binary_kind(),
            "analysis_domain": analysis_domain,
            "active_backend": analysis_domain,
            "representations": representations,
            "catalogs": catalogs,
            "callgraph_quality": "coderefs",
            "decompiler_state": decompiler_state,
            "decompile_mode": decompile_mode,
            "string_index_quality": self._string_index_quality(),
            "string_index_status": string_index_status,
            "type_writeback_support": self._type_writeback_support(),
            "debugger_support": "available" if debugger_available else "unavailable",
            "managed_support": self._managed_support_matrix(),
        })

    def string_index_status(self) -> JsonObject:
        """返回字符串索引状态说明，不触发 IDA 全库字符串重建。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain == "managed":
            return self._json_object({
                "state": "lazy_symbolic",
                "quality": "deferred",
                "is_expensive": True,
                "can_build": True,
                "reason": "托管字符串需要从反汇编/IL 文本里按需抽取，默认摘要不会主动扫描全部函数。",
                "build_tools": ["list_strings", "find_strings", "investigate_string"],
            })
        return self._json_object({
            "state": "deferred",
            "quality": "unknown_until_requested",
            "is_expensive": True,
            "can_build": True,
            "reason": "IDA 原生字符串列表由 ida_strlist.build_strlist 构建；大型 UE/PDB 数据库上可能持续数分钟，默认摘要不会主动触发。",
            "build_tools": ["list_strings", "find_strings", "investigate_string"],
        })

    def capability_matrix(self) -> JsonObject:
        """返回正式能力矩阵文档。

        这里不是“当前样本是否正好可用”的一次性快照，而是把 headless 模式下
        native / managed 两条主能力域的设计边界显式表达出来，便于 MCP 客户端
        在调用前做规划，而不是靠失败来反推能力边界。
        """
        debugger_available = bool(self.debugger_health().get("backend_available"))
        return self._json_object({
            "capabilities": [
                {"capability": "list_functions", "native": "full", "managed": "full", "notes": "native 与托管都支持符号级函数枚举"},
                {"capability": "build_callgraph", "native": "full", "managed": "degraded", "notes": "托管场景目前基于符号与 IL/反汇编文本构图"},
                {
                    "capability": "decompile_function",
                    "native": "full" if self.hexrays_available() else "degraded",
                    "managed": "full" if self.managed_csharp_available() else "degraded",
                    "notes": "托管目标优先走外部 C# 反编译，失败时才回退到 IL/反汇编文本",
                },
                {"capability": "list_strings", "native": "explicit_heavy", "managed": self._string_index_quality(), "notes": "字符串索引是显式重任务；默认摘要只报告状态，不主动构建全库字符串列表"},
                {"capability": "set_types", "native": "full", "managed": self._type_writeback_support(), "notes": "类型写回作用于 IDA 数据库，native/managed 都可持久化到 IDB"},
                {"capability": "patch_bytes", "native": "full", "managed": "full", "notes": "只要地址可写，补丁能力本身不依赖 GUI"},
                {"capability": "debugger", "native": "available" if debugger_available else "unavailable", "managed": "available" if debugger_available else "unavailable", "notes": "是否真正可用取决于当前调试器后端"},
            ],
            "current_domain": self.get_analysis_domain(),
            "current_snapshot": self.capabilities(),
        })

    def idb_metadata(self) -> JsonObject:
        """返回当前 IDB 元数据。"""
        input_path = Path(ida_nalt.get_input_file_path() or "")
        md5_bytes = ida_nalt.retrieve_input_file_md5()
        sha256_bytes = ida_nalt.retrieve_input_file_sha256()
        return self._json_object({
            "path": GET_IDB_PATH(ida_loader.PATH_TYPE_IDB) or "",
            "input_path": str(input_path),
            "module": input_path.name,
            "processor": GET_PROCNAME(),
            "arch": str(8 * GET_APP_BITNESS()),
            "base_address": hex(GET_IMAGEBASE()),
            "image_size": hex(max(0, GET_MAX_EA() - GET_MIN_EA())),
            "md5": md5_bytes.hex() if md5_bytes else "",
            "sha256": sha256_bytes.hex() if sha256_bytes else "",
            "binary_kind": self.get_binary_kind(),
            "analysis_domain": self.get_analysis_domain(),
        })

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
            seg = GET_SEG(seg_ea)
            if seg is None:
                continue
            results.append(
                {
                    "name": GET_SEG_NAME(seg),
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
        if GET_ENTRY_QTY is None or GET_ENTRY_ORDINAL is None or GET_ENTRY is None or GET_ENTRY_NAME is None:
            return results
        for index in range(GET_ENTRY_QTY()):
            ordinal = GET_ENTRY_ORDINAL(index)
            ea = GET_ENTRY(ordinal)
            if ea == BADADDR:
                continue
            results.append(
                {
                    "addr": hex(ea),
                    "name": GET_ENTRY_NAME(ordinal) or GET_NAME(ea) or hex(ea),
                    "ordinal": ordinal,
                }
            )
        return results

    def import_categories(self) -> JsonObject:
        """返回导入表分类摘要。"""
        return self._categorize_imports()

    def callgraph_summary(self, *, function_limit: int = 2000) -> JsonObject:
        """返回基于代码引用的轻量调用图摘要。"""
        return self._callgraph_summary(self.list_functions(limit=function_limit))

    def binary_survey_snapshot(self, *, include_strings: bool = False, string_limit: int = 0) -> JsonObject:
        """返回默认不触发重型字符串索引的二进制概览。

        Args:
            include_strings: 是否显式构建并返回字符串样本。原生 IDA 字符串
                索引会调用 `ida_strlist.build_strlist`，大型 UE/PDB 数据库上
                可能非常慢，因此默认关闭。
            string_limit: `include_strings` 为 true 时最多返回多少条字符串。
        """
        functions = self.list_functions(limit=2000)
        strings = self.list_strings(limit=max(0, string_limit)) if include_strings else []
        segments = self.segments()
        string_index = self.string_index_status()
        interesting_functions: list[JsonObject] = []
        for item in functions[:15]:
            addr_text = item.get("addr")
            if not isinstance(addr_text, str):
                continue
            try:
                callees = self.get_callees(addr_text)
                xrefs = self.xrefs_to(addr_text)
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
        total_strings: JsonValue = len(strings) if include_strings else None
        string_count_status = "counted" if include_strings else "deferred"
        return self._json_object({
            "metadata": self.idb_metadata(),
            "statistics": {
                "total_functions": len(functions),
                "named_functions": len([item for item in functions if not str(item.get("name", "")).startswith("sub_")]),
                "library_functions": len([item for item in functions if bool(item.get("is_library", False))]),
                "unnamed_functions": len([item for item in functions if str(item.get("name", "")).startswith("sub_")]),
                "total_strings": total_strings,
                "string_count_status": string_count_status,
                "total_segments": len(segments),
            },
            "string_index": string_index,
            "capabilities": self.capabilities(),
            "segments": segments,
            "entrypoints": self.entrypoints(),
            "interesting_strings": strings[: max(0, string_limit)],
            "interesting_functions": interesting_functions,
            "imports_by_category": self._categorize_imports(),
            "call_graph_summary": self._callgraph_summary(functions),
            "managed_summary": self.managed_summary(),
            "quality": {
                "decompile_mode": self.capabilities()["decompile_mode"],
                "string_index_quality": self.capabilities()["string_index_quality"],
                "type_writeback_support": self.capabilities()["type_writeback_support"],
                "debugger_support": self.capabilities()["debugger_support"],
            },
        })

    def triage_binary_snapshot(
        self,
        *,
        function_limit: int = 12,
        string_limit: int = 12,
        import_limit_per_category: int = 6,
        include_strings: bool = False,
    ) -> JsonObject:
        """返回更适合快速开局的样本摘要。

        Args:
            function_limit: 返回多少个关键函数摘要。
            string_limit: `include_strings` 为 true 时返回多少个关键字符串。
            import_limit_per_category: 每个导入分类返回多少个示例。
            include_strings: 是否显式构建字符串索引。默认关闭，避免大型
                UE/PDB 数据库在摘要阶段卡进 `ida_strlist.build_strlist`。
        """
        survey = self.binary_survey_snapshot(include_strings=include_strings, string_limit=string_limit)
        metadata = self.idb_metadata()
        capabilities = self.capabilities()
        statistics_value = survey.get("statistics")
        statistics = statistics_value if isinstance(statistics_value, dict) else {}
        quality_value = survey.get("quality")
        quality = quality_value if isinstance(quality_value, dict) else {}
        managed_summary_value = survey.get("managed_summary")
        managed_summary = managed_summary_value if isinstance(managed_summary_value, dict) else {}

        analysis_domain = str(metadata.get("analysis_domain", "unknown"))
        binary_kind = str(metadata.get("binary_kind", "unknown"))
        decompile_mode = str(capabilities.get("decompile_mode", "unknown"))
        total_functions = self._json_int_or_default(statistics.get("total_functions"), 0)
        total_strings_value = statistics.get("total_strings")
        if isinstance(total_strings_value, int) and not isinstance(total_strings_value, bool):
            total_strings_text = str(total_strings_value)
        else:
            total_strings_text = "未构建索引"

        entrypoints = self.entrypoints()
        interesting_functions = self._interesting_function_rows(limit=function_limit)
        interesting_strings = self._interesting_string_rows(limit=string_limit) if include_strings else []
        import_summary = self._import_category_summary(limit_per_category=import_limit_per_category)
        recommended_queries = self._recommended_binary_queries(entrypoints, interesting_functions)
        recommended_next_tools = self._recommended_binary_tools(
            analysis_domain=analysis_domain,
            has_strings=bool(interesting_strings),
        )

        summary_text = (
            f"当前样本属于 {analysis_domain} 分析域，文件类型为 {binary_kind}；"
            f"已识别 {total_functions} 个函数、字符串状态为 {total_strings_text}，"
            f"当前反编译模式为 {decompile_mode}。"
        )
        opening_moves: list[JsonValue] = [
            "优先查看 entrypoints 与 interesting_functions，先锁定入口函数、初始化逻辑或明显的业务函数。",
            "如果 interesting_strings 里已经出现 URL、路径、错误文案、协议字段，下一步直接用 investigate_string 追到所属函数。",
            "如果需要函数级深挖，继续调用 decompile_function、get_function_profile、read_struct、query_types。",
        ]
        if analysis_domain == "managed":
            opening_moves.insert(0, "这是托管/.NET 样本，优先使用 decompile_function 读取 C#；若外部反编译器不可用，再看 IL/反汇编。")
        else:
            opening_moves.insert(0, "这是 native 样本，优先从入口点、导入分类和关键字符串切入，再决定是否继续看 Hex-Rays 伪代码或汇编。")

        return self._json_object({
            "summary": summary_text,
            "metadata": metadata,
            "statistics": statistics,
            "capabilities": capabilities,
            "quality": quality,
            "entrypoints": entrypoints,
            "interesting_functions": interesting_functions,
            "interesting_strings": interesting_strings,
            "string_index": survey.get("string_index", {}),
            "imports": import_summary,
            "managed_summary": managed_summary,
            "recommended_queries": recommended_queries,
            "recommended_next_tools": recommended_next_tools,
            "opening_moves": opening_moves,
        })

    def list_functions(self, *, filter_text: str = "", offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """分页列出函数。"""
        lowered = filter_text.lower()
        analysis_domain = self.get_analysis_domain()
        results: list[JsonObject] = []
        for ea in idautils.Functions():
            func = GET_FUNC(ea)
            if func is None:
                continue
            name = GET_FUNC_NAME(ea) or hex(ea)
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
            func = GET_FUNC(ea)
            if func is None:
                raise ValueError(f"找不到函数：{query}")
            return self._json_object({"ea": func.start_ea, "name": GET_FUNC_NAME(func.start_ea) or hex(func.start_ea)})
        partial: JsonObject | None = None
        for ea in idautils.Functions():
            name = GET_FUNC_NAME(ea) or hex(ea)
            if name == text:
                return self._json_object({"ea": ea, "name": name})
            if partial is None and text.lower() in name.lower():
                partial = self._json_object({"ea": ea, "name": name})
        if partial is None:
            raise ValueError(f"找不到函数：{query}")
        return partial

    def get_function(self, query: str) -> JsonObject:
        """返回单个函数详情。"""
        match = self.lookup_function(query)
        ea = self._match_ea(match)
        name = self._match_name(match)
        func = self.require_function(ea)
        return self._json_object({
            "addr": hex(func.start_ea),
            "name": name,
            "size": func.end_ea - func.start_ea,
            "prototype": self.function_signature(func.start_ea),
            "flags": int(func.flags),
            "comments": self.function_comments(func.start_ea),
            "callers": self.get_callers(hex(func.start_ea)),
            "callees": self.get_callees(hex(func.start_ea)),
        })

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
                    "to": self.xrefs_to(hex(func.start_ea)),
                    "from": self.get_xrefs_from(hex(func.start_ea)),
                },
                "comments": self.function_comments(func.start_ea),
                "basic_blocks": self.get_basic_blocks(hex(func.start_ea)),
            }
        )
        if include_asm:
            result["disassembly"] = self.disassemble_function(query)["text"]
        return result

    def analyze_functions(self, items: list[str]) -> list[JsonObject]:
        """批量分析多个函数。"""
        return [self.get_function_profile(query) for query in items]

    def function_signature(self, ea: int) -> str:
        """读取函数签名。"""
        return idc.get_type(ea) or (GET_FUNC_NAME(ea) or hex(ea))

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
        if analysis_domain == "managed":
            managed_result = self._managed_csharp_decompile(func.start_ea)
            if managed_result is not None:
                managed_warnings = managed_result.get("warnings")
                if isinstance(managed_warnings, list):
                    warnings.extend(str(item) for item in managed_warnings)
                return self._json_object({
                    "status": "ok",
                    "addr": hex(func.start_ea),
                    "name": func_name,
                    "signature": signature,
                    "analysis_domain": analysis_domain,
                    "representation": "csharp",
                    "backend": managed_result["backend"],
                    "confidence": "high" if managed_result["exact"] else "medium",
                    "reconstruction_level": "high_level_csharp" if managed_result["exact"] else "type_level_csharp",
                    "type_recovery": "high",
                    "variable_recovery": "partial",
                    "language": "csharp",
                    "text": managed_result["text"],
                    "source": managed_result["source"],
                    "warnings": warnings,
                    "error": None,
                    "managed_identity": managed_identity,
                })
        if self.hexrays_available():
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                cfunc_text = str(cfunc).strip()
                if not cfunc_text or cfunc_text == "None":
                    raise RuntimeError("Hex-Rays 返回了空文本")
                return self._json_object({
                    "status": "ok",
                    "addr": hex(func.start_ea),
                    "name": func_name,
                    "signature": signature,
                    "analysis_domain": analysis_domain,
                    "representation": "hexrays",
                    "backend": "ida_hexrays",
                    "confidence": "high",
                    "reconstruction_level": "high_level_c",
                    "type_recovery": "full",
                    "variable_recovery": "full",
                    "language": "c",
                    "text": cfunc_text,
                    "source": "ida_hexrays",
                    "warnings": warnings,
                    "error": None,
                    "managed_identity": managed_identity,
                })
            except Exception as exc:
                warnings.append(f"Hex-Rays 反编译失败，已降级：{exc}")
        representation = "il" if analysis_domain == "managed" else "asm_fallback"
        if representation == "il":
            warnings.append("当前样本属于托管/IL 域，暂未提供真正托管高层反编译，已返回 IL/反汇编级表示")
        return self._json_object({
            "status": "degraded",
            "addr": hex(func.start_ea),
            "name": func_name,
            "signature": signature,
            "analysis_domain": analysis_domain,
            "representation": representation,
            "backend": "ida_lines_managed" if representation == "il" else "ida_lines",
            "confidence": "medium" if representation == "il" else "low",
            "reconstruction_level": "il_text" if representation == "il" else "assembly_text",
            "type_recovery": "partial" if representation == "il" else "limited",
            "variable_recovery": "none",
            "language": "il" if representation == "il" else "asm",
            "text": self.render_managed_method_view(func.start_ea) if representation == "il" else self.render_function_disassembly(func.start_ea),
            "source": "ida_lines_managed" if representation == "il" else "ida_lines",
            "warnings": warnings or ["当前不可用 Hex-Rays，已回退到汇编文本"],
            "error": None,
            "managed_identity": managed_identity,
        })

    def disassemble_function(self, query: str) -> JsonObject:
        """返回函数反汇编。"""
        match = self.lookup_function(query)
        ea = self._match_ea(match)
        func = self.require_function(ea)
        lines = self.disassembly_lines(func.start_ea)
        return self._json_object({
            "addr": hex(func.start_ea),
            "name": self._match_name(match),
            "text": "\n".join(str(item.get("text", "")) for item in lines),
            "lines": lines,
        })

    def list_globals(self, *, filter_text: str = "", offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """列出全局符号。"""
        lowered = filter_text.lower()
        results: list[JsonObject] = []
        for ea, name in idautils.Names():
            if GET_FUNC(ea) is not None:
                continue
            if lowered and lowered not in name.lower() and lowered not in hex(ea):
                continue
            seg = GET_SEG(ea)
            results.append(
                {
                    "addr": hex(ea),
                    "name": name,
                    "segment": ida_segment.get_segm_name(seg) if seg is not None else "",
                    "size": GET_ITEM_SIZE(ea),
                }
            )
        return results[offset : offset + limit]

    def list_imports(self, *, offset: int = 0, limit: int = 200) -> list[JsonObject]:
        """列出导入表。"""
        results: list[JsonObject] = []
        for index in range(GET_IMPORT_MODULE_QTY()):
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

    def get_import_at(self, addr: str) -> JsonObject:
        """按地址读取导入项。"""
        ea = self.parse_address(addr)
        import_entry = self._import_entry_for_ea(ea)
        if import_entry is None:
            return self._json_object(
                {
                    "addr": hex(ea),
                    "found": False,
                    "module": "",
                    "name": "",
                    "ordinal": None,
                }
            )
        import_entry["found"] = True
        return import_entry

    def query_imports(self, *, module: str = "", filter_text: str = "", offset: int = 0, limit: int = 200) -> list[JsonObject]:
        """按条件查询导入。"""
        module_text = module.lower()
        name_text = filter_text.lower()
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

    def xrefs_to(self, target: str) -> list[JsonObject]:
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

    def query_xrefs(self, *, query: str, direction: str = "to", filter_text: str = "") -> list[JsonObject]:
        """按条件过滤 xref。"""
        if direction == "from":
            items = self.get_xrefs_from(query)
        elif direction == "to":
            items = self.xrefs_to(query)
        else:
            raise ValueError("direction 必须是 from 或 to")
        if not filter_text:
            return items
        return [item for item in items if filter_text.lower() in str(item.get("type", "")).lower()]

    def xrefs_to_field(self, struct_name: str, field_name: str) -> list[JsonObject]:
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
        return self.xrefs_to(hex(member_id))

    def get_callees(self, query: str) -> list[JsonObject]:
        """读取函数调用目标。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        edges: dict[int, JsonObject] = {}
        for item_ea in idautils.FuncItems(func.start_ea):
            edge_kind = self.callgraph_edge_kind(item_ea, func.start_ea)
            if edge_kind is None:
                continue
            for target in idautils.CodeRefsFrom(item_ea, False):
                callee_func = GET_FUNC(target)
                if callee_func is None and not self._is_external_call_target(target):
                    continue
                resolved = callee_func.start_ea if callee_func is not None else target
                if resolved in edges:
                    continue
                import_info = self._import_entry_for_ea(resolved) if callee_func is None else None
                edges[resolved] = {
                    "addr": hex(resolved),
                    "from_addr": hex(func.start_ea),
                    "to_addr": hex(resolved),
                    "name": str(import_info.get("name", "")) if import_info is not None else self.best_name(resolved),
                    "type": "internal" if callee_func is not None else "external",
                    "edge_kind": edge_kind,
                    "source": "coderefs",
                    "resolution": "function_start" if callee_func is not None else "direct_address",
                    "import": import_info,
                }
        return list(edges.values())

    def get_callers(self, query: str) -> list[JsonObject]:
        """读取函数调用者。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        callers: dict[int, JsonObject] = {}
        for caller_site in idautils.CodeRefsTo(func.start_ea, False):
            caller_func = GET_FUNC(caller_site)
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
        flowchart = GET_FLOW_CHART(func)
        blocks: list[JsonObject] = []
        edge_count = 0
        for block in cast(list[_FlowBlock], self._iter_objects(flowchart)):
            block_start = block.start_ea
            block_end = block.end_ea
            succs = [hex(self._int_attr(succ, "start_ea")) for succ in self._iter_objects(block.succs())]
            preds = [hex(self._int_attr(pred, "start_ea")) for pred in self._iter_objects(block.preds())]
            edge_count += len(succs)
            blocks.append(self._json_object({"start": hex(block_start), "end": hex(block_end), "succs": succs, "preds": preds}))
        cyclomatic = edge_count - len(blocks) + 2 if blocks else 1
        return self._json_object({"count": len(blocks), "cyclomatic_complexity": cyclomatic, "blocks": blocks})

    def list_strings(self, *, offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """分页列出字符串。

        这是显式字符串工具，原生样本会触发 IDA 字符串列表构建；大型
        数据库上可能很慢。默认摘要路径不得隐式调用本方法。
        """
        if limit <= 0:
            return []
        results: list[JsonObject] = []
        seen: set[tuple[str, str]] = set()
        for row in self._native_string_rows(limit=10_000):
            addr_value = row.get("addr")
            text_value = row.get("string")
            if not isinstance(addr_value, str) or not isinstance(text_value, str):
                continue
            key = (addr_value, text_value)
            if key in seen:
                continue
            seen.add(key)
            results.append(row)
        for row in self._managed_string_rows(limit=10_000):
            addr_value = row.get("addr")
            text_value = row.get("string")
            if not isinstance(addr_value, str) or not isinstance(text_value, str):
                continue
            key = (addr_value, text_value)
            if key in seen:
                continue
            seen.add(key)
            results.append(row)
        return results[offset : offset + limit]

    def find_strings(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """按子串搜索字符串。"""
        lowered = pattern.lower()
        matched = [item for item in self.list_strings(offset=0, limit=10_000) if lowered in str(item.get("string", "")).lower()]
        next_offset = offset + limit if offset + limit < len(matched) else None
        return self._json_object({"data": matched[offset : offset + limit], "next_offset": next_offset})

    def search_regex(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """按正则搜索字符串。"""
        compiled = re.compile(pattern)
        matched = [item for item in self.list_strings(offset=0, limit=10_000) if compiled.search(str(item.get("string", "")))]
        next_offset = offset + limit if offset + limit < len(matched) else None
        return self._json_object({"data": matched[offset : offset + limit], "next_offset": next_offset})

    def investigate_string(
        self,
        *,
        pattern: str = "",
        addr: str = "",
        max_strings: int = 20,
        max_usages: int = 100,
    ) -> JsonObject:
        """返回字符串到函数的闭环使用点结果。"""
        if not pattern and not addr:
            raise ValueError("必须提供 pattern 或 addr")

        matched_rows = self.list_strings(offset=0, limit=10_000)
        if pattern:
            lowered = pattern.lower()
            matched_rows = [
                row
                for row in matched_rows
                if lowered in str(row.get("string", "")).lower()
            ]
        if addr:
            target_ea = self.parse_address(addr)
            matched_rows = [
                row
                for row in matched_rows
                if isinstance(row.get("addr"), str) and self.parse_address(str(row.get("addr"))) == target_ea
            ]

        selected_matches = matched_rows[:max_strings]
        usages: list[JsonObject] = []
        function_map: dict[str, JsonObject] = {}
        usage_seen: set[tuple[str, str, str]] = set()

        for row in selected_matches:
            string_addr = str(row.get("addr", ""))
            string_text = str(row.get("string", ""))
            if not string_addr or not string_text:
                continue

            usage_rows = self._string_usage_rows(row)
            for usage in usage_rows:
                function_addr_value = usage.get("function_addr")
                function_addr = function_addr_value if isinstance(function_addr_value, str) else ""
                usage_addr_value = usage.get("usage_addr")
                usage_addr = usage_addr_value if isinstance(usage_addr_value, str) else ""
                dedupe_key = (string_addr, usage_addr, function_addr)
                if dedupe_key in usage_seen:
                    continue
                usage_seen.add(dedupe_key)
                usages.append(usage)
                if len(usages) >= max_usages:
                    break

                if function_addr:
                    summary = function_map.get(function_addr)
                    if summary is None:
                        function_name = str(usage.get("function_name", function_addr))
                        summary = self._json_object({
                            "addr": function_addr,
                            "name": function_name,
                            "prototype": self.function_signature(self.parse_address(function_addr)),
                            "type": self._classify_function(function_addr),
                            "use_count": 0,
                            "strings": [],
                        })
                        function_map[function_addr] = summary
                    strings_value = summary.get("strings")
                    if isinstance(strings_value, list) and string_text not in strings_value:
                        strings_value.append(string_text)
                    use_count = self._json_int_or_default(summary.get("use_count"), 0)
                    summary["use_count"] = use_count + 1
            if len(usages) >= max_usages:
                break

        functions = sorted(
            function_map.values(),
            key=lambda item: (
                self._json_int_or_default(item.get("use_count"), 0),
                len(cast(list[JsonValue], item.get("strings", []))) if isinstance(item.get("strings"), list) else 0,
            ),
            reverse=True,
        )

        match_rows: list[JsonObject] = []
        usage_count_by_string: dict[str, int] = {}
        for usage in usages:
            string_addr_value = usage.get("string_addr")
            if isinstance(string_addr_value, str):
                usage_count_by_string[string_addr_value] = usage_count_by_string.get(string_addr_value, 0) + 1
        for row in selected_matches:
            match_addr = str(row.get("addr", ""))
            enriched = dict(row)
            enriched["usage_count"] = usage_count_by_string.get(match_addr, 0)
            match_rows.append(self._json_object(enriched))

        return self._json_object({
            "query": {
                "pattern": pattern or None,
                "addr": addr or None,
            },
            "statistics": {
                "matched_strings": len(matched_rows),
                "returned_strings": len(match_rows),
                "returned_usages": len(usages),
                "distinct_functions": len(functions),
                "truncated_matches": len(matched_rows) > len(selected_matches),
                "truncated_usages": len(usages) >= max_usages,
            },
            "matches": match_rows,
            "usages": usages,
            "functions": functions,
            "recommended_next_tools": ["explain_function", "decompile_function", "query_xrefs", "export_report"],
        })

    def find_bytes(self, pattern: str, *, max_hits: int = 100) -> list[JsonObject]:
        """按字节模式搜索。"""
        current = GET_MIN_EA()
        end = GET_MAX_EA()
        results: list[JsonObject] = []
        while current != BADADDR and current < end and len(results) < max_hits:
            found = FIND_BYTES(
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

    def query_instructions(self, pattern: str, *, max_hits: int = 100) -> list[JsonObject]:
        """按助记符查询指令。"""
        results: list[JsonObject] = []
        lowered = pattern.lower()
        for ea in idautils.Heads():
            if not IS_CODE(GET_FLAGS(ea)):
                continue
            current = idc.print_insn_mnem(ea)
            line = self.line_text(ea)
            if lowered not in current.lower() and lowered not in line.lower():
                continue
            results.append({"addr": hex(ea), "mnem": current, "text": line})
            if len(results) >= max_hits:
                break
        return results

    def read_bytes(self, addrs: list[str], *, size: int = 16) -> list[JsonObject]:
        """读取字节。"""
        results: list[JsonObject] = []
        for addr in addrs:
            ea = self.parse_address(addr)
            data = GET_BYTES(ea, size, 0) or b""
            results.append({"addr": hex(ea), "size": len(data), "hex": data.hex()})
        return results

    def read_ints(self, items: list[JsonObject]) -> list[JsonObject]:
        """读取整数。"""
        results: list[JsonObject] = []
        for query in items:
            addr_text = query.get("addr")
            size_value = query.get("size", 4)
            signed_value = query.get("signed", False)
            if not isinstance(addr_text, str):
                raise ValueError("read_ints 的 addr 必须是字符串")
            if not isinstance(size_value, int):
                raise ValueError("read_ints 的 size 必须是整数")
            if not isinstance(signed_value, bool):
                raise ValueError("read_ints 的 signed 必须是布尔值")
            size = size_value
            signed = signed_value
            ea = self.parse_address(addr_text)
            raw = GET_BYTES(ea, size, 0) or b""
            value = int.from_bytes(raw, byteorder="little", signed=signed)
            results.append({"addr": hex(ea), "size": size, "signed": signed, "value": value})
        return results

    def read_strings(self, addrs: list[str], *, max_length: int = 512) -> list[JsonObject]:
        """读取字符串值。"""
        results: list[JsonObject] = []
        string_index = self._string_row_index(limit=10_000)
        for addr in addrs:
            ea = self.parse_address(addr)
            exact = string_index.get(ea)
            if exact is not None:
                results.append(exact)
                continue

            text = ""
            source = "unresolved"
            str_type = idc.get_str_type(ea)
            if isinstance(str_type, int) and str_type >= 0:
                raw = idc.get_strlit_contents(ea, max_length, str_type)
                if isinstance(raw, bytes):
                    text = self._decode_string_bytes(raw, str_type)
                    if text:
                        source = "ida_strlit_fallback"
            if not text and self.get_analysis_domain() == "managed":
                line_strings = self._line_string_literals(self.line_text(ea))
                text = line_strings[0] if line_strings else ""
                if text:
                    source = "managed_il_text"
            results.append(self._json_object({"addr": hex(ea), "string": text, "source": source}))
        return results

    def read_global_values(self, addrs: list[str], *, size: int = 8) -> list[JsonObject]:
        """读取全局值。"""
        return self.read_ints([self._json_object({"addr": addr, "size": size, "signed": False}) for addr in addrs])

    def get_stack_frame(self, query: str) -> JsonObject:
        """读取栈帧。"""
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        frame_id = int(idc.get_frame_id(func.start_ea))
        if frame_id in (-1, BADADDR):
            return self._json_object({"size": 0, "members": []})
        members: list[JsonObject] = []
        for member_offset, member_name, member_size in idautils.StructMembers(frame_id):
            members.append(
                {
                    "name": str(member_name),
                    "offset": int(member_offset),
                    "size": int(member_size),
                }
            )
        return self._json_object({"size": int(idc.get_frame_size(func.start_ea)), "members": members})

    def read_struct(self, struct_name: str) -> JsonObject:
        """读取结构体。"""
        struct_id = int(idc.get_struc_id(struct_name))
        if struct_id in (-1, BADADDR):
            type_row = self.inspect_type(struct_name)
            kind = type_row.get("kind")
            if kind in {"udt", "managed_type"}:
                return self._json_object({
                    "name": struct_name,
                    "size": None,
                    "members": type_row.get("members", []),
                    "catalog": type_row.get("catalog", "local_types"),
                    "source": type_row.get("source", "ida_typeinf"),
                })
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
        return self._json_object({"name": struct_name, "size": int(idc.get_struc_size(struct_id)), "members": members})

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
            tif = NEW_TINFO()
            get_numbered_type = cast(Callable[[object, int], bool], tif.get_numbered_type)
            if not get_numbered_type(cast(object, ida_typeinf.get_idati()), ordinal):
                continue
            raw_name = tif.get_type_name()
            name = str(raw_name).strip()
            if not name:
                continue
            row = self._type_row(name, tif)
            if lowered and not self._type_row_matches_filter(row, lowered):
                continue
            results.append(row)
        if self.get_analysis_domain() == "managed":
            results.extend(self.managed_types(filter_text=filter_text))
        return results

    def inspect_type(self, name: str) -> JsonObject:
        """读取单个类型。"""
        tif = NEW_TINFO()
        get_named_type = cast(Callable[[object, str], bool], tif.get_named_type)
        if not get_named_type(cast(object, ida_typeinf.get_idati()), name):
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
        items: list[str] | None = None,
        format_name: str = "json",
        limit: int = 1000,
    ) -> list[JsonObject]:
        """导出函数信息。

        这里保留 tool 层需要的三种视图：
        - `json`：富字段结构化导出，适合 AI/批处理继续消费
        - `c_header`：把函数原型拼成近似头文件
        - `prototypes`：只关心签名摘要
        """
        target_queries = self._export_function_targets(items=items, limit=limit)
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
                row["xrefs"] = self._json_object({
                    "to": self.xrefs_to(addr_value),
                    "from": self.get_xrefs_from(addr_value),
                })
                row["stack_frame"] = self.get_stack_frame(addr_value)
            exported.append(row)

        if format_name == "c_header":
            lines = ["// Auto-generated by ida-stdio-mcp", ""]
            for item in exported:
                prototype = item.get("prototype")
                if isinstance(prototype, str) and prototype:
                    lines.append(prototype.rstrip(";") + ";")
            return [self._json_object({"format": "c_header", "content": "\n".join(lines), "count": len(exported)})]

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
            return [self._json_object({"format": "prototypes", "functions": functions})]

        return [self._json_object({"format": "json", "functions": exported})]

    def export_full_analysis(
        self,
        *,
        function_limit: int = 200,
        string_limit: int = 500,
        global_limit: int = 200,
        import_limit: int = 500,
        type_limit: int = 200,
        struct_limit: int = 100,
        include_decompile: bool = True,
        include_asm: bool = False,
    ) -> JsonObject:
        """导出当前 IDB 的结构化分析总包。"""
        summary = self.triage_binary_snapshot(
            function_limit=min(function_limit, 12),
            string_limit=min(string_limit, 12),
            import_limit_per_category=6,
        )
        triage_snapshot = self.binary_survey_snapshot()
        functions_block = self.export_functions(format_name="json", limit=function_limit)[0]
        raw_functions = functions_block.get("functions")
        functions = cast(list[JsonObject], raw_functions) if isinstance(raw_functions, list) else []

        function_items: list[JsonObject] = []
        for row in functions:
            exported = dict(row)
            if not include_decompile:
                exported.pop("code", None)
                exported.pop("decompile_status", None)
                exported.pop("decompile_representation", None)
                exported.pop("warnings", None)
            if not include_asm:
                exported.pop("asm", None)
            function_items.append(self._json_object(exported))

        imports = self.list_imports(offset=0, limit=import_limit)
        globals_list = self.list_globals(offset=0, limit=global_limit)
        strings = self.list_strings(offset=0, limit=string_limit)
        all_types = self.query_types()
        all_structs = self.search_structs()
        statistics_value = triage_snapshot.get("statistics")
        statistics = statistics_value if isinstance(statistics_value, dict) else {}
        total_functions = self._json_int_or_default(statistics.get("total_functions"), len(function_items))
        total_strings = self._json_int_or_default(statistics.get("total_strings"), len(strings))

        return self._json_object({
            "bundle_format": "analysis_report_v2",
            "metadata": self.idb_metadata(),
            "capabilities": self.capabilities(),
            "summary": summary,
            "triage_snapshot": triage_snapshot,
            "entrypoints": self.entrypoints(),
            "imports": {
                "total": len(imports),
                "limit": import_limit,
                "truncated": len(imports) >= import_limit,
                "items": imports,
                "categories": self._categorize_imports(),
            },
            "globals": {
                "total": len(globals_list),
                "limit": global_limit,
                "truncated": len(globals_list) >= global_limit,
                "items": globals_list,
            },
            "strings": {
                "total_estimate": total_strings,
                "limit": string_limit,
                "truncated": total_strings > len(strings),
                "items": strings,
            },
            "types": {
                "total": len(all_types),
                "limit": type_limit,
                "truncated": len(all_types) > type_limit,
                "items": all_types[:type_limit],
            },
            "structs": {
                "total": len(all_structs),
                "limit": struct_limit,
                "truncated": len(all_structs) > struct_limit,
                "items": all_structs[:struct_limit],
            },
            "functions": {
                "format": "json",
                "total_estimate": total_functions,
                "limit": function_limit,
                "truncated": total_functions > len(function_items),
                "include_decompile": include_decompile,
                "include_asm": include_asm,
                "items": function_items,
            },
            "recommended_next_tools": [
                "explain_function",
                "decompile_function",
                "investigate_string",
                "read_struct",
                "query_types",
                "save_workspace",
            ],
        })

    def build_callgraph(self, items: list[str], *, max_depth: int = 3) -> JsonObject:
        """构建调用图。"""
        queue: list[tuple[str, int]] = [(root_item, 0) for root_item in items]
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
        return self._json_object({
            "nodes": list(nodes.values()),
            "edges": edges,
            "max_depth": max_depth,
            "external_targets": list(externals.values()),
        })

    def analyze_function(self, query: str, *, include_asm: bool = False) -> JsonObject:
        """函数级综合分析。"""
        profile = self.get_function_profile(query, include_asm=include_asm)
        profile["decompile"] = self.decompile_function(query)
        return profile

    def analyze_component(self, query: str, *, max_depth: int = 2, include_asm: bool = False) -> JsonObject:
        """组件级综合分析。"""
        return self._json_object({
            "root": self.analyze_function(query, include_asm=include_asm),
            "internal_call_graph": self.build_callgraph([query], max_depth=max_depth),
        })

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
            func = GET_FUNC(ea)
            is_function_root = func is not None and func.start_ea == ea
            node_type = "function" if is_function_root else ("code" if IS_CODE(GET_FLAGS(ea)) else "data")
            nodes.append(
                {
                    "addr": hex(ea),
                    "name": GET_NAME(ea) or None,
                    "func": GET_FUNC_NAME(func.start_ea) if func is not None else None,
                    "instruction": self.line_text(ea) if IS_LOADED(ea) else None,
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
                    next_refs.extend((ea, ref.to, "forward", ref.type, ref.iscode) for ref in idautils.XrefsFrom(ea, False))
                if direction in {"backward", "both"}:
                    next_refs.extend((ref.frm, ea, "backward", ref.type, ref.iscode) for ref in idautils.XrefsTo(ea, False))

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
                        "from_name": GET_NAME(from_ea) or None,
                        "to_name": GET_NAME(to_ea) or None,
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

        return self._json_object({
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
        })

    def microcode_summary(self, query: str, *, max_instructions: int = 80) -> ToolEnvelope:
        """返回只读 microcode 摘要。"""
        if not self.hexrays_available():
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": ["当前环境不可用 Hex-Rays，无法生成 microcode。"],
                    "data": None,
                }
            )
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            mba = getattr(cfunc, "mba", None)
            if mba is None:
                return self._json_object(
                    {
                        "status": "unsupported",
                        "warnings": ["Hex-Rays 未返回 mba_t，当前反编译结果无法读取 microcode。"],
                        "data": None,
                    }
                )
            blocks = self._microcode_blocks(mba, max_instructions=max_instructions)
            instruction_count = 0
            for block in blocks:
                raw_count = block.get("instruction_count")
                if isinstance(raw_count, int):
                    instruction_count += raw_count
            return self._json_object(
                {
                    "status": "ok",
                    "warnings": [],
                    "data": {
                        "addr": hex(func.start_ea),
                        "name": self._match_name(match),
                        "experimental": True,
                        "read_only": True,
                        "block_count": len(blocks),
                        "instruction_count": instruction_count,
                        "blocks": blocks,
                    },
                }
            )
        except Exception as exc:
            return self._json_object(
                {
                    "status": "degraded",
                    "warnings": [f"microcode 读取失败，已降级：{exc}"],
                    "data": None,
                }
            )

    def microcode_def_use(self, query: str, *, max_instructions: int = 120) -> ToolEnvelope:
        """返回 microcode def-use 线索。"""
        summary = self.microcode_summary(query, max_instructions=max_instructions)
        if summary.get("status") != "ok":
            return summary
        data = summary.get("data")
        if not isinstance(data, dict):
            return summary
        rows: list[JsonObject] = []
        blocks = data.get("blocks")
        if isinstance(blocks, list):
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                instructions = block.get("instructions")
                if not isinstance(instructions, list):
                    continue
                for instruction in instructions:
                    if not isinstance(instruction, dict):
                        continue
                    defs = instruction.get("defs")
                    uses = instruction.get("uses")
                    if defs or uses:
                        rows.append(
                            self._json_object(
                                {
                                    "block": block.get("serial"),
                                    "addr": instruction.get("addr"),
                                    "opcode": instruction.get("opcode"),
                                    "defs": defs,
                                    "uses": uses,
                                    "text": instruction.get("text"),
                                }
                            )
                        )
        return self._json_object(
            {
                "status": "ok",
                "warnings": ["def-use 来自 Hex-Rays microcode，只作为辅助线索。"],
                "data": {
                    "addr": data.get("addr"),
                    "name": data.get("name"),
                    "experimental": True,
                    "rows": rows,
                },
            }
        )

    def microcode_experiment(self, query: str, *, action: str = "mark_chains_dirty") -> ToolEnvelope:
        """执行实验性 microcode mutation。"""
        if action not in {"mark_chains_dirty"}:
            raise ValueError("microcode_experiment 当前仅支持 mark_chains_dirty")
        if not self.hexrays_available():
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": ["当前环境不可用 Hex-Rays，无法执行 microcode 实验。"],
                    "data": None,
                }
            )
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        cfunc = ida_hexrays.decompile(func.start_ea)
        mba = getattr(cfunc, "mba", None)
        if mba is None:
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": ["Hex-Rays 未返回 mba_t，无法执行 microcode 实验。"],
                    "data": None,
                }
            )
        mark_chains_dirty = getattr(mba, "mark_chains_dirty", None)
        if not callable(mark_chains_dirty):
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": ["当前 IDA 运行时未暴露 mba_t.mark_chains_dirty。"],
                    "data": None,
                }
            )
        mark_chains_dirty()
        return self._json_object(
            {
                "status": "ok",
                "warnings": ["这是 experimental microcode mutation；只在 --unsafe 与 --tool-surface expert 下暴露。"],
                "data": {
                    "addr": hex(func.start_ea),
                    "name": self._match_name(match),
                    "experimental": True,
                    "action": action,
                    "mutated": True,
                },
            }
        )

    def convert_integer(self, value: str | int, *, width: int = 8, signed: bool = False) -> JsonObject:
        """做整数与字节序转换。"""
        integer = int(value, 0) if isinstance(value, str) else value
        byte_width = max(1, width)
        blob = int(integer).to_bytes(byte_width, byteorder="little", signed=signed)
        mask = (1 << (byte_width * 8)) - 1
        return self._json_object({
            "input": value,
            "int": integer,
            "hex": hex(integer & mask),
            "little_endian_hex": blob.hex(),
            "big_endian_hex": blob[::-1].hex(),
            "signed": signed,
            "width": width,
        })

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
                existing = GET_CMT(ea, repeatable) or ""
                final_comment = f"{existing}\n{comment_text}".strip() if existing else comment_text
            if not SET_CMT(ea, final_comment, repeatable):
                raise RuntimeError(f"设置注释失败：{addr_text}")
            func = GET_FUNC(ea)
            if func is not None and func.start_ea == ea:
                existing_func_comment = GET_FUNC_CMT(func, repeatable) or ""
                func_comment = final_comment
                if append and existing_func_comment:
                    func_comment = f"{existing_func_comment}\n{comment_text}".strip()
                if not SET_FUNC_CMT(func, func_comment, repeatable):
                    raise RuntimeError(f"设置函数注释失败：{addr_text}")
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
            if not SET_NAME(ea, name_text, ida_name.SN_NOWARN):
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
            PATCH_BYTES(ea, blob)
            written = GET_BYTES(ea, len(blob), 0) or b""
            if written != blob:
                raise RuntimeError(f"写入字节失败：{addr_text}")
            self._refresh_analysis_range(ea, len(blob))
            results.append({"addr": hex(ea), "size": len(blob)})
        return results

    def write_ints(self, items: list[JsonObject]) -> list[JsonObject]:
        """按整数写入。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            value = item.get("value")
            size_value = item.get("size", 4)
            signed_value = item.get("signed", False)
            if not isinstance(addr_text, str) or not isinstance(value, int):
                raise ValueError("write_ints 的 addr 必须为字符串，value 必须为整数")
            if not isinstance(size_value, int):
                raise ValueError("write_ints 的 size 必须为整数")
            if not isinstance(signed_value, bool):
                raise ValueError("write_ints 的 signed 必须为布尔值")
            size = size_value
            signed = signed_value
            blob = value.to_bytes(size, byteorder="little", signed=signed)
            ea = self.parse_address(addr_text)
            PATCH_BYTES(ea, blob)
            written = GET_BYTES(ea, len(blob), 0) or b""
            if written != blob:
                raise RuntimeError(f"写入整数失败：{addr_text}")
            self._refresh_analysis_range(ea, len(blob))
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
            insn = NEW_INSN()
            size = CREATE_INSN(ea, insn)
            if size <= 0:
                raise RuntimeError(f"定义代码失败：{addr_text}")
            results.append({"addr": hex(ea), "size": size})
        return results

    def undefine_items(self, addrs: list[str]) -> list[JsonObject]:
        """取消定义。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            size = GET_ITEM_SIZE(ea)
            if not DEL_ITEMS(ea, ida_bytes.DELIT_SIMPLE, size):
                raise RuntimeError(f"取消定义失败：{addr_text}")
            results.append({"addr": hex(ea), "size": size})
        return results

    def declare_types(self, items: list[str]) -> list[JsonObject]:
        """把 C 声明写入本地类型库。"""
        results: list[JsonObject] = []
        for declaration in items:
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

    def infer_types(self, items: list[str]) -> list[JsonObject]:
        """推断地址上的可能类型并尽量写回。"""
        results: list[JsonObject] = []
        for query in items:
            ea = self.parse_address(query)
            func = GET_FUNC(ea)
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

            tif = NEW_TINFO()
            if GUESS_TINFO(tif, ea) > 0 and not tif.empty():
                applied = bool(APPLY_TINFO(ea, tif, ida_typeinf.TINFO_DEFINITE))
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

            if GET_TINFO(tif, ea) and not tif.empty():
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

            size = GET_ITEM_SIZE(ea)
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
            if not DEFINE_STKVAR(func, name_text, offset, tif):
                raise RuntimeError(f"定义栈变量失败：{addr_text} {name_text}")
            results.append({"addr": hex(func.start_ea), "name": name_text, "offset": offset, "type": type_text})
        return results

    def delete_stack_variables(self, items: list[JsonObject]) -> list[JsonObject]:
        """删除已声明的栈变量。"""
        results: list[JsonObject] = []
        for item in items:
            addr_text = item.get("addr")
            name_text = item.get("name")
            offset_value = item.get("offset")
            if not isinstance(addr_text, str):
                raise ValueError("delete_stack_variables 的 addr 必须为字符串")
            if name_text is not None and not isinstance(name_text, str):
                raise ValueError("delete_stack_variables 的 name 必须为字符串")
            if offset_value is not None and not isinstance(offset_value, (int, str)):
                raise ValueError("delete_stack_variables 的 offset 必须为整数或字符串")
            func = self.require_function(self.parse_address(addr_text))
            frame_id = int(idc.get_frame_id(func.start_ea))
            if frame_id in (-1, BADADDR):
                raise RuntimeError(f"无法获取函数栈帧：{addr_text}")

            member_offset = self._resolve_stack_member_offset(frame_id, name_text, offset_value)
            if member_offset is None:
                target = name_text if isinstance(name_text, str) and name_text else offset_value
                raise RuntimeError(f"找不到栈变量：{target}")
            if not idc.del_struc_member(frame_id, member_offset):
                raise RuntimeError(f"删除栈变量失败：{name_text or member_offset}")
            results.append({"addr": hex(func.start_ea), "name": name_text or "", "offset": member_offset})
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
                assembled = ASSEMBLE(current_ea, asm_line)
                if not isinstance(assembled, tuple):
                    raise RuntimeError(f"汇编失败：{asm_line}")
                assembled_pair = cast(tuple[object, ...], assembled)
                if len(assembled_pair) != 2:
                    raise RuntimeError(f"汇编失败：{asm_line}")
                assembled_ok = bool(assembled_pair[0])
                blob = assembled_pair[1]
                if not assembled_ok or not isinstance(blob, (bytes, bytearray)):
                    raise RuntimeError(f"汇编失败：{asm_line}")
                patch_blob = bytes(blob)
                PATCH_BYTES(current_ea, patch_blob)
                written = GET_BYTES(current_ea, len(patch_blob), 0) or b""
                if written != patch_blob:
                    raise RuntimeError(f"补丁写入失败：{hex(current_ea)}")
                self._refresh_analysis_range(current_ea, len(patch_blob))
                current_ea += len(blob)
            results.append({"addr": hex(ea), "size": current_ea - ea, "asm": asm_text})
        return results

    def evaluate_python(self, code: str) -> JsonObject:
        """执行 Python 代码。"""
        local_scope: dict[str, object] = {}
        try:
            value = eval(code, {}, local_scope)
            return self._json_object({"mode": "eval", "value": self.jsonify(value)})
        except SyntaxError:
            exec(code, {}, local_scope)
            return self._json_object({"mode": "exec", "locals": {key: self.jsonify(value) for key, value in local_scope.items()}})

    def execute_python_file(self, path: str) -> JsonObject:
        """执行 Python 文件。"""
        return self.evaluate_python(Path(path).read_text(encoding="utf-8"))

    def debug_start(self, path: str = "") -> ToolEnvelope:
        """启动调试会话。"""
        target = path or (ida_nalt.get_input_file_path() or "")
        if not target:
            return {"status": "unsupported", "data": {"reason": "当前没有可调试目标"}, "warnings": ["请显式提供 path"]}
        ok = bool(START_PROCESS(target, "", ""))
        ida_idd.get_dbg()
        backend_ready = True
        session_active = GET_PROCESS_STATE() != -1
        if ok and backend_ready and session_active:
            return self._json_object({
                "status": "ok",
                "data": {"started": True, "path": target, "backend_available": True, "session_active": True},
                "warnings": [],
            })
        return self._json_object({
            "status": "unsupported",
            "data": {"started": bool(ok), "path": target, "backend_available": backend_ready, "session_active": session_active},
            "warnings": ["当前环境未形成可用调试链路，后续寄存器/栈回溯/内存接口不可继续调用"],
        })

    def debug_exit(self) -> ToolEnvelope:
        """退出调试。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        EXIT_PROCESS()
        return self._json_object({"status": "ok", "data": {"exited": True}, "warnings": []})

    def debug_continue(self) -> ToolEnvelope:
        """继续执行。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        CONTINUE_PROCESS()
        return self._json_object({"status": "ok", "data": {"continued": True}, "warnings": []})

    def debug_run_to(self, addr: str) -> ToolEnvelope:
        """运行到指定地址。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        ok = bool(REQUEST_RUN_TO(self.parse_address(addr)))
        return self._json_object({"status": "ok" if ok else "unsupported", "data": {"requested": ok, "addr": addr}, "warnings": [] if ok else ["request_run_to 失败"]})

    def debug_step_into(self) -> ToolEnvelope:
        """单步进入。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        STEP_INTO()
        return self._json_object({"status": "ok", "data": {"step": "into"}, "warnings": []})

    def debug_step_over(self) -> ToolEnvelope:
        """单步越过。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        STEP_OVER()
        return self._json_object({"status": "ok", "data": {"step": "over"}, "warnings": []})

    def debug_breakpoints(self) -> list[JsonObject]:
        """列出断点。"""
        results: list[JsonObject] = []
        for index in range(GET_BPT_QTY()):
            bpt = NEW_BPT()
            if GET_NTH_BPT(index, bpt):
                results.append({"addr": hex(bpt.ea), "enabled": bool(bpt.enabled), "size": bpt.size})
        return results

    def debug_add_breakpoints(self, addrs: list[str]) -> list[JsonObject]:
        """添加断点。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not ADD_BPT(ea):
                raise RuntimeError(f"添加断点失败：{addr_text}")
            results.append({"addr": hex(ea)})
        return results

    def debug_delete_breakpoints(self, addrs: list[str]) -> list[JsonObject]:
        """删除断点。"""
        results: list[JsonObject] = []
        for addr_text in addrs:
            ea = self.parse_address(addr_text)
            if not DEL_BPT(ea):
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
            if not EXIST_BPT(ea):
                raise RuntimeError(f"找不到断点：{addr_text}")
            if not ENABLE_BPT(ea, enabled):
                raise RuntimeError(f"更新断点失败：{addr_text}")
            results.append({"addr": hex(ea), "enabled": enabled})
        return results

    def debug_registers(self, *, thread_id: int | None = None, names: list[str] | None = None) -> JsonObject:
        """读取寄存器。"""
        if GET_PROCESS_STATE() == -1:
            raise RuntimeError("当前没有活动调试会话")
        current_thread = thread_id if thread_id is not None else int(GET_CURRENT_THREAD())
        debugger = ida_idd.get_dbg()
        regvals = self._iter_objects(GET_REG_VALS(current_thread, -1))
        selected = {item.lower() for item in names} if names is not None else None
        registers: dict[str, JsonValue] = {}
        for reg_index, regval in enumerate(regvals):
            reg_info = cast(object, debugger.regs(reg_index))
            reg_name = str(getattr(reg_info, "name"))
            if selected is not None and reg_name.lower() not in selected:
                continue
            try:
                pyval_fn = cast(Callable[[object], object], getattr(regval, "pyval"))
                registers[reg_name] = self.jsonify(pyval_fn(getattr(reg_info, "dtype")))
            except Exception:
                registers[reg_name] = str(regval)
        return self._json_object({"thread_id": current_thread, "registers": registers})

    def debug_registers_all_threads(self, *, names: list[str] | None = None) -> ToolEnvelope:
        """读取所有线程的寄存器快照。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})

        current_thread = int(GET_CURRENT_THREAD())
        thread_count = int(GET_THREAD_QTY())
        threads: list[JsonObject] = []
        warnings: list[str] = []

        for index in range(thread_count):
            thread_id = int(GET_NTH_THREAD(index))
            if thread_id in (BADADDR, -1):
                warnings.append(f"第 {index} 个线程句柄无效，已跳过")
                continue
            thread_name = GET_NTH_THREAD_NAME(index)
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
            return self._json_object({
                "status": "unsupported",
                "data": {"reason": "没有可读取的线程寄存器", "thread_count": thread_count},
                "warnings": warnings or ["调试器未返回可用线程"],
            })

        return self._json_object({
            "status": "ok",
            "data": {"current_thread": current_thread, "thread_count": thread_count, "threads": threads},
            "warnings": warnings,
        })

    def debug_stacktrace(self) -> ToolEnvelope:
        """读取当前线程调用栈。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})

        thread_id = int(GET_CURRENT_THREAD())
        trace = NEW_CALL_STACK()
        if not COLLECT_STACK_TRACE(thread_id, trace):
            return self._json_object({"status": "unsupported", "data": {"reason": "读取调用栈失败", "thread_id": thread_id}, "warnings": ["collect_stack_trace 失败"]})

        frames: list[JsonObject] = []
        for index, frame in enumerate(trace):
            call_ea = int(frame.callea)
            function_ea = int(frame.funcea) if int(frame.funcea) != BADADDR else call_ea
            module_name = "<unknown>"
            module_info = NEW_MODINFO()
            if GET_MODULE_INFO(call_ea, module_info):
                raw_module_name = module_info.name
                if isinstance(raw_module_name, str) and raw_module_name:
                    module_name = Path(raw_module_name).name

            symbol_name = GET_NICE_COLORED_NAME(
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

        return self._json_object({"status": "ok", "data": {"thread_id": thread_id, "frames": frames}, "warnings": []})

    def debug_read_memory(self, addr: str, size: int) -> ToolEnvelope:
        """读取调试内存。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        data = READ_DBG_MEMORY(self.parse_address(addr), size)
        if data is None:
            return self._json_object({"status": "unsupported", "data": {"reason": "读取调试内存失败", "addr": addr}, "warnings": ["read_dbg_memory 返回 None"]})
        return self._json_object({"status": "ok", "data": {"addr": addr, "size": len(data), "hex": data.hex()}, "warnings": []})

    def debug_write_memory(self, addr: str, hex_data: str) -> ToolEnvelope:
        """写入调试内存。"""
        if GET_PROCESS_STATE() == -1:
            return self._json_object({"status": "unsupported", "data": {"reason": "当前没有活动调试会话"}, "warnings": ["未附加调试器"]})
        blob = bytes.fromhex(hex_data)
        written = WRITE_DBG_MEMORY(self.parse_address(addr), blob)
        if written != len(blob):
            return self._json_object({"status": "unsupported", "data": {"reason": "写入调试内存失败", "written": written, "expected": len(blob)}, "warnings": ["write_dbg_memory 未完整写入"]})
        return self._json_object({"status": "ok", "data": {"addr": addr, "size": len(blob)}, "warnings": []})

    def _refresh_analysis_range(self, start_ea: int, size: int) -> None:
        """在写回后主动触发局部重分析。"""
        end_ea = start_ea + max(1, size)
        PLAN_AND_WAIT(start_ea, end_ea, True)
        func = GET_FUNC(start_ea)
        if func is not None:
            PLAN_AND_WAIT(func.start_ea, func.end_ea, True)

    def _resolve_stack_member_offset(self, frame_id: int, name_text: str | None, offset_value: int | str | None) -> int | None:
        """解析栈变量在 frame struct 里的精确偏移。"""
        if offset_value is not None:
            target_offset = self._parse_signed_int(offset_value)
            for member_offset, _, _ in idautils.StructMembers(frame_id):
                if int(member_offset) == target_offset:
                    return int(member_offset)
            return None

        if not name_text:
            return None
        for member_offset, member_name, _ in idautils.StructMembers(frame_id):
            if str(member_name) == name_text:
                return int(member_offset)
        return None

    def parse_address(self, value: str) -> int:
        """解析地址或名称。"""
        text = value.strip()
        if text.startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
        ea = GET_NAME_EA(BADADDR, value)
        if ea == BADADDR:
            raise ValueError(f"Address/name not found: '{value}'")
        func = GET_FUNC(ea)
        return func.start_ea if func is not None else ea

    def require_function(self, ea: int) -> ida_funcs.func_t:
        """获取函数对象，不存在时直接失败。"""
        func = GET_FUNC(ea)
        if func is None:
            raise ValueError(f"找不到函数：{hex(ea)}")
        return func

    def best_name(self, ea: int) -> str:
        """返回尽量可读的名字。"""
        return GET_FUNC_NAME(ea) or GET_NAME(ea) or GET_EA_NAME(ea, 0) or hex(ea)

    def line_text(self, ea: int) -> str:
        """读取一行反汇编。"""
        line = GENERATE_DISASM_LINE(ea, 0)
        return ida_lines.tag_remove(line).strip() if line else ""

    def disassembly_lines(self, start_ea: int) -> list[JsonObject]:
        """渲染函数每行反汇编。"""
        func = self.require_function(start_ea)
        return [{"addr": hex(item_ea), "text": self.line_text(item_ea)} for item_ea in idautils.FuncItems(func.start_ea)]

    def render_function_disassembly(self, start_ea: int) -> str:
        """渲染完整函数反汇编文本。"""
        return "\n".join(f"{item['addr']}: {item['text']}" for item in self.disassembly_lines(start_ea))

    def _line_string_literals(self, text: str) -> list[str]:
        """从一行反汇编/IL 文本里提取双引号字符串。"""
        results: list[str] = []
        for match in STRING_LITERAL_PATTERN.finditer(text):
            literal = match.group(1)
            if literal:
                if "\\" in literal:
                    try:
                        results.append(bytes(literal, "utf-8").decode("unicode_escape"))
                        continue
                    except Exception:
                        pass
                results.append(literal)
        return results

    def _decode_string_bytes(self, raw: bytes, str_type: int) -> str:
        """根据字符串类型解码原始字节。"""
        if str_type == idc.STRTYPE_C_16:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return raw.decode("utf-8", errors="replace").rstrip("\x00")

    def _native_string_rows(self, *, limit: int = 2000) -> list[JsonObject]:
        """提取原生字符串索引。"""
        if limit <= 0:
            return []
        results: list[JsonObject] = []
        strings = CREATE_STRINGS()
        # `idautils.Strings()` 构造时已经 refresh；再次 setup 会重复
        # 调用 ida_strlist.build_strlist，在大型 UE/PDB 样本上代价很高。
        for item in cast(list[_StringItem], self._iter_objects(strings)):
            text = str(item)
            if not text:
                continue
            results.append(
                self._json_object(
                    {
                        "addr": hex(int(item.ea)),
                        "string": text,
                        "length": len(text),
                        "xref_count": len(list(idautils.XrefsTo(int(item.ea)))),
                        "source": "ida_strings",
                    }
                )
            )
            if len(results) >= limit:
                break
        return results

    def _string_row_index(self, *, limit: int = 10_000) -> dict[int, JsonObject]:
        """构建“地址 -> 字符串行”的精确索引。"""
        rows: dict[int, JsonObject] = {}
        for row in self._native_string_rows(limit=limit):
            addr_value = row.get("addr")
            if isinstance(addr_value, str):
                rows.setdefault(self.parse_address(addr_value), row)
        for row in self._managed_string_rows(limit=limit):
            addr_value = row.get("addr")
            if isinstance(addr_value, str):
                rows.setdefault(self.parse_address(addr_value), row)
        return rows

    def _managed_string_rows(self, *, limit: int = 2000) -> list[JsonObject]:
        """基于反汇编/IL 文本提取托管字符串行。

        这里不伪装成“完整字符串索引”，而是明确把可见于 IL/反汇编中的
        字符串字面量抽出来，至少保证 managed 场景下：
        - `list_strings`
        - `find_strings`
        - `read_strings`
        走的是同一条字符串来源。
        """
        if self.get_analysis_domain() != "managed":
            return []
        results: list[JsonObject] = []
        seen: set[tuple[int, str]] = set()
        for func_ea in idautils.Functions():
            for item_ea in idautils.FuncItems(func_ea):
                line = self.line_text(item_ea)
                for literal in self._line_string_literals(line):
                    key = (item_ea, literal)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(
                        {
                            "addr": hex(item_ea),
                            "string": literal,
                            "length": len(literal),
                            "xref_count": 1,
                            "source": "managed_il_text",
                            "function": GET_FUNC_NAME(func_ea) or hex(func_ea),
                        }
                    )
                    if len(results) >= limit:
                        return results
        return results

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
            for text in self._line_string_literals(self.line_text(item_ea)):
                if text and text not in seen:
                    seen.add(text)
                    results.append(text)
        return results

    def function_constants(self, start_ea: int) -> list[int]:
        """提取函数中的立即数。"""
        func = self.require_function(start_ea)
        constants: list[int] = []
        for item_ea in idautils.FuncItems(func.start_ea):
            insn = NEW_INSN()
            if DECODE_INSN(insn, item_ea) == 0:
                continue
            for operand in insn.ops:
                if operand.type == ida_ua.o_imm:
                    constants.append(int(operand.value))
        return constants

    def function_comments(self, start_ea: int) -> JsonObject:
        """读取函数内注释。"""
        func = self.require_function(start_ea)
        comments: JsonObject = {}
        function_regular = GET_FUNC_CMT(func, False)
        function_repeatable = GET_FUNC_CMT(func, True)
        if function_regular or function_repeatable:
            comments[hex(func.start_ea)] = self._json_object(
                {
                    "regular": function_regular or "",
                    "repeatable": function_repeatable or "",
                    "scope": "function",
                }
            )
        for item_ea in idautils.FuncItems(func.start_ea):
            regular = GET_CMT(item_ea, False)
            repeatable = GET_CMT(item_ea, True)
            if regular or repeatable:
                existing = comments.get(hex(item_ea))
                payload: JsonObject = {
                    "regular": regular or "",
                    "repeatable": repeatable or "",
                    "scope": "item",
                }
                if isinstance(existing, dict):
                    existing_regular = existing.get("regular")
                    existing_repeatable = existing.get("repeatable")
                    if isinstance(existing_regular, str) and not payload["regular"]:
                        payload["regular"] = existing_regular
                    if isinstance(existing_repeatable, str) and not payload["repeatable"]:
                        payload["repeatable"] = existing_repeatable
                    payload["scope"] = "function+item"
                comments[hex(item_ea)] = self._json_object(payload)
        return comments

    def managed_csharp_available(self) -> bool:
        """判断当前托管样本是否具备 C# 反编译能力。"""
        return self.get_analysis_domain() == "managed" and managed_decompiler_available()

    def _managed_csharp_decompile(self, start_ea: int) -> JsonObject | None:
        """尝试把托管方法反编译成 C#。"""
        identity = self.managed_method_identity(start_ea)
        if identity is None:
            return None
        full_type_value = identity.get("full_type")
        method_value = identity.get("method")
        if not isinstance(full_type_value, str) or not isinstance(method_value, str):
            return None

        assembly_path = Path(ida_nalt.get_input_file_path() or "")
        if not assembly_path.exists():
            return None

        result = decompile_managed_method(assembly_path, full_type_value, method_value)
        if result is None:
            return None

        warnings: list[str] = []
        if not result.extracted_exact:
            warnings.append("未能精确截取单方法，已返回所属类型的 C# 源码。")
        return self._json_object(
            {
                "text": result.method_source,
                "backend": result.command,
                "source": "ilspycmd",
                "exact": result.extracted_exact,
                "warnings": warnings,
            }
        )

    def managed_summary(self) -> JsonObject:
        """返回托管/.NET 目标的能力与类型摘要。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain != "managed":
            return self._json_object({
                "analysis_domain": analysis_domain,
                "available": False,
                "support_level": "not_managed",
                "external_decompiler": managed_decompiler_command() or "",
                "type_count": 0,
                "namespace_count": 0,
                "top_namespaces": [],
                "sample_types": [],
                "sample_methods": [],
            })
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
        top_namespaces: list[JsonObject] = [
            self._json_object({"namespace": namespace, "count": count})
            for namespace, count in sorted(namespace_histogram.items(), key=lambda item: item[1], reverse=True)[:20]
        ]
        support_level = "csharp_external" if self.managed_csharp_available() else "symbolic_il"
        return self._json_object({
            "analysis_domain": analysis_domain,
            "available": True,
            "support_level": support_level,
            "external_decompiler": managed_decompiler_command() or "",
            "type_count": len(managed_rows),
            "namespace_count": len(namespace_histogram),
            "top_namespaces": top_namespaces,
            "sample_types": managed_rows[:20],
            "sample_methods": sample_methods,
        })

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
        func = GET_FUNC(ea)
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

        tif = NEW_TINFO()
        if GET_TINFO(tif, func.start_ea) and tif.is_func():
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
        process_state = int(GET_PROCESS_STATE())
        current_thread = int(GET_CURRENT_THREAD())
        return {
            "backend_available": True,
            "session_active": process_state != -1,
            "process_state": process_state,
            "current_thread": current_thread if current_thread not in (-1, BADADDR) else None,
        }

    def _string_index_quality(self) -> str:
        """返回字符串索引质量的非阻塞声明。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain == "managed":
            return "symbolic_lazy"
        return "deferred"

    def _type_writeback_support(self) -> str:
        """评估类型写回能力。"""
        return "full"

    def _export_function_targets(self, *, items: list[str] | None, limit: int) -> list[str]:
        """确定导出目标函数集合。

        这里单独收口，是为了避免 `export_functions` 里混入太多筛选细节：
        - 未显式给 `items` 时，按当前数据库的函数列表分页导出
        - 给了 `items` 时，允许名字/地址混用，并自动去重
        """
        if not items:
            targets: list[str] = []
            for item in self.list_functions(offset=0, limit=limit):
                addr_value = item.get("addr")
                if isinstance(addr_value, str):
                    targets.append(addr_value)
            return targets

        targets = []
        seen: set[int] = set()
        for query in items[:limit]:
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
            func = GET_FUNC(func_start)
            if func is not None and bool(func.flags & ida_funcs.FUNC_THUNK):
                return "tailcall"
        return None

    def _is_external_call_target(self, ea: int) -> bool:
        """判断目标地址是否可视为合法的外部调用目标。"""
        seg = GET_SEG(ea)
        if seg is None:
            return False
        seg_name = ida_segment.get_segm_name(seg).lower()
        if "plt" in seg_name or "idata" in seg_name or "got" in seg_name or "extern" in seg_name:
            return True
        name = self.best_name(ea).lower()
        return name.startswith("__imp_") or name.startswith("j_")

    def _import_entry_for_ea(self, ea: int) -> JsonObject | None:
        """按地址解析导入项，优先使用 IDA 9.3 的 import-by-address API。"""
        if GET_IMPORT_ENTRY is not None and IMPORT_ENTRY_T is not None:
            runtime_entry = IMPORT_ENTRY_T()
            if GET_IMPORT_ENTRY(runtime_entry, ea):
                parsed = self._import_entry_from_runtime_object(ea, runtime_entry)
                if parsed is not None:
                    return parsed
        for item in self.list_imports(offset=0, limit=100_000):
            addr_text = item.get("addr")
            if isinstance(addr_text, str) and int(addr_text, 16) == ea:
                return self._json_object(item)
        return None

    def _import_entry_from_runtime_object(self, ea: int, runtime_entry: object) -> JsonObject | None:
        """把 IDA 9.3 运行时导入对象收窄成稳定 JSON。"""
        name = self._runtime_attr_text(runtime_entry, ("name", "import_name", "imported_name"))
        module = self._runtime_attr_text(runtime_entry, ("module", "module_name", "dll", "library"))
        module_index = self._runtime_attr_int(runtime_entry, ("mod_index", "module_index"))
        if not module and module_index is not None:
            module = ida_nalt.get_import_module_name(module_index) or f"module_{module_index}"
        ordinal = self._runtime_attr_int(runtime_entry, ("ordinal", "ord"))
        if ordinal is None:
            ordinal = self._runtime_vector_first_int(getattr(runtime_entry, "ordinals", None))
        if not name and ordinal is None:
            return None
        return self._json_object(
            {
                "addr": hex(ea),
                "name": name or (f"ord_{ordinal}" if ordinal is not None else self.best_name(ea)),
                "module": module,
                "ordinal": ordinal,
                "source": "ida_nalt.get_import_entry",
            }
        )

    @staticmethod
    def _runtime_attr_text(runtime_entry: object, names: tuple[str, ...]) -> str:
        """从第三方运行时对象读取字符串属性。"""
        for name in names:
            value = getattr(runtime_entry, name, None)
            if isinstance(value, str) and value:
                return value
        return ""

    @staticmethod
    def _runtime_attr_int(runtime_entry: object, names: tuple[str, ...]) -> int | None:
        """从第三方运行时对象读取整数属性。"""
        for name in names:
            value = getattr(runtime_entry, name, None)
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                return value
        return None

    @staticmethod
    def _runtime_vector_first_int(value: object) -> int | None:
        """从 SWIG 向量对象里读取第一个整数。"""
        if value is None:
            return None
        get_item = getattr(value, "__getitem__", None)
        if not callable(get_item):
            return None
        get_length = getattr(value, "__len__", None)
        try:
            if callable(get_length):
                length_value = get_length()
                if isinstance(length_value, bool) or not isinstance(length_value, int):
                    return None
                if length_value <= 0:
                    return None
            first = get_item(0)
        except Exception:
            return None
        if isinstance(first, bool):
            return None
        if isinstance(first, int):
            return first
        return None

    def _microcode_blocks(self, mba: object, *, max_instructions: int) -> list[JsonObject]:
        """把 mba_t 收窄为块与指令摘要。"""
        qty_value = getattr(mba, "qty", 0)
        qty = int(qty_value) if isinstance(qty_value, int) else 0
        get_mblock = getattr(mba, "get_mblock", None)
        if not callable(get_mblock):
            return []
        blocks: list[JsonObject] = []
        remaining = max(1, max_instructions)
        for index in range(qty):
            block = get_mblock(index)
            if block is None:
                continue
            instructions: list[JsonObject] = []
            current = getattr(block, "head", None)
            while current is not None and remaining > 0:
                instruction_ea = self._runtime_attr_int(current, ("ea",))
                opcode_value = self._runtime_attr_int(current, ("opcode",))
                instructions.append(
                    {
                        "addr": hex(instruction_ea) if instruction_ea is not None and instruction_ea != BADADDR else "",
                        "opcode": self._micro_opcode_name(opcode_value),
                        "defs": self._micro_operand_text(getattr(current, "d", None)),
                        "uses": [
                            item
                            for item in (
                                self._micro_operand_text(getattr(current, "l", None)),
                                self._micro_operand_text(getattr(current, "r", None)),
                            )
                            if item
                        ],
                        "text": self._micro_insn_text(current),
                    }
                )
                remaining -= 1
                current = getattr(current, "next", None)
            serial = self._runtime_attr_int(block, ("serial",))
            start = self._runtime_attr_int(block, ("start",))
            end = self._runtime_attr_int(block, ("end",))
            blocks.append(
                self._json_object(
                    {
                        "serial": serial if serial is not None else index,
                        "start": hex(start) if start is not None and start != BADADDR else "",
                        "end": hex(end) if end is not None and end != BADADDR else "",
                        "instruction_count": len(instructions),
                        "instructions": instructions,
                    }
                )
            )
            if remaining <= 0:
                break
        return blocks

    @staticmethod
    def _micro_opcode_name(opcode: int | None) -> str:
        """把 microcode opcode 转为尽量可读的名字。"""
        if opcode is None:
            return ""
        return str(opcode)

    @staticmethod
    def _micro_operand_text(operand: object | None) -> str:
        """把 microcode 操作数转为短文本。"""
        if operand is None:
            return ""
        text = str(operand).strip()
        if text.startswith("<") and text.endswith(">"):
            return ""
        return text

    @staticmethod
    def _micro_insn_text(instruction: object) -> str:
        """把 microcode 指令转为短文本。"""
        dstr = getattr(instruction, "dstr", None)
        if callable(dstr):
            rendered = dstr()
            return str(rendered).strip()
        return str(instruction).strip()

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
            list_value = cast(list[object], value)
            normalized_list: list[JsonValue] = [self.jsonify(item) for item in list_value]
            return normalized_list
        if isinstance(value, tuple):
            tuple_value = cast(tuple[object, ...], value)
            normalized_tuple: list[JsonValue] = [self.jsonify(item) for item in tuple_value]
            return normalized_tuple
        if isinstance(value, dict):
            dict_value = cast(dict[object, object], value)
            normalized_object: JsonObject = {str(key): self.jsonify(item) for key, item in dict_value.items()}
            return normalized_object
        return str(value)

    def _json_object(self, value: object) -> JsonObject:
        """把任意运行时对象收敛成 JSON 对象。"""
        normalized = self.jsonify(value)
        if not isinstance(normalized, dict):
            raise TypeError("内部错误：期望 JSON 对象")
        return normalized

    def _iter_objects(self, value: object) -> list[object]:
        """把未知可迭代对象收敛成对象列表。"""
        return list(cast(Iterable[object], value))

    def _int_attr(self, value: object, name: str) -> int:
        """读取对象整数属性。"""
        return int(getattr(value, name))

    def _json_int_or_default(self, value: JsonValue | None, default: int = 0) -> int:
        """把 JSON 数值安全收窄为整数。"""
        if isinstance(value, bool):
            return default
        if isinstance(value, int):
            return value
        return default

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
        chars: list[str] = []
        chars.append("r" if perm & ida_segment.SEGPERM_READ else "-")
        chars.append("w" if perm & ida_segment.SEGPERM_WRITE else "-")
        chars.append("x" if perm & ida_segment.SEGPERM_EXEC else "-")
        return "".join(chars)

    def _classify_function(self, addr_text: str) -> str:
        func = self.require_function(self.parse_address(addr_text))
        if func.flags & ida_funcs.FUNC_THUNK:
            return "thunk"
        block_count = len(self._iter_objects(GET_FLOW_CHART(func)))
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
        return self._json_object({
            "total_edges": total_edges,
            "max_depth_estimate": None,
            "root_functions": roots[:25],
            "leaf_functions_count": leaf_count,
        })

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
        return self._json_object(dict(buckets))

    def _interesting_function_rows(self, *, limit: int = 12, seed_limit: int = 160) -> list[JsonObject]:
        """选出更值得优先逆向的函数摘要。"""
        entrypoints = self.entrypoints()
        entry_names = {
            str(item.get("name", "")).lower()
            for item in entrypoints
            if isinstance(item.get("name"), str)
        }
        entry_addrs = {
            str(item.get("addr", ""))
            for item in entrypoints
            if isinstance(item.get("addr"), str)
        }

        seeds: list[tuple[int, JsonObject]] = []
        for row in self.list_functions(limit=seed_limit):
            if bool(row.get("is_library", False)):
                continue
            score = self._function_interest_seed_score(row, entry_names=entry_names, entry_addrs=entry_addrs)
            if score <= 0:
                continue
            seeds.append((score, row))

        seeds.sort(
            key=lambda item: (
                item[0],
                self._json_int_or_default(item[1].get("size"), 0),
                0 if str(item[1].get("name", "")).startswith("sub_") else 1,
            ),
            reverse=True,
        )

        detailed_rows: list[JsonObject] = []
        seen_addrs: set[str] = set()
        for seed_score, row in seeds[: max(limit * 3, 24)]:
            addr_value = row.get("addr")
            if not isinstance(addr_value, str) or addr_value in seen_addrs:
                continue
            seen_addrs.add(addr_value)
            try:
                xrefs = self.xrefs_to(addr_value)
                callees = self.get_callees(addr_value)
                func_type = self._classify_function(addr_value)
            except Exception:
                xrefs = []
                callees = []
                func_type = "unknown"

            score = seed_score + min(len(xrefs), 6) * 2 + min(len(callees), 6)
            if func_type == "complex":
                score += 4
            elif func_type == "wrapper":
                score += 2
            elif func_type == "thunk":
                score -= 3

            detailed_rows.append(
                self._json_object({
                    "addr": addr_value,
                    "name": row.get("name", addr_value),
                    "size": row.get("size", 0),
                    "signature": row.get("signature", ""),
                    "is_entrypoint": addr_value in entry_addrs or str(row.get("name", "")).lower() in entry_names,
                    "xref_count": len(xrefs),
                    "callee_count": len(callees),
                    "type": func_type,
                    "score": score,
                })
            )

        detailed_rows.sort(
            key=lambda item: (
                self._json_int_or_default(item.get("score"), 0),
                self._json_int_or_default(item.get("xref_count"), 0),
                self._json_int_or_default(item.get("callee_count"), 0),
                self._json_int_or_default(item.get("size"), 0),
            ),
            reverse=True,
        )
        return detailed_rows[:limit]

    def _function_interest_seed_score(
        self,
        row: JsonObject,
        *,
        entry_names: set[str],
        entry_addrs: set[str],
    ) -> int:
        """估算某个函数作为开局目标的优先级。"""
        name = str(row.get("name", ""))
        addr = str(row.get("addr", ""))
        lowered = name.lower()
        score = 0

        if addr in entry_addrs or lowered in entry_names:
            score += 20
        if not name.startswith("sub_"):
            score += 6
        if any(keyword in lowered for keyword in ("main", "start", "entry", "init", "auth", "login", "check", "verify", "decrypt", "encrypt", "dispatch", "handle", "process", "flag")):
            score += 8

        size = self._json_int_or_default(row.get("size"), 0)
        score += min(size // 64, 6)

        signature = row.get("signature")
        if isinstance(signature, str) and signature:
            score += 2
        if "managed_identity" in row:
            score += 2
        return score

    def _interesting_string_rows(self, *, limit: int = 12, pool_limit: int = 2000) -> list[JsonObject]:
        """选出更值得优先追踪的字符串。"""
        scored_rows: list[JsonObject] = []
        for row in self.list_strings(limit=pool_limit):
            text_value = row.get("string")
            if not isinstance(text_value, str) or not text_value.strip():
                continue
            scored = dict(row)
            scored["score"] = self._string_interest_score(row)
            scored_rows.append(self._json_object(scored))

        scored_rows.sort(
            key=lambda item: (
                self._json_int_or_default(item.get("score"), 0),
                self._json_int_or_default(item.get("xref_count"), 0),
                self._json_int_or_default(item.get("length"), 0),
            ),
            reverse=True,
        )
        return scored_rows[:limit]

    def _string_interest_score(self, row: JsonObject) -> int:
        """估算某条字符串对逆向开局的价值。"""
        text = str(row.get("string", ""))
        lowered = text.lower()
        xref_count = self._json_int_or_default(row.get("xref_count"), 0)
        score = min(xref_count * 3, 18)

        if 4 <= len(text) <= 120:
            score += 4
        elif len(text) > 200:
            score -= 2

        if any(
            keyword in lowered
            for keyword in (
                "http",
                "https",
                "socket",
                "token",
                "password",
                "login",
                "error",
                "fail",
                "flag",
                ".dll",
                ".exe",
                ".sys",
                ".so",
                ".json",
                ".xml",
                "\\",
                "/",
                "%s",
                "%d",
            )
        ):
            score += 8

        if text.count(" ") >= 2:
            score += 2
        if sum(1 for ch in text if ch.isalnum()) < 3:
            score -= 6
        if len(set(text)) <= 2:
            score -= 6
        return score

    def _import_category_summary(self, *, limit_per_category: int = 6) -> JsonObject:
        """把导入分类收敛为更适合摘要阅读的结构。"""
        categorized = self._categorize_imports()
        summary: JsonObject = {}
        for category, value in categorized.items():
            items = cast(list[JsonObject], value) if isinstance(value, list) else []
            summary[category] = self._json_object({
                "count": len(items),
                "examples": items[:limit_per_category],
            })
        return self._json_object(summary)

    def _recommended_binary_queries(
        self,
        entrypoints: list[JsonObject],
        interesting_functions: list[JsonObject],
    ) -> list[JsonValue]:
        """给出下一步最值得查看的函数查询词。"""
        results: list[JsonValue] = []
        seen: set[str] = set()
        for row in [*entrypoints, *interesting_functions]:
            name_value = row.get("name")
            addr_value = row.get("addr")
            query = ""
            if isinstance(name_value, str) and name_value and not name_value.startswith("sub_"):
                query = name_value
            elif isinstance(addr_value, str):
                query = addr_value
            if query and query not in seen:
                seen.add(query)
                results.append(query)
            if len(results) >= 8:
                break
        return results

    def _recommended_binary_tools(self, *, analysis_domain: str, has_strings: bool) -> list[JsonValue]:
        """返回摘要场景下推荐的下一跳工具。"""
        tools: list[str] = ["list_functions", "decompile_function", "get_function_profile"]
        if has_strings:
            tools.append("investigate_string")
        if analysis_domain == "managed":
            tools.extend(["query_types", "inspect_type", "export_report"])
        else:
            tools.extend(["read_struct", "query_types", "export_report"])

        deduped: list[JsonValue] = []
        seen: set[str] = set()
        for name in tools:
            if name in seen:
                continue
            seen.add(name)
            deduped.append(name)
        return deduped

    def _string_usage_rows(self, row: JsonObject) -> list[JsonObject]:
        """把单条字符串记录展开为使用点列表。"""
        addr_value = row.get("addr")
        string_text = str(row.get("string", ""))
        source = str(row.get("source", ""))
        if not isinstance(addr_value, str):
            return []

        if source == "managed_il_text":
            function_name = row.get("function")
            func = GET_FUNC(self.parse_address(addr_value))
            function_addr = hex(func.start_ea) if func is not None else None
            return [
                self._json_object({
                    "string_addr": addr_value,
                    "string": string_text,
                    "string_source": source,
                    "usage_addr": addr_value,
                    "usage_kind": "inline_literal",
                    "xref_type": "inline_literal",
                    "instruction": self.line_text(self.parse_address(addr_value)),
                    "function_addr": function_addr,
                    "function_name": function_name if isinstance(function_name, str) else (self.best_name(func.start_ea) if func is not None else None),
                })
            ]

        string_ea = self.parse_address(addr_value)
        results: list[JsonObject] = []
        for ref in idautils.XrefsTo(string_ea):
            usage_addr = hex(ref.frm)
            func = GET_FUNC(ref.frm)
            function_addr = hex(func.start_ea) if func is not None else None
            function_name = self.best_name(func.start_ea) if func is not None else None
            results.append(
                self._json_object({
                    "string_addr": addr_value,
                    "string": string_text,
                    "string_source": source,
                    "usage_addr": usage_addr,
                    "usage_kind": "xref",
                    "xref_type": self.xref_type_name(ref.type),
                    "instruction": self.line_text(ref.frm),
                    "function_addr": function_addr,
                    "function_name": function_name,
                })
            )
        return results

    def _type_row(self, name: str, tif: ida_typeinf.tinfo_t) -> JsonObject:
        return self._json_object({
            "catalog": "local_types",
            "kind": self._type_kind(tif),
            "name": name,
            "namespace": "",
            "declaration_or_signature": self._print_tinfo(tif),
            "members": self._type_members(tif),
            "source": "ida_typeinf",
        })

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
        udt_data = NEW_UDT_DATA()
        get_udt_details = cast(Callable[[ida_typeinf.udt_type_data_t], bool], tif.get_udt_details)
        if not get_udt_details(udt_data):
            return []
        return [
            self._json_object({
                "name": member.name,
                "offset": member.offset,
                "size": member.size,
                "type": self._print_tinfo(member.type),
            })
            for member in udt_data
        ]

    def _type_row_matches_filter(self, row: JsonObject, lowered: str) -> bool:
        """判断类型行是否真正命中过滤条件。"""
        haystacks: list[str] = []
        for key in ("name", "namespace", "declaration_or_signature", "kind", "catalog"):
            value = row.get(key)
            if isinstance(value, str) and value:
                haystacks.append(value.lower())
        members = row.get("members")
        if isinstance(members, list):
            for member in members:
                if not isinstance(member, dict):
                    continue
                for key in ("name", "type", "signature", "full_name"):
                    value = member.get(key)
                    if isinstance(value, str) and value:
                        haystacks.append(value.lower())
        return any(lowered in item for item in haystacks)

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
            tif = NEW_TINFO()
            try:
                parse_result = PARSE_DECL(tif, cast(object, ida_typeinf.get_idati()), candidate, flags)
            except Exception:
                continue
            if parse_result is not None and not tif.empty():
                return tif

        parsed = idc.parse_decl(type_text, flags)
        if isinstance(parsed, tuple):
            parsed_tuple = cast(tuple[object, ...], parsed)
            if len(parsed_tuple) < 2:
                parsed_tuple = ()
        else:
            parsed_tuple = ()
        if len(parsed_tuple) >= 2:
            type_info = parsed_tuple[1]
            if isinstance(type_info, ida_typeinf.tinfo_t):
                return type_info

        raise ValueError(f"无法解析类型：{type_text}")

    def _managed_support_matrix(self) -> JsonObject:
        """返回托管能力矩阵。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain != "managed":
            return self._json_object({
                "available": False,
                "type_catalog": "native_only",
                "decompiler": "native_only",
                "notes": ["当前样本不是托管/.NET 程序"],
            })
        return self._json_object({
            "available": True,
            "type_catalog": "symbolic_managed_types",
            "decompiler": "external_csharp" if self.managed_csharp_available() else "il_symbolic_fallback",
            "notes": [
                "托管类型目录仍以 IDA 已识别符号和方法签名为主。",
                "若系统存在 ilspycmd，则 decompile_function 会直接返回高层 C# 结果。",
            ],
        })

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
        pointer_size = 8 if GET_APP_BITNESS() >= 64 else 4
        item_size = GET_ITEM_SIZE(ea)
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

        target_func = GET_FUNC(target)
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
        pointer_size = 8 if GET_APP_BITNESS() >= 64 else 4
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
        pointer_size = 8 if GET_APP_BITNESS() >= 64 else 4
        target = self._read_pointer_target(ea, pointer_size)
        if target is None:
            return None

        tif = NEW_TINFO()
        if not GET_TINFO(tif, target) or tif.empty():
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
            target = int(GET_QWORD(ea))
        else:
            target = int(GET_DWORD(ea))
        if target in (0, BADADDR):
            return None
        if not IS_LOADED(target):
            return None
        return target

    def _try_apply_decl(self, ea: int, type_text: str) -> bool:
        """尝试把声明应用到地址上。"""
        try:
            tif = self._parse_type_tinfo(type_text)
        except Exception:
            return False
        return bool(APPLY_TINFO(ea, tif, ida_typeinf.TINFO_DEFINITE))

    @staticmethod
    def _looks_like_address(text: str) -> bool:
        if text.startswith("0x"):
            return True
        return text.isdigit()
