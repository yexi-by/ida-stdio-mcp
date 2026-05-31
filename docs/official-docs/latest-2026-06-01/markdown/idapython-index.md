# IDAPython overview and quick reference

- 官方来源：https://python.docs.hex-rays.com/index.html

- ida_auto
- ida_bitrange
- ida_bytes
- ida_dbg
- ida_dirtree
- ida_diskio
- ida_entry
- ida_expr
- ida_fixup
- ida_fpro
- ida_frame
- ida_funcs
- ida_gdl
- ida_graph
- ida_hexrays
- ida_ida
- ida_idaapi
- ida_idc
- ida_idd
- ida_idp
- ida_ieee
- ida_kernwin
- ida_libfuncs
- ida_lines
- ida_lumina
- ida_loader
- ida_merge
- ida_mergemod
- ida_moves
- ida_nalt
- ida_name
- ida_netnode
- ida_offset
- ida_pro
- ida_problems
- ida_range
- ida_regfinder
- ida_registry
- ida_search
- ida_segment
- ida_segregs
- ida_srclang
- ida_strlist
- ida_tryblks
- ida_typeinf
- ida_ua
- ida_undo
- ida_xref
- idaapi
- idadex
- idautils
- idc
- init
- lumina_model

IDAPython references

-
- IDAPython API Reference
- View page source

# IDAPython API Reference

IDAPython allows you to create custom scripts and plugins that enhance IDA’s core functionality. This reference documentation covers 50+ modules for disassembly manipulation, decompilation, debugging, and UI customization. You can explore the IDAPython API by navigating the modules below, or use the quick reference to jump straight to what you need.

Tip

Looking for a simpler, more Pythonic way to script IDA? The IDA Domain API provides a high-level, developer-friendly interface built on top of IDAPython. It’s designed from the ground up with modern Python best practices, offering:

-
Cleaner syntax - Write less boilerplate, focus on reverse engineering tasks

-
Better type hints - Enhanced IDE support with full type annotations

-
Intuitive abstractions - Work directly with domain concepts like functions, types, and cross-references

-
Full compatibility - Use alongside IDAPython; both APIs work seamlessly together

-
Open source - Community-driven development with independent versioning

-
Pure Python - No compilation required, works with modern Python versions

The Domain API doesn’t replace IDAPython—it complements it. Use Domain API for everyday scripting tasks and drop down to IDAPython when you need fine-grained control or access to advanced features.

## Quick Reference by Task

### Reading/Writing Bytes

-
ida_bytes: `get_byte`, `patch_byte`, `get_flags`, `get_strlit_contents`

-
idc: `get_wide_byte`, `patch_byte`, `get_strlit_contents`

### Working with Functions

-
ida_funcs: `get_func`, `add_func`, `get_func_name`, `func_t`

-
ida_frame: `get_frame`, `add_stkvar`, `get_spd`

-
idautils: `Functions()`, `FuncItems()`

### Names and Labels

-
ida_name: `set_name`, `get_name`, `demangle_name`

-
idc: `set_name`, `get_name`

### Segments

-
ida_segment: `get_segm_by_name`, `add_segm`, `segment_t`

-
idautils: `Segments()`

### Cross-References

-
ida_xref: `add_cref`, `add_dref`, `get_first_cref_to`

-
idautils: `XrefsTo()`, `XrefsFrom()`

### Types and Structures

-
ida_typeinf: `tinfo_t`, `get_idati`, `parse_decl`

-
`ida_struct`(deprecated — use ida_typeinf instead): `get_struc`, `add_struc_member`

### Decompilation

-
ida_hexrays: `decompile`, `cfunc_t`, `citem_t`, `mba_t`, `Hexrays_Hooks`

### UI and Dialogs

-
ida_kernwin: `ask_yn`, `ask_str`, `Choose`, `action_handler_t`, `register_action`

-
ida_graph: `GraphViewer`

### Debugging

-
ida_dbg: `run_to`, `step_into`, `get_reg_val`, `add_bpt`

### Search

-
ida_search: `find_binary`, `find_text`

-
idautils: `Heads()`

## Module Reference

### Essential (Start Here)

-
idautils — High-level iteration: `Functions()`, `Segments()`, `Heads()`, `XrefsTo()`, `XrefsFrom()`, `Names()`

-
idc — IDC compatibility layer: `get_wide_byte`, `set_name`, `get_func_name`, `add_func`

-
ida_idaapi — Plugin base class, `BADADDR`, `ea_t`, `plugin_t`

-
idaapi — Legacy compatibility module

### Bytes and Flags

-
ida_bytes — `get_byte`, `patch_byte`, `get_flags`, `del_items`, `create_data`, `get_strlit_contents`; `flags64_t` manipulation

-
ida_nalt — Netnode altvals/supvals: `get_aflags`, `set_aflags`, `refinfo_t`

### Functions

-
ida_funcs — `func_t`, `get_func`, `add_func`, `del_func`, `get_func_qty`, `set_func_cmt`; use with ida_frame, ida_name

-
ida_frame — Stack frames: `get_frame`, `add_stkvar`, `get_spd`

### Names

-
ida_name — `set_name`, `get_name`, `get_name_ea`, `demangle_name`, `SN_*` flags

-
ida_entry — Entry points: `add_entry`, `get_entry_qty`, `get_entry`

### Segments

-
ida_segment — `segment_t`, `get_segm_by_name`, `add_segm_ex`, `getseg`, `get_segm_qty`

-
ida_segregs — Segment registers: `get_sreg`, `set_default_sreg_value`

-
ida_range — `range_t` base class for address ranges

### Cross-References

-
ida_xref — `add_cref`, `add_dref`, `del_cref`, `get_first_cref_to`, `xrefblk_t`; `fl_*` and `dr_*` constants

### Search

-
ida_search — `find_binary`, `find_text`, `find_code`, `SEARCH_*` flags

### Decompiler (Hex-Rays)

-
ida_hexrays — `decompile`, `cfunc_t`, `citem_t`, `cexpr_t`, `cinsn_t`, `mba_t`, `minsn_t`, `lvar_t`, `Hexrays_Hooks`, `ctree_visitor_t`

### Types

-
ida_typeinf — `tinfo_t`, `parse_decl`, `get_idati`, `apply_tinfo`, `udt_type_data_t`, `func_type_data_t`

### UI

-
ida_kernwin — `ask_yn`, `ask_str`, `jumpto`, `refresh_idaview`, `Choose`, `simplecustviewer_t`, `action_handler_t`, `register_action`, `UI_Hooks`

-
ida_lines — `generate_disasm_line`, `tag_remove`, `COLSTR`, `COLOR_*`

-
ida_graph — `GraphViewer`, `set_node_info`, `get_graph_viewer`

### Debugging

-
ida_dbg — `run_to`, `step_into`, `step_over`, `get_reg_val`, `add_bpt`, `DBG_Hooks`

-
ida_idd — `debugger_t`, `register_info_t`, `bpt_t`

### Instructions

-
ida_ua — `insn_t`, `op_t`, `decode_insn`, `create_insn`, `print_insn_mnem`

-
ida_idp — `processor_t`, `ph` (processor handle), `IDP_Hooks`

-
`ida_allins` — Instruction opcodes (`NN_*`, `ARM_*`, etc.)

### Database

-
ida_netnode — `netnode` class for persistent storage: `altval`, `supval`, `hashval`

-
ida_loader — `load_file`, `save_database`, `snapshot_t`

-
ida_auto — `auto_wait`, `plan_ea`, `AU_*` queue constants

### Analysis

-
ida_problems — `PR_*` problem types, `get_problem`

-
ida_offset — `op_offset`, `get_offbase`

-
ida_fixup — `fixup_data_t`, `set_fixup`, `get_fixup`

-
ida_libfuncs — `apply_idasgn_to` (FLIRT)

### Lumina

-
ida_lumina — `calc_func_metadata`, `apply_metadata`, `score_metadata`, `backup_metadata`, `revert_metadata`, `get_server_connection`, `func_info_t`, `lumina_client_t`

-
lumina_model — High-level helpers: `func_md_t`, `idb_md_t`, `differ_t`

### Utility

-
ida_pro — `qvector`, `qstring`, `ea_t`, `BADADDR`

-
ida_ida — `idainfo` (`inf` structure), `cvar.inf`

-
ida_expr — `idc_value_t`, `eval_idc_expr`

-
ida_strlist — `string_info_t`, `get_strlist_qty`

-
ida_diskio — `idadir`, `getsysfile`

-
ida_registry — `reg_read_string`, `reg_write_string`

### Less Common

-
ida_gdl — `qflow_chart_t`, GDL graph export

-
ida_bitrange — `bitrange_t` for bit-level operations

-
ida_tryblks — `tryblk_t` exception handling info

-
ida_undo — `perform_undo`, `create_undo_point`

-
ida_merge — Database merging

-
ida_mergemod — Merge module interface

-
ida_srclang — Source language detection

-
ida_regfinder — Register value tracking

-
ida_fpro — File operations

-
ida_ieee — IEEE float conversion

-
ida_dirtree — Folder organization

-
ida_moves — Navigation history

-
idadex — Extension utilities

-
init — Initialization

## Common Patterns

```text
# Iterate all functions
for ea in idautils.Functions():
 name = idc.get_func_name(ea)

# Get xrefs to address
for xref in idautils.XrefsTo(ea):
 print(hex(xref.frm))

# Decompile function
cfunc = ida_hexrays.decompile(ea)
print(cfunc)

# Create action
class MyHandler(ida_kernwin.action_handler_t):
 def activate(self, ctx): ...
 def update(self, ctx): return ida_kernwin.AST_ENABLE_ALWAYS

```

## Other Documentation Resources

Explore the Developer Guide in our Hex-Rays Documentation Hub:

-
Cookbook: Check our examples library, which demonstrates practical implementation for the IDAPython API, complementing this reference. The samples include recent examples for working with types.

-
Getting Started: If you’re new to IDAPython, we recommend starting with Getting Started with IDAPython. These docs introduce key concepts and help you begin exploring IDAPython’s capabilities.

-
Migration Guide: Read our Porting Guide that streamlines the process of updating your current scripts and plugins to the latest version of IDAPython API, along with how-to examples.

-
Release Notes: For a complete list of recent API changes, refer to the latest Release Notes.

-
C++ SDK: For the native C++ SDK reference, see the C++ SDK documentation.

If you need further assistance, you can contact us or submit a request to our support team.
