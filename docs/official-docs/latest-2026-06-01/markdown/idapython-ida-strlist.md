# IDAPython string list API

- 官方来源：https://python.docs.hex-rays.com/ida_strlist/index.html

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
- ida_strlist
- View page source

# ida_strlist

Functions that deal with the string list.

While the kernel keeps the string list, it does not update it. The string list is not used by the kernel because keeping it up-to-date would slow down IDA without any benefit. If the string list is not cleared using clear_strlist(), the list will be saved to the database and restored on the next startup. The users of this list should call build_strlist() if they need an up-to-date version.

## Classes

`strwinsetup_t`
 |

`string_info_t`
 |

## Functions

`get_strlist_options`(→ strwinsetup_t const *)
 |
Get the static string list options.

`build_strlist`(→ None)
 |
Rebuild the string list.

`clear_strlist`(→ None)
 |
Clear the string list.

`get_strlist_qty`(→ int)
 |
Get number of elements in the string list. The list will be loaded from the database (if saved) or built from scratch.

`get_strlist_item`(→ bool)
 |
Get nth element of the string list (n=0..get_strlist_qty()-1)

## Module Contents

classida_strlist.strwinsetup_t
Bases: `object`
thisownminlen:intdisplay_only_existing_strings:ucharonly_7bit:ucharignore_heads:ucharstrtypesclassida_strlist.string_info_t(*args)
Bases: `object`
thisownea:ida_idaapi.ea_tlength:inttype:intida_strlist.get_strlist_options()→strwinsetup_tconst*
Get the static string list options.
ida_strlist.build_strlist()→None
Rebuild the string list.
ida_strlist.clear_strlist()→None
Clear the string list.
ida_strlist.get_strlist_qty()→int
Get number of elements in the string list. The list will be loaded from the database (if saved) or built from scratch.
ida_strlist.get_strlist_item(si:string_info_t, n:int)→bool
Get nth element of the string list (n=0..get_strlist_qty()-1)
