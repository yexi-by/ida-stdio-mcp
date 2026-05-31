# IDAPython entry points API

- 官方来源：https://python.docs.hex-rays.com/ida_entry/index.html

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
- ida_entry
- View page source

# ida_entry

Functions that deal with entry points.

Exported functions are considered as entry points as well. IDA maintains list of entry points to the program. Each entry point: * has an address * has a name * may have an ordinal number

## Attributes

`AEF_UTF8`
 |
the name is given in UTF-8 (default)

`AEF_IDBENC`
 |
the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly. Specifying AEF_IDBENC also implies AEF_NODUMMY

`AEF_NODUMMY`
 |
automatically prepend the name with '_' if it begins with a dummy suffix. See also AEF_IDBENC

`AEF_WEAK`
 |
make name weak

`AEF_NOFORCE`
 |
if the specified address already has a name, the new name will be appended to the regular comment, except for the case when the old name is weak and the new one is not.

## Functions

`get_entry_qty`(→ int)
 |
Get number of entry points.

`add_entry`(→ bool)
 |
Add an entry point to the list of entry points.

`get_entry_ordinal`(→ int)
 |
Get ordinal number of an entry point.

`get_entry`(→ ida_idaapi.ea_t)
 |
Get entry point address by its ordinal

`get_entry_name`(→ str)
 |
Get name of the entry point by its ordinal.

`rename_entry`(→ bool)
 |
Rename entry point.

`set_entry_forwarder`(→ bool)
 |
Set forwarder name for ordinal.

`get_entry_forwarder`(→ str)
 |
Get forwarder name for the entry point by its ordinal.

## Module Contents

ida_entry.get_entry_qty()→int
Get number of entry points.
ida_entry.AEF_UTF8
the name is given in UTF-8 (default)
ida_entry.AEF_IDBENC
the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly. Specifying AEF_IDBENC also implies AEF_NODUMMY
ida_entry.AEF_NODUMMY
automatically prepend the name with ‘_’ if it begins with a dummy suffix. See also AEF_IDBENC
ida_entry.AEF_WEAK
make name weak
ida_entry.AEF_NOFORCE
if the specified address already has a name, the new name will be appended to the regular comment, except for the case when the old name is weak and the new one is not.
ida_entry.add_entry(ord:int, ea:ida_idaapi.ea_t, name:str, makecode:bool, flags:int=0)→bool
Add an entry point to the list of entry points.
Parameters:

-
ord – ordinal number if ordinal number is equal to ‘ea’ then ordinal is not used

-
ea – linear address

-
name – name of entry point. If the specified location already has a name, the old name will be appended to the regular comment.

-
makecode – should the kernel convert bytes at the entry point to instruction(s)

-
flags – See AEF_*

Returns:
success (currently always true)
ida_entry.get_entry_ordinal(idx:int)→int
Get ordinal number of an entry point.
Parameters:
idx – internal number of entry point. Should be in the range 0..get_entry_qty()-1
Returns:
ordinal number or 0.
ida_entry.get_entry(ord:int)→ida_idaapi.ea_t
Get entry point address by its ordinal
Parameters:
ord – ordinal number of entry point
Returns:
address or BADADDR
ida_entry.get_entry_name(ord:int)→str
Get name of the entry point by its ordinal.
Parameters:
ord – ordinal number of entry point
Returns:
size of entry name or -1
ida_entry.rename_entry(ord:int, name:str, flags:int=0)→bool
Rename entry point.
Parameters:

-
ord – ordinal number of the entry point

-
name – name of entry point. If the specified location already has a name, the old name will be appended to a non-repeatable comment.

-
flags – See AEF_*

Returns:
success
ida_entry.set_entry_forwarder(ord:int, name:str, flags:int=0)→bool
Set forwarder name for ordinal.
Parameters:

-
ord – ordinal number of the entry point

-
name – forwarder name for entry point.

-
flags – See AEF_*

Returns:
success
ida_entry.get_entry_forwarder(ord:int)→str
Get forwarder name for the entry point by its ordinal.
Parameters:
ord – ordinal number of entry point
Returns:
size of entry forwarder name or -1
