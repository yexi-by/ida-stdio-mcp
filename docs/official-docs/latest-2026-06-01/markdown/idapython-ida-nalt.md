# IDAPython netnode/alt metadata API

- 官方来源：https://python.docs.hex-rays.com/ida_nalt/index.html

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
- ida_nalt
- View page source

# ida_nalt

Definitions of various information kept in netnodes.

Each address in the program has a corresponding netnode: netnode(ea). If no information exists for an address, its corresponding netnode is not created. Otherwise we will create a netnode and save information in it. All variable length information (names, comments, offset information, etc) is stored in the netnode. Don’t forget that some information is already stored in the flags (bytes.hpp) netnode.

## Attributes

`NALT_SWITCH`
|
switch idiom address (used at jump targets)

`NALT_STRUCT`
|
struct id

`NALT_AFLAGS`
|
additional flags for an item

`NALT_LINNUM`
|
source line number

`NALT_ABSBASE`
|
absolute segment location

`NALT_ENUM0`
|
enum id for the first operand

`NALT_ENUM1`
|
enum id for the second operand

`NALT_PURGE`
|
number of bytes purged from the stack when a function is called indirectly

`NALT_STRTYPE`
|
type of a string item

`NALT_ALIGN`
|
alignment value if the item is FF_ALIGN (should be equal to a power of 2)

`NALT_COLOR`
|
instruction/data background color

`NSUP_CMT`
|
regular comment

`NSUP_REPCMT`
|
repeatable comment

`NSUP_FOP1`
|
forced operand 1

`NSUP_FOP2`
|
forced operand 2

`NSUP_JINFO`
|
jump table info

`NSUP_ARRAY`
|
array parameters

`NSUP_OMFGRP`
|
OMF: group of segments (not used anymore)

`NSUP_FOP3`
|
forced operand 3

`NSUP_SWITCH`
|
switch information

`NSUP_REF0`
|
complex reference information for operand 1

`NSUP_REF1`
|
complex reference information for operand 2

`NSUP_REF2`
|
complex reference information for operand 3

`NSUP_OREF0`
|
outer complex reference information for operand 1

`NSUP_OREF1`
|
outer complex reference information for operand 2

`NSUP_OREF2`
|
outer complex reference information for operand 3

`NSUP_STROFF0`
|
stroff: struct path for the first operand

`NSUP_STROFF1`
|
stroff: struct path for the second operand

`NSUP_SEGTRANS`
|
segment translations

`NSUP_FOP4`
|
forced operand 4

`NSUP_FOP5`
|
forced operand 5

`NSUP_FOP6`
|
forced operand 6

`NSUP_REF3`
|
complex reference information for operand 4

`NSUP_REF4`
|
complex reference information for operand 5

`NSUP_REF5`
|
complex reference information for operand 6

`NSUP_OREF3`
|
outer complex reference information for operand 4

`NSUP_OREF4`
|
outer complex reference information for operand 5

`NSUP_OREF5`
|
outer complex reference information for operand 6

`NSUP_XREFPOS`
|
saved xref address and type in the xrefs window

`NSUP_CUSTDT`
|
custom data type id

`NSUP_GROUPS`
|
SEG_GRP: pack_dd encoded list of selectors.

`NSUP_ARGEAS`
|
instructions that initialize call arguments

`NSUP_FOP7`
|
forced operand 7

`NSUP_FOP8`
|
forced operand 8

`NSUP_REF6`
|
complex reference information for operand 7

`NSUP_REF7`
|
complex reference information for operand 8

`NSUP_OREF6`
|
outer complex reference information for operand 7

`NSUP_OREF7`
|
outer complex reference information for operand 8

`NSUP_EX_FLAGS`
|
Extended flags.

`NSUP_POINTS`
|
SP change points blob (see funcs.cpp). values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved

`NSUP_MANUAL`
|
manual instruction. values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved

`NSUP_TYPEINFO`
|
type information. values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved

`NSUP_REGVAR`
|
register variables. values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved

`NSUP_LLABEL`
|
local labels. values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved

`NSUP_REGARG`
|
register argument type/name descriptions values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved

`NSUP_FTAILS`
|
function tails or tail referers values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved

`NSUP_GROUP`
|
graph group information values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved

`NSUP_OPTYPES`
|
operand type information. values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved

`NSUP_ORIGFMD`
|
function metadata before lumina information was applied values NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved

`NSUP_FRAME`
|
function frame type values NSUP_FRAME..NSUP_FRAME+0x10000 are reserved

`NALT_CREF_TO`
|
code xref to, idx: target address

`NALT_CREF_FROM`
|
code xref from, idx: source address

`NALT_DREF_TO`
|
data xref to, idx: target address

`NALT_DREF_FROM`
|
data xref from, idx: source address

`NSUP_GR_INFO`
|
group node info: color, ea, text

`NALT_GR_LAYX`
|
group layout ptrs, hash: md5 of 'belongs'

`NSUP_GR_LAYT`
|
group layouts, idx: layout pointer

`PATCH_TAG`
|
Patch netnode tag.

`IDB_DESKTOPS_NODE_NAME`
|
hash indexed by desktop name with desktop netnode

`IDB_DESKTOPS_TAG`
|
tag to store desktop blob & timestamp

`AFL_LINNUM`
|
has line number info

`AFL_USERSP`
|
user-defined SP value

`AFL_PUBNAM`
|
name is public (inter-file linkage)

`AFL_WEAKNAM`
|
name is weak

`AFL_HIDDEN`
|
the item is hidden completely

`AFL_MANUAL`
|
the instruction/data is specified by the user

`AFL_NOBRD`
|
the code/data border is hidden

`AFL_ZSTROFF`
|
display struct field name at offset 0 when displaying an offset. example: `offset somestruct.field_0 ` if this flag is clear, then `offset somestruct `

`AFL_BNOT0`
|
the 1st operand is bitwise negated

`AFL_BNOT1`
|
the 2nd operand is bitwise negated

`AFL_LIB`
|
item from the standard library. low level flag, is used to set FUNC_LIB of func_t

`AFL_TI`
|
has typeinfo? (NSUP_TYPEINFO); used only for addresses, not for member_t

`AFL_TI0`
|
has typeinfo for operand 0? (NSUP_OPTYPES)

`AFL_TI1`
|
has typeinfo for operand 1? (NSUP_OPTYPES+1)

`AFL_LNAME`
|
has local name too (FF_NAME should be set)

`AFL_TILCMT`
|
has type comment? (such a comment may be changed by IDA)

`AFL_LZERO0`
|
toggle leading zeros for the 1st operand

`AFL_LZERO1`
|
toggle leading zeros for the 2nd operand

`AFL_COLORED`
|
has user-defined instruction color?

`AFL_TERSESTR`
|
terse structure variable display?

`AFL_SIGN0`
|
code: toggle sign of the 1st operand

`AFL_SIGN1`
|
code: toggle sign of the 2nd operand

`AFL_NORET`
|
for imported function pointers: doesn't return. this flag can also be used for any instruction which halts or finishes the program execution

`AFL_FIXEDSPD`
|
sp delta value is fixed by analysis. should not be modified by modules

`AFL_ALIGNFLOW`
|
the previous insn was created for alignment purposes only

`AFL_USERTI`
|
the type information is definitive. (comes from the user or type library) if not set see AFL_TYPE_GUESSED

`AFL_RETFP`
|
function returns a floating point value

`AFL_USEMODSP`
|
insn modifies SP and uses the modified value; example: pop [rsp+N]

`AFL_NOTCODE`
|
autoanalysis should not create code here

`AFL_NOTPROC`
|
autoanalysis should not create proc here

`AFL_TYPE_GUESSED`
|
who guessed the type information?

`AFL_IDA_GUESSED`
|
the type is guessed by IDA

`AFL_HR_GUESSED_FUNC`
|
the function type is guessed by the decompiler

`AFL_HR_GUESSED_DATA`
|
the data type is guessed by the decompiler

`AFL_HR_DETERMINED`
|
the type is definitely guessed by the decompiler

`STRWIDTH_1B`
|

`STRWIDTH_2B`
|

`STRWIDTH_4B`
|

`STRWIDTH_MASK`
|

`STRLYT_TERMCHR`
|

`STRLYT_PASCAL1`
|

`STRLYT_PASCAL2`
|

`STRLYT_PASCAL4`
|

`STRLYT_MASK`
|

`STRLYT_SHIFT`
|

`STRTYPE_TERMCHR`
|
C-style string.

`STRTYPE_C`
|
Zero-terminated 16-bit chars.

`STRTYPE_C_16`
|
Zero-terminated 32-bit chars.

`STRTYPE_C_32`
|
Pascal-style, one-byte length prefix.

`STRTYPE_PASCAL`
|
Pascal-style, 16-bit chars, one-byte length prefix.

`STRTYPE_PASCAL_16`
|
Pascal-style, 32-bit chars, one-byte length prefix.

`STRTYPE_PASCAL_32`
|
Pascal-style, two-byte length prefix.

`STRTYPE_LEN2`
|
Pascal-style, 16-bit chars, two-byte length prefix.

`STRTYPE_LEN2_16`
|
Pascal-style, 32-bit chars, two-byte length prefix.

`STRTYPE_LEN2_32`
|
Pascal-style, four-byte length prefix.

`STRTYPE_LEN4`
|
Pascal-style, 16-bit chars, four-byte length prefix.

`STRTYPE_LEN4_16`
|
Pascal-style, 32-bit chars, four-byte length prefix.

`STRTYPE_LEN4_32`
|

`STRENC_DEFAULT`
|
use default encoding for this type (see get_default_encoding_idx())

`STRENC_NONE`
|
force no-conversion encoding

`AP_ALLOWDUPS`
|
use 'dup' construct

`AP_SIGNED`
|
treat numbers as signed

`AP_INDEX`
|
display array element indexes as comments

`AP_ARRAY`
|
create as array (this flag is not stored in database)

`AP_IDXBASEMASK`
|
mask for number base of the indexes

`AP_IDXDEC`
|
display indexes in decimal

`AP_IDXHEX`
|
display indexes in hex

`AP_IDXOCT`
|
display indexes in octal

`AP_IDXBIN`
|
display indexes in binary

`SWI_SPARSE`
|
sparse switch (value table present), otherwise lowcase present

`SWI_V32`
|
32-bit values in table

`SWI_J32`
|
32-bit jump offsets

`SWI_VSPLIT`
|
value table is split (only for 32-bit values)

`SWI_USER`
|
user specified switch (starting from version 2)

`SWI_DEF_IN_TBL`
|
default case is an entry in the jump table. This flag is applicable in 2 cases:

`SWI_JMP_INV`
|
jumptable is inversed. (last entry is for first entry in values table)

`SWI_SHIFT_MASK`
|
use formula (element<<shift) + elbase to find jump targets

`SWI_ELBASE`
|
elbase is present (otherwise the base of the switch segment will be used)

`SWI_JSIZE`
|
jump offset expansion bit

`SWI_VSIZE`
|
value table element size expansion bit

`SWI_SEPARATE`
|
create an array of individual elements (otherwise separate items)

`SWI_SIGNED`
|
jump table entries are signed

`SWI_CUSTOM`
|
custom jump table. processor_t::create_switch_xrefs will be called to create code xrefs for the table. Custom jump table must be created by the module (see also SWI_STDTBL)

`SWI_INDIRECT`
|
value table elements are used as indexes into the jump table (for sparse switches)

`SWI_SUBTRACT`
|
table values are subtracted from the elbase instead of being added

`SWI_HXNOLOWCASE`
|
lowcase value should not be used by the decompiler (internal flag)

`SWI_STDTBL`
|
custom jump table with standard table formatting. ATM IDA doesn't use SWI_CUSTOM for switches with standard table formatting. So this flag can be considered as obsolete.

`SWI_DEFRET`
|
return in the default case (defjump==BADADDR)

`SWI_SELFREL`
|
jump address is relative to the element not to ELBASE

`SWI_JMPINSN`
|
jump table entries are insns. For such entries SHIFT has a different meaning. It denotes the number of insns in the entry. For example, 0 - the entry contains the jump to the case, 1 - the entry contains one insn like a 'mov' and jump to the end of case, and so on.

`SWI_VERSION`
|
the structure contains the VERSION member

`cvar`
|

`V695_REF_OFF8`
|
reserved

`REF_OFF16`
|
16-bit full offset

`REF_OFF32`
|
32-bit full offset

`REF_LOW8`
|
low 8 bits of 16-bit offset

`REF_LOW16`
|
low 16 bits of 32-bit offset

`REF_HIGH8`
|
high 8 bits of 16-bit offset

`REF_HIGH16`
|
high 16 bits of 32-bit offset

`V695_REF_VHIGH`
|
obsolete

`V695_REF_VLOW`
|
obsolete

`REF_OFF64`
|
64-bit full offset

`REF_OFF8`
|
8-bit full offset

`REF_LOW32`
|
low 32 bits of 64-bit offset

`REF_HIGH32`
|
high 32 bits of 64-bit offset

`REF_LAST`
|

`REFINFO_TYPE`
|
reference type (reftype_t), or custom reference ID if REFINFO_CUSTOM set

`REFINFO_RVAOFF`
|
based reference (rva); refinfo_t::base will be forced to get_imagebase(); such a reference is displayed with the asm_t::a_rva keyword

`REFINFO_PASTEND`
|
reference past an item; it may point to a nonexistent address; do not destroy alignment dirs

`REFINFO_CUSTOM`
|
a custom reference. see custom_refinfo_handler_t. the id of the custom refinfo is stored under the REFINFO_TYPE mask.

`REFINFO_NOBASE`
|
don't create the base xref; implies that the base can be any value. nb: base xrefs are created only if the offset base points to the middle of a segment

`REFINFO_SUBTRACT`
|
the reference value is subtracted from the base value instead of (as usual) being added to it

`REFINFO_SIGNEDOP`
|
the operand value is sign-extended (only supported for REF_OFF8/16/32/64)

`REFINFO_NO_ZEROS`
|
an opval of 0 will be considered invalid

`REFINFO_NO_ONES`
|
an opval of ~0 will be considered invalid

`REFINFO_SELFREF`
|
the self-based reference; refinfo_t::base will be forced to the reference address

`REFINFO_USER`
|
ignore fixup when processing this refinfo

`MAXSTRUCPATH`
|
maximum inclusion depth for nested unions

`POF_VALID_TI`
|

`POF_VALID_AFLAGS`
|

`POF_IS_F64`
|

`RIDX_FILE_FORMAT_NAME`
|
file format name for loader modules

`RIDX_SELECTORS`
|
2..63 are for selector_t blob (see init_selectors())

`RIDX_GROUPS`
|
segment group information (see init_groups())

`RIDX_H_PATH`
|
C header path.

`RIDX_C_MACROS`
|
C predefined macros.

`RIDX_SMALL_IDC_OLD`
|
Instant IDC statements (obsolete)

`RIDX_NOTEPAD`
|
notepad blob, occupies 1000 indexes (1MB of text)

`RIDX_INCLUDE`
|
assembler include file name

`RIDX_SMALL_IDC`
|
Instant IDC statements, blob.

`RIDX_DUALOP_GRAPH`
|
Graph text representation options.

`RIDX_DUALOP_TEXT`
|
Text representation options.

`RIDX_MD5`
|
MD5 of the input file.

`RIDX_IDA_VERSION`
|
version of ida which created the database

`RIDX_STR_ENCODINGS`
|
a list of encodings for the program strings

`RIDX_SRCDBG_PATHS`
|
source debug paths, occupies 20 indexes

`RIDX_DBG_BINPATHS`
|
unused (20 indexes)

`RIDX_SHA256`
|
SHA256 of the input file.

`RIDX_ABINAME`
|
ABI name (processor specific)

`RIDX_ARCHIVE_PATH`
|
archive file path

`RIDX_PROBLEMS`
|
problem lists

`RIDX_SRCDBG_UNDESIRED`
|
user-closed source files, occupies 20 indexes

`BPU_1B`
|

`BPU_2B`
|

`BPU_4B`
|

`GOTEA_NODE_NAME`
|
node containing address of .got section

`GOTEA_NODE_IDX`
|

`get_initial_version`
|

## Classes

`custom_data_type_ids_fids_array`
|

`strpath_ids_array`
|

`array_parameters_t`
|

`switch_info_t`
|

`custom_data_type_ids_t`
|

`refinfo_t`
|

`strpath_t`
|

`enum_const_t`
|

`opinfo_t`
|

`printop_t`
|

`import_entry_t`
|

## Functions

`ea2node`(→ nodeidx_t)
|
Get netnode for the specified address.

`node2ea`(→ ida_idaapi.ea_t)
|

`end_ea2node`(→ nodeidx_t)
|

`getnode`(→ netnode)
|

`get_strid`(→ tid_t)
|

`set_aflags`(→ None)
|

`upd_abits`(→ None)
|

`set_abits`(→ None)
|

`clr_abits`(→ None)
|

`get_aflags`(→ aflags_t)
|

`del_aflags`(→ None)
|

`has_aflag_linnum`(→ bool)
|

`is_aflag_usersp`(→ bool)
|

`is_aflag_public_name`(→ bool)
|

`is_aflag_weak_name`(→ bool)
|

`is_aflag_hidden_item`(→ bool)
|

`is_aflag_manual_insn`(→ bool)
|

`is_aflag_hidden_border`(→ bool)
|

`is_aflag_zstroff`(→ bool)
|

`is_aflag__bnot0`(→ bool)
|

`is_aflag__bnot1`(→ bool)
|

`is_aflag_libitem`(→ bool)
|

`has_aflag_ti`(→ bool)
|

`has_aflag_ti0`(→ bool)
|

`has_aflag_ti1`(→ bool)
|

`has_aflag_lname`(→ bool)
|

`is_aflag_tilcmt`(→ bool)
|

`is_aflag_lzero0`(→ bool)
|

`is_aflag_lzero1`(→ bool)
|

`is_aflag_colored_item`(→ bool)
|

`is_aflag_terse_struc`(→ bool)
|

`is_aflag__invsign0`(→ bool)
|

`is_aflag__invsign1`(→ bool)
|

`is_aflag_noret`(→ bool)
|

`is_aflag_fixed_spd`(→ bool)
|

`is_aflag_align_flow`(→ bool)
|

`is_aflag_userti`(→ bool)
|

`is_aflag_retfp`(→ bool)
|

`uses_aflag_modsp`(→ bool)
|

`is_aflag_notcode`(→ bool)
|

`is_aflag_notproc`(→ bool)
|

`is_aflag_type_guessed_by_ida`(→ bool)
|

`is_aflag_func_guessed_by_hexrays`(→ bool)
|

`is_aflag_data_guessed_by_hexrays`(→ bool)
|

`is_aflag_type_determined_by_hexrays`(→ bool)
|

`is_aflag_type_guessed_by_hexrays`(→ bool)
|

`is_hidden_item`(→ bool)
|

`hide_item`(→ None)
|

`unhide_item`(→ None)
|

`is_hidden_border`(→ bool)
|

`hide_border`(→ None)
|

`unhide_border`(→ None)
|

`uses_modsp`(→ bool)
|

`set_usemodsp`(→ None)
|

`clr_usemodsp`(→ None)
|

`is_zstroff`(→ bool)
|

`set_zstroff`(→ None)
|

`clr_zstroff`(→ None)
|

`is__bnot0`(→ bool)
|

`set__bnot0`(→ None)
|

`clr__bnot0`(→ None)
|

`is__bnot1`(→ bool)
|

`set__bnot1`(→ None)
|

`clr__bnot1`(→ None)
|

`is_libitem`(→ bool)
|

`set_libitem`(→ None)
|

`clr_libitem`(→ None)
|

`has_ti`(→ bool)
|

`set_has_ti`(→ None)
|

`clr_has_ti`(→ None)
|

`has_ti0`(→ bool)
|

`set_has_ti0`(→ None)
|

`clr_has_ti0`(→ None)
|

`has_ti1`(→ bool)
|

`set_has_ti1`(→ None)
|

`clr_has_ti1`(→ None)
|

`has_lname`(→ bool)
|

`set_has_lname`(→ None)
|

`clr_has_lname`(→ None)
|

`is_tilcmt`(→ bool)
|

`set_tilcmt`(→ None)
|

`clr_tilcmt`(→ None)
|

`is_usersp`(→ bool)
|

`set_usersp`(→ None)
|

`clr_usersp`(→ None)
|

`is_lzero0`(→ bool)
|

`set_lzero0`(→ None)
|

`clr_lzero0`(→ None)
|

`is_lzero1`(→ bool)
|

`set_lzero1`(→ None)
|

`clr_lzero1`(→ None)
|

`is_colored_item`(→ bool)
|

`set_colored_item`(→ None)
|

`clr_colored_item`(→ None)
|

`is_terse_struc`(→ bool)
|

`set_terse_struc`(→ None)
|

`clr_terse_struc`(→ None)
|

`is__invsign0`(→ bool)
|

`set__invsign0`(→ None)
|

`clr__invsign0`(→ None)
|

`is__invsign1`(→ bool)
|

`set__invsign1`(→ None)
|

`clr__invsign1`(→ None)
|

`is_noret`(→ bool)
|

`set_noret`(→ None)
|

`clr_noret`(→ None)
|

`is_fixed_spd`(→ bool)
|

`set_fixed_spd`(→ None)
|

`clr_fixed_spd`(→ None)
|

`is_align_flow`(→ bool)
|

`set_align_flow`(→ None)
|

`clr_align_flow`(→ None)
|

`is_userti`(→ bool)
|

`set_userti`(→ None)
|

`clr_userti`(→ None)
|

`is_retfp`(→ bool)
|

`set_retfp`(→ None)
|

`clr_retfp`(→ None)
|

`is_notproc`(→ bool)
|

`set_notproc`(→ None)
|

`clr_notproc`(→ None)
|

`is_type_guessed_by_ida`(→ bool)
|

`is_func_guessed_by_hexrays`(→ bool)
|

`is_data_guessed_by_hexrays`(→ bool)
|

`is_type_determined_by_hexrays`(→ bool)
|

`is_type_guessed_by_hexrays`(→ bool)
|

`set_type_guessed_by_ida`(→ None)
|

`set_func_guessed_by_hexrays`(→ None)
|

`set_data_guessed_by_hexrays`(→ None)
|

`set_type_determined_by_hexrays`(→ None)
|

`set_notcode`(→ None)
|
Mark address so that it cannot be converted to instruction.

`clr_notcode`(→ None)
|
Clear not-code mark.

`is_notcode`(→ bool)
|
Is the address marked as not-code?

`set_visible_item`(→ None)
|
Change visibility of item at given ea.

`is_visible_item`(→ bool)
|
Test visibility of item at given ea.

`is_finally_visible_item`(→ bool)
|
Is instruction visible?

`set_source_linnum`(→ None)
|

`get_source_linnum`(→ int)
|

`del_source_linnum`(→ None)
|

`get_absbase`(→ ida_idaapi.ea_t)
|

`set_absbase`(→ None)
|

`del_absbase`(→ None)
|

`get_ind_purged`(→ ida_idaapi.ea_t)
|

`del_ind_purged`(→ None)
|

`get_str_type`(→ int)
|

`set_str_type`(→ None)
|

`del_str_type`(→ None)
|

`get_str_type_code`(→ uchar)
|

`get_str_term1`(→ char)
|

`get_str_term2`(→ char)
|

`get_str_encoding_idx`(→ uchar)
|

`set_str_encoding_idx`(→ int)
|

`make_str_type`(→ int)
|

`is_pascal`(→ bool)
|

`get_str_type_prefix_length`(→ int)
|

`get_alignment`(→ int)
|

`set_alignment`(→ None)
|

`del_alignment`(→ None)
|

`set_item_color`(→ None)
|

`get_item_color`(→ bgcolor_t)
|

`del_item_color`(→ bool)
|

`get_array_parameters`(→ ssize_t)
|

`set_array_parameters`(→ None)
|

`del_array_parameters`(→ None)
|

`get_switch_info`(*args)
|

`set_switch_info`(→ None)
|

`del_switch_info`(→ None)
|

`get_switch_parent`(→ ida_idaapi.ea_t)
|

`set_switch_parent`(→ None)
|

`del_switch_parent`(→ None)
|

`get_custom_data_type_ids`(→ int)
|

`set_custom_data_type_ids`(→ None)
|

`del_custom_data_type_ids`(→ None)
|

`is_reftype_target_optional`(→ bool)
|
Can the target be calculated using operand value?

`get_reftype_by_size`(→ reftype_t)
|
Get REF_... constant from size Supported sizes: 1,2,4,8,16 For other sizes returns reftype_t(-1)

`find_custom_refinfo`(→ int)
|
Get id of a custom refinfo type.

`get_custom_refinfo`(→ custom_refinfo_handler_t const *)
|
Get definition of a registered custom refinfo type.

`set_refinfo_ex`(→ bool)
|

`set_refinfo`(→ bool)
|

`get_refinfo`(→ bool)
|

`del_refinfo`(→ bool)
|

`get_tinfo`(→ bool)
|

`set_tinfo`(→ bool)
|

`del_tinfo`(→ None)
|

`get_op_tinfo`(→ bool)
|

`set_op_tinfo`(→ bool)
|

`del_op_tinfo`(→ None)
|

`get_root_filename`(→ str)
|
Get file name only of the input file.

`dbg_get_input_path`(→ str)
|
Get debugger input file name/path (see LFLG_DBG_NOPATH)

`get_input_file_path`(→ str)
|
Get full path of the input file.

`set_root_filename`(→ None)
|
Set full path of the input file.

`retrieve_input_file_size`(→ int)
|
Get size of input file in bytes.

`retrieve_input_file_crc32`(→ int)
|
Get input file crc32 stored in the database. it can be used to check that the input file has not been changed.

`retrieve_input_file_md5`(→ bytes)
|
Get input file md5.

`retrieve_input_file_sha256`(→ bytes)
|
Get input file sha256.

`get_asm_inc_file`(→ str)
|
Get name of the include file.

`set_asm_inc_file`(→ bool)
|
Set name of the include file.

`get_imagebase`(→ ida_idaapi.ea_t)
|
Get image base address.

`set_imagebase`(→ None)
|
Set image base address.

`get_ids_modnode`(→ netnode)
|
Get ids modnode.

`set_ids_modnode`(→ None)
|
Set ids modnode.

`get_archive_path`(→ str)
|
Get archive file path from which input file was extracted.

`set_archive_path`(→ bool)
|
Set archive file path from which input file was extracted.

`get_loader_format_name`(→ str)
|
Get file format name for loader modules.

`set_loader_format_name`(→ None)
|
Set file format name for loader modules.

`get_initial_ida_version`(→ str)
|
Get version of ida which created the database (string format like "7.5")

`get_ida_notepad_text`(→ str)
|
Get notepad text.

`set_ida_notepad_text`(→ None)
|
Set notepad text.

`get_srcdbg_paths`(→ str)
|
Get source debug paths.

`set_srcdbg_paths`(→ None)
|
Set source debug paths.

`get_srcdbg_undesired_paths`(→ str)
|
Get user-closed source files.

`set_srcdbg_undesired_paths`(→ None)
|
Set user-closed source files.

`get_initial_idb_version`(→ ushort)
|
Get initial version of the database (numeric format like 700)

`get_idb_ctime`(→ time_t)
|
Get database creation timestamp.

`get_elapsed_secs`(→ int)
|
Get seconds database stayed open.

`get_idb_nopens`(→ int)
|
Get number of times the database is opened.

`get_encoding_qty`(→ int)
|

`get_encoding_name`(→ str)
|

`add_encoding`(→ int)
|

`del_encoding`(→ bool)
|

`rename_encoding`(→ bool)
|

`get_encoding_bpu`(→ int)
|

`get_encoding_bpu_by_name`(→ int)
|

`get_strtype_bpu`(→ int)
|

`get_default_encoding_idx`(→ int)
|

`set_default_encoding_idx`(→ bool)
|

`encoding_from_strtype`(→ str)
|

`get_outfile_encoding_idx`(→ int)
|

`set_outfile_encoding_idx`(→ bool)
|

`get_import_module_qty`(→ uint)
|

`delete_imports`(→ None)
|

`get_import_entry`(→ bool)
|

`set_gotea`(→ None)
|

`get_gotea`(→ ida_idaapi.ea_t)
|

`get_import_module_name`(mod_index)
|
Returns the name of an imported module given its index

`enum_import_names`(mod_index, callback)
|
Enumerate imports from a specific module.

`switch_info_t__from_ptrval__`(→ switch_info_t *)
|

`get_switch_info`(*args)
|

`get_abi_name`()
|

## Module Contents

classida_nalt.custom_data_type_ids_fids_array(data:short(&)[8])
Bases: `object`
thisowndata:short(&)[8]bytesclassida_nalt.strpath_ids_array(data:unsignedlonglong(&)[32])
Bases: `object`
thisowndata:unsignedlonglong(&)[32]bytesida_nalt.NALT_SWITCH
switch idiom address (used at jump targets)
ida_nalt.NALT_STRUCT
struct id
ida_nalt.NALT_AFLAGS
additional flags for an item
ida_nalt.NALT_LINNUM
source line number
ida_nalt.NALT_ABSBASE
absolute segment location
ida_nalt.NALT_ENUM0
enum id for the first operand
ida_nalt.NALT_ENUM1
enum id for the second operand
ida_nalt.NALT_PURGE
number of bytes purged from the stack when a function is called indirectly
ida_nalt.NALT_STRTYPE
type of a string item
ida_nalt.NALT_ALIGN
alignment value if the item is FF_ALIGN (should be equal to a power of 2)
ida_nalt.NALT_COLOR
instruction/data background color
ida_nalt.NSUP_CMT
regular comment
ida_nalt.NSUP_REPCMT
repeatable comment
ida_nalt.NSUP_FOP1
forced operand 1
ida_nalt.NSUP_FOP2
forced operand 2
ida_nalt.NSUP_JINFO
jump table info
ida_nalt.NSUP_ARRAY
array parameters
ida_nalt.NSUP_OMFGRP
OMF: group of segments (not used anymore)
ida_nalt.NSUP_FOP3
forced operand 3
ida_nalt.NSUP_SWITCH
switch information
ida_nalt.NSUP_REF0
complex reference information for operand 1
ida_nalt.NSUP_REF1
complex reference information for operand 2
ida_nalt.NSUP_REF2
complex reference information for operand 3
ida_nalt.NSUP_OREF0
outer complex reference information for operand 1
ida_nalt.NSUP_OREF1
outer complex reference information for operand 2
ida_nalt.NSUP_OREF2
outer complex reference information for operand 3
ida_nalt.NSUP_STROFF0
stroff: struct path for the first operand
ida_nalt.NSUP_STROFF1
stroff: struct path for the second operand
ida_nalt.NSUP_SEGTRANS
segment translations
ida_nalt.NSUP_FOP4
forced operand 4
ida_nalt.NSUP_FOP5
forced operand 5
ida_nalt.NSUP_FOP6
forced operand 6
ida_nalt.NSUP_REF3
complex reference information for operand 4
ida_nalt.NSUP_REF4
complex reference information for operand 5
ida_nalt.NSUP_REF5
complex reference information for operand 6
ida_nalt.NSUP_OREF3
outer complex reference information for operand 4
ida_nalt.NSUP_OREF4
outer complex reference information for operand 5
ida_nalt.NSUP_OREF5
outer complex reference information for operand 6
ida_nalt.NSUP_XREFPOS
saved xref address and type in the xrefs window
ida_nalt.NSUP_CUSTDT
custom data type id
ida_nalt.NSUP_GROUPS
SEG_GRP: pack_dd encoded list of selectors.
ida_nalt.NSUP_ARGEAS
instructions that initialize call arguments
ida_nalt.NSUP_FOP7
forced operand 7
ida_nalt.NSUP_FOP8
forced operand 8
ida_nalt.NSUP_REF6
complex reference information for operand 7
ida_nalt.NSUP_REF7
complex reference information for operand 8
ida_nalt.NSUP_OREF6
outer complex reference information for operand 7
ida_nalt.NSUP_OREF7
outer complex reference information for operand 8
ida_nalt.NSUP_EX_FLAGS
Extended flags.
ida_nalt.NSUP_POINTS
SP change points blob (see funcs.cpp). values NSUP_POINTS..NSUP_POINTS+0x1000 are reserved
ida_nalt.NSUP_MANUAL
manual instruction. values NSUP_MANUAL..NSUP_MANUAL+0x1000 are reserved
ida_nalt.NSUP_TYPEINFO
type information. values NSUP_TYPEINFO..NSUP_TYPEINFO+0x1000 are reserved
ida_nalt.NSUP_REGVAR
register variables. values NSUP_REGVAR..NSUP_REGVAR+0x1000 are reserved
ida_nalt.NSUP_LLABEL
local labels. values NSUP_LLABEL..NSUP_LLABEL+0x1000 are reserved
ida_nalt.NSUP_REGARG
register argument type/name descriptions values NSUP_REGARG..NSUP_REGARG+0x1000 are reserved
ida_nalt.NSUP_FTAILS
function tails or tail referers values NSUP_FTAILS..NSUP_FTAILS+0x1000 are reserved
ida_nalt.NSUP_GROUP
graph group information values NSUP_GROUP..NSUP_GROUP+0x1000 are reserved
ida_nalt.NSUP_OPTYPES
operand type information. values NSUP_OPTYPES..NSUP_OPTYPES+0x100000 are reserved
ida_nalt.NSUP_ORIGFMD
function metadata before lumina information was applied values NSUP_ORIGFMD..NSUP_ORIGFMD+0x1000 are reserved
ida_nalt.NSUP_FRAME
function frame type values NSUP_FRAME..NSUP_FRAME+0x10000 are reserved
ida_nalt.NALT_CREF_TO
code xref to, idx: target address
ida_nalt.NALT_CREF_FROM
code xref from, idx: source address
ida_nalt.NALT_DREF_TO
data xref to, idx: target address
ida_nalt.NALT_DREF_FROM
data xref from, idx: source address
ida_nalt.NSUP_GR_INFO
group node info: color, ea, text
ida_nalt.NALT_GR_LAYX
group layout ptrs, hash: md5 of ‘belongs’
ida_nalt.NSUP_GR_LAYT
group layouts, idx: layout pointer
ida_nalt.PATCH_TAG
Patch netnode tag.
ida_nalt.IDB_DESKTOPS_NODE_NAME
hash indexed by desktop name with desktop netnode
ida_nalt.IDB_DESKTOPS_TAG
tag to store desktop blob & timestamp
ida_nalt.ea2node(ea:ida_idaapi.ea_t)→nodeidx_t
Get netnode for the specified address.
ida_nalt.node2ea(ndx:nodeidx_t)→ida_idaapi.ea_tida_nalt.end_ea2node(ea:ida_idaapi.ea_t)→nodeidx_tida_nalt.getnode(ea:ida_idaapi.ea_t)→netnodeida_nalt.get_strid(ea:ida_idaapi.ea_t)→tid_tida_nalt.AFL_LINNUM
has line number info
ida_nalt.AFL_USERSP
user-defined SP value
ida_nalt.AFL_PUBNAM
name is public (inter-file linkage)
ida_nalt.AFL_WEAKNAM
name is weak
ida_nalt.AFL_HIDDEN
the item is hidden completely
ida_nalt.AFL_MANUAL
the instruction/data is specified by the user
ida_nalt.AFL_NOBRD
the code/data border is hidden
ida_nalt.AFL_ZSTROFF
display struct field name at offset 0 when displaying an offset. example: `offset somestruct.field_0 ` if this flag is clear, then `offset somestruct `
ida_nalt.AFL_BNOT0
the 1st operand is bitwise negated
ida_nalt.AFL_BNOT1
the 2nd operand is bitwise negated
ida_nalt.AFL_LIB
item from the standard library. low level flag, is used to set FUNC_LIB of func_t
ida_nalt.AFL_TI
has typeinfo? (NSUP_TYPEINFO); used only for addresses, not for member_t
ida_nalt.AFL_TI0
has typeinfo for operand 0? (NSUP_OPTYPES)
ida_nalt.AFL_TI1
has typeinfo for operand 1? (NSUP_OPTYPES+1)
ida_nalt.AFL_LNAME
has local name too (FF_NAME should be set)
ida_nalt.AFL_TILCMT
has type comment? (such a comment may be changed by IDA)
ida_nalt.AFL_LZERO0
toggle leading zeros for the 1st operand
ida_nalt.AFL_LZERO1
toggle leading zeros for the 2nd operand
ida_nalt.AFL_COLORED
has user-defined instruction color?
ida_nalt.AFL_TERSESTR
terse structure variable display?
ida_nalt.AFL_SIGN0
code: toggle sign of the 1st operand
ida_nalt.AFL_SIGN1
code: toggle sign of the 2nd operand
ida_nalt.AFL_NORET
for imported function pointers: doesn’t return. this flag can also be used for any instruction which halts or finishes the program execution
ida_nalt.AFL_FIXEDSPD
sp delta value is fixed by analysis. should not be modified by modules
ida_nalt.AFL_ALIGNFLOW
the previous insn was created for alignment purposes only
ida_nalt.AFL_USERTI
the type information is definitive. (comes from the user or type library) if not set see AFL_TYPE_GUESSED
ida_nalt.AFL_RETFP
function returns a floating point value
ida_nalt.AFL_USEMODSP
insn modifies SP and uses the modified value; example: pop [rsp+N]
ida_nalt.AFL_NOTCODE
autoanalysis should not create code here
ida_nalt.AFL_NOTPROC
autoanalysis should not create proc here
ida_nalt.AFL_TYPE_GUESSED
who guessed the type information?
ida_nalt.AFL_IDA_GUESSED
the type is guessed by IDA
ida_nalt.AFL_HR_GUESSED_FUNC
the function type is guessed by the decompiler
ida_nalt.AFL_HR_GUESSED_DATA
the data type is guessed by the decompiler
ida_nalt.AFL_HR_DETERMINED
the type is definitely guessed by the decompiler
ida_nalt.set_aflags(ea:ida_idaapi.ea_t, flags:aflags_t)→Noneida_nalt.upd_abits(ea:ida_idaapi.ea_t, clr_bits:aflags_t, set_bits:aflags_t)→Noneida_nalt.set_abits(ea:ida_idaapi.ea_t, bits:aflags_t)→Noneida_nalt.clr_abits(ea:ida_idaapi.ea_t, bits:aflags_t)→Noneida_nalt.get_aflags(ea:ida_idaapi.ea_t)→aflags_tida_nalt.del_aflags(ea:ida_idaapi.ea_t)→Noneida_nalt.has_aflag_linnum(flags:aflags_t)→boolida_nalt.is_aflag_usersp(flags:aflags_t)→boolida_nalt.is_aflag_public_name(flags:aflags_t)→boolida_nalt.is_aflag_weak_name(flags:aflags_t)→boolida_nalt.is_aflag_hidden_item(flags:aflags_t)→boolida_nalt.is_aflag_manual_insn(flags:aflags_t)→boolida_nalt.is_aflag_hidden_border(flags:aflags_t)→boolida_nalt.is_aflag_zstroff(flags:aflags_t)→boolida_nalt.is_aflag__bnot0(flags:aflags_t)→boolida_nalt.is_aflag__bnot1(flags:aflags_t)→boolida_nalt.is_aflag_libitem(flags:aflags_t)→boolida_nalt.has_aflag_ti(flags:aflags_t)→boolida_nalt.has_aflag_ti0(flags:aflags_t)→boolida_nalt.has_aflag_ti1(flags:aflags_t)→boolida_nalt.has_aflag_lname(flags:aflags_t)→boolida_nalt.is_aflag_tilcmt(flags:aflags_t)→boolida_nalt.is_aflag_lzero0(flags:aflags_t)→boolida_nalt.is_aflag_lzero1(flags:aflags_t)→boolida_nalt.is_aflag_colored_item(flags:aflags_t)→boolida_nalt.is_aflag_terse_struc(flags:aflags_t)→boolida_nalt.is_aflag__invsign0(flags:aflags_t)→boolida_nalt.is_aflag__invsign1(flags:aflags_t)→boolida_nalt.is_aflag_noret(flags:aflags_t)→boolida_nalt.is_aflag_fixed_spd(flags:aflags_t)→boolida_nalt.is_aflag_align_flow(flags:aflags_t)→boolida_nalt.is_aflag_userti(flags:aflags_t)→boolida_nalt.is_aflag_retfp(flags:aflags_t)→boolida_nalt.uses_aflag_modsp(flags:aflags_t)→boolida_nalt.is_aflag_notcode(flags:aflags_t)→boolida_nalt.is_aflag_notproc(flags:aflags_t)→boolida_nalt.is_aflag_type_guessed_by_ida(flags:aflags_t)→boolida_nalt.is_aflag_func_guessed_by_hexrays(flags:aflags_t)→boolida_nalt.is_aflag_data_guessed_by_hexrays(flags:aflags_t)→boolida_nalt.is_aflag_type_determined_by_hexrays(flags:aflags_t)→boolida_nalt.is_aflag_type_guessed_by_hexrays(flags:aflags_t)→boolida_nalt.is_hidden_item(ea:ida_idaapi.ea_t)→boolida_nalt.hide_item(ea:ida_idaapi.ea_t)→Noneida_nalt.unhide_item(ea:ida_idaapi.ea_t)→Noneida_nalt.is_hidden_border(ea:ida_idaapi.ea_t)→boolida_nalt.hide_border(ea:ida_idaapi.ea_t)→Noneida_nalt.unhide_border(ea:ida_idaapi.ea_t)→Noneida_nalt.uses_modsp(ea:ida_idaapi.ea_t)→boolida_nalt.set_usemodsp(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_usemodsp(ea:ida_idaapi.ea_t)→Noneida_nalt.is_zstroff(ea:ida_idaapi.ea_t)→boolida_nalt.set_zstroff(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_zstroff(ea:ida_idaapi.ea_t)→Noneida_nalt.is__bnot0(ea:ida_idaapi.ea_t)→boolida_nalt.set__bnot0(ea:ida_idaapi.ea_t)→Noneida_nalt.clr__bnot0(ea:ida_idaapi.ea_t)→Noneida_nalt.is__bnot1(ea:ida_idaapi.ea_t)→boolida_nalt.set__bnot1(ea:ida_idaapi.ea_t)→Noneida_nalt.clr__bnot1(ea:ida_idaapi.ea_t)→Noneida_nalt.is_libitem(ea:ida_idaapi.ea_t)→boolida_nalt.set_libitem(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_libitem(ea:ida_idaapi.ea_t)→Noneida_nalt.has_ti(ea:ida_idaapi.ea_t)→boolida_nalt.set_has_ti(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_has_ti(ea:ida_idaapi.ea_t)→Noneida_nalt.has_ti0(ea:ida_idaapi.ea_t)→boolida_nalt.set_has_ti0(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_has_ti0(ea:ida_idaapi.ea_t)→Noneida_nalt.has_ti1(ea:ida_idaapi.ea_t)→boolida_nalt.set_has_ti1(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_has_ti1(ea:ida_idaapi.ea_t)→Noneida_nalt.has_lname(ea:ida_idaapi.ea_t)→boolida_nalt.set_has_lname(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_has_lname(ea:ida_idaapi.ea_t)→Noneida_nalt.is_tilcmt(ea:ida_idaapi.ea_t)→boolida_nalt.set_tilcmt(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_tilcmt(ea:ida_idaapi.ea_t)→Noneida_nalt.is_usersp(ea:ida_idaapi.ea_t)→boolida_nalt.set_usersp(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_usersp(ea:ida_idaapi.ea_t)→Noneida_nalt.is_lzero0(ea:ida_idaapi.ea_t)→boolida_nalt.set_lzero0(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_lzero0(ea:ida_idaapi.ea_t)→Noneida_nalt.is_lzero1(ea:ida_idaapi.ea_t)→boolida_nalt.set_lzero1(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_lzero1(ea:ida_idaapi.ea_t)→Noneida_nalt.is_colored_item(ea:ida_idaapi.ea_t)→boolida_nalt.set_colored_item(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_colored_item(ea:ida_idaapi.ea_t)→Noneida_nalt.is_terse_struc(ea:ida_idaapi.ea_t)→boolida_nalt.set_terse_struc(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_terse_struc(ea:ida_idaapi.ea_t)→Noneida_nalt.is__invsign0(ea:ida_idaapi.ea_t)→boolida_nalt.set__invsign0(ea:ida_idaapi.ea_t)→Noneida_nalt.clr__invsign0(ea:ida_idaapi.ea_t)→Noneida_nalt.is__invsign1(ea:ida_idaapi.ea_t)→boolida_nalt.set__invsign1(ea:ida_idaapi.ea_t)→Noneida_nalt.clr__invsign1(ea:ida_idaapi.ea_t)→Noneida_nalt.is_noret(ea:ida_idaapi.ea_t)→boolida_nalt.set_noret(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_noret(ea:ida_idaapi.ea_t)→Noneida_nalt.is_fixed_spd(ea:ida_idaapi.ea_t)→boolida_nalt.set_fixed_spd(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_fixed_spd(ea:ida_idaapi.ea_t)→Noneida_nalt.is_align_flow(ea:ida_idaapi.ea_t)→boolida_nalt.set_align_flow(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_align_flow(ea:ida_idaapi.ea_t)→Noneida_nalt.is_userti(ea:ida_idaapi.ea_t)→boolida_nalt.set_userti(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_userti(ea:ida_idaapi.ea_t)→Noneida_nalt.is_retfp(ea:ida_idaapi.ea_t)→boolida_nalt.set_retfp(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_retfp(ea:ida_idaapi.ea_t)→Noneida_nalt.is_notproc(ea:ida_idaapi.ea_t)→boolida_nalt.set_notproc(ea:ida_idaapi.ea_t)→Noneida_nalt.clr_notproc(ea:ida_idaapi.ea_t)→Noneida_nalt.is_type_guessed_by_ida(ea:ida_idaapi.ea_t)→boolida_nalt.is_func_guessed_by_hexrays(ea:ida_idaapi.ea_t)→boolida_nalt.is_data_guessed_by_hexrays(ea:ida_idaapi.ea_t)→boolida_nalt.is_type_determined_by_hexrays(ea:ida_idaapi.ea_t)→boolida_nalt.is_type_guessed_by_hexrays(ea:ida_idaapi.ea_t)→boolida_nalt.set_type_guessed_by_ida(ea:ida_idaapi.ea_t)→Noneida_nalt.set_func_guessed_by_hexrays(ea:ida_idaapi.ea_t)→Noneida_nalt.set_data_guessed_by_hexrays(ea:ida_idaapi.ea_t)→Noneida_nalt.set_type_determined_by_hexrays(ea:ida_idaapi.ea_t)→Noneida_nalt.set_notcode(ea:ida_idaapi.ea_t)→None
Mark address so that it cannot be converted to instruction.
ida_nalt.clr_notcode(ea:ida_idaapi.ea_t)→None
Clear not-code mark.
ida_nalt.is_notcode(ea:ida_idaapi.ea_t)→bool
Is the address marked as not-code?
ida_nalt.set_visible_item(ea:ida_idaapi.ea_t, visible:bool)→None
Change visibility of item at given ea.
ida_nalt.is_visible_item(ea:ida_idaapi.ea_t)→bool
Test visibility of item at given ea.
ida_nalt.is_finally_visible_item(ea:ida_idaapi.ea_t)→bool
Is instruction visible?
ida_nalt.set_source_linnum(ea:ida_idaapi.ea_t, lnnum:int)→Noneida_nalt.get_source_linnum(ea:ida_idaapi.ea_t)→intida_nalt.del_source_linnum(ea:ida_idaapi.ea_t)→Noneida_nalt.get_absbase(ea:ida_idaapi.ea_t)→ida_idaapi.ea_tida_nalt.set_absbase(ea:ida_idaapi.ea_t, x:ida_idaapi.ea_t)→Noneida_nalt.del_absbase(ea:ida_idaapi.ea_t)→Noneida_nalt.get_ind_purged(ea:ida_idaapi.ea_t)→ida_idaapi.ea_tida_nalt.del_ind_purged(ea:ida_idaapi.ea_t)→Noneida_nalt.get_str_type(ea:ida_idaapi.ea_t)→intida_nalt.set_str_type(ea:ida_idaapi.ea_t, x:int)→Noneida_nalt.del_str_type(ea:ida_idaapi.ea_t)→Noneida_nalt.STRWIDTH_1Bida_nalt.STRWIDTH_2Bida_nalt.STRWIDTH_4Bida_nalt.STRWIDTH_MASKida_nalt.STRLYT_TERMCHRida_nalt.STRLYT_PASCAL1ida_nalt.STRLYT_PASCAL2ida_nalt.STRLYT_PASCAL4ida_nalt.STRLYT_MASKida_nalt.STRLYT_SHIFTida_nalt.STRTYPE_TERMCHR
C-style string.
ida_nalt.STRTYPE_C
Zero-terminated 16-bit chars.
ida_nalt.STRTYPE_C_16
Zero-terminated 32-bit chars.
ida_nalt.STRTYPE_C_32
Pascal-style, one-byte length prefix.
ida_nalt.STRTYPE_PASCAL
Pascal-style, 16-bit chars, one-byte length prefix.
ida_nalt.STRTYPE_PASCAL_16
Pascal-style, 32-bit chars, one-byte length prefix.
ida_nalt.STRTYPE_PASCAL_32
Pascal-style, two-byte length prefix.
ida_nalt.STRTYPE_LEN2
Pascal-style, 16-bit chars, two-byte length prefix.
ida_nalt.STRTYPE_LEN2_16
Pascal-style, 32-bit chars, two-byte length prefix.
ida_nalt.STRTYPE_LEN2_32
Pascal-style, four-byte length prefix.
ida_nalt.STRTYPE_LEN4
Pascal-style, 16-bit chars, four-byte length prefix.
ida_nalt.STRTYPE_LEN4_16
Pascal-style, 32-bit chars, four-byte length prefix.
ida_nalt.STRTYPE_LEN4_32ida_nalt.get_str_type_code(strtype:int)→ucharida_nalt.get_str_term1(strtype:int)→charida_nalt.get_str_term2(strtype:int)→charida_nalt.get_str_encoding_idx(strtype:int)→ucharida_nalt.set_str_encoding_idx(strtype:int, encoding_idx:int)→intida_nalt.make_str_type(type_code:uchar, encoding_idx:int, term1:uchar=0, term2:uchar=0)→intida_nalt.is_pascal(strtype:int)→boolida_nalt.get_str_type_prefix_length(strtype:int)→intida_nalt.STRENC_DEFAULT
use default encoding for this type (see get_default_encoding_idx())
ida_nalt.STRENC_NONE
force no-conversion encoding
ida_nalt.get_alignment(ea:ida_idaapi.ea_t)→intida_nalt.set_alignment(ea:ida_idaapi.ea_t, x:int)→Noneida_nalt.del_alignment(ea:ida_idaapi.ea_t)→Noneida_nalt.set_item_color(ea:ida_idaapi.ea_t, color:bgcolor_t)→Noneida_nalt.get_item_color(ea:ida_idaapi.ea_t)→bgcolor_tida_nalt.del_item_color(ea:ida_idaapi.ea_t)→boolclassida_nalt.array_parameters_t(_f:int=1, _l:int=0, _a:int=-1)
Bases: `object`
thisownflags:intlineitems:int
number of items on a line
alignment:int
-1 - don’t align. 0 - align automatically. else item width
is_default()→boolida_nalt.AP_ALLOWDUPS
use ‘dup’ construct
ida_nalt.AP_SIGNED
treat numbers as signed
ida_nalt.AP_INDEX
display array element indexes as comments
ida_nalt.AP_ARRAY
create as array (this flag is not stored in database)
ida_nalt.AP_IDXBASEMASK
mask for number base of the indexes
ida_nalt.AP_IDXDEC
display indexes in decimal
ida_nalt.AP_IDXHEX
display indexes in hex
ida_nalt.AP_IDXOCT
display indexes in octal
ida_nalt.AP_IDXBIN
display indexes in binary
ida_nalt.get_array_parameters(out:array_parameters_t, ea:ida_idaapi.ea_t)→ssize_tida_nalt.set_array_parameters(ea:ida_idaapi.ea_t, _in:array_parameters_t)→Noneida_nalt.del_array_parameters(ea:ida_idaapi.ea_t)→Noneclassida_nalt.switch_info_t
Bases: `object`
thisownflags:int
Switch info flags
get_shift()→int
See SWI_SHIFT_MASK. possible answers: 0..3.
set_shift(shift:int)→None
See SWI_SHIFT_MASK.
get_jtable_element_size()→intset_jtable_element_size(size:int)→Noneget_vtable_element_size()→intset_vtable_element_size(size:int)→Nonehas_default()→boolhas_elbase()→boolis_sparse()→boolis_custom()→boolis_indirect()→boolis_subtract()→boolis_nolowcase()→booluse_std_table()→boolis_user_defined()→boolncases:ushort
number of cases (excluding default)
jumps:ida_idaapi.ea_t
jump table start address
values:ida_idaapi.ea_t
values table address (if SWI_SPARSE is set)
lowcase:int
the lowest value in cases
defjump:ida_idaapi.ea_t
default jump address (BADADDR if no default case)
startea:ida_idaapi.ea_t
start of the switch idiom
jcases:int
number of entries in the jump table (SWI_INDIRECT)
ind_lowcase:intget_lowcase()→intelbase:ida_idaapi.ea_t
element base
regnum:int
the switch expression as a value of the REGNUM register before the instruction at EXPR_EA. -1 means ‘unknown’
regdtype:op_dtype_t
size of the switch expression register as dtype
get_jtable_size()→intset_jtable_size(size:int)→Noneset_elbase(base:ida_idaapi.ea_t)→Noneset_expr(r:int, dt:op_dtype_t)→Noneget_jrange_vrange(jrange:range_t=None, vrange:range_t=None)→bool
get separate parts of the switch
custom:int
information for custom tables (filled and used by modules)
SWITCH_INFO_VERSIONget_version()→intexpr_ea:ida_idaapi.ea_t
the address before that the switch expression is in REGNUM. If BADADDR, then the first insn marked as IM_SWITCH after STARTEA is used.
marks:eavec_t
the insns marked as IM_SWITCH. They are used to delete the switch.
clear()→Noneassign(other:switch_info_t)→Noneida_nalt.SWI_SPARSE
sparse switch (value table present), otherwise lowcase present
ida_nalt.SWI_V32
32-bit values in table
ida_nalt.SWI_J32
32-bit jump offsets
ida_nalt.SWI_VSPLIT
value table is split (only for 32-bit values)
ida_nalt.SWI_USER
user specified switch (starting from version 2)
ida_nalt.SWI_DEF_IN_TBL
default case is an entry in the jump table. This flag is applicable in 2 cases: * The sparse indirect switch (i.e. a switch with a values table) {jump table size} == {value table size} + 1. The default case entry is the last one in the table (or the first one in the case of an inversed jump table). * The switch with insns in the jump table. The default case entry is before the first entry of the table.

See also the find_defjump_from_table() helper function.

ida_nalt.SWI_JMP_INV
jumptable is inversed. (last entry is for first entry in values table)
ida_nalt.SWI_SHIFT_MASK
use formula (element<<shift) + elbase to find jump targets
ida_nalt.SWI_ELBASE
elbase is present (otherwise the base of the switch segment will be used)
ida_nalt.SWI_JSIZE
jump offset expansion bit
ida_nalt.SWI_VSIZE
value table element size expansion bit
ida_nalt.SWI_SEPARATE
create an array of individual elements (otherwise separate items)
ida_nalt.SWI_SIGNED
jump table entries are signed
ida_nalt.SWI_CUSTOM
custom jump table. processor_t::create_switch_xrefs will be called to create code xrefs for the table. Custom jump table must be created by the module (see also SWI_STDTBL)
ida_nalt.SWI_INDIRECT
value table elements are used as indexes into the jump table (for sparse switches)
ida_nalt.SWI_SUBTRACT
table values are subtracted from the elbase instead of being added
ida_nalt.SWI_HXNOLOWCASE
lowcase value should not be used by the decompiler (internal flag)
ida_nalt.SWI_STDTBL
custom jump table with standard table formatting. ATM IDA doesn’t use SWI_CUSTOM for switches with standard table formatting. So this flag can be considered as obsolete.
ida_nalt.SWI_DEFRET
return in the default case (defjump==BADADDR)
ida_nalt.SWI_SELFREL
jump address is relative to the element not to ELBASE
ida_nalt.SWI_JMPINSN
jump table entries are insns. For such entries SHIFT has a different meaning. It denotes the number of insns in the entry. For example, 0 - the entry contains the jump to the case, 1 - the entry contains one insn like a ‘mov’ and jump to the end of case, and so on.
ida_nalt.SWI_VERSION
the structure contains the VERSION member
ida_nalt.get_switch_info(out:switch_info_t, ea:ida_idaapi.ea_t)→ssize_tida_nalt.set_switch_info(ea:ida_idaapi.ea_t, _in:switch_info_t)→Noneida_nalt.del_switch_info(ea:ida_idaapi.ea_t)→Noneida_nalt.get_switch_parent(ea:ida_idaapi.ea_t)→ida_idaapi.ea_tida_nalt.set_switch_parent(ea:ida_idaapi.ea_t, x:ida_idaapi.ea_t)→Noneida_nalt.del_switch_parent(ea:ida_idaapi.ea_t)→Noneclassida_nalt.custom_data_type_ids_t
Bases: `object`
thisowndtid:int16
data type id
fids:int16[8]
data format ids
set(tid:tid_t)→Noneget_dtid()→tid_tida_nalt.get_custom_data_type_ids(cdis:custom_data_type_ids_t, ea:ida_idaapi.ea_t)→intida_nalt.set_custom_data_type_ids(ea:ida_idaapi.ea_t, cdis:custom_data_type_ids_t)→Noneida_nalt.del_custom_data_type_ids(ea:ida_idaapi.ea_t)→Noneida_nalt.is_reftype_target_optional(type:reftype_t)→bool
Can the target be calculated using operand value?
ida_nalt.get_reftype_by_size(size:int)→reftype_t
Get REF_… constant from size Supported sizes: 1,2,4,8,16 For other sizes returns reftype_t(-1)
classida_nalt.refinfo_t
Bases: `object`
thisowntarget:ida_idaapi.ea_t
reference target (BADADDR-none)
base:ida_idaapi.ea_t
base of reference (may be BADADDR)
tdelta:adiff_t
offset from the target
flags:int
Reference info flags
type()→reftype_tis_target_optional()→bool
< is_reftype_target_optional()
no_base_xref()→boolis_pastend()→boolis_rvaoff()→boolis_custom()→boolis_subtract()→boolis_signed()→boolis_no_zeros()→boolis_no_ones()→boolis_selfref()→boolis_user()→boolset_type(rt:reftype_t)→Noneinit(*args)→Noneida_nalt.cvarida_nalt.V695_REF_OFF8
reserved
ida_nalt.REF_OFF16
16-bit full offset
ida_nalt.REF_OFF32
32-bit full offset
ida_nalt.REF_LOW8
low 8 bits of 16-bit offset
ida_nalt.REF_LOW16
low 16 bits of 32-bit offset
ida_nalt.REF_HIGH8
high 8 bits of 16-bit offset
ida_nalt.REF_HIGH16
high 16 bits of 32-bit offset
ida_nalt.V695_REF_VHIGH
obsolete
ida_nalt.V695_REF_VLOW
obsolete
ida_nalt.REF_OFF64
64-bit full offset
ida_nalt.REF_OFF8
8-bit full offset
ida_nalt.REF_LOW32
low 32 bits of 64-bit offset
ida_nalt.REF_HIGH32
high 32 bits of 64-bit offset
ida_nalt.REF_LASTida_nalt.REFINFO_TYPE
reference type (reftype_t), or custom reference ID if REFINFO_CUSTOM set
ida_nalt.REFINFO_RVAOFF
based reference (rva); refinfo_t::base will be forced to get_imagebase(); such a reference is displayed with the asm_t::a_rva keyword
ida_nalt.REFINFO_PASTEND
reference past an item; it may point to a nonexistent address; do not destroy alignment dirs
ida_nalt.REFINFO_CUSTOM
a custom reference. see custom_refinfo_handler_t. the id of the custom refinfo is stored under the REFINFO_TYPE mask.
ida_nalt.REFINFO_NOBASE
don’t create the base xref; implies that the base can be any value. nb: base xrefs are created only if the offset base points to the middle of a segment
ida_nalt.REFINFO_SUBTRACT
the reference value is subtracted from the base value instead of (as usual) being added to it
ida_nalt.REFINFO_SIGNEDOP
the operand value is sign-extended (only supported for REF_OFF8/16/32/64)
ida_nalt.REFINFO_NO_ZEROS
an opval of 0 will be considered invalid
ida_nalt.REFINFO_NO_ONES
an opval of ~0 will be considered invalid
ida_nalt.REFINFO_SELFREF
the self-based reference; refinfo_t::base will be forced to the reference address
ida_nalt.REFINFO_USER
ignore fixup when processing this refinfo
ida_nalt.find_custom_refinfo(name:str)→int
Get id of a custom refinfo type.
ida_nalt.get_custom_refinfo(crid:int)→custom_refinfo_handler_tconst*
Get definition of a registered custom refinfo type.
ida_nalt.MAXSTRUCPATH
maximum inclusion depth for nested unions
classida_nalt.strpath_t
Bases: `object`
thisownlen:intids:tid_t[32]delta:adiff_tclassida_nalt.enum_const_t
Bases: `object`
thisowntid:tid_tserial:ucharclassida_nalt.opinfo_t
Bases: `object`
thisownri:refinfo_t
for offset members
tid:tid_t
for struct, etc. members
path:strpath_t
for stroff
strtype:int
for strings (String type codes)
ec:enum_const_t
for enums
cd:custom_data_type_ids_t
for custom data
classida_nalt.printop_t
Bases: `object`
thisownti:opinfo_tfeatures:ucharsuspop:intaflags:aflags_tflags:flags64_tis_ti_initialized()→boolset_ti_initialized(v:bool=True)→Noneis_aflags_initialized()→boolset_aflags_initialized(v:bool=True)→Noneis_f64()→boolget_ti()→opinfo_tconst*is_ti_validida_nalt.POF_VALID_TIida_nalt.POF_VALID_AFLAGSida_nalt.POF_IS_F64ida_nalt.set_refinfo_ex(ea:ida_idaapi.ea_t, n:int, ri:refinfo_t)→boolida_nalt.set_refinfo(*args)→boolida_nalt.get_refinfo(ri:refinfo_t, ea:ida_idaapi.ea_t, n:int)→boolida_nalt.del_refinfo(ea:ida_idaapi.ea_t, n:int)→boolida_nalt.get_tinfo(tif:tinfo_t, ea:ida_idaapi.ea_t)→boolida_nalt.set_tinfo(ea:ida_idaapi.ea_t, tif:tinfo_t)→boolida_nalt.del_tinfo(ea:ida_idaapi.ea_t)→Noneida_nalt.get_op_tinfo(tif:tinfo_t, ea:ida_idaapi.ea_t, n:int)→boolida_nalt.set_op_tinfo(ea:ida_idaapi.ea_t, n:int, tif:tinfo_t)→boolida_nalt.del_op_tinfo(ea:ida_idaapi.ea_t, n:int)→Noneida_nalt.RIDX_FILE_FORMAT_NAME
file format name for loader modules
ida_nalt.RIDX_SELECTORS
2..63 are for selector_t blob (see init_selectors())
ida_nalt.RIDX_GROUPS
segment group information (see init_groups())
ida_nalt.RIDX_H_PATH
C header path.
ida_nalt.RIDX_C_MACROS
C predefined macros.
ida_nalt.RIDX_SMALL_IDC_OLD
Instant IDC statements (obsolete)
ida_nalt.RIDX_NOTEPAD
notepad blob, occupies 1000 indexes (1MB of text)
ida_nalt.RIDX_INCLUDE
assembler include file name
ida_nalt.RIDX_SMALL_IDC
Instant IDC statements, blob.
ida_nalt.RIDX_DUALOP_GRAPH
Graph text representation options.
ida_nalt.RIDX_DUALOP_TEXT
Text representation options.
ida_nalt.RIDX_MD5
MD5 of the input file.
ida_nalt.RIDX_IDA_VERSION
version of ida which created the database
ida_nalt.RIDX_STR_ENCODINGS
a list of encodings for the program strings
ida_nalt.RIDX_SRCDBG_PATHS
source debug paths, occupies 20 indexes
ida_nalt.RIDX_DBG_BINPATHS
unused (20 indexes)
ida_nalt.RIDX_SHA256
SHA256 of the input file.
ida_nalt.RIDX_ABINAME
ABI name (processor specific)
ida_nalt.RIDX_ARCHIVE_PATH
archive file path
ida_nalt.RIDX_PROBLEMS
problem lists
ida_nalt.RIDX_SRCDBG_UNDESIRED
user-closed source files, occupies 20 indexes
ida_nalt.get_root_filename()→str
Get file name only of the input file.
ida_nalt.dbg_get_input_path()→str
Get debugger input file name/path (see LFLG_DBG_NOPATH)
ida_nalt.get_input_file_path()→str
Get full path of the input file.
ida_nalt.set_root_filename(file:str)→None
Set full path of the input file.
ida_nalt.retrieve_input_file_size()→int
Get size of input file in bytes.
ida_nalt.retrieve_input_file_crc32()→int
Get input file crc32 stored in the database. it can be used to check that the input file has not been changed.
ida_nalt.retrieve_input_file_md5()→bytes
Get input file md5.
ida_nalt.retrieve_input_file_sha256()→bytes
Get input file sha256.
ida_nalt.get_asm_inc_file()→str
Get name of the include file.
ida_nalt.set_asm_inc_file(file:str)→bool
Set name of the include file.
ida_nalt.get_imagebase()→ida_idaapi.ea_t
Get image base address.
ida_nalt.set_imagebase(base:ida_idaapi.ea_t)→None
Set image base address.
ida_nalt.get_ids_modnode()→netnode
Get ids modnode.
ida_nalt.set_ids_modnode(id:netnode)→None
Set ids modnode.
ida_nalt.get_archive_path()→str
Get archive file path from which input file was extracted.
ida_nalt.set_archive_path(file:str)→bool
Set archive file path from which input file was extracted.
ida_nalt.get_loader_format_name()→str
Get file format name for loader modules.
ida_nalt.set_loader_format_name(name:str)→None
Set file format name for loader modules.
ida_nalt.get_initial_ida_version()→str
Get version of ida which created the database (string format like “7.5”)
ida_nalt.get_ida_notepad_text()→str
Get notepad text.
ida_nalt.set_ida_notepad_text(text:str, size:int=0)→None
Set notepad text.
ida_nalt.get_srcdbg_paths()→str
Get source debug paths.
ida_nalt.set_srcdbg_paths(paths:str)→None
Set source debug paths.
ida_nalt.get_srcdbg_undesired_paths()→str
Get user-closed source files.
ida_nalt.set_srcdbg_undesired_paths(paths:str)→None
Set user-closed source files.
ida_nalt.get_initial_idb_version()→ushort
Get initial version of the database (numeric format like 700)
ida_nalt.get_idb_ctime()→time_t
Get database creation timestamp.
ida_nalt.get_elapsed_secs()→int
Get seconds database stayed open.
ida_nalt.get_idb_nopens()→int
Get number of times the database is opened.
ida_nalt.get_encoding_qty()→intida_nalt.get_encoding_name(idx:int)→strida_nalt.add_encoding(encname:str)→intida_nalt.del_encoding(idx:int)→boolida_nalt.rename_encoding(idx:int, encname:str)→boolida_nalt.BPU_1Bida_nalt.BPU_2Bida_nalt.BPU_4Bida_nalt.get_encoding_bpu(idx:int)→intida_nalt.get_encoding_bpu_by_name(encname:str)→intida_nalt.get_strtype_bpu(strtype:int)→intida_nalt.get_default_encoding_idx(bpu:int)→intida_nalt.set_default_encoding_idx(bpu:int, idx:int)→boolida_nalt.encoding_from_strtype(strtype:int)→strida_nalt.get_outfile_encoding_idx()→intida_nalt.set_outfile_encoding_idx(idx:int)→boolida_nalt.get_import_module_qty()→uintida_nalt.delete_imports()→Noneclassida_nalt.import_entry_t
Bases: `object`
thisownname:str
name of import entry (may be empty)
ordinals:qvector
import ordinals (may be empty)
mod_index:int
module
ida_nalt.get_import_entry(entry:import_entry_t, ea:ida_idaapi.ea_t)→boolida_nalt.GOTEA_NODE_NAME
node containing address of .got section
ida_nalt.GOTEA_NODE_IDXida_nalt.set_gotea(gotea:ida_idaapi.ea_t)→Noneida_nalt.get_gotea()→ida_idaapi.ea_tida_nalt.get_import_module_name(mod_index)
Returns the name of an imported module given its index
Parameters:
mod_index – the module index
Returns:
None or the module name
ida_nalt.enum_import_names(mod_index, callback)
Enumerate imports from a specific module. Please refer to list_imports.py example.
Parameters:

-
mod_index – The module index

-
callback – A callable object that will be invoked with an ea, name (could be None) and ordinal.

Returns:
1-finished ok, -1 on error, otherwise callback return value (<=0)
ida_nalt.switch_info_t__from_ptrval__(ptrval:int)→switch_info_t*ida_nalt.get_switch_info(*args)ida_nalt.get_abi_name()ida_nalt.get_initial_version
