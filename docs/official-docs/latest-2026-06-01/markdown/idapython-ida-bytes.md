# IDAPython bytes/data API

- 官方来源：https://python.docs.hex-rays.com/ida_bytes/index.html

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
- ida_bytes
- View page source

# ida_bytes

Contains functions that deal with individual byte characteristics.

Each byte of the disassembled program is represented by a 32-bit value. We will call this value ‘flags’. The structure of the flags is here. You are not allowed to inspect individual bits of flags and modify them directly. Use special functions to inspect and/or modify flags. Flags are kept in a virtual array file (*.id1). Addresses (ea) are all 32-bit (or 64-bit) quantities.

## Attributes

`ITEM_END_FIXUP`
|
stop at the first fixup

`ITEM_END_INITED`
|
stop when initialization changes i.e.

`ITEM_END_NAME`
|
stop at the first named location

`ITEM_END_XREF`
|
stop at the first referenced location

`ITEM_END_CANCEL`
|
stop when operation cancelled, it is the responsibility of the caller to show the wait dialog

`GFE_VALUE`
|
get flags with FF_IVL & MS_VAL. It is much slower under remote debugging because the kernel needs to read the process memory.

`GFE_IDB_VALUE`
|
get flags with FF_IVL & MS_VAL. but never use the debugger memory.

`GFE_32BIT`
|
get only low 32 bits of flags

`MS_VAL`
|
Mask for byte value.

`FF_IVL`
|
Byte has value ?

`GMB_READALL`
|
try to read all bytes; if this bit is not set, fail at first uninited byte

`GMB_WAITBOX`
|
show wait box (may return -1 in this case)

`MS_CLS`
|
Mask for typing.

`FF_CODE`
|
Code ?

`FF_DATA`
|
Data ?

`FF_TAIL`
|
Tail ?

`FF_UNK`
|
Unknown ?

`DELIT_SIMPLE`
|
simply undefine the specified item(s)

`DELIT_EXPAND`
|
propagate undefined items; for example if removing an instruction removes all references to the next instruction, then plan to convert to unexplored the next instruction too.

`DELIT_DELNAMES`
|
delete any names at the specified address range (except for the starting address). this bit is valid if nbytes > 1

`DELIT_NOTRUNC`
|
don't truncate the current function even if AF_TRFUNC is set

`DELIT_NOUNAME`
|
reject to delete if a user name is in address range (except for the starting address). this bit is valid if nbytes > 1

`DELIT_NOCMT`
|
reject to delete if a comment is in address range (except for the starting address). this bit is valid if nbytes > 1

`DELIT_KEEPFUNC`
|
do not undefine the function start. Just delete xrefs, ops e.t.c.

`MS_COMM`
|
Mask of common bits.

`FF_COMM`
|
Has comment?

`FF_REF`
|
has references

`FF_LINE`
|
Has next or prev lines?

`FF_NAME`
|
Has name?

`FF_LABL`
|
Has dummy name?

`FF_FLOW`
|
Exec flow from prev instruction.

`FF_SIGN`
|
Inverted sign of operands.

`FF_BNOT`
|
Bitwise negation of operands.

`FF_UNUSED`
|
unused bit (was used for variable bytes)

`FF_ANYNAME`
|
Has name or dummy name?

`MS_N_TYPE`
|
Mask for nth arg (a 64-bit constant)

`FF_N_VOID`
|
Void (unknown)?

`FF_N_NUMH`
|
Hexadecimal number?

`FF_N_NUMD`
|
Decimal number?

`FF_N_CHAR`
|
Char ('x')?

`FF_N_SEG`
|
Segment?

`FF_N_OFF`
|
Offset?

`FF_N_NUMB`
|
Binary number?

`FF_N_NUMO`
|
Octal number?

`FF_N_ENUM`
|
Enumeration?

`FF_N_FOP`
|
Forced operand?

`FF_N_STRO`
|
Struct offset?

`FF_N_STK`
|
Stack variable?

`FF_N_FLT`
|
Floating point number?

`FF_N_CUST`
|
Custom representation?

`OPND_OUTER`
|
outer offset base (combined with operand number). used only in set, get, del_offset() functions

`OPND_MASK`
|
mask for operand number

`OPND_ALL`
|
all operands

`DT_TYPE`
|
Mask for DATA typing.

`FF_BYTE`
|
byte

`FF_WORD`
|
word

`FF_DWORD`
|
double word

`FF_QWORD`
|
quadro word

`FF_TBYTE`
|
tbyte

`FF_STRLIT`
|
string literal

`FF_STRUCT`
|
struct variable

`FF_OWORD`
|
octaword/xmm word (16 bytes/128 bits)

`FF_FLOAT`
|
float

`FF_DOUBLE`
|
double

`FF_PACKREAL`
|
packed decimal real

`FF_ALIGN`
|
alignment directive

`FF_CUSTOM`
|
custom data type

`FF_YWORD`
|
ymm word (32 bytes/256 bits)

`FF_ZWORD`
|
zmm word (64 bytes/512 bits)

`ALOPT_IGNHEADS`
|
don't stop if another data item is encountered. only the byte values will be used to determine the string length. if not set, a defined data item or instruction will truncate the string

`ALOPT_IGNPRINT`
|
if set, don't stop at non-printable codepoints, but only at the terminating character (or not unicode-mapped character (e.g., 0x8f in CP1252))

`ALOPT_IGNCLT`
|
if set, don't stop at codepoints that are not part of the current 'culture'; accept all those that are graphical (this is typically used used by user-initiated actions creating string literals.)

`ALOPT_MAX4K`
|
if string length is more than 4K, return the accumulated length

`ALOPT_ONLYTERM`
|
only the termination characters can be at the string end. Without this option illegal characters also terminate the string.

`ALOPT_APPEND`
|
if an existing strlit is encountered, then append it to the string.

`STRCONV_ESCAPE`
|
convert non-printable characters to C escapes (

`STRCONV_REPLCHAR`
|
convert non-printable characters to the Unicode replacement character (U+FFFD)

`STRCONV_INCLLEN`
|
for Pascal-style strings, include the prefixing length byte(s) as C-escaped sequence

`PSTF_TNORM`
|
use normal name

`PSTF_TBRIEF`
|
use brief name (e.g., in the 'Strings' window)

`PSTF_TINLIN`
|
use 'inline' name (e.g., in the structures comments)

`PSTF_TMASK`
|
type mask

`PSTF_HOTKEY`
|
have hotkey markers part of the name

`PSTF_ENC`
|
if encoding is specified, append it

`PSTF_ONLY_ENC`
|
generate only the encoding name

`PSTF_ATTRIB`
|
generate for type attribute usage

`MS_CODE`
|
Mask for code bits.

`FF_FUNC`
|
function start?

`FF_IMMD`
|
Has Immediate value ?

`FF_JUMP`
|
Has jump table or switch_info?

`DTP_NODUP`
|
do not use dup construct

`PBSENC_DEF1BPU`
|
Use the default 1 byte-per-unit IDB encoding.

`PBSENC_ALL`
|
Use all IDB encodings.

`BIN_SEARCH_CASE`
|
case sensitive

`BIN_SEARCH_NOCASE`
|
case insensitive

`BIN_SEARCH_NOBREAK`
|
don't check for Ctrl-Break

`BIN_SEARCH_INITED`
|
find_byte, find_byter: any initilized value

`BIN_SEARCH_NOSHOW`
|
don't show search progress or update screen

`BIN_SEARCH_FORWARD`
|
search forward for bytes

`BIN_SEARCH_BACKWARD`
|
search backward for bytes

`BIN_SEARCH_BITMASK`
|
searching using strict bit mask

`MS_0TYPE`
|

`FF_0VOID`
|

`FF_0NUMH`
|

`FF_0NUMD`
|

`FF_0CHAR`
|

`FF_0SEG`
|

`FF_0OFF`
|

`FF_0NUMB`
|

`FF_0NUMO`
|

`FF_0ENUM`
|

`FF_0FOP`
|

`FF_0STRO`
|

`FF_0STK`
|

`FF_0FLT`
|

`FF_0CUST`
|

`MS_1TYPE`
|

`FF_1VOID`
|

`FF_1NUMH`
|

`FF_1NUMD`
|

`FF_1CHAR`
|

`FF_1SEG`
|

`FF_1OFF`
|

`FF_1NUMB`
|

`FF_1NUMO`
|

`FF_1ENUM`
|

`FF_1FOP`
|

`FF_1STRO`
|

`FF_1STK`
|

`FF_1FLT`
|

`FF_1CUST`
|

`DTP_NODUP`
|
do not use dup construct

## Classes

`compiled_binpat_vec_t`
|

`octet_generator_t`
|

`data_type_t`
|
Information about a data type

`data_format_t`
|
Information about a data format

`compiled_binpat_t`
|

`hidden_range_t`
|

## Functions

`enable_flags`(→ error_t)
|
Allocate flags for address range. This function does not change the storage type of existing ranges. Exit with an error message if not enough disk space.

`disable_flags`(→ error_t)
|
Deallocate flags for address range. Exit with an error message if not enough disk space (this may occur too).

`change_storage_type`(→ error_t)
|
Change flag storage type for address range.

`next_addr`(→ ida_idaapi.ea_t)
|
Get next address in the program (i.e. next address which has flags).

`prev_addr`(→ ida_idaapi.ea_t)
|
Get previous address in the program.

`next_chunk`(→ ida_idaapi.ea_t)
|
Get the first address of next contiguous chunk in the program.

`prev_chunk`(→ ida_idaapi.ea_t)
|
Get the last address of previous contiguous chunk in the program.

`chunk_start`(→ ida_idaapi.ea_t)
|
Get start of the contiguous address block containing 'ea'.

`chunk_size`(→ asize_t)
|
Get size of the contiguous address block containing 'ea'.

`find_free_chunk`(→ ida_idaapi.ea_t)
|
Search for a hole in the addressing space of the program.

`next_that`(→ ida_idaapi.ea_t)
|
Find next address with a flag satisfying the function 'testf'.

`next_unknown`(→ ida_idaapi.ea_t)
|
Similar to next_that(), but will find the next address that is unexplored.

`prev_that`(→ ida_idaapi.ea_t)
|
Find previous address with a flag satisfying the function 'testf'.

`prev_unknown`(→ ida_idaapi.ea_t)
|
Similar to prev_that(), but will find the previous address that is unexplored.

`prev_head`(→ ida_idaapi.ea_t)
|
Get start of previous defined item.

`next_head`(→ ida_idaapi.ea_t)
|
Get start of next defined item.

`prev_not_tail`(→ ida_idaapi.ea_t)
|
Get address of previous non-tail byte.

`next_not_tail`(→ ida_idaapi.ea_t)
|
Get address of next non-tail byte.

`prev_visea`(→ ida_idaapi.ea_t)
|
Get previous visible address.

`next_visea`(→ ida_idaapi.ea_t)
|
Get next visible address.

`get_item_head`(→ ida_idaapi.ea_t)
|
Get the start address of the item at 'ea'. If there is no current item, then 'ea' is returned (see definition at the end of bytes.hpp source)

`get_item_end`(→ ida_idaapi.ea_t)
|
Get the end address of the item at 'ea'. The returned address does not belong to the current item. Unexplored bytes are counted as 1 byte entities.

`calc_max_item_end`(→ ida_idaapi.ea_t)
|
Calculate maximal reasonable end address of a new item. This function will limit the item with the current segment bounds.

`get_item_size`(→ asize_t)
|
Get size of item (instruction/data) in bytes. Unexplored bytes have length of 1 byte. This function returns 0 only for BADADDR.

`is_mapped`(→ bool)
|
Is the specified address 'ea' present in the program?

`get_flags_ex`(→ flags64_t)
|
Get flags for the specified address, extended form.

`get_flags32`(→ flags64_t)
|
Get only 32 low bits of flags. This function returns the most commonly used bits of the flags. However, it does not return the operand info for the operands beyond the first two operands (0,1). If you need to deal with the operands (2..n), then use get_flags(). It is customary to assign the return value to the variable named "F32", to distinguish is from 64-bit flags.

`get_flags`(→ flags64_t)
|
Get flags value for address 'ea'. The byte value is not included in the flags. This function should be used if the operand types of any operand beyond the first two operands is required. This function is more expensive to use than get_flags32()

`get_full_flags`(→ flags64_t)
|
Get full flags value for address 'ea'. This function returns the byte value in the flags as well. See FF_IVL and MS_VAL. This function is more expensive to use than get_flags()

`get_item_flag`(→ flags64_t)
|
Get flag of the item at 'ea' even if it is a tail byte of some array or structure. This function is used to get flags of structure members or array elements.

`get_item_refinfo`(→ bool)
|
Get refinfo of the item at 'ea'. This function works for a regular offset operand as well as for a tail byte of a structure variable (in this case refinfo to corresponding structure member is returned)

`has_value`(→ bool)
|
Do flags contain byte value?

`del_value`(→ None)
|
Delete byte value from flags. The corresponding byte becomes uninitialized.

`is_loaded`(→ bool)
|
Does the specified address have a byte value (is initialized?)

`nbits`(→ int)
|
Get number of bits in a byte at the given address.

`bytesize`(→ int)
|
Get number of bytes required to store a byte at the given address.

`get_byte`(→ uchar)
|
Get one byte (8-bit) of the program at 'ea'. This function works only for 8-bit byte processors.

`get_db_byte`(→ uchar)
|
Get one byte (8-bit) of the program at 'ea' from the database. Works even if the debugger is active. See also get_dbg_byte() to read the process memory directly. This function works only for 8-bit byte processors.

`get_word`(→ ushort)
|
Get one word (16-bit) of the program at 'ea'. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8-bit byte processors.

`get_dword`(→ int)
|
Get one dword (32-bit) of the program at 'ea'. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8-bit byte processors.

`get_qword`(→ uint64)
|
Get one qword (64-bit) of the program at 'ea'. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8-bit byte processors.

`get_wide_byte`(→ uint64)
|
Get one wide byte of the program at 'ea'. Some processors may access more than 8-bit quantity at an address. These processors have 32-bit byte organization from the IDA's point of view.

`get_wide_word`(→ uint64)
|
Get one wide word (2 'byte') of the program at 'ea'. Some processors may access more than 8-bit quantity at an address. These processors have 32-bit byte organization from the IDA's point of view. This function takes into account order of bytes specified in idainfo::is_be()

`get_wide_dword`(→ uint64)
|
Get two wide words (4 'bytes') of the program at 'ea'. Some processors may access more than 8-bit quantity at an address. These processors have 32-bit byte organization from the IDA's point of view. This function takes into account order of bytes specified in idainfo::is_be()

`get_octet`(→ uchar *)
|

`get_16bit`(→ int)
|
Get 16bits of the program at 'ea'.

`get_32bit`(→ int)
|
Get not more than 32bits of the program at 'ea'.

`get_64bit`(→ uint64)
|
Get not more than 64bits of the program at 'ea'.

`get_data_value`(→ bool)
|
Get the value at of the item at 'ea'. This function works with entities up to sizeof(ea_t) (bytes, word, etc)

`get_original_byte`(→ uint64)
|
Get original byte value (that was before patching). This function works for wide byte processors too.

`get_original_word`(→ uint64)
|
Get original word value (that was before patching). This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()

`get_original_dword`(→ uint64)
|
Get original dword (that was before patching) This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()

`get_original_qword`(→ uint64)
|
Get original qword value (that was before patching) This function DOESN'T work for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()

`put_byte`(→ bool)
|
Set value of one byte of the program. This function modifies the database. If the debugger is active then the debugged process memory is patched too.

`put_word`(→ None)
|
Set value of one word of the program. This function takes into account order of bytes specified in idainfo::is_be() This function works for wide byte processors too.

`put_dword`(→ None)
|
Set value of one dword of the program. This function takes into account order of bytes specified in idainfo::is_be() This function works for wide byte processors too.

`put_qword`(→ None)
|
Set value of one qword (8 bytes) of the program. This function takes into account order of bytes specified in idainfo::is_be() This function DOESN'T works for wide byte processors.

`patch_byte`(→ bool)
|
Patch a byte of the program. The original value of the byte is saved and can be obtained by get_original_byte(). This function works for wide byte processors too.

`patch_word`(→ bool)
|
Patch a word of the program. The original value of the word is saved and can be obtained by get_original_word(). This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()

`patch_dword`(→ bool)
|
Patch a dword of the program. The original value of the dword is saved and can be obtained by get_original_dword(). This function DOESN'T work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be()

`patch_qword`(→ bool)
|
Patch a qword of the program. The original value of the qword is saved and can be obtained by get_original_qword(). This function DOESN'T work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be()

`revert_byte`(→ bool)
|
Revert patched byte

`add_byte`(→ None)
|
Add a value to one byte of the program. This function works for wide byte processors too.

`add_word`(→ None)
|
Add a value to one word of the program. This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()

`add_dword`(→ None)
|
Add a value to one dword of the program. This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()

`add_qword`(→ None)
|
Add a value to one qword of the program. This function does not work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be()

`get_zero_ranges`(→ bool)
|
Return set of ranges with zero initialized bytes. The returned set includes only big zero initialized ranges (at least >1KB). Some zero initialized byte ranges may be not included. Only zero bytes that use the sparse storage method (STT_MM) are reported.

`put_bytes`(→ None)
|
Modify the specified number of bytes of the program. This function does not save the original values of bytes. See also patch_bytes().

`patch_bytes`(→ None)
|
Patch the specified number of bytes of the program. Original values of bytes are saved and are available with get_original...() functions. See also put_bytes().

`is_code`(→ bool)
|
Does flag denote start of an instruction?

`f_is_code`(→ bool)
|
Does flag denote start of an instruction?

`is_data`(→ bool)
|
Does flag denote start of data?

`f_is_data`(→ bool)
|
Does flag denote start of data?

`is_tail`(→ bool)
|
Does flag denote tail byte?

`f_is_tail`(→ bool)
|
Does flag denote tail byte?

`is_not_tail`(→ bool)
|
Does flag denote tail byte?

`f_is_not_tail`(→ bool)
|
Does flag denote tail byte?

`is_unknown`(→ bool)
|
Does flag denote unexplored byte?

`is_head`(→ bool)
|
Does flag denote start of instruction OR data?

`f_is_head`(→ bool)
|
Does flag denote start of instruction OR data?

`del_items`(→ bool)
|
Convert item (instruction/data) to unexplored bytes. The whole item (including the head and tail bytes) will be destroyed. It is allowed to pass any address in the item to this function

`is_manual_insn`(→ bool)
|
Is the instruction overridden?

`get_manual_insn`(→ str)
|
Retrieve the user-specified string for the manual instruction.

`set_manual_insn`(→ None)
|
Set manual instruction string.

`is_flow`(→ bool)
|
Does the previous instruction exist and pass execution flow to the current byte?

`has_extra_cmts`(→ bool)
|
Does the current byte have additional anterior or posterior lines?

`f_has_extra_cmts`(→ bool)
|

`has_cmt`(→ bool)
|
Does the current byte have an indented comment?

`f_has_cmt`(→ bool)
|

`has_xref`(→ bool)
|
Does the current byte have cross-references to it?

`f_has_xref`(→ bool)
|
Does the current byte have cross-references to it?

`has_name`(→ bool)
|
Does the current byte have non-trivial (non-dummy) name?

`f_has_name`(→ bool)
|
Does the current byte have non-trivial (non-dummy) name?

`has_dummy_name`(→ bool)
|
Does the current byte have dummy (auto-generated, with special prefix) name?

`f_has_dummy_name`(→ bool)
|
Does the current byte have dummy (auto-generated, with special prefix) name?

`has_auto_name`(→ bool)
|
Does the current byte have auto-generated (no special prefix) name?

`has_any_name`(→ bool)
|
Does the current byte have any name?

`has_user_name`(→ bool)
|
Does the current byte have user-specified name?

`f_has_user_name`(→ bool)
|
Does the current byte have user-specified name?

`is_invsign`(→ bool)
|
Should the sign of n-th operand be inverted during output? allowed values of n: 0-first operand, 1-other operands

`toggle_sign`(→ bool)
|
Toggle sign of n-th operand. allowed values of n: 0-first operand, 1-other operands

`is_bnot`(→ bool)
|
Should we negate the operand? asm_t::a_bnot should be defined in the idp module in order to work with this function

`toggle_bnot`(→ bool)
|
Toggle binary negation of operand. also see is_bnot()

`is_lzero`(→ bool)
|
Display leading zeros? Display leading zeros in operands. The global switch for the leading zeros is in idainfo::s_genflags Note: the leading zeros does not work if for the target assembler octal numbers start with 0.

`set_lzero`(→ bool)
|
Set toggle lzero bit. This function changes the display of leading zeros for the specified operand. If the default is not to display leading zeros, this function will display them and vice versa.

`clr_lzero`(→ bool)
|
Clear toggle lzero bit. This function reset the display of leading zeros for the specified operand to the default. If the default is not to display leading zeros, leading zeros will not be displayed, as vice versa.

`toggle_lzero`(→ bool)
|
Toggle lzero bit.

`leading_zero_important`(→ bool)
|
Check if leading zeros are important.

`get_operand_type_shift`(→ int)
|
Get the shift in flags64_t for the nibble representing operand n's type

`get_operand_flag`(→ flags64_t)
|
Place operand n's type flag in the right nibble of a 64-bit flags set.

`is_flag_for_operand`(→ bool)
|
Check that the 64-bit flags set has the expected type for operand n.

`is_defarg0`(→ bool)
|
Is the first operand defined? Initially operand has no defined representation.

`is_defarg1`(→ bool)
|
Is the second operand defined? Initially operand has no defined representation.

`is_off0`(→ bool)
|
Is the first operand offset? (example: push offset xxx)

`is_off1`(→ bool)
|
Is the second operand offset? (example: mov ax, offset xxx)

`is_char0`(→ bool)
|
Is the first operand character constant? (example: push 'a')

`is_char1`(→ bool)
|
Is the second operand character constant? (example: mov al, 'a')

`is_seg0`(→ bool)
|
Is the first operand segment selector? (example: push seg seg001)

`is_seg1`(→ bool)
|
Is the second operand segment selector? (example: mov dx, seg dseg)

`is_enum0`(→ bool)
|
Is the first operand a symbolic constant (enum member)?

`is_enum1`(→ bool)
|
Is the second operand a symbolic constant (enum member)?

`is_stroff0`(→ bool)
|
Is the first operand an offset within a struct?

`is_stroff1`(→ bool)
|
Is the second operand an offset within a struct?

`is_stkvar0`(→ bool)
|
Is the first operand a stack variable?

`is_stkvar1`(→ bool)
|
Is the second operand a stack variable?

`is_float0`(→ bool)
|
Is the first operand a floating point number?

`is_float1`(→ bool)
|
Is the second operand a floating point number?

`is_custfmt0`(→ bool)
|
Does the first operand use a custom data representation?

`is_custfmt1`(→ bool)
|
Does the second operand use a custom data representation?

`is_numop0`(→ bool)
|
Is the first operand a number (i.e. binary, octal, decimal or hex?)

`is_numop1`(→ bool)
|
Is the second operand a number (i.e. binary, octal, decimal or hex?)

`get_optype_flags0`(→ flags64_t)
|
Get flags for first operand.

`get_optype_flags1`(→ flags64_t)
|
Get flags for second operand.

`is_defarg`(→ bool)
|
is defined?

`is_off`(→ bool)
|
is offset?

`is_char`(→ bool)
|
is character constant?

`is_seg`(→ bool)
|
is segment?

`is_enum`(→ bool)
|
is enum?

`is_manual`(→ bool)
|
is forced operand? (use is_forced_operand())

`is_stroff`(→ bool)
|
is struct offset?

`is_stkvar`(→ bool)
|
is stack variable?

`is_fltnum`(→ bool)
|
is floating point number?

`is_custfmt`(→ bool)
|
is custom data format?

`is_numop`(→ bool)
|
is number (bin, oct, dec, hex)?

`is_suspop`(→ bool)
|
is suspicious operand?

`op_adds_xrefs`(→ bool)
|
Should processor module create xrefs from the operand? Currently 'offset', 'structure offset', 'stack' and 'enum' operands create xrefs

`set_op_type`(→ bool)
|
(internal function) change representation of operand(s).

`op_seg`(→ bool)
|
Set operand representation to be 'segment'. If applied to unexplored bytes, converts them to 16-/32-bit word data

`op_enum`(→ bool)
|
Set operand representation to be enum type If applied to unexplored bytes, converts them to 16-/32-bit word data

`get_enum_id`(→ uchar *)
|
Get enum id of 'enum' operand.

`op_based_stroff`(→ bool)
|
Set operand representation to be 'struct offset' if the operand likely points to a structure member. For example, let's there is a structure at 1000 1000 stru_1000 Elf32_Sym the operand #8 will be represented as '#Elf32_Sym.st_size' after the call of 'op_based_stroff(..., 8, 0x1000)' By the way, after the call of 'op_plain_offset(..., 0x1000)' it will be represented as '#(stru_1000.st_size - 0x1000)'

`op_stkvar`(→ bool)
|
Set operand representation to be 'stack variable'. Should be applied to an instruction within a function. Should be applied after creating a stack var using insn_t::create_stkvar().

`set_forced_operand`(→ bool)
|
Set forced operand.

`get_forced_operand`(→ str)
|
Get forced operand.

`is_forced_operand`(→ bool)
|
Is operand manually defined?

`combine_flags`(→ flags64_t)
|

`char_flag`(→ flags64_t)
|
see FF_opbits

`off_flag`(→ flags64_t)
|
see FF_opbits

`enum_flag`(→ flags64_t)
|
see FF_opbits

`stroff_flag`(→ flags64_t)
|
see FF_opbits

`stkvar_flag`(→ flags64_t)
|
see FF_opbits

`flt_flag`(→ flags64_t)
|
see FF_opbits

`custfmt_flag`(→ flags64_t)
|
see FF_opbits

`seg_flag`(→ flags64_t)
|
see FF_opbits

`num_flag`(→ flags64_t)
|
Get number of default base (bin, oct, dec, hex)

`hex_flag`(→ flags64_t)
|
Get number flag of the base, regardless of current processor - better to use num_flag()

`dec_flag`(→ flags64_t)
|
Get number flag of the base, regardless of current processor - better to use num_flag()

`oct_flag`(→ flags64_t)
|
Get number flag of the base, regardless of current processor - better to use num_flag()

`bin_flag`(→ flags64_t)
|
Get number flag of the base, regardless of current processor - better to use num_flag()

`op_chr`(→ bool)
|
set op type to char_flag()

`op_num`(→ bool)
|
set op type to num_flag()

`op_hex`(→ bool)
|
set op type to hex_flag()

`op_dec`(→ bool)
|
set op type to dec_flag()

`op_oct`(→ bool)
|
set op type to oct_flag()

`op_bin`(→ bool)
|
set op type to bin_flag()

`op_flt`(→ bool)
|
set op type to flt_flag()

`op_custfmt`(→ bool)
|
Set custom data format for operand (fid-custom data format id)

`clr_op_type`(→ bool)
|
Remove operand representation information. (set operand representation to be 'undefined')

`get_default_radix`(→ int)
|
Get default base of number for the current processor.

`get_radix`(→ int)
|
Get radix of the operand, in: flags. If the operand is not a number, returns get_default_radix()

`code_flag`(→ flags64_t)
|
FF_CODE

`byte_flag`(→ flags64_t)
|
Get a flags64_t representing a byte.

`word_flag`(→ flags64_t)
|
Get a flags64_t representing a word.

`dword_flag`(→ flags64_t)
|
Get a flags64_t representing a double word.

`qword_flag`(→ flags64_t)
|
Get a flags64_t representing a quad word.

`oword_flag`(→ flags64_t)
|
Get a flags64_t representing a octaword.

`yword_flag`(→ flags64_t)
|
Get a flags64_t representing a ymm word.

`zword_flag`(→ flags64_t)
|
Get a flags64_t representing a zmm word.

`tbyte_flag`(→ flags64_t)
|
Get a flags64_t representing a tbyte.

`strlit_flag`(→ flags64_t)
|
Get a flags64_t representing a string literal.

`stru_flag`(→ flags64_t)
|
Get a flags64_t representing a struct.

`cust_flag`(→ flags64_t)
|
Get a flags64_t representing custom type data.

`align_flag`(→ flags64_t)
|
Get a flags64_t representing an alignment directive.

`float_flag`(→ flags64_t)
|
Get a flags64_t representing a float.

`double_flag`(→ flags64_t)
|
Get a flags64_t representing a double.

`packreal_flag`(→ flags64_t)
|
Get a flags64_t representing a packed decimal real.

`is_byte`(→ bool)
|
FF_BYTE

`is_word`(→ bool)
|
FF_WORD

`is_dword`(→ bool)
|
FF_DWORD

`is_qword`(→ bool)
|
FF_QWORD

`is_oword`(→ bool)
|
FF_OWORD

`is_yword`(→ bool)
|
FF_YWORD

`is_zword`(→ bool)
|
FF_ZWORD

`is_tbyte`(→ bool)
|
FF_TBYTE

`is_float`(→ bool)
|
FF_FLOAT

`is_double`(→ bool)
|
FF_DOUBLE

`is_pack_real`(→ bool)
|
FF_PACKREAL

`is_strlit`(→ bool)
|
FF_STRLIT

`is_struct`(→ bool)
|
FF_STRUCT

`is_align`(→ bool)
|
FF_ALIGN

`is_custom`(→ bool)
|
FF_CUSTOM

`f_is_byte`(→ bool)
|
See is_byte()

`f_is_word`(→ bool)
|
See is_word()

`f_is_dword`(→ bool)
|
See is_dword()

`f_is_qword`(→ bool)
|
See is_qword()

`f_is_oword`(→ bool)
|
See is_oword()

`f_is_yword`(→ bool)
|
See is_yword()

`f_is_tbyte`(→ bool)
|
See is_tbyte()

`f_is_float`(→ bool)
|
See is_float()

`f_is_double`(→ bool)
|
See is_double()

`f_is_pack_real`(→ bool)
|
See is_pack_real()

`f_is_strlit`(→ bool)
|
See is_strlit()

`f_is_struct`(→ bool)
|
See is_struct()

`f_is_align`(→ bool)
|
See is_align()

`f_is_custom`(→ bool)
|
See is_custom()

`is_same_data_type`(→ bool)
|
Do the given flags specify the same data type?

`get_flags_by_size`(→ flags64_t)
|
Get flags from size (in bytes). Supported sizes: 1, 2, 4, 8, 16, 32. For other sizes, returns 0

`create_data`(→ bool)
|
Convert to data (byte, word, dword, etc). This function may be used to create arrays.

`calc_dflags`(→ flags64_t)
|

`create_byte`(→ bool)
|
Convert to byte.

`create_word`(→ bool)
|
Convert to word.

`create_dword`(→ bool)
|
Convert to dword.

`create_qword`(→ bool)
|
Convert to quadword.

`create_oword`(→ bool)
|
Convert to octaword/xmm word.

`create_yword`(→ bool)
|
Convert to ymm word.

`create_zword`(→ bool)
|
Convert to zmm word.

`create_tbyte`(→ bool)
|
Convert to tbyte.

`create_float`(→ bool)
|
Convert to float.

`create_double`(→ bool)
|
Convert to double.

`create_packed_real`(→ bool)
|
Convert to packed decimal real.

`create_struct`(→ bool)
|
Convert to struct.

`create_custdata`(→ bool)
|
Convert to custom data type.

`create_align`(→ bool)
|
Create an alignment item.

`calc_min_align`(→ int)
|
Calculate the minimal possible alignment exponent.

`calc_max_align`(→ int)
|
Calculate the maximal possible alignment exponent.

`calc_def_align`(→ int)
|
Calculate the default alignment exponent.

`create_16bit_data`(→ bool)
|
Convert to 16-bit quantity (take the byte size into account)

`create_32bit_data`(→ bool)
|
Convert to 32-bit quantity (take the byte size into account)

`get_max_strlit_length`(→ int)
|
Determine maximum length of string literal.

`create_strlit`(→ bool)
|
Convert to string literal and give a meaningful name. 'start' may be higher than 'end', the kernel will swap them in this case

`get_opinfo`(→ opinfo_t *)
|
Get additional information about an operand representation.

`set_opinfo`(→ bool)
|
Set additional information about an operand representation. This function is a low level one. Only the kernel should use it.

`get_data_elsize`(→ asize_t)
|
Get size of data type specified in flags 'F'.

`get_full_data_elsize`(→ asize_t)
|
Get full size of data type specified in flags 'F'. takes into account processors with wide bytes e.g. returns 2 for a byte element with 16-bit bytes

`is_varsize_item`(→ int)
|
Is the item at 'ea' variable size?

`get_possible_item_varsize`(→ asize_t)
|
Return the possible size of the item at EA of type TIF if TIF is the variable structure.

`can_define_item`(→ bool)
|
Can define item (instruction/data) of the specified 'length', starting at 'ea'?

`has_immd`(→ bool)
|
Has immediate value?

`is_func`(→ bool)
|
Is function start?

`set_immd`(→ bool)
|
Set 'has immediate operand' flag. Returns true if the FF_IMMD bit was not set and now is set

`get_custom_data_type`(→ data_type_t const *)
|
Get definition of a registered custom data type.

`get_custom_data_format`(→ data_format_t const *)
|
Get definition of a registered custom data format.

`attach_custom_data_format`(→ bool)
|
Attach the data format to the data type.

`detach_custom_data_format`(→ bool)
|
Detach the data format from the data type. Unregistering a custom data type detaches all attached data formats, no need to detach them explicitly. You still need unregister them. Unregistering a custom data format detaches it from all attached data types.

`is_attached_custom_data_format`(→ bool)
|
Is the custom data format attached to the custom data type?

`get_custom_data_types`(→ int)
|
Get list of registered custom data type ids.

`get_custom_data_formats`(→ int)
|
Get list of attached custom data formats for the specified data type.

`find_custom_data_type`(→ int)
|
Get id of a custom data type.

`find_custom_data_format`(→ int)
|
Get id of a custom data format.

`set_cmt`(→ bool)
|
Set an indented comment.

`get_cmt`(→ str)
|
Get an indented comment.

`append_cmt`(→ bool)
|
Append to an indented comment. Creates a new comment if none exists. Appends a newline character and the specified string otherwise.

`get_predef_insn_cmt`(→ str)
|
Get predefined comment.

`find_byte`(→ ida_idaapi.ea_t)
|
Find forward a byte with the specified value (only 8-bit value from the database). example: ea=4 size=3 will inspect addresses 4, 5, and 6

`find_byter`(→ ida_idaapi.ea_t)
|
Find reverse a byte with the specified value (only 8-bit value from the database). example: ea=4 size=3 will inspect addresses 6, 5, and 4

`parse_binpat_str`(→ bool)
|
Deprecated.

`bin_search`(*args)
|
Search for a set of bytes in the program

`next_inited`(→ ida_idaapi.ea_t)
|
Find the next initialized address.

`prev_inited`(→ ida_idaapi.ea_t)
|
Find the previous initialized address.

`equal_bytes`(→ bool)
|
Compare 'len' bytes of the program starting from 'ea' with 'image'.

`update_hidden_range`(→ bool)
|
Update hidden range information in the database. You cannot use this function to change the range boundaries

`add_hidden_range`(→ bool)
|
Mark a range of addresses as hidden. The range will be created in the invisible state with the default color

`get_hidden_range`(→ hidden_range_t *)
|
Get pointer to hidden range structure, in: linear address.

`getn_hidden_range`(→ hidden_range_t *)
|
Get pointer to hidden range structure, in: number of hidden range.

`get_hidden_range_qty`(→ int)
|
Get number of hidden ranges.

`get_hidden_range_num`(→ int)
|
Get number of a hidden range.

`get_prev_hidden_range`(→ hidden_range_t *)
|
Get pointer to previous hidden range.

`get_next_hidden_range`(→ hidden_range_t *)
|
Get pointer to next hidden range.

`get_first_hidden_range`(→ hidden_range_t *)
|
Get pointer to the first hidden range.

`get_last_hidden_range`(→ hidden_range_t *)
|
Get pointer to the last hidden range.

`del_hidden_range`(→ bool)
|
Delete hidden range.

`add_mapping`(→ bool)
|
IDA supports memory mapping. References to the addresses from the mapped range use data and meta-data from the mapping range.

`del_mapping`(→ None)
|
Delete memory mapping range.

`use_mapping`(→ ida_idaapi.ea_t)
|
Translate address according to current mappings.

`get_mappings_qty`(→ int)
|
Get number of mappings.

`get_mapping`(→ ea_t *, ea_t *, asize_t *)
|
Get memory mapping range by its number.

`visit_patched_bytes`(ea1, ea2, callable)
|
Enumerates patched bytes in the given range and invokes a callable

`get_bytes`(ea, size[, gmb_flags])
|
Get the specified number of bytes of the program.

`get_bytes_and_mask`(ea, size[, gmb_flags])
|
Get the specified number of bytes of the program, and a bitmask

`get_strlit_contents`(ea, len, type[, flags])
|
Get contents of string literal, as UTF-8-encoded codepoints.

`print_strlit_type`(→ PyObject *)
|
Get string type information: the string type name (possibly decorated with hotkey markers), and the tooltip.

`op_stroff`(→ bool)
|
Set operand representation to be 'struct offset'.

`get_stroff_path`(*args)
|
Get the structure offset path for operand n, at the

`register_custom_data_type`(dt)
|
Registers a custom data type.

`unregister_custom_data_type`(dtid)
|
Unregisters a custom data type.

`register_custom_data_format`(df)
|
Registers a custom data format with a given data type.

`unregister_custom_data_format`(dfid)
|
Unregisters a custom data format

`register_data_types_and_formats`(formats)
|
Registers multiple data types and formats at once.

`unregister_data_types_and_formats`(formats)
|
As opposed to register_data_types_and_formats(), this function

`find_bytes`(→ int)
|

`find_string`(→ int)
|

## Module Contents

classida_bytes.compiled_binpat_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→compiled_binpat_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→compiled_binpat_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:compiled_binpat_vec_t)→Noneextract()→compiled_binpat_t*inject(s:compiled_binpat_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:compiled_binpat_t, x:compiled_binpat_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:compiled_binpat_t)→booladd_unique(x:compiled_binpat_t)→boolappend(x:compiled_binpat_t)→Noneextend(x:compiled_binpat_vec_t)→Nonefrontbackstaticparse(ea:ida_idaapi.ea_t, text:str, radix:int=-1, strlits_encoding:int=-1)→compiled_binpat_vec_t
Convert user-specified binary string to internal representation.

The ‘in’ parameter contains space-separated tokens:

*numbers (numeric base is determined by ‘radix’)

-
if value of number fits a byte, it is considered as a byte

-
if value of number fits a word, it is considered as 2 bytes

-
if value of number fits a dword,it is considered as 4 bytes

-
“…” string constants

-
‘x’ single-character constants

-
? variable bytes

Note that string constants are surrounded with double quotes.

Here are a few examples (assuming base 16):

-
CD 21 - bytes 0xCD, 0x21

-
21CD - bytes 0xCD, 0x21 (little endian ) or 0x21, 0xCD (big-endian)

-
“Hello”, 0 - the null terminated string “Hello”

-
L”Hello” - ‘H’, 0, ‘e’, 0, ‘l’, 0, ‘l’, 0, ‘o’, 0

-
B8 ? ? ? ? 90 - byte 0xB8, 4 bytes with any value, byte 0x90

This method will throw an exception if the pattern could not be parsed
Parameters:

-
ea – linear address to convert for (the conversion depends on the address, because the number of bits in a byte depend on the segment type)

-
text – input text string

-
radix – numeric base of numbers (8,10,16). If -1 (the default), then the default radix will be used (see get_default_radix)

-
strlits_encoding – the target encoding into which the string literals present in ‘in’, should be encoded. Can be any from [1, get_encoding_qty()), or the special values PBSENC_*

Returns:
a set of patterns
ida_bytes.enable_flags(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, stt:storage_type_t)→error_t
Allocate flags for address range. This function does not change the storage type of existing ranges. Exit with an error message if not enough disk space.
Parameters:

-
start_ea – should be lower than end_ea.

-
end_ea – does not belong to the range.

-
stt – storage_type_t

Returns:
0 if ok, otherwise an error code
ida_bytes.disable_flags(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t)→error_t
Deallocate flags for address range. Exit with an error message if not enough disk space (this may occur too).
Parameters:

-
start_ea – should be lower than end_ea.

-
end_ea – does not belong to the range.

Returns:
0 if ok, otherwise return error code
ida_bytes.change_storage_type(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, stt:storage_type_t)→error_t
Change flag storage type for address range.
Parameters:

-
start_ea – should be lower than end_ea.

-
end_ea – does not belong to the range.

-
stt – storage_type_t

Returns:
error code
ida_bytes.next_addr(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get next address in the program (i.e. next address which has flags).
Returns:
BADADDR if no such address exists.
ida_bytes.prev_addr(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get previous address in the program.
Returns:
BADADDR if no such address exists.
ida_bytes.next_chunk(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get the first address of next contiguous chunk in the program.
Returns:
BADADDR if next chunk does not exist.
ida_bytes.prev_chunk(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get the last address of previous contiguous chunk in the program.
Returns:
BADADDR if previous chunk does not exist.
ida_bytes.chunk_start(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get start of the contiguous address block containing ‘ea’.
Returns:
BADADDR if ‘ea’ does not belong to the program.
ida_bytes.chunk_size(ea:ida_idaapi.ea_t)→asize_t
Get size of the contiguous address block containing ‘ea’.
Returns:
0 if ‘ea’ does not belong to the program.
ida_bytes.find_free_chunk(start:ida_idaapi.ea_t, size:asize_t, alignment:asize_t)→ida_idaapi.ea_t
Search for a hole in the addressing space of the program.
Parameters:

-
start – Address to start searching from

-
size – Size of the desired empty range

-
alignment – Alignment bitmask, must be a pow2-1. (for example, 0xF would align the returned range to 16 bytes).

Returns:
Start of the found empty range or BADADDR
ida_bytes.next_that(ea:ida_idaapi.ea_t, maxea:ida_idaapi.ea_t, testf:testf_t*)→ida_idaapi.ea_t
Find next address with a flag satisfying the function ‘testf’.
Parameters:

-
ea – start searching at this address + 1

-
maxea – not included in the search range.

-
testf – test function to find next address

Returns:
the found address or BADADDR.
ida_bytes.next_unknown(ea:ida_idaapi.ea_t, maxea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Similar to next_that(), but will find the next address that is unexplored.
ida_bytes.prev_that(ea:ida_idaapi.ea_t, minea:ida_idaapi.ea_t, testf:testf_t*)→ida_idaapi.ea_t
Find previous address with a flag satisfying the function ‘testf’.
Parameters:

-
ea – start searching from this address - 1.

-
minea – included in the search range.

-
testf – test function to find previous address

Returns:
the found address or BADADDR.
ida_bytes.prev_unknown(ea:ida_idaapi.ea_t, minea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Similar to prev_that(), but will find the previous address that is unexplored.
ida_bytes.prev_head(ea:ida_idaapi.ea_t, minea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get start of previous defined item.
Parameters:

-
ea – begin search at this address

-
minea – included in the search range

Returns:
BADADDR if none exists.
ida_bytes.next_head(ea:ida_idaapi.ea_t, maxea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get start of next defined item.
Parameters:

-
ea – begin search at this address

-
maxea – not included in the search range

Returns:
BADADDR if none exists.
ida_bytes.prev_not_tail(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get address of previous non-tail byte.
Returns:
BADADDR if none exists.
ida_bytes.next_not_tail(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get address of next non-tail byte.
Returns:
BADADDR if none exists.
ida_bytes.prev_visea(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get previous visible address.
Returns:
BADADDR if none exists.
ida_bytes.next_visea(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get next visible address.
Returns:
BADADDR if none exists.
ida_bytes.get_item_head(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get the start address of the item at ‘ea’. If there is no current item, then ‘ea’ is returned (see definition at the end of bytes.hpp source)
ida_bytes.get_item_end(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Get the end address of the item at ‘ea’. The returned address does not belong to the current item. Unexplored bytes are counted as 1 byte entities.
ida_bytes.calc_max_item_end(ea:ida_idaapi.ea_t, how:int=15)→ida_idaapi.ea_t
Calculate maximal reasonable end address of a new item. This function will limit the item with the current segment bounds.
Parameters:

-
ea – linear address

-
how – when to stop the search. A combination of Item end search flags

Returns:
end of new item. If it is not possible to create an item, it will return ‘ea’. If operation was cancelled by user, it will return ‘ea’
ida_bytes.ITEM_END_FIXUP
stop at the first fixup
ida_bytes.ITEM_END_INITED
stop when initialization changes i.e. * if is_loaded(ea): stop if uninitialized byte is encountered * if !is_loaded(ea): stop if initialized byte is encountered
ida_bytes.ITEM_END_NAME
stop at the first named location
ida_bytes.ITEM_END_XREF
stop at the first referenced location
ida_bytes.ITEM_END_CANCEL
stop when operation cancelled, it is the responsibility of the caller to show the wait dialog
ida_bytes.get_item_size(ea:ida_idaapi.ea_t)→asize_t
Get size of item (instruction/data) in bytes. Unexplored bytes have length of 1 byte. This function returns 0 only for BADADDR.
ida_bytes.is_mapped(ea:ida_idaapi.ea_t)→bool
Is the specified address ‘ea’ present in the program?
ida_bytes.get_flags_ex(ea:ida_idaapi.ea_t, how:int)→flags64_t
Get flags for the specified address, extended form.
ida_bytes.GFE_VALUE
get flags with FF_IVL & MS_VAL. It is much slower under remote debugging because the kernel needs to read the process memory.
ida_bytes.GFE_IDB_VALUE
get flags with FF_IVL & MS_VAL. but never use the debugger memory.
ida_bytes.GFE_32BIT
get only low 32 bits of flags
ida_bytes.get_flags32(ea:ida_idaapi.ea_t)→flags64_t
Get only 32 low bits of flags. This function returns the most commonly used bits of the flags. However, it does not return the operand info for the operands beyond the first two operands (0,1). If you need to deal with the operands (2..n), then use get_flags(). It is customary to assign the return value to the variable named “F32”, to distinguish is from 64-bit flags.
Returns:
0 if address is not present in the program
ida_bytes.get_flags(ea:ida_idaapi.ea_t)→flags64_t
Get flags value for address ‘ea’. The byte value is not included in the flags. This function should be used if the operand types of any operand beyond the first two operands is required. This function is more expensive to use than get_flags32()
Returns:
0 if address is not present in the program
ida_bytes.get_full_flags(ea:ida_idaapi.ea_t)→flags64_t
Get full flags value for address ‘ea’. This function returns the byte value in the flags as well. See FF_IVL and MS_VAL. This function is more expensive to use than get_flags()
Returns:
0 if address is not present in the program
ida_bytes.get_item_flag(_from:ida_idaapi.ea_t, n:int, ea:ida_idaapi.ea_t, appzero:bool)→flags64_t
Get flag of the item at ‘ea’ even if it is a tail byte of some array or structure. This function is used to get flags of structure members or array elements.
Parameters:

-
n – operand number which refers to ‘ea’ or OPND_ALL for one of the operands

-
ea – the referenced address

-
appzero – append a struct field name if the field offset is zero? meaningful only if the name refers to a structure.

Returns:
flags or 0 (if failed)
ida_bytes.get_item_refinfo(ri:refinfo_t, ea:ida_idaapi.ea_t, n:int)→bool
Get refinfo of the item at ‘ea’. This function works for a regular offset operand as well as for a tail byte of a structure variable (in this case refinfo to corresponding structure member is returned)
Parameters:

-
ri – refinfo holder

-
ea – the item address

-
n – operand number which refers to ‘ea’ or OPND_ALL for one of the operands

Returns:
success
ida_bytes.MS_VAL
Mask for byte value.
ida_bytes.FF_IVL
Byte has value ?
ida_bytes.has_value(F:flags64_t)→bool
Do flags contain byte value?
ida_bytes.del_value(ea:ida_idaapi.ea_t)→None
Delete byte value from flags. The corresponding byte becomes uninitialized.
ida_bytes.is_loaded(ea:ida_idaapi.ea_t)→bool
Does the specified address have a byte value (is initialized?)
ida_bytes.nbits(ea:ida_idaapi.ea_t)→int
Get number of bits in a byte at the given address.
Returns:
processor_t::dnbits() if the address does not belong to a segment, otherwise the result depends on the segment type
ida_bytes.bytesize(ea:ida_idaapi.ea_t)→int
Get number of bytes required to store a byte at the given address.
ida_bytes.get_byte(ea:ida_idaapi.ea_t)→uchar
Get one byte (8-bit) of the program at ‘ea’. This function works only for 8-bit byte processors.
ida_bytes.get_db_byte(ea:ida_idaapi.ea_t)→uchar
Get one byte (8-bit) of the program at ‘ea’ from the database. Works even if the debugger is active. See also get_dbg_byte() to read the process memory directly. This function works only for 8-bit byte processors.
ida_bytes.get_word(ea:ida_idaapi.ea_t)→ushort
Get one word (16-bit) of the program at ‘ea’. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8-bit byte processors.
ida_bytes.get_dword(ea:ida_idaapi.ea_t)→int
Get one dword (32-bit) of the program at ‘ea’. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8-bit byte processors.
ida_bytes.get_qword(ea:ida_idaapi.ea_t)→uint64
Get one qword (64-bit) of the program at ‘ea’. This function takes into account order of bytes specified in idainfo::is_be() This function works only for 8-bit byte processors.
ida_bytes.get_wide_byte(ea:ida_idaapi.ea_t)→uint64
Get one wide byte of the program at ‘ea’. Some processors may access more than 8-bit quantity at an address. These processors have 32-bit byte organization from the IDA’s point of view.
ida_bytes.get_wide_word(ea:ida_idaapi.ea_t)→uint64
Get one wide word (2 ‘byte’) of the program at ‘ea’. Some processors may access more than 8-bit quantity at an address. These processors have 32-bit byte organization from the IDA’s point of view. This function takes into account order of bytes specified in idainfo::is_be()
ida_bytes.get_wide_dword(ea:ida_idaapi.ea_t)→uint64
Get two wide words (4 ‘bytes’) of the program at ‘ea’. Some processors may access more than 8-bit quantity at an address. These processors have 32-bit byte organization from the IDA’s point of view. This function takes into account order of bytes specified in idainfo::is_be()
classida_bytes.octet_generator_t(_ea:ida_idaapi.ea_t)
Bases: `object`
thisownvalue:uint64ea:ida_idaapi.ea_tavail_bits:inthigh_byte_first:boolinvert_byte_order()→Noneida_bytes.get_octet(ogen:octet_generator_t)→uchar*ida_bytes.get_16bit(ea:ida_idaapi.ea_t)→int
Get 16bits of the program at ‘ea’.
Returns:
1 byte (getFullByte()) if the current processor has 16-bit byte, otherwise return get_word()
ida_bytes.get_32bit(ea:ida_idaapi.ea_t)→int
Get not more than 32bits of the program at ‘ea’.
Returns:
32 bit value, depending on processor_t::nbits:

-
if ( nbits <= 8 ) return get_dword(ea);

-
if ( nbits <= 16) return get_wide_word(ea);

-
return get_wide_byte(ea);

ida_bytes.get_64bit(ea:ida_idaapi.ea_t)→uint64
Get not more than 64bits of the program at ‘ea’.
Returns:
64 bit value, depending on processor_t::nbits:

-
if ( nbits <= 8 ) return get_qword(ea);

-
if ( nbits <= 16) return get_wide_dword(ea);

-
return get_wide_byte(ea);

ida_bytes.get_data_value(v:uval_t*, ea:ida_idaapi.ea_t, size:asize_t)→bool
Get the value at of the item at ‘ea’. This function works with entities up to sizeof(ea_t) (bytes, word, etc)
Parameters:

-
v – pointer to the result. may be nullptr

-
ea – linear address

-
size – size of data to read. If 0, then the item type at ‘ea’ will be used

Returns:
success
ida_bytes.get_original_byte(ea:ida_idaapi.ea_t)→uint64
Get original byte value (that was before patching). This function works for wide byte processors too.
ida_bytes.get_original_word(ea:ida_idaapi.ea_t)→uint64
Get original word value (that was before patching). This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()
ida_bytes.get_original_dword(ea:ida_idaapi.ea_t)→uint64
Get original dword (that was before patching) This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()
ida_bytes.get_original_qword(ea:ida_idaapi.ea_t)→uint64
Get original qword value (that was before patching) This function DOESN’T work for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()
ida_bytes.put_byte(ea:ida_idaapi.ea_t, x:uint64)→bool
Set value of one byte of the program. This function modifies the database. If the debugger is active then the debugged process memory is patched too.
Parameters:

-
ea – linear address

-
x – byte value

Returns:
true if the database has been modified
ida_bytes.put_word(ea:ida_idaapi.ea_t, x:uint64)→None
Set value of one word of the program. This function takes into account order of bytes specified in idainfo::is_be() This function works for wide byte processors too.
ida_bytes.put_dword(ea:ida_idaapi.ea_t, x:uint64)→None
Set value of one dword of the program. This function takes into account order of bytes specified in idainfo::is_be() This function works for wide byte processors too.
Parameters:

-
ea – linear address

-
x – dword value

ida_bytes.put_qword(ea:ida_idaapi.ea_t, x:uint64)→None
Set value of one qword (8 bytes) of the program. This function takes into account order of bytes specified in idainfo::is_be() This function DOESN’T works for wide byte processors.
Parameters:

-
ea – linear address

-
x – qword value

ida_bytes.patch_byte(ea:ida_idaapi.ea_t, x:uint64)→bool
Patch a byte of the program. The original value of the byte is saved and can be obtained by get_original_byte(). This function works for wide byte processors too.
Returns:
true: the database has been modified,
Returns:
false: the debugger is running and the process’ memory has value ‘x’ at address ‘ea’, or the debugger is not running, and the IDB has value ‘x’ at address ‘ea already.
ida_bytes.patch_word(ea:ida_idaapi.ea_t, x:uint64)→bool
Patch a word of the program. The original value of the word is saved and can be obtained by get_original_word(). This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()
Returns:
true: the database has been modified,
Returns:
false: the debugger is running and the process’ memory has value ‘x’ at address ‘ea’, or the debugger is not running, and the IDB has value ‘x’ at address ‘ea already.
ida_bytes.patch_dword(ea:ida_idaapi.ea_t, x:uint64)→bool
Patch a dword of the program. The original value of the dword is saved and can be obtained by get_original_dword(). This function DOESN’T work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be()
Returns:
true: the database has been modified,
Returns:
false: the debugger is running and the process’ memory has value ‘x’ at address ‘ea’, or the debugger is not running, and the IDB has value ‘x’ at address ‘ea already.
ida_bytes.patch_qword(ea:ida_idaapi.ea_t, x:uint64)→bool
Patch a qword of the program. The original value of the qword is saved and can be obtained by get_original_qword(). This function DOESN’T work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be()
Returns:
true: the database has been modified,
Returns:
false: the debugger is running and the process’ memory has value ‘x’ at address ‘ea’, or the debugger is not running, and the IDB has value ‘x’ at address ‘ea already.
ida_bytes.revert_byte(ea:ida_idaapi.ea_t)→bool
Revert patched byte
Returns:
true: byte was patched before and reverted now
ida_bytes.add_byte(ea:ida_idaapi.ea_t, value:int)→None
Add a value to one byte of the program. This function works for wide byte processors too.
Parameters:

-
ea – linear address

-
value – byte value

ida_bytes.add_word(ea:ida_idaapi.ea_t, value:uint64)→None
Add a value to one word of the program. This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()
Parameters:

-
ea – linear address

-
value – byte value

ida_bytes.add_dword(ea:ida_idaapi.ea_t, value:uint64)→None
Add a value to one dword of the program. This function works for wide byte processors too. This function takes into account order of bytes specified in idainfo::is_be()
Parameters:

-
ea – linear address

-
value – byte value

ida_bytes.add_qword(ea:ida_idaapi.ea_t, value:uint64)→None
Add a value to one qword of the program. This function does not work for wide byte processors. This function takes into account order of bytes specified in idainfo::is_be()
Parameters:

-
ea – linear address

-
value – byte value

ida_bytes.get_zero_ranges(zranges:rangeset_t, range:range_t)→bool
Return set of ranges with zero initialized bytes. The returned set includes only big zero initialized ranges (at least >1KB). Some zero initialized byte ranges may be not included. Only zero bytes that use the sparse storage method (STT_MM) are reported.
Parameters:

-
zranges – pointer to the return value. cannot be nullptr

-
range – the range of addresses to verify. can be nullptr - means all ranges

Returns:
true if the result is a non-empty set
ida_bytes.GMB_READALL
try to read all bytes; if this bit is not set, fail at first uninited byte
ida_bytes.GMB_WAITBOX
show wait box (may return -1 in this case)
ida_bytes.put_bytes(ea:ida_idaapi.ea_t, buf:voidconst*)→None
Modify the specified number of bytes of the program. This function does not save the original values of bytes. See also patch_bytes().
Parameters:

-
ea – linear address

-
buf – buffer with new values of bytes

ida_bytes.patch_bytes(ea:ida_idaapi.ea_t, buf:voidconst*)→None
Patch the specified number of bytes of the program. Original values of bytes are saved and are available with get_original…() functions. See also put_bytes().
Parameters:

-
ea – linear address

-
buf – buffer with new values of bytes

ida_bytes.MS_CLS
Mask for typing.
ida_bytes.FF_CODE
Code ?
ida_bytes.FF_DATA
Data ?
ida_bytes.FF_TAIL
Tail ?
ida_bytes.FF_UNK
Unknown ?
ida_bytes.is_code(F:flags64_t)→bool
Does flag denote start of an instruction?
ida_bytes.f_is_code(F:flags64_t, arg2:void*)→bool
Does flag denote start of an instruction?
ida_bytes.is_data(F:flags64_t)→bool
Does flag denote start of data?
ida_bytes.f_is_data(F:flags64_t, arg2:void*)→bool
Does flag denote start of data?
ida_bytes.is_tail(F:flags64_t)→bool
Does flag denote tail byte?
ida_bytes.f_is_tail(F:flags64_t, arg2:void*)→bool
Does flag denote tail byte?
ida_bytes.is_not_tail(F:flags64_t)→bool
Does flag denote tail byte?
ida_bytes.f_is_not_tail(F:flags64_t, arg2:void*)→bool
Does flag denote tail byte?
ida_bytes.is_unknown(F:flags64_t)→bool
Does flag denote unexplored byte?
ida_bytes.is_head(F:flags64_t)→bool
Does flag denote start of instruction OR data?
ida_bytes.f_is_head(F:flags64_t, arg2:void*)→bool
Does flag denote start of instruction OR data?
ida_bytes.del_items(ea:ida_idaapi.ea_t, flags:int=0, nbytes:asize_t=1, may_destroy:may_destroy_cb_t*=None)→bool
Convert item (instruction/data) to unexplored bytes. The whole item (including the head and tail bytes) will be destroyed. It is allowed to pass any address in the item to this function
Parameters:

-
ea – any address within the first item to delete

-
flags – combination of Unexplored byte conversion flags

-
nbytes – number of bytes in the range to be undefined

-
may_destroy – optional routine invoked before deleting a head item. If callback returns false then item is not to be deleted and operation fails

Returns:
true on successful operation, otherwise false
ida_bytes.DELIT_SIMPLE
simply undefine the specified item(s)
ida_bytes.DELIT_EXPAND
propagate undefined items; for example if removing an instruction removes all references to the next instruction, then plan to convert to unexplored the next instruction too.
ida_bytes.DELIT_DELNAMES
delete any names at the specified address range (except for the starting address). this bit is valid if nbytes > 1
ida_bytes.DELIT_NOTRUNC
don’t truncate the current function even if AF_TRFUNC is set
ida_bytes.DELIT_NOUNAME
reject to delete if a user name is in address range (except for the starting address). this bit is valid if nbytes > 1
ida_bytes.DELIT_NOCMT
reject to delete if a comment is in address range (except for the starting address). this bit is valid if nbytes > 1
ida_bytes.DELIT_KEEPFUNC
do not undefine the function start. Just delete xrefs, ops e.t.c.
ida_bytes.is_manual_insn(ea:ida_idaapi.ea_t)→bool
Is the instruction overridden?
Parameters:
ea – linear address of the instruction or data item
ida_bytes.get_manual_insn(ea:ida_idaapi.ea_t)→str
Retrieve the user-specified string for the manual instruction.
Parameters:
ea – linear address of the instruction or data item
Returns:
size of manual instruction or -1
ida_bytes.set_manual_insn(ea:ida_idaapi.ea_t, manual_insn:str)→None
Set manual instruction string.
Parameters:

-
ea – linear address of the instruction or data item

-
manual_insn – “” - delete manual string. nullptr - do nothing

ida_bytes.MS_COMM
Mask of common bits.
ida_bytes.FF_COMM
Has comment?
ida_bytes.FF_REF
has references
ida_bytes.FF_LINE
Has next or prev lines?
ida_bytes.FF_NAME
Has name?
ida_bytes.FF_LABL
Has dummy name?
ida_bytes.FF_FLOW
Exec flow from prev instruction.
ida_bytes.FF_SIGN
Inverted sign of operands.
ida_bytes.FF_BNOT
Bitwise negation of operands.
ida_bytes.FF_UNUSED
unused bit (was used for variable bytes)
ida_bytes.is_flow(F:flags64_t)→bool
Does the previous instruction exist and pass execution flow to the current byte?
ida_bytes.has_extra_cmts(F:flags64_t)→bool
Does the current byte have additional anterior or posterior lines?
ida_bytes.f_has_extra_cmts(f:flags64_t, arg2:void*)→boolida_bytes.has_cmt(F:flags64_t)→bool
Does the current byte have an indented comment?
ida_bytes.f_has_cmt(f:flags64_t, arg2:void*)→boolida_bytes.has_xref(F:flags64_t)→bool
Does the current byte have cross-references to it?
ida_bytes.f_has_xref(f:flags64_t, arg2:void*)→bool
Does the current byte have cross-references to it?
ida_bytes.has_name(F:flags64_t)→bool
Does the current byte have non-trivial (non-dummy) name?
ida_bytes.f_has_name(f:flags64_t, arg2:void*)→bool
Does the current byte have non-trivial (non-dummy) name?
ida_bytes.FF_ANYNAME
Has name or dummy name?
ida_bytes.has_dummy_name(F:flags64_t)→bool
Does the current byte have dummy (auto-generated, with special prefix) name?
ida_bytes.f_has_dummy_name(f:flags64_t, arg2:void*)→bool
Does the current byte have dummy (auto-generated, with special prefix) name?
ida_bytes.has_auto_name(F:flags64_t)→bool
Does the current byte have auto-generated (no special prefix) name?
ida_bytes.has_any_name(F:flags64_t)→bool
Does the current byte have any name?
ida_bytes.has_user_name(F:flags64_t)→bool
Does the current byte have user-specified name?
ida_bytes.f_has_user_name(F:flags64_t, arg2:void*)→bool
Does the current byte have user-specified name?
ida_bytes.is_invsign(ea:ida_idaapi.ea_t, F:flags64_t, n:int)→bool
Should the sign of n-th operand be inverted during output? allowed values of n: 0-first operand, 1-other operands
ida_bytes.toggle_sign(ea:ida_idaapi.ea_t, n:int)→bool
Toggle sign of n-th operand. allowed values of n: 0-first operand, 1-other operands
ida_bytes.is_bnot(ea:ida_idaapi.ea_t, F:flags64_t, n:int)→bool
Should we negate the operand? asm_t::a_bnot should be defined in the idp module in order to work with this function
ida_bytes.toggle_bnot(ea:ida_idaapi.ea_t, n:int)→bool
Toggle binary negation of operand. also see is_bnot()
ida_bytes.is_lzero(ea:ida_idaapi.ea_t, n:int)→bool
Display leading zeros? Display leading zeros in operands. The global switch for the leading zeros is in idainfo::s_genflags Note: the leading zeros does not work if for the target assembler octal numbers start with 0.
Parameters:

-
ea – the item (insn/data) address

-
n – the operand number (0-first operand, 1-other operands)

Returns:
success
ida_bytes.set_lzero(ea:ida_idaapi.ea_t, n:int)→bool
Set toggle lzero bit. This function changes the display of leading zeros for the specified operand. If the default is not to display leading zeros, this function will display them and vice versa.
Parameters:

-
ea – the item (insn/data) address

-
n – the operand number (0-first operand, 1-other operands)

Returns:
success
ida_bytes.clr_lzero(ea:ida_idaapi.ea_t, n:int)→bool
Clear toggle lzero bit. This function reset the display of leading zeros for the specified operand to the default. If the default is not to display leading zeros, leading zeros will not be displayed, as vice versa.
Parameters:

-
ea – the item (insn/data) address

-
n – the operand number (0-first operand, 1-other operands)

Returns:
success
ida_bytes.toggle_lzero(ea:ida_idaapi.ea_t, n:int)→bool
Toggle lzero bit.
Parameters:

-
ea – the item (insn/data) address

-
n – the operand number (0-first operand, 1-other operands)

Returns:
success
ida_bytes.leading_zero_important(ea:ida_idaapi.ea_t, n:int)→bool
Check if leading zeros are important.
ida_bytes.MS_N_TYPE
Mask for nth arg (a 64-bit constant)
ida_bytes.FF_N_VOID
Void (unknown)?
ida_bytes.FF_N_NUMH
Hexadecimal number?
ida_bytes.FF_N_NUMD
Decimal number?
ida_bytes.FF_N_CHAR
Char (‘x’)?
ida_bytes.FF_N_SEG
Segment?
ida_bytes.FF_N_OFF
Offset?
ida_bytes.FF_N_NUMB
Binary number?
ida_bytes.FF_N_NUMO
Octal number?
ida_bytes.FF_N_ENUM
Enumeration?
ida_bytes.FF_N_FOP
Forced operand?
ida_bytes.FF_N_STRO
Struct offset?
ida_bytes.FF_N_STK
Stack variable?
ida_bytes.FF_N_FLT
Floating point number?
ida_bytes.FF_N_CUST
Custom representation?
ida_bytes.get_operand_type_shift(n:int)→int
Get the shift in flags64_t for the nibble representing operand n’s type Note: n must be < UA_MAXOP, and is not checked
Parameters:
n – the operand number
Returns:
the shift to the nibble
ida_bytes.get_operand_flag(typebits:uint8, n:int)→flags64_t
Place operand n’s type flag in the right nibble of a 64-bit flags set.
Parameters:

-
typebits – the type bits (one of FF_N_)

-
n – the operand number

Returns:
the shift to the nibble
ida_bytes.is_flag_for_operand(F:flags64_t, typebits:uint8, n:int)→bool
Check that the 64-bit flags set has the expected type for operand n.
Parameters:

-
F – the flags

-
typebits – the type bits (one of FF_N_)

-
n – the operand number

Returns:
success
ida_bytes.is_defarg0(F:flags64_t)→bool
Is the first operand defined? Initially operand has no defined representation.
ida_bytes.is_defarg1(F:flags64_t)→bool
Is the second operand defined? Initially operand has no defined representation.
ida_bytes.is_off0(F:flags64_t)→bool
Is the first operand offset? (example: push offset xxx)
ida_bytes.is_off1(F:flags64_t)→bool
Is the second operand offset? (example: mov ax, offset xxx)
ida_bytes.is_char0(F:flags64_t)→bool
Is the first operand character constant? (example: push ‘a’)
ida_bytes.is_char1(F:flags64_t)→bool
Is the second operand character constant? (example: mov al, ‘a’)
ida_bytes.is_seg0(F:flags64_t)→bool
Is the first operand segment selector? (example: push seg seg001)
ida_bytes.is_seg1(F:flags64_t)→bool
Is the second operand segment selector? (example: mov dx, seg dseg)
ida_bytes.is_enum0(F:flags64_t)→bool
Is the first operand a symbolic constant (enum member)?
ida_bytes.is_enum1(F:flags64_t)→bool
Is the second operand a symbolic constant (enum member)?
ida_bytes.is_stroff0(F:flags64_t)→bool
Is the first operand an offset within a struct?
ida_bytes.is_stroff1(F:flags64_t)→bool
Is the second operand an offset within a struct?
ida_bytes.is_stkvar0(F:flags64_t)→bool
Is the first operand a stack variable?
ida_bytes.is_stkvar1(F:flags64_t)→bool
Is the second operand a stack variable?
ida_bytes.is_float0(F:flags64_t)→bool
Is the first operand a floating point number?
ida_bytes.is_float1(F:flags64_t)→bool
Is the second operand a floating point number?
ida_bytes.is_custfmt0(F:flags64_t)→bool
Does the first operand use a custom data representation?
ida_bytes.is_custfmt1(F:flags64_t)→bool
Does the second operand use a custom data representation?
ida_bytes.is_numop0(F:flags64_t)→bool
Is the first operand a number (i.e. binary, octal, decimal or hex?)
ida_bytes.is_numop1(F:flags64_t)→bool
Is the second operand a number (i.e. binary, octal, decimal or hex?)
ida_bytes.get_optype_flags0(F:flags64_t)→flags64_t
Get flags for first operand.
ida_bytes.get_optype_flags1(F:flags64_t)→flags64_t
Get flags for second operand.
ida_bytes.OPND_OUTER
outer offset base (combined with operand number). used only in set, get, del_offset() functions
ida_bytes.OPND_MASK
mask for operand number
ida_bytes.OPND_ALL
all operands
ida_bytes.is_defarg(F:flags64_t, n:int)→bool
is defined?
ida_bytes.is_off(F:flags64_t, n:int)→bool
is offset?
ida_bytes.is_char(F:flags64_t, n:int)→bool
is character constant?
ida_bytes.is_seg(F:flags64_t, n:int)→bool
is segment?
ida_bytes.is_enum(F:flags64_t, n:int)→bool
is enum?
ida_bytes.is_manual(F:flags64_t, n:int)→bool
is forced operand? (use is_forced_operand())
ida_bytes.is_stroff(F:flags64_t, n:int)→bool
is struct offset?
ida_bytes.is_stkvar(F:flags64_t, n:int)→bool
is stack variable?
ida_bytes.is_fltnum(F:flags64_t, n:int)→bool
is floating point number?
ida_bytes.is_custfmt(F:flags64_t, n:int)→bool
is custom data format?
ida_bytes.is_numop(F:flags64_t, n:int)→bool
is number (bin, oct, dec, hex)?
ida_bytes.is_suspop(ea:ida_idaapi.ea_t, F:flags64_t, n:int)→bool
is suspicious operand?
ida_bytes.op_adds_xrefs(F:flags64_t, n:int)→bool
Should processor module create xrefs from the operand? Currently ‘offset’, ‘structure offset’, ‘stack’ and ‘enum’ operands create xrefs
ida_bytes.set_op_type(ea:ida_idaapi.ea_t, type:flags64_t, n:int)→bool
(internal function) change representation of operand(s).
Parameters:

-
ea – linear address

-
type – new flag value (should be obtained from char_flag(), num_flag() and similar functions)

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all operands

Returns:
1: ok
Returns:
0: failed (applied to a tail byte)
ida_bytes.op_seg(ea:ida_idaapi.ea_t, n:int)→bool
Set operand representation to be ‘segment’. If applied to unexplored bytes, converts them to 16-/32-bit word data
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all operands

Returns:
success
ida_bytes.op_enum(ea:ida_idaapi.ea_t, n:int, id:tid_t, serial:uchar=0)→bool
Set operand representation to be enum type If applied to unexplored bytes, converts them to 16-/32-bit word data
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all operands

-
id – id of enum

-
serial – the serial number of the constant in the enumeration, usually 0. the serial numbers are used if the enumeration contains several constants with the same value

Returns:
success
ida_bytes.get_enum_id(ea:ida_idaapi.ea_t, n:int)→uchar*
Get enum id of ‘enum’ operand.
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL one of the operands

Returns:
id of enum or BADNODE
ida_bytes.op_based_stroff(insn:insn_tconst&, n:int, opval:adiff_t, base:ida_idaapi.ea_t)→bool
Set operand representation to be ‘struct offset’ if the operand likely points to a structure member. For example, let’s there is a structure at 1000 1000 stru_1000 Elf32_Sym the operand #8 will be represented as ‘#Elf32_Sym.st_size’ after the call of ‘op_based_stroff(…, 8, 0x1000)’ By the way, after the call of ‘op_plain_offset(…, 0x1000)’ it will be represented as ‘#(stru_1000.st_size - 0x1000)’
Parameters:

-
insn – the instruction

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all operands

-
opval – operand value (usually op_t::value or op_t::addr)

-
base – base reference

Returns:
success
ida_bytes.op_stkvar(ea:ida_idaapi.ea_t, n:int)→bool
Set operand representation to be ‘stack variable’. Should be applied to an instruction within a function. Should be applied after creating a stack var using insn_t::create_stkvar().
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all operands

Returns:
success
ida_bytes.set_forced_operand(ea:ida_idaapi.ea_t, n:int, op:str)→bool
Set forced operand.
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number

-
op – text of operand

-
nullptr: do nothing (return 0)

-
“” : delete forced operand

Returns:
success
ida_bytes.get_forced_operand(ea:ida_idaapi.ea_t, n:int)→str
Get forced operand.
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number

Returns:
size of the forced operand or -1
ida_bytes.is_forced_operand(ea:ida_idaapi.ea_t, n:int)→bool
Is operand manually defined?
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number

ida_bytes.combine_flags(F:flags64_t)→flags64_tida_bytes.char_flag()→flags64_t
see FF_opbits
ida_bytes.off_flag()→flags64_t
see FF_opbits
ida_bytes.enum_flag()→flags64_t
see FF_opbits
ida_bytes.stroff_flag()→flags64_t
see FF_opbits
ida_bytes.stkvar_flag()→flags64_t
see FF_opbits
ida_bytes.flt_flag()→flags64_t
see FF_opbits
ida_bytes.custfmt_flag()→flags64_t
see FF_opbits
ida_bytes.seg_flag()→flags64_t
see FF_opbits
ida_bytes.num_flag()→flags64_t
Get number of default base (bin, oct, dec, hex)
ida_bytes.hex_flag()→flags64_t
Get number flag of the base, regardless of current processor - better to use num_flag()
ida_bytes.dec_flag()→flags64_t
Get number flag of the base, regardless of current processor - better to use num_flag()
ida_bytes.oct_flag()→flags64_t
Get number flag of the base, regardless of current processor - better to use num_flag()
ida_bytes.bin_flag()→flags64_t
Get number flag of the base, regardless of current processor - better to use num_flag()
ida_bytes.op_chr(ea:ida_idaapi.ea_t, n:int)→bool
set op type to char_flag()
ida_bytes.op_num(ea:ida_idaapi.ea_t, n:int)→bool
set op type to num_flag()
ida_bytes.op_hex(ea:ida_idaapi.ea_t, n:int)→bool
set op type to hex_flag()
ida_bytes.op_dec(ea:ida_idaapi.ea_t, n:int)→bool
set op type to dec_flag()
ida_bytes.op_oct(ea:ida_idaapi.ea_t, n:int)→bool
set op type to oct_flag()
ida_bytes.op_bin(ea:ida_idaapi.ea_t, n:int)→bool
set op type to bin_flag()
ida_bytes.op_flt(ea:ida_idaapi.ea_t, n:int)→bool
set op type to flt_flag()
ida_bytes.op_custfmt(ea:ida_idaapi.ea_t, n:int, fid:int)→bool
Set custom data format for operand (fid-custom data format id)
ida_bytes.clr_op_type(ea:ida_idaapi.ea_t, n:int)→bool
Remove operand representation information. (set operand representation to be ‘undefined’)
Parameters:

-
ea – linear address

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all operands

Returns:
success
ida_bytes.get_default_radix()→int
Get default base of number for the current processor.
Returns:
2, 8, 10, 16
ida_bytes.get_radix(F:flags64_t, n:int)→int
Get radix of the operand, in: flags. If the operand is not a number, returns get_default_radix()
Parameters:

-
F – flags

-
n – number of operand (0, 1, -1)

Returns:
2, 8, 10, 16
ida_bytes.DT_TYPE
Mask for DATA typing.
ida_bytes.FF_BYTE
byte
ida_bytes.FF_WORD
word
ida_bytes.FF_DWORD
double word
ida_bytes.FF_QWORD
quadro word
ida_bytes.FF_TBYTE
tbyte
ida_bytes.FF_STRLIT
string literal
ida_bytes.FF_STRUCT
struct variable
ida_bytes.FF_OWORD
octaword/xmm word (16 bytes/128 bits)
ida_bytes.FF_FLOAT
float
ida_bytes.FF_DOUBLE
double
ida_bytes.FF_PACKREAL
packed decimal real
ida_bytes.FF_ALIGN
alignment directive
ida_bytes.FF_CUSTOM
custom data type
ida_bytes.FF_YWORD
ymm word (32 bytes/256 bits)
ida_bytes.FF_ZWORD
zmm word (64 bytes/512 bits)
ida_bytes.code_flag()→flags64_t
FF_CODE
ida_bytes.byte_flag()→flags64_t
Get a flags64_t representing a byte.
ida_bytes.word_flag()→flags64_t
Get a flags64_t representing a word.
ida_bytes.dword_flag()→flags64_t
Get a flags64_t representing a double word.
ida_bytes.qword_flag()→flags64_t
Get a flags64_t representing a quad word.
ida_bytes.oword_flag()→flags64_t
Get a flags64_t representing a octaword.
ida_bytes.yword_flag()→flags64_t
Get a flags64_t representing a ymm word.
ida_bytes.zword_flag()→flags64_t
Get a flags64_t representing a zmm word.
ida_bytes.tbyte_flag()→flags64_t
Get a flags64_t representing a tbyte.
ida_bytes.strlit_flag()→flags64_t
Get a flags64_t representing a string literal.
ida_bytes.stru_flag()→flags64_t
Get a flags64_t representing a struct.
ida_bytes.cust_flag()→flags64_t
Get a flags64_t representing custom type data.
ida_bytes.align_flag()→flags64_t
Get a flags64_t representing an alignment directive.
ida_bytes.float_flag()→flags64_t
Get a flags64_t representing a float.
ida_bytes.double_flag()→flags64_t
Get a flags64_t representing a double.
ida_bytes.packreal_flag()→flags64_t
Get a flags64_t representing a packed decimal real.
ida_bytes.is_byte(F:flags64_t)→bool
FF_BYTE
ida_bytes.is_word(F:flags64_t)→bool
FF_WORD
ida_bytes.is_dword(F:flags64_t)→bool
FF_DWORD
ida_bytes.is_qword(F:flags64_t)→bool
FF_QWORD
ida_bytes.is_oword(F:flags64_t)→bool
FF_OWORD
ida_bytes.is_yword(F:flags64_t)→bool
FF_YWORD
ida_bytes.is_zword(F:flags64_t)→bool
FF_ZWORD
ida_bytes.is_tbyte(F:flags64_t)→bool
FF_TBYTE
ida_bytes.is_float(F:flags64_t)→bool
FF_FLOAT
ida_bytes.is_double(F:flags64_t)→bool
FF_DOUBLE
ida_bytes.is_pack_real(F:flags64_t)→bool
FF_PACKREAL
ida_bytes.is_strlit(F:flags64_t)→bool
FF_STRLIT
ida_bytes.is_struct(F:flags64_t)→bool
FF_STRUCT
ida_bytes.is_align(F:flags64_t)→bool
FF_ALIGN
ida_bytes.is_custom(F:flags64_t)→bool
FF_CUSTOM
ida_bytes.f_is_byte(F:flags64_t, arg2:void*)→bool
See is_byte()
ida_bytes.f_is_word(F:flags64_t, arg2:void*)→bool
See is_word()
ida_bytes.f_is_dword(F:flags64_t, arg2:void*)→bool
See is_dword()
ida_bytes.f_is_qword(F:flags64_t, arg2:void*)→bool
See is_qword()
ida_bytes.f_is_oword(F:flags64_t, arg2:void*)→bool
See is_oword()
ida_bytes.f_is_yword(F:flags64_t, arg2:void*)→bool
See is_yword()
ida_bytes.f_is_tbyte(F:flags64_t, arg2:void*)→bool
See is_tbyte()
ida_bytes.f_is_float(F:flags64_t, arg2:void*)→bool
See is_float()
ida_bytes.f_is_double(F:flags64_t, arg2:void*)→bool
See is_double()
ida_bytes.f_is_pack_real(F:flags64_t, arg2:void*)→bool
See is_pack_real()
ida_bytes.f_is_strlit(F:flags64_t, arg2:void*)→bool
See is_strlit()
ida_bytes.f_is_struct(F:flags64_t, arg2:void*)→bool
See is_struct()
ida_bytes.f_is_align(F:flags64_t, arg2:void*)→bool
See is_align()
ida_bytes.f_is_custom(F:flags64_t, arg2:void*)→bool
See is_custom()
ida_bytes.is_same_data_type(F1:flags64_t, F2:flags64_t)→bool
Do the given flags specify the same data type?
ida_bytes.get_flags_by_size(size:int)→flags64_t
Get flags from size (in bytes). Supported sizes: 1, 2, 4, 8, 16, 32. For other sizes, returns 0
ida_bytes.create_data(ea:ida_idaapi.ea_t, dataflag:flags64_t, size:asize_t, tid:tid_t)→bool
Convert to data (byte, word, dword, etc). This function may be used to create arrays.
Parameters:

-
ea – linear address

-
dataflag – type of data. Value of function byte_flag(), word_flag(), etc.

-
size – size of array in bytes. should be divisible by the size of one item of the specified type. for variable sized items it can be specified as 0, and the kernel will try to calculate the size.

-
tid – type id. If the specified type is a structure, then tid is structure id. Otherwise should be BADNODE.

Returns:
success
ida_bytes.calc_dflags(f:flags64_t, force:bool)→flags64_tida_bytes.create_byte(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to byte.
ida_bytes.create_word(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to word.
ida_bytes.create_dword(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to dword.
ida_bytes.create_qword(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to quadword.
ida_bytes.create_oword(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to octaword/xmm word.
ida_bytes.create_yword(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to ymm word.
ida_bytes.create_zword(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to zmm word.
ida_bytes.create_tbyte(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to tbyte.
ida_bytes.create_float(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to float.
ida_bytes.create_double(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to double.
ida_bytes.create_packed_real(ea:ida_idaapi.ea_t, length:asize_t, force:bool=False)→bool
Convert to packed decimal real.
ida_bytes.create_struct(ea:ida_idaapi.ea_t, length:asize_t, tid:tid_t, force:bool=False)→bool
Convert to struct.
ida_bytes.create_custdata(ea:ida_idaapi.ea_t, length:asize_t, dtid:int, fid:int, force:bool=False)→bool
Convert to custom data type.
ida_bytes.create_align(ea:ida_idaapi.ea_t, length:asize_t, alignment:int)→bool
Create an alignment item.
Parameters:

-
ea – linear address

-
length – size of the item in bytes. 0 means to infer from ALIGNMENT

-
alignment – alignment exponent. Example: 3 means align to 8 bytes. 0 means to infer from LENGTH It is forbidden to specify both LENGTH and ALIGNMENT as 0.

Returns:
success
ida_bytes.calc_min_align(length:asize_t)→int
Calculate the minimal possible alignment exponent.
Parameters:
length – size of the item in bytes.
Returns:
a value in the 1..32 range
ida_bytes.calc_max_align(endea:ida_idaapi.ea_t)→int
Calculate the maximal possible alignment exponent.
Parameters:
endea – end address of the alignment item.
Returns:
a value in the 0..32 range
ida_bytes.calc_def_align(ea:ida_idaapi.ea_t, mina:int, maxa:int)→int
Calculate the default alignment exponent.
Parameters:

-
ea – linear address

-
mina – minimal possible alignment exponent.

-
maxa – minimal possible alignment exponent.

ida_bytes.create_16bit_data(ea:ida_idaapi.ea_t, length:asize_t)→bool
Convert to 16-bit quantity (take the byte size into account)
ida_bytes.create_32bit_data(ea:ida_idaapi.ea_t, length:asize_t)→bool
Convert to 32-bit quantity (take the byte size into account)
ida_bytes.ALOPT_IGNHEADS
don’t stop if another data item is encountered. only the byte values will be used to determine the string length. if not set, a defined data item or instruction will truncate the string
ida_bytes.ALOPT_IGNPRINT
if set, don’t stop at non-printable codepoints, but only at the terminating character (or not unicode-mapped character (e.g., 0x8f in CP1252))
ida_bytes.ALOPT_IGNCLT
if set, don’t stop at codepoints that are not part of the current ‘culture’; accept all those that are graphical (this is typically used used by user-initiated actions creating string literals.)
ida_bytes.ALOPT_MAX4K
if string length is more than 4K, return the accumulated length
ida_bytes.ALOPT_ONLYTERM
only the termination characters can be at the string end. Without this option illegal characters also terminate the string.
ida_bytes.ALOPT_APPEND
if an existing strlit is encountered, then append it to the string.
ida_bytes.get_max_strlit_length(ea:ida_idaapi.ea_t, strtype:int, options:int=0)→int
Determine maximum length of string literal. If the string literal has a length prefix (e.g., STRTYPE_LEN2 has a two-byte length prefix), the length of that prefix (i.e., 2) will be part of the returned value.
Parameters:

-
ea – starting address

-
strtype – string type. one of String type codes

-
options – combination of string literal length options

Returns:
length of the string in octets (octet == 8 bits)
ida_bytes.STRCONV_ESCAPE
convert non-printable characters to C escapes ( , xNN, uNNNN)
ida_bytes.STRCONV_REPLCHAR
convert non-printable characters to the Unicode replacement character (U+FFFD)
ida_bytes.STRCONV_INCLLEN
for Pascal-style strings, include the prefixing length byte(s) as C-escaped sequence
ida_bytes.create_strlit(start:ida_idaapi.ea_t, len:int, strtype:int)→bool
Convert to string literal and give a meaningful name. ‘start’ may be higher than ‘end’, the kernel will swap them in this case
Parameters:

-
start – starting address

-
len – length of the string in bytes. if 0, then get_max_strlit_length() will be used to determine the length

-
strtype – string type. one of String type codes

Returns:
success
ida_bytes.PSTF_TNORM
use normal name
ida_bytes.PSTF_TBRIEF
use brief name (e.g., in the ‘Strings’ window)
ida_bytes.PSTF_TINLIN
use ‘inline’ name (e.g., in the structures comments)
ida_bytes.PSTF_TMASK
type mask
ida_bytes.PSTF_HOTKEY
have hotkey markers part of the name
ida_bytes.PSTF_ENC
if encoding is specified, append it
ida_bytes.PSTF_ONLY_ENC
generate only the encoding name
ida_bytes.PSTF_ATTRIB
generate for type attribute usage
ida_bytes.get_opinfo(buf:opinfo_t, ea:ida_idaapi.ea_t, n:int, flags:flags64_t)→opinfo_t*
Get additional information about an operand representation.
Parameters:

-
buf – buffer to receive the result. may not be nullptr

-
ea – linear address of item

-
n – number of operand, 0 or 1

-
flags – flags of the item

Returns:
nullptr if no additional representation information
ida_bytes.set_opinfo(ea:ida_idaapi.ea_t, n:int, flag:flags64_t, ti:opinfo_t, suppress_events:bool=False)→bool
Set additional information about an operand representation. This function is a low level one. Only the kernel should use it.
Parameters:

-
ea – linear address of the item

-
n – number of operand, 0 or 1 (see the note below)

-
flag – flags of the item

-
ti – additional representation information

-
suppress_events – do not generate changing_op_type and op_type_changed events

Returns:
success
ida_bytes.get_data_elsize(ea:ida_idaapi.ea_t, F:flags64_t, ti:opinfo_t=None)→asize_t
Get size of data type specified in flags ‘F’.
Parameters:

-
ea – linear address of the item

-
F – flags

-
ti – additional information about the data type. For example, if the current item is a structure instance, then ti->tid is structure id. Otherwise is ignored (may be nullptr). If specified as nullptr, will be automatically retrieved from the database

Returns:

-
byte : 1

-
word : 2

-
etc…

ida_bytes.get_full_data_elsize(ea:ida_idaapi.ea_t, F:flags64_t, ti:opinfo_t=None)→asize_t
Get full size of data type specified in flags ‘F’. takes into account processors with wide bytes e.g. returns 2 for a byte element with 16-bit bytes
ida_bytes.is_varsize_item(ea:ida_idaapi.ea_t, F:flags64_t, ti:opinfo_t=None, itemsize:asize_t*=None)→int
Is the item at ‘ea’ variable size?
Parameters:

-
ea – linear address of the item

-
F – flags

-
ti – additional information about the data type. For example, if the current item is a structure instance, then ti->tid is structure id. Otherwise is ignored (may be nullptr). If specified as nullptr, will be automatically retrieved from the database

-
itemsize – if not nullptr and the item is varsize, itemsize will contain the calculated item size (for struct types, the minimal size is returned)

Returns:
1: varsize item
Returns:
0: fixed item
Returns:
-1: error (bad data definition)
ida_bytes.get_possible_item_varsize(ea:ida_idaapi.ea_t, tif:tinfo_t)→asize_t
Return the possible size of the item at EA of type TIF if TIF is the variable structure.
Parameters:

-
ea – the linear address of the item

-
tif – the item type

Returns:
the possible size
Returns:
asize_t(-1): TIF is not a variable structure
ida_bytes.can_define_item(ea:ida_idaapi.ea_t, length:asize_t, flags:flags64_t)→bool
Can define item (instruction/data) of the specified ‘length’, starting at ‘ea’? * a new item would cross segment boundaries * a new item would overlap with existing items (except items specified by ‘flags’)
Parameters:

-
ea – start of the range for the new item

-
length – length of the new item in bytes

-
flags – if not 0, then the kernel will ignore the data types specified by the flags and destroy them. For example:
1000 dw 5 1002 db 5 ; undef 1003 db 5 ; undef 1004 dw 5 1006 dd 5

can_define_item(1000, 6, 0) - false because of dw at 1004

can_define_item(1000, 6, word_flag()) - true, word at 1004 is destroyed

Returns:
1-yes, 0-no
ida_bytes.MS_CODE
Mask for code bits.
ida_bytes.FF_FUNC
function start?
ida_bytes.FF_IMMD
Has Immediate value ?
ida_bytes.FF_JUMP
Has jump table or switch_info?
ida_bytes.has_immd(F:flags64_t)→bool
Has immediate value?
ida_bytes.is_func(F:flags64_t)→bool
Is function start?
ida_bytes.set_immd(ea:ida_idaapi.ea_t)→bool
Set ‘has immediate operand’ flag. Returns true if the FF_IMMD bit was not set and now is set
classida_bytes.data_type_t(_self:PyObject*, name:str, value_size:asize_t=0, menu_name:str=None, hotkey:str=None, asm_keyword:str=None, props:int=0)
Bases: `object`

Information about a data type
thisownprops:int
properties
name:str
name of the data type. must be unique
menu_name:str
Visible data type name to use in menus if nullptr, no menu item will be created
hotkey:str
Hotkey for the corresponding menu item if nullptr, no hotkey will be associated with the menu item
asm_keyword:str
keyword to use for this type in the assembly if nullptr, the data type cannot be used in the listing it can still be used in cpuregs window
value_size:asize_t
size of the value in bytes
is_present_in_menus()→bool
Should this type be shown in UI menus
Returns:
success
idida_bytes.DTP_NODUP
do not use dup construct
classida_bytes.data_format_t(_self:PyObject*, name:str, value_size:asize_t=0, menu_name:str=None, props:int=0, hotkey:str=None, text_width:int=0)
Bases: `object`

Information about a data format
thisownprops:int
properties (currently 0)
name:str
Format name, must be unique.
menu_name:str
Visible format name to use in menus if nullptr, no menu item will be created
hotkey:str
Hotkey for the corresponding menu item if nullptr, no hotkey will be associated with the menu item
value_size:asize_t
size of the value in bytes 0 means any size is ok data formats that are registered for standard types (dtid 0) may be called with any value_size (instruction operands only)
text_width:int
Usual width of the text representation This value is used to calculate the width of the control to display values of this type
is_present_in_menus()→bool
Should this format be shown in UI menus
Returns:
success
idida_bytes.get_custom_data_type(dtid:int)→data_type_tconst*
Get definition of a registered custom data type.
Parameters:
dtid – data type id
Returns:
data type definition or nullptr
ida_bytes.get_custom_data_format(dfid:int)→data_format_tconst*
Get definition of a registered custom data format.
Parameters:
dfid – data format id
Returns:
data format definition or nullptr
ida_bytes.attach_custom_data_format(dtid:int, dfid:int)→bool
Attach the data format to the data type.
Parameters:

-
dtid – data type id that can use the data format. 0 means all standard data types. Such data formats can be applied to any data item or instruction operands. For instruction operands, the data_format_t::value_size check is not performed by the kernel.

-
dfid – data format id

Returns:
true: ok
Returns:
false: no such dtid, or no such `dfid’, or the data format has already been attached to the data type
ida_bytes.detach_custom_data_format(dtid:int, dfid:int)→bool
Detach the data format from the data type. Unregistering a custom data type detaches all attached data formats, no need to detach them explicitly. You still need unregister them. Unregistering a custom data format detaches it from all attached data types.
Parameters:

-
dtid – data type id to detach data format from

-
dfid – data format id to detach

Returns:
true: ok
Returns:
false: no such dtid, or no such `dfid’, or the data format was not attached to the data type
ida_bytes.is_attached_custom_data_format(dtid:int, dfid:int)→bool
Is the custom data format attached to the custom data type?
Parameters:

-
dtid – data type id

-
dfid – data format id

Returns:
true or false
ida_bytes.get_custom_data_types(*args)→int
Get list of registered custom data type ids.
Parameters:

-
out – buffer for the output. may be nullptr

-
min_size – minimum value size

-
max_size – maximum value size

Returns:
number of custom data types with the specified size limits
ida_bytes.get_custom_data_formats(out:intvec_t*, dtid:int)→int
Get list of attached custom data formats for the specified data type.
Parameters:

-
out – buffer for the output. may be nullptr

-
dtid – data type id

Returns:
number of returned custom data formats. if error, returns -1
ida_bytes.find_custom_data_type(name:str)→int
Get id of a custom data type.
Parameters:
name – name of the custom data type
Returns:
id or -1
ida_bytes.find_custom_data_format(name:str)→int
Get id of a custom data format.
Parameters:
name – name of the custom data format
Returns:
id or -1
ida_bytes.set_cmt(ea:ida_idaapi.ea_t, comm:str, rptble:bool)→bool
Set an indented comment.
Parameters:

-
ea – linear address

-
comm – comment string

-
nullptr: do nothing (return 0)

-
“” : delete comment

Parameters:
rptble – is repeatable?
Returns:
success
ida_bytes.get_cmt(ea:ida_idaapi.ea_t, rptble:bool)→str
Get an indented comment.
Parameters:

-
ea – linear address. may point to tail byte, the function will find start of the item

-
rptble – get repeatable comment?

Returns:
size of comment or -1
ida_bytes.append_cmt(ea:ida_idaapi.ea_t, str:append_cmt.str, rptble:bool)→bool
Append to an indented comment. Creates a new comment if none exists. Appends a newline character and the specified string otherwise.
Parameters:

-
ea – linear address

-
str – comment string to append

-
rptble – append to repeatable comment?

Returns:
success
ida_bytes.get_predef_insn_cmt(ins:insn_tconst&)→str
Get predefined comment.
Parameters:
ins – current instruction information
Returns:
size of comment or -1
ida_bytes.find_byte(sEA:ida_idaapi.ea_t, size:asize_t, value:uchar, bin_search_flags:int)→ida_idaapi.ea_t
Find forward a byte with the specified value (only 8-bit value from the database). example: ea=4 size=3 will inspect addresses 4, 5, and 6
Parameters:

-
sEA – linear address

-
size – number of bytes to inspect

-
value – value to find

-
bin_search_flags – combination of Search flags

Returns:
address of byte or BADADDR
ida_bytes.find_byter(sEA:ida_idaapi.ea_t, size:asize_t, value:uchar, bin_search_flags:int)→ida_idaapi.ea_t
Find reverse a byte with the specified value (only 8-bit value from the database). example: ea=4 size=3 will inspect addresses 6, 5, and 4
Parameters:

-
sEA – the lower address of the search range

-
size – number of bytes to inspect

-
value – value to find

-
bin_search_flags – combination of Search flags

Returns:
address of byte or BADADDR
classida_bytes.compiled_binpat_t
Bases: `object`
thisownbytes:bytevec_tmask:bytevec_tstrlits:rangevec_tencidx:intall_bytes_defined()→boolqclear()→Noneida_bytes.PBSENC_DEF1BPU
Use the default 1 byte-per-unit IDB encoding.
ida_bytes.PBSENC_ALL
Use all IDB encodings.
ida_bytes.parse_binpat_str(out:compiled_binpat_vec_t, ea:ida_idaapi.ea_t, _in:str, radix:int, strlits_encoding:int=0)→bool
Deprecated.

Please use compiled_binpat_vec_t.from_pattern() instead.
ida_bytes.bin_search(*args)
Search for a set of bytes in the program

This function has the following signatures:

-
bin_search(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, data: compiled_binpat_vec_t, flags: int) -> Tuple[ida_idaapi.ea_t, int]

-
bin_search(start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, image: bytes, mask: bytes, len: int, flags: int) -> ida_idaapi.ea_t

The return value type will differ depending on the form:

-
a tuple (matched-address, index-in-compiled_binpat_vec_t) (1st form)

-
the address of a match, or ida_idaapi.BADADDR if not found (2nd form)

This is a low-level function; more user-friendly alternatives are available. Please see ‘find_bytes’ and ‘find_string’.
Parameters:

-
start_ea – linear address, start of range to search

-
end_ea – linear address, end of range to search (exclusive)

-
data – (1st form) the prepared data to search for (see parse_binpat_str())

-
bytes – (2nd form) a set of bytes to match

-
mask – (2nd form) a mask to apply to the set of bytes

-
flags – combination of BIN_SEARCH_* flags

Returns:
either a tuple holding both the address of the match and the index of the compiled pattern that matched, or the address of a match (ida_idaapi.BADADDR if not found)
ida_bytes.BIN_SEARCH_CASE
case sensitive
ida_bytes.BIN_SEARCH_NOCASE
case insensitive
ida_bytes.BIN_SEARCH_NOBREAK
don’t check for Ctrl-Break
ida_bytes.BIN_SEARCH_INITED
find_byte, find_byter: any initilized value
ida_bytes.BIN_SEARCH_NOSHOW
don’t show search progress or update screen
ida_bytes.BIN_SEARCH_FORWARD
search forward for bytes
ida_bytes.BIN_SEARCH_BACKWARD
search backward for bytes
ida_bytes.BIN_SEARCH_BITMASK
searching using strict bit mask
ida_bytes.next_inited(ea:ida_idaapi.ea_t, maxea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Find the next initialized address.
ida_bytes.prev_inited(ea:ida_idaapi.ea_t, minea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Find the previous initialized address.
ida_bytes.equal_bytes(ea:ida_idaapi.ea_t, image:ucharconst*, mask:ucharconst*, len:int, bin_search_flags:int)→bool
Compare ‘len’ bytes of the program starting from ‘ea’ with ‘image’.
Parameters:

-
ea – linear address

-
image – bytes to compare with

-
mask – array of mask bytes, it’s length is ‘len’. if the flag BIN_SEARCH_BITMASK is passsed, ‘bitwise AND’ is used to compare. if not; 1 means to perform the comparison of the corresponding byte. 0 means not to perform. if mask == nullptr, then all bytes of ‘image’ will be compared. if mask == SKIP_FF_MASK then 0xFF bytes will be skipped

-
len – length of block to compare in bytes.

-
bin_search_flags – combination of Search flags

Returns:
1: equal
Returns:
0: not equal
classida_bytes.hidden_range_t
Bases: `ida_range.range_t`
thisowndescription:char*
description to display if the range is collapsed
header:char*
header lines to display if the range is expanded
footer:char*
footer lines to display if the range is expanded
visible:bool
the range state
color:bgcolor_t
range color
ida_bytes.update_hidden_range(ha:hidden_range_t)→bool
Update hidden range information in the database. You cannot use this function to change the range boundaries
Parameters:
ha – range to update
Returns:
success
ida_bytes.add_hidden_range(*args)→bool
Mark a range of addresses as hidden. The range will be created in the invisible state with the default color
Parameters:

-
ea1 – linear address of start of the address range

-
ea2 – linear address of end of the address range

-
description – range parameters

-
header – range parameters

-
footer – range parameters

-
color – the range color

Returns:
success
ida_bytes.get_hidden_range(ea:ida_idaapi.ea_t)→hidden_range_t*
Get pointer to hidden range structure, in: linear address.
Parameters:
ea – any address in the hidden range
ida_bytes.getn_hidden_range(n:int)→hidden_range_t*
Get pointer to hidden range structure, in: number of hidden range.
Parameters:
n – number of hidden range, is in range 0..get_hidden_range_qty()-1
ida_bytes.get_hidden_range_qty()→int
Get number of hidden ranges.
ida_bytes.get_hidden_range_num(ea:ida_idaapi.ea_t)→int
Get number of a hidden range.
Parameters:
ea – any address in the hidden range
Returns:
number of hidden range (0..get_hidden_range_qty()-1)
ida_bytes.get_prev_hidden_range(ea:ida_idaapi.ea_t)→hidden_range_t*
Get pointer to previous hidden range.
Parameters:
ea – any address in the program
Returns:
ptr to hidden range or nullptr if previous hidden range does not exist
ida_bytes.get_next_hidden_range(ea:ida_idaapi.ea_t)→hidden_range_t*
Get pointer to next hidden range.
Parameters:
ea – any address in the program
Returns:
ptr to hidden range or nullptr if next hidden range does not exist
ida_bytes.get_first_hidden_range()→hidden_range_t*
Get pointer to the first hidden range.
Returns:
ptr to hidden range or nullptr
ida_bytes.get_last_hidden_range()→hidden_range_t*
Get pointer to the last hidden range.
Returns:
ptr to hidden range or nullptr
ida_bytes.del_hidden_range(ea:ida_idaapi.ea_t)→bool
Delete hidden range.
Parameters:
ea – any address in the hidden range
Returns:
success
ida_bytes.add_mapping(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t, size:asize_t)→bool
IDA supports memory mapping. References to the addresses from the mapped range use data and meta-data from the mapping range.
Parameters:

-
to – start of the mapping range (existent address)

-
size – size of the range

Returns:
success
ida_bytes.del_mapping(ea:ida_idaapi.ea_t)→None
Delete memory mapping range.
Parameters:
ea – any address in the mapped range
ida_bytes.use_mapping(ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Translate address according to current mappings.
Parameters:
ea – address to translate
Returns:
translated address
ida_bytes.get_mappings_qty()→int
Get number of mappings.
ida_bytes.get_mapping(n:int)→ea_t*,ea_t*,asize_t*
Get memory mapping range by its number.
Parameters:
n – number of mapping range (0..get_mappings_qty()-1)
Returns:
false if the specified range does not exist, otherwise returns from, to, size
ida_bytes.MS_0TYPEida_bytes.FF_0VOIDida_bytes.FF_0NUMHida_bytes.FF_0NUMDida_bytes.FF_0CHARida_bytes.FF_0SEGida_bytes.FF_0OFFida_bytes.FF_0NUMBida_bytes.FF_0NUMOida_bytes.FF_0ENUMida_bytes.FF_0FOPida_bytes.FF_0STROida_bytes.FF_0STKida_bytes.FF_0FLTida_bytes.FF_0CUSTida_bytes.MS_1TYPEida_bytes.FF_1VOIDida_bytes.FF_1NUMHida_bytes.FF_1NUMDida_bytes.FF_1CHARida_bytes.FF_1SEGida_bytes.FF_1OFFida_bytes.FF_1NUMBida_bytes.FF_1NUMOida_bytes.FF_1ENUMida_bytes.FF_1FOPida_bytes.FF_1STROida_bytes.FF_1STKida_bytes.FF_1FLTida_bytes.FF_1CUSTida_bytes.visit_patched_bytes(ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, callable)
Enumerates patched bytes in the given range and invokes a callable
Parameters:

-
ea1 – start address

-
ea2 – end address

-
callable – a Python callable with the following prototype: callable(ea, fpos, org_val, patch_val). If the callable returns non-zero then that value will be returned to the caller and the enumeration will be interrupted.

Returns:
Zero if the enumeration was successful or the return value of the callback if enumeration was interrupted.
ida_bytes.get_bytes(ea:ida_idaapi.ea_t, size:int, gmb_flags:int=GMB_READALL)
Get the specified number of bytes of the program.
Parameters:

-
ea – program address

-
size – number of bytes to return

-
gmb_flags – OR’ed combination of GMB_* values (defaults to GMB_READALL)

Returns:
the bytes (as bytes object), or None in case of failure
ida_bytes.get_bytes_and_mask(ea:ida_idaapi.ea_t, size:int, gmb_flags:int=GMB_READALL)
Get the specified number of bytes of the program, and a bitmask specifying what bytes are defined and what bytes are not.
Parameters:

-
ea – program address

-
size – number of bytes to return

-
gmb_flags – OR’ed combination of GMB_* values (defaults to GMB_READALL)

Returns:
a tuple (bytes, mask), or None in case of failure. Both ‘bytes’ and ‘mask’ are ‘str’ instances.
ida_bytes.get_strlit_contents(ea:ida_idaapi.ea_t, len:int, type:int, flags:int=0)
Get contents of string literal, as UTF-8-encoded codepoints. It works even if the string has not been created in the database yet.

Note that the returned value will be of type ‘bytes’; if you want auto-conversion to unicode strings (that is: real Python strings), you should probably be using the idautils.Strings class.
Parameters:

-
ea – linear address of the string

-
len – length of the string in bytes (including terminating 0)

-
type – type of the string. Represents both the character encoding, and the ‘type’ of string at the given location.

-
flags – combination of STRCONV_…, to perform output conversion.

Returns:
a bytes-filled str object.
ida_bytes.print_strlit_type(strtype:int, flags:int=0)→PyObject*
Get string type information: the string type name (possibly decorated with hotkey markers), and the tooltip.
Parameters:

-
strtype – the string type

-
flags – or’ed PSTF_* constants

Returns:
length of generated text
ida_bytes.op_stroff(*args)→bool
Set operand representation to be ‘struct offset’.

This function has the following signatures:

-
op_stroff(ins: ida_ua.insn_t, n: int, path: List[int], delta: int)

-
op_stroff(ins: ida_ua.insn_t, n: int, path: ida_pro.tid_array, path_len: int, delta: int) (backward-compatibility only)

Here is an example using this function:

ins = ida_ua.insn_t() if ida_ua.decode_insn(ins, some_address):

operand = 0 path = [ida_typeinf.get_named_type_tid(“my_stucture_t”)] # a one-element path ida_bytes.op_stroff(ins, operand, path, 0)

ida_bytes.get_stroff_path(*args)
Get the structure offset path for operand n, at the specified address.

This function has the following signatures:

-
get_stroff_path(ea: ida_idaapi.ea_t, n : int) -> Tuple[List[int], int]

-
get_stroff_path(path: tid_array, delta: sval_pointer, ea: ida_idaapi.ea_t, n : int) (backward-compatibility only)

Parameters:

-
ea – address where the operand holds a path to a structure offset (1st form)

-
n – operand number (1st form)

Returns:
a tuple holding a (list_of_tid_t’s, delta_within_the_last_type), or (None, None)
ida_bytes.register_custom_data_type(dt)
Registers a custom data type.
Parameters:
dt – an instance of the data_type_t class
Returns:
< 0 if failed to register
Returns:
> 0 data type id
ida_bytes.unregister_custom_data_type(dtid)
Unregisters a custom data type.
Parameters:
dtid – the data type id
Returns:
Boolean
ida_bytes.register_custom_data_format(df)
Registers a custom data format with a given data type.
Parameters:
df – an instance of data_format_t
Returns:
< 0 if failed to register
Returns:
> 0 data format id
ida_bytes.unregister_custom_data_format(dfid)
Unregisters a custom data format
Parameters:
dfid – data format id
Returns:
Boolean
ida_bytes.DTP_NODUP=1
do not use dup construct
ida_bytes.register_data_types_and_formats(formats)
Registers multiple data types and formats at once. To register one type/format at a time use register_custom_data_type/register_custom_data_format

It employs a special table of types and formats described below:

The ‘formats’ is a list of tuples. If a tuple has one element then it is the format to be registered with dtid=0 If the tuple has more than one element, then tuple[0] is the data type and tuple[1:] are the data formats. For example: many_formats = [

(pascal_data_type(), pascal_data_format()), (simplevm_data_type(), simplevm_data_format()), (makedword_data_format(),), (simplevm_data_format(),)

] The first two tuples describe data types and their associated formats. The last two tuples describe two data formats to be used with built-in data types. The data format may be attached to several data types. The id of the data format is stored in the first data_format_t object. For example: assert many_formats[1][1] != -1 assert many_formats[2][0] != -1 assert many_formats[3][0] == -1
ida_bytes.unregister_data_types_and_formats(formats)
As opposed to register_data_types_and_formats(), this function unregisters multiple data types and formats at once.
ida_bytes.find_bytes(bs:bytes|bytearray|str, range_start:int, range_size:int|None=None, range_end:int|None=ida_idaapi.BADADDR, mask:bytes|bytearray|None=None, flags:int|None=BIN_SEARCH_FORWARD|BIN_SEARCH_NOSHOW, radix:int|None=16, strlit_encoding:int|str|None=PBSENC_DEF1BPU)→intida_bytes.find_string(_str:str, range_start:int, range_end:int|None=ida_idaapi.BADADDR, range_size:int|None=None, strlit_encoding:int|str|None=PBSENC_DEF1BPU, flags:int|None=BIN_SEARCH_FORWARD|BIN_SEARCH_NOSHOW)→int
