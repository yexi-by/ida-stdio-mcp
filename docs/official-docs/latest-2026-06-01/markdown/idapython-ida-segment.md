# IDAPython segment API

- 官方来源：https://python.docs.hex-rays.com/ida_segment/index.html

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
- ida_segment
- View page source

# ida_segment

Functions that deal with segments.

IDA requires that all program addresses belong to segments (each address must belong to exactly one segment). The situation when an address doesn’t belong to any segment is allowed as a temporary situation only when the user changes program segmentation. Bytes outside a segment can’t be converted to instructions, have names, comments, etc. Each segment has its start address, ending address and represents a contiguous range of addresses. There might be unused holes between segments. Each segment has its unique segment selector. This selector is used to distinguish the segment from other segments. For 16-bit programs the selector is equal to the segment base paragraph. For 32-bit programs there is special array to translate the selectors to the segment base paragraphs. A selector is a 32/64 bit value. The segment base paragraph determines the offsets in the segment. If the start address of the segment == (base << 4) then the first offset in the segment will be 0. The start address should be higher or equal to (base << 4). We will call the offsets in the segment ‘virtual addresses’. So, the virtual address of the first byte of the segment is (start address of segment - segment base linear address) For IBM PC, the virtual address corresponds to the offset part of the address. For other processors (Z80, for example), virtual addresses correspond to Z80 addresses and linear addresses are used only internally. For MS Windows programs the segment base paragraph is 0 and therefore the segment virtual addresses are equal to linear addresses.

## Attributes

`SREG_NUM`
|
Maximum number of segment registers is 16 (see segregs.hpp)

`saAbs`
|
Absolute segment.

`saRelByte`
|
Relocatable, byte aligned.

`saRelWord`
|
Relocatable, word (2-byte) aligned.

`saRelPara`
|
Relocatable, paragraph (16-byte) aligned.

`saRelPage`
|
Relocatable, aligned on 256-byte boundary.

`saRelDble`
|
Relocatable, aligned on a double word (4-byte) boundary.

`saRel4K`
|
This value is used by the PharLap OMF for page (4K) alignment. It is not supported by LINK.

`saGroup`
|
Segment group.

`saRel32Bytes`
|
32 bytes

`saRel64Bytes`
|
64 bytes

`saRelQword`
|
8 bytes

`saRel128Bytes`
|
128 bytes

`saRel512Bytes`
|
512 bytes

`saRel1024Bytes`
|
1024 bytes

`saRel2048Bytes`
|
2048 bytes

`saRel_MAX_ALIGN_CODE`
|

`scPriv`
|
Private. Do not combine with any other program segment.

`scGroup`
|
Segment group.

`scPub`
|
Public. Combine by appending at an offset that meets the alignment requirement.

`scPub2`
|
As defined by Microsoft, same as C=2 (public).

`scStack`
|
Stack. Combine as for C=2. This combine type forces byte alignment.

`scCommon`
|
Common. Combine by overlay using maximum size.

`scPub3`
|
As defined by Microsoft, same as C=2 (public).

`sc_MAX_COMB_CODE`
|

`SEGPERM_EXEC`
|
Execute.

`SEGPERM_WRITE`
|
Write.

`SEGPERM_READ`
|
Read.

`SEGPERM_MAXVAL`
|
Execute + Write + Read.

`SEG_MAX_BITNESS_CODE`
|
Maximum segment bitness value.

`SFL_COMORG`
|
IDP dependent field (IBM PC: if set, ORG directive is not commented out)

`SFL_OBOK`
|
Orgbase is present? (IDP dependent field)

`SFL_HIDDEN`
|
Is the segment hidden?

`SFL_DEBUG`
|
Is the segment created for the debugger? Such segments are temporary and do not have permanent flags.

`SFL_LOADER`
|
Is the segment created by the loader?

`SFL_HIDETYPE`
|
Hide segment type (do not print it in the listing)

`SFL_HEADER`
|
Header segment (do not create offsets to it in the disassembly)

`SEG_NORM`
|
unknown type, no assumptions

`SEG_XTRN`
|

`SEG_CODE`
|
code segment

`SEG_DATA`
|
data segment

`SEG_IMP`
|
java: implementation segment

`SEG_GRP`
|

`SEG_NULL`
|
zero-length segment

`SEG_UNDF`
|
undefined segment type (not used)

`SEG_BSS`
|
uninitialized segment

`SEG_ABSSYM`
|

`SEG_COMM`
|

`SEG_IMEM`
|
internal processor memory & sfr (8051)

`SEG_MAX_SEGTYPE_CODE`
|
maximum value segment type can take

`ADDSEG_NOSREG`
|
set all default segment register values to BADSEL (undefine all default segment registers)

`ADDSEG_OR_DIE`
|
qexit() if can't add a segment

`ADDSEG_NOTRUNC`
|
don't truncate the new segment at the beginning of the next segment if they overlap. destroy/truncate old segments instead.

`ADDSEG_QUIET`
|
silent mode, no "Adding segment..." in the messages window

`ADDSEG_FILLGAP`
|
fill gap between new segment and previous one. i.e. if such a gap exists, and this gap is less than 64K, then fill the gap by extending the previous segment and adding .align directive to it. This way we avoid gaps between segments. too many gaps lead to a virtual array failure. it cannot hold more than ~1000 gaps.

`ADDSEG_SPARSE`
|
use sparse storage method for the new ranges of the created segment. please note that the ranges that were already enabled before creating the segment will not change their storage type.

`ADDSEG_NOAA`
|
do not mark new segment for auto-analysis

`ADDSEG_IDBENC`
|
'name' and 'sclass' are given in the IDB encoding; non-ASCII bytes will be decoded accordingly

`SEGMOD_KILL`
|
disable addresses if segment gets shrinked or deleted

`SEGMOD_KEEP`
|
keep information (code & data, etc)

`SEGMOD_SILENT`
|
be silent

`SEGMOD_KEEP0`
|
flag for internal use, don't set

`SEGMOD_KEEPSEL`
|
do not try to delete unused selector

`SEGMOD_NOMOVE`
|
don't move info from the start of segment to the new start address (for set_segm_start())

`SEGMOD_SPARSE`
|
use sparse storage if extending the segment (for set_segm_start(), set_segm_end())

`MOVE_SEGM_OK`
|
all ok

`MOVE_SEGM_PARAM`
|
The specified segment does not exist.

`MOVE_SEGM_ROOM`
|
Not enough free room at the target address.

`MOVE_SEGM_IDP`
|
IDP module forbids moving the segment.

`MOVE_SEGM_CHUNK`
|
Too many chunks are defined, can't move.

`MOVE_SEGM_LOADER`
|
The segment has been moved but the loader complained.

`MOVE_SEGM_ODD`
|
Cannot move segments by an odd number of bytes.

`MOVE_SEGM_ORPHAN`
|
Orphan bytes hinder segment movement.

`MOVE_SEGM_DEBUG`
|
Debugger segments cannot be moved.

`MOVE_SEGM_SOURCEFILES`
|
Source files ranges of addresses hinder segment movement.

`MOVE_SEGM_MAPPING`
|
Memory mapping ranges of addresses hinder segment movement.

`MOVE_SEGM_INVAL`
|
Invalid argument (delta/target does not fit the address space)

`MSF_SILENT`
|
don't display a "please wait" box on the screen

`MSF_NOFIX`
|
don't call the loader to fix relocations

`MSF_LDKEEP`
|
keep the loader in the memory (optimization)

`MSF_FIXONCE`
|
call loader only once with the special calling method. valid for rebase_program(). see loader_t::move_segm.

`MSF_PRIORITY`
|
loader segments will overwrite any existing debugger segments when moved. valid for move_segm()

`MSF_NETNODES`
|
move netnodes instead of changing inf.netdelta (this is slower); valid for rebase_program()

`CSS_OK`
|
ok

`CSS_NODBG`
|
debugger is not running

`CSS_NORANGE`
|
could not find corresponding memory range

`CSS_NOMEM`
|
not enough memory (might be because the segment is too big)

`CSS_BREAK`
|
memory reading process stopped by user

`SNAP_ALL_SEG`
|
Take a snapshot of all segments.

`SNAP_LOAD_SEG`
|
Take a snapshot of loader segments.

`SNAP_CUR_SEG`
|
Take a snapshot of current segment.

`MAX_GROUPS`
|
max number of segment groups

`MAX_SEGM_TRANSLATIONS`
|
max number of segment translations

## Classes

`segment_defsr_array`
|

`segment_t`
|

`lock_segment`
|

## Functions

`set_segment_translations`(→ bool)
|
Set new translation list.

`is_visible_segm`(→ bool)
|
See SFL_HIDDEN.

`is_finally_visible_segm`(→ bool)
|
See SFL_HIDDEN, SCF_SHHID_SEGM.

`set_visible_segm`(→ None)
|
See SFL_HIDDEN.

`is_spec_segm`(→ bool)
|
Has segment a special type? (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)

`is_spec_ea`(→ bool)
|
Does the address belong to a segment with a special type? (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)

`lock_segm`(→ None)
|
Lock segment pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved.

`is_segm_locked`(→ bool)
|
Is a segment pointer locked?

`getn_selector`(→ sel_t *, ea_t *)
|
Get description of selector (0..get_selector_qty()-1)

`get_selector_qty`(→ int)
|
Get number of defined selectors.

`setup_selector`(→ sel_t)
|
Allocate a selector for a segment if necessary. You must call this function before calling add_segm_ex(). add_segm() calls this function itself, so you don't need to allocate a selector. This function will allocate a selector if 'segbase' requires more than 16 bits and the current processor is IBM PC. Otherwise it will return the segbase value.

`allocate_selector`(→ sel_t)
|
Allocate a selector for a segment unconditionally. You must call this function before calling add_segm_ex(). add_segm() calls this function itself, so you don't need to allocate a selector. This function will allocate a new free selector and setup its mapping using find_free_selector() and set_selector() functions.

`find_free_selector`(→ sel_t)
|
Find first unused selector.

`set_selector`(→ int)
|
Set mapping of selector to a paragraph. You should call this function _before_ creating a segment which uses the selector, otherwise the creation of the segment will fail.

`del_selector`(→ None)
|
Delete mapping of a selector. Be wary of deleting selectors that are being used in the program, this can make a mess in the segments.

`sel2para`(→ ida_idaapi.ea_t)
|
Get mapping of a selector.

`sel2ea`(→ ida_idaapi.ea_t)
|
Get mapping of a selector as a linear address.

`find_selector`(→ sel_t)
|
Find a selector that has mapping to the specified paragraph.

`get_segm_by_sel`(→ segment_t *)
|
Get pointer to segment structure. This function finds a segment by its selector. If there are several segments with the same selectors, the last one will be returned.

`add_segm_ex`(→ bool)
|
Add a new segment. If a segment already exists at the specified range of addresses, this segment will be truncated. Instructions and data in the old segment will be deleted if the new segment has another addressing mode or another segment base address.

`add_segm`(→ bool)
|
Add a new segment, second form. Segment alignment is set to saRelByte. Segment combination is "public" or "stack" (if segment class is "STACK"). Addressing mode of segment is taken as default (16-bit or 32-bit). Default segment registers are set to BADSEL. If a segment already exists at the specified range of addresses, this segment will be truncated. Instructions and data in the old segment will be deleted if the new segment has another addressing mode or another segment base address.

`del_segm`(→ bool)
|
Delete a segment.

`get_segm_qty`(→ int)
|
Get number of segments.

`getseg`(→ segment_t *)
|
Get pointer to segment by linear address.

`getnseg`(→ segment_t *)
|
Get pointer to segment by its number.

`get_segm_num`(→ int)
|
Get number of segment by address.

`get_next_seg`(→ segment_t *)
|
Get pointer to the next segment.

`get_prev_seg`(→ segment_t *)
|
Get pointer to the previous segment.

`get_first_seg`(→ segment_t *)
|
Get pointer to the first segment.

`get_last_seg`(→ segment_t *)
|
Get pointer to the last segment.

`get_segm_by_name`(→ segment_t *)
|
Get pointer to segment by its name. If there are several segments with the same name, returns the first of them.

`set_segm_end`(→ bool)
|
Set segment end address. The next segment is shrinked to allow expansion of the specified segment. The kernel might even delete the next segment if necessary. The kernel will ask the user for a permission to destroy instructions or data going out of segment scope if such instructions exist.

`set_segm_start`(→ bool)
|
Set segment start address. The previous segment is trimmed to allow expansion of the specified segment. The kernel might even delete the previous segment if necessary. The kernel will ask the user for a permission to destroy instructions or data going out of segment scope if such instructions exist.

`move_segm_start`(→ bool)
|
Move segment start. The main difference between this function and set_segm_start() is that this function may expand the previous segment while set_segm_start() never does it. So, this function allows to change bounds of two segments simultaneously. If the previous segment and the specified segment have the same addressing mode and segment base, then instructions and data are not destroyed - they simply move from one segment to another. Otherwise all instructions/data which migrate from one segment to another are destroyed.

`move_segm_strerror`(→ str)
|
Return string describing error MOVE_SEGM_... code.

`move_segm`(→ move_segm_code_t)
|
This function moves all information to the new address. It fixes up address sensitive information in the kernel. The total effect is equal to reloading the segment to the target address. For the file format dependent address sensitive information, loader_t::move_segm is called. Also IDB notification event idb_event::segm_moved is called.

`change_segment_status`(→ int)
|
Convert a debugger segment to a regular segment and vice versa. When converting debug->regular, the memory contents will be copied to the database.

`take_memory_snapshot`(→ bool)
|
Take a memory snapshot of the running process.

`is_miniidb`(→ bool)
|
Is the database a miniidb created by the debugger?

`set_segm_base`(→ bool)
|
Internal function.

`set_group_selector`(→ int)
|
Create a new group of segments (used OMF files).

`get_group_selector`(→ sel_t)
|
Get common selector for a group of segments.

`add_segment_translation`(→ bool)
|
Add segment translation.

`del_segment_translations`(→ None)
|
Delete the translation list

`get_segment_translations`(→ ssize_t)
|
Get segment translation list.

`get_segment_cmt`(→ str)
|
Get segment comment.

`set_segment_cmt`(→ None)
|
Set segment comment.

`std_out_segm_footer`(→ None)
|
Generate segment footer line as a comment line. This function may be used in IDP modules to generate segment footer if the target assembler doesn't have 'ends' directive.

`set_segm_name`(→ int)
|
Rename segment. The new name is validated (see validate_name). A segment always has a name. If you hadn't specified a name, the kernel will assign it "seg###" name where ### is segment number.

`get_segm_name`(→ str)
|
Get true segment name by pointer to segment.

`get_visible_segm_name`(→ str)
|
Get segment name by pointer to segment.

`get_segm_class`(→ str)
|
Get segment class. Segment class is arbitrary text (max 8 characters).

`set_segm_class`(→ int)
|
Set segment class.

`segtype`(→ uchar)
|
Get segment type.

`get_segment_alignment`(→ str)
|
Get text representation of segment alignment code.

`get_segment_combination`(→ str)
|
Get text representation of segment combination code.

`get_segm_para`(→ ida_idaapi.ea_t)
|
Get segment base paragraph. Segment base paragraph may be converted to segment base linear address using to_ea() function. In fact, to_ea(get_segm_para(s), 0) == get_segm_base(s).

`get_segm_base`(→ ida_idaapi.ea_t)
|
Get segment base linear address. Segment base linear address is used to calculate virtual addresses. The virtual address of the first byte of the segment will be (start address of segment - segment base linear address)

`set_segm_addressing`(→ bool)
|
Change segment addressing mode (16, 32, 64 bits). You must use this function to change segment addressing, never change the 'bitness' field directly. This function will delete all instructions, comments and names in the segment

`update_segm`(→ bool)
|

`segm_adjust_diff`(→ adiff_t)
|
Truncate and sign extend a delta depending on the segment.

`segm_adjust_ea`(→ ida_idaapi.ea_t)
|
Truncate an address depending on the segment.

`get_defsr`(s, reg)
|
Deprecated, use instead:

`set_defsr`(s, reg, value)
|
Deprecated, use instead:

`rebase_program`(→ int)
|
Rebase the whole program by 'delta' bytes.

## Module Contents

classida_segment.segment_defsr_array(data:unsignedlonglong(&)[SREG_NUM])
Bases: `object`
thisowndata:unsignedlonglong(&)[SREG_NUM]bytesida_segment.set_segment_translations(segstart:ida_idaapi.ea_t, transmap:eavec_tconst&)→bool
Set new translation list.
Parameters:

-
segstart – start address of the segment to add translation to

-
transmap – vector of segment start addresses for the translation list. If transmap is empty, the translation list is deleted.

Returns:
1: ok
Returns:
0: too many translations or bad segstart
ida_segment.SREG_NUM
Maximum number of segment registers is 16 (see segregs.hpp)
classida_segment.segment_t
Bases: `ida_range.range_t`
thisownname:int
use get/set_segm_name() functions
sclass:int
use get/set_segm_class() functions
orgbase:int
this field is IDP dependent. you may keep your information about the segment here
align:uchar
Segment alignment codes
comb:uchar
Segment combination codes
perm:uchar
Segment permissions (0 means no information)
bitness:uchar
Number of bits in the segment addressing * 0: 16 bits * 1: 32 bits * 2: 64 bits
is_16bit()→bool
Is a 16-bit segment?
is_32bit()→bool
Is a 32-bit segment?
is_64bit()→bool
Is a 64-bit segment?
abits()→int
Get number of address bits.
abytes()→int
Get number of address bytes.
flags:ushort
Segment flags
comorg()→boolset_comorg()→Noneclr_comorg()→Noneob_ok()→boolset_ob_ok()→Noneclr_ob_ok()→Noneis_visible_segm()→boolset_visible_segm(visible:bool)→Noneset_debugger_segm(debseg:bool)→Noneis_loader_segm()→boolset_loader_segm(ldrseg:bool)→Noneis_hidden_segtype()→boolset_hidden_segtype(hide:bool)→Noneis_header_segm()→boolset_header_segm(on:bool)→Nonesel:sel_t
segment selector - should be unique. You can’t change this field after creating the segment. Exception: 16-bit OMF files may have several segments with the same selector, but this is not good (no way to denote a segment exactly) so it should be fixed in the future.
defsr:sel_t[16]
default segment register values. first element of this array keeps information about value of processor_t::reg_first_sreg
type:uchar
segment type (see Segment types). The kernel treats different segment types differently. Segments marked with ‘*’ contain no instructions or data and are not declared as ‘segments’ in the disassembly.
color:bgcolor_t
the segment color
update()→bool
Update segment information. You must call this function after modification of segment characteristics. Note that not all fields of segment structure may be modified directly, there are special functions to modify some fields.
Returns:
success
start_ea:ida_idaapi.ea_t
start_ea included
end_ea:ida_idaapi.ea_t
end_ea excluded
use64ida_segment.saAbs
Absolute segment.
ida_segment.saRelByte
Relocatable, byte aligned.
ida_segment.saRelWord
Relocatable, word (2-byte) aligned.
ida_segment.saRelPara
Relocatable, paragraph (16-byte) aligned.
ida_segment.saRelPage
Relocatable, aligned on 256-byte boundary.
ida_segment.saRelDble
Relocatable, aligned on a double word (4-byte) boundary.
ida_segment.saRel4K
This value is used by the PharLap OMF for page (4K) alignment. It is not supported by LINK.
ida_segment.saGroup
Segment group.
ida_segment.saRel32Bytes
32 bytes
ida_segment.saRel64Bytes
64 bytes
ida_segment.saRelQword
8 bytes
ida_segment.saRel128Bytes
128 bytes
ida_segment.saRel512Bytes
512 bytes
ida_segment.saRel1024Bytes
1024 bytes
ida_segment.saRel2048Bytes
2048 bytes
ida_segment.saRel_MAX_ALIGN_CODEida_segment.scPriv
Private. Do not combine with any other program segment.
ida_segment.scGroup
Segment group.
ida_segment.scPub
Public. Combine by appending at an offset that meets the alignment requirement.
ida_segment.scPub2
As defined by Microsoft, same as C=2 (public).
ida_segment.scStack
Stack. Combine as for C=2. This combine type forces byte alignment.
ida_segment.scCommon
Common. Combine by overlay using maximum size.
ida_segment.scPub3
As defined by Microsoft, same as C=2 (public).
ida_segment.sc_MAX_COMB_CODEida_segment.SEGPERM_EXEC
Execute.
ida_segment.SEGPERM_WRITE
Write.
ida_segment.SEGPERM_READ
Read.
ida_segment.SEGPERM_MAXVAL
Execute + Write + Read.
ida_segment.SEG_MAX_BITNESS_CODE
Maximum segment bitness value.
ida_segment.SFL_COMORG
IDP dependent field (IBM PC: if set, ORG directive is not commented out)
ida_segment.SFL_OBOK
Orgbase is present? (IDP dependent field)
ida_segment.SFL_HIDDEN
Is the segment hidden?
ida_segment.SFL_DEBUG
Is the segment created for the debugger? Such segments are temporary and do not have permanent flags.
ida_segment.SFL_LOADER
Is the segment created by the loader?
ida_segment.SFL_HIDETYPE
Hide segment type (do not print it in the listing)
ida_segment.SFL_HEADER
Header segment (do not create offsets to it in the disassembly)
ida_segment.SEG_NORM
unknown type, no assumptions
ida_segment.SEG_XTRN

-
segment with ‘extern’ definitions. no instructions are allowed

ida_segment.SEG_CODE
code segment
ida_segment.SEG_DATA
data segment
ida_segment.SEG_IMP
java: implementation segment
ida_segment.SEG_GRP

-
group of segments

ida_segment.SEG_NULL
zero-length segment
ida_segment.SEG_UNDF
undefined segment type (not used)
ida_segment.SEG_BSS
uninitialized segment
ida_segment.SEG_ABSSYM

-
segment with definitions of absolute symbols

ida_segment.SEG_COMM

-
segment with communal definitions

ida_segment.SEG_IMEM
internal processor memory & sfr (8051)
ida_segment.SEG_MAX_SEGTYPE_CODE
maximum value segment type can take
ida_segment.is_visible_segm(s:segment_t)→bool
See SFL_HIDDEN.
ida_segment.is_finally_visible_segm(s:segment_t)→bool
See SFL_HIDDEN, SCF_SHHID_SEGM.
ida_segment.set_visible_segm(s:segment_t, visible:bool)→None
See SFL_HIDDEN.
ida_segment.is_spec_segm(seg_type:uchar)→bool
Has segment a special type? (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)
ida_segment.is_spec_ea(ea:ida_idaapi.ea_t)→bool
Does the address belong to a segment with a special type? (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)
Parameters:
ea – linear address
ida_segment.lock_segm(segm:segment_t, lock:bool)→None
Lock segment pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved.
classida_segment.lock_segment(_segm:segment_t)
Bases: `object`
thisownida_segment.is_segm_locked(segm:segment_t)→bool
Is a segment pointer locked?
ida_segment.getn_selector(n:int)→sel_t*,ea_t*
Get description of selector (0..get_selector_qty()-1)
ida_segment.get_selector_qty()→int
Get number of defined selectors.
ida_segment.setup_selector(segbase:ida_idaapi.ea_t)→sel_t
Allocate a selector for a segment if necessary. You must call this function before calling add_segm_ex(). add_segm() calls this function itself, so you don’t need to allocate a selector. This function will allocate a selector if ‘segbase’ requires more than 16 bits and the current processor is IBM PC. Otherwise it will return the segbase value.
Parameters:
segbase – a new segment base paragraph
Returns:
the allocated selector number
ida_segment.allocate_selector(segbase:ida_idaapi.ea_t)→sel_t
Allocate a selector for a segment unconditionally. You must call this function before calling add_segm_ex(). add_segm() calls this function itself, so you don’t need to allocate a selector. This function will allocate a new free selector and setup its mapping using find_free_selector() and set_selector() functions.
Parameters:
segbase – a new segment base paragraph
Returns:
the allocated selector number
ida_segment.find_free_selector()→sel_t
Find first unused selector.
Returns:
a number >= 1
ida_segment.set_selector(selector:sel_t, paragraph:ida_idaapi.ea_t)→int
Set mapping of selector to a paragraph. You should call this function _before_ creating a segment which uses the selector, otherwise the creation of the segment will fail.
Parameters:
selector – number of selector to map

-
if selector == BADSEL, then return 0 (fail)

-
if the selector has had a mapping, old mapping is destroyed

-
if the selector number is equal to paragraph value, then the mapping is destroyed because we don’t need to keep trivial mappings.

Parameters:
paragraph – paragraph to map selector
Returns:
1: ok
Returns:
0: failure (bad selector or too many mappings)
ida_segment.del_selector(selector:sel_t)→None
Delete mapping of a selector. Be wary of deleting selectors that are being used in the program, this can make a mess in the segments.
Parameters:
selector – number of selector to remove from the translation table
ida_segment.sel2para(selector:sel_t)→ida_idaapi.ea_t
Get mapping of a selector.
Parameters:
selector – number of selector to translate
Returns:
paragraph the specified selector is mapped to. if there is no mapping, returns ‘selector’.
ida_segment.sel2ea(selector:sel_t)→ida_idaapi.ea_t
Get mapping of a selector as a linear address.
Parameters:
selector – number of selector to translate to linear address
Returns:
linear address the specified selector is mapped to. if there is no mapping, returns to_ea(selector,0);
ida_segment.find_selector(base:ida_idaapi.ea_t)→sel_t
Find a selector that has mapping to the specified paragraph.
Parameters:
base – paragraph to search in the translation table
Returns:
selector value or base
ida_segment.get_segm_by_sel(selector:sel_t)→segment_t*
Get pointer to segment structure. This function finds a segment by its selector. If there are several segments with the same selectors, the last one will be returned.
Parameters:
selector – a segment with the specified selector will be returned
Returns:
pointer to segment or nullptr
ida_segment.add_segm_ex(s:segment_t, name:str, sclass:str, flags:int)→bool
Add a new segment. If a segment already exists at the specified range of addresses, this segment will be truncated. Instructions and data in the old segment will be deleted if the new segment has another addressing mode or another segment base address.
Parameters:
s – pointer to filled segment structure. segment selector should have proper mapping (see set_selector()).

-
if s.start_ea==BADADDR then s.start_ea <- get_segm_base(&s)

-
if s.end_ea==BADADDR, then a segment up to the next segment will be created (if the next segment doesn’t exist, then 1 byte segment will be created).

-
if the s.end_ea < s.start_ea, then fail.

-
if s.end_ea is too high and the new segment would overlap the next segment, s.end_ea is adjusted properly.

Parameters:

-
name – name of new segment. may be nullptr. if specified, the segment is immediately renamed

-
sclass – class of the segment. may be nullptr. if specified, the segment class is immediately changed

-
flags – Add segment flags

Returns:
1: ok
Returns:
0: failed, a warning message is displayed The specified default segment register values may be modified by processor modules (see ev_creating_segm). Also, if the default data segment value is BADSEL, it will be changed to the selector of the newly created segment. This ensures that the data segment is always correctly set, which is a good default for most processors.
ida_segment.ADDSEG_NOSREG
set all default segment register values to BADSEL (undefine all default segment registers)
ida_segment.ADDSEG_OR_DIE
qexit() if can’t add a segment
ida_segment.ADDSEG_NOTRUNC
don’t truncate the new segment at the beginning of the next segment if they overlap. destroy/truncate old segments instead.
ida_segment.ADDSEG_QUIET
silent mode, no “Adding segment…” in the messages window
ida_segment.ADDSEG_FILLGAP
fill gap between new segment and previous one. i.e. if such a gap exists, and this gap is less than 64K, then fill the gap by extending the previous segment and adding .align directive to it. This way we avoid gaps between segments. too many gaps lead to a virtual array failure. it cannot hold more than ~1000 gaps.
ida_segment.ADDSEG_SPARSE
use sparse storage method for the new ranges of the created segment. please note that the ranges that were already enabled before creating the segment will not change their storage type.
ida_segment.ADDSEG_NOAA
do not mark new segment for auto-analysis
ida_segment.ADDSEG_IDBENC
‘name’ and ‘sclass’ are given in the IDB encoding; non-ASCII bytes will be decoded accordingly
ida_segment.add_segm(para:ida_idaapi.ea_t, start:ida_idaapi.ea_t, end:ida_idaapi.ea_t, name:str, sclass:str, flags:int=0)→bool
Add a new segment, second form. Segment alignment is set to saRelByte. Segment combination is “public” or “stack” (if segment class is “STACK”). Addressing mode of segment is taken as default (16-bit or 32-bit). Default segment registers are set to BADSEL. If a segment already exists at the specified range of addresses, this segment will be truncated. Instructions and data in the old segment will be deleted if the new segment has another addressing mode or another segment base address.
Parameters:

-
para – segment base paragraph. if paragraph can’t fit in 16-bit, then a new selector is allocated and mapped to the paragraph.

-
start – start address of the segment. if start==BADADDR then start <- to_ea(para,0).

-
end – end address of the segment. end address should be higher than start address. For emulate empty segments, use SEG_NULL segment type. If the end address is lower than start address, then fail. If end==BADADDR, then a segment up to the next segment will be created (if the next segment doesn’t exist, then 1 byte segment will be created). If ‘end’ is too high and the new segment would overlap the next segment, ‘end’ is adjusted properly.

-
name – name of new segment. may be nullptr

-
sclass – class of the segment. may be nullptr. type of the new segment is modified if class is one of predefined names:

-
“CODE” -> SEG_CODE

-
“DATA” -> SEG_DATA

-
“CONST” -> SEG_DATA

-
“STACK” -> SEG_BSS

-
“BSS” -> SEG_BSS

-
“XTRN” -> SEG_XTRN

-
“COMM” -> SEG_COMM

-
“ABS” -> SEG_ABSSYM

Parameters:
flags – Add segment flags
Returns:
1: ok
Returns:
0: failed, a warning message is displayed
ida_segment.del_segm(ea:ida_idaapi.ea_t, flags:int)→bool
Delete a segment.
Parameters:

-
ea – any address belonging to the segment

-
flags – Segment modification flags

Returns:
1: ok
Returns:
0: failed, no segment at ‘ea’.
ida_segment.SEGMOD_KILL
disable addresses if segment gets shrinked or deleted
ida_segment.SEGMOD_KEEP
keep information (code & data, etc)
ida_segment.SEGMOD_SILENT
be silent
ida_segment.SEGMOD_KEEP0
flag for internal use, don’t set
ida_segment.SEGMOD_KEEPSEL
do not try to delete unused selector
ida_segment.SEGMOD_NOMOVE
don’t move info from the start of segment to the new start address (for set_segm_start())
ida_segment.SEGMOD_SPARSE
use sparse storage if extending the segment (for set_segm_start(), set_segm_end())
ida_segment.get_segm_qty()→int
Get number of segments.
ida_segment.getseg(ea:ida_idaapi.ea_t)→segment_t*
Get pointer to segment by linear address.
Parameters:
ea – linear address belonging to the segment
Returns:
nullptr or pointer to segment structure
ida_segment.getnseg(n:int)→segment_t*
Get pointer to segment by its number.
Parameters:
n – segment number in the range (0..get_segm_qty()-1)
Returns:
nullptr or pointer to segment structure
ida_segment.get_segm_num(ea:ida_idaapi.ea_t)→int
Get number of segment by address.
Parameters:
ea – linear address belonging to the segment
Returns:
-1 if no segment occupies the specified address. otherwise returns number of the specified segment (0..get_segm_qty()-1)
ida_segment.get_next_seg(ea:ida_idaapi.ea_t)→segment_t*
Get pointer to the next segment.
ida_segment.get_prev_seg(ea:ida_idaapi.ea_t)→segment_t*
Get pointer to the previous segment.
ida_segment.get_first_seg()→segment_t*
Get pointer to the first segment.
ida_segment.get_last_seg()→segment_t*
Get pointer to the last segment.
ida_segment.get_segm_by_name(name:str)→segment_t*
Get pointer to segment by its name. If there are several segments with the same name, returns the first of them.
Parameters:
name – segment name. may be nullptr.
Returns:
nullptr or pointer to segment structure
ida_segment.set_segm_end(ea:ida_idaapi.ea_t, newend:ida_idaapi.ea_t, flags:int)→bool
Set segment end address. The next segment is shrinked to allow expansion of the specified segment. The kernel might even delete the next segment if necessary. The kernel will ask the user for a permission to destroy instructions or data going out of segment scope if such instructions exist.
Parameters:

-
ea – any address belonging to the segment

-
newend – new end address of the segment

-
flags – Segment modification flags

Returns:
1: ok
Returns:
0: failed, a warning message is displayed
ida_segment.set_segm_start(ea:ida_idaapi.ea_t, newstart:ida_idaapi.ea_t, flags:int)→bool
Set segment start address. The previous segment is trimmed to allow expansion of the specified segment. The kernel might even delete the previous segment if necessary. The kernel will ask the user for a permission to destroy instructions or data going out of segment scope if such instructions exist.
Parameters:

-
ea – any address belonging to the segment

-
newstart – new start address of the segment note that segment start address should be higher than segment base linear address.

-
flags – Segment modification flags

Returns:
1: ok
Returns:
0: failed, a warning message is displayed
ida_segment.move_segm_start(ea:ida_idaapi.ea_t, newstart:ida_idaapi.ea_t, mode:int)→bool
Move segment start. The main difference between this function and set_segm_start() is that this function may expand the previous segment while set_segm_start() never does it. So, this function allows to change bounds of two segments simultaneously. If the previous segment and the specified segment have the same addressing mode and segment base, then instructions and data are not destroyed - they simply move from one segment to another. Otherwise all instructions/data which migrate from one segment to another are destroyed.
Parameters:

-
ea – any address belonging to the segment

-
newstart – new start address of the segment note that segment start address should be higher than segment base linear address.

-
mode – policy for destroying defined items

-
0: if it is necessary to destroy defined items, display a dialog box and ask confirmation

-
1: if it is necessary to destroy defined items, just destroy them without asking the user

-
-1: if it is necessary to destroy defined items, don’t destroy them (i.e. function will fail)

-
-2: don’t destroy defined items (function will succeed)

Returns:
1: ok
Returns:
0: failed, a warning message is displayed
ida_segment.MOVE_SEGM_OK
all ok
ida_segment.MOVE_SEGM_PARAM
The specified segment does not exist.
ida_segment.MOVE_SEGM_ROOM
Not enough free room at the target address.
ida_segment.MOVE_SEGM_IDP
IDP module forbids moving the segment.
ida_segment.MOVE_SEGM_CHUNK
Too many chunks are defined, can’t move.
ida_segment.MOVE_SEGM_LOADER
The segment has been moved but the loader complained.
ida_segment.MOVE_SEGM_ODD
Cannot move segments by an odd number of bytes.
ida_segment.MOVE_SEGM_ORPHAN
Orphan bytes hinder segment movement.
ida_segment.MOVE_SEGM_DEBUG
Debugger segments cannot be moved.
ida_segment.MOVE_SEGM_SOURCEFILES
Source files ranges of addresses hinder segment movement.
ida_segment.MOVE_SEGM_MAPPING
Memory mapping ranges of addresses hinder segment movement.
ida_segment.MOVE_SEGM_INVAL
Invalid argument (delta/target does not fit the address space)
ida_segment.move_segm_strerror(code:move_segm_code_t)→str
Return string describing error MOVE_SEGM_… code.
ida_segment.move_segm(s:segment_t, to:ida_idaapi.ea_t, flags:int=0)→move_segm_code_t
This function moves all information to the new address. It fixes up address sensitive information in the kernel. The total effect is equal to reloading the segment to the target address. For the file format dependent address sensitive information, loader_t::move_segm is called. Also IDB notification event idb_event::segm_moved is called.
Parameters:

-
s – segment to move

-
to – new segment start address

-
flags – Move segment flags

Returns:
Move segment result codes
ida_segment.MSF_SILENT
don’t display a “please wait” box on the screen
ida_segment.MSF_NOFIX
don’t call the loader to fix relocations
ida_segment.MSF_LDKEEP
keep the loader in the memory (optimization)
ida_segment.MSF_FIXONCE
call loader only once with the special calling method. valid for rebase_program(). see loader_t::move_segm.
ida_segment.MSF_PRIORITY
loader segments will overwrite any existing debugger segments when moved. valid for move_segm()
ida_segment.MSF_NETNODES
move netnodes instead of changing inf.netdelta (this is slower); valid for rebase_program()
ida_segment.change_segment_status(s:segment_t, is_deb_segm:bool)→int
Convert a debugger segment to a regular segment and vice versa. When converting debug->regular, the memory contents will be copied to the database.
Parameters:

-
s – segment to modify

-
is_deb_segm – new status of the segment

Returns:
Change segment status result codes
ida_segment.CSS_OK
ok
ida_segment.CSS_NODBG
debugger is not running
ida_segment.CSS_NORANGE
could not find corresponding memory range
ida_segment.CSS_NOMEM
not enough memory (might be because the segment is too big)
ida_segment.CSS_BREAK
memory reading process stopped by user
ida_segment.SNAP_ALL_SEG
Take a snapshot of all segments.
ida_segment.SNAP_LOAD_SEG
Take a snapshot of loader segments.
ida_segment.SNAP_CUR_SEG
Take a snapshot of current segment.
ida_segment.take_memory_snapshot(type:int)→bool
Take a memory snapshot of the running process.
Parameters:
type – specifies which snapshot we want (see SNAP_ Snapshot types)
Returns:
success
ida_segment.is_miniidb()→bool
Is the database a miniidb created by the debugger?
Returns:
true if the database contains no segments or only debugger segments
ida_segment.set_segm_base(s:segment_t, newbase:ida_idaapi.ea_t)→bool
Internal function.
ida_segment.set_group_selector(grp:sel_t, sel:sel_t)→int
Create a new group of segments (used OMF files).
Parameters:

-
grp – selector of group segment (segment type is SEG_GRP) You should create an ‘empty’ (1 byte) group segment It won’t contain anything and will be used to redirect references to the group of segments to the common selector.

-
sel – common selector of all segments belonging to the segment You should create all segments within the group with the same selector value.

Returns:
1: ok
Returns:
0: too many groups (see MAX_GROUPS)
ida_segment.MAX_GROUPS
max number of segment groups
ida_segment.get_group_selector(grpsel:sel_t)→sel_t
Get common selector for a group of segments.
Parameters:
grpsel – selector of group segment
Returns:
common selector of the group or ‘grpsel’ if no such group is found
ida_segment.add_segment_translation(segstart:ida_idaapi.ea_t, mappedseg:ida_idaapi.ea_t)→bool
Add segment translation.
Parameters:

-
segstart – start address of the segment to add translation to

-
mappedseg – start address of the overlayed segment

Returns:
1: ok
Returns:
0: too many translations or bad segstart
ida_segment.MAX_SEGM_TRANSLATIONS
max number of segment translations
ida_segment.del_segment_translations(segstart:ida_idaapi.ea_t)→None
Delete the translation list
Parameters:
segstart – start address of the segment to delete translation list
ida_segment.get_segment_translations(transmap:eavec_t*, segstart:ida_idaapi.ea_t)→ssize_t
Get segment translation list.
Parameters:

-
transmap – vector of segment start addresses for the translation list

-
segstart – start address of the segment to get information about

Returns:
-1 if no translation list or bad segstart. otherwise returns size of translation list.
ida_segment.get_segment_cmt(s:segment_t, repeatable:bool)→str
Get segment comment.
Parameters:

-
s – pointer to segment structure

-
repeatable – 0: get regular comment. 1: get repeatable comment.

Returns:
size of comment or -1
ida_segment.set_segment_cmt(s:segment_t, cmt:str, repeatable:bool)→None
Set segment comment.
Parameters:

-
s – pointer to segment structure

-
cmt – comment string, may be multiline (with ‘

‘). maximal size is 4096 bytes. Use empty str (“”) to delete comment :param repeatable: 0: set regular comment. 1: set repeatable comment.
ida_segment.std_out_segm_footer(ctx:outctx_t&, seg:segment_t)→None
Generate segment footer line as a comment line. This function may be used in IDP modules to generate segment footer if the target assembler doesn’t have ‘ends’ directive.
ida_segment.set_segm_name(s:segment_t, name:str, flags:int=0)→int
Rename segment. The new name is validated (see validate_name). A segment always has a name. If you hadn’t specified a name, the kernel will assign it “seg###” name where ### is segment number.
Parameters:

-
s – pointer to segment (may be nullptr)

-
name – new segment name

-
flags – ADDSEG_IDBENC or 0

Returns:
1: ok, name is good and segment is renamed
Returns:
0: failure, name is bad or segment is nullptr
ida_segment.get_segm_name(s:segment_t, flags:int=0)→str
Get true segment name by pointer to segment.
Parameters:

-
s – pointer to segment

-
flags – 0-return name as is; 1-substitute bad symbols with _ 1 corresponds to GN_VISIBLE

Returns:
size of segment name (-1 if s==nullptr)
ida_segment.get_visible_segm_name(s:segment_t)→str
Get segment name by pointer to segment.
Parameters:
s – pointer to segment
Returns:
size of segment name (-1 if s==nullptr)
ida_segment.get_segm_class(s:segment_t)→str
Get segment class. Segment class is arbitrary text (max 8 characters).
Parameters:
s – pointer to segment
Returns:
size of segment class (-1 if s==nullptr or bufsize<=0)
ida_segment.set_segm_class(s:segment_t, sclass:str, flags:int=0)→int
Set segment class.
Parameters:

-
s – pointer to segment (may be nullptr)

-
sclass – segment class (may be nullptr). If segment type is SEG_NORM and segment class is one of predefined names, then segment type is changed to:

-
“CODE” -> SEG_CODE

-
“DATA” -> SEG_DATA

-
“STACK” -> SEG_BSS

-
“BSS” -> SEG_BSS

-
if “UNK” then segment type is reset to SEG_NORM.

Parameters:
flags – Add segment flags
Returns:
1: ok, name is good and segment is renamed
Returns:
0: failure, name is nullptr or bad or segment is nullptr
ida_segment.segtype(ea:ida_idaapi.ea_t)→uchar
Get segment type.
Parameters:
ea – any linear address within the segment
Returns:
Segment types, SEG_UNDF if no segment found at ‘ea’
ida_segment.get_segment_alignment(align:uchar)→str
Get text representation of segment alignment code.
Returns:
text digestable by IBM PC assembler.
ida_segment.get_segment_combination(comb:uchar)→str
Get text representation of segment combination code.
Returns:
text digestable by IBM PC assembler.
ida_segment.get_segm_para(s:segment_t)→ida_idaapi.ea_t
Get segment base paragraph. Segment base paragraph may be converted to segment base linear address using to_ea() function. In fact, to_ea(get_segm_para(s), 0) == get_segm_base(s).
Parameters:
s – pointer to segment
Returns:
0 if s == nullptr, the segment base paragraph
ida_segment.get_segm_base(s:segment_t)→ida_idaapi.ea_t
Get segment base linear address. Segment base linear address is used to calculate virtual addresses. The virtual address of the first byte of the segment will be (start address of segment - segment base linear address)
Parameters:
s – pointer to segment
Returns:
0 if s == nullptr, otherwise segment base linear address
ida_segment.set_segm_addressing(s:segment_t, bitness:int)→bool
Change segment addressing mode (16, 32, 64 bits). You must use this function to change segment addressing, never change the ‘bitness’ field directly. This function will delete all instructions, comments and names in the segment
Parameters:

-
s – pointer to segment

-
bitness – new addressing mode of segment

-
2: 64-bit segment

-
1: 32-bit segment

-
0: 16-bit segment

Returns:
success
ida_segment.update_segm(s:segment_t)→boolida_segment.segm_adjust_diff(s:segment_t, delta:adiff_t)→adiff_t
Truncate and sign extend a delta depending on the segment.
ida_segment.segm_adjust_ea(s:segment_t, ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Truncate an address depending on the segment.
ida_segment.get_defsr(s, reg)
Deprecated, use instead: value = s.defsr[reg]
ida_segment.set_defsr(s, reg, value)
Deprecated, use instead: s.defsr[reg] = value
ida_segment.rebase_program(delta:PyObject*, flags:int)→int
Rebase the whole program by ‘delta’ bytes.
Parameters:

-
delta – number of bytes to move the program

-
flags – Move segment flags it is recommended to use MSF_FIXONCE so that the loader takes care of global variables it stored in the database

Returns:
Move segment result codes
