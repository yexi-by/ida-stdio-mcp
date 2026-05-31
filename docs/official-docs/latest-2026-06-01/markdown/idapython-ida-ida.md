# IDAPython database info API

- 官方来源：https://python.docs.hex-rays.com/ida_ida/index.html

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
- ida_ida
- View page source

# ida_ida

Contains the ::inf structure definition and some functions common to the whole IDA project.

The ::inf structure is saved in the database and contains information specific to the current program being disassembled. Initially it is filled with values from ida.cfg. Although it is not a good idea to change values in ::inf structure (because you will overwrite values taken from ida.cfg), you are allowed to do it if you feel it necessary.

## Attributes

`AF_FINAL`
|
Final pass of analysis.

`f_EXE_old`
|
MS-DOS EXE file.

`f_COM_old`
|
MS-DOS COM file.

`f_BIN`
|
Binary file.

`f_DRV`
|
MS-DOS Driver.

`f_WIN`
|
New Executable (NE)

`f_HEX`
|
Intel Hex Object file.

`f_MEX`
|
MOS Technology Hex Object file.

`f_LX`
|
Linear Executable (LX)

`f_LE`
|
Linear Executable (LE)

`f_NLM`
|
Netware Loadable Module (NLM)

`f_COFF`
|
Common Object file Format (COFF)

`f_PE`
|
Portable Executable (PE)

`f_OMF`
|
Object Module Format.

`f_SREC`
|
Motorola SREC (S-record)

`f_ZIP`
|
ZIP file (this file is never loaded to IDA database)

`f_OMFLIB`
|
Library of OMF Modules.

`f_AR`
|
ar library

`f_LOADER`
|
file is loaded using LOADER DLL

`f_ELF`
|
Executable and Linkable Format (ELF)

`f_W32RUN`
|
Watcom DOS32 Extender (W32RUN)

`f_AOUT`
|
Linux a.out (AOUT)

`f_PRC`
|
PalmPilot program file.

`f_EXE`
|
MS-DOS EXE file.

`f_COM`
|
MS-DOS COM file.

`f_AIXAR`
|
AIX ar library.

`f_MACHO`
|
Mac OS X Mach-O.

`f_PSXOBJ`
|
Sony Playstation PSX object file.

`f_MD1IMG`
|
Mediatek Firmware Image.

`STT_CUR`
|
use current storage type (may be used only as a function argument)

`STT_VA`
|
regular storage: virtual arrays, an explicit flag for each byte

`STT_MM`
|
memory map: sparse storage. useful for huge objects

`STT_DBG`
|
memory map: temporary debugger storage. used internally

`IDAINFO_TAG_SIZE`
|
The database parameters. This structure is kept in the ida database. It contains the essential parameters for the current program

`IDAINFO_PROCNAME_SIZE`
|

`IDAINFO_STRLIT_PREF_SIZE`
|

`INFFL_AUTO`
|
Autoanalysis is enabled?

`INFFL_ALLASM`
|
may use constructs not supported by the target assembler

`INFFL_LOADIDC`
|
loading an idc file that contains database info

`INFFL_NOUSER`
|
do not store user info in the database

`INFFL_READONLY`
|
(internal) temporary interdiction to modify the database

`INFFL_CHKOPS`
|
check manual operands (unused)

`INFFL_NMOPS`
|
allow non-matched operands (unused)

`INFFL_GRAPH_VIEW`
|
currently using graph options ( text_options_t::graph)

`LFLG_PC_FPP`
|
decode floating point processor instructions?

`LFLG_PC_FLAT`
|
32-bit program (or higher)?

`LFLG_64BIT`
|
64-bit program?

`LFLG_IS_DLL`
|
Is dynamic library?

`LFLG_FLAT_OFF32`
|
treat REF_OFF32 as 32-bit offset for 16-bit segments (otherwise try SEG16:OFF16)

`LFLG_MSF`
|
Byte order: is MSB first?

`LFLG_WIDE_HBF`
|
Bit order of wide bytes: high byte first? (wide bytes: processor_t::dnbits > 8)

`LFLG_DBG_NOPATH`
|
do not store input full path in debugger process options

`LFLG_SNAPSHOT`
|
memory snapshot was taken?

`LFLG_PACK`
|
pack the database?

`LFLG_COMPRESS`
|
compress the database?

`LFLG_KERNMODE`
|
is a kernel-mode binary?

`LFLG_ILP32`
|
64-bit instructions with 64-bit registers, but 32-bit pointers and address space. this bit is mutually exclusive with LFLG_64BIT

`IDB_UNPACKED`
|
leave database components unpacked

`IDB_PACKED`
|
pack database components into .idb

`IDB_COMPRESSED`
|
compress & pack database components

`AF_CODE`
|
Trace execution flow.

`AF_MARKCODE`
|
Mark typical code sequences as code.

`AF_JUMPTBL`
|
Locate and create jump tables.

`AF_PURDAT`
|
Control flow to data segment is ignored.

`AF_USED`
|
Analyze and create all xrefs.

`AF_UNK`
|
Delete instructions with no xrefs.

`AF_PROCPTR`
|
Create function if data xref data->code32 exists.

`AF_PROC`
|
Create functions if call is present.

`AF_FTAIL`
|
Create function tails.

`AF_LVAR`
|
Create stack variables.

`AF_STKARG`
|
Propagate stack argument information.

`AF_REGARG`
|
Propagate register argument information.

`AF_TRACE`
|
Trace stack pointer.

`AF_VERSP`
|
Perform full SP-analysis. ( processor_t::verify_sp)

`AF_ANORET`
|
Perform 'no-return' analysis.

`AF_MEMFUNC`
|
Try to guess member function types.

`AF_TRFUNC`
|
Truncate functions upon code deletion.

`AF_STRLIT`
|
Create string literal if data xref exists.

`AF_CHKUNI`
|
Check for unicode strings.

`AF_FIXUP`
|
Create offsets and segments using fixup info.

`AF_DREFOFF`
|
Create offset if data xref to seg32 exists.

`AF_IMMOFF`
|
Convert 32-bit instruction operand to offset.

`AF_DATOFF`
|
Automatically convert data to offsets.

`AF_FLIRT`
|
Use flirt signatures.

`AF_SIGCMT`
|
Append a signature name comment for recognized anonymous library functions.

`AF_SIGMLT`
|
Allow recognition of several copies of the same function.

`AF_HFLIRT`
|
Automatically hide library functions.

`AF_JFUNC`
|
Rename jump functions as j_...

`AF_NULLSUB`
|
Rename empty functions as nullsub_...

`AF_DODATA`
|
Coagulate data segs at the final pass.

`AF_DOCODE`
|
Coagulate code segs at the final pass.

`AF2_DOEH`
|
Handle EH information.

`AF2_DORTTI`
|
Handle RTTI information.

`AF2_MACRO`
|
Try to combine several instructions into a macro instruction

`AF2_MERGESTR`
|
Merge string literals created using data xrefs

`SW_SEGXRF`
|
show segments in xrefs?

`SW_XRFMRK`
|
show xref type marks?

`SW_XRFFNC`
|
show function offsets?

`SW_XRFVAL`
|
show xref values? (otherwise-"...")

`NM_REL_OFF`
|

`NM_PTR_OFF`
|

`NM_NAM_OFF`
|

`NM_REL_EA`
|

`NM_PTR_EA`
|

`NM_NAM_EA`
|

`NM_EA`
|

`NM_EA4`
|

`NM_EA8`
|

`NM_SHORT`
|

`NM_SERIAL`
|

`DEMNAM_MASK`
|
mask for name form

`DEMNAM_CMNT`
|
display demangled names as comments

`DEMNAM_NAME`
|
display demangled names as regular names

`DEMNAM_NONE`
|
don't display demangled names

`DEMNAM_GCC3`
|
assume gcc3 names (valid for gnu compiler)

`DEMNAM_FIRST`
|
override type info

`LN_NORMAL`
|
include normal names

`LN_PUBLIC`
|
include public names

`LN_AUTO`
|
include autogenerated names

`LN_WEAK`
|
include weak names

`OFLG_SHOW_VOID`
|
Display void marks?

`OFLG_SHOW_AUTO`
|
Display autoanalysis indicator?

`OFLG_GEN_NULL`
|
Generate empty lines?

`OFLG_SHOW_PREF`
|
Show line prefixes?

`OFLG_PREF_SEG`
|
line prefixes with segment name?

`OFLG_LZERO`
|
generate leading zeros in numbers

`OFLG_GEN_ORG`
|
Generate 'org' directives?

`OFLG_GEN_ASSUME`
|
Generate 'assume' directives?

`OFLG_GEN_TRYBLKS`
|
Generate try/catch directives?

`SCF_RPTCMT`
|
show repeatable comments?

`SCF_ALLCMT`
|
comment all lines?

`SCF_NOCMT`
|
no comments at all

`SCF_LINNUM`
|
show source line numbers

`SCF_TESTMODE`
|
testida.idc is running

`SCF_SHHID_ITEM`
|
show hidden instructions

`SCF_SHHID_FUNC`
|
show hidden functions

`SCF_SHHID_SEGM`
|
show hidden segments

`LMT_THIN`
|
thin borders

`LMT_THICK`
|
thick borders

`LMT_EMPTY`
|
empty lines at the end of basic blocks

`PREF_SEGADR`
|
show segment addresses?

`PREF_FNCOFF`
|
show function offsets?

`PREF_STACK`
|
show stack pointer?

`PREF_PFXTRUNC`
|
truncate instruction bytes if they would need more than 1 line

`STRF_GEN`
|
generate names?

`STRF_AUTO`
|
names have 'autogenerated' bit?

`STRF_SERIAL`
|
generate serial names?

`STRF_UNICODE`
|
unicode strings are present?

`STRF_COMMENT`
|
generate auto comment for string references?

`STRF_SAVECASE`
|
preserve case of strings for identifiers

`ABI_8ALIGN4`
|
4 byte alignment for 8byte scalars (__int64/double) inside structures?

`ABI_PACK_STKARGS`
|
do not align stack arguments to stack slots

`ABI_BIGARG_ALIGN`
|
use natural type alignment for argument if the alignment exceeds native word size. (e.g. __int64 argument should be 8byte aligned on some 32-bit platforms)

`ABI_STACK_LDBL`
|
long double arguments are passed on stack

`ABI_STACK_VARARGS`
|
varargs are always passed on stack (even when there are free registers)

`ABI_HARD_FLOAT`
|
use the floating-point register set

`ABI_SET_BY_USER`
|
compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed

`ABI_GCC_LAYOUT`
|
use GCC layout for UDTs (used for mingw)

`ABI_MAP_STKARGS`
|
register arguments are mapped to stack area (and consume stack slots)

`ABI_HUGEARG_ALIGN`
|
use natural type alignment for an argument even if its alignment exceeds double native word size (the default is to use double word max). e.g. if this bit is set, __int128 has 16-byte alignment. this bit is not used by IDA yet

`INF_VERSION`
|

`INF_PROCNAME`
|

`INF_GENFLAGS`
|

`INF_LFLAGS`
|

`INF_DATABASE_CHANGE_COUNT`
|

`INF_FILETYPE`
|

`INF_OSTYPE`
|

`INF_APPTYPE`
|

`INF_ASMTYPE`
|

`INF_SPECSEGS`
|

`INF_AF`
|

`INF_AF2`
|

`INF_BASEADDR`
|

`INF_START_SS`
|

`INF_START_CS`
|

`INF_START_IP`
|

`INF_START_EA`
|

`INF_START_SP`
|

`INF_MAIN`
|

`INF_MIN_EA`
|

`INF_MAX_EA`
|

`INF_OMIN_EA`
|

`INF_OMAX_EA`
|

`INF_LOWOFF`
|

`INF_HIGHOFF`
|

`INF_MAXREF`
|

`INF_PRIVRANGE`
|

`INF_PRIVRANGE_START_EA`
|

`INF_PRIVRANGE_END_EA`
|

`INF_NETDELTA`
|

`INF_XREFNUM`
|

`INF_TYPE_XREFNUM`
|

`INF_REFCMTNUM`
|

`INF_XREFFLAG`
|

`INF_MAX_AUTONAME_LEN`
|

`INF_NAMETYPE`
|

`INF_SHORT_DEMNAMES`
|

`INF_LONG_DEMNAMES`
|

`INF_DEMNAMES`
|

`INF_LISTNAMES`
|

`INF_INDENT`
|

`INF_CMT_INDENT`
|

`INF_MARGIN`
|

`INF_LENXREF`
|

`INF_OUTFLAGS`
|

`INF_CMTFLG`
|

`INF_LIMITER`
|

`INF_BIN_PREFIX_SIZE`
|

`INF_PREFFLAG`
|

`INF_STRLIT_FLAGS`
|

`INF_STRLIT_BREAK`
|

`INF_STRLIT_ZEROES`
|

`INF_STRTYPE`
|

`INF_STRLIT_PREF`
|

`INF_STRLIT_SERNUM`
|

`INF_DATATYPES`
|

`INF_OBSOLETE_CC`
|

`INF_CC_ID`
|

`INF_CC_CM`
|

`INF_CC_SIZE_I`
|

`INF_CC_SIZE_B`
|

`INF_CC_SIZE_E`
|

`INF_CC_DEFALIGN`
|

`INF_CC_SIZE_S`
|

`INF_CC_SIZE_L`
|

`INF_CC_SIZE_LL`
|

`INF_CC_SIZE_LDBL`
|

`INF_ABIBITS`
|

`INF_APPCALL_OPTIONS`
|

`INF_FILE_FORMAT_NAME`
|
file format name for loader modules

`INF_GROUPS`
|
segment group information (see init_groups())

`INF_H_PATH`
|
C header path.

`INF_C_MACROS`
|
C predefined macros.

`INF_INCLUDE`
|
assembler include file name

`INF_DUALOP_GRAPH`
|
Graph text representation options.

`INF_DUALOP_TEXT`
|
Text representation options.

`INF_MD5`
|
MD5 of the input file.

`INF_IDA_VERSION`
|
version of ida which created the database

`INF_STR_ENCODINGS`
|
a list of encodings for the program strings

`INF_DBG_BINPATHS`
|
unused (20 indexes)

`INF_SHA256`
|
SHA256 of the input file.

`INF_ABINAME`
|
ABI name (processor specific)

`INF_ARCHIVE_PATH`
|
archive file path

`INF_PROBLEMS`
|
problem lists

`INF_SELECTORS`
|
2..63 are for selector_t blob (see init_selectors())

`INF_NOTEPAD`
|
notepad blob, occupies 1000 indexes (1MB of text)

`INF_SRCDBG_PATHS`
|
source debug paths, occupies 20 indexes

`INF_SRCDBG_UNDESIRED`
|
user-closed source files, occupies 20 indexes

`INF_INITIAL_VERSION`
|
initial version of database

`INF_CTIME`
|
database creation timestamp

`INF_ELAPSED`
|
seconds database stayed open

`INF_NOPENS`
|
how many times the database is opened

`INF_CRC32`
|
input file crc32

`INF_IMAGEBASE`
|
image base

`INF_IDSNODE`
|
ids modnode id (for import_module)

`INF_FSIZE`
|
input file size

`INF_OUTFILEENC`
|
output file encoding index

`INF_INPUT_FILE_PATH`
|

`INF_COMPILER_INFO`
|

`INF_CALLCNV`
|

`INF_LAST`
|

`UA_MAXOP`
|
max number of operands allowed for an instruction

`IDB_EXT32`
|

`IDB_EXT64`
|

`IDB_EXT`
|

`VLD_AUTO_REPAIR`
|
automatically repair the database

`VLD_DIALOG`
|
ask user to repair (this bit is mutually exclusive with VLD_AUTO_REPAIR)

`VLD_SILENT`
|
no messages to the output window

`IDI_STRUCFLD`
|
structure field (opposite to IDI_NODEVAL)

`IDI_ALTVAL`
|
netnode: altval

`IDI_SUPVAL`
|
netnode: supval

`IDI_VALOBJ`
|
netnode: valobj

`IDI_BLOB`
|
netnode: blob

`IDI_SCALAR`
|
scalar value (default)

`IDI_CSTR`
|
string

`IDI_QSTRING`
|
qstring

`IDI_BYTEARRAY`
|
byte array: binary representation

`IDI_EA_HEX`
|
default representation: hex or "BADADDR"

`IDI_DEC`
|
show as decimal

`IDI_HEX`
|
show as hexadecimal

`IDI_INC`
|
stored value is incremented (scalars only)

`IDI_MAP_VAL`
|
apply ea2node() to value

`IDI_HASH`
|
hashed node field, hash name in offset

`IDI_HLPSTRUC`
|
call helper for pointer to structure

`IDI_READONLY`
|
read-only field (cannot be modified)

`IDI_BITMAP`
|
bitmap field: interpret bitmask as bit number

`IDI_ONOFF`
|
show boolean as on/off (not true/false)

`IDI_NOMERGE`
|
field should not be merged as part of INF

`IDI_NODEVAL`
|

`IDI_BUFVAR`
|

`idainfo_big_arg_align`
|

`idainfo_gen_null`
|

`idainfo_set_gen_null`
|

`idainfo_gen_lzero`
|

`idainfo_set_gen_lzero`
|

`idainfo_gen_tryblks`
|

`idainfo_set_gen_tryblks`
|

`idainfo_get_demname_form`
|

`idainfo_get_pack_mode`
|

`idainfo_set_pack_mode`
|

`idainfo_is_64bit`
|

`idainfo_set_64bit`
|

`idainfo_is_auto_enabled`
|

`idainfo_set_auto_enabled`
|

`idainfo_is_be`
|

`idainfo_set_be`
|

`idainfo_is_dll`
|

`idainfo_is_flat_off32`
|

`idainfo_is_graph_view`
|

`idainfo_set_graph_view`
|

`idainfo_is_hard_float`
|

`idainfo_is_kernel_mode`
|

`idainfo_is_mem_aligned4`
|

`idainfo_is_snapshot`
|

`idainfo_is_wide_high_byte_first`
|

`idainfo_set_wide_high_byte_first`
|

`idainfo_like_binary`
|

`idainfo_line_pref_with_seg`
|

`idainfo_set_line_pref_with_seg`
|

`idainfo_show_auto`
|

`idainfo_set_show_auto`
|

`idainfo_show_line_pref`
|

`idainfo_set_show_line_pref`
|

`idainfo_show_void`
|

`idainfo_set_show_void`
|

`idainfo_loading_idc`
|

`idainfo_map_stkargs`
|

`idainfo_pack_stkargs`
|

`idainfo_readonly_idb`
|

`idainfo_set_store_user_info`
|

`idainfo_stack_ldbl`
|

`idainfo_stack_varargs`
|

`idainfo_use_allasm`
|

`idainfo_use_gcc_layout`
|

`macros_enabled`
|

`should_create_stkvars`
|

`should_trace_sp`
|

`show_all_comments`
|

`show_comments`
|

`show_repeatables`
|

`inf_get_comment`
|

`inf_set_comment`
|

`idainfo_comment_get`
|

`idainfo_comment_set`
|

## Classes

`compiler_info_t`
|

`idainfo`
|

`idbattr_valmap_t`
|

`idbattr_info_t`
|

## Functions

`is_filetype_like_binary`(→ bool)
|
Is an unstructured input file?

`getinf_str`(→ str)
|
Get program specific information (a non-scalar value)

`delinf`(→ bool)
|
Undefine a program specific information

`inf_get_version`(→ ushort)
|

`inf_set_version`(→ bool)
|

`inf_get_genflags`(→ ushort)
|

`inf_set_genflags`(→ bool)
|

`inf_is_auto_enabled`(→ bool)
|

`inf_set_auto_enabled`(→ bool)
|

`inf_use_allasm`(→ bool)
|

`inf_set_use_allasm`(→ bool)
|

`inf_loading_idc`(→ bool)
|

`inf_set_loading_idc`(→ bool)
|

`inf_no_store_user_info`(→ bool)
|

`inf_set_no_store_user_info`(→ bool)
|

`inf_readonly_idb`(→ bool)
|

`inf_set_readonly_idb`(→ bool)
|

`inf_check_manual_ops`(→ bool)
|

`inf_set_check_manual_ops`(→ bool)
|

`inf_allow_non_matched_ops`(→ bool)
|

`inf_set_allow_non_matched_ops`(→ bool)
|

`inf_is_graph_view`(→ bool)
|

`inf_set_graph_view`(→ bool)
|

`inf_get_lflags`(→ int)
|

`inf_set_lflags`(→ bool)
|

`inf_decode_fpp`(→ bool)
|

`inf_set_decode_fpp`(→ bool)
|

`inf_is_32bit_or_higher`(→ bool)
|

`inf_is_32bit_exactly`(→ bool)
|

`inf_set_32bit`(→ bool)
|

`inf_is_16bit`(→ bool)
|

`inf_is_64bit`(→ bool)
|

`inf_set_64bit`(→ bool)
|

`inf_is_ilp32`(→ bool)
|

`inf_set_ilp32`(→ bool)
|

`inf_is_dll`(→ bool)
|

`inf_set_dll`(→ bool)
|

`inf_is_flat_off32`(→ bool)
|

`inf_set_flat_off32`(→ bool)
|

`inf_is_be`(→ bool)
|

`inf_set_be`(→ bool)
|

`inf_is_wide_high_byte_first`(→ bool)
|

`inf_set_wide_high_byte_first`(→ bool)
|

`inf_dbg_no_store_path`(→ bool)
|

`inf_set_dbg_no_store_path`(→ bool)
|

`inf_is_snapshot`(→ bool)
|

`inf_set_snapshot`(→ bool)
|

`inf_pack_idb`(→ bool)
|

`inf_set_pack_idb`(→ bool)
|

`inf_compress_idb`(→ bool)
|

`inf_set_compress_idb`(→ bool)
|

`inf_is_kernel_mode`(→ bool)
|

`inf_set_kernel_mode`(→ bool)
|

`inf_get_app_bitness`(→ uint)
|

`inf_set_app_bitness`(→ None)
|

`inf_get_database_change_count`(→ int)
|

`inf_set_database_change_count`(→ bool)
|

`inf_get_filetype`(→ filetype_t)
|

`inf_set_filetype`(→ bool)
|

`inf_get_ostype`(→ ushort)
|

`inf_set_ostype`(→ bool)
|

`inf_get_apptype`(→ ushort)
|

`inf_set_apptype`(→ bool)
|

`inf_get_asmtype`(→ uchar)
|

`inf_set_asmtype`(→ bool)
|

`inf_get_specsegs`(→ uchar)
|

`inf_set_specsegs`(→ bool)
|

`inf_get_af`(→ int)
|

`inf_set_af`(→ bool)
|

`inf_trace_flow`(→ bool)
|

`inf_set_trace_flow`(→ bool)
|

`inf_mark_code`(→ bool)
|

`inf_set_mark_code`(→ bool)
|

`inf_create_jump_tables`(→ bool)
|

`inf_set_create_jump_tables`(→ bool)
|

`inf_noflow_to_data`(→ bool)
|

`inf_set_noflow_to_data`(→ bool)
|

`inf_create_all_xrefs`(→ bool)
|

`inf_set_create_all_xrefs`(→ bool)
|

`inf_del_no_xref_insns`(→ bool)
|

`inf_set_del_no_xref_insns`(→ bool)
|

`inf_create_func_from_ptr`(→ bool)
|

`inf_set_create_func_from_ptr`(→ bool)
|

`inf_create_func_from_call`(→ bool)
|

`inf_set_create_func_from_call`(→ bool)
|

`inf_create_func_tails`(→ bool)
|

`inf_set_create_func_tails`(→ bool)
|

`inf_should_create_stkvars`(→ bool)
|

`inf_set_should_create_stkvars`(→ bool)
|

`inf_propagate_stkargs`(→ bool)
|

`inf_set_propagate_stkargs`(→ bool)
|

`inf_propagate_regargs`(→ bool)
|

`inf_set_propagate_regargs`(→ bool)
|

`inf_should_trace_sp`(→ bool)
|

`inf_set_should_trace_sp`(→ bool)
|

`inf_full_sp_ana`(→ bool)
|

`inf_set_full_sp_ana`(→ bool)
|

`inf_noret_ana`(→ bool)
|

`inf_set_noret_ana`(→ bool)
|

`inf_guess_func_type`(→ bool)
|

`inf_set_guess_func_type`(→ bool)
|

`inf_truncate_on_del`(→ bool)
|

`inf_set_truncate_on_del`(→ bool)
|

`inf_create_strlit_on_xref`(→ bool)
|

`inf_set_create_strlit_on_xref`(→ bool)
|

`inf_check_unicode_strlits`(→ bool)
|

`inf_set_check_unicode_strlits`(→ bool)
|

`inf_create_off_using_fixup`(→ bool)
|

`inf_set_create_off_using_fixup`(→ bool)
|

`inf_create_off_on_dref`(→ bool)
|

`inf_set_create_off_on_dref`(→ bool)
|

`inf_op_offset`(→ bool)
|

`inf_set_op_offset`(→ bool)
|

`inf_data_offset`(→ bool)
|

`inf_set_data_offset`(→ bool)
|

`inf_use_flirt`(→ bool)
|

`inf_set_use_flirt`(→ bool)
|

`inf_append_sigcmt`(→ bool)
|

`inf_set_append_sigcmt`(→ bool)
|

`inf_allow_sigmulti`(→ bool)
|

`inf_set_allow_sigmulti`(→ bool)
|

`inf_hide_libfuncs`(→ bool)
|

`inf_set_hide_libfuncs`(→ bool)
|

`inf_rename_jumpfunc`(→ bool)
|

`inf_set_rename_jumpfunc`(→ bool)
|

`inf_rename_nullsub`(→ bool)
|

`inf_set_rename_nullsub`(→ bool)
|

`inf_coagulate_data`(→ bool)
|

`inf_set_coagulate_data`(→ bool)
|

`inf_coagulate_code`(→ bool)
|

`inf_set_coagulate_code`(→ bool)
|

`inf_final_pass`(→ bool)
|

`inf_set_final_pass`(→ bool)
|

`inf_get_af2`(→ int)
|

`inf_set_af2`(→ bool)
|

`inf_handle_eh`(→ bool)
|

`inf_set_handle_eh`(→ bool)
|

`inf_handle_rtti`(→ bool)
|

`inf_set_handle_rtti`(→ bool)
|

`inf_macros_enabled`(→ bool)
|

`inf_set_macros_enabled`(→ bool)
|

`inf_merge_strlits`(→ bool)
|

`inf_set_merge_strlits`(→ bool)
|

`inf_get_baseaddr`(→ int)
|

`inf_set_baseaddr`(→ bool)
|

`inf_get_start_ss`(→ sel_t)
|

`inf_set_start_ss`(→ bool)
|

`inf_get_start_cs`(→ sel_t)
|

`inf_set_start_cs`(→ bool)
|

`inf_get_start_ip`(→ ida_idaapi.ea_t)
|

`inf_set_start_ip`(→ bool)
|

`inf_get_start_ea`(→ ida_idaapi.ea_t)
|

`inf_set_start_ea`(→ bool)
|

`inf_get_start_sp`(→ ida_idaapi.ea_t)
|

`inf_set_start_sp`(→ bool)
|

`inf_get_main`(→ ida_idaapi.ea_t)
|

`inf_set_main`(→ bool)
|

`inf_get_min_ea`(→ ida_idaapi.ea_t)
|

`inf_set_min_ea`(→ bool)
|

`inf_get_max_ea`(→ ida_idaapi.ea_t)
|

`inf_set_max_ea`(→ bool)
|

`inf_get_omin_ea`(→ ida_idaapi.ea_t)
|

`inf_set_omin_ea`(→ bool)
|

`inf_get_omax_ea`(→ ida_idaapi.ea_t)
|

`inf_set_omax_ea`(→ bool)
|

`inf_get_lowoff`(→ ida_idaapi.ea_t)
|

`inf_set_lowoff`(→ bool)
|

`inf_get_highoff`(→ ida_idaapi.ea_t)
|

`inf_set_highoff`(→ bool)
|

`inf_get_maxref`(→ int)
|

`inf_set_maxref`(→ bool)
|

`inf_get_netdelta`(→ int)
|

`inf_set_netdelta`(→ bool)
|

`inf_get_xrefnum`(→ uchar)
|

`inf_set_xrefnum`(→ bool)
|

`inf_get_type_xrefnum`(→ uchar)
|

`inf_set_type_xrefnum`(→ bool)
|

`inf_get_refcmtnum`(→ uchar)
|

`inf_set_refcmtnum`(→ bool)
|

`inf_get_xrefflag`(→ uchar)
|

`inf_set_xrefflag`(→ bool)
|

`inf_show_xref_seg`(→ bool)
|

`inf_set_show_xref_seg`(→ bool)
|

`inf_show_xref_tmarks`(→ bool)
|

`inf_set_show_xref_tmarks`(→ bool)
|

`inf_show_xref_fncoff`(→ bool)
|

`inf_set_show_xref_fncoff`(→ bool)
|

`inf_show_xref_val`(→ bool)
|

`inf_set_show_xref_val`(→ bool)
|

`inf_get_max_autoname_len`(→ ushort)
|

`inf_set_max_autoname_len`(→ bool)
|

`inf_get_nametype`(→ char)
|

`inf_set_nametype`(→ bool)
|

`inf_get_short_demnames`(→ int)
|

`inf_set_short_demnames`(→ bool)
|

`inf_get_long_demnames`(→ int)
|

`inf_set_long_demnames`(→ bool)
|

`inf_get_demnames`(→ uchar)
|

`inf_set_demnames`(→ bool)
|

`inf_get_listnames`(→ uchar)
|

`inf_set_listnames`(→ bool)
|

`inf_get_indent`(→ uchar)
|

`inf_set_indent`(→ bool)
|

`inf_get_cmt_indent`(→ uchar)
|

`inf_set_cmt_indent`(→ bool)
|

`inf_get_margin`(→ ushort)
|

`inf_set_margin`(→ bool)
|

`inf_get_lenxref`(→ ushort)
|

`inf_set_lenxref`(→ bool)
|

`inf_get_outflags`(→ int)
|

`inf_set_outflags`(→ bool)
|

`inf_show_void`(→ bool)
|

`inf_set_show_void`(→ bool)
|

`inf_show_auto`(→ bool)
|

`inf_set_show_auto`(→ bool)
|

`inf_gen_null`(→ bool)
|

`inf_set_gen_null`(→ bool)
|

`inf_show_line_pref`(→ bool)
|

`inf_set_show_line_pref`(→ bool)
|

`inf_line_pref_with_seg`(→ bool)
|

`inf_set_line_pref_with_seg`(→ bool)
|

`inf_gen_lzero`(→ bool)
|

`inf_set_gen_lzero`(→ bool)
|

`inf_gen_org`(→ bool)
|

`inf_set_gen_org`(→ bool)
|

`inf_gen_assume`(→ bool)
|

`inf_set_gen_assume`(→ bool)
|

`inf_gen_tryblks`(→ bool)
|

`inf_set_gen_tryblks`(→ bool)
|

`inf_get_cmtflg`(→ uchar)
|

`inf_set_cmtflg`(→ bool)
|

`inf_show_repeatables`(→ bool)
|

`inf_set_show_repeatables`(→ bool)
|

`inf_show_all_comments`(→ bool)
|

`inf_set_show_all_comments`(→ bool)
|

`inf_hide_comments`(→ bool)
|

`inf_set_hide_comments`(→ bool)
|

`inf_show_src_linnum`(→ bool)
|

`inf_set_show_src_linnum`(→ bool)
|

`inf_test_mode`(→ bool)
|

`inf_show_hidden_insns`(→ bool)
|

`inf_set_show_hidden_insns`(→ bool)
|

`inf_show_hidden_funcs`(→ bool)
|

`inf_set_show_hidden_funcs`(→ bool)
|

`inf_show_hidden_segms`(→ bool)
|

`inf_set_show_hidden_segms`(→ bool)
|

`inf_get_limiter`(→ uchar)
|

`inf_set_limiter`(→ bool)
|

`inf_is_limiter_thin`(→ bool)
|

`inf_set_limiter_thin`(→ bool)
|

`inf_is_limiter_thick`(→ bool)
|

`inf_set_limiter_thick`(→ bool)
|

`inf_is_limiter_empty`(→ bool)
|

`inf_set_limiter_empty`(→ bool)
|

`inf_get_bin_prefix_size`(→ short)
|

`inf_set_bin_prefix_size`(→ bool)
|

`inf_get_prefflag`(→ uchar)
|

`inf_set_prefflag`(→ bool)
|

`inf_prefix_show_segaddr`(→ bool)
|

`inf_set_prefix_show_segaddr`(→ bool)
|

`inf_prefix_show_funcoff`(→ bool)
|

`inf_set_prefix_show_funcoff`(→ bool)
|

`inf_prefix_show_stack`(→ bool)
|

`inf_set_prefix_show_stack`(→ bool)
|

`inf_prefix_truncate_opcode_bytes`(→ bool)
|

`inf_set_prefix_truncate_opcode_bytes`(→ bool)
|

`inf_get_strlit_flags`(→ uchar)
|

`inf_set_strlit_flags`(→ bool)
|

`inf_strlit_names`(→ bool)
|

`inf_set_strlit_names`(→ bool)
|

`inf_strlit_name_bit`(→ bool)
|

`inf_set_strlit_name_bit`(→ bool)
|

`inf_strlit_serial_names`(→ bool)
|

`inf_set_strlit_serial_names`(→ bool)
|

`inf_unicode_strlits`(→ bool)
|

`inf_set_unicode_strlits`(→ bool)
|

`inf_strlit_autocmt`(→ bool)
|

`inf_set_strlit_autocmt`(→ bool)
|

`inf_strlit_savecase`(→ bool)
|

`inf_set_strlit_savecase`(→ bool)
|

`inf_get_strlit_break`(→ uchar)
|

`inf_set_strlit_break`(→ bool)
|

`inf_get_strlit_zeroes`(→ char)
|

`inf_set_strlit_zeroes`(→ bool)
|

`inf_get_strtype`(→ int)
|

`inf_set_strtype`(→ bool)
|

`inf_get_strlit_sernum`(→ int)
|

`inf_set_strlit_sernum`(→ bool)
|

`inf_get_datatypes`(→ int)
|

`inf_set_datatypes`(→ bool)
|

`inf_get_abibits`(→ int)
|

`inf_set_abibits`(→ bool)
|

`inf_is_mem_aligned4`(→ bool)
|

`inf_set_mem_aligned4`(→ bool)
|

`inf_pack_stkargs`(→ bool)
|

`inf_set_pack_stkargs`(→ bool)
|

`inf_big_arg_align`(→ bool)
|

`inf_set_big_arg_align`(→ bool)
|

`inf_stack_ldbl`(→ bool)
|

`inf_set_stack_ldbl`(→ bool)
|

`inf_stack_varargs`(→ bool)
|

`inf_set_stack_varargs`(→ bool)
|

`inf_is_hard_float`(→ bool)
|

`inf_set_hard_float`(→ bool)
|

`inf_abi_set_by_user`(→ bool)
|

`inf_set_abi_set_by_user`(→ bool)
|

`inf_use_gcc_layout`(→ bool)
|

`inf_set_use_gcc_layout`(→ bool)
|

`inf_map_stkargs`(→ bool)
|

`inf_set_map_stkargs`(→ bool)
|

`inf_huge_arg_align`(→ bool)
|

`inf_set_huge_arg_align`(→ bool)
|

`inf_get_appcall_options`(→ int)
|

`inf_set_appcall_options`(→ bool)
|

`inf_get_privrange_start_ea`(→ ida_idaapi.ea_t)
|

`inf_set_privrange_start_ea`(→ bool)
|

`inf_get_privrange_end_ea`(→ ida_idaapi.ea_t)
|

`inf_set_privrange_end_ea`(→ bool)
|

`inf_get_cc_id`(→ comp_t)
|

`inf_set_cc_id`(→ bool)
|

`inf_get_cc_cm`(→ cm_t)
|

`inf_set_cc_cm`(→ bool)
|

`inf_get_callcnv`(→ callcnv_t)
|

`inf_set_callcnv`(→ bool)
|

`inf_get_cc_size_i`(→ uchar)
|

`inf_set_cc_size_i`(→ bool)
|

`inf_get_cc_size_b`(→ uchar)
|

`inf_set_cc_size_b`(→ bool)
|

`inf_get_cc_size_e`(→ uchar)
|

`inf_set_cc_size_e`(→ bool)
|

`inf_get_cc_defalign`(→ uchar)
|

`inf_set_cc_defalign`(→ bool)
|

`inf_get_cc_size_s`(→ uchar)
|

`inf_set_cc_size_s`(→ bool)
|

`inf_get_cc_size_l`(→ uchar)
|

`inf_set_cc_size_l`(→ bool)
|

`inf_get_cc_size_ll`(→ uchar)
|

`inf_set_cc_size_ll`(→ bool)
|

`inf_get_cc_size_ldbl`(→ uchar)
|

`inf_set_cc_size_ldbl`(→ bool)
|

`inf_get_procname`(→ str)
|

`inf_set_procname`(→ bool)
|

`inf_get_strlit_pref`(→ str)
|

`inf_set_strlit_pref`(→ bool)
|

`inf_get_cc`(→ bool)
|

`inf_set_cc`(→ bool)
|

`inf_set_privrange`(→ bool)
|

`inf_get_privrange`(→ range_t)
|
This function has the following signatures:

`inf_get_af_low`(→ ushort)
|
Get/set low/high 16-bit halves of inf.af.

`inf_set_af_low`(→ None)
|

`inf_get_af_high`(→ ushort)
|

`inf_set_af_high`(→ None)
|

`inf_get_af2_low`(→ ushort)
|
Get/set low 16-bit half of inf.af2.

`inf_set_af2_low`(→ None)
|

`inf_get_pack_mode`(→ int)
|

`inf_set_pack_mode`(→ int)
|

`inf_inc_database_change_count`(→ None)
|

`inf_get_demname_form`(→ uchar)
|
Get DEMNAM_MASK bits of #demnames.

`inf_postinc_strlit_sernum`(→ int)
|

`inf_like_binary`(→ bool)
|

`calc_default_idaplace_flags`(→ int)
|
Get default disassembly line options.

`to_ea`(→ ida_idaapi.ea_t)
|
Convert (sel,off) value to a linear address.

`get_dbctx_id`(→ ssize_t)
|
Get the current database context ID

`get_dbctx_qty`(→ int)
|
Get number of database contexts

`switch_dbctx`(→ dbctx_t *)
|
Switch to the database with the provided context ID

`is_database_busy`(→ bool)
|
Check if the database is busy (e.g. performing some critical operations and cannot be safely accessed)

`validate_idb`(→ int)
|
Validate the database

`move_privrange`(→ bool)
|
Move privrange to the specified address

`idainfo_is_32bit`()
|

## Module Contents

ida_ida.AF_FINAL
Final pass of analysis.
ida_ida.f_EXE_old
MS-DOS EXE file.
ida_ida.f_COM_old
MS-DOS COM file.
ida_ida.f_BIN
Binary file.
ida_ida.f_DRV
MS-DOS Driver.
ida_ida.f_WIN
New Executable (NE)
ida_ida.f_HEX
Intel Hex Object file.
ida_ida.f_MEX
MOS Technology Hex Object file.
ida_ida.f_LX
Linear Executable (LX)
ida_ida.f_LE
Linear Executable (LE)
ida_ida.f_NLM
Netware Loadable Module (NLM)
ida_ida.f_COFF
Common Object file Format (COFF)
ida_ida.f_PE
Portable Executable (PE)
ida_ida.f_OMF
Object Module Format.
ida_ida.f_SREC
Motorola SREC (S-record)
ida_ida.f_ZIP
ZIP file (this file is never loaded to IDA database)
ida_ida.f_OMFLIB
Library of OMF Modules.
ida_ida.f_AR
ar library
ida_ida.f_LOADER
file is loaded using LOADER DLL
ida_ida.f_ELF
Executable and Linkable Format (ELF)
ida_ida.f_W32RUN
Watcom DOS32 Extender (W32RUN)
ida_ida.f_AOUT
Linux a.out (AOUT)
ida_ida.f_PRC
PalmPilot program file.
ida_ida.f_EXE
MS-DOS EXE file.
ida_ida.f_COM
MS-DOS COM file.
ida_ida.f_AIXAR
AIX ar library.
ida_ida.f_MACHO
Mac OS X Mach-O.
ida_ida.f_PSXOBJ
Sony Playstation PSX object file.
ida_ida.f_MD1IMG
Mediatek Firmware Image.
ida_ida.is_filetype_like_binary(ft:filetype_t)→bool
Is an unstructured input file?
classida_ida.compiler_info_t
Bases: `object`
thisownid:comp_t
compiler id (see Compiler IDs)
cm:cm_t
memory model and calling convention (see CM) see also get_cc/set_cc
size_i:uchar
sizeof(int)
size_b:uchar
sizeof(bool)
size_e:uchar
sizeof(enum)
defalign:uchar
default alignment for structures
size_s:uchar
short
size_l:uchar
long
size_ll:uchar
longlong
size_ldbl:uchar
longdouble (if different from processor_t::tbyte_size)
get_cc()→callcnv_tset_cc(cc:callcnv_t)→Noneida_ida.STT_CUR
use current storage type (may be used only as a function argument)
ida_ida.STT_VA
regular storage: virtual arrays, an explicit flag for each byte
ida_ida.STT_MM
memory map: sparse storage. useful for huge objects
ida_ida.STT_DBG
memory map: temporary debugger storage. used internally
ida_ida.IDAINFO_TAG_SIZE
The database parameters. This structure is kept in the ida database. It contains the essential parameters for the current program
ida_ida.IDAINFO_PROCNAME_SIZEida_ida.IDAINFO_STRLIT_PREF_SIZEclassida_ida.idainfo(*args, **kwargs)
Bases: `object`
thisowntag:char[3]
‘IDA’
version:ushort
Version of database.
procname:char[16]
Name of the current processor (with 0)
s_genflags:ushort
General idainfo flags
database_change_count:int
incremented after each byte and regular segment modifications
filetype:ushort
The input file type.
ostype:ushort
OS type the program is for bit definitions in libfuncs.hpp
apptype:ushort
Application type bit definitions in libfuncs.hpp
asmtype:uchar
target assembler number
specsegs:uchar
What format do special segments use? 0 - unspecified; 4 - entries are 4 bytes; 8 - entries are 8 bytes.
af:int
Analysis flags
af2:int
Analysis flags 2
baseaddr:int
remaining 28 bits are reserved

base address of the program (in paragraphs)
start_ss:sel_t
selector of the initial stack segment
start_cs:sel_t
selector of the segment with the main entry point
start_ip:ida_idaapi.ea_t
IP register value at the start of program execution
start_ea:ida_idaapi.ea_t
Linear address of the program entry point.
start_sp:ida_idaapi.ea_t
SP register value at the start of program execution
main:ida_idaapi.ea_t
address of main()
min_ea:ida_idaapi.ea_t
current limits of the program
max_ea:ida_idaapi.ea_t
maxEA is excluded
omin_ea:ida_idaapi.ea_t
original minEA (is set after loading the input file)
omax_ea:ida_idaapi.ea_t
original maxEA (is set after loading the input file)
lowoff:ida_idaapi.ea_t
Low limit for offsets (used in calculation of ‘void’ operands)
highoff:ida_idaapi.ea_t
High limit for offsets (used in calculation of ‘void’ operands)
maxref:int
Max tail for references.
xrefnum:uchar
CROSS REFERENCES.

Number of references to generate in the disassembly listing 0 - xrefs won’t be generated at all
type_xrefnum:uchar
Number of references to generate in the struct & enum windows 0 - xrefs won’t be generated at all
refcmtnum:uchar
Number of comment lines to generate for refs to string literals or demangled names 0 - such comments won’t be generated at all
s_xrefflag:uchar
Xref options
max_autoname_len:ushort
NAMES.

max autogenerated name length (without zero byte)
nametype:char
Dummy names representation types
short_demnames:int
short form of demangled names
long_demnames:int
long form of demangled names see demangle.h for definitions
demnames:uchar
Demangled name flags
listnames:uchar
Name list options
indent:uchar
DISASSEMBLY LISTING DETAILS.

Indentation for instructions
cmt_indent:uchar
Indentation for comments.
margin:ushort
max length of data lines
lenxref:ushort
max length of line with xrefs
outflags:int
output flags
s_cmtflg:uchar
Comment options
s_limiter:uchar
Delimiter options
bin_prefix_size:short
Number of instruction bytes (opcodes) to show in line prefix.
s_prefflag:uchar
Line prefix options
strlit_flags:uchar
STRING LITERALS.

string literal flags
strlit_break:uchar
Character used to break string literal lines.
strlit_zeroes:char
leading zeros
strtype:int
current ASCII string type see nalt.hpp for string types
strlit_pref:char[16]
prefix for string literal names
strlit_sernum:int
serial number
datatypes:int
data types allowed in data carousel
cc:compiler_info_t
COMPILER.

Target compiler
abibits:int
ABI features. Depends on info returned by get_abi_name() Processor modules may modify them in set_compiler
appcall_options:int
appcall options, see idd.hpp
get_abiname()→strabinamelflags
Misc. database flags
minEAmaxEAprocNameida_ida.INFFL_AUTO
Autoanalysis is enabled?
ida_ida.INFFL_ALLASM
may use constructs not supported by the target assembler
ida_ida.INFFL_LOADIDC
loading an idc file that contains database info
ida_ida.INFFL_NOUSER
do not store user info in the database
ida_ida.INFFL_READONLY
(internal) temporary interdiction to modify the database
ida_ida.INFFL_CHKOPS
check manual operands (unused)
ida_ida.INFFL_NMOPS
allow non-matched operands (unused)
ida_ida.INFFL_GRAPH_VIEW
currently using graph options ( text_options_t::graph)
ida_ida.LFLG_PC_FPP
decode floating point processor instructions?
ida_ida.LFLG_PC_FLAT
32-bit program (or higher)?
ida_ida.LFLG_64BIT
64-bit program?
ida_ida.LFLG_IS_DLL
Is dynamic library?
ida_ida.LFLG_FLAT_OFF32
treat REF_OFF32 as 32-bit offset for 16-bit segments (otherwise try SEG16:OFF16)
ida_ida.LFLG_MSF
Byte order: is MSB first?
ida_ida.LFLG_WIDE_HBF
Bit order of wide bytes: high byte first? (wide bytes: processor_t::dnbits > 8)
ida_ida.LFLG_DBG_NOPATH
do not store input full path in debugger process options
ida_ida.LFLG_SNAPSHOT
memory snapshot was taken?
ida_ida.LFLG_PACK
pack the database?
ida_ida.LFLG_COMPRESS
compress the database?
ida_ida.LFLG_KERNMODE
is a kernel-mode binary?
ida_ida.LFLG_ILP32
64-bit instructions with 64-bit registers, but 32-bit pointers and address space. this bit is mutually exclusive with LFLG_64BIT
ida_ida.IDB_UNPACKED
leave database components unpacked
ida_ida.IDB_PACKED
pack database components into .idb
ida_ida.IDB_COMPRESSED
compress & pack database components
ida_ida.AF_CODE
Trace execution flow.
ida_ida.AF_MARKCODE
Mark typical code sequences as code.
ida_ida.AF_JUMPTBL
Locate and create jump tables.
ida_ida.AF_PURDAT
Control flow to data segment is ignored.
ida_ida.AF_USED
Analyze and create all xrefs.
ida_ida.AF_UNK
Delete instructions with no xrefs.
ida_ida.AF_PROCPTR
Create function if data xref data->code32 exists.
ida_ida.AF_PROC
Create functions if call is present.
ida_ida.AF_FTAIL
Create function tails.
ida_ida.AF_LVAR
Create stack variables.
ida_ida.AF_STKARG
Propagate stack argument information.
ida_ida.AF_REGARG
Propagate register argument information.
ida_ida.AF_TRACE
Trace stack pointer.
ida_ida.AF_VERSP
Perform full SP-analysis. ( processor_t::verify_sp)
ida_ida.AF_ANORET
Perform ‘no-return’ analysis.
ida_ida.AF_MEMFUNC
Try to guess member function types.
ida_ida.AF_TRFUNC
Truncate functions upon code deletion.
ida_ida.AF_STRLIT
Create string literal if data xref exists.
ida_ida.AF_CHKUNI
Check for unicode strings.
ida_ida.AF_FIXUP
Create offsets and segments using fixup info.
ida_ida.AF_DREFOFF
Create offset if data xref to seg32 exists.
ida_ida.AF_IMMOFF
Convert 32-bit instruction operand to offset.
ida_ida.AF_DATOFF
Automatically convert data to offsets.
ida_ida.AF_FLIRT
Use flirt signatures.
ida_ida.AF_SIGCMT
Append a signature name comment for recognized anonymous library functions.
ida_ida.AF_SIGMLT
Allow recognition of several copies of the same function.
ida_ida.AF_HFLIRT
Automatically hide library functions.
ida_ida.AF_JFUNC
Rename jump functions as j_…
ida_ida.AF_NULLSUB
Rename empty functions as nullsub_…
ida_ida.AF_DODATA
Coagulate data segs at the final pass.
ida_ida.AF_DOCODE
Coagulate code segs at the final pass.
ida_ida.AF2_DOEH
Handle EH information.
ida_ida.AF2_DORTTI
Handle RTTI information.
ida_ida.AF2_MACRO
Try to combine several instructions into a macro instruction
ida_ida.AF2_MERGESTR
Merge string literals created using data xrefs
ida_ida.SW_SEGXRF
show segments in xrefs?
ida_ida.SW_XRFMRK
show xref type marks?
ida_ida.SW_XRFFNC
show function offsets?
ida_ida.SW_XRFVAL
show xref values? (otherwise-”…”)
ida_ida.NM_REL_OFFida_ida.NM_PTR_OFFida_ida.NM_NAM_OFFida_ida.NM_REL_EAida_ida.NM_PTR_EAida_ida.NM_NAM_EAida_ida.NM_EAida_ida.NM_EA4ida_ida.NM_EA8ida_ida.NM_SHORTida_ida.NM_SERIALida_ida.DEMNAM_MASK
mask for name form
ida_ida.DEMNAM_CMNT
display demangled names as comments
ida_ida.DEMNAM_NAME
display demangled names as regular names
ida_ida.DEMNAM_NONE
don’t display demangled names
ida_ida.DEMNAM_GCC3
assume gcc3 names (valid for gnu compiler)
ida_ida.DEMNAM_FIRST
override type info
ida_ida.LN_NORMAL
include normal names
ida_ida.LN_PUBLIC
include public names
ida_ida.LN_AUTO
include autogenerated names
ida_ida.LN_WEAK
include weak names
ida_ida.OFLG_SHOW_VOID
Display void marks?
ida_ida.OFLG_SHOW_AUTO
Display autoanalysis indicator?
ida_ida.OFLG_GEN_NULL
Generate empty lines?
ida_ida.OFLG_SHOW_PREF
Show line prefixes?
ida_ida.OFLG_PREF_SEG
line prefixes with segment name?
ida_ida.OFLG_LZERO
generate leading zeros in numbers
ida_ida.OFLG_GEN_ORG
Generate ‘org’ directives?
ida_ida.OFLG_GEN_ASSUME
Generate ‘assume’ directives?
ida_ida.OFLG_GEN_TRYBLKS
Generate try/catch directives?
ida_ida.SCF_RPTCMT
show repeatable comments?
ida_ida.SCF_ALLCMT
comment all lines?
ida_ida.SCF_NOCMT
no comments at all
ida_ida.SCF_LINNUM
show source line numbers
ida_ida.SCF_TESTMODE
testida.idc is running
ida_ida.SCF_SHHID_ITEM
show hidden instructions
ida_ida.SCF_SHHID_FUNC
show hidden functions
ida_ida.SCF_SHHID_SEGM
show hidden segments
ida_ida.LMT_THIN
thin borders
ida_ida.LMT_THICK
thick borders
ida_ida.LMT_EMPTY
empty lines at the end of basic blocks
ida_ida.PREF_SEGADR
show segment addresses?
ida_ida.PREF_FNCOFF
show function offsets?
ida_ida.PREF_STACK
show stack pointer?
ida_ida.PREF_PFXTRUNC
truncate instruction bytes if they would need more than 1 line
ida_ida.STRF_GEN
generate names?
ida_ida.STRF_AUTO
names have ‘autogenerated’ bit?
ida_ida.STRF_SERIAL
generate serial names?
ida_ida.STRF_UNICODE
unicode strings are present?
ida_ida.STRF_COMMENT
generate auto comment for string references?
ida_ida.STRF_SAVECASE
preserve case of strings for identifiers
ida_ida.ABI_8ALIGN4
4 byte alignment for 8byte scalars (__int64/double) inside structures?
ida_ida.ABI_PACK_STKARGS
do not align stack arguments to stack slots
ida_ida.ABI_BIGARG_ALIGN
use natural type alignment for argument if the alignment exceeds native word size. (e.g. __int64 argument should be 8byte aligned on some 32-bit platforms)
ida_ida.ABI_STACK_LDBL
long double arguments are passed on stack
ida_ida.ABI_STACK_VARARGS
varargs are always passed on stack (even when there are free registers)
ida_ida.ABI_HARD_FLOAT
use the floating-point register set
ida_ida.ABI_SET_BY_USER
compiler/abi were set by user flag and require SETCOMP_BY_USER flag to be changed
ida_ida.ABI_GCC_LAYOUT
use GCC layout for UDTs (used for mingw)
ida_ida.ABI_MAP_STKARGS
register arguments are mapped to stack area (and consume stack slots)
ida_ida.ABI_HUGEARG_ALIGN
use natural type alignment for an argument even if its alignment exceeds double native word size (the default is to use double word max). e.g. if this bit is set, __int128 has 16-byte alignment. this bit is not used by IDA yet
ida_ida.INF_VERSIONida_ida.INF_PROCNAMEida_ida.INF_GENFLAGSida_ida.INF_LFLAGSida_ida.INF_DATABASE_CHANGE_COUNTida_ida.INF_FILETYPEida_ida.INF_OSTYPEida_ida.INF_APPTYPEida_ida.INF_ASMTYPEida_ida.INF_SPECSEGSida_ida.INF_AFida_ida.INF_AF2ida_ida.INF_BASEADDRida_ida.INF_START_SSida_ida.INF_START_CSida_ida.INF_START_IPida_ida.INF_START_EAida_ida.INF_START_SPida_ida.INF_MAINida_ida.INF_MIN_EAida_ida.INF_MAX_EAida_ida.INF_OMIN_EAida_ida.INF_OMAX_EAida_ida.INF_LOWOFFida_ida.INF_HIGHOFFida_ida.INF_MAXREFida_ida.INF_PRIVRANGEida_ida.INF_PRIVRANGE_START_EAida_ida.INF_PRIVRANGE_END_EAida_ida.INF_NETDELTAida_ida.INF_XREFNUMida_ida.INF_TYPE_XREFNUMida_ida.INF_REFCMTNUMida_ida.INF_XREFFLAGida_ida.INF_MAX_AUTONAME_LENida_ida.INF_NAMETYPEida_ida.INF_SHORT_DEMNAMESida_ida.INF_LONG_DEMNAMESida_ida.INF_DEMNAMESida_ida.INF_LISTNAMESida_ida.INF_INDENTida_ida.INF_CMT_INDENTida_ida.INF_MARGINida_ida.INF_LENXREFida_ida.INF_OUTFLAGSida_ida.INF_CMTFLGida_ida.INF_LIMITERida_ida.INF_BIN_PREFIX_SIZEida_ida.INF_PREFFLAGida_ida.INF_STRLIT_FLAGSida_ida.INF_STRLIT_BREAKida_ida.INF_STRLIT_ZEROESida_ida.INF_STRTYPEida_ida.INF_STRLIT_PREFida_ida.INF_STRLIT_SERNUMida_ida.INF_DATATYPESida_ida.INF_OBSOLETE_CCida_ida.INF_CC_IDida_ida.INF_CC_CMida_ida.INF_CC_SIZE_Iida_ida.INF_CC_SIZE_Bida_ida.INF_CC_SIZE_Eida_ida.INF_CC_DEFALIGNida_ida.INF_CC_SIZE_Sida_ida.INF_CC_SIZE_Lida_ida.INF_CC_SIZE_LLida_ida.INF_CC_SIZE_LDBLida_ida.INF_ABIBITSida_ida.INF_APPCALL_OPTIONSida_ida.INF_FILE_FORMAT_NAME
file format name for loader modules
ida_ida.INF_GROUPS
segment group information (see init_groups())
ida_ida.INF_H_PATH
C header path.
ida_ida.INF_C_MACROS
C predefined macros.
ida_ida.INF_INCLUDE
assembler include file name
ida_ida.INF_DUALOP_GRAPH
Graph text representation options.
ida_ida.INF_DUALOP_TEXT
Text representation options.
ida_ida.INF_MD5
MD5 of the input file.
ida_ida.INF_IDA_VERSION
version of ida which created the database
ida_ida.INF_STR_ENCODINGS
a list of encodings for the program strings
ida_ida.INF_DBG_BINPATHS
unused (20 indexes)
ida_ida.INF_SHA256
SHA256 of the input file.
ida_ida.INF_ABINAME
ABI name (processor specific)
ida_ida.INF_ARCHIVE_PATH
archive file path
ida_ida.INF_PROBLEMS
problem lists
ida_ida.INF_SELECTORS
2..63 are for selector_t blob (see init_selectors())
ida_ida.INF_NOTEPAD
notepad blob, occupies 1000 indexes (1MB of text)
ida_ida.INF_SRCDBG_PATHS
source debug paths, occupies 20 indexes
ida_ida.INF_SRCDBG_UNDESIRED
user-closed source files, occupies 20 indexes
ida_ida.INF_INITIAL_VERSION
initial version of database
ida_ida.INF_CTIME
database creation timestamp
ida_ida.INF_ELAPSED
seconds database stayed open
ida_ida.INF_NOPENS
how many times the database is opened
ida_ida.INF_CRC32
input file crc32
ida_ida.INF_IMAGEBASE
image base
ida_ida.INF_IDSNODE
ids modnode id (for import_module)
ida_ida.INF_FSIZE
input file size
ida_ida.INF_OUTFILEENC
output file encoding index
ida_ida.INF_INPUT_FILE_PATHida_ida.INF_COMPILER_INFOida_ida.INF_CALLCNVida_ida.INF_LASTida_ida.getinf_str(tag:inftag_t)→str
Get program specific information (a non-scalar value)
Parameters:
tag – one of inftag_t constants
Returns:
number of bytes stored in the buffer (<0 - not defined)
ida_ida.delinf(tag:inftag_t)→bool
Undefine a program specific information
Parameters:
tag – one of inftag_t constants
Returns:
success
ida_ida.inf_get_version()→ushortida_ida.inf_set_version(_v:ushort)→boolida_ida.inf_get_genflags()→ushortida_ida.inf_set_genflags(_v:ushort)→boolida_ida.inf_is_auto_enabled()→boolida_ida.inf_set_auto_enabled(_v:bool=True)→boolida_ida.inf_use_allasm()→boolida_ida.inf_set_use_allasm(_v:bool=True)→boolida_ida.inf_loading_idc()→boolida_ida.inf_set_loading_idc(_v:bool=True)→boolida_ida.inf_no_store_user_info()→boolida_ida.inf_set_no_store_user_info(_v:bool=True)→boolida_ida.inf_readonly_idb()→boolida_ida.inf_set_readonly_idb(_v:bool=True)→boolida_ida.inf_check_manual_ops()→boolida_ida.inf_set_check_manual_ops(_v:bool=True)→boolida_ida.inf_allow_non_matched_ops()→boolida_ida.inf_set_allow_non_matched_ops(_v:bool=True)→boolida_ida.inf_is_graph_view()→boolida_ida.inf_set_graph_view(_v:bool=True)→boolida_ida.inf_get_lflags()→intida_ida.inf_set_lflags(_v:int)→boolida_ida.inf_decode_fpp()→boolida_ida.inf_set_decode_fpp(_v:bool=True)→boolida_ida.inf_is_32bit_or_higher()→boolida_ida.inf_is_32bit_exactly()→boolida_ida.inf_set_32bit(_v:bool=True)→boolida_ida.inf_is_16bit()→boolida_ida.inf_is_64bit()→boolida_ida.inf_set_64bit(_v:bool=True)→boolida_ida.inf_is_ilp32()→boolida_ida.inf_set_ilp32(_v:bool=True)→boolida_ida.inf_is_dll()→boolida_ida.inf_set_dll(_v:bool=True)→boolida_ida.inf_is_flat_off32()→boolida_ida.inf_set_flat_off32(_v:bool=True)→boolida_ida.inf_is_be()→boolida_ida.inf_set_be(_v:bool=True)→boolida_ida.inf_is_wide_high_byte_first()→boolida_ida.inf_set_wide_high_byte_first(_v:bool=True)→boolida_ida.inf_dbg_no_store_path()→boolida_ida.inf_set_dbg_no_store_path(_v:bool=True)→boolida_ida.inf_is_snapshot()→boolida_ida.inf_set_snapshot(_v:bool=True)→boolida_ida.inf_pack_idb()→boolida_ida.inf_set_pack_idb(_v:bool=True)→boolida_ida.inf_compress_idb()→boolida_ida.inf_set_compress_idb(_v:bool=True)→boolida_ida.inf_is_kernel_mode()→boolida_ida.inf_set_kernel_mode(_v:bool=True)→boolida_ida.inf_get_app_bitness()→uintida_ida.inf_set_app_bitness(bitness:uint)→Noneida_ida.inf_get_database_change_count()→intida_ida.inf_set_database_change_count(_v:int)→boolida_ida.inf_get_filetype()→filetype_tida_ida.inf_set_filetype(_v:filetype_t)→boolida_ida.inf_get_ostype()→ushortida_ida.inf_set_ostype(_v:ushort)→boolida_ida.inf_get_apptype()→ushortida_ida.inf_set_apptype(_v:ushort)→boolida_ida.inf_get_asmtype()→ucharida_ida.inf_set_asmtype(_v:uchar)→boolida_ida.inf_get_specsegs()→ucharida_ida.inf_set_specsegs(_v:uchar)→boolida_ida.inf_get_af()→intida_ida.inf_set_af(_v:int)→boolida_ida.inf_trace_flow()→boolida_ida.inf_set_trace_flow(_v:bool=True)→boolida_ida.inf_mark_code()→boolida_ida.inf_set_mark_code(_v:bool=True)→boolida_ida.inf_create_jump_tables()→boolida_ida.inf_set_create_jump_tables(_v:bool=True)→boolida_ida.inf_noflow_to_data()→boolida_ida.inf_set_noflow_to_data(_v:bool=True)→boolida_ida.inf_create_all_xrefs()→boolida_ida.inf_set_create_all_xrefs(_v:bool=True)→boolida_ida.inf_del_no_xref_insns()→boolida_ida.inf_set_del_no_xref_insns(_v:bool=True)→boolida_ida.inf_create_func_from_ptr()→boolida_ida.inf_set_create_func_from_ptr(_v:bool=True)→boolida_ida.inf_create_func_from_call()→boolida_ida.inf_set_create_func_from_call(_v:bool=True)→boolida_ida.inf_create_func_tails()→boolida_ida.inf_set_create_func_tails(_v:bool=True)→boolida_ida.inf_should_create_stkvars()→boolida_ida.inf_set_should_create_stkvars(_v:bool=True)→boolida_ida.inf_propagate_stkargs()→boolida_ida.inf_set_propagate_stkargs(_v:bool=True)→boolida_ida.inf_propagate_regargs()→boolida_ida.inf_set_propagate_regargs(_v:bool=True)→boolida_ida.inf_should_trace_sp()→boolida_ida.inf_set_should_trace_sp(_v:bool=True)→boolida_ida.inf_full_sp_ana()→boolida_ida.inf_set_full_sp_ana(_v:bool=True)→boolida_ida.inf_noret_ana()→boolida_ida.inf_set_noret_ana(_v:bool=True)→boolida_ida.inf_guess_func_type()→boolida_ida.inf_set_guess_func_type(_v:bool=True)→boolida_ida.inf_truncate_on_del()→boolida_ida.inf_set_truncate_on_del(_v:bool=True)→boolida_ida.inf_create_strlit_on_xref()→boolida_ida.inf_set_create_strlit_on_xref(_v:bool=True)→boolida_ida.inf_check_unicode_strlits()→boolida_ida.inf_set_check_unicode_strlits(_v:bool=True)→boolida_ida.inf_create_off_using_fixup()→boolida_ida.inf_set_create_off_using_fixup(_v:bool=True)→boolida_ida.inf_create_off_on_dref()→boolida_ida.inf_set_create_off_on_dref(_v:bool=True)→boolida_ida.inf_op_offset()→boolida_ida.inf_set_op_offset(_v:bool=True)→boolida_ida.inf_data_offset()→boolida_ida.inf_set_data_offset(_v:bool=True)→boolida_ida.inf_use_flirt()→boolida_ida.inf_set_use_flirt(_v:bool=True)→boolida_ida.inf_append_sigcmt()→boolida_ida.inf_set_append_sigcmt(_v:bool=True)→boolida_ida.inf_allow_sigmulti()→boolida_ida.inf_set_allow_sigmulti(_v:bool=True)→boolida_ida.inf_hide_libfuncs()→boolida_ida.inf_set_hide_libfuncs(_v:bool=True)→boolida_ida.inf_rename_jumpfunc()→boolida_ida.inf_set_rename_jumpfunc(_v:bool=True)→boolida_ida.inf_rename_nullsub()→boolida_ida.inf_set_rename_nullsub(_v:bool=True)→boolida_ida.inf_coagulate_data()→boolida_ida.inf_set_coagulate_data(_v:bool=True)→boolida_ida.inf_coagulate_code()→boolida_ida.inf_set_coagulate_code(_v:bool=True)→boolida_ida.inf_final_pass()→boolida_ida.inf_set_final_pass(_v:bool=True)→boolida_ida.inf_get_af2()→intida_ida.inf_set_af2(_v:int)→boolida_ida.inf_handle_eh()→boolida_ida.inf_set_handle_eh(_v:bool=True)→boolida_ida.inf_handle_rtti()→boolida_ida.inf_set_handle_rtti(_v:bool=True)→boolida_ida.inf_macros_enabled()→boolida_ida.inf_set_macros_enabled(_v:bool=True)→boolida_ida.inf_merge_strlits()→boolida_ida.inf_set_merge_strlits(_v:bool=True)→boolida_ida.inf_get_baseaddr()→intida_ida.inf_set_baseaddr(_v:int)→boolida_ida.inf_get_start_ss()→sel_tida_ida.inf_set_start_ss(_v:sel_t)→boolida_ida.inf_get_start_cs()→sel_tida_ida.inf_set_start_cs(_v:sel_t)→boolida_ida.inf_get_start_ip()→ida_idaapi.ea_tida_ida.inf_set_start_ip(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_start_ea()→ida_idaapi.ea_tida_ida.inf_set_start_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_start_sp()→ida_idaapi.ea_tida_ida.inf_set_start_sp(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_main()→ida_idaapi.ea_tida_ida.inf_set_main(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_min_ea()→ida_idaapi.ea_tida_ida.inf_set_min_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_max_ea()→ida_idaapi.ea_tida_ida.inf_set_max_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_omin_ea()→ida_idaapi.ea_tida_ida.inf_set_omin_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_omax_ea()→ida_idaapi.ea_tida_ida.inf_set_omax_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_lowoff()→ida_idaapi.ea_tida_ida.inf_set_lowoff(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_highoff()→ida_idaapi.ea_tida_ida.inf_set_highoff(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_maxref()→intida_ida.inf_set_maxref(_v:int)→boolida_ida.inf_get_netdelta()→intida_ida.inf_set_netdelta(_v:int)→boolida_ida.inf_get_xrefnum()→ucharida_ida.inf_set_xrefnum(_v:uchar)→boolida_ida.inf_get_type_xrefnum()→ucharida_ida.inf_set_type_xrefnum(_v:uchar)→boolida_ida.inf_get_refcmtnum()→ucharida_ida.inf_set_refcmtnum(_v:uchar)→boolida_ida.inf_get_xrefflag()→ucharida_ida.inf_set_xrefflag(_v:uchar)→boolida_ida.inf_show_xref_seg()→boolida_ida.inf_set_show_xref_seg(_v:bool=True)→boolida_ida.inf_show_xref_tmarks()→boolida_ida.inf_set_show_xref_tmarks(_v:bool=True)→boolida_ida.inf_show_xref_fncoff()→boolida_ida.inf_set_show_xref_fncoff(_v:bool=True)→boolida_ida.inf_show_xref_val()→boolida_ida.inf_set_show_xref_val(_v:bool=True)→boolida_ida.inf_get_max_autoname_len()→ushortida_ida.inf_set_max_autoname_len(_v:ushort)→boolida_ida.inf_get_nametype()→charida_ida.inf_set_nametype(_v:char)→boolida_ida.inf_get_short_demnames()→intida_ida.inf_set_short_demnames(_v:int)→boolida_ida.inf_get_long_demnames()→intida_ida.inf_set_long_demnames(_v:int)→boolida_ida.inf_get_demnames()→ucharida_ida.inf_set_demnames(_v:uchar)→boolida_ida.inf_get_listnames()→ucharida_ida.inf_set_listnames(_v:uchar)→boolida_ida.inf_get_indent()→ucharida_ida.inf_set_indent(_v:uchar)→boolida_ida.inf_get_cmt_indent()→ucharida_ida.inf_set_cmt_indent(_v:uchar)→boolida_ida.inf_get_margin()→ushortida_ida.inf_set_margin(_v:ushort)→boolida_ida.inf_get_lenxref()→ushortida_ida.inf_set_lenxref(_v:ushort)→boolida_ida.inf_get_outflags()→intida_ida.inf_set_outflags(_v:int)→boolida_ida.inf_show_void()→boolida_ida.inf_set_show_void(_v:bool=True)→boolida_ida.inf_show_auto()→boolida_ida.inf_set_show_auto(_v:bool=True)→boolida_ida.inf_gen_null()→boolida_ida.inf_set_gen_null(_v:bool=True)→boolida_ida.inf_show_line_pref()→boolida_ida.inf_set_show_line_pref(_v:bool=True)→boolida_ida.inf_line_pref_with_seg()→boolida_ida.inf_set_line_pref_with_seg(_v:bool=True)→boolida_ida.inf_gen_lzero()→boolida_ida.inf_set_gen_lzero(_v:bool=True)→boolida_ida.inf_gen_org()→boolida_ida.inf_set_gen_org(_v:bool=True)→boolida_ida.inf_gen_assume()→boolida_ida.inf_set_gen_assume(_v:bool=True)→boolida_ida.inf_gen_tryblks()→boolida_ida.inf_set_gen_tryblks(_v:bool=True)→boolida_ida.inf_get_cmtflg()→ucharida_ida.inf_set_cmtflg(_v:uchar)→boolida_ida.inf_show_repeatables()→boolida_ida.inf_set_show_repeatables(_v:bool=True)→boolida_ida.inf_show_all_comments()→boolida_ida.inf_set_show_all_comments(_v:bool=True)→boolida_ida.inf_hide_comments()→boolida_ida.inf_set_hide_comments(_v:bool=True)→boolida_ida.inf_show_src_linnum()→boolida_ida.inf_set_show_src_linnum(_v:bool=True)→boolida_ida.inf_test_mode()→boolida_ida.inf_show_hidden_insns()→boolida_ida.inf_set_show_hidden_insns(_v:bool=True)→boolida_ida.inf_show_hidden_funcs()→boolida_ida.inf_set_show_hidden_funcs(_v:bool=True)→boolida_ida.inf_show_hidden_segms()→boolida_ida.inf_set_show_hidden_segms(_v:bool=True)→boolida_ida.inf_get_limiter()→ucharida_ida.inf_set_limiter(_v:uchar)→boolida_ida.inf_is_limiter_thin()→boolida_ida.inf_set_limiter_thin(_v:bool=True)→boolida_ida.inf_is_limiter_thick()→boolida_ida.inf_set_limiter_thick(_v:bool=True)→boolida_ida.inf_is_limiter_empty()→boolida_ida.inf_set_limiter_empty(_v:bool=True)→boolida_ida.inf_get_bin_prefix_size()→shortida_ida.inf_set_bin_prefix_size(_v:short)→boolida_ida.inf_get_prefflag()→ucharida_ida.inf_set_prefflag(_v:uchar)→boolida_ida.inf_prefix_show_segaddr()→boolida_ida.inf_set_prefix_show_segaddr(_v:bool=True)→boolida_ida.inf_prefix_show_funcoff()→boolida_ida.inf_set_prefix_show_funcoff(_v:bool=True)→boolida_ida.inf_prefix_show_stack()→boolida_ida.inf_set_prefix_show_stack(_v:bool=True)→boolida_ida.inf_prefix_truncate_opcode_bytes()→boolida_ida.inf_set_prefix_truncate_opcode_bytes(_v:bool=True)→boolida_ida.inf_get_strlit_flags()→ucharida_ida.inf_set_strlit_flags(_v:uchar)→boolida_ida.inf_strlit_names()→boolida_ida.inf_set_strlit_names(_v:bool=True)→boolida_ida.inf_strlit_name_bit()→boolida_ida.inf_set_strlit_name_bit(_v:bool=True)→boolida_ida.inf_strlit_serial_names()→boolida_ida.inf_set_strlit_serial_names(_v:bool=True)→boolida_ida.inf_unicode_strlits()→boolida_ida.inf_set_unicode_strlits(_v:bool=True)→boolida_ida.inf_strlit_autocmt()→boolida_ida.inf_set_strlit_autocmt(_v:bool=True)→boolida_ida.inf_strlit_savecase()→boolida_ida.inf_set_strlit_savecase(_v:bool=True)→boolida_ida.inf_get_strlit_break()→ucharida_ida.inf_set_strlit_break(_v:uchar)→boolida_ida.inf_get_strlit_zeroes()→charida_ida.inf_set_strlit_zeroes(_v:char)→boolida_ida.inf_get_strtype()→intida_ida.inf_set_strtype(_v:int)→boolida_ida.inf_get_strlit_sernum()→intida_ida.inf_set_strlit_sernum(_v:int)→boolida_ida.inf_get_datatypes()→intida_ida.inf_set_datatypes(_v:int)→boolida_ida.inf_get_abibits()→intida_ida.inf_set_abibits(_v:int)→boolida_ida.inf_is_mem_aligned4()→boolida_ida.inf_set_mem_aligned4(_v:bool=True)→boolida_ida.inf_pack_stkargs(*args)→boolida_ida.inf_set_pack_stkargs(_v:bool=True)→boolida_ida.inf_big_arg_align(*args)→boolida_ida.inf_set_big_arg_align(_v:bool=True)→boolida_ida.inf_stack_ldbl()→boolida_ida.inf_set_stack_ldbl(_v:bool=True)→boolida_ida.inf_stack_varargs()→boolida_ida.inf_set_stack_varargs(_v:bool=True)→boolida_ida.inf_is_hard_float()→boolida_ida.inf_set_hard_float(_v:bool=True)→boolida_ida.inf_abi_set_by_user()→boolida_ida.inf_set_abi_set_by_user(_v:bool=True)→boolida_ida.inf_use_gcc_layout()→boolida_ida.inf_set_use_gcc_layout(_v:bool=True)→boolida_ida.inf_map_stkargs()→boolida_ida.inf_set_map_stkargs(_v:bool=True)→boolida_ida.inf_huge_arg_align(*args)→boolida_ida.inf_set_huge_arg_align(_v:bool=True)→boolida_ida.inf_get_appcall_options()→intida_ida.inf_set_appcall_options(_v:int)→boolida_ida.inf_get_privrange_start_ea()→ida_idaapi.ea_tida_ida.inf_set_privrange_start_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_privrange_end_ea()→ida_idaapi.ea_tida_ida.inf_set_privrange_end_ea(_v:ida_idaapi.ea_t)→boolida_ida.inf_get_cc_id()→comp_tida_ida.inf_set_cc_id(_v:comp_t)→boolida_ida.inf_get_cc_cm()→cm_tida_ida.inf_set_cc_cm(_v:cm_t)→boolida_ida.inf_get_callcnv()→callcnv_tida_ida.inf_set_callcnv(_v:callcnv_t)→boolida_ida.inf_get_cc_size_i()→ucharida_ida.inf_set_cc_size_i(_v:uchar)→boolida_ida.inf_get_cc_size_b()→ucharida_ida.inf_set_cc_size_b(_v:uchar)→boolida_ida.inf_get_cc_size_e()→ucharida_ida.inf_set_cc_size_e(_v:uchar)→boolida_ida.inf_get_cc_defalign()→ucharida_ida.inf_set_cc_defalign(_v:uchar)→boolida_ida.inf_get_cc_size_s()→ucharida_ida.inf_set_cc_size_s(_v:uchar)→boolida_ida.inf_get_cc_size_l()→ucharida_ida.inf_set_cc_size_l(_v:uchar)→boolida_ida.inf_get_cc_size_ll()→ucharida_ida.inf_set_cc_size_ll(_v:uchar)→boolida_ida.inf_get_cc_size_ldbl()→ucharida_ida.inf_set_cc_size_ldbl(_v:uchar)→boolida_ida.inf_get_procname()→strida_ida.inf_set_procname(*args)→boolida_ida.inf_get_strlit_pref()→strida_ida.inf_set_strlit_pref(*args)→boolida_ida.inf_get_cc(out:compiler_info_t)→boolida_ida.inf_set_cc(_v:compiler_info_t)→boolida_ida.inf_set_privrange(_v:range_t)→boolida_ida.inf_get_privrange(*args)→range_t
This function has the following signatures:

-
inf_get_privrange(out: range_t *) -> bool

-
inf_get_privrange() -> range_t

# 0: inf_get_privrange(out: range_t *) -> bool

# 1: inf_get_privrange() -> range_t
ida_ida.inf_get_af_low()→ushort
Get/set low/high 16-bit halves of inf.af.
ida_ida.inf_set_af_low(saf:ushort)→Noneida_ida.inf_get_af_high()→ushortida_ida.inf_set_af_high(saf2:ushort)→Noneida_ida.inf_get_af2_low()→ushort
Get/set low 16-bit half of inf.af2.
ida_ida.inf_set_af2_low(saf:ushort)→Noneida_ida.inf_get_pack_mode()→intida_ida.inf_set_pack_mode(pack_mode:int)→intida_ida.inf_inc_database_change_count(cnt:int=1)→Noneida_ida.inf_get_demname_form()→uchar
Get DEMNAM_MASK bits of #demnames.
ida_ida.inf_postinc_strlit_sernum(cnt:int=1)→intida_ida.inf_like_binary()→boolida_ida.UA_MAXOP
max number of operands allowed for an instruction
ida_ida.calc_default_idaplace_flags()→int
Get default disassembly line options.
ida_ida.to_ea(reg_cs:sel_t, reg_ip:int)→ida_idaapi.ea_t
Convert (sel,off) value to a linear address.
ida_ida.IDB_EXT32ida_ida.IDB_EXT64ida_ida.IDB_EXTida_ida.get_dbctx_id()→ssize_t
Get the current database context ID
Returns:
the database context ID, or -1 if no current database
ida_ida.get_dbctx_qty()→int
Get number of database contexts
Returns:
number of database contexts
ida_ida.switch_dbctx(idx:int)→dbctx_t*
Switch to the database with the provided context ID
Parameters:
idx – the index of the database to switch to
Returns:
the current dbctx_t instance or nullptr
ida_ida.is_database_busy()→bool
Check if the database is busy (e.g. performing some critical operations and cannot be safely accessed)
ida_ida.validate_idb(vld_flags:int=0)→int
Validate the database
Parameters:
vld_flags – combination of VLD_.. constants
Returns:
number of corrupted/fixed records
ida_ida.VLD_AUTO_REPAIR
automatically repair the database
ida_ida.VLD_DIALOG
ask user to repair (this bit is mutually exclusive with VLD_AUTO_REPAIR)
ida_ida.VLD_SILENT
no messages to the output window
ida_ida.move_privrange(new_privrange_start:ida_idaapi.ea_t)→bool
Move privrange to the specified address
Parameters:
new_privrange_start – new start address of the privrange
Returns:
success
classida_ida.idbattr_valmap_t
Bases: `object`
thisownvalue:uint64valname:strclassida_ida.idbattr_info_t(name:str, offset:uintptr_t, width:int, bitmask:uint64=0, tag:uchar=0, idi_flags:uint=0)
Bases: `object`
thisownname:str
human-readable name. if null, then the field will not be merged as part of INF.
offset:uintptr_t
field position: offset within a structure (IDI_STRUCFLD) altval or supval index (IDI_NODEVAL) hashval name (IDI_ALTVAL/IDI_SUPVAL+IDI_HASH)
width:int
field width in bytes
bitmask:uint64
mask for bitfields (0-not bitfield)
tag:uchar
tag of node value (if IDI_NODEVAL is set)
vmap:idbattr_valmap_tconst*
array value=>name (terminated by empty element)
individual_node:str
individual node name (nullptr - use default)
idi_flags:uintmaxsize:int
max bytes reserved for storage in netnode
is_node_altval()→boolis_node_supval()→boolis_node_valobj()→boolis_node_blob()→boolis_node_var()→boolis_struc_field()→boolis_cstr()→boolis_qstring()→boolis_bytearray()→boolis_buf_var()→boolis_decimal()→boolis_hexadecimal()→boolis_readonly_var()→boolis_incremented()→boolis_val_mapped()→boolis_hash()→booluse_hlpstruc()→boolis_bitmap()→boolis_onoff()→boolis_scalar_var()→boolis_bitfield()→boolis_boolean()→boolhas_individual_node()→boolstr_true()→strstr_false()→strridx()→inthashname()→strida_ida.IDI_STRUCFLD
structure field (opposite to IDI_NODEVAL)
ida_ida.IDI_ALTVAL
netnode: altval
ida_ida.IDI_SUPVAL
netnode: supval
ida_ida.IDI_VALOBJ
netnode: valobj
ida_ida.IDI_BLOB
netnode: blob
ida_ida.IDI_SCALAR
scalar value (default)
ida_ida.IDI_CSTR
string
ida_ida.IDI_QSTRING
qstring
ida_ida.IDI_BYTEARRAY
byte array: binary representation
ida_ida.IDI_EA_HEX
default representation: hex or “BADADDR”
ida_ida.IDI_DEC
show as decimal
ida_ida.IDI_HEX
show as hexadecimal
ida_ida.IDI_INC
stored value is incremented (scalars only)
ida_ida.IDI_MAP_VAL
apply ea2node() to value
ida_ida.IDI_HASH
hashed node field, hash name in offset
ida_ida.IDI_HLPSTRUC
call helper for pointer to structure
ida_ida.IDI_READONLY
read-only field (cannot be modified)
ida_ida.IDI_BITMAP
bitmap field: interpret bitmask as bit number
ida_ida.IDI_ONOFF
show boolean as on/off (not true/false)
ida_ida.IDI_NOMERGE
field should not be merged as part of INF
ida_ida.IDI_NODEVALida_ida.IDI_BUFVARida_ida.idainfo_big_arg_alignida_ida.idainfo_gen_nullida_ida.idainfo_set_gen_nullida_ida.idainfo_gen_lzeroida_ida.idainfo_set_gen_lzeroida_ida.idainfo_gen_tryblksida_ida.idainfo_set_gen_tryblksida_ida.idainfo_get_demname_formida_ida.idainfo_get_pack_modeida_ida.idainfo_set_pack_modeida_ida.idainfo_is_32bit()ida_ida.idainfo_is_64bitida_ida.idainfo_set_64bitida_ida.idainfo_is_auto_enabledida_ida.idainfo_set_auto_enabledida_ida.idainfo_is_beida_ida.idainfo_set_beida_ida.idainfo_is_dllida_ida.idainfo_is_flat_off32ida_ida.idainfo_is_graph_viewida_ida.idainfo_set_graph_viewida_ida.idainfo_is_hard_floatida_ida.idainfo_is_kernel_modeida_ida.idainfo_is_mem_aligned4ida_ida.idainfo_is_snapshotida_ida.idainfo_is_wide_high_byte_firstida_ida.idainfo_set_wide_high_byte_firstida_ida.idainfo_like_binaryida_ida.idainfo_line_pref_with_segida_ida.idainfo_set_line_pref_with_segida_ida.idainfo_show_autoida_ida.idainfo_set_show_autoida_ida.idainfo_show_line_prefida_ida.idainfo_set_show_line_prefida_ida.idainfo_show_voidida_ida.idainfo_set_show_voidida_ida.idainfo_loading_idcida_ida.idainfo_map_stkargsida_ida.idainfo_pack_stkargsida_ida.idainfo_readonly_idbida_ida.idainfo_set_store_user_infoida_ida.idainfo_stack_ldblida_ida.idainfo_stack_varargsida_ida.idainfo_use_allasmida_ida.idainfo_use_gcc_layoutida_ida.macros_enabledida_ida.should_create_stkvarsida_ida.should_trace_spida_ida.show_all_commentsida_ida.show_commentsida_ida.show_repeatablesida_ida.inf_get_commentida_ida.inf_set_commentida_ida.idainfo_comment_getida_ida.idainfo_comment_set
