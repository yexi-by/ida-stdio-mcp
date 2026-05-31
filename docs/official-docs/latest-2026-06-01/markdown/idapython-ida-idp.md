# IDAPython processor module API

- 官方来源：https://python.docs.hex-rays.com/ida_idp/index.html

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
- ida_idp
- View page source

# ida_idp

Contains definition of the interface to IDP modules.

The interface consists of two structures: * definition of target assembler: ::ash * definition of current processor: ::ph

These structures contain information about target processor and assembler features. It also defines two groups of kernel events: * processor_t::event_t processor related events * idb_event:event_code_t database related events

The processor related events are used to communicate with the processor module. The database related events are used to inform any interested parties, like plugins or processor modules, about the changes in the database.

## Attributes

`IDP_INTERFACE_VERSION`
|
The interface version number.

`CF_STOP`
|
Instruction doesn't pass execution to the next instruction

`CF_CALL`
|
CALL instruction (should make a procedure here)

`CF_CHG1`
|
The instruction modifies the first operand.

`CF_CHG2`
|
The instruction modifies the second operand.

`CF_CHG3`
|
The instruction modifies the third operand.

`CF_CHG4`
|
The instruction modifies the fourth operand.

`CF_CHG5`
|
The instruction modifies the fifth operand.

`CF_CHG6`
|
The instruction modifies the sixth operand.

`CF_USE1`
|
The instruction uses value of the first operand.

`CF_USE2`
|
The instruction uses value of the second operand.

`CF_USE3`
|
The instruction uses value of the third operand.

`CF_USE4`
|
The instruction uses value of the fourth operand.

`CF_USE5`
|
The instruction uses value of the fifth operand.

`CF_USE6`
|
The instruction uses value of the sixth operand.

`CF_JUMP`
|
The instruction passes execution using indirect jump or call (thus needs additional analysis)

`CF_SHFT`
|
Bit-shift instruction (shl,shr...)

`CF_HLL`
|
Instruction may be present in a high level language function

`CF_CHG7`
|
The instruction modifies the seventh operand.

`CF_CHG8`
|
The instruction modifies the eighth operand.

`CF_USE7`
|
The instruction uses value of the seventh operand.

`CF_USE8`
|
The instruction uses value of the eighth operand

`IRI_EXTENDED`
|
Is the instruction a "return"?

`IRI_RET_LITERALLY`
|
report only 'ret' instructions

`IRI_SKIP_RETTARGET`
|
exclude 'ret' instructions that have special targets (see set_ret_target in PC)

`IRI_STRICT`
|

`AS_OFFST`
|
offsets are 'offset xxx' ?

`AS_COLON`
|
create colons after data names ?

`AS_UDATA`
|
can use '?' in data directives

`AS_2CHRE`
|
double char constants are: "xy

`AS_NCHRE`
|
char constants are: 'x

`AS_N2CHR`
|
can't have 2 byte char consts

`AS_1TEXT`
|
1 text per line, no bytes

`AS_NHIAS`
|
no characters with high bit

`AS_NCMAS`
|
no commas in ascii directives

`AS_HEXFM`
|
mask - hex number format

`ASH_HEXF0`
|
34h

`ASH_HEXF1`
|
h'34

`ASH_HEXF2`
|
34

`ASH_HEXF3`
|
0x34

`ASH_HEXF4`
|
$34

`ASH_HEXF5`
|
 (radix)

`AS_DECFM`
|
mask - decimal number format

`ASD_DECF0`
|
34

`ASD_DECF1`
|
#34

`ASD_DECF2`
|

`ASD_DECF3`
|
.34

`AS_OCTFM`
|
mask - octal number format

`ASO_OCTF0`
|
123o

`ASO_OCTF1`
|
0123

`ASO_OCTF2`
|
123

`ASO_OCTF3`
|
@123

`ASO_OCTF4`
|
o'123

`ASO_OCTF5`
|
123q

`ASO_OCTF6`
|
~123

`ASO_OCTF7`
|
q'123

`AS_BINFM`
|
mask - binary number format

`ASB_BINF0`
|
010101b

`ASB_BINF1`
|
^B010101

`ASB_BINF2`
|
%010101

`ASB_BINF3`
|
0b1010101

`ASB_BINF4`
|
b'1010101

`ASB_BINF5`
|
b'1010101'

`AS_UNEQU`
|
replace undefined data items with EQU (for ANTA's A80)

`AS_ONEDUP`
|
One array definition per line.

`AS_NOXRF`
|
Disable xrefs during the output file generation.

`AS_XTRNTYPE`
|
Assembler understands type of extern symbols as ":type" suffix.

`AS_RELSUP`
|
Checkarg: 'and','or','xor' operations with addresses are possible.

`AS_LALIGN`
|
Labels at "align" keyword are supported.

`AS_NOCODECLN`
|
don't create colons after code names

`AS_NOSPACE`
|
No spaces in expressions.

`AS_ALIGN2`
|
.align directive expects an exponent rather than a power of 2 (.align 5 means to align at 32byte boundary)

`AS_ASCIIC`
|
ascii directive accepts C-like escape sequences (n,x01 and similar)

`AS_ASCIIZ`
|
ascii directive inserts implicit zero byte at the end

`AS2_BRACE`
|
Use braces for all expressions.

`AS2_STRINV`
|
Invert meaning of idainfo::wide_high_byte_first for text strings (for processors with bytes bigger than 8 bits)

`AS2_BYTE1CHAR`
|
One symbol per processor byte. Meaningful only for wide byte processors

`AS2_IDEALDSCR`
|
Description of struc/union is in the 'reverse' form (keyword before name), the same as in borland tasm ideal

`AS2_TERSESTR`
|
'terse' structure initialization form; NAME is supported

`AS2_COLONSUF`
|
addresses may have ":xx" suffix; this suffix must be ignored when extracting the address under the cursor

`AS2_YWORD`
|
a_yword field is present and valid

`AS2_ZWORD`
|
a_zword field is present and valid

`HKCB_GLOBAL`
|
is global event listener? if true, the listener will survive database closing and opening. it will stay in the memory until explicitly unhooked. otherwise the kernel will delete it as soon as the owner is unloaded. should be used only with PLUGIN_FIX plugins.

`PLFM_386`
|
Intel 80x86.

`PLFM_Z80`
|
8085, Z80

`PLFM_I860`
|
Intel 860.

`PLFM_8051`
|
8051

`PLFM_TMS`
|
Texas Instruments TMS320C5x.

`PLFM_6502`
|
6502

`PLFM_PDP`
|
PDP11.

`PLFM_68K`
|
Motorola 680x0.

`PLFM_JAVA`
|
Java.

`PLFM_6800`
|
Motorola 68xx.

`PLFM_ST7`
|
SGS-Thomson ST7.

`PLFM_MC6812`
|
Motorola 68HC12.

`PLFM_MIPS`
|
MIPS.

`PLFM_ARM`
|
Advanced RISC Machines.

`PLFM_TMSC6`
|
Texas Instruments TMS320C6x.

`PLFM_PPC`
|
PowerPC.

`PLFM_80196`
|
Intel 80196.

`PLFM_Z8`
|
Z8.

`PLFM_SH`
|
Renesas (formerly Hitachi) SuperH.

`PLFM_NET`
|
Microsoft Visual Studio.Net.

`PLFM_AVR`
|
Atmel 8-bit RISC processor(s)

`PLFM_H8`
|
Hitachi H8/300, H8/2000.

`PLFM_PIC`
|
Microchip's PIC.

`PLFM_SPARC`
|
SPARC.

`PLFM_ALPHA`
|
DEC Alpha.

`PLFM_HPPA`
|
Hewlett-Packard PA-RISC.

`PLFM_H8500`
|
Hitachi H8/500.

`PLFM_TRICORE`
|
Tasking Tricore.

`PLFM_DSP56K`
|
Motorola DSP5600x.

`PLFM_C166`
|
Siemens C166 family.

`PLFM_ST20`
|
SGS-Thomson ST20.

`PLFM_IA64`
|
Intel Itanium IA64.

`PLFM_I960`
|
Intel 960.

`PLFM_F2MC`
|
Fujitsu F2MC-16.

`PLFM_TMS320C54`
|
Texas Instruments TMS320C54xx.

`PLFM_TMS320C55`
|
Texas Instruments TMS320C55xx.

`PLFM_TRIMEDIA`
|
Trimedia.

`PLFM_M32R`
|
Mitsubishi 32-bit RISC.

`PLFM_NEC_78K0`
|
NEC 78K0.

`PLFM_NEC_78K0S`
|
NEC 78K0S.

`PLFM_M740`
|
Mitsubishi 8bit.

`PLFM_M7700`
|
Mitsubishi 16-bit.

`PLFM_ST9`
|
ST9+.

`PLFM_FR`
|
Fujitsu FR Family.

`PLFM_MC6816`
|
Motorola 68HC16.

`PLFM_M7900`
|
Mitsubishi 7900.

`PLFM_TMS320C3`
|
Texas Instruments TMS320C3.

`PLFM_KR1878`
|
Angstrem KR1878.

`PLFM_AD218X`
|
Analog Devices ADSP 218X.

`PLFM_OAKDSP`
|
Atmel OAK DSP.

`PLFM_TLCS900`
|
Toshiba TLCS-900.

`PLFM_C39`
|
Rockwell C39.

`PLFM_CR16`
|
NSC CR16.

`PLFM_MN102L00`
|
Panasonic MN10200.

`PLFM_TMS320C1X`
|
Texas Instruments TMS320C1x.

`PLFM_NEC_V850X`
|
NEC V850 and V850ES/E1/E2.

`PLFM_SCR_ADPT`
|
Processor module adapter for processor modules written in scripting languages.

`PLFM_EBC`
|
EFI Bytecode.

`PLFM_MSP430`
|
Texas Instruments MSP430.

`PLFM_SPU`
|
Cell Broadband Engine Synergistic Processor Unit.

`PLFM_DALVIK`
|
Android Dalvik Virtual Machine.

`PLFM_65C816`
|
65802/65816

`PLFM_M16C`
|
Renesas M16C.

`PLFM_ARC`
|
Argonaut RISC Core.

`PLFM_UNSP`
|
SunPlus unSP.

`PLFM_TMS320C28`
|
Texas Instruments TMS320C28x.

`PLFM_DSP96K`
|
Motorola DSP96000.

`PLFM_SPC700`
|
Sony SPC700.

`PLFM_AD2106X`
|
Analog Devices ADSP 2106X.

`PLFM_PIC16`
|
Microchip's 16-bit PIC.

`PLFM_S390`
|
IBM's S390.

`PLFM_XTENSA`
|
Tensilica Xtensa.

`PLFM_RISCV`
|
RISC-V.

`PLFM_RL78`
|
Renesas RL78.

`PLFM_RX`
|
Renesas RX.

`PLFM_WASM`
|
WASM.

`PLFM_NDS32`
|
Andes Technology NDS32.

`PR_SEGS`
|
has segment registers?

`PR_USE32`
|
supports 32-bit addressing?

`PR_DEFSEG32`
|
segments are 32-bit by default

`PR_RNAMESOK`
|
allow user register names for location names

`PR_ADJSEGS`
|
IDA may adjust segments' starting/ending addresses.

`PR_DEFNUM`
|
mask - default number representation

`PRN_HEX`
|
hex

`PRN_OCT`
|
octal

`PRN_DEC`
|
decimal

`PRN_BIN`
|
binary

`PR_WORD_INS`
|
instruction codes are grouped 2bytes in binary line prefix

`PR_NOCHANGE`
|
The user can't change segments and code/data attributes (display only)

`PR_ASSEMBLE`
|
Module has a built-in assembler and will react to ev_assemble.

`PR_ALIGN`
|
All data items should be aligned properly.

`PR_TYPEINFO`
|
the processor module fully supports type information callbacks; without full support, function argument locations and other things will probably be wrong.

`PR_USE64`
|
supports 64-bit addressing?

`PR_SGROTHER`
|
the segment registers don't contain the segment selectors.

`PR_STACK_UP`
|
the stack grows up

`PR_BINMEM`
|
the processor module provides correct segmentation for binary files (i.e. it creates additional segments). The kernel will not ask the user to specify the RAM/ROM sizes

`PR_SEGTRANS`
|
the processor module supports the segment translation feature (meaning it calculates the code addresses using the map_code_ea() function)

`PR_CHK_XREF`
|
don't allow near xrefs between segments with different bases

`PR_NO_SEGMOVE`
|
the processor module doesn't support move_segm() (i.e. the user can't move segments)

`PR_USE_ARG_TYPES`
|
use processor_t::use_arg_types callback

`PR_SCALE_STKVARS`
|
use processor_t::get_stkvar_scale callback

`PR_DELAYED`
|
has delayed jumps and calls. If this flag is set, processor_t::is_basic_block_end, processor_t::delay_slot_insn should be implemented

`PR_ALIGN_INSN`
|
allow ida to create alignment instructions arbitrarily. Since these instructions might lead to other wrong instructions and spoil the listing, IDA does not create them by default anymore

`PR_PURGING`
|
there are calling conventions which may purge bytes from the stack

`PR_CNDINSNS`
|
has conditional instructions

`PR_USE_TBYTE`
|
BTMT_SPECFLT means _TBYTE type

`PR_DEFSEG64`
|
segments are 64-bit by default

`PR_OUTER`
|
has outer operands (currently only mc68k)

`PR2_MAPPINGS`
|
the processor module uses memory mapping

`PR2_IDP_OPTS`
|
the module has processor-specific configuration options

`PR2_CODE16_BIT`
|
low bit of code addresses has special meaning e.g. ARM Thumb, MIPS16

`PR2_MACRO`
|
processor supports macro instructions

`PR2_USE_CALCREL`
|
(Lumina) the module supports calcrel info

`PR2_REL_BITS`
|
(Lumina) calcrel info has bits granularity, not bytes - construction flag only

`PR2_FORCE_16BIT`
|
use 16-bit basic types despite of 32-bit segments (used by c166)

`PR2_IGNORE_IDA_GUESS`
|
allow to create items inside the IDA-guessed data arrays

`OP_FP_BASED`
|
operand is FP based

`OP_SP_BASED`
|
operand is SP based

`OP_SP_ADD`
|
operand value is added to the pointer

`OP_SP_SUB`
|
operand value is subtracted from the pointer

`CUSTOM_INSN_ITYPE`
|
Custom instruction codes defined by processor extension plugins must be greater than or equal to this

`REG_SPOIL`
|
processor_t::use_regarg_type uses this bit in the return value to indicate that the register value has been spoiled

`NO_ACCESS`
|

`WRITE_ACCESS`
|

`READ_ACCESS`
|

`RW_ACCESS`
|

`SETPROC_IDB`
|
set processor type for old idb

`SETPROC_LOADER`
|
set processor type for new idb; if the user has specified a compatible processor, return success without changing it. if failure, call loader_failure()

`SETPROC_LOADER_NON_FATAL`
|
the same as SETPROC_LOADER but non-fatal failures.

`SETPROC_USER`
|
set user-specified processor used for -p and manual processor change at later time

`LTC_NONE`
|
no event (internal use)

`LTC_ADDED`
|
added a local type

`LTC_DELETED`
|
deleted a local type

`LTC_EDITED`
|
edited a local type

`LTC_ALIASED`
|
added a type alias

`LTC_COMPILER`
|
changed the compiler and calling convention

`LTC_TIL_LOADED`
|
loaded a til file

`LTC_TIL_UNLOADED`
|
unloaded a til file

`LTC_TIL_COMPACTED`
|
numbered types have been compacted compact_numbered_types()

`closebase`
|

`savebase`
|

`upgraded`
|

`auto_empty`
|

`auto_empty_finally`
|

`determined_main`
|

`extlang_changed`
|

`idasgn_loaded`
|

`kernel_config_loaded`
|

`loader_finished`
|

`flow_chart_created`
|

`compiler_changed`
|

`changing_ti`
|

`ti_changed`
|

`changing_op_ti`
|

`op_ti_changed`
|

`changing_op_type`
|

`op_type_changed`
|

`segm_added`
|

`deleting_segm`
|

`segm_deleted`
|

`changing_segm_start`
|

`segm_start_changed`
|

`changing_segm_end`
|

`segm_end_changed`
|

`changing_segm_name`
|

`segm_name_changed`
|

`changing_segm_class`
|

`segm_class_changed`
|

`segm_attrs_updated`
|

`segm_moved`
|

`allsegs_moved`
|

`func_added`
|

`func_updated`
|

`set_func_start`
|

`set_func_end`
|

`deleting_func`
|

`frame_deleted`
|

`thunk_func_created`
|

`func_tail_appended`
|

`deleting_func_tail`
|

`func_tail_deleted`
|

`tail_owner_changed`
|

`func_noret_changed`
|

`stkpnts_changed`
|

`updating_tryblks`
|

`tryblks_updated`
|

`deleting_tryblks`
|

`sgr_changed`
|

`make_code`
|

`make_data`
|

`destroyed_items`
|

`renamed`
|

`byte_patched`
|

`changing_cmt`
|

`cmt_changed`
|

`changing_range_cmt`
|

`range_cmt_changed`
|

`extra_cmt_changed`
|

`item_color_changed`
|

`callee_addr_changed`
|

`bookmark_changed`
|

`sgr_deleted`
|

`adding_segm`
|

`func_deleted`
|

`dirtree_mkdir`
|

`dirtree_rmdir`
|

`dirtree_link`
|

`dirtree_move`
|

`dirtree_rank`
|

`dirtree_rminode`
|

`dirtree_segm_moved`
|

`local_types_changed`
|

`lt_udm_created`
|

`lt_udm_deleted`
|

`lt_udm_renamed`
|

`lt_udm_changed`
|

`lt_udt_expanded`
|

`frame_created`
|

`frame_udm_created`
|

`frame_udm_deleted`
|

`frame_udm_renamed`
|

`frame_udm_changed`
|

`frame_expanded`
|

`idasgn_matched_ea`
|

`lt_edm_created`
|

`lt_edm_deleted`
|

`lt_edm_renamed`
|

`lt_edm_changed`
|

`local_type_renamed`
|

`dirtree_ordering_changed`
|

`dirtree_bulk_move`
|

`IDPOPT_CST`
|

`IDPOPT_JVL`
|

`IDPOPT_PRI_DEFAULT`
|

`IDPOPT_PRI_HIGH`
|

`IDPOPT_NUM_INT`
|

`IDPOPT_NUM_CHAR`
|

`IDPOPT_NUM_SHORT`
|

`IDPOPT_NUM_RANGE`
|

`IDPOPT_NUM_UNS`
|

`IDPOPT_BIT_UINT`
|

`IDPOPT_BIT_UCHAR`
|

`IDPOPT_BIT_USHORT`
|

`IDPOPT_BIT_BOOL`
|

`IDPOPT_STR_QSTRING`
|

`IDPOPT_STR_LONG`
|

`IDPOPT_I64_RANGE`
|

`IDPOPT_I64_UNS`
|

`IDPOPT_CST_PARAMS`
|

`IDPOPT_MBROFF`
|

`cik_string`
|

`cik_filename`
|

`cik_path`
|

`REAL_ERROR_FORMAT`
|

`REAL_ERROR_RANGE`
|

`REAL_ERROR_BADDATA`
|

`IDPOPT_STR`
|

`IDPOPT_NUM`
|

`IDPOPT_BIT`
|

`IDPOPT_FLT`
|

`IDPOPT_I64`
|

`IDPOPT_OK`
|

`IDPOPT_BADKEY`
|

`IDPOPT_BADTYPE`
|

`IDPOPT_BADVALUE`
|

`ph`
|

## Classes

`reg_access_vec_t`
|

`asm_t`
|

`reg_info_t`
|

`reg_access_t`
|

`reg_accesses_t`
|

`num_range_t`
|

`params_t`
|

`IDP_Hooks`
|

`processor_t`
|

`IDB_Hooks`
|

## Functions

`has_cf_chg`(→ bool)
|
Does an instruction with the specified feature modify the i-th operand?

`has_cf_use`(→ bool)
|
Does an instruction with the specified feature use a value of the i-th operand?

`has_insn_feature`(→ bool)
|
Does the specified instruction have the specified feature?

`is_call_insn`(→ bool)
|
Is the instruction a "call"?

`is_ret_insn`(→ bool)
|

`is_indirect_jump_insn`(→ bool)
|
Is the instruction an indirect jump?

`is_basic_block_end`(→ bool)
|
Is the instruction the end of a basic block?

`get_ph`(→ processor_t *)
|

`get_ash`(→ asm_t *)
|

`str2reg`(→ int)
|
Get any register number (-1 on error)

`is_align_insn`(→ int)
|
If the instruction at 'ea' looks like an alignment instruction, return its length in bytes. Otherwise return 0.

`get_reg_name`(→ str)
|
Get text representation of a register. For most processors this function will just return processor_t::reg_names[reg]. If the processor module has implemented processor_t::get_reg_name, it will be used instead

`parse_reg_name`(→ bool)
|
Get register info by name.

`set_processor_type`(→ bool)
|
Set target processor type. Once a processor module is loaded, it cannot be replaced until we close the idb.

`get_idp_name`(→ str)
|
Get name of the current processor module. The name is derived from the file name. For example, for IBM PC the module is named "pc.w32" (windows version), then the module name is "PC" (uppercase). If no processor module is loaded, this function will return nullptr

`set_target_assembler`(→ bool)
|
Set target assembler.

`gen_idb_event`(→ None)
|
the kernel will use this function to generate idb_events

`register_cfgopts`(→ bool)
|

`get_config_value`(→ jvalue_t *)
|

`cfg_get_cc_parm`(→ str)
|

`cfg_get_cc_header_path`(→ str)
|

`cfg_get_cc_predefined_macros`(→ str)
|

`process_config_directive`(→ None)
|

`AssembleLine`(ea, cs, ip, use32, line)
|
Assemble an instruction to a string (display a warning if an error is found)

`assemble`(ea, cs, ip, use32, line)
|
Assemble an instruction into the database (display a warning if an error is found)

`ph_get_id`()
|
Returns the 'ph.id' field

`ph_get_version`()
|
Returns the 'ph.version'

`ph_get_flag`()
|
Returns the 'ph.flag'

`ph_get_cnbits`()
|
Returns the 'ph.cnbits'

`ph_get_dnbits`()
|
Returns the 'ph.dnbits'

`ph_get_reg_first_sreg`()
|
Returns the 'ph.reg_first_sreg'

`ph_get_reg_last_sreg`()
|
Returns the 'ph.reg_last_sreg'

`ph_get_segreg_size`()
|
Returns the 'ph.segreg_size'

`ph_get_reg_code_sreg`()
|
Returns the 'ph.reg_code_sreg'

`ph_get_reg_data_sreg`()
|
Returns the 'ph.reg_data_sreg'

`ph_get_icode_return`()
|
Returns the 'ph.icode_return'

`ph_get_instruc_start`()
|
Returns the 'ph.instruc_start'

`ph_get_instruc_end`()
|
Returns the 'ph.instruc_end'

`ph_get_tbyte_size`()
|
Returns the 'ph.tbyte_size' field as defined in he processor module

`ph_get_instruc`()
|
Returns a list of tuples (instruction_name, instruction_feature) containing the

`ph_get_regnames`()
|
Returns the list of register names as defined in the processor module

`ph_get_operand_info`(→ Union[Tuple[int, ...)
|
Returns the operand information given an ea and operand number.

`ph_calcrel`(→ bytevec_t *, size_t *)
|

`ph_find_reg_value`(→ uint64 *)
|

`ph_find_op_value`(→ uint64 *)
|

`ph_get_reg_accesses`(→ ssize_t)
|

`ph_get_abi_info`(→ qstrvec_t *, qstrvec_t *)
|

`get_idp_notifier_addr`(→ PyObject *)
|

`get_idp_notifier_ud_addr`(→ PyObject *)
|

`delay_slot_insn`(→ bool)
|

`get_reg_info`(→ str)
|

`sizeof_ldbl`(→ int)
|

`str2sreg`(name)
|
get segment register number from its name or -1

`get_idb_notifier_addr`(→ PyObject *)
|

`get_idb_notifier_ud_addr`(→ PyObject *)
|

## Module Contents

classida_idp.reg_access_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→reg_access_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→reg_access_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:reg_access_vec_t)→Noneextract()→reg_access_t*inject(s:reg_access_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:reg_access_t, x:reg_access_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:reg_access_t)→booladd_unique(x:reg_access_t)→boolappend(x:reg_access_t)→Noneextend(x:reg_access_vec_t)→Nonefrontbackida_idp.IDP_INTERFACE_VERSION
The interface version number.
ida_idp.CF_STOP
Instruction doesn’t pass execution to the next instruction
ida_idp.CF_CALL
CALL instruction (should make a procedure here)
ida_idp.CF_CHG1
The instruction modifies the first operand.
ida_idp.CF_CHG2
The instruction modifies the second operand.
ida_idp.CF_CHG3
The instruction modifies the third operand.
ida_idp.CF_CHG4
The instruction modifies the fourth operand.
ida_idp.CF_CHG5
The instruction modifies the fifth operand.
ida_idp.CF_CHG6
The instruction modifies the sixth operand.
ida_idp.CF_USE1
The instruction uses value of the first operand.
ida_idp.CF_USE2
The instruction uses value of the second operand.
ida_idp.CF_USE3
The instruction uses value of the third operand.
ida_idp.CF_USE4
The instruction uses value of the fourth operand.
ida_idp.CF_USE5
The instruction uses value of the fifth operand.
ida_idp.CF_USE6
The instruction uses value of the sixth operand.
ida_idp.CF_JUMP
The instruction passes execution using indirect jump or call (thus needs additional analysis)
ida_idp.CF_SHFT
Bit-shift instruction (shl,shr…)
ida_idp.CF_HLL
Instruction may be present in a high level language function
ida_idp.CF_CHG7
The instruction modifies the seventh operand.
ida_idp.CF_CHG8
The instruction modifies the eighth operand.
ida_idp.CF_USE7
The instruction uses value of the seventh operand.
ida_idp.CF_USE8
The instruction uses value of the eighth operand
ida_idp.has_cf_chg(feature:int, opnum:uint)→bool
Does an instruction with the specified feature modify the i-th operand?
ida_idp.has_cf_use(feature:int, opnum:uint)→bool
Does an instruction with the specified feature use a value of the i-th operand?
ida_idp.has_insn_feature(icode:uint16, bit:int)→bool
Does the specified instruction have the specified feature?
ida_idp.is_call_insn(insn:insn_tconst&)→bool
Is the instruction a “call”?
ida_idp.IRI_EXTENDED
Is the instruction a “return”?

include instructions like “leave” that begin the function epilog
ida_idp.IRI_RET_LITERALLY
report only ‘ret’ instructions
ida_idp.IRI_SKIP_RETTARGET
exclude ‘ret’ instructions that have special targets (see set_ret_target in PC)
ida_idp.IRI_STRICTida_idp.is_ret_insn(*args)→boolida_idp.is_indirect_jump_insn(insn:insn_tconst&)→bool
Is the instruction an indirect jump?
ida_idp.is_basic_block_end(insn:insn_tconst&, call_insn_stops_block:bool)→bool
Is the instruction the end of a basic block?
classida_idp.asm_t
Bases: `object`
thisownflag:int
Assembler feature bits
uflag:uint16
user defined flags (local only for IDP) you may define and use your own bits
name:str
Assembler name (displayed in menus)
help:help_t
Help screen number, 0 - no help.
header:charconst*const*
array of automatically generated header lines they appear at the start of disassembled text
origin:str
org directive
end:str
end directive
cmnt:str
comment string (see also cmnt2)
ascsep:char
string literal delimiter
accsep:char
char constant delimiter
esccodes:str
special chars that cannot appear as is in string and char literals
a_ascii:str
string literal directive
a_byte:str
byte directive
a_word:str
word directive
a_dword:str
nullptr if not allowed
a_qword:str
nullptr if not allowed
a_oword:str
nullptr if not allowed
a_float:str
float; 4bytes; nullptr if not allowed
a_double:str
double; 8bytes; nullptr if not allowed
a_tbyte:str
long double; nullptr if not allowed
a_packreal:str
packed decimal real nullptr if not allowed
a_dups:str
array keyword. the following sequences may appear: * #h header * #d size * #v value * #s(b,w,l,q,f,d,o) size specifiers for byte,word, dword,qword, float,double,oword
a_bss:str
uninitialized data directive should include ‘s’ for the size of data
a_equ:str
‘equ’ Used if AS_UNEQU is set
a_seg:str
‘seg ‘ prefix (example: push seg seg001)
a_curip:str
current IP (instruction pointer) symbol in assembler
a_public:str
“public” name keyword. nullptr-use default, “”-do not generate
a_weak:str
“weak” name keyword. nullptr-use default, “”-do not generate
a_extrn:str
“extern” name keyword
a_comdef:str
“comm” (communal variable)
a_align:str
“align” keyword
lbrace:char
left brace used in complex expressions
rbrace:char
right brace used in complex expressions
a_mod:str
% mod assembler time operation
a_band:str
& bit and assembler time operation
a_bor:str

bit or assembler time operation

a_xor:str
^ bit xor assembler time operation
a_bnot:str
~ bit not assembler time operation
a_shl:str
<< shift left assembler time operation
a_shr:str
>> shift right assembler time operation
a_sizeof_fmt:str
size of type (format string)
flag2:int
Secondary assembler feature bits
cmnt2:str
comment close string (usually nullptr) this is used to denote a string which closes comments, for example, if the comments are represented with (* … ) then cmnt = “(” and cmnt2 = “*)”
low8:str
low8 operation, should contain s for the operand
high8:str
high8
low16:str
low16
high16:str
high16
a_include_fmt:str
the include directive (format string)
a_vstruc_fmt:str
if a named item is a structure and displayed in the verbose (multiline) form then display the name as printf(a_strucname_fmt, typename) (for asms with type checking, e.g. tasm ideal)
a_rva:str
‘rva’ keyword for image based offsets (see REFINFO_RVAOFF)
a_yword:str
32-byte (256-bit) data; nullptr if not allowed requires AS2_YWORD
a_zword:str
64-byte (512-bit) data; nullptr if not allowed requires AS2_ZWORD
ida_idp.AS_OFFST
offsets are ‘offset xxx’ ?
ida_idp.AS_COLON
create colons after data names ?
ida_idp.AS_UDATA
can use ‘?’ in data directives
ida_idp.AS_2CHRE
double char constants are: “xy
ida_idp.AS_NCHRE
char constants are: ‘x
ida_idp.AS_N2CHR
can’t have 2 byte char consts
ida_idp.AS_1TEXT
1 text per line, no bytes
ida_idp.AS_NHIAS
no characters with high bit
ida_idp.AS_NCMAS
no commas in ascii directives
ida_idp.AS_HEXFM
mask - hex number format
ida_idp.ASH_HEXF0
34h
ida_idp.ASH_HEXF1
h’34
ida_idp.ASH_HEXF2
34
ida_idp.ASH_HEXF3
0x34
ida_idp.ASH_HEXF4
$34
ida_idp.ASH_HEXF5
 (radix)
ida_idp.AS_DECFM
mask - decimal number format
ida_idp.ASD_DECF0
34
ida_idp.ASD_DECF1
#34
ida_idp.ASD_DECF2

-
ida_idp.ASD_DECF3
.34
ida_idp.AS_OCTFM
mask - octal number format
ida_idp.ASO_OCTF0
123o
ida_idp.ASO_OCTF1
0123
ida_idp.ASO_OCTF2
123
ida_idp.ASO_OCTF3
@123
ida_idp.ASO_OCTF4
o’123
ida_idp.ASO_OCTF5
123q
ida_idp.ASO_OCTF6
~123
ida_idp.ASO_OCTF7
q’123
ida_idp.AS_BINFM
mask - binary number format
ida_idp.ASB_BINF0
010101b
ida_idp.ASB_BINF1
^B010101
ida_idp.ASB_BINF2
%010101
ida_idp.ASB_BINF3
0b1010101
ida_idp.ASB_BINF4
b’1010101
ida_idp.ASB_BINF5
b’1010101’
ida_idp.AS_UNEQU
replace undefined data items with EQU (for ANTA’s A80)
ida_idp.AS_ONEDUP
One array definition per line.
ida_idp.AS_NOXRF
Disable xrefs during the output file generation.
ida_idp.AS_XTRNTYPE
Assembler understands type of extern symbols as “:type” suffix.
ida_idp.AS_RELSUP
Checkarg: ‘and’,’or’,’xor’ operations with addresses are possible.
ida_idp.AS_LALIGN
Labels at “align” keyword are supported.
ida_idp.AS_NOCODECLN
don’t create colons after code names
ida_idp.AS_NOSPACE
No spaces in expressions.
ida_idp.AS_ALIGN2
.align directive expects an exponent rather than a power of 2 (.align 5 means to align at 32byte boundary)
ida_idp.AS_ASCIIC
ascii directive accepts C-like escape sequences (n,x01 and similar)
ida_idp.AS_ASCIIZ
ascii directive inserts implicit zero byte at the end
ida_idp.AS2_BRACE
Use braces for all expressions.
ida_idp.AS2_STRINV
Invert meaning of idainfo::wide_high_byte_first for text strings (for processors with bytes bigger than 8 bits)
ida_idp.AS2_BYTE1CHAR
One symbol per processor byte. Meaningful only for wide byte processors
ida_idp.AS2_IDEALDSCR
Description of struc/union is in the ‘reverse’ form (keyword before name), the same as in borland tasm ideal
ida_idp.AS2_TERSESTR
‘terse’ structure initialization form; NAME is supported
ida_idp.AS2_COLONSUF
addresses may have “:xx” suffix; this suffix must be ignored when extracting the address under the cursor
ida_idp.AS2_YWORD
a_yword field is present and valid
ida_idp.AS2_ZWORD
a_zword field is present and valid
ida_idp.HKCB_GLOBAL
is global event listener? if true, the listener will survive database closing and opening. it will stay in the memory until explicitly unhooked. otherwise the kernel will delete it as soon as the owner is unloaded. should be used only with PLUGIN_FIX plugins.
ida_idp.PLFM_386
Intel 80x86.
ida_idp.PLFM_Z80
8085, Z80
ida_idp.PLFM_I860
Intel 860.
ida_idp.PLFM_8051
8051
ida_idp.PLFM_TMS
Texas Instruments TMS320C5x.
ida_idp.PLFM_6502
6502
ida_idp.PLFM_PDP
PDP11.
ida_idp.PLFM_68K
Motorola 680x0.
ida_idp.PLFM_JAVA
Java.
ida_idp.PLFM_6800
Motorola 68xx.
ida_idp.PLFM_ST7
SGS-Thomson ST7.
ida_idp.PLFM_MC6812
Motorola 68HC12.
ida_idp.PLFM_MIPS
MIPS.
ida_idp.PLFM_ARM
Advanced RISC Machines.
ida_idp.PLFM_TMSC6
Texas Instruments TMS320C6x.
ida_idp.PLFM_PPC
PowerPC.
ida_idp.PLFM_80196
Intel 80196.
ida_idp.PLFM_Z8
Z8.
ida_idp.PLFM_SH
Renesas (formerly Hitachi) SuperH.
ida_idp.PLFM_NET
Microsoft Visual Studio.Net.
ida_idp.PLFM_AVR
Atmel 8-bit RISC processor(s)
ida_idp.PLFM_H8
Hitachi H8/300, H8/2000.
ida_idp.PLFM_PIC
Microchip’s PIC.
ida_idp.PLFM_SPARC
SPARC.
ida_idp.PLFM_ALPHA
DEC Alpha.
ida_idp.PLFM_HPPA
Hewlett-Packard PA-RISC.
ida_idp.PLFM_H8500
Hitachi H8/500.
ida_idp.PLFM_TRICORE
Tasking Tricore.
ida_idp.PLFM_DSP56K
Motorola DSP5600x.
ida_idp.PLFM_C166
Siemens C166 family.
ida_idp.PLFM_ST20
SGS-Thomson ST20.
ida_idp.PLFM_IA64
Intel Itanium IA64.
ida_idp.PLFM_I960
Intel 960.
ida_idp.PLFM_F2MC
Fujitsu F2MC-16.
ida_idp.PLFM_TMS320C54
Texas Instruments TMS320C54xx.
ida_idp.PLFM_TMS320C55
Texas Instruments TMS320C55xx.
ida_idp.PLFM_TRIMEDIA
Trimedia.
ida_idp.PLFM_M32R
Mitsubishi 32-bit RISC.
ida_idp.PLFM_NEC_78K0
NEC 78K0.
ida_idp.PLFM_NEC_78K0S
NEC 78K0S.
ida_idp.PLFM_M740
Mitsubishi 8bit.
ida_idp.PLFM_M7700
Mitsubishi 16-bit.
ida_idp.PLFM_ST9
ST9+.
ida_idp.PLFM_FR
Fujitsu FR Family.
ida_idp.PLFM_MC6816
Motorola 68HC16.
ida_idp.PLFM_M7900
Mitsubishi 7900.
ida_idp.PLFM_TMS320C3
Texas Instruments TMS320C3.
ida_idp.PLFM_KR1878
Angstrem KR1878.
ida_idp.PLFM_AD218X
Analog Devices ADSP 218X.
ida_idp.PLFM_OAKDSP
Atmel OAK DSP.
ida_idp.PLFM_TLCS900
Toshiba TLCS-900.
ida_idp.PLFM_C39
Rockwell C39.
ida_idp.PLFM_CR16
NSC CR16.
ida_idp.PLFM_MN102L00
Panasonic MN10200.
ida_idp.PLFM_TMS320C1X
Texas Instruments TMS320C1x.
ida_idp.PLFM_NEC_V850X
NEC V850 and V850ES/E1/E2.
ida_idp.PLFM_SCR_ADPT
Processor module adapter for processor modules written in scripting languages.
ida_idp.PLFM_EBC
EFI Bytecode.
ida_idp.PLFM_MSP430
Texas Instruments MSP430.
ida_idp.PLFM_SPU
Cell Broadband Engine Synergistic Processor Unit.
ida_idp.PLFM_DALVIK
Android Dalvik Virtual Machine.
ida_idp.PLFM_65C816
65802/65816
ida_idp.PLFM_M16C
Renesas M16C.
ida_idp.PLFM_ARC
Argonaut RISC Core.
ida_idp.PLFM_UNSP
SunPlus unSP.
ida_idp.PLFM_TMS320C28
Texas Instruments TMS320C28x.
ida_idp.PLFM_DSP96K
Motorola DSP96000.
ida_idp.PLFM_SPC700
Sony SPC700.
ida_idp.PLFM_AD2106X
Analog Devices ADSP 2106X.
ida_idp.PLFM_PIC16
Microchip’s 16-bit PIC.
ida_idp.PLFM_S390
IBM’s S390.
ida_idp.PLFM_XTENSA
Tensilica Xtensa.
ida_idp.PLFM_RISCV
RISC-V.
ida_idp.PLFM_RL78
Renesas RL78.
ida_idp.PLFM_RX
Renesas RX.
ida_idp.PLFM_WASM
WASM.
ida_idp.PLFM_NDS32
Andes Technology NDS32.
ida_idp.PR_SEGS
has segment registers?
ida_idp.PR_USE32
supports 32-bit addressing?
ida_idp.PR_DEFSEG32
segments are 32-bit by default
ida_idp.PR_RNAMESOK
allow user register names for location names
ida_idp.PR_ADJSEGS
IDA may adjust segments’ starting/ending addresses.
ida_idp.PR_DEFNUM
mask - default number representation
ida_idp.PRN_HEX
hex
ida_idp.PRN_OCT
octal
ida_idp.PRN_DEC
decimal
ida_idp.PRN_BIN
binary
ida_idp.PR_WORD_INS
instruction codes are grouped 2bytes in binary line prefix
ida_idp.PR_NOCHANGE
The user can’t change segments and code/data attributes (display only)
ida_idp.PR_ASSEMBLE
Module has a built-in assembler and will react to ev_assemble.
ida_idp.PR_ALIGN
All data items should be aligned properly.
ida_idp.PR_TYPEINFO
the processor module fully supports type information callbacks; without full support, function argument locations and other things will probably be wrong.
ida_idp.PR_USE64
supports 64-bit addressing?
ida_idp.PR_SGROTHER
the segment registers don’t contain the segment selectors.
ida_idp.PR_STACK_UP
the stack grows up
ida_idp.PR_BINMEM
the processor module provides correct segmentation for binary files (i.e. it creates additional segments). The kernel will not ask the user to specify the RAM/ROM sizes
ida_idp.PR_SEGTRANS
the processor module supports the segment translation feature (meaning it calculates the code addresses using the map_code_ea() function)
ida_idp.PR_CHK_XREF
don’t allow near xrefs between segments with different bases
ida_idp.PR_NO_SEGMOVE
the processor module doesn’t support move_segm() (i.e. the user can’t move segments)
ida_idp.PR_USE_ARG_TYPES
use processor_t::use_arg_types callback
ida_idp.PR_SCALE_STKVARS
use processor_t::get_stkvar_scale callback
ida_idp.PR_DELAYED
has delayed jumps and calls. If this flag is set, processor_t::is_basic_block_end, processor_t::delay_slot_insn should be implemented
ida_idp.PR_ALIGN_INSN
allow ida to create alignment instructions arbitrarily. Since these instructions might lead to other wrong instructions and spoil the listing, IDA does not create them by default anymore
ida_idp.PR_PURGING
there are calling conventions which may purge bytes from the stack
ida_idp.PR_CNDINSNS
has conditional instructions
ida_idp.PR_USE_TBYTE
BTMT_SPECFLT means _TBYTE type
ida_idp.PR_DEFSEG64
segments are 64-bit by default
ida_idp.PR_OUTER
has outer operands (currently only mc68k)
ida_idp.PR2_MAPPINGS
the processor module uses memory mapping
ida_idp.PR2_IDP_OPTS
the module has processor-specific configuration options
ida_idp.PR2_CODE16_BIT
low bit of code addresses has special meaning e.g. ARM Thumb, MIPS16
ida_idp.PR2_MACRO
processor supports macro instructions
ida_idp.PR2_USE_CALCREL
(Lumina) the module supports calcrel info
ida_idp.PR2_REL_BITS
(Lumina) calcrel info has bits granularity, not bytes - construction flag only
ida_idp.PR2_FORCE_16BIT
use 16-bit basic types despite of 32-bit segments (used by c166)
ida_idp.PR2_IGNORE_IDA_GUESS
allow to create items inside the IDA-guessed data arrays
ida_idp.OP_FP_BASED
operand is FP based
ida_idp.OP_SP_BASED
operand is SP based
ida_idp.OP_SP_ADD
operand value is added to the pointer
ida_idp.OP_SP_SUB
operand value is subtracted from the pointer
ida_idp.CUSTOM_INSN_ITYPE
Custom instruction codes defined by processor extension plugins must be greater than or equal to this
ida_idp.REG_SPOIL
processor_t::use_regarg_type uses this bit in the return value to indicate that the register value has been spoiled
ida_idp.get_ph()→processor_t*ida_idp.get_ash()→asm_t*ida_idp.str2reg(p:str)→int
Get any register number (-1 on error)
ida_idp.is_align_insn(ea:ida_idaapi.ea_t)→int
If the instruction at ‘ea’ looks like an alignment instruction, return its length in bytes. Otherwise return 0.
ida_idp.get_reg_name(reg:int, width:int, reghi:int=-1)→str
Get text representation of a register. For most processors this function will just return processor_t::reg_names[reg]. If the processor module has implemented processor_t::get_reg_name, it will be used instead
Parameters:

-
reg – internal register number as defined in the processor module

-
width – register width in bytes

-
reghi – if specified, then this function will return the register pair

Returns:
length of register name in bytes or -1 if failure
classida_idp.reg_info_t
Bases: `object`
thisownreg:int
register number
size:int
register size
compare(r:reg_info_t)→intida_idp.parse_reg_name(ri:reg_info_t, regname:str)→bool
Get register info by name.
Parameters:

-
ri – result

-
regname – name of register

Returns:
success
ida_idp.NO_ACCESSida_idp.WRITE_ACCESSida_idp.READ_ACCESSida_idp.RW_ACCESSclassida_idp.reg_access_t
Bases: `object`
thisownregnum:int
register number (only entire registers)
range:bitrange_t
bitrange inside the register
access_type:access_type_topnum:uchar
operand number
have_common_bits(r:reg_access_t)→boolclassida_idp.reg_accesses_t
Bases: `reg_access_vec_t`
thisownida_idp.SETPROC_IDB
set processor type for old idb
ida_idp.SETPROC_LOADER
set processor type for new idb; if the user has specified a compatible processor, return success without changing it. if failure, call loader_failure()
ida_idp.SETPROC_LOADER_NON_FATAL
the same as SETPROC_LOADER but non-fatal failures.
ida_idp.SETPROC_USER
set user-specified processor used for -p and manual processor change at later time
ida_idp.set_processor_type(procname:str, level:setproc_level_t)→bool
Set target processor type. Once a processor module is loaded, it cannot be replaced until we close the idb.
Parameters:

-
procname – name of processor type (one of names present in processor_t::psnames)

-
level – SETPROC_

Returns:
success
ida_idp.get_idp_name()→str
Get name of the current processor module. The name is derived from the file name. For example, for IBM PC the module is named “pc.w32” (windows version), then the module name is “PC” (uppercase). If no processor module is loaded, this function will return nullptr
ida_idp.set_target_assembler(asmnum:int)→bool
Set target assembler.
Parameters:
asmnum – number of assembler in the current processor module
Returns:
success
ida_idp.LTC_NONE
no event (internal use)
ida_idp.LTC_ADDED
added a local type
ida_idp.LTC_DELETED
deleted a local type
ida_idp.LTC_EDITED
edited a local type
ida_idp.LTC_ALIASED
added a type alias
ida_idp.LTC_COMPILER
changed the compiler and calling convention
ida_idp.LTC_TIL_LOADED
loaded a til file
ida_idp.LTC_TIL_UNLOADED
unloaded a til file
ida_idp.LTC_TIL_COMPACTED
numbered types have been compacted compact_numbered_types()
ida_idp.closebaseida_idp.savebaseida_idp.upgradedida_idp.auto_emptyida_idp.auto_empty_finallyida_idp.determined_mainida_idp.extlang_changedida_idp.idasgn_loadedida_idp.kernel_config_loadedida_idp.loader_finishedida_idp.flow_chart_createdida_idp.compiler_changedida_idp.changing_tiida_idp.ti_changedida_idp.changing_op_tiida_idp.op_ti_changedida_idp.changing_op_typeida_idp.op_type_changedida_idp.segm_addedida_idp.deleting_segmida_idp.segm_deletedida_idp.changing_segm_startida_idp.segm_start_changedida_idp.changing_segm_endida_idp.segm_end_changedida_idp.changing_segm_nameida_idp.segm_name_changedida_idp.changing_segm_classida_idp.segm_class_changedida_idp.segm_attrs_updatedida_idp.segm_movedida_idp.allsegs_movedida_idp.func_addedida_idp.func_updatedida_idp.set_func_startida_idp.set_func_endida_idp.deleting_funcida_idp.frame_deletedida_idp.thunk_func_createdida_idp.func_tail_appendedida_idp.deleting_func_tailida_idp.func_tail_deletedida_idp.tail_owner_changedida_idp.func_noret_changedida_idp.stkpnts_changedida_idp.updating_tryblksida_idp.tryblks_updatedida_idp.deleting_tryblksida_idp.sgr_changedida_idp.make_codeida_idp.make_dataida_idp.destroyed_itemsida_idp.renamedida_idp.byte_patchedida_idp.changing_cmtida_idp.cmt_changedida_idp.changing_range_cmtida_idp.range_cmt_changedida_idp.extra_cmt_changedida_idp.item_color_changedida_idp.callee_addr_changedida_idp.bookmark_changedida_idp.sgr_deletedida_idp.adding_segmida_idp.func_deletedida_idp.dirtree_mkdirida_idp.dirtree_rmdirida_idp.dirtree_linkida_idp.dirtree_moveida_idp.dirtree_rankida_idp.dirtree_rminodeida_idp.dirtree_segm_movedida_idp.local_types_changedida_idp.lt_udm_createdida_idp.lt_udm_deletedida_idp.lt_udm_renamedida_idp.lt_udm_changedida_idp.lt_udt_expandedida_idp.frame_createdida_idp.frame_udm_createdida_idp.frame_udm_deletedida_idp.frame_udm_renamedida_idp.frame_udm_changedida_idp.frame_expandedida_idp.idasgn_matched_eaida_idp.lt_edm_createdida_idp.lt_edm_deletedida_idp.lt_edm_renamedida_idp.lt_edm_changedida_idp.local_type_renamedida_idp.dirtree_ordering_changedida_idp.dirtree_bulk_moveida_idp.gen_idb_event(*args)→None
the kernel will use this function to generate idb_events
ida_idp.IDPOPT_CSTida_idp.IDPOPT_JVLida_idp.IDPOPT_PRI_DEFAULTida_idp.IDPOPT_PRI_HIGHida_idp.IDPOPT_NUM_INTida_idp.IDPOPT_NUM_CHARida_idp.IDPOPT_NUM_SHORTida_idp.IDPOPT_NUM_RANGEida_idp.IDPOPT_NUM_UNSida_idp.IDPOPT_BIT_UINTida_idp.IDPOPT_BIT_UCHARida_idp.IDPOPT_BIT_USHORTida_idp.IDPOPT_BIT_BOOLida_idp.IDPOPT_STR_QSTRINGida_idp.IDPOPT_STR_LONGida_idp.IDPOPT_I64_RANGEida_idp.IDPOPT_I64_UNSida_idp.IDPOPT_CST_PARAMSida_idp.IDPOPT_MBROFFclassida_idp.num_range_t(_min:int64, _max:int64)
Bases: `object`
thisownminval:int64maxval:int64classida_idp.params_t(_p1:int64, _p2:int64)
Bases: `object`
thisownp1:int64p2:int64ida_idp.cik_stringida_idp.cik_filenameida_idp.cik_pathida_idp.register_cfgopts(opts:cfgopt_tconst[], nopts:int, cb:config_changed_cb_t*=None, obj:void*=None)→boolida_idp.get_config_value(key:str)→jvalue_t*ida_idp.cfg_get_cc_parm(compid:comp_t, name:str)→strida_idp.cfg_get_cc_header_path(compid:comp_t)→strida_idp.cfg_get_cc_predefined_macros(compid:comp_t)→strida_idp.process_config_directive(directive:str, priority:int=2)→Noneida_idp.AssembleLine(ea, cs, ip, use32, line)
Assemble an instruction to a string (display a warning if an error is found)
Parameters:

-
ea – linear address of instruction

-
cs – cs of instruction

-
ip – ip of instruction

-
use32 – is 32bit segment

-
line – line to assemble

Returns:
a string containing the assembled instruction, or None on failure
ida_idp.assemble(ea, cs, ip, use32, line)
Assemble an instruction into the database (display a warning if an error is found)
Parameters:

-
ea – linear address of instruction

-
cs – cs of instruction

-
ip – ip of instruction

-
use32 – is 32bit segment?

-
line – line to assemble

Returns:
Boolean. True on success.
ida_idp.ph_get_id()
Returns the ‘ph.id’ field
ida_idp.ph_get_version()
Returns the ‘ph.version’
ida_idp.ph_get_flag()
Returns the ‘ph.flag’
ida_idp.ph_get_cnbits()
Returns the ‘ph.cnbits’
ida_idp.ph_get_dnbits()
Returns the ‘ph.dnbits’
ida_idp.ph_get_reg_first_sreg()
Returns the ‘ph.reg_first_sreg’
ida_idp.ph_get_reg_last_sreg()
Returns the ‘ph.reg_last_sreg’
ida_idp.ph_get_segreg_size()
Returns the ‘ph.segreg_size’
ida_idp.ph_get_reg_code_sreg()
Returns the ‘ph.reg_code_sreg’
ida_idp.ph_get_reg_data_sreg()
Returns the ‘ph.reg_data_sreg’
ida_idp.ph_get_icode_return()
Returns the ‘ph.icode_return’
ida_idp.ph_get_instruc_start()
Returns the ‘ph.instruc_start’
ida_idp.ph_get_instruc_end()
Returns the ‘ph.instruc_end’
ida_idp.ph_get_tbyte_size()
Returns the ‘ph.tbyte_size’ field as defined in he processor module
ida_idp.ph_get_instruc()
Returns a list of tuples (instruction_name, instruction_feature) containing the instructions list as defined in he processor module
ida_idp.ph_get_regnames()
Returns the list of register names as defined in the processor module
ida_idp.ph_get_operand_info(ea:ida_idaapi.ea_t, n:int)→Tuple[int,ida_idaapi.ea_t,int,int,int]|None
Returns the operand information given an ea and operand number.
Parameters:

-
ea – address

-
n – operand number

Returns:
Returns an idd_opinfo_t as a tuple: (modified, ea, reg_ival, regidx, value_size). Please refer to idd_opinfo_t structure in the SDK.
ida_idp.ph_calcrel(ea:ida_idaapi.ea_t)→bytevec_t*,size_t*ida_idp.ph_find_reg_value(insn:insn_tconst&, reg:int)→uint64*ida_idp.ph_find_op_value(insn:insn_tconst&, op:int)→uint64*ida_idp.ph_get_reg_accesses(accvec:reg_accesses_t, insn:insn_tconst&, flags:int)→ssize_tida_idp.ph_get_abi_info(comp:comp_t)→qstrvec_t*,qstrvec_t*classida_idp.IDP_Hooks(_flags:int=0, _hkcb_flags:int=1)
Bases: `object`
thisownhook()→boolunhook()→boolev_init(idp_modname:str)→int
The IDP module is just loaded.
Parameters:
idp_modname – (const char *) processor module name
Returns:
<0: on failure
ev_term()→int
The IDP module is being unloaded.
ev_newprc(pnum:int, keep_cfg:bool)→int
Before changing processor type.
Parameters:

-
pnum – (int) processor number in the array of processor names

-
keep_cfg – (bool) true: do not modify kernel configuration

Returns:
1: ok
Returns:
<0: prohibit
ev_newasm(asmnum:int)→int
Before setting a new assembler.
Parameters:
asmnum – (int) See also ev_asm_installed
ev_newfile(fname:char*)→int
A new file has been loaded.
Parameters:
fname – (char *) input file name
ev_oldfile(fname:char*)→int
An old file has been loaded.
Parameters:
fname – (char *) input file name
ev_newbinary(filename:char*, fileoff:qoff64_t, basepara:ida_idaapi.ea_t, binoff:ida_idaapi.ea_t, nbytes:uint64)→int
IDA is about to load a binary file.
Parameters:

-
filename – (char *) binary file name

-
fileoff – (qoff64_t) offset in the file

-
basepara – (::ea_t) base loading paragraph

-
binoff – (::ea_t) loader offset

-
nbytes – (::uint64) number of bytes to load

ev_endbinary(ok:bool)→int
IDA has loaded a binary file.
Parameters:
ok – (bool) file loaded successfully?
ev_set_idp_options(keyword:str, value_type:int, value:voidconst*, idb_loaded:bool)→int
Set IDP-specific configuration option Also see set_options_t in config.hpp
Parameters:

-
keyword – (const char *)

-
value_type – (int)

-
value – (const void *)

-
idb_loaded – (bool) true if the ev_oldfile/ev_newfile events have been generated

Returns:
1: ok
Returns:
0: not implemented
Returns:
-1: error (and message in errbuf)
ev_set_proc_options(options:str, confidence:int)→int
Called if the user specified an option string in the command line: -p:. Can be used for setting a processor subtype. Also called if option string is passed to set_processor_type() and IDC’s SetProcessorType().
Parameters:

-
options – (const char *)

-
confidence – (int) 0: loader’s suggestion 1: user’s decision

Returns:
<0: if bad option string
ev_ana_insn(out:insn_t*)→bool
Analyze one instruction and fill ‘out’ structure. This function shouldn’t change the database, flags or anything else. All these actions should be performed only by emu_insn() function. insn_t::ea contains address of instruction to analyze.
Parameters:
out – (insn_t *)
Returns:
length of the instruction in bytes, 0 if instruction can’t be decoded.
Returns:
0: if instruction can’t be decoded.
ev_emu_insn(insn:insn_tconst*)→bool
Emulate instruction, create cross-references, plan to analyze subsequent instructions, modify flags etc. Upon entrance to this function, all information about the instruction is in ‘insn’ structure.
Parameters:
insn – (const insn_t *)
Returns:
1: ok
Returns:
-1: the kernel will delete the instruction
ev_out_header(outctx:outctx_t*)→int
Function to produce start of disassembled text
Parameters:
outctx – (outctx_t *)
Returns:
void:
ev_out_footer(outctx:outctx_t*)→int
Function to produce end of disassembled text
Parameters:
outctx – (outctx_t *)
Returns:
void:
ev_out_segstart(outctx:outctx_t*, seg:segment_t*)→int
Function to produce start of segment
Parameters:

-
outctx – (outctx_t *)

-
seg – (segment_t *)

Returns:
1: ok
Returns:
0: not implemented
ev_out_segend(outctx:outctx_t*, seg:segment_t*)→int
Function to produce end of segment
Parameters:

-
outctx – (outctx_t *)

-
seg – (segment_t *)

Returns:
1: ok
Returns:
0: not implemented
ev_out_assumes(outctx:outctx_t*)→int
Function to produce assume directives when segment register value changes.
Parameters:
outctx – (outctx_t *)
Returns:
1: ok
Returns:
0: not implemented
ev_out_insn(outctx:outctx_t*)→bool
Generate text representation of an instruction in ‘ctx.insn’ outctx_t provides functions to output the generated text. This function shouldn’t change the database, flags or anything else. All these actions should be performed only by emu_insn() function.
Parameters:
outctx – (outctx_t *)
Returns:
void:
ev_out_mnem(outctx:outctx_t*)→int
Generate instruction mnemonics. This callback should append the colored mnemonics to ctx.outbuf Optional notification, if absent, out_mnem will be called.
Parameters:
outctx – (outctx_t *)
Returns:
1: if appended the mnemonics
Returns:
0: not implemented
ev_out_operand(outctx:outctx_t*, op:op_tconst*)→bool
Generate text representation of an instruction operand outctx_t provides functions to output the generated text. All these actions should be performed only by emu_insn() function.
Parameters:

-
outctx – (outctx_t *)

-
op – (const op_t *)

Returns:
1: ok
Returns:
-1: operand is hidden
ev_out_data(outctx:outctx_t*, analyze_only:bool)→int
Generate text representation of data items This function may change the database and create cross-references if analyze_only is set
Parameters:

-
outctx – (outctx_t *)

-
analyze_only – (bool)

Returns:
1: ok
Returns:
0: not implemented
ev_out_label(outctx:outctx_t*, colored_name:str)→int
The kernel is going to generate an instruction label line or a function header.
Parameters:

-
outctx – (outctx_t *)

-
colored_name – (const char *)

Returns:
<0: if the kernel should not generate the label
Returns:
0: not implemented or continue
ev_out_special_item(outctx:outctx_t*, segtype:uchar)→int
Generate text representation of an item in a special segment i.e. absolute symbols, externs, communal definitions etc
Parameters:

-
outctx – (outctx_t *)

-
segtype – (uchar)

Returns:
1: ok
Returns:
0: not implemented
Returns:
-1: overflow
ev_gen_regvar_def(outctx:outctx_t*, v:regvar_t*)→int
Generate register variable definition line.
Parameters:

-
outctx – (outctx_t *)

-
v – (regvar_t *)

Returns:
>0: ok, generated the definition text
Returns:
0: not implemented
ev_gen_src_file_lnnum(outctx:outctx_t*, file:str, lnnum:int)→intCallback: generate analog of:
#line 123
Parameters:

-
outctx – (outctx_t *) output context

-
file – (const char *) source file (may be nullptr)

-
lnnum – (size_t) line number

Returns:
1: directive has been generated
Returns:
0: not implemented
ev_creating_segm(seg:segment_t*)→int
A new segment is about to be created.
Parameters:
seg – (segment_t *)
Returns:
1: ok
Returns:
<0: segment should not be created
ev_moving_segm(seg:segment_t*, to:ida_idaapi.ea_t, flags:int)→int
May the kernel move the segment?
Parameters:

-
seg – (segment_t *) segment to move

-
to – (::ea_t) new segment start address

-
flags – (int) combination of Move segment flags

Returns:
0: yes
Returns:
<0: the kernel should stop
ev_coagulate(start_ea:ida_idaapi.ea_t)→int
Try to define some unexplored bytes. This notification will be called if the kernel tried all possibilities and could not find anything more useful than to convert to array of bytes. The module can help the kernel and convert the bytes into something more useful.
Parameters:
start_ea – (::ea_t)
Returns:
number of converted bytes
ev_undefine(ea:ida_idaapi.ea_t)→int
An item in the database (insn or data) is being deleted.
Parameters:
ea – (ea_t)
Returns:
1: do not delete srranges at the item end
Returns:
0: srranges can be deleted
ev_treat_hindering_item(hindering_item_ea:ida_idaapi.ea_t, new_item_flags:flags64_t, new_item_ea:ida_idaapi.ea_t, new_item_length:asize_t)→int
An item hinders creation of another item.
Parameters:

-
hindering_item_ea – (::ea_t)

-
new_item_flags – (flags64_t) (0 for code)

-
new_item_ea – (::ea_t)

-
new_item_length – (::asize_t)

Returns:
0: no reaction
Returns:
!=0: the kernel may delete the hindering item
ev_rename(ea:ida_idaapi.ea_t, new_name:str)→int
The kernel is going to rename a byte.
Parameters:

-
ea – (::ea_t)

-
new_name – (const char *)

Returns:
<0: if the kernel should not rename it.
Returns:
2: to inhibit the notification. I.e., the kernel should not rename, but ‘set_name()’ should return ‘true’. also see renamed the return value is ignored when kernel is going to delete name
ev_is_far_jump(icode:int)→int
is indirect far jump or call instruction? meaningful only if the processor has ‘near’ and ‘far’ reference types
Parameters:
icode – (int)
Returns:
0: not implemented
Returns:
1: yes
Returns:
-1: no
ev_is_sane_insn(insn:insn_tconst*, no_crefs:int)→int
Is the instruction sane for the current file type?
Parameters:

-
insn – (const insn_t*) the instruction

-
no_crefs – (int) 1: the instruction has no code refs to it. ida just tries to convert unexplored bytes to an instruction (but there is no other reason to convert them into an instruction) 0: the instruction is created because of some coderef, user request or another weighty reason.

Returns:
>=0: ok
Returns:
<0: no, the instruction isn’t likely to appear in the program
ev_is_cond_insn(insn:insn_tconst*)→int
Is conditional instruction?
Parameters:
insn – (const insn_t *) instruction address
Returns:
1: yes
Returns:
-1: no
Returns:
0: not implemented or not instruction
ev_is_call_insn(insn:insn_tconst*)→int
Is the instruction a “call”?
Parameters:
insn – (const insn_t *) instruction
Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_is_ret_insn(insn:insn_tconst*, flags:uchar)→int
Is the instruction a “return”?
Parameters:

-
insn – (const insn_t *) instruction

-
flags – (uchar), combination of IRI_… flags (see above)

Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_may_be_func(insn:insn_tconst*, state:int)→int
Can a function start here?
Parameters:

-
insn – (const insn_t*) the instruction

-
state – (int) autoanalysis phase 0: creating functions 1: creating chunks

Returns:
probability 1..100
ev_is_basic_block_end(insn:insn_tconst*, call_insn_stops_block:bool)→int
Is the current instruction end of a basic block? This function should be defined for processors with delayed jump slots.
Parameters:

-
insn – (const insn_t*) the instruction

-
call_insn_stops_block – (bool)

Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_is_indirect_jump(insn:insn_tconst*)→int
Determine if instruction is an indirect jump. If CF_JUMP bit cannot describe all jump types jumps, please define this callback.
Parameters:
insn – (const insn_t*) the instruction
Returns:
0: use CF_JUMP
Returns:
1: no
Returns:
2: yes
ev_is_insn_table_jump()→int
Reserved.
ev_is_switch(si:switch_info_t, insn:insn_tconst*)→int
Find ‘switch’ idiom or override processor module’s decision. It will be called for instructions marked with CF_JUMP.
Parameters:

-
si – (switch_info_t *), out

-
insn – (const insn_t *) instruction possibly belonging to a switch

Returns:
1: switch is found, ‘si’ is filled. IDA will create the switch using the filled ‘si’
Returns:
-1: no switch found. This value forbids switch creation by the processor module
Returns:
0: not implemented
ev_calc_switch_cases(casevec:casevec_t*, targets:eavec_t*, insn_ea:ida_idaapi.ea_t, si:switch_info_t)→int
Calculate case values and targets for a custom jump table.
Parameters:

-
casevec – (::casevec_t *) vector of case values (may be nullptr)

-
targets – (eavec_t *) corresponding target addresses (my be nullptr)

-
insn_ea – (::ea_t) address of the ‘indirect jump’ instruction

-
si – (switch_info_t *) switch information

Returns:
1: ok
Returns:
<=0: failed
ev_create_switch_xrefs(jumpea:ida_idaapi.ea_t, si:switch_info_t)→int
Create xrefs for a custom jump table.
Parameters:

-
jumpea – (::ea_t) address of the jump insn

-
si – (const switch_info_t *) switch information

Returns:
must return 1 Must be implemented if module uses custom jump tables, SWI_CUSTOM
ev_is_align_insn(ea:ida_idaapi.ea_t)→int
Is the instruction created only for alignment purposes?. Do not directly call this function, use is_align_insn()
Parameters:
ea – (ea_t) - instruction address
Returns:
number: of bytes in the instruction
ev_is_alloca_probe(ea:ida_idaapi.ea_t)→int
Does the function at ‘ea’ behave like __alloca_probe?
Parameters:
ea – (::ea_t)
Returns:
1: yes
Returns:
0: no
ev_delay_slot_insn(ea:ida_idaapi.ea_t, bexec:bool, fexec:bool)→PyObject*
Get delay slot instruction
Parameters:

-
ea – (::ea_t *) in: instruction address in question, out: (if the answer is positive) if the delay slot contains valid insn: the address of the delay slot insn else: BADADDR (invalid insn, e.g. a branch)

-
bexec – (bool *) execute slot if jumping, initially set to ‘true’

-
fexec – (bool *) execute slot if not jumping, initially set to ‘true’

Returns:
1: positive answer
Returns:
<=0: ordinary insn
ev_is_sp_based(mode:int*, insn:insn_tconst*, op:op_tconst*)→int
Check whether the operand is relative to stack pointer or frame pointer This event is used to determine how to output a stack variable If not implemented, then all operands are sp based by default. Implement this event only if some stack references use frame pointer instead of stack pointer.
Parameters:

-
mode – (int *) out, combination of SP/FP operand flags

-
insn – (const insn_t *)

-
op – (const op_t *)

Returns:
0: not implemented
Returns:
1: ok
ev_can_have_type(op:op_tconst*)→int
Can the operand have a type as offset, segment, decimal, etc? (for example, a register AX can’t have a type, meaning that the user can’t change its representation. see bytes.hpp for information about types and flags)
Parameters:
op – (const op_t *)
Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_cmp_operands(op1:op_tconst*, op2:op_tconst*)→int
Compare instruction operands
Parameters:

-
op1 – (const op_t*)

-
op2 – (const op_t*)

Returns:
1: equal
Returns:
-1: not equal
Returns:
0: not implemented
ev_adjust_refinfo(ri:refinfo_t, ea:ida_idaapi.ea_t, n:int, fd:fixup_data_tconst*)→int
Called from apply_fixup before converting operand to reference. Can be used for changing the reference info. (e.g. the PPC module adds REFINFO_NOBASE for some references)
Parameters:

-
ri – (refinfo_t *)

-
ea – (::ea_t) instruction address

-
n – (int) operand number

-
fd – (const fixup_data_t *)

Returns:
<0: do not create an offset
Returns:
0: not implemented or refinfo adjusted
ev_get_operand_string(insn:insn_tconst*, opnum:int)→PyObject*
Request text string for operand (cli, java, …).
Parameters:

-
insn – (const insn_t*) the instruction

-
opnum – (int) operand number, -1 means any string operand

Returns:
0: no string (or empty string)
Returns:
>0: original string length without terminating zero
ev_get_reg_name(reg:int, width:int, reghi:int)→PyObject*
Generate text representation of a register. Most processor modules do not need to implement this callback. It is useful only if processor_t::reg_names[reg] does not provide the correct register name.
Parameters:

-
reg – (int) internal register number as defined in the processor module

-
width – (size_t) register width in bytes

-
reghi – (int) if not -1 then this function will return the register pair

Returns:
-1: if error
Returns:
strlen(buf): if success
ev_str2reg(regname:str)→int
Convert a register name to a register number. The register number is the register index in the processor_t::reg_names array Most processor modules do not need to implement this callback It is useful only if processor_t::reg_names[reg] does not provide the correct register names
Parameters:
regname – (const char *)
Returns:
register: number + 1
Returns:
0: not implemented or could not be decoded
ev_get_autocmt(insn:insn_tconst*)→PyObject*
Callback: get dynamic auto comment. Will be called if the autocomments are enabled and the comment retrieved from ida.int starts with ‘$!’. ‘insn’ contains valid info.
Parameters:
insn – (const insn_t*) the instruction
Returns:
1: new comment has been generated
Returns:
0: callback has not been handled. the buffer must not be changed in this case
ev_get_bg_color(color:bgcolor_t*, ea:ida_idaapi.ea_t)→int
Get item background color. Plugins can hook this callback to color disassembly lines dynamically
Parameters:

-
color – (bgcolor_t *), out

-
ea – (::ea_t)

Returns:
0: not implemented
Returns:
1: color set
ev_is_jump_func(pfn:func_t*, jump_target:ea_t*, func_pointer:ea_t*)→int
Is the function a trivial “jump” function?
Parameters:

-
pfn – (func_t *)

-
jump_target – (::ea_t *)

-
func_pointer – (::ea_t *)

Returns:
<0: no
Returns:
0: don’t know
Returns:
1: yes, see ‘jump_target’ and ‘func_pointer’
ev_func_bounds(possible_return_code:int*, pfn:func_t*, max_func_end_ea:ida_idaapi.ea_t)→int
find_func_bounds() finished its work. The module may fine tune the function bounds
Parameters:

-
possible_return_code – (int *), in/out

-
pfn – (func_t *)

-
max_func_end_ea – (::ea_t) (from the kernel’s point of view)

Returns:
void:
ev_verify_sp(pfn:func_t*)→int
All function instructions have been analyzed. Now the processor module can analyze the stack pointer for the whole function
Parameters:
pfn – (func_t *)
Returns:
0: ok
Returns:
<0: bad stack pointer
ev_verify_noreturn(pfn:func_t*)→int
The kernel wants to set ‘noreturn’ flags for a function.
Parameters:
pfn – (func_t *)
Returns:
0: ok. any other value: do not set ‘noreturn’ flag
ev_create_func_frame(pfn:func_t*)→int
Create a function frame for a newly created function Set up frame size, its attributes etc
Parameters:
pfn – (func_t *)
Returns:
1: ok
Returns:
0: not implemented
ev_get_frame_retsize(frsize:int*, pfn:func_tconst*)→int
Get size of function return address in bytes If this event is not implemented, the kernel will assume * 8 bytes for 64-bit function * 4 bytes for 32-bit function * 2 bytes otherwise
Parameters:

-
frsize – (int *) frame size (out)

-
pfn – (const func_t *), can’t be nullptr

Returns:
1: ok
Returns:
0: not implemented
ev_get_stkvar_scale_factor()→int
Should stack variable references be multiplied by a coefficient before being used in the stack frame? Currently used by TMS320C55 because the references into the stack should be multiplied by 2
Returns:
scaling factor
Returns:
0: not implemented
ev_demangle_name(name:str, disable_mask:int, demreq:int)→PyObject*
Demangle a C++ (or another language) name into a user-readable string. This event is called by demangle_name()
Parameters:

-
name – (const char *) mangled name

-
disable_mask – (uint32) flags to inhibit parts of output or compiler info/other (see MNG_)

-
demreq – (demreq_type_t) operation to perform

Returns:
1: if success
Returns:
0: not implemented
ev_add_cref(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t, type:cref_t)→int
A code reference is being created.
Parameters:

-
to – (::ea_t)

-
type – (cref_t)

Returns:
<0: cancel cref creation
Returns:
0: not implemented or continue
ev_add_dref(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t, type:dref_t)→int
A data reference is being created.
Parameters:

-
to – (::ea_t)

-
type – (dref_t)

Returns:
<0: cancel dref creation
Returns:
0: not implemented or continue
ev_del_cref(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t, expand:bool)→int
A code reference is being deleted.
Parameters:

-
to – (::ea_t)

-
expand – (bool)

Returns:
<0: cancel cref deletion
Returns:
0: not implemented or continue
ev_del_dref(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t)→int
A data reference is being deleted.
Parameters:
to – (::ea_t)
Returns:
<0: cancel dref deletion
Returns:
0: not implemented or continue
ev_coagulate_dref(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t, may_define:bool, code_ea:ea_t*)→int
Data reference is being analyzed. plugin may correct ‘code_ea’ (e.g. for thumb mode refs, we clear the last bit)
Parameters:

-
to – (::ea_t)

-
may_define – (bool)

-
code_ea – (::ea_t *)

Returns:
0 done dref analysis
Returns:
0: not implemented or continue
ev_may_show_sreg(current_ea:ida_idaapi.ea_t)→int
The kernel wants to display the segment registers in the messages window.
Parameters:
current_ea – (::ea_t)
Returns:
<0: if the kernel should not show the segment registers. (assuming that the module has done it)
Returns:
0: not implemented
ev_auto_queue_empty(type:atype_t)→int
One analysis queue is empty.
Parameters:
type – (atype_t)
Returns:
void: see also idb_event::auto_empty_finally
ev_validate_flirt_func(start_ea:ida_idaapi.ea_t, funcname:str)→int
Flirt has recognized a library function. This callback can be used by a plugin or proc module to intercept it and validate such a function.
Parameters:

-
start_ea – (::ea_t)

-
funcname – (const char *)

Returns:
-1: do not create a function,
Returns:
0: function is validated
ev_adjust_libfunc_ea(sig:idasgn_tconst*, libfun:libfunc_tconst*, ea:ea_t*)→int
Called when a signature module has been matched against bytes in the database. This is used to compute the offset at which a particular module’s libfunc should be applied.
Parameters:

-
sig – (const idasgn_t *)

-
libfun – (const libfunc_t *)

-
ea – (::ea_t *)

Returns:
1: the ea_t pointed to by the third argument was modified.
Returns:
<=0: not modified. use default algorithm.
ev_assemble(ea:ida_idaapi.ea_t, cs:ida_idaapi.ea_t, ip:ida_idaapi.ea_t, use32:bool, line:str)→PyObject*
Assemble an instruction. (display a warning if an error occurs).
Parameters:

-
ea – (::ea_t) linear address of instruction

-
cs – (::ea_t) cs of instruction

-
ip – (::ea_t) ip of instruction

-
use32 – (bool) is 32-bit segment?

-
line – (const char *) line to assemble

Returns:
size of the instruction in bytes
ev_extract_address(out_ea:ea_t*, screen_ea:ida_idaapi.ea_t, string:str, position:int)→int
Extract address from a string.
Parameters:

-
out_ea – (ea_t *), out

-
screen_ea – (ea_t)

-
string – (const char *)

-
position – (size_t)

Returns:
1: ok
Returns:
0: kernel should use the standard algorithm
Returns:
-1: error
ev_realcvt(m:void*, e:fpvalue_t*, swt:uint16)→int
Floating point -> IEEE conversion
Parameters:

-
m – (void *) ptr to processor-specific floating point value

-
e – (fpvalue_t *) IDA representation of a floating point value

-
swt – (uint16) operation (see realcvt() in ieee.h)

Returns:
0: not implemented
ev_gen_asm_or_lst(starting:bool, fp:FILE*, is_asm:bool, flags:int, outline:html_line_cb_t**)→int
Callback: generating asm or lst file. The kernel calls this callback twice, at the beginning and at the end of listing generation. The processor module can intercept this event and adjust its output
Parameters:

-
starting – (bool) beginning listing generation

-
fp – (FILE *) output file

-
is_asm – (bool) true:assembler, false:listing

-
flags – (int) flags passed to gen_file()

-
outline – (html_line_cb_t **) ptr to ptr to outline callback. if this callback is defined for this code, it will be used by the kernel to output the generated lines

Returns:
void:
ev_gen_map_file(nlines:int*, fp:FILE*)→int
Generate map file. If not implemented the kernel itself will create the map file.
Parameters:

-
nlines – (int *) number of lines in map file (-1 means write error)

-
fp – (FILE *) output file

Returns:
0: not implemented
Returns:
1: ok
Returns:
-1: write error
ev_create_flat_group(image_base:ida_idaapi.ea_t, bitness:int, dataseg_sel:sel_t)→int
Create special segment representing the flat group.
Parameters:

-
image_base – (::ea_t)

-
bitness – (int)

-
dataseg_sel – (::sel_t) return value is ignored

ev_getreg(regval:uval_t*, regnum:int)→int
IBM PC only internal request, should never be used for other purpose Get register value by internal index
Parameters:

-
regval – (uval_t *), out

-
regnum – (int)

Returns:
1: ok
Returns:
0: not implemented
Returns:
-1: failed (undefined value or bad regnum)
ev_analyze_prolog(ea:ida_idaapi.ea_t)→int
Analyzes function prolog, epilog, and updates purge, and function attributes
Parameters:
ea – (::ea_t) start of function
Returns:
1: ok
Returns:
0: not implemented
ev_calc_spdelta(spdelta:sval_t*, insn:insn_tconst*)→int
Calculate amount of change to sp for the given insn. This event is required to decompile code snippets.
Parameters:

-
spdelta – (sval_t *)

-
insn – (const insn_t *)

Returns:
1: ok
Returns:
0: not implemented
ev_calcrel()→int
Reserved.
ev_find_reg_value(pinsn:insn_tconst*, reg:int)→PyObject*
Find register value via a register tracker. The returned value in ‘out’ is valid before executing the instruction.
Parameters:

-
pinsn – (const insn_t *) instruction

-
reg – (int) register index

Returns:
1: if implemented, and value was found
Returns:
0: not implemented, -1 decoding failed, or no value found
ev_find_op_value(pinsn:insn_tconst*, opn:int)→PyObject*
Find operand value via a register tracker. The returned value in ‘out’ is valid before executing the instruction.
Parameters:

-
pinsn – (const insn_t *) instruction

-
opn – (int) operand index

Returns:
1: if implemented, and value was found
Returns:
0: not implemented, -1 decoding failed, or no value found
ev_replaying_undo(action_name:str, vec:undo_records_tconst*, is_undo:bool)→int
Replaying an undo/redo buffer
Parameters:

-
action_name – (const char *) action that we perform undo/redo for. may be nullptr for intermediate buffers.

-
vec – (const undo_records_t *)

-
is_undo – (bool) true if performing undo, false if performing redo This event may be generated multiple times per undo/redo

ev_ending_undo(action_name:str, is_undo:bool)→int
Ended undoing/redoing an action
Parameters:

-
action_name – (const char *) action that we finished undoing/redoing. is not nullptr.

-
is_undo – (bool) true if performing undo, false if performing redo

ev_set_code16_mode(ea:ida_idaapi.ea_t, code16:bool)→int
Some processors have ISA 16-bit mode e.g. ARM Thumb mode, PPC VLE, MIPS16 Set ISA 16-bit mode
Parameters:

-
ea – (ea_t) address to set new ISA mode

-
code16 – (bool) true for 16-bit mode, false for 32-bit mode

ev_get_code16_mode(ea:ida_idaapi.ea_t)→int
Get ISA 16-bit mode
Parameters:
ea – (ea_t) address to get the ISA mode
Returns:
1: 16-bit mode
Returns:
0: not implemented or 32-bit mode
ev_get_procmod()→int
Get pointer to the processor module object. All processor modules must implement this. The pointer is returned as size_t.
ev_asm_installed(asmnum:int)→int
After setting a new assembler
Parameters:
asmnum – (int) See also ev_newasm
ev_get_reg_accesses(accvec:reg_accesses_t, insn:insn_tconst*, flags:int)→int
Get info about the registers that are used/changed by an instruction.
Parameters:

-
accvec – (reg_accesses_t*) out: info about accessed registers

-
insn – (const insn_t *) instruction in question

-
flags – (int) reserved, must be 0

Returns:
-1: if accvec is nullptr
Returns:
1: found the requested access (and filled accvec)
Returns:
0: not implemented
ev_is_control_flow_guard(p_reg:int*, insn:insn_tconst*)→int
Detect if an instruction is a “thunk call” to a flow guard function (equivalent to call reg/return/nop)
Parameters:

-
p_reg – (int *) indirect register number, may be -1

-
insn – (const insn_t *) call/jump instruction

Returns:
-1: no thunk detected
Returns:
1: indirect call
Returns:
2: security check routine call (NOP)
Returns:
3: return thunk
Returns:
0: not implemented
ev_create_merge_handlers(md:merge_data_t*)→int
Create merge handlers, if needed
Parameters:
md – (merge_data_t *) This event is generated immediately after opening idbs.
Returns:
must be 0
ev_privrange_changed(old_privrange:range_t, delta:adiff_t)→int
Privrange interval has been moved to a new location. Most common actions to be done by module in this case: fix indices of netnodes used by module
Parameters:

-
old_privrange – (const range_t *) - old privrange interval

-
delta – (::adiff_t)

Returns:
0: Ok
Returns:
-1: error (and message in errbuf)
ev_cvt64_supval(node:nodeidx_t, tag:uchar, idx:nodeidx_t, data:ucharconst*)→int
perform 32-64 conversion for a netnode array element
Parameters:

-
node – (::nodeidx_t)

-
tag – (uchar)

-
idx – (::nodeidx_t)

-
data – (const uchar *)

Returns:
0: nothing was done
Returns:
1: converted successfully
Returns:
-1: error (and message in errbuf)
ev_cvt64_hashval(node:nodeidx_t, tag:uchar, name:str, data:ucharconst*)→int
perform 32-64 conversion for a hash value
Parameters:

-
node – (::nodeidx_t)

-
tag – (uchar)

-
name – (const ::char *)

-
data – (const uchar *)

Returns:
0: nothing was done
Returns:
1: converted successfully
Returns:
-1: error (and message in errbuf)
ev_gen_stkvar_def(outctx:outctx_t*, stkvar:udm_t, v:int, tid:tid_t)→int
Generate stack variable definition line Default line is varname = type ptr value, where ‘type’ is one of byte,word,dword,qword,tbyte
Parameters:

-
outctx – (outctx_t *)

-
stkvar – (const udm_t *)

-
v – (sval_t)

-
tid – (tid_t) stkvar TID

Returns:
1: ok
Returns:
0: not implemented
ev_is_addr_insn(type:int*, insn:insn_tconst*)→int
Does the instruction calculate some address using an immediate operand? e.g. in PC such operand may be o_displ: ‘lea eax, [esi+4]’
Parameters:
type – (int *) pointer to the returned instruction type:

-
0 the “add” instruction (the immediate operand is a relative value)

-
1 the “move” instruction (the immediate operand is an absolute value)

-
2 the “sub” instruction (the immediate operand is a relative value)

Parameters:
insn – (const insn_t *) instruction
Returns:
>0 the operand number+1
Returns:
0: not implemented
ev_next_exec_insn(target:ea_t*, ea:ida_idaapi.ea_t, tid:int, getreg:processor_t::regval_getter_t*, regvalues:regval_t)→int
Get next address to be executed This function must return the next address to be executed. If the instruction following the current one is executed, then it must return BADADDR Usually the instructions to consider are: jumps, branches, calls, returns. This function is essential if the ‘single step’ is not supported in hardware.
Parameters:

-
target – (::ea_t *), out: pointer to the answer

-
ea – (::ea_t) instruction address

-
tid – (int) current therad id

-
getreg – (::processor_t::regval_getter_t *) function to get register values

-
regvalues – (const regval_t *) register values array

Returns:
0: unimplemented
Returns:
1: implemented
ev_calc_step_over(target:ea_t*, ip:ida_idaapi.ea_t)→int
Calculate the address of the instruction which will be executed after “step over”. The kernel will put a breakpoint there. If the step over is equal to step into or we cannot calculate the address, return BADADDR.
Parameters:

-
target – (::ea_t *) pointer to the answer

-
ip – (::ea_t) instruction address

Returns:
0: unimplemented
Returns:
1: implemented
ev_calc_next_eas(res:eavec_t*, insn:insn_tconst*, over:bool)→int
Calculate list of addresses the instruction in ‘insn’ may pass control to. This callback is required for source level debugging.
Parameters:

-
res – (eavec_t *), out: array for the results.

-
insn – (const insn_t*) the instruction

-
over – (bool) calculate for step over (ignore call targets)

Returns:
<0: incalculable (indirect jumps, for example)
Returns:
>=0: number of addresses of called functions in the array. They must be put at the beginning of the array (0 if over=true)
ev_get_macro_insn_head(head:ea_t*, ip:ida_idaapi.ea_t)→int
Calculate the start of a macro instruction. This notification is called if IP points to the middle of an instruction
Parameters:

-
head – (::ea_t *), out: answer, BADADDR means normal instruction

-
ip – (::ea_t) instruction address

Returns:
0: unimplemented
Returns:
1: implemented
ev_get_dbr_opnum(opnum:int*, insn:insn_tconst*)→int
Get the number of the operand to be displayed in the debugger reference view (text mode).
Parameters:

-
opnum – (int *) operand number (out, -1 means no such operand)

-
insn – (const insn_t*) the instruction

Returns:
0: unimplemented
Returns:
1: implemented
ev_insn_reads_tbit(insn:insn_tconst*, getreg:processor_t::regval_getter_t*, regvalues:regval_t)→int
Check if insn will read the TF bit.
Parameters:

-
insn – (const insn_t*) the instruction

-
getreg – (::processor_t::regval_getter_t *) function to get register values

-
regvalues – (const regval_t *) register values array

Returns:
2: yes, will generate ‘step’ exception
Returns:
1: yes, will store the TF bit in memory
Returns:
0: no
ev_clean_tbit(ea:ida_idaapi.ea_t, getreg:processor_t::regval_getter_t*, regvalues:regval_t)→int
Clear the TF bit after an insn like pushf stored it in memory.
Parameters:

-
ea – (::ea_t) instruction address

-
getreg – (::processor_t::regval_getter_t *) function to get register values

-
regvalues – (const regval_t *) register values array

Returns:
1: ok
Returns:
0: failed
ev_get_reg_info(main_regname:charconst**, bitrange:bitrange_t, regname:str)→int
Get register information by its name. example: “ah” returns: * main_regname=”eax” * bitrange_t = { offset==8, nbits==8 }

This callback may be unimplemented if the register names are all present in processor_t::reg_names and they all have the same size
Parameters:

-
main_regname – (const char **), out

-
bitrange – (bitrange_t *), out: position and size of the value within ‘main_regname’ (empty bitrange == whole register)

-
regname – (const char *)

Returns:
1: ok
Returns:
-1: failed (not found)
Returns:
0: unimplemented
ev_update_call_stack(stack:call_stack_t, tid:int, getreg:processor_t::regval_getter_t*, regvalues:regval_t)→int
Calculate the call stack trace for the given thread. This callback is invoked when the process is suspended and should fill the ‘trace’ object with the information about the current call stack. Note that this callback is NOT invoked if the current debugger backend implements stack tracing via debugger_t::event_t::ev_update_call_stack. The debugger-specific algorithm takes priority. Implementing this callback in the processor module is useful when multiple debugging platforms follow similar patterns, and thus the same processor-specific algorithm can be used for different platforms.
Parameters:

-
stack – (call_stack_t *) result

-
tid – (int) thread id

-
getreg – (::processor_t::regval_getter_t *) function to get register values

-
regvalues – (const regval_t *) register values array

Returns:
1: ok
Returns:
-1: failed
Returns:
0: unimplemented
ev_setup_til()→int
Setup default type libraries. (called after loading a new file into the database). The processor module may load tils, setup memory model and perform other actions required to set up the type system. This is an optional callback.
Returns:
void:
ev_get_abi_info(comp:comp_t)→int
Get all possible ABI names and optional extensions for given compiler abiname/option is a string entirely consisting of letters, digits and underscore
Parameters:
comp – (comp_t) - compiler ID
Returns:
0: not implemented
Returns:
1: ok
ev_max_ptr_size()→int
Get maximal size of a pointer in bytes.
Returns:
max possible size of a pointer
ev_get_default_enum_size()→int
Get default enum size. Not generated anymore. inf_get_cc_size_e() is used instead
ev_get_cc_regs(regs:callregs_t, cc:callcnv_t)→int
Get register allocation convention for given calling convention
Parameters:

-
regs – (callregs_t *), out

-
cc – (::callcnv_t)

Returns:
1:
Returns:
0: not implemented
ev_get_simd_types(out:simd_info_vec_t, simd_attrs:simd_info_t, argloc:argloc_t, create_tifs:bool, insn:insn_tconst*, op:op_tconst*)→int
Get SIMD-related types according to given attributes ant/or argument location
Parameters:

-
out – (simd_info_vec_t *)

-
simd_attrs – (const simd_info_t *), may be nullptr

-
argloc – (const argloc_t *), may be nullptr

-
create_tifs – (bool) return valid tinfo_t objects, create if neccessary

-
insn – (::const insn_t *)

-
op – (::const op_t *)

Returns:
number: of found types
Returns:
-1: error If insn and op are specified, return only the types that match them
ev_calc_cdecl_purged_bytes(ea:ida_idaapi.ea_t)→int
Calculate number of purged bytes after call.
Parameters:
ea – (::ea_t) address of the call instruction
Returns:
number of purged bytes (usually add sp, N)
ev_calc_purged_bytes(p_purged_bytes:int*, fti:func_type_data_t)→int
Calculate number of purged bytes by the given function type.
Parameters:

-
p_purged_bytes – (int *) ptr to output

-
fti – (const func_type_data_t *) func type details

Returns:
1:
Returns:
0: not implemented
ev_calc_retloc(retloc:argloc_t, rettype:tinfo_t, cc:callcnv_t)→int
Calculate return value location.
Parameters:

-
retloc – (argloc_t *)

-
rettype – (const tinfo_t *)

-
cc – (::callcnv_t)

Returns:
0: not implemented
Returns:
1: ok,
Returns:
-1: error
ev_calc_arglocs(fti:func_type_data_t)→int
Calculate function argument locations. This callback should fill retloc, all arglocs, and stkargs. This callback is never called for CM_CC_SPECIAL functions.
Parameters:
fti – (func_type_data_t *) points to the func type info
Returns:
0: not implemented
Returns:
1: ok
Returns:
-1: error
ev_calc_varglocs(ftd:func_type_data_t, aux_regs:regobjs_t, aux_stkargs:relobj_t, nfixed:int)→int
Calculate locations of the arguments that correspond to ‘…’.
Parameters:

-
ftd – (func_type_data_t *), inout: info about all arguments (including varargs)

-
aux_regs – (regobjs_t *) buffer for hidden register arguments, may be nullptr

-
aux_stkargs – (relobj_t *) buffer for hidden stack arguments, may be nullptr

-
nfixed – (int) number of fixed arguments

Returns:
0: not implemented
Returns:
1: ok
Returns:
-1: error On some platforms variadic calls require passing additional information: for example, number of floating variadic arguments must be passed in rax on gcc-x64. The locations and values that constitute this additional information are returned in the buffers pointed by aux_regs and aux_stkargs
ev_adjust_argloc(argloc:argloc_t, optional_type:tinfo_t, size:int)→int
Adjust argloc according to its type/size and platform endianess
Parameters:

-
argloc – (argloc_t *), inout

-
size – (int) ‘size’ makes no sense if type != nullptr (type->get_size() should be used instead)

Returns:
0: not implemented
Returns:
1: ok
Returns:
-1: error
ev_lower_func_type(argnums:intvec_t*, fti:func_type_data_t)→int
Get function arguments which should be converted to pointers when lowering function prototype. The processor module can also modify ‘fti’ in order to make non-standard conversion of some arguments.
Parameters:

-
argnums – (intvec_t *), out - numbers of arguments to be converted to pointers in acsending order

-
fti – (func_type_data_t *), inout func type details

Returns:
0: not implemented
Returns:
1: argnums was filled
Returns:
2: argnums was filled and made substantial changes to fti argnums[0] can contain a special negative value indicating that the return value should be passed as a hidden ‘retstr’ argument: -1 this argument is passed as the first one and the function returns a pointer to the argument, -2 this argument is passed as the last one and the function returns a pointer to the argument, -3 this argument is passed as the first one and the function returns ‘void’.
ev_equal_reglocs(a1:argloc_t, a2:argloc_t)→int
Are 2 register arglocs the same?. We need this callback for the pc module.
Parameters:

-
a1 – (argloc_t *)

-
a2 – (argloc_t *)

Returns:
1: yes
Returns:
-1: no
Returns:
0: not implemented
ev_use_stkarg_type(ea:ida_idaapi.ea_t, arg:funcarg_t)→int
Use information about a stack argument.
Parameters:

-
ea – (::ea_t) address of the push instruction which pushes the function argument into the stack

-
arg – (const funcarg_t *) argument info

Returns:
1: ok
Returns:
<=0: failed, the kernel will create a comment with the argument name or type for the instruction
ev_use_regarg_type(ea:ida_idaapi.ea_t, rargs:funcargvec_tconst*)→PyObject*
Use information about register argument.
Parameters:

-
ea – (::ea_t) address of the instruction

-
rargs – (const funcargvec_t *) vector of register arguments (including regs extracted from scattered arguments)

Returns:
1:
Returns:
0: not implemented
ev_use_arg_types(ea:ida_idaapi.ea_t, fti:func_type_data_t, rargs:funcargvec_t*)→int
Use information about callee arguments.
Parameters:

-
ea – (::ea_t) address of the call instruction

-
fti – (func_type_data_t *) info about function type

-
rargs – (funcargvec_t *) array of register arguments

Returns:
1: (and removes handled arguments from fti and rargs)
Returns:
0: not implemented
ev_arg_addrs_ready(caller:ida_idaapi.ea_t, n:int, tif:tinfo_t, addrs:ea_t*)→int
Argument address info is ready.
Parameters:

-
caller – (::ea_t)

-
n – (int) number of formal arguments

-
tif – (tinfo_t *) call prototype

-
addrs – (::ea_t *) argument intilization addresses

Returns:
<0: do not save into idb; other values mean “ok to save”
ev_decorate_name(name:str, mangle:bool, cc:int, optional_type:tinfo_t)→PyObject*
Decorate/undecorate a C symbol name.
Parameters:

-
name – (const char *) name of symbol

-
mangle – (bool) true-mangle, false-unmangle

-
cc – (::callcnv_t) calling convention

Returns:
1: if success
Returns:
0: not implemented or failed
ev_arch_changed()→int
The loader is done parsing arch-related information, which the processor module might want to use to finish its initialization.
Returns:
1: if success
Returns:
0: not implemented or failed
ev_get_stkarg_area_info(out:stkarg_area_info_t, cc:callcnv_t)→int
Get some metrics of the stack argument area.
Parameters:

-
out – (stkarg_area_info_t *) ptr to stkarg_area_info_t

-
cc – (::callcnv_t) calling convention

Returns:
1: if success
Returns:
0: not implemented
ev_last_cb_before_loader()→intev_loader()→int
This code and higher ones are reserved for the loaders. The arguments and the return values are defined by the loaders
ida_idp.get_idp_notifier_addr(arg1:PyObject*)→PyObject*ida_idp.get_idp_notifier_ud_addr(hooks:IDP_Hooks)→PyObject*ida_idp.delay_slot_insn(ea:ea_t*, bexec:bool*, fexec:bool*)→boolida_idp.get_reg_info(regname:str, bitrange:bitrange_t)→strida_idp.sizeof_ldbl()→intida_idp.REAL_ERROR_FORMAT=-1ida_idp.REAL_ERROR_RANGE=-2ida_idp.REAL_ERROR_BADDATA=-3ida_idp.IDPOPT_STR=1ida_idp.IDPOPT_NUM=2ida_idp.IDPOPT_BIT=3ida_idp.IDPOPT_FLT=4ida_idp.IDPOPT_I64=5ida_idp.IDPOPT_OK=0ida_idp.IDPOPT_BADKEY=1ida_idp.IDPOPT_BADTYPE=2ida_idp.IDPOPT_BADVALUE=3classida_idp.processor_t
Bases: `IDP_Hooks`
idb_hooksget_idpdesc()
This function must be present and should return the list of short processor names similar to the one in ph.psnames. This method can be overridden to return to the kernel a different IDP description.
get_auxpref(insn)
This function returns insn.auxpref value
ev_newprc(*args)
Before changing processor type.
Parameters:

-
pnum – (int) processor number in the array of processor names

-
keep_cfg – (bool) true: do not modify kernel configuration

Returns:
1: ok
Returns:
<0: prohibit
ev_newfile(*args)
A new file has been loaded.
Parameters:
fname – (char *) input file name
ev_oldfile(*args)
An old file has been loaded.
Parameters:
fname – (char *) input file name
ev_newbinary(*args)
IDA is about to load a binary file.
Parameters:

-
filename – (char *) binary file name

-
fileoff – (qoff64_t) offset in the file

-
basepara – (::ea_t) base loading paragraph

-
binoff – (::ea_t) loader offset

-
nbytes – (::uint64) number of bytes to load

ev_endbinary(*args)
IDA has loaded a binary file.
Parameters:
ok – (bool) file loaded successfully?
ev_set_idp_options(keyword, value_type, value, idb_loaded)
Set IDP-specific configuration option Also see set_options_t in config.hpp
Parameters:

-
keyword – (const char *)

-
value_type – (int)

-
value – (const void *)

-
idb_loaded – (bool) true if the ev_oldfile/ev_newfile events have been generated

Returns:
1: ok
Returns:
0: not implemented
Returns:
-1: error (and message in errbuf)
ev_set_proc_options(*args)
Called if the user specified an option string in the command line: -p:. Can be used for setting a processor subtype. Also called if option string is passed to set_processor_type() and IDC’s SetProcessorType().
Parameters:

-
options – (const char *)

-
confidence – (int) 0: loader’s suggestion 1: user’s decision

Returns:
<0: if bad option string
ev_ana_insn(*args)
Analyze one instruction and fill ‘out’ structure. This function shouldn’t change the database, flags or anything else. All these actions should be performed only by emu_insn() function. insn_t::ea contains address of instruction to analyze.
Parameters:
out – (insn_t *)
Returns:
length of the instruction in bytes, 0 if instruction can’t be decoded.
Returns:
0: if instruction can’t be decoded.
ev_emu_insn(*args)
Emulate instruction, create cross-references, plan to analyze subsequent instructions, modify flags etc. Upon entrance to this function, all information about the instruction is in ‘insn’ structure.
Parameters:
insn – (const insn_t *)
Returns:
1: ok
Returns:
-1: the kernel will delete the instruction
ev_out_header(*args)
Function to produce start of disassembled text
Parameters:
outctx – (outctx_t *)
Returns:
void:
ev_out_footer(*args)
Function to produce end of disassembled text
Parameters:
outctx – (outctx_t *)
Returns:
void:
ev_out_segstart(ctx, s)
Function to produce start of segment
Parameters:

-
outctx – (outctx_t *)

-
seg – (segment_t *)

Returns:
1: ok
Returns:
0: not implemented
ev_out_segend(ctx, s)
Function to produce end of segment
Parameters:

-
outctx – (outctx_t *)

-
seg – (segment_t *)

Returns:
1: ok
Returns:
0: not implemented
ev_out_assumes(*args)
Function to produce assume directives when segment register value changes.
Parameters:
outctx – (outctx_t *)
Returns:
1: ok
Returns:
0: not implemented
ev_out_insn(*args)
Generate text representation of an instruction in ‘ctx.insn’ outctx_t provides functions to output the generated text. This function shouldn’t change the database, flags or anything else. All these actions should be performed only by emu_insn() function.
Parameters:
outctx – (outctx_t *)
Returns:
void:
ev_out_mnem(*args)
Generate instruction mnemonics. This callback should append the colored mnemonics to ctx.outbuf Optional notification, if absent, out_mnem will be called.
Parameters:
outctx – (outctx_t *)
Returns:
1: if appended the mnemonics
Returns:
0: not implemented
ev_out_operand(*args)
Generate text representation of an instruction operand outctx_t provides functions to output the generated text. All these actions should be performed only by emu_insn() function.
Parameters:

-
outctx – (outctx_t *)

-
op – (const op_t *)

Returns:
1: ok
Returns:
-1: operand is hidden
ev_out_data(*args)
Generate text representation of data items This function may change the database and create cross-references if analyze_only is set
Parameters:

-
outctx – (outctx_t *)

-
analyze_only – (bool)

Returns:
1: ok
Returns:
0: not implemented
ev_out_label(*args)
The kernel is going to generate an instruction label line or a function header.
Parameters:

-
outctx – (outctx_t *)

-
colored_name – (const char *)

Returns:
<0: if the kernel should not generate the label
Returns:
0: not implemented or continue
ev_out_special_item(*args)
Generate text representation of an item in a special segment i.e. absolute symbols, externs, communal definitions etc
Parameters:

-
outctx – (outctx_t *)

-
segtype – (uchar)

Returns:
1: ok
Returns:
0: not implemented
Returns:
-1: overflow
ev_gen_regvar_def(ctx, v)
Generate register variable definition line.
Parameters:

-
outctx – (outctx_t *)

-
v – (regvar_t *)

Returns:
>0: ok, generated the definition text
Returns:
0: not implemented
ev_gen_src_file_lnnum(*args)Callback: generate analog of:
#line 123
Parameters:

-
outctx – (outctx_t *) output context

-
file – (const char *) source file (may be nullptr)

-
lnnum – (size_t) line number

Returns:
1: directive has been generated
Returns:
0: not implemented
ev_creating_segm(s)
A new segment is about to be created.
Parameters:
seg – (segment_t *)
Returns:
1: ok
Returns:
<0: segment should not be created
ev_moving_segm(s, to_ea, flags)
May the kernel move the segment?
Parameters:

-
seg – (segment_t *) segment to move

-
to – (::ea_t) new segment start address

-
flags – (int) combination of Move segment flags

Returns:
0: yes
Returns:
<0: the kernel should stop
ev_coagulate(*args)
Try to define some unexplored bytes. This notification will be called if the kernel tried all possibilities and could not find anything more useful than to convert to array of bytes. The module can help the kernel and convert the bytes into something more useful.
Parameters:
start_ea – (::ea_t)
Returns:
number of converted bytes
ev_undefine(*args)
An item in the database (insn or data) is being deleted.
Parameters:
ea – (ea_t)
Returns:
1: do not delete srranges at the item end
Returns:
0: srranges can be deleted
ev_treat_hindering_item(*args)
An item hinders creation of another item.
Parameters:

-
hindering_item_ea – (::ea_t)

-
new_item_flags – (flags64_t) (0 for code)

-
new_item_ea – (::ea_t)

-
new_item_length – (::asize_t)

Returns:
0: no reaction
Returns:
!=0: the kernel may delete the hindering item
ev_rename(*args)
The kernel is going to rename a byte.
Parameters:

-
ea – (::ea_t)

-
new_name – (const char *)

Returns:
<0: if the kernel should not rename it.
Returns:
2: to inhibit the notification. I.e., the kernel should not rename, but ‘set_name()’ should return ‘true’. also see renamed the return value is ignored when kernel is going to delete name
ev_is_far_jump(*args)
is indirect far jump or call instruction? meaningful only if the processor has ‘near’ and ‘far’ reference types
Parameters:
icode – (int)
Returns:
0: not implemented
Returns:
1: yes
Returns:
-1: no
ev_is_sane_insn(*args)
Is the instruction sane for the current file type?
Parameters:

-
insn – (const insn_t*) the instruction

-
no_crefs – (int) 1: the instruction has no code refs to it. ida just tries to convert unexplored bytes to an instruction (but there is no other reason to convert them into an instruction) 0: the instruction is created because of some coderef, user request or another weighty reason.

Returns:
>=0: ok
Returns:
<0: no, the instruction isn’t likely to appear in the program
ev_is_call_insn(*args)
Is the instruction a “call”?
Parameters:
insn – (const insn_t *) instruction
Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_is_ret_insn(*args)
Is the instruction a “return”?
Parameters:

-
insn – (const insn_t *) instruction

-
flags – (uchar), combination of IRI_… flags (see above)

Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_may_be_func(*args)
Can a function start here?
Parameters:

-
insn – (const insn_t*) the instruction

-
state – (int) autoanalysis phase 0: creating functions 1: creating chunks

Returns:
probability 1..100
ev_is_basic_block_end(*args)
Is the current instruction end of a basic block? This function should be defined for processors with delayed jump slots.
Parameters:

-
insn – (const insn_t*) the instruction

-
call_insn_stops_block – (bool)

Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_is_indirect_jump(*args)
Determine if instruction is an indirect jump. If CF_JUMP bit cannot describe all jump types jumps, please define this callback.
Parameters:
insn – (const insn_t*) the instruction
Returns:
0: use CF_JUMP
Returns:
1: no
Returns:
2: yes
ev_is_insn_table_jump(*args)
Reserved.
ev_is_switch(*args)
Find ‘switch’ idiom or override processor module’s decision. It will be called for instructions marked with CF_JUMP.
Parameters:

-
si – (switch_info_t *), out

-
insn – (const insn_t *) instruction possibly belonging to a switch

Returns:
1: switch is found, ‘si’ is filled. IDA will create the switch using the filled ‘si’
Returns:
-1: no switch found. This value forbids switch creation by the processor module
Returns:
0: not implemented
ev_create_switch_xrefs(*args)
Create xrefs for a custom jump table.
Parameters:

-
jumpea – (::ea_t) address of the jump insn

-
si – (const switch_info_t *) switch information

Returns:
must return 1 Must be implemented if module uses custom jump tables, SWI_CUSTOM
ev_is_align_insn(*args)
Is the instruction created only for alignment purposes?. Do not directly call this function, use is_align_insn()
Parameters:
ea – (ea_t) - instruction address
Returns:
number: of bytes in the instruction
ev_is_alloca_probe(*args)
Does the function at ‘ea’ behave like __alloca_probe?
Parameters:
ea – (::ea_t)
Returns:
1: yes
Returns:
0: no
ev_is_sp_based(mode, insn, op)
Check whether the operand is relative to stack pointer or frame pointer This event is used to determine how to output a stack variable If not implemented, then all operands are sp based by default. Implement this event only if some stack references use frame pointer instead of stack pointer.
Parameters:

-
mode – (int *) out, combination of SP/FP operand flags

-
insn – (const insn_t *)

-
op – (const op_t *)

Returns:
0: not implemented
Returns:
1: ok
ev_can_have_type(*args)
Can the operand have a type as offset, segment, decimal, etc? (for example, a register AX can’t have a type, meaning that the user can’t change its representation. see bytes.hpp for information about types and flags)
Parameters:
op – (const op_t *)
Returns:
0: unknown
Returns:
<0: no
Returns:
1: yes
ev_cmp_operands(*args)
Compare instruction operands
Parameters:

-
op1 – (const op_t*)

-
op2 – (const op_t*)

Returns:
1: equal
Returns:
-1: not equal
Returns:
0: not implemented
ev_get_operand_string(buf, insn, opnum)
Request text string for operand (cli, java, …).
Parameters:

-
insn – (const insn_t*) the instruction

-
opnum – (int) operand number, -1 means any string operand

Returns:
0: no string (or empty string)
Returns:
>0: original string length without terminating zero
ev_str2reg(*args)
Convert a register name to a register number. The register number is the register index in the processor_t::reg_names array Most processor modules do not need to implement this callback It is useful only if processor_t::reg_names[reg] does not provide the correct register names
Parameters:
regname – (const char *)
Returns:
register: number + 1
Returns:
0: not implemented or could not be decoded
ev_get_autocmt(*args)
Callback: get dynamic auto comment. Will be called if the autocomments are enabled and the comment retrieved from ida.int starts with ‘$!’. ‘insn’ contains valid info.
Parameters:
insn – (const insn_t*) the instruction
Returns:
1: new comment has been generated
Returns:
0: callback has not been handled. the buffer must not be changed in this case
ev_func_bounds(_possible_return_code, pfn, max_func_end_ea)
find_func_bounds() finished its work. The module may fine tune the function bounds
Parameters:

-
possible_return_code – (int *), in/out

-
pfn – (func_t *)

-
max_func_end_ea – (::ea_t) (from the kernel’s point of view)

Returns:
void:
ev_verify_sp(pfn)
All function instructions have been analyzed. Now the processor module can analyze the stack pointer for the whole function
Parameters:
pfn – (func_t *)
Returns:
0: ok
Returns:
<0: bad stack pointer
ev_verify_noreturn(pfn)
The kernel wants to set ‘noreturn’ flags for a function.
Parameters:
pfn – (func_t *)
Returns:
0: ok. any other value: do not set ‘noreturn’ flag
ev_create_func_frame(pfn)
Create a function frame for a newly created function Set up frame size, its attributes etc
Parameters:
pfn – (func_t *)
Returns:
1: ok
Returns:
0: not implemented
ev_get_frame_retsize(frsize, pfn)
Get size of function return address in bytes If this event is not implemented, the kernel will assume * 8 bytes for 64-bit function * 4 bytes for 32-bit function * 2 bytes otherwise
Parameters:

-
frsize – (int *) frame size (out)

-
pfn – (const func_t *), can’t be nullptr

Returns:
1: ok
Returns:
0: not implemented
ev_coagulate_dref(from_ea, to_ea, may_define, _code_ea)
Data reference is being analyzed. plugin may correct ‘code_ea’ (e.g. for thumb mode refs, we clear the last bit)
Parameters:

-
to – (::ea_t)

-
may_define – (bool)

-
code_ea – (::ea_t *)

Returns:
0 done dref analysis
Returns:
0: not implemented or continue
ev_may_show_sreg(*args)
The kernel wants to display the segment registers in the messages window.
Parameters:
current_ea – (::ea_t)
Returns:
<0: if the kernel should not show the segment registers. (assuming that the module has done it)
Returns:
0: not implemented
ev_auto_queue_empty(*args)
One analysis queue is empty.
Parameters:
type – (atype_t)
Returns:
void: see also idb_event::auto_empty_finally
ev_validate_flirt_func(*args)
Flirt has recognized a library function. This callback can be used by a plugin or proc module to intercept it and validate such a function.
Parameters:

-
start_ea – (::ea_t)

-
funcname – (const char *)

Returns:
-1: do not create a function,
Returns:
0: function is validated
ev_assemble(*args)
Assemble an instruction. (display a warning if an error occurs).
Parameters:

-
ea – (::ea_t) linear address of instruction

-
cs – (::ea_t) cs of instruction

-
ip – (::ea_t) ip of instruction

-
use32 – (bool) is 32-bit segment?

-
line – (const char *) line to assemble

Returns:
size of the instruction in bytes
ev_gen_map_file(nlines, fp)
Generate map file. If not implemented the kernel itself will create the map file.
Parameters:

-
nlines – (int *) number of lines in map file (-1 means write error)

-
fp – (FILE *) output file

Returns:
0: not implemented
Returns:
1: ok
Returns:
-1: write error
ev_calc_step_over(target, ip)
Calculate the address of the instruction which will be executed after “step over”. The kernel will put a breakpoint there. If the step over is equal to step into or we cannot calculate the address, return BADADDR.
Parameters:

-
target – (::ea_t *) pointer to the answer

-
ip – (::ea_t) instruction address

Returns:
0: unimplemented
Returns:
1: implemented
closebase(*args)savebase(*args)auto_empty(*args)auto_empty_finally(*args)determined_main(*args)idasgn_loaded(*args)kernel_config_loaded(*args)compiler_changed(*args)segm_moved(from_ea, to_ea, size, changed_netmap)func_added(pfn)set_func_start(*args)set_func_end(*args)deleting_func(pfn)sgr_changed(*args)make_code(*args)make_data(*args)renamed(*args)ida_idp.str2sreg(name:str)
get segment register number from its name or -1
ida_idp.phclassida_idp.IDB_Hooks(_flags:int=0, _hkcb_flags:int=1)
Bases: `object`
thisownhook()→boolunhook()→boolclosebase()→None
The database will be closed now.
savebase()→None
The database is being saved.
upgraded(_from:int)→None
The database has been upgraded and the receiver can upgrade its info as well
auto_empty()→None
Info: all analysis queues are empty. This callback is called once when the initial analysis is finished. If the queue is not empty upon the return from this callback, it will be called later again.
auto_empty_finally()→None
Info: all analysis queues are empty definitively. This callback is called only once.
determined_main(main:ida_idaapi.ea_t)→None
The main() function has been determined.
Parameters:
main – (::ea_t) address of the main() function
extlang_changed(kind:int, el:extlang_t*, idx:int)→None
The list of extlangs or the default extlang was changed.
Parameters:

-
kind – (int) 0: extlang installed 1: extlang removed 2: default extlang changed

-
el – (extlang_t *) pointer to the extlang affected

-
idx – (int) extlang index

idasgn_loaded(short_sig_name:str)→None
FLIRT signature has been loaded for normal processing (not for recognition of startup sequences).
Parameters:
short_sig_name – (const char *)
kernel_config_loaded(pass_number:int)→None
This event is issued when ida.cfg is parsed.
Parameters:
pass_number – (int)
loader_finished(li:linput_t*, neflags:uint16, filetypename:str)→None
External file loader finished its work. Use this event to augment the existing loader functionality.
Parameters:

-
li – (linput_t *)

-
neflags – (uint16) Load file flags

-
filetypename – (const char *)

flow_chart_created(fc:qflow_chart_t)→None
Gui has retrieved a function flow chart. Plugins may modify the flow chart in this callback.
Parameters:
fc – (qflow_chart_t *)
compiler_changed(adjust_inf_fields:bool)→None
The kernel has changed the compiler information. ( idainfo::cc structure; get_abi_name)
Parameters:
adjust_inf_fields – (::bool) may change inf fields?
changing_ti(ea:ida_idaapi.ea_t, new_type:type_tconst*, new_fnames:p_listconst*)→None
An item typestring (c/c++ prototype) is to be changed.
Parameters:

-
ea – (::ea_t)

-
new_type – (const type_t *)

-
new_fnames – (const p_list *)

ti_changed(ea:ida_idaapi.ea_t, type:type_tconst*, fnames:p_listconst*)→None
An item typestring (c/c++ prototype) has been changed.
Parameters:

-
ea – (::ea_t)

-
type – (const type_t *)

-
fnames – (const p_list *)

changing_op_ti(ea:ida_idaapi.ea_t, n:int, new_type:type_tconst*, new_fnames:p_listconst*)→None
An operand typestring (c/c++ prototype) is to be changed.
Parameters:

-
ea – (::ea_t)

-
n – (int)

-
new_type – (const type_t *)

-
new_fnames – (const p_list *)

op_ti_changed(ea:ida_idaapi.ea_t, n:int, type:type_tconst*, fnames:p_listconst*)→None
An operand typestring (c/c++ prototype) has been changed.
Parameters:

-
ea – (::ea_t)

-
n – (int)

-
type – (const type_t *)

-
fnames – (const p_list *)

changing_op_type(ea:ida_idaapi.ea_t, n:int, opinfo:opinfo_t)→None
An operand type (offset, hex, etc…) is to be changed.
Parameters:

-
ea – (::ea_t)

-
n – (int) eventually or’ed with OPND_OUTER or OPND_ALL

-
opinfo – (const opinfo_t *) additional operand info

op_type_changed(ea:ida_idaapi.ea_t, n:int)→None
An operand type (offset, hex, etc…) has been set or deleted.
Parameters:

-
ea – (::ea_t)

-
n – (int) eventually or’ed with OPND_OUTER or OPND_ALL

segm_added(s:segment_t*)→None
A new segment has been created.
Parameters:
s – (segment_t *) See also adding_segm
deleting_segm(start_ea:ida_idaapi.ea_t)→None
A segment is to be deleted.
Parameters:
start_ea – (::ea_t)
segm_deleted(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, flags:int)→None
A segment has been deleted.
Parameters:

-
start_ea – (::ea_t)

-
end_ea – (::ea_t)

-
flags – (int)

changing_segm_start(s:segment_t*, new_start:ida_idaapi.ea_t, segmod_flags:int)→None
Segment start address is to be changed.
Parameters:

-
s – (segment_t *)

-
new_start – (::ea_t)

-
segmod_flags – (int)

segm_start_changed(s:segment_t*, oldstart:ida_idaapi.ea_t)→None
Segment start address has been changed.
Parameters:

-
s – (segment_t *)

-
oldstart – (::ea_t)

changing_segm_end(s:segment_t*, new_end:ida_idaapi.ea_t, segmod_flags:int)→None
Segment end address is to be changed.
Parameters:

-
s – (segment_t *)

-
new_end – (::ea_t)

-
segmod_flags – (int)

segm_end_changed(s:segment_t*, oldend:ida_idaapi.ea_t)→None
Segment end address has been changed.
Parameters:

-
s – (segment_t *)

-
oldend – (::ea_t)

changing_segm_name(s:segment_t*, oldname:str)→None
Segment name is being changed.
Parameters:

-
s – (segment_t *)

-
oldname – (const char *)

segm_name_changed(s:segment_t*, name:str)→None
Segment name has been changed.
Parameters:

-
s – (segment_t *)

-
name – (const char *)

changing_segm_class(s:segment_t*)→None
Segment class is being changed.
Parameters:
s – (segment_t *)
segm_class_changed(s:segment_t*, sclass:str)→None
Segment class has been changed.
Parameters:

-
s – (segment_t *)

-
sclass – (const char *)

segm_attrs_updated(s:segment_t*)→None
Segment attributes has been changed.
Parameters:
s – (segment_t *) This event is generated for secondary segment attributes (examples: color, permissions, etc)
segm_moved(_from:ida_idaapi.ea_t, to:ida_idaapi.ea_t, size:asize_t, changed_netmap:bool)→None
Segment has been moved.
Parameters:

-
to – (::ea_t)

-
size – (::asize_t)

-
changed_netmap – (bool) See also idb_event::allsegs_moved

allsegs_moved(info:segm_move_infos_t*)→None
Program rebasing is complete. This event is generated after series of segm_moved events
Parameters:
info – (segm_move_infos_t *)
func_added(pfn:func_t*)→None
The kernel has added a function.
Parameters:
pfn – (func_t *)
func_updated(pfn:func_t*)→None
The kernel has updated a function.
Parameters:
pfn – (func_t *)
set_func_start(pfn:func_t*, new_start:ida_idaapi.ea_t)→None
Function chunk start address will be changed.
Parameters:

-
pfn – (func_t *)

-
new_start – (::ea_t)

set_func_end(pfn:func_t*, new_end:ida_idaapi.ea_t)→None
Function chunk end address will be changed.
Parameters:

-
pfn – (func_t *)

-
new_end – (::ea_t)

deleting_func(pfn:func_t*)→None
The kernel is about to delete a function.
Parameters:
pfn – (func_t *)
frame_deleted(pfn:func_t*)→None
The kernel has deleted a function frame.
Parameters:
pfn – (func_t *) idb_event::frame_created
thunk_func_created(pfn:func_t*)→None
A thunk bit has been set for a function.
Parameters:
pfn – (func_t *)
func_tail_appended(pfn:func_t*, tail:func_t*)→None
A function tail chunk has been appended.
Parameters:

-
pfn – (func_t *)

-
tail – (func_t *)

deleting_func_tail(pfn:func_t*, tail:range_t)→None
A function tail chunk is to be removed.
Parameters:

-
pfn – (func_t *)

-
tail – (const range_t *)

func_tail_deleted(pfn:func_t*, tail_ea:ida_idaapi.ea_t)→None
A function tail chunk has been removed.
Parameters:

-
pfn – (func_t *)

-
tail_ea – (::ea_t)

tail_owner_changed(tail:func_t*, owner_func:ida_idaapi.ea_t, old_owner:ida_idaapi.ea_t)→None
A tail chunk owner has been changed.
Parameters:

-
tail – (func_t *)

-
owner_func – (::ea_t)

-
old_owner – (::ea_t)

func_noret_changed(pfn:func_t*)→None
FUNC_NORET bit has been changed.
Parameters:
pfn – (func_t *)
stkpnts_changed(pfn:func_t*)→None
Stack change points have been modified.
Parameters:
pfn – (func_t *)
updating_tryblks(tbv:tryblks_tconst*)→None
About to update tryblk information
Parameters:
tbv – (const ::tryblks_t *)
tryblks_updated(tbv:tryblks_tconst*)→None
Updated tryblk information
Parameters:
tbv – (const ::tryblks_t *)
deleting_tryblks(range:range_t)→None
About to delete tryblk information in given range
Parameters:
range – (const range_t *)
sgr_changed(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, regnum:int, value:sel_t, old_value:sel_t, tag:uchar)→None
The kernel has changed a segment register value.
Parameters:

-
start_ea – (::ea_t)

-
end_ea – (::ea_t)

-
regnum – (int)

-
value – (::sel_t)

-
old_value – (::sel_t)

-
tag – (uchar) Segment register range tags

make_code(insn:insn_tconst*)→None
An instruction is being created.
Parameters:
insn – (const insn_t*)
make_data(ea:ida_idaapi.ea_t, flags:flags64_t, tid:tid_t, len:asize_t)→None
A data item is being created.
Parameters:

-
ea – (::ea_t)

-
flags – (flags64_t)

-
tid – (tid_t)

-
len – (::asize_t)

destroyed_items(ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, will_disable_range:bool)→None
Instructions/data have been destroyed in [ea1,ea2).
Parameters:

-
ea1 – (::ea_t)

-
ea2 – (::ea_t)

-
will_disable_range – (bool)

renamed(ea:ida_idaapi.ea_t, new_name:str, local_name:bool, old_name:str)→None
The kernel has renamed a byte. See also the rename event
Parameters:

-
ea – (::ea_t)

-
new_name – (const char *) can be nullptr

-
local_name – (bool)

-
old_name – (const char *) can be nullptr

byte_patched(ea:ida_idaapi.ea_t, old_value:int)→None
A byte has been patched.
Parameters:

-
ea – (::ea_t)

-
old_value – (uint32)

changing_cmt(ea:ida_idaapi.ea_t, repeatable_cmt:bool, newcmt:str)→None
An item comment is to be changed.
Parameters:

-
ea – (::ea_t)

-
repeatable_cmt – (bool)

-
newcmt – (const char *)

cmt_changed(ea:ida_idaapi.ea_t, repeatable_cmt:bool)→None
An item comment has been changed.
Parameters:

-
ea – (::ea_t)

-
repeatable_cmt – (bool)

changing_range_cmt(kind:range_kind_t, a:range_t, cmt:str, repeatable:bool)→None
Range comment is to be changed.
Parameters:

-
kind – (range_kind_t)

-
a – (const range_t *)

-
cmt – (const char *)

-
repeatable – (bool)

range_cmt_changed(kind:range_kind_t, a:range_t, cmt:str, repeatable:bool)→None
Range comment has been changed.
Parameters:

-
kind – (range_kind_t)

-
a – (const range_t *)

-
cmt – (const char *)

-
repeatable – (bool)

extra_cmt_changed(ea:ida_idaapi.ea_t, line_idx:int, cmt:str)→None
An extra comment has been changed.
Parameters:

-
ea – (::ea_t)

-
line_idx – (int)

-
cmt – (const char *)

item_color_changed(ea:ida_idaapi.ea_t, color:bgcolor_t)→None
An item color has been changed.
Parameters:

-
ea – (::ea_t)

-
color – (bgcolor_t) if color==DEFCOLOR, the color is deleted.

callee_addr_changed(ea:ida_idaapi.ea_t, callee:ida_idaapi.ea_t)→None
Callee address has been updated by the user.
Parameters:

-
ea – (::ea_t)

-
callee – (::ea_t)

bookmark_changed(index:int, pos:lochist_entry_tconst*, desc:str, operation:int)→None
Bookmarked position changed.
Parameters:

-
index – (uint32)

-
pos – (::const lochist_entry_t *)

-
desc – (::const char *)

-
operation – (int) 0-added, 1-updated, 2-deleted if desc==nullptr, then the bookmark was deleted.

sgr_deleted(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, regnum:int)→None
The kernel has deleted a segment register value.
Parameters:

-
start_ea – (::ea_t)

-
end_ea – (::ea_t)

-
regnum – (int)

adding_segm(s:segment_t*)→None
A segment is being created.
Parameters:
s – (segment_t *)
func_deleted(func_ea:ida_idaapi.ea_t)→None
A function has been deleted.
Parameters:
func_ea – (::ea_t)
dirtree_mkdir(dt:dirtree_t*, path:str)→None
Dirtree: a directory has been created.
Parameters:

-
dt – (dirtree_t *)

-
path – (::const char *)

dirtree_rmdir(dt:dirtree_t*, path:str)→None
Dirtree: a directory has been deleted.
Parameters:

-
dt – (dirtree_t *)

-
path – (::const char *)

dirtree_link(dt:dirtree_t*, path:str, link:bool)→None
Dirtree: an item has been linked/unlinked.
Parameters:

-
dt – (dirtree_t *)

-
path – (::const char *)

-
link – (::bool)

dirtree_move(dt:dirtree_t*, _from:str, to:str)→None
Dirtree: a directory or item has been moved.
Parameters:

-
dt – (dirtree_t *)

-
to – (::const char *)

dirtree_rank(dt:dirtree_t*, path:str, rank:int)→None
Dirtree: a directory or item rank has been changed.
Parameters:

-
dt – (dirtree_t *)

-
path – (::const char *)

-
rank – (::size_t)

dirtree_rminode(dt:dirtree_t*, inode:inode_t)→None
Dirtree: an inode became unavailable.
Parameters:

-
dt – (dirtree_t *)

-
inode – (inode_t)

dirtree_segm_moved(dt:dirtree_t*)→None
Dirtree: inodes were changed due to a segment movement or a program rebasing
Parameters:
dt – (dirtree_t *)
local_types_changed(ltc:local_type_change_t, ordinal:int, name:str)→None
Local types have been changed
Parameters:

-
ltc – (local_type_change_t)

-
ordinal – (uint32) 0 means ordinal is unknown

-
name – (const char *) nullptr means name is unknown

lt_udm_created(udtname:str, udm:udm_t)→None
local type udt member has been added
Parameters:

-
udtname – (::const char *)

-
udm – (::const udm_t *)

lt_udm_deleted(udtname:str, udm_tid:tid_t, udm:udm_t)→None
local type udt member has been deleted
Parameters:

-
udtname – (::const char *)

-
udm_tid – (tid_t)

-
udm – (::const udm_t *)

lt_udm_renamed(udtname:str, udm:udm_t, oldname:str)→None
local type udt member has been renamed
Parameters:

-
udtname – (::const char *)

-
udm – (::const udm_t *)

-
oldname – (::const char *)

lt_udm_changed(udtname:str, udm_tid:tid_t, udmold:udm_t, udmnew:udm_t)→None
local type udt member has been changed
Parameters:

-
udtname – (::const char *)

-
udm_tid – (tid_t)

-
udmold – (::const udm_t *)

-
udmnew – (::const udm_t *)

lt_udt_expanded(udtname:str, udm_tid:tid_t, delta:adiff_t)→None
A structure type has been expanded/shrank.
Parameters:

-
udtname – (::const char *)

-
udm_tid – (tid_t) the gap was added/removed before this member

-
delta – (::adiff_t) number of added/removed bytes

frame_created(func_ea:ida_idaapi.ea_t)→None
A function frame has been created.
Parameters:
func_ea – (::ea_t) idb_event::frame_deleted
frame_udm_created(func_ea:ida_idaapi.ea_t, udm:udm_t)→None
Frame member has been added.
Parameters:

-
func_ea – (::ea_t)

-
udm – (::const udm_t *)

frame_udm_deleted(func_ea:ida_idaapi.ea_t, udm_tid:tid_t, udm:udm_t)→None
Frame member has been deleted.
Parameters:

-
func_ea – (::ea_t)

-
udm_tid – (tid_t)

-
udm – (::const udm_t *)

frame_udm_renamed(func_ea:ida_idaapi.ea_t, udm:udm_t, oldname:str)→None
Frame member has been renamed.
Parameters:

-
func_ea – (::ea_t)

-
udm – (::const udm_t *)

-
oldname – (::const char *)

frame_udm_changed(func_ea:ida_idaapi.ea_t, udm_tid:tid_t, udmold:udm_t, udmnew:udm_t)→None
Frame member has been changed.
Parameters:

-
func_ea – (::ea_t)

-
udm_tid – (tid_t)

-
udmold – (::const udm_t *)

-
udmnew – (::const udm_t *)

frame_expanded(func_ea:ida_idaapi.ea_t, udm_tid:tid_t, delta:adiff_t)→None
A frame type has been expanded/shrank.
Parameters:

-
func_ea – (::ea_t)

-
udm_tid – (tid_t) the gap was added/removed before this member

-
delta – (::adiff_t) number of added/removed bytes

idasgn_matched_ea(ea:ida_idaapi.ea_t, name:str, lib_name:str)→None
A FLIRT match has been found
Parameters:

-
ea – (::ea_t) the matching address

-
name – (::const char *) the matched name

-
lib_name – (::const char *) library name extracted from signature file

lt_edm_created(enumname:str, edm:edm_t)→None
local type enum member has been added
Parameters:

-
enumname – (::const char *)

-
edm – (::const edm_t *)

lt_edm_deleted(enumname:str, edm_tid:tid_t, edm:edm_t)→None
local type enum member has been deleted
Parameters:

-
enumname – (::const char *)

-
edm_tid – (tid_t)

-
edm – (::const edm_t *)

lt_edm_renamed(enumname:str, edm:edm_t, oldname:str)→None
local type enum member has been renamed
Parameters:

-
enumname – (::const char *)

-
edm – (::const edm_t *)

-
oldname – (::const char *)

lt_edm_changed(enumname:str, edm_tid:tid_t, edmold:edm_t, edmnew:edm_t)→None
local type enum member has been changed
Parameters:

-
enumname – (::const char *)

-
edm_tid – (tid_t)

-
edmold – (::const edm_t *)

-
edmnew – (::const edm_t *)

local_type_renamed(ordinal:int, oldname:str, newname:str)→None
Local type has been renamed
Parameters:

-
ordinal – (uint32) 0 means ordinal is unknown

-
oldname – (const char *) nullptr means name is unknown

-
newname – (const char *) nullptr means name is unknown

dirtree_ordering_changed(dt:dirtree_t*, diridx:diridx_t, natural:bool)→None
Dirtree: a directory’s “natural” ordering changed
Parameters:

-
dt – (dirtree_t *)

-
diridx – (diridx_t)

-
natural – (::bool)

dirtree_bulk_move(dt:dirtree_t*, sources:dirtree_bulk_results_t*, moved_items:dirtree_cursor_vec_t*, dstdir:str, dstrank:ssize_t)→None
Dirtree: many items have been moved.
Parameters:

-
dt – (dirtree_t *)

-
sources – (::dirtree_bulk_results_t *)

-
moved_items – (::dirtree_cursor_vec_t *)

-
dstdir – (::const char *)

-
dstrank – (ssize_t) SOURCES and MOVED_ITEMS correspond to each other

ida_idp.get_idb_notifier_addr(arg1:PyObject*)→PyObject*ida_idp.get_idb_notifier_ud_addr(hooks:IDB_Hooks)→PyObject*
