# IDAPython instruction decode API

- 官方来源：https://python.docs.hex-rays.com/ida_ua/index.html

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
- ida_ua
- View page source

# ida_ua

Functions that deal with the disassembling of program instructions.

There are 2 kinds of functions: * functions that are called from the kernel to disassemble an instruction. These functions call IDP module for it. * functions that are called from IDP module to disassemble an instruction. We will call them ‘helper functions’.

Disassembly of an instruction is made in three steps: 0. analysis: ana.cpp 1. emulation: emu.cpp 2. conversion to text: out.cpp

The kernel calls the IDP module to perform these steps. At first, the kernel always calls the analysis. The analyzer must decode the instruction and fill the insn_t instance that it receives through its callback. It must not change anything in the database. The second step, the emulation, is called for each instruction. This step must make necessary changes to the database, plan analysis of subsequent instructions, track register values, memory contents, etc. Please keep in mind that the kernel may call the emulation step for any address in the program - there is no ordering of addresses. Usually, the emulation is called for consecutive addresses but this is not guaranteed. The last step, conversion to text, is called each time an instruction is displayed on the screen. The kernel will always call the analysis step before calling the text conversion step. The emulation and the text conversion steps should use the information stored in the insn_t instance they receive. They should not access the bytes of the instruction and decode it again - this should only be done in the analysis step.

## Attributes

`cvar`
|

`o_void`
|
No Operand.

`o_reg`
|
General Register (al,ax,es,ds...).

`o_mem`
|
A direct memory reference to a data item. Use this operand type when the address can be calculated statically.

`o_phrase`
|
An indirect memory reference that uses a register: [reg] There can be several registers but no displacement.

`o_displ`
|
An indirect memory reference that uses a register and has an immediate constant added to it: [reg+N] There can be several registers.

`o_imm`
|
An immediate Value (constant).

`o_far`
|
An immediate far code reference (inter-segment)

`o_near`
|
An immediate near code reference (intra-segment)

`o_idpspec0`
|
processor specific type.

`o_idpspec1`
|
processor specific type.

`o_idpspec2`
|
processor specific type.

`o_idpspec3`
|
processor specific type.

`o_idpspec4`
|
processor specific type.

`o_idpspec5`
|
processor specific type. (there can be more processor specific types)

`OF_NO_BASE_DISP`
|
base displacement doesn't exist. meaningful only for o_displ type. if set, base displacement (op_t::addr) doesn't exist.

`OF_OUTER_DISP`
|
outer displacement exists. meaningful only for o_displ type. if set, outer displacement (op_t::value) exists.

`PACK_FORM_DEF`
|
packed factor defined. (!o_reg + dt_packreal)

`OF_NUMBER`
|
the operand can be converted to a number only

`OF_SHOW`
|
should the operand be displayed?

`dt_byte`
|
8 bit integer

`dt_word`
|
16 bit integer

`dt_dword`
|
32 bit integer

`dt_float`
|
4 byte floating point

`dt_double`
|
8 byte floating point

`dt_tbyte`
|
variable size ( processor_t::tbyte_size) floating point

`dt_packreal`
|
packed real format for mc68040

`dt_qword`
|
64 bit integer

`dt_byte16`
|
128 bit integer

`dt_code`
|
ptr to code

`dt_void`
|
none

`dt_fword`
|
48 bit

`dt_bitfild`
|
bit field (mc680x0)

`dt_string`
|
pointer to asciiz string

`dt_unicode`
|
pointer to unicode string

`dt_ldbl`
|
long double (which may be different from tbyte)

`dt_byte32`
|
256 bit integer

`dt_byte64`
|
512 bit integer

`dt_half`
|
2-byte floating point

`INSN_MACRO`
|
macro instruction

`INSN_MODMAC`
|
may modify the database to make room for the macro insn

`INSN_64BIT`
|
belongs to 64-bit segment?

`CTXF_MAIN`
|
produce only the essential line(s)

`CTXF_MULTI`
|
enable multi-line essential lines

`CTXF_CODE`
|
display as code regardless of the database flags

`CTXF_STACK`
|
stack view (display undefined items as 2/4/8 bytes)

`CTXF_GEN_XREFS`
|
generate the xrefs along with the next line

`CTXF_XREF_STATE`
|
xref state:

`XREFSTATE_NONE`
|
not generated yet

`XREFSTATE_GO`
|
being generated

`XREFSTATE_DONE`
|
have been generated

`CTXF_GEN_CMT`
|
generate the comment along with the next line

`CTXF_CMT_STATE`
|
comment state:

`COMMSTATE_NONE`
|
not generated yet

`COMMSTATE_GO`
|
being generated

`COMMSTATE_DONE`
|
have been generated

`CTXF_VOIDS`
|
display void marks

`CTXF_NORMAL_LABEL`
|
generate plain label (+demangled label as cmt)

`CTXF_DEMANGLED_LABEL`
|
generate only demangled label as comment

`CTXF_LABEL_OK`
|
the label have been generated

`CTXF_DEMANGLED_OK`
|
the label has been demangled successfully

`CTXF_OVSTORE_PRNT`
|
out_value should store modified values

`CTXF_OUTCTX_T`
|
instance is, in fact, a outctx_t

`CTXF_DBLIND_OPND`
|
an operand was printed with double indirection (e.g. =var in arm)

`CTXF_BINOP_STATE`
|
opcode bytes state:

`BINOPSTATE_NONE`
|
not generated yet

`BINOPSTATE_GO`
|
being generated

`BINOPSTATE_DONE`
|
have been generated

`CTXF_HIDDEN_ADDR`
|
generate an hidden addr tag at the beginning of the line

`CTXF_BIT_PREFIX`
|
generate a line prefix with a bit offset, e.g.: 12345678.3

`CTXF_UNHIDE`
|
display hidden objects (segment, function, range)

`OOF_SIGNMASK`
|
sign symbol (+/-) output

`OOFS_IFSIGN`
|
output sign if needed

`OOFS_NOSIGN`
|
don't output sign, forbid the user to change the sign

`OOFS_NEEDSIGN`
|
always out sign (+-)

`OOF_SIGNED`
|
output as signed if < 0

`OOF_NUMBER`
|
always as a number

`OOF_WIDTHMASK`
|
width of value in bits

`OOFW_IMM`
|
take from x.dtype

`OOFW_8`
|
8 bit width

`OOFW_16`
|
16 bit width

`OOFW_24`
|
24 bit width

`OOFW_32`
|
32 bit width

`OOFW_64`
|
64 bit width

`OOF_ADDR`
|
output x.addr, otherwise x.value OOF_WIDTHMASK must be explicitly specified with it

`OOF_OUTER`
|
output outer operand

`OOF_ZSTROFF`
|
meaningful only if is_stroff(F); append a struct field name if the field offset is zero? if AFL_ZSTROFF is set, then this flag is ignored.

`OOF_NOBNOT`
|
prohibit use of binary not

`OOF_SPACES`
|
do not suppress leading spaces; currently works only for floating point numbers

`OOF_ANYSERIAL`
|
if enum: select first available serial

`OOF_LZEROES`
|
print leading zeros

`OOF_NO_LZEROES`
|
do not print leading zeros; if none of OOF_LZEROES and OOF_NO_LZEROES was specified, is_lzero() is used

`DEFAULT_INDENT`
|

`MAKELINE_NONE`
|

`MAKELINE_BINPREF`
|
allow display of binary prefix

`MAKELINE_VOID`
|
allow display of '' marks

`MAKELINE_STACK`
|
allow display of sp trace prefix

`GH_PRINT_PROC`
|
processor name

`GH_PRINT_ASM`
|
selected assembler

`GH_PRINT_BYTESEX`
|
byte sex

`GH_PRINT_HEADER`
|
lines from ash.header

`GH_BYTESEX_HAS_HIGHBYTE`
|
describe inf.is_wide_high_byte_first()

`GH_PRINT_PROC_AND_ASM`
|

`GH_PRINT_PROC_ASM_AND_BYTESEX`
|

`GH_PRINT_ALL`
|

`GH_PRINT_ALL_BUT_BYTESEX`
|

`FCBF_CONT`
|
don't stop on decoding, or any other kind of error

`FCBF_ERR_REPL`
|
in case of an error, use a CP_REPLCHAR instead of a hex representation of the problematic byte

`FCBF_FF_LIT`
|
in case of codepoints == 0xFF, use it as-is (i.e., LATIN SMALL LETTER Y WITH DIAERESIS). If both this, and FCBF_REPL are specified, this will take precedence

`FCBF_DELIM`
|
add the 'ash'-specified delimiters around the generated data. Note: if those are not defined and the INFFL_ALLASM is not set, format_charlit() will return an error

`ua_mnem`
|

`STKVAR_VALID_SIZE`
|

`STKVAR_KEEP_EXISTING`
|

## Classes

`operands_array`
|

`op_t`
|

`insn_t`
|

`outctx_base_t`
|

`outctx_t`
|

`macro_constructor_t`
|

## Functions

`insn_add_cref`(→ None)
|

`insn_add_dref`(→ None)
|

`insn_add_off_drefs`(→ ida_idaapi.ea_t)
|

`insn_create_stkvar`(→ bool)
|

`get_lookback`(→ int)
|
Number of instructions to look back. This variable is not used by the kernel. Its value may be specified in ida.cfg: LOOKBACK = . IDP may use it as you like it. (TMS module uses it)

`calc_dataseg`(→ ida_idaapi.ea_t)
|

`map_data_ea`(→ ida_idaapi.ea_t)
|

`map_code_ea`(→ ida_idaapi.ea_t)
|

`map_ea`(→ ida_idaapi.ea_t)
|

`create_outctx`(→ outctx_base_t *)
|
Create a new output context. To delete it, just use "delete pctx"

`print_insn_mnem`(→ str)
|
Print instruction mnemonics.

`get_dtype_flag`(→ flags64_t)
|
Get flags for op_t::dtype field.

`get_dtype_size`(→ int)
|
Get size of opt_::dtype field.

`is_floating_dtype`(→ bool)
|
Is a floating type operand?

`create_insn`(→ int)
|
Create an instruction at the specified address. This function checks if an instruction is present at the specified address and will try to create one if there is none. It will fail if there is a data item or other items hindering the creation of the new instruction. This function will also fill the 'out' structure.

`decode_insn`(→ int)
|
Analyze the specified address and fill 'out'. This function does not modify the database. It just tries to interpret the specified address as an instruction and fills the 'out' structure.

`can_decode`(→ bool)
|
Can the bytes at address 'ea' be decoded as instruction?

`print_operand`(→ str)
|
Generate text representation for operand #n. This function will generate the text representation of the specified operand (includes color codes.)

`decode_prev_insn`(→ ida_idaapi.ea_t)
|
Decode previous instruction if it exists, fill 'out'.

`decode_preceding_insn`(→ Tuple[ida_idaapi.ea_t, bool])
|
Decodes the preceding instruction.

`construct_macro`(*args)
|
See ua.hpp's construct_macro().

`get_dtype_by_size`(→ int)
|
Get op_t::dtype from size.

`get_immvals`(→ PyObject *)
|
Get immediate values at the specified address. This function decodes instruction at the specified address or inspects the data item. It finds immediate values and copies them to 'out'. This function will store the original value of the operands in 'out', unless the last bits of 'F' are "...0 11111111", in which case the transformed values (as needed for printing) will be stored instead.

`get_printable_immvals`(→ PyObject *)
|
Get immediate ready-to-print values at the specified address

`insn_t__from_ptrval__`(→ insn_t *)
|

`op_t__from_ptrval__`(→ op_t *)
|

`outctx_base_t__from_ptrval__`(→ outctx_base_t *)
|

`outctx_t__from_ptrval__`(→ outctx_t *)
|

## Module Contents

classida_ua.operands_array(data:op_t(&)[8])
Bases: `object`
thisowndata:op_t(&)[8]bytesclassida_ua.op_t
Bases: `object`
thisownn:uchar
Number of operand (0,1,2). Initialized once at the start of work. You have no right to change its value.
type:optype_t
Type of operand (see Operand types)
offb:char
Offset of operand value from the instruction start (0 means unknown). Of course this field is meaningful only for certain types of operands. Leave it equal to zero if the operand has no offset. This offset should point to the ‘interesting’ part of operand. For example, it may point to the address of a function in `call func ` or it may point to bytes holding ‘5’ in `mov ax, [bx+5] ` Usually bytes pointed to this offset are relocated (have fixup information).
offo:char
Same as offb (some operands have 2 numeric values used to form an operand). This field is used for the second part of operand if it exists. Currently this field is used only for outer offsets of Motorola processors. Leave it equal to zero if the operand has no offset.
flags:uchar
Operand flags
set_shown()→None
Set operand to be shown.
clr_shown()→None
Set operand to hidden.
shown()→bool
Is operand set to be shown?
dtype:op_dtype_t
Type of operand value (see Operand value types). This is the type of the operand itself, not the size of the addressing mode. for example, byte ptr [epb+32_bit_offset] will have the dt_byte type.
reg:uint16
number of register (o_reg)
phrase:uint16
number of register phrase (o_phrase,o_displ). you yourself define numbers of phrases as you like
is_reg(r:int)→bool
Is register operand?
value:int
operand value (o_imm) or outer displacement (o_displ+OF_OUTER_DISP). integer values should be in IDA’s (little-endian) order. when using ieee_realcvt(), floating point values should be in the processor’s native byte order. dt_double and dt_qword values take up 8 bytes (value and addr fields for 32-bit modules). NB: in case a dt_dword/dt_qword immediate is forced to float by user, the kernel converts it to processor’s native order before calling FP conversion routines.
is_imm(v:int)→bool
Is immediate operand?
addr:ida_idaapi.ea_t
virtual address pointed or used by the operand. (o_mem,o_displ,o_far,o_near)
specval:ida_idaapi.ea_t
This field may be used as you want.
specflag1:charspecflag2:charspecflag3:charspecflag4:charassign(other:op_t)→Nonehas_reg(r)
Checks if the operand accesses the given processor register
value64ida_ua.cvarida_ua.o_void
No Operand.
ida_ua.o_reg
General Register (al,ax,es,ds…).

The register number should be stored in op_t::reg. All processor registers, including special registers, can be represented by this operand type.
ida_ua.o_mem
A direct memory reference to a data item. Use this operand type when the address can be calculated statically. A direct memory data reference whose target address is known at compilation time. The target virtual address is stored in op_t::addr and the full address is calculated as to_ea( insn_t::cs, op_t::addr ). For the processors with complex memory organization the final address can be calculated using other segment registers. For flat memories, op_t::addr is the final address and insn_t::cs is usually equal to zero. In any case, the address within the segment should be stored in op_t::addr.
ida_ua.o_phrase
An indirect memory reference that uses a register: [reg] There can be several registers but no displacement. A memory reference using register contents. Indexed, register based, and other addressing modes can be represented with the operand type. This addressing mode cannot contain immediate values (use o_displ instead). The phrase number should be stored in op_t::phrase. To denote the pre-increment and similar features please use additional operand fields like op_t::specflag… Usually op_t::phrase contains the register number and additional information is stored in op_t::specflags… Please note that this operand type cannot contain immediate values (except the scaling coefficients).
ida_ua.o_displ
An indirect memory reference that uses a register and has an immediate constant added to it: [reg+N] There can be several registers. A memory reference using register contents with displacement. The displacement should be stored in the op_t::addr field. The rest of information is stored the same way as in o_phrase.
ida_ua.o_imm
An immediate Value (constant).

Any operand consisting of only a number is represented by this operand type. The value should be stored in op_t::value. You may sign extend short (1-2 byte) values. In any case don’t forget to specify op_t::dtype (should be set for all operand types).
ida_ua.o_far
An immediate far code reference (inter-segment)

If the current processor has a special addressing mode for inter-segment references, then this operand type should be used instead of o_near. If you want, you may use PR_CHK_XREF in processor_t::flag to disable inter-segment calls if o_near operand type is used. Currently only IBM PC uses this flag.
ida_ua.o_near
An immediate near code reference (intra-segment)

A direct memory code reference whose target address is known at the compilation time. The target virtual address is stored in op_t::addr and the final address is always to_ea( insn_t::cs, op_t::addr). Usually this operand type is used for the branches and calls whose target address is known. If the current processor has 2 different types of references for inter-segment and intra-segment references, then this should be used only for intra-segment references. If the above operand types do not cover all possible addressing modes, then use o_idpspec… operand types.
ida_ua.o_idpspec0
processor specific type.
ida_ua.o_idpspec1
processor specific type.
ida_ua.o_idpspec2
processor specific type.
ida_ua.o_idpspec3
processor specific type.
ida_ua.o_idpspec4
processor specific type.
ida_ua.o_idpspec5
processor specific type. (there can be more processor specific types)
ida_ua.OF_NO_BASE_DISP
base displacement doesn’t exist. meaningful only for o_displ type. if set, base displacement (op_t::addr) doesn’t exist.
ida_ua.OF_OUTER_DISP
outer displacement exists. meaningful only for o_displ type. if set, outer displacement (op_t::value) exists.
ida_ua.PACK_FORM_DEF
packed factor defined. (!o_reg + dt_packreal)
ida_ua.OF_NUMBER
the operand can be converted to a number only
ida_ua.OF_SHOW
should the operand be displayed?
ida_ua.dt_byte
8 bit integer
ida_ua.dt_word
16 bit integer
ida_ua.dt_dword
32 bit integer
ida_ua.dt_float
4 byte floating point
ida_ua.dt_double
8 byte floating point
ida_ua.dt_tbyte
variable size ( processor_t::tbyte_size) floating point
ida_ua.dt_packreal
packed real format for mc68040
ida_ua.dt_qword
64 bit integer
ida_ua.dt_byte16
128 bit integer
ida_ua.dt_code
ptr to code
ida_ua.dt_void
none
ida_ua.dt_fword
48 bit
ida_ua.dt_bitfild
bit field (mc680x0)
ida_ua.dt_string
pointer to asciiz string
ida_ua.dt_unicode
pointer to unicode string
ida_ua.dt_ldbl
long double (which may be different from tbyte)
ida_ua.dt_byte32
256 bit integer
ida_ua.dt_byte64
512 bit integer
ida_ua.dt_half
2-byte floating point
ida_ua.insn_add_cref(insn:insn_t, to:ida_idaapi.ea_t, opoff:int, type:cref_t)→Noneida_ua.insn_add_dref(insn:insn_t, to:ida_idaapi.ea_t, opoff:int, type:dref_t)→Noneida_ua.insn_add_off_drefs(insn:insn_t, x:op_t, type:dref_t, outf:int)→ida_idaapi.ea_tida_ua.insn_create_stkvar(insn:insn_t, x:op_t, v:adiff_t, flags:int)→boolclassida_ua.insn_t
Bases: `object`
thisowncs:ida_idaapi.ea_t
Current segment base paragraph. Initialized by the kernel.
ip:ida_idaapi.ea_t
Virtual address of the instruction (address within the segment). Initialized by the kernel.
ea:ida_idaapi.ea_t
Linear address of the instruction. Initialized by the kernel.
itype:uint16
Internal code of instruction (only for canonical insns - not user defined!). IDP should define its own instruction codes. These codes are usually defined in ins.hpp. The array of instruction names and features (ins.cpp) is accessed using this code.
size:uint16
Size of instruction in bytes. The analyzer should put here the actual size of the instruction.
auxpref:int
processor dependent field
auxpref_u16:uint16[2]auxpref_u8:uint8[4]segpref:char
processor dependent field
insnpref:char
processor dependent field
flags:int16
Instruction flags
ops:op_t[8]
array of operands
is_macro()→bool
Is a macro instruction?
is_64bit()→bool
Belongs to a 64-bit segment?
get_next_byte()→uint8get_next_word()→uint16get_next_dword()→intget_next_qword()→uint64create_op_data(*args)→boolcreate_stkvar(x:op_t, v:adiff_t, stkvar_flags:int)→booladd_cref(to:ida_idaapi.ea_t, opoff:int, type:cref_t)→Noneadd_dref(to:ida_idaapi.ea_t, opoff:int, type:dref_t)→Noneadd_off_drefs(x:op_t, type:dref_t, outf:int)→ida_idaapi.ea_tassign(other:insn_t)→Noneis_canon_insn(*args)→bool
see processor_t::is_canon_insn()
get_canon_feature(*args)→int
see instruc_t::feature
get_canon_mnem(*args)→str
see instruc_t::name
Op1Op2Op3Op4Op5Op6Op7Op8ida_ua.INSN_MACRO
macro instruction
ida_ua.INSN_MODMAC
may modify the database to make room for the macro insn
ida_ua.INSN_64BIT
belongs to 64-bit segment?
ida_ua.get_lookback()→int
Number of instructions to look back. This variable is not used by the kernel. Its value may be specified in ida.cfg: LOOKBACK = . IDP may use it as you like it. (TMS module uses it)
ida_ua.calc_dataseg(insn:insn_t, n:int=-1, rgnum:int=-1)→ida_idaapi.ea_tida_ua.map_data_ea(*args)→ida_idaapi.ea_tida_ua.map_code_ea(*args)→ida_idaapi.ea_tida_ua.map_ea(*args)→ida_idaapi.ea_tclassida_ua.outctx_base_t(*args, **kwargs)
Bases: `object`
thisowninsn_ea:ida_idaapi.ea_toutbuf:str
buffer for the current output line once ready, it is moved to lnar
F32:flags_t
please use outctx_t::F instead
default_lnnum:int
index of the most important line in lnar
only_main_line()→boolmultiline()→boolforce_code()→boolstack_view()→booldisplay_voids()→booldisplay_hidden()→boolset_gen_xrefs(on:bool=True)→Noneset_gen_cmt(on:bool=True)→Noneclr_gen_label()→Noneset_gen_label()→Noneset_gen_demangled_label()→Noneset_comment_addr(ea:ida_idaapi.ea_t)→Noneset_dlbind_opnd()→Noneprint_label_now()→boolforbid_annotations()→intrestore_ctxflags(saved_flags:int)→Noneout_printf(format:str)→int
————————————————————————- Functions to append text to the current output buffer (outbuf) Append a formatted string to the output string.
Returns:
the number of characters appended
out_value(x:op_t, outf:int=0)→flags64_t
Output immediate value. Try to use this function to output all constants of instruction operands. This function outputs a number from x.addr or x.value in the form determined by F. It outputs colored text.
Parameters:

-
x – value to output

-
outf – Output value flags

Returns:
flags of the output value, otherwise:
Returns:
-1: if printed a number with COLOR_ERROR
Returns:
0: if printed a nice number or character or segment or enum
out_symbol(c:char)→None
Output a character with COLOR_SYMBOL color.
out_chars(c:char, n:int)→None
Append a character multiple times.
out_spaces(len:ssize_t)→None
Appends spaces to outbuf until its tag_strlen becomes ‘len’.
out_line(str:outctx_base_t.out_line.str, color:color_t=0)→None
Output a string with the specified color.
out_keyword(str:outctx_base_t.out_keyword.str)→None
Output a string with COLOR_KEYWORD color.
out_register(str:outctx_base_t.out_register.str)→None
Output a character with COLOR_REG color.
out_lvar(name:str, width:int=-1)→None
Output local variable name with COLOR_LOCNAME color.
out_tagon(tag:color_t)→None
Output “turn color on” escape sequence.
out_tagoff(tag:color_t)→None
Output “turn color off” escape sequence.
out_addr_tag(ea:ida_idaapi.ea_t)→None
Output “address” escape sequence.
out_colored_register_line(str:outctx_base_t.out_colored_register_line.str)→None
Output a colored line with register names in it. The register names will be substituted by user-defined names (regvar_t) Please note that out_tagoff tries to make substitutions too (when called with COLOR_REG)
out_char(c:char)→None
Output one character. The character is output without color codes. see also out_symbol()
out_btoa(Word:int, radix:char=0)→None
Output a number with the specified base (binary, octal, decimal, hex) The number is output without color codes. see also out_long()
out_long(v:int, radix:char)→None
Output a number with appropriate color. Low level function. Use out_value() if you can. if ‘suspop’ is set then this function uses COLOR_VOIDOP instead of COLOR_NUMBER. ‘suspop’ is initialized: * in out_one_operand() * in ..idagl.cpp (before calling processor_t::d_out())
Parameters:

-
v – value to output

-
radix – base (2,8,10,16)

out_name_expr(*args)→bool
Output a name expression.
Parameters:

-
x – instruction operand referencing the name expression

-
ea – address to convert to name expression

-
off – the value of name expression. this parameter is used only to check that the name expression will have the wanted value. You may pass BADADDR for this parameter but I discourage it because it prohibits checks.

Returns:
true if the name expression has been produced
close_comment()→Noneflush_outbuf(indent:int=-1)→bool
————————————————————————- Functions to populate the output line array (lnar) Move the contents of the output buffer to the line array (outbuf->lnar) The kernel augments the outbuf contents with additional text like the line prefix, user-defined comments, xrefs, etc at this call.
flush_buf(buf:str, indent:int=-1)→bool
Append contents of ‘buf’ to the line array. Behaves like flush_outbuf but accepts an arbitrary buffer
term_outctx(prefix:str=None)→int
Finalize the output context.
Returns:
the number of generated lines.
gen_printf(indent:int, format:str)→bool
printf-like function to add lines to the line array.
Parameters:

-
indent – indention of the line. if indent == -1, the kernel will indent the line at idainfo::indent. if indent < 0, -indent will be used for indention. The first line printed with indent < 0 is considered as the most important line at the current address. Usually it is the line with the instruction itself. This line will be displayed in the cross-reference lists and other places. If you need to output an additional line before the main line then pass DEFAULT_INDENT instead of -1. The kernel will know that your line is not the most important one.

-
format – printf style colored line to generate

Returns:
overflow, lnar_maxsize has been reached
gen_empty_line()→bool
Generate empty line. This function does nothing if generation of empty lines is disabled.
Returns:
overflow, lnar_maxsize has been reached
gen_border_line(solid:bool=False)→bool
Generate thin border line. This function does nothing if generation of border lines is disabled.
Parameters:
solid – generate solid border line (with =), otherwise with -
Returns:
overflow, lnar_maxsize has been reached
gen_cmt_line(format:str)→bool
Generate one non-indented comment line, colored with COLOR_AUTOCMT.
Parameters:
format – printf() style format line. The resulting comment line should not include comment character (;)
Returns:
overflow, lnar_maxsize has been reached
gen_collapsed_line(format:str)→bool
Generate one non-indented comment line, colored with COLOR_COLLAPSED.
Parameters:
format – printf() style format line. The resulting comment line should not include comment character (;)
Returns:
overflow, lnar_maxsize has been reached
gen_block_cmt(cmt:str, color:color_t)→bool
Generate big non-indented comment lines.
Parameters:

-
cmt – comment text. may contain n characters to denote new lines. should not contain comment character (;)

-
color – color of comment text (one of Color tags)

Returns:
overflow, lnar_maxsize has been reached
setup_outctx(prefix:str, makeline_flags:int)→None
Initialization; normally used only by the kernel.
retrieve_cmt()→ssize_tretrieve_name(arg2:str, arg3:color_t*)→ssize_tgen_xref_lines()→boolinit_lines_array(answers:qstrvec_t*, maxsize:int)→Noneget_stkvar(x:op_t, v:int, vv:sval_t*, is_sp_based:int*, _frame:tinfo_t)→ssize_tgen_empty_line_without_annotations()→NonegetF()→flags64_tida_ua.CTXF_MAIN
produce only the essential line(s)
ida_ua.CTXF_MULTI
enable multi-line essential lines
ida_ua.CTXF_CODE
display as code regardless of the database flags
ida_ua.CTXF_STACK
stack view (display undefined items as 2/4/8 bytes)
ida_ua.CTXF_GEN_XREFS
generate the xrefs along with the next line
ida_ua.CTXF_XREF_STATE
xref state:
ida_ua.XREFSTATE_NONE
not generated yet
ida_ua.XREFSTATE_GO
being generated
ida_ua.XREFSTATE_DONE
have been generated
ida_ua.CTXF_GEN_CMT
generate the comment along with the next line
ida_ua.CTXF_CMT_STATE
comment state:
ida_ua.COMMSTATE_NONE
not generated yet
ida_ua.COMMSTATE_GO
being generated
ida_ua.COMMSTATE_DONE
have been generated
ida_ua.CTXF_VOIDS
display void marks
ida_ua.CTXF_NORMAL_LABEL
generate plain label (+demangled label as cmt)
ida_ua.CTXF_DEMANGLED_LABEL
generate only demangled label as comment
ida_ua.CTXF_LABEL_OK
the label have been generated
ida_ua.CTXF_DEMANGLED_OK
the label has been demangled successfully
ida_ua.CTXF_OVSTORE_PRNT
out_value should store modified values
ida_ua.CTXF_OUTCTX_T
instance is, in fact, a outctx_t
ida_ua.CTXF_DBLIND_OPND
an operand was printed with double indirection (e.g. =var in arm)
ida_ua.CTXF_BINOP_STATE
opcode bytes state:
ida_ua.BINOPSTATE_NONE
not generated yet
ida_ua.BINOPSTATE_GO
being generated
ida_ua.BINOPSTATE_DONE
have been generated
ida_ua.CTXF_HIDDEN_ADDR
generate an hidden addr tag at the beginning of the line
ida_ua.CTXF_BIT_PREFIX
generate a line prefix with a bit offset, e.g.: 12345678.3
ida_ua.CTXF_UNHIDE
display hidden objects (segment, function, range)
ida_ua.OOF_SIGNMASK
sign symbol (+/-) output
ida_ua.OOFS_IFSIGN
output sign if needed
ida_ua.OOFS_NOSIGN
don’t output sign, forbid the user to change the sign
ida_ua.OOFS_NEEDSIGN
always out sign (+-)
ida_ua.OOF_SIGNED
output as signed if < 0
ida_ua.OOF_NUMBER
always as a number
ida_ua.OOF_WIDTHMASK
width of value in bits
ida_ua.OOFW_IMM
take from x.dtype
ida_ua.OOFW_8
8 bit width
ida_ua.OOFW_16
16 bit width
ida_ua.OOFW_24
24 bit width
ida_ua.OOFW_32
32 bit width
ida_ua.OOFW_64
64 bit width
ida_ua.OOF_ADDR
output x.addr, otherwise x.value OOF_WIDTHMASK must be explicitly specified with it
ida_ua.OOF_OUTER
output outer operand
ida_ua.OOF_ZSTROFF
meaningful only if is_stroff(F); append a struct field name if the field offset is zero? if AFL_ZSTROFF is set, then this flag is ignored.
ida_ua.OOF_NOBNOT
prohibit use of binary not
ida_ua.OOF_SPACES
do not suppress leading spaces; currently works only for floating point numbers
ida_ua.OOF_ANYSERIAL
if enum: select first available serial
ida_ua.OOF_LZEROES
print leading zeros
ida_ua.OOF_NO_LZEROES
do not print leading zeros; if none of OOF_LZEROES and OOF_NO_LZEROES was specified, is_lzero() is used
ida_ua.DEFAULT_INDENTida_ua.MAKELINE_NONEida_ua.MAKELINE_BINPREF
allow display of binary prefix
ida_ua.MAKELINE_VOID
allow display of ‘’ marks
ida_ua.MAKELINE_STACK
allow display of sp trace prefix
classida_ua.outctx_t(*args, **kwargs)
Bases: `outctx_base_t`
thisownbin_ea:ida_idaapi.ea_tbin_state:chargl_bpsize:intbin_width:intinsn:insn_tcurlabel:strwif:printop_tconst*procmod:procmod_t*ph:processor_t&ash:asm_t&saved_immvals:uval_t[8]prefix_ea:ida_idaapi.ea_tnext_line_ea:ida_idaapi.ea_tsetup_outctx(prefix:str, flags:int)→None
Initialization; normally used only by the kernel.
term_outctx(prefix:str=None)→int
Finalize the output context.
Returns:
the number of generated lines.
retrieve_cmt()→ssize_tretrieve_name(arg2:str, arg3:color_t*)→ssize_tgen_xref_lines()→boolout_btoa(Word:int, radix:char=0)→None
Output a number with the specified base (binary, octal, decimal, hex) The number is output without color codes. see also out_long()
set_bin_state(value:int)→Noneout_mnem(width:int=8, postfix:str=None)→None
Output instruction mnemonic for ‘insn’ using information in ‘ph.instruc’ array. This function outputs colored text. It should be called from processor_t::ev_out_insn() or processor_t::ev_out_mnem() handler. It will output at least one space after the instruction. mnemonic even if the specified ‘width’ is not enough.
Parameters:

-
width – width of field with mnemonic. if < 0, then ‘postfix’ will be output before the mnemonic, i.e. as a prefix

-
postfix – optional postfix added to the instruction mnemonic

out_custom_mnem(mnem:str, width:int=8, postfix:str=None)→None
Output custom mnemonic for ‘insn’. E.g. if it should differ from the one in ‘ph.instruc’. This function outputs colored text. See out_mnem
Parameters:

-
mnem – custom mnemonic

-
width – width of field with mnemonic. if < 0, then ‘postfix’ will be output before the mnemonic, i.e. as a prefix

-
postfix – optional postfix added to ‘mnem’

out_mnemonic()→None
Output instruction mnemonic using information in ‘insn’. It should be called from processor_t::ev_out_insn() and it will call processor_t::ev_out_mnem() or out_mnem. This function outputs colored text.
out_one_operand(n:int)→bool
Use this function to output an operand of an instruction. This function checks for the existence of a manually defined operand and will output it if it exists. It should be called from processor_t::ev_out_insn() and it will call processor_t::ev_out_operand(). This function outputs colored text.
Parameters:
n – 0..UA_MAXOP-1 operand number
Returns:
1: operand is displayed
Returns:
0: operand is hidden
out_immchar_cmts()→None
Print all operand values as commented character constants. This function is used to comment void operands with their representation in the form of character constants. This function outputs colored text.
gen_func_header(pfn:func_t*)→Nonegen_func_footer(pfn:func_tconst*)→Noneout_data(analyze_only:bool)→Noneout_specea(segtype:uchar)→boolgen_header_extra()→Nonegen_header(*args)→Noneout_fcref_names()→None
Print addresses referenced from the specified address as commented symbolic names. This function is used to show, for example, multiple callees of an indirect call. This function outputs colored text.
ida_ua.GH_PRINT_PROC
processor name
ida_ua.GH_PRINT_ASM
selected assembler
ida_ua.GH_PRINT_BYTESEX
byte sex
ida_ua.GH_PRINT_HEADER
lines from ash.header
ida_ua.GH_BYTESEX_HAS_HIGHBYTE
describe inf.is_wide_high_byte_first()
ida_ua.GH_PRINT_PROC_AND_ASMida_ua.GH_PRINT_PROC_ASM_AND_BYTESEXida_ua.GH_PRINT_ALLida_ua.GH_PRINT_ALL_BUT_BYTESEXida_ua.create_outctx(ea:ida_idaapi.ea_t, F:flags64_t=0, suspop:int=0)→outctx_base_t*
Create a new output context. To delete it, just use “delete pctx”
ida_ua.print_insn_mnem(ea:ida_idaapi.ea_t)→str
Print instruction mnemonics.
Parameters:
ea – linear address of the instruction
Returns:
success
ida_ua.FCBF_CONT
don’t stop on decoding, or any other kind of error
ida_ua.FCBF_ERR_REPL
in case of an error, use a CP_REPLCHAR instead of a hex representation of the problematic byte
ida_ua.FCBF_FF_LIT
in case of codepoints == 0xFF, use it as-is (i.e., LATIN SMALL LETTER Y WITH DIAERESIS). If both this, and FCBF_REPL are specified, this will take precedence
ida_ua.FCBF_DELIM
add the ‘ash’-specified delimiters around the generated data. Note: if those are not defined and the INFFL_ALLASM is not set, format_charlit() will return an error
ida_ua.get_dtype_flag(dtype:op_dtype_t)→flags64_t
Get flags for op_t::dtype field.
ida_ua.get_dtype_size(dtype:op_dtype_t)→int
Get size of opt_::dtype field.
ida_ua.is_floating_dtype(dtype:op_dtype_t)→bool
Is a floating type operand?
ida_ua.create_insn(ea:ida_idaapi.ea_t, out:insn_t=None)→int
Create an instruction at the specified address. This function checks if an instruction is present at the specified address and will try to create one if there is none. It will fail if there is a data item or other items hindering the creation of the new instruction. This function will also fill the ‘out’ structure.
Parameters:

-
ea – linear address

-
out – the resulting instruction

Returns:
the length of the instruction or 0
ida_ua.decode_insn(out:insn_t, ea:ida_idaapi.ea_t)→int
Analyze the specified address and fill ‘out’. This function does not modify the database. It just tries to interpret the specified address as an instruction and fills the ‘out’ structure.
Parameters:

-
out – the resulting instruction

-
ea – linear address

Returns:
the length of the (possible) instruction or 0
ida_ua.can_decode(ea:ida_idaapi.ea_t)→bool
Can the bytes at address ‘ea’ be decoded as instruction?
Parameters:
ea – linear address
Returns:
whether or not the contents at that address could be a valid instruction
ida_ua.print_operand(ea:ida_idaapi.ea_t, n:int, getn_flags:int=0, newtype:printop_t=None)→str
Generate text representation for operand #n. This function will generate the text representation of the specified operand (includes color codes.)
Parameters:

-
ea – the item address (instruction or data)

-
n – 0..UA_MAXOP-1 operand number, meaningful only for instructions

-
getn_flags – Name expression flags Currently only GETN_NODUMMY is accepted.

-
newtype – if specified, print the operand using the specified type

Returns:
success
ida_ua.decode_prev_insn(out:insn_t, ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Decode previous instruction if it exists, fill ‘out’.
Parameters:

-
out – the resulting instruction

-
ea – the address to decode the previous instruction from

Returns:
the previous instruction address (BADADDR-no such insn)
classida_ua.macro_constructor_t
Bases: `object`
thisownreserved:intconstruct_macro(insn:insn_t, enable:bool)→bool
Construct a macro instruction. This function may be called from ana() to generate a macro instruction. The real work is done by the ‘build_macro()’ virtual function. It must be defined by the processor module. construct_macro() modifies the database using the info provided by build_macro(). It verifies if the instruction can really be created (for example, that other items do not hinder), may plan to reanalyze the macro, etc. If the macro instructions are disabled by the user, construct_macro() will destroy the macro instruction. Note: if INSN_MODMAC is not set in insn.flags, the database will not be modified.
Parameters:

-
insn – the instruction to modify into a macro

-
enable – enable macro generation

Returns:
true: the macro instruction is generated in ‘insn’
Returns:
false: did not create a macro
build_macro(insn:insn_t, may_go_forward:bool)→bool
Try to extend the instruction. This function may modify ‘insn’ and return false; these changes will be accepted by the kernel but the instruction will not be considered as a macro.
Parameters:

-
insn – Instruction to modify, usually the first instruction of the macro

-
may_go_forward – Is it ok to consider the next instruction for the macro? This argument may be false, for example, if there is a cross reference to the end of INSN. In this case creating a macro is not desired. However, it may still be useful to perform minor tweaks to the instruction using the information about the surrounding instructions.

Returns:
true if created an macro instruction.
ida_ua.decode_preceding_insn(out:insn_t, ea:ida_idaapi.ea_t)→Tuple[ida_idaapi.ea_t,bool]
Decodes the preceding instruction.
Parameters:

-
out – instruction storage

-
ea – current ea

Returns:
tuple(preceeding_ea or BADADDR, farref = Boolean)
ida_ua.construct_macro(*args)
See ua.hpp’s construct_macro().

This function has the following signatures

-
construct_macro(insn: insn_t, enable: bool, build_macro: callable) -> bool

-
construct_macro(constuctor: macro_constructor_t, insn: insn_t, enable: bool) -> bool

Parameters:

-
insn – the instruction to build the macro for

-
enable – enable macro generation

-
build_macro – a callable with 2 arguments: an insn_t, and whether it is ok to consider the next instruction for the macro

-
constructor – a macro_constructor_t implementation

Returns:
success
ida_ua.get_dtype_by_size(size:asize_t)→int
Get op_t::dtype from size.
ida_ua.get_immvals(ea:ida_idaapi.ea_t, n:int, F:flags64_t=0)→PyObject*
Get immediate values at the specified address. This function decodes instruction at the specified address or inspects the data item. It finds immediate values and copies them to ‘out’. This function will store the original value of the operands in ‘out’, unless the last bits of ‘F’ are “…0 11111111”, in which case the transformed values (as needed for printing) will be stored instead.
Parameters:

-
ea – address to analyze

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all the operands

-
F – flags for the specified address

Returns:
number of immediate values (0..2*UA_MAXOP)
ida_ua.get_printable_immvals(ea:ida_idaapi.ea_t, n:int, F:flags64_t=0)→PyObject*
Get immediate ready-to-print values at the specified address
Parameters:

-
ea – address to analyze

-
n – 0..UA_MAXOP-1 operand number, OPND_ALL all the operands

-
F – flags for the specified address

Returns:
number of immediate values (0..2*UA_MAXOP)
ida_ua.insn_t__from_ptrval__(ptrval:int)→insn_t*ida_ua.op_t__from_ptrval__(ptrval:int)→op_t*ida_ua.outctx_base_t__from_ptrval__(ptrval:int)→outctx_base_t*ida_ua.outctx_t__from_ptrval__(ptrval:int)→outctx_t*ida_ua.ua_mnemida_ua.STKVAR_VALID_SIZE=1ida_ua.STKVAR_KEEP_EXISTING=2
