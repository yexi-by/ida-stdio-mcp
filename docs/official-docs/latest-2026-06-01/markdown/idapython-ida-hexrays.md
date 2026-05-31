# IDAPython Hex-Rays API

- 官方来源：https://python.docs.hex-rays.com/ida_hexrays/index.html

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
- ida_hexrays
- View page source

# ida_hexrays

There are 2 representations of the binary code in the decompiler:

Hex-Rays Decompiler project Copyright (c) 1990-2026 Hex-Rays ALL RIGHTS RESERVED.

-
microcode: processor instructions are translated into it and then the decompiler optimizes and transforms it

-
ctree: ctree is built from the optimized microcode and represents AST-like tree with C statements and expressions. It can be printed as C code.

Microcode is represented by the following classes: * mba_t keeps general info about the decompiled code and array of basic blocks. usually mba_t is named ‘mba’ * mblock_t a basic block. includes list of instructions * minsn_t an instruction. contains 3 operands: left, right, and destination * mop_t an operand. depending on its type may hold various info like a number, register, stack variable, etc. * mlist_t list of memory or register locations; can hold vast areas of memory and multiple registers. this class is used very extensively in the decompiler. it may represent list of locations accessed by an instruction or even an entire basic block. it is also used as argument of many functions. for example, there is a function that searches for an instruction that refers to a mlist_t.

See [https://hex-rays.com/blog/microcode-in-pictures](https://hex-rays.com/blog/microcode-in-pictures) for a few pictures. Ctree is represented by: * cfunc_t keeps general info about the decompiled code, including a pointer to mba_t. deleting cfunc_t will delete mba_t too (however, decompiler returns cfuncptr_t, which is a reference counting object and deletes the underlying function as soon as all references to it go out of scope). cfunc_t has ‘body’, which represents the decompiled function body as cinsn_t. * cinsn_t a C statement. can be a compound statement or any other legal C statements (like if, for, while, return, expression-statement, etc). depending on the statement type has pointers to additional info. for example, the ‘if’ statement has poiner to cif_t, which holds the ‘if’ condition, ‘then’ branch, and optionally ‘else’ branch. Please note that despite of the name cinsn_t we say “statements”, not “instructions”. For us instructions are part of microcode, not ctree. * cexpr_t a C expression. is used as part of a C statement, when necessary. cexpr_t has ‘type’ field, which keeps the expression type. * citem_t a base class for cinsn_t and cexpr_t, holds common info like the address, label, and opcode. * cnumber_t a constant 64-bit number. in addition to its value also holds information how to represent it: decimal, hex, or as a symbolic constant (enum member). please note that numbers are represented by another class (mnumber_t) in microcode.

See [https://hex-rays.com/blog/hex-rays-decompiler-primer](https://hex-rays.com/blog/hex-rays-decompiler-primer) for more pictures and more details. Both microcode and ctree use the following class: * lvar_t a local variable. may represent a stack or register variable. a variable has a name, type, location, etc. the list of variables is stored in mba->vars. * lvar_locator_t holds a variable location (vdloc_t) and its definition address. * vdloc_t describes a variable location, like a register number, a stack offset, or, in complex cases, can be a mix of register and stack locations. very similar to argloc_t, which is used in ida. the differences between argloc_t and vdloc_t are: * vdloc_t never uses ARGLOC_REG2 * vdloc_t uses micro register numbers instead of processor register numbers * the stack offsets are never negative in vdloc_t, while in argloc_t there can be negative offsets

The above are the most important classes in this header file. There are many auxiliary classes, please see their definitions in the header file. See also the description of Virtual Machine used by Microcode.

## Attributes

`MAX_SUPPORTED_STACK_SIZE`
|

`MAX_VLR_SIZE`
|

`CMP_NZ`
|

`CMP_Z`
|

`CMP_AE`
|

`CMP_B`
|

`CMP_A`
|

`CMP_BE`
|

`CMP_GT`
|

`CMP_GE`
|

`CMP_LT`
|

`CMP_LE`
|

`cvar`
|

`MAX_VLR_VALUE`
|

`MAX_VLR_SVALUE`
|

`MIN_VLR_SVALUE`
|

`MERR_OK`
|
ok

`MERR_BLOCK`
|
no error, switch to new block

`MERR_INTERR`
|
internal error

`MERR_INSN`
|
cannot convert to microcode

`MERR_MEM`
|
not enough memory

`MERR_BADBLK`
|
bad block found

`MERR_BADSP`
|
positive sp value has been found

`MERR_PROLOG`
|
prolog analysis failed

`MERR_SWITCH`
|
wrong switch idiom

`MERR_EXCEPTION`
|
exception analysis failed

`MERR_HUGESTACK`
|
stack frame is too big

`MERR_LVARS`
|
local variable allocation failed

`MERR_BITNESS`
|
16-bit functions cannot be decompiled

`MERR_BADCALL`
|
could not determine call arguments

`MERR_BADFRAME`
|
function frame is wrong

`MERR_UNKTYPE`
|
undefined type s (currently unused error code)

`MERR_BADIDB`
|
inconsistent database information

`MERR_SIZEOF`
|
wrong basic type sizes in compiler settings

`MERR_REDO`
|
redecompilation has been requested

`MERR_CANCELED`
|
decompilation has been cancelled

`MERR_RECDEPTH`
|
max recursion depth reached during lvar allocation

`MERR_OVERLAP`
|
variables would overlap: s

`MERR_PARTINIT`
|
partially initialized variable s

`MERR_COMPLEX`
|
too complex function

`MERR_LICENSE`
|
no license available

`MERR_ONLY32`
|
only 32-bit functions can be decompiled for the current database

`MERR_ONLY64`
|
only 64-bit functions can be decompiled for the current database

`MERR_BUSY`
|
already decompiling a function

`MERR_FARPTR`
|
far memory model is supported only for pc

`MERR_EXTERN`
|
special segments cannot be decompiled

`MERR_FUNCSIZE`
|
too big function

`MERR_BADRANGES`
|
bad input ranges

`MERR_BADARCH`
|
current architecture is not supported

`MERR_DSLOT`
|
bad instruction in the delay slot

`MERR_STOP`
|
no error, stop the analysis

`MERR_CLOUD`
|
cloud: s

`MERR_EMULATOR`
|
emulator: s

`MERR_MAX_ERR`
|

`MERR_LOOP`
|
internal code: redo last loop (never reported)

`MUST_ACCESS`
|

`MAY_ACCESS`
|

`MAYMUST_ACCESS_MASK`
|

`ONE_ACCESS_TYPE`
|

`INCLUDE_SPOILED_REGS`
|

`EXCLUDE_PASS_REGS`
|

`FULL_XDSU`
|

`WITH_ASSERTS`
|

`EXCLUDE_VOLATILE`
|

`INCLUDE_UNUSED_SRC`
|

`INCLUDE_DEAD_RETREGS`
|

`INCLUDE_RESTRICTED`
|

`CALL_SPOILS_ONLY_ARGS`
|

`m_nop`
|

`m_stx`
|

`m_ldx`
|

`m_ldc`
|

`m_mov`
|

`m_neg`
|

`m_lnot`
|

`m_bnot`
|

`m_xds`
|

`m_xdu`
|

`m_low`
|

`m_high`
|

`m_add`
|

`m_sub`
|

`m_mul`
|

`m_udiv`
|

`m_sdiv`
|

`m_umod`
|

`m_smod`
|

`m_or`
|

`m_and`
|

`m_xor`
|

`m_shl`
|

`m_shr`
|

`m_sar`
|

`m_cfadd`
|

`m_ofadd`
|

`m_cfshl`
|

`m_cfshr`
|

`m_sets`
|

`m_seto`
|

`m_setp`
|

`m_setnz`
|

`m_setz`
|

`m_setae`
|

`m_setb`
|

`m_seta`
|

`m_setbe`
|

`m_setg`
|

`m_setge`
|

`m_setl`
|

`m_setle`
|

`m_jcnd`
|

`m_jnz`
|

`m_jz`
|

`m_jae`
|

`m_jb`
|

`m_ja`
|

`m_jbe`
|

`m_jg`
|

`m_jge`
|

`m_jl`
|

`m_jle`
|

`m_jtbl`
|

`m_ijmp`
|

`m_goto`
|

`m_call`
|

`m_icall`
|

`m_ret`
|

`m_push`
|

`m_pop`
|

`m_und`
|

`m_ext`
|

`m_f2i`
|

`m_f2u`
|

`m_i2f`
|

`m_u2f`
|

`m_f2f`
|

`m_fneg`
|

`m_fadd`
|

`m_fsub`
|

`m_fmul`
|

`m_fdiv`
|

`mr_none`
|

`mr_cf`
|

`mr_zf`
|

`mr_sf`
|

`mr_of`
|

`mr_pf`
|

`cc_count`
|

`mr_cc`
|

`mr_first`
|

`NF_FIXED`
|
number format has been defined by the user

`NF_NEGDONE`
|
temporary internal bit: negation has been performed

`NF_BINVDONE`
|
temporary internal bit: inverting bits is done

`NF_NEGATE`
|
The user asked to negate the constant.

`NF_BITNOT`
|
The user asked to invert bits of the constant.

`NF_VALID`
|
internal bit: stroff or enum is valid for enums: this bit is set immediately for stroffs: this bit is set at the end of decompilation

`GUESSED_NONE`
|

`GUESSED_WEAK`
|

`GUESSED_FUNC`
|

`GUESSED_DATA`
|

`TS_NOELL`
|

`TS_SHRINK`
|

`TS_DONTREF`
|

`TS_MASK`
|

`SVW_INT`
|

`SVW_FLOAT`
|

`SVW_SOFT`
|

`LVINF_KEEP`
|
preserve saved user settings regardless of vars for example, if a var loses all its user-defined attributes or even gets destroyed, keep its lvar_saved_info_t. this is used for ephemeral variables that get destroyed by macro recognition.

`LVINF_SPLIT`
|
split allocation of a new variable. forces the decompiler to create a new variable at ll.defea

`LVINF_NOPTR`
|
variable type should not be a pointer

`LVINF_NOMAP`
|
forbid automatic mapping of the variable

`LVINF_UNUSED`
|
unused argument, corresponds to CVAR_UNUSED

`LVINF_NOPROP`
|
don't propagate assignments to this lvar (CVAR_NOPROP)

`ULV_PRECISE_DEFEA`
|
Use precise defea's for lvar locations.

`MLI_NAME`
|
apply lvar name

`MLI_TYPE`
|
apply lvar type

`MLI_CMT`
|
apply lvar comment

`MLI_SET_FLAGS`
|
set LVINF_... bits

`MLI_CLR_FLAGS`
|
clear LVINF_... bits

`bitset_width`
|

`bitset_align`
|

`bitset_shift`
|

`mop_z`
|
none

`mop_r`
|
register (they exist until MMAT_LVARS)

`mop_n`
|
immediate number constant

`mop_str`
|
immediate string constant (user representation)

`mop_d`
|
result of another instruction

`mop_S`
|
local stack variable (they exist until MMAT_LVARS)

`mop_v`
|
global variable

`mop_b`
|
micro basic block (mblock_t)

`mop_f`
|
list of arguments

`mop_l`
|
local variable

`mop_a`
|
mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)

`mop_h`
|
helper function

`mop_c`
|
mcases

`mop_fn`
|
floating point constant

`mop_p`
|
operand pair

`mop_sc`
|
scattered

`NOSIZE`
|
wrong or unexisting operand size

`SHINS_NUMADDR`
|
display definition addresses for numbers

`SHINS_VALNUM`
|
display value numbers

`SHINS_SHORT`
|
do not display use-def chains and other attrs

`SHINS_LDXEA`
|
display address of ldx expressions (not used)

`NO_SIDEFF`
|
change operand size but ignore side effects if you decide to keep the changed operand, handle_new_size() must be called

`WITH_SIDEFF`
|
change operand size and handle side effects

`ONLY_SIDEFF`
|
only handle side effects

`ANY_REGSIZE`
|
any register size is permitted

`ANY_FPSIZE`
|
any size of floating operand is permitted

`OPROP_IMPDONE`
|
imported operand (a pointer) has been dereferenced

`OPROP_UDT`
|
a struct or union

`OPROP_FLOAT`
|
possibly floating value

`OPROP_CCFLAGS`
|
mop_n: a pc-relative value mop_a: an address obtained from a relocation else: value of a condition code register (like mr_cc)

`OPROP_UDEFVAL`
|
uses undefined value

`OPROP_LOWADDR`
|
a low address offset

`OPROP_ABI`
|
is used to organize arg/retval of a call such operands should be combined more carefully than others at least on BE platforms

`ROLE_UNK`
|
unknown function role

`ROLE_EMPTY`
|
empty, does not do anything (maybe spoils regs)

`ROLE_MEMSET`
|
memset(void *dst, uchar value, size_t count);

`ROLE_MEMSET32`
|
memset32(void *dst, uint32 value, size_t count);

`ROLE_MEMSET64`
|
memset64(void *dst, uint64 value, size_t count);

`ROLE_MEMCPY`
|
memcpy(void *dst, const void *src, size_t count);

`ROLE_STRCPY`
|
strcpy(char *dst, const char *src);

`ROLE_STRLEN`
|
strlen(const char *src);

`ROLE_STRCAT`
|
strcat(char *dst, const char *src);

`ROLE_TAIL`
|
char *tail(const char *str);

`ROLE_BUG`
|
BUG() helper macro: never returns, causes exception.

`ROLE_ALLOCA`
|
alloca() function

`ROLE_BSWAP`
|
bswap() function (any size)

`ROLE_PRESENT`
|
present() function (used in patterns)

`ROLE_CONTAINING_RECORD`
|
CONTAINING_RECORD() macro.

`ROLE_FASTFAIL`
|
__fastfail()

`ROLE_READFLAGS`
|
__readeflags, __readcallersflags

`ROLE_IS_MUL_OK`
|
is_mul_ok

`ROLE_SATURATED_MUL`
|
saturated_mul

`ROLE_BITTEST`
|
[lock] bt

`ROLE_BITTESTANDSET`
|
[lock] bts

`ROLE_BITTESTANDRESET`
|
[lock] btr

`ROLE_BITTESTANDCOMPLEMENT`
|
[lock] btc

`ROLE_VA_ARG`
|
va_arg() macro

`ROLE_VA_COPY`
|
va_copy() function

`ROLE_VA_START`
|
va_start() function

`ROLE_VA_END`
|
va_end() function

`ROLE_ROL`
|
rotate left

`ROLE_ROR`
|
rotate right

`ROLE_CFSUB3`
|
carry flag after subtract with carry

`ROLE_OFSUB3`
|
overflow flag after subtract with carry

`ROLE_ABS`
|
integer absolute value

`ROLE_3WAYCMP0`
|
3-way compare helper, returns -1/0/1

`ROLE_3WAYCMP1`
|
3-way compare helper, returns 0/1/2

`ROLE_WMEMCPY`
|
wchar_t *wmemcpy(wchar_t *dst, const wchar_t *src, size_t n)

`ROLE_WMEMSET`
|
wchar_t *wmemset(wchar_t *dst, wchar_t wc, size_t n)

`ROLE_WCSCPY`
|
wchar_t *wcscpy(wchar_t *dst, const wchar_t *src);

`ROLE_WCSLEN`
|
size_t wcslen(const wchar_t *s)

`ROLE_WCSCAT`
|
wchar_t *wcscat(wchar_t *dst, const wchar_t *src)

`ROLE_SSE_CMP4`
|
e.g. _mm_cmpgt_ss

`ROLE_SSE_CMP8`
|
e.g. _mm_cmpgt_sd

`FUNC_NAME_MEMCPY`
|

`FUNC_NAME_WMEMCPY`
|

`FUNC_NAME_MEMSET`
|

`FUNC_NAME_WMEMSET`
|

`FUNC_NAME_MEMSET32`
|

`FUNC_NAME_MEMSET64`
|

`FUNC_NAME_STRCPY`
|

`FUNC_NAME_WCSCPY`
|

`FUNC_NAME_STRLEN`
|

`FUNC_NAME_WCSLEN`
|

`FUNC_NAME_STRCAT`
|

`FUNC_NAME_WCSCAT`
|

`FUNC_NAME_TAIL`
|

`FUNC_NAME_VA_ARG`
|

`FUNC_NAME_EMPTY`
|

`FUNC_NAME_PRESENT`
|

`FUNC_NAME_CONTAINING_RECORD`
|

`FUNC_NAME_MORESTACK`
|

`FCI_PROP`
|
call has been propagated

`FCI_DEAD`
|
some return registers were determined dead

`FCI_FINAL`
|
call type is final, should not be changed

`FCI_NORET`
|
call does not return

`FCI_PURE`
|
pure function

`FCI_NOSIDE`
|
call does not have side effects

`FCI_SPLOK`
|
spoiled/visible_memory lists have been optimized. for some functions we can reduce them as soon as information about the arguments becomes available. in order not to try optimize them again we use this bit.

`FCI_HASCALL`
|
A function is an synthetic helper combined from several instructions and at least one of them was a call to a real functions

`FCI_HASFMT`
|
A variadic function with recognized printf- or scanf-style format string

`FCI_EXPLOCS`
|
all arglocs are specified explicitly

`CHF_INITED`
|
is chain initialized? (valid only after lvar allocation)

`CHF_REPLACED`
|
chain operands have been replaced?

`CHF_OVER`
|
overlapped chain

`CHF_FAKE`
|
fake chain created by widen_chains()

`CHF_PASSTHRU`
|
pass-thru chain, must use the input variable to the block

`CHF_TERM`
|
terminating chain; the variable does not survive across the block

`GCA_EMPTY`
|
include empty chains

`GCA_SPEC`
|
include chains for special registers

`GCA_ALLOC`
|
enumerate only allocated chains

`GCA_NALLOC`
|
enumerate only non-allocated chains

`GCA_OFIRST`
|
consider only chains of the first block

`GCA_OLAST`
|
consider only chains of the last block

`IPROP_OPTIONAL`
|
optional instruction

`IPROP_PERSIST`
|
persistent insn; they are not destroyed

`IPROP_WILDMATCH`
|
match multiple insns

`IPROP_CLNPOP`
|
the purpose of the instruction is to clean stack (e.g. "pop ecx" is often used for that)

`IPROP_FPINSN`
|
floating point insn

`IPROP_FARCALL`
|
call of a far function using push cs/call sequence

`IPROP_TAILCALL`
|
tail call

`IPROP_ASSERT`
|
assertion: usually mov #val, op. assertions are used to help the optimizer. assertions are ignored when generating ctree

`IPROP_SPLIT`
|
the instruction has been split:

`IPROP_SPLIT1`
|
into 1 byte

`IPROP_SPLIT2`
|
into 2 bytes

`IPROP_SPLIT4`
|
into 4 bytes

`IPROP_SPLIT8`
|
into 8 bytes

`IPROP_COMBINED`
|
insn has been modified because of a partial reference

`IPROP_EXTSTX`
|
this is m_ext propagated into m_stx

`IPROP_IGNLOWSRC`
|
low part of the instruction source operand has been created artificially (this bit is used only for 'and x, 80...')

`IPROP_INV_JX`
|
inverted conditional jump

`IPROP_WAS_NORET`
|
was noret icall

`IPROP_MULTI_MOV`
|
bits that can be set by plugins:

`IPROP_DONT_PROP`
|
may not propagate

`IPROP_DONT_COMB`
|
may not combine this instruction with others

`IPROP_MBARRIER`
|
this instruction acts as a memory barrier (instructions accessing memory may not be reordered past it)

`IPROP_UNMERGED`
|
'goto' instruction was transformed info 'call'

`IPROP_UNPAIRED`
|
instruction is a result of del_dest_pairs() transformation

`OPTI_ADDREXPRS`
|
optimize all address expressions (&x+N; &x-&y)

`OPTI_MINSTKREF`
|
may update minstkref

`OPTI_COMBINSNS`
|
may combine insns (only for optimize_insn)

`OPTI_NO_LDXOPT`
|
the function is called after the propagation attempt, we do not optimize low/high(ldx) in this case

`OPTI_NO_VALRNG`
|
forbid using valranges

`EQ_IGNSIZE`
|
ignore source operand sizes

`EQ_IGNCODE`
|
ignore instruction opcodes

`EQ_CMPDEST`
|
compare instruction destinations

`EQ_OPTINSN`
|
optimize mop_d operands

`NORET_IGNORE_WAS_NORET_ICALL`
|

`NORET_FORBID_ANALYSIS`
|

`BLT_NONE`
|
unknown block type

`BLT_STOP`
|
stops execution regularly (must be the last block)

`BLT_0WAY`
|
does not have successors (tail is a noret function)

`BLT_1WAY`
|
passes execution to one block (regular or goto block)

`BLT_2WAY`
|
passes execution to two blocks (conditional jump)

`BLT_NWAY`
|
passes execution to many blocks (switch idiom)

`BLT_XTRN`
|
external block (out of function address)

`MBL_PRIV`
|
private block - no instructions except the specified are accepted (used in patterns)

`MBL_NONFAKE`
|
regular block

`MBL_FAKE`
|
fake block

`MBL_GOTO`
|
this block is a goto target

`MBL_TCAL`
|
aritifical call block for tail calls

`MBL_PUSH`
|
needs "convert push/pop instructions"

`MBL_DMT64`
|
needs "demote 64bits"

`MBL_COMB`
|
needs "combine" pass

`MBL_PROP`
|
needs 'propagation' pass

`MBL_DEAD`
|
needs "eliminate deads" pass

`MBL_LIST`
|
use/def lists are ready (not dirty)

`MBL_INCONST`
|
inconsistent lists: we are building them

`MBL_CALL`
|
call information has been built

`MBL_BACKPROP`
|
performed backprop_cc

`MBL_NORET`
|
dead end block: doesn't return execution control

`MBL_DSLOT`
|
block for delay slot

`MBL_VALRANGES`
|
should optimize using value ranges

`MBL_KEEP`
|
do not remove even if unreachable

`MBL_INLINED`
|
block was inlined, not originally part of mbr

`MBL_EXTFRAME`
|
an inlined block with an external frame

`FD_BACKWARD`
|
search direction

`FD_FORWARD`
|
search direction

`FD_USE`
|
look for use

`FD_DEF`
|
look for definition

`FD_DIRTY`
|
ignore possible implicit definitions by function calls and indirect memory access

`VR_AT_START`
|
get value ranges before the instruction or at the block start (if M is nullptr)

`VR_AT_END`
|
get value ranges after the instruction or at the block end, just after the last instruction (if M is nullptr)

`VR_EXACT`
|
find exact match. if not set, the returned valrng size will be >= vivl.size

`WARN_VARARG_REGS`
|
0 cannot handle register arguments in vararg function, discarded them

`WARN_ILL_PURGED`
|
1 odd caller purged bytes d, correcting

`WARN_ILL_FUNCTYPE`
|
2 invalid function type 's' has been ignored

`WARN_VARARG_TCAL`
|
3 cannot handle tail call to vararg

`WARN_VARARG_NOSTK`
|
4 call vararg without local stack

`WARN_VARARG_MANY`
|
5 too many varargs, some ignored

`WARN_ADDR_OUTARGS`
|
6 cannot handle address arithmetics in outgoing argument area of stack frame - unused

`WARN_DEP_UNK_CALLS`
|
7 found interdependent unknown calls

`WARN_ILL_ELLIPSIS`
|
8 erroneously detected ellipsis type has been ignored

`WARN_GUESSED_TYPE`
|
9 using guessed type s;

`WARN_EXP_LINVAR`
|
10 failed to expand a linear variable

`WARN_WIDEN_CHAINS`
|
11 failed to widen chains

`WARN_BAD_PURGED`
|
12 inconsistent function type and number of purged bytes

`WARN_CBUILD_LOOPS`
|
13 too many cbuild loops

`WARN_NO_SAVE_REST`
|
14 could not find valid save-restore pair for s

`WARN_ODD_INPUT_REG`
|
15 odd input register s

`WARN_ODD_ADDR_USE`
|
16 odd use of a variable address

`WARN_MUST_RET_FP`
|
17 function return type is incorrect (must be floating point)

`WARN_ILL_FPU_STACK`
|
18 inconsistent fpu stack

`WARN_SELFREF_PROP`
|
19 self-referencing variable has been detected

`WARN_WOULD_OVERLAP`
|
20 variables would overlap: s

`WARN_ARRAY_INARG`
|
21 array has been used for an input argument

`WARN_MAX_ARGS`
|
22 too many input arguments, some ignored

`WARN_BAD_FIELD_TYPE`
|
23 incorrect structure member type for s::s, ignored

`WARN_WRITE_CONST`
|
24 write access to const memory at a has been detected

`WARN_BAD_RETVAR`
|
25 wrong return variable

`WARN_FRAG_LVAR`
|
26 fragmented variable at s may be wrong

`WARN_HUGE_STKOFF`
|
27 exceedingly huge offset into the stack frame

`WARN_UNINITED_REG`
|
28 reference to an uninitialized register has been removed: s

`WARN_FIXED_INSN`
|
29 fixed broken insn

`WARN_WRONG_VA_OFF`
|
30 wrong offset of va_list variable

`WARN_CR_NOFIELD`
|
31 CONTAINING_RECORD: no field 's' in struct 's' at d

`WARN_CR_BADOFF`
|
32 CONTAINING_RECORD: too small offset d for struct 's'

`WARN_BAD_STROFF`
|
33 user specified stroff has not been processed: s

`WARN_BAD_VARSIZE`
|
34 inconsistent variable size for 's'

`WARN_UNSUPP_REG`
|
35 unsupported processor register 's'

`WARN_UNALIGNED_ARG`
|
36 unaligned function argument 's'

`WARN_BAD_STD_TYPE`
|
37 corrupted or unexisting local type 's'

`WARN_BAD_CALL_SP`
|
38 bad sp value at call

`WARN_MISSED_SWITCH`
|
39 wrong markup of switch jump, skipped it

`WARN_BAD_SP`
|
40 positive sp value a has been found

`WARN_BAD_STKPNT`
|
41 wrong sp change point

`WARN_UNDEF_LVAR`
|
42 variable 's' is possibly undefined

`WARN_JUMPOUT`
|
43 control flows out of bounds

`WARN_BAD_VALRNG`
|
44 values range analysis failed

`WARN_BAD_SHADOW`
|
45 ignored the value written to the shadow area of the succeeding call

`WARN_OPT_VALRNG`
|
46 conditional instruction was optimized away because s

`WARN_RET_LOCREF`
|
47 returning address of temporary local variable 's'

`WARN_BAD_MAPDST`
|
48 too short map destination 's' for variable 's'

`WARN_BAD_INSN`
|
49 bad instruction

`WARN_ODD_ABI`
|
50 encountered odd instruction for the current ABI

`WARN_UNBALANCED_STACK`
|
51 unbalanced stack, ignored a potential tail call

`WARN_OPT_VALRNG2`
|
52 mask 0xX is shortened because s <= 0xX"

`WARN_OPT_VALRNG3`
|
53 masking with 0XX was optimized away because s <= 0xX

`WARN_OPT_USELESS_JCND`
|
54 simplified comparisons for 's': s became s

`WARN_SUBFRAME_OVERFLOW`
|
55 call arguments overflow the function chunk frame

`WARN_OPT_VALRNG4`
|
56 the cases s were optimized away because s

`WARN_FRAME_ACCESS`
|
57 illegal frame access

`WARN_MAX`
|
may be used in notes as a placeholder when the warning id is not available

`MMAT_ZERO`
|
microcode does not exist

`MMAT_GENERATED`
|
generated microcode

`MMAT_PREOPTIMIZED`
|
preoptimized pass is complete

`MMAT_LOCOPT`
|
local optimization of each basic block is complete. control flow graph is ready too.

`MMAT_CALLS`
|
detected call arguments. see also hxe_calls_done

`MMAT_GLBOPT1`
|
performed the first pass of global optimization

`MMAT_GLBOPT2`
|
most global optimization passes are done

`MMAT_GLBOPT3`
|
completed all global optimization. microcode is fixed now.

`MMAT_LVARS`
|
allocated local variables

`MMIDX_GLBLOW`
|
global memory: low part

`MMIDX_LVARS`
|
stack: local variables

`MMIDX_RETADDR`
|
stack: return address

`MMIDX_SHADOW`
|
stack: shadow arguments

`MMIDX_ARGS`
|
stack: regular stack arguments

`MMIDX_GLBHIGH`
|
global memory: high part

`MBA_PRCDEFS`
|
use precise defeas for chain-allocated lvars

`MBA_NOFUNC`
|
function is not present, addresses might be wrong

`MBA_PATTERN`
|
microcode pattern, callinfo is present

`MBA_LOADED`
|
loaded gdl, no instructions (debugging)

`MBA_RETFP`
|
function returns floating point value

`MBA_SPLINFO`
|
(final_type ? idb_spoiled : spoiled_regs) is valid

`MBA_PASSREGS`
|
has mcallinfo_t::pass_regs

`MBA_THUNK`
|
thunk function

`MBA_CMNSTK`
|
stkvars+stkargs should be considered as one area

`MBA_PREOPT`
|
preoptimization stage complete

`MBA_CMBBLK`
|
request to combine blocks

`MBA_ASRTOK`
|
assertions have been generated

`MBA_CALLS`
|
callinfo has been built

`MBA_ASRPROP`
|
assertion have been propagated

`MBA_SAVRST`
|
save-restore analysis has been performed

`MBA_RETREF`
|
return type has been refined

`MBA_GLBOPT`
|
microcode has been optimized globally

`MBA_LVARS0`
|
lvar pre-allocation has been performed

`MBA_LVARS1`
|
lvar real allocation has been performed

`MBA_DELPAIRS`
|
pairs have been deleted once

`MBA_CHVARS`
|
can verify chain varnums

`MBA_SHORT`
|
use short display

`MBA_COLGDL`
|
display graph after each reduction

`MBA_INSGDL`
|
display instruction in graphs

`MBA_NICE`
|
apply transformations to c code

`MBA_REFINE`
|
may refine return value size

`MBA_WINGR32`
|
use wingraph32 (deprecated, see hexrays_config_t::use_external_graph)

`MBA_NUMADDR`
|
display definition addresses for numbers

`MBA_VALNUM`
|
display value numbers

`MBA_SHOWEA`
|
display EA in line prefix

`MBA_INITIAL_FLAGS`
|

`MBA2_LVARNAMES_OK`
|
may verify lvar_names?

`MBA2_LVARS_RENAMED`
|
accept empty names now?

`MBA2_OVER_CHAINS`
|
has overlapped chains?

`MBA2_VALRNG_DONE`
|
calculated valranges?

`MBA2_IS_CTR`
|
is constructor?

`MBA2_IS_DTR`
|
is destructor?

`MBA2_ARGIDX_OK`
|
may verify input argument list?

`MBA2_NO_DUP_CALLS`
|
forbid multiple calls with the same ea

`MBA2_NO_DUP_LVARS`
|
forbid multiple lvars with the same ea

`MBA2_UNDEF_RETVAR`
|
return value is undefined

`MBA2_ARGIDX_SORTED`
|
args finally sorted according to ABI (e.g. reverse stkarg order in Borland)

`MBA2_CODE16_BIT`
|
the code16 bit got removed

`MBA2_STACK_RETVAL`
|
the return value (or its part) is on the stack

`MBA2_HAS_OUTLINES`
|
calls to outlined code have been inlined

`MBA2_NO_FRAME`
|
do not use function frame info (only snippet mode)

`MBA2_PROP_COMPLEX`
|
allow propagation of more complex variable definitions

`MBA2_DONT_VERIFY`
|
Do not verify microcode. This flag is recomended to be set only when debugging decompiler plugins

`MBA2_INITIAL_FLAGS`
|

`MBA2_ALL_FLAGS`
|

`NALT_VD`
|
this index is not used by ida

`LOCOPT_ALL`
|
redo optimization for all blocks. if this bit is not set, only dirty blocks will be optimized

`LOCOPT_REFINE`
|
refine return type, ok to fail

`LOCOPT_REFINE2`
|
refine return type, try harder

`ACFL_LOCOPT`
|
perform local propagation (requires ACFL_BLKOPT)

`ACFL_BLKOPT`
|
perform interblock transformations

`ACFL_GLBPROP`
|
perform global propagation

`ACFL_GLBDEL`
|
perform dead code eliminition

`ACFL_GUESS`
|
may guess calling conventions

`CPBLK_FAST`
|
do not update minbstkref and minbargref

`CPBLK_MINREF`
|
update minbstkref and minbargref

`CPBLK_OPTJMP`
|
del the jump insn at the end of the block if it becomes useless

`INLINE_EXTFRAME`
|
Inlined function has its own (external) frame.

`INLINE_DONTCOPY`
|
Do not reuse old inlined copy even if it exists.

`GC_REGS_AND_STKVARS`
|
registers and stkvars (restricted memory only)

`GC_ASR`
|
all the above and assertions

`GC_XDSU`
|
only registers calculated with FULL_XDSU

`GC_END`
|
number of chain types

`GC_DIRTY_ALL`
|
bitmask to represent all chains

`OPF_REUSE`
|
reuse existing window

`OPF_NEW_WINDOW`
|
open new window

`OPF_REUSE_ACTIVE`
|
reuse existing window, only if the currently active widget is a pseudocode view

`OPF_NO_WAIT`
|
do not display waitbox if decompilation happens

`OPF_WINDOW_MGMT_MASK`
|

`VDRUN_NEWFILE`
|
Create a new file or overwrite existing file.

`VDRUN_APPEND`
|
Create a new file or append to existing file.

`VDRUN_ONLYNEW`
|
Fail if output file already exists.

`VDRUN_SILENT`
|
Silent decompilation.

`VDRUN_SENDIDB`
|
Send problematic databases to hex-rays.com.

`VDRUN_MAYSTOP`
|
The user can cancel decompilation.

`VDRUN_CMDLINE`
|
Called from ida's command line.

`VDRUN_STATS`
|
Print statistics into vd_stats.txt.

`VDRUN_LUMINA`
|
Use lumina server.

`VDRUN_PERF`
|
Print performance stats to ida.log.

`GCO_STK`
|
a stack variable

`GCO_REG`
|
is register? otherwise a stack variable

`GCO_USE`
|
is source operand?

`GCO_DEF`
|
is destination operand?

`cot_empty`
|

`cot_comma`
|
x, y

`cot_asg`
|
x = y

`cot_asgbor`
|
x |= y

`cot_asgxor`
|
x ^= y

`cot_asgband`
|
x &= y

`cot_asgadd`
|
x += y

`cot_asgsub`
|
x -= y

`cot_asgmul`
|
x *= y

`cot_asgsshr`
|
x >>= y signed

`cot_asgushr`
|
x >>= y unsigned

`cot_asgshl`
|
x <<= y

`cot_asgsdiv`
|
x /= y signed

`cot_asgudiv`
|
x /= y unsigned

`cot_asgsmod`
|
x %= y signed

`cot_asgumod`
|
x %= y unsigned

`cot_tern`
|
x ? y : z

`cot_lor`
|
x || y

`cot_land`
|
x && y

`cot_bor`
|
x | y

`cot_xor`
|
x ^ y

`cot_band`
|
x & y

`cot_eq`
|
x == y int or fpu (see EXFL_FPOP)

`cot_ne`
|
x != y int or fpu (see EXFL_FPOP)

`cot_sge`
|
x >= y signed or fpu (see EXFL_FPOP)

`cot_uge`
|
x >= y unsigned

`cot_sle`
|
x <= y signed or fpu (see EXFL_FPOP)

`cot_ule`
|
x <= y unsigned

`cot_sgt`
|
x > y signed or fpu (see EXFL_FPOP)

`cot_ugt`
|
x > y unsigned

`cot_slt`
|
x < y signed or fpu (see EXFL_FPOP)

`cot_ult`
|
x < y unsigned

`cot_sshr`
|
x >> y signed

`cot_ushr`
|
x >> y unsigned

`cot_shl`
|
x << y

`cot_add`
|
x + y

`cot_sub`
|
x - y

`cot_mul`
|
x * y

`cot_sdiv`
|
x / y signed

`cot_udiv`
|
x / y unsigned

`cot_smod`
|
x % y signed

`cot_umod`
|
x % y unsigned

`cot_fadd`
|
x + y fp

`cot_fsub`
|
x - y fp

`cot_fmul`
|
x * y fp

`cot_fdiv`
|
x / y fp

`cot_fneg`
|
-x fp

`cot_neg`
|
-x

`cot_cast`
|
(type)x

`cot_lnot`
|
!x

`cot_bnot`
|
~x

`cot_ptr`
|
*x, access size in 'ptrsize'

`cot_ref`
|
&x

`cot_postinc`
|
x++

`cot_postdec`
|
x-

`cot_preinc`
|
++x

`cot_predec`
|
-x

`cot_call`
|
x(...)

`cot_idx`
|
x[y]

`cot_memref`
|
x.m

`cot_memptr`
|
x->m, access size in 'ptrsize'

`cot_num`
|
n

`cot_fnum`
|
fpc

`cot_str`
|
string constant (user representation)

`cot_obj`
|
obj_ea

`cot_var`
|
v

`cot_insn`
|
instruction in expression, internal representation only

`cot_sizeof`
|
sizeof(x)

`cot_helper`
|
arbitrary name

`cot_type`
|
arbitrary type

`cot_last`
|

`cit_empty`
|
instruction types start here

`cit_block`
|
block-statement: { ... }

`cit_expr`
|
expression-statement: expr;

`cit_if`
|
if-statement

`cit_for`
|
for-statement

`cit_while`
|
while-statement

`cit_do`
|
do-statement

`cit_switch`
|
switch-statement

`cit_break`
|
break-statement

`cit_continue`
|
continue-statement

`cit_return`
|
return-statement

`cit_goto`
|
goto-statement

`cit_asm`
|
asm-statement

`cit_try`
|
C++ try-statement.

`cit_throw`
|
C++ throw-statement.

`cit_end`
|

`CMAT_ZERO`
|
does not exist

`CMAT_BUILT`
|
just generated

`CMAT_TRANS1`
|
applied first wave of transformations

`CMAT_NICE`
|
nicefied expressions

`CMAT_TRANS2`
|
applied second wave of transformations

`CMAT_CPA`
|
corrected pointer arithmetic

`CMAT_TRANS3`
|
applied third wave of transformations

`CMAT_CASTED`
|
added necessary casts

`CMAT_FINAL`
|
ready-to-use

`ITP_EMPTY`
|
nothing

`ITP_ARG1`
|
, (64 entries are reserved for 64 call arguments)

`ITP_ARG64`
|

`ITP_BRACE1`
|

`ITP_INNER_LAST`
|

`ITP_ASM`
|
__asm-line

`ITP_ELSE`
|
else-line

`ITP_DO`
|
do-line

`ITP_SEMI`
|
semicolon

`ITP_CURLY1`
|

`ITP_CURLY2`
|

`ITP_BRACE2`
|

`ITP_COLON`
|
: (label)

`ITP_BLOCK1`
|
opening block comment. this comment is printed before the item (other comments are indented and printed after the item)

`ITP_BLOCK2`
|
closing block comment.

`ITP_TRY`
|
C++ try statement.

`ITP_CASE`
|
bit for switch cases

`ITP_SIGN`
|
if this bit is set too, then we have a negative case value

`RETRIEVE_ONCE`
|
Retrieve comment if it has not been used yet.

`RETRIEVE_ALWAYS`
|
Retrieve comment even if it has been used.

`EXFL_CPADONE`
|
pointer arithmetic correction done

`EXFL_LVALUE`
|
expression is lvalue even if it doesn't look like it

`EXFL_FPOP`
|
floating point operation

`EXFL_ALONE`
|
standalone helper

`EXFL_CSTR`
|
string literal

`EXFL_PARTIAL`
|
type of the expression is considered partial

`EXFL_UNDEF`
|
expression uses undefined value

`EXFL_JUMPOUT`
|
jump out-of-function

`EXFL_VFTABLE`
|
is ptr to vftable (used for cot_memptr, cot_memref)

`EXFL_ALL`
|
all currently defined bits

`CALC_CURLY_BRACES`
|
print curly braces if necessary

`NO_CURLY_BRACES`
|
don't print curly braces

`USE_CURLY_BRACES`
|
print curly braces without any checks

`CFL_FINAL`
|
call type is final, should not be changed

`CFL_HELPER`
|
created from a decompiler helper function

`CFL_NORET`
|
call does not return

`CV_FAST`
|
do not maintain parent information

`CV_PRUNE`
|
this bit is set by visit...() to prune the walk

`CV_PARENTS`
|
maintain parent information

`CV_POST`
|
call the leave...() functions

`CV_RESTART`
|
restart enumeration at the top expr (apply_to_exprs)

`CV_INSNS`
|
visit only statements, prune all expressions do not use before the final ctree maturity because expressions may contain statements at intermediate stages (see cot_insn). Otherwise you risk missing statements embedded into expressions.

`ANCHOR_INDEX`
|

`ANCHOR_MASK`
|

`ANCHOR_CITEM`
|
c-tree item

`ANCHOR_LVAR`
|
declaration of local variable

`ANCHOR_ITP`
|
item type preciser

`ANCHOR_BLKCMT`
|
block comment (for ctree items)

`VDI_NONE`
|
undefined

`VDI_EXPR`
|
c-tree item

`VDI_LVAR`
|
declaration of local variable

`VDI_FUNC`
|
the function itself (the very first line with the function prototype)

`VDI_TAIL`
|
cursor is at (beyond) the line end (commentable line)

`GLN_CURRENT`
|
get label of the current item

`GLN_GOTO_TARGET`
|
get goto target

`GLN_ALL`
|
get both

`FORBID_UNUSED_LABELS`
|
Unused labels cause interr.

`ALLOW_UNUSED_LABELS`
|
Unused labels are permitted.

`CIT_COLLAPSED`
|
display ctree item in collapsed form

`CFS_BOUNDS`
|
'eamap' and 'boundaries' are ready

`CFS_TEXT`
|
'sv' is ready (and hdrlines)

`CFS_LVARS_HIDDEN`
|
local variable definitions are collapsed

`CFS_LOCKED`
|
cfunc is temporarily locked

`DECOMP_NO_WAIT`
|
do not display waitbox

`DECOMP_NO_CACHE`
|
do not use decompilation cache (snippets are never cached)

`DECOMP_NO_FRAME`
|
do not use function frame info (only snippet mode)

`DECOMP_WARNINGS`
|
display warnings in the output window

`DECOMP_ALL_BLKS`
|
generate microcode for unreachable blocks

`DECOMP_NO_HIDE`
|
do not close display waitbox. see close_hexrays_waitbox()

`DECOMP_GXREFS_DEFLT`
|
the default behavior: do not update the global xrefs cache upon decompile() call, but when the pseudocode text is generated (e.g., through cfunc_t.get_pseudocode())

`DECOMP_GXREFS_NOUPD`
|
do not update the global xrefs cache

`DECOMP_GXREFS_FORCE`
|
update the global xrefs cache immediately

`DECOMP_VOID_MBA`
|
return empty mba object (to be used with gen_microcode)

`DECOMP_OUTLINE`
|
generate code for an outline

`hxe_flowchart`
|
Flowchart has been generated.

`hxe_stkpnts`
|
SP change points have been calculated.

`hxe_prolog`
|
Prolog analysis has been finished.

`hxe_microcode`
|
Microcode has been generated.

`hxe_preoptimized`
|
Microcode has been preoptimized.

`hxe_locopt`
|
Basic block level optimization has been finished.

`hxe_prealloc`
|
Local variables: preallocation step begins.

`hxe_glbopt`
|
Global optimization has been finished. If microcode is modified, MERR_LOOP must be returned. It will cause a complete restart of the optimization.

`hxe_pre_structural`
|
Structure analysis is starting.

`hxe_structural`
|
Structural analysis has been finished.

`hxe_maturity`
|
Ctree maturity level is being changed.

`hxe_interr`
|
Internal error has occurred.

`hxe_combine`
|
Trying to combine instructions of basic block.

`hxe_print_func`
|
Printing ctree and generating text.

`hxe_func_printed`
|
Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.

`hxe_resolve_stkaddrs`
|
The optimizer is about to resolve stack addresses.

`hxe_build_callinfo`
|
Analyzing a call instruction.

`hxe_callinfo_built`
|
A call instruction has been anallyzed.

`hxe_calls_done`
|
All calls have been analyzed.

`hxe_begin_inlining`
|
Starting to inline outlined functions.

`hxe_inlining_func`
|
A set of ranges is going to be inlined.

`hxe_inlined_func`
|
A set of ranges got inlined.

`hxe_collect_warnings`
|
Collect warning messages from plugins. These warnings will be displayed at the function header, after the user-defined comments.

`hxe_open_pseudocode`
|
New pseudocode view has been opened.

`hxe_switch_pseudocode`
|
Existing pseudocode view has been reloaded with a new function. Its text has not been refreshed yet, only cfunc and mba pointers are ready.

`hxe_refresh_pseudocode`
|
Existing pseudocode text has been refreshed. Adding/removing pseudocode lines is forbidden in this event.

`hxe_close_pseudocode`
|
Pseudocode view is being closed.

`hxe_keyboard`
|
Keyboard has been hit.

`hxe_right_click`
|
Mouse right click. Use hxe_populating_popup instead, in case you want to add items in the popup menu.

`hxe_double_click`
|
Mouse double click.

`hxe_curpos`
|
Current cursor position has been changed. (for example, by left-clicking or using keyboard)

`hxe_create_hint`
|
Create a hint for the current item.

`hxe_text_ready`
|
Decompiled text is ready.

`hxe_populating_popup`
|
Populating popup menu. We can add menu items now.

`lxe_lvar_name_changed`
|
Local variable got renamed.

`lxe_lvar_type_changed`
|
Local variable type got changed.

`lxe_lvar_cmt_changed`
|
Local variable comment got changed.

`lxe_lvar_mapping_changed`
|
Local variable mapping got changed.

`hxe_cmt_changed`
|
Comment got changed.

`hxe_mba_maturity`
|
Maturity level of an MBA was changed.

`USE_KEYBOARD`
|
Keyboard.

`USE_MOUSE`
|
Mouse.

`HEXRAYS_API_MAGIC`
|

`CMT_NONE`
|
No comment is possible.

`CMT_TAIL`
|
Indented comment.

`CMT_BLOCK1`
|
Anterioir block comment.

`CMT_BLOCK2`
|
Posterior block comment.

`CMT_LVAR`
|
Local variable comment.

`CMT_FUNC`
|
Function comment.

`CMT_ALL`
|
All comments.

`VDUI_VISIBLE`
|
is visible?

`VDUI_VALID`
|
is valid?

`hx_user_numforms_begin`
|

`hx_user_numforms_end`
|

`hx_user_numforms_next`
|

`hx_user_numforms_prev`
|

`hx_user_numforms_first`
|

`hx_user_numforms_second`
|

`hx_user_numforms_find`
|

`hx_user_numforms_insert`
|

`hx_user_numforms_erase`
|

`hx_user_numforms_clear`
|

`hx_user_numforms_size`
|

`hx_user_numforms_free`
|

`hx_user_numforms_new`
|

`hx_lvar_mapping_begin`
|

`hx_lvar_mapping_end`
|

`hx_lvar_mapping_next`
|

`hx_lvar_mapping_prev`
|

`hx_lvar_mapping_first`
|

`hx_lvar_mapping_second`
|

`hx_lvar_mapping_find`
|

`hx_lvar_mapping_insert`
|

`hx_lvar_mapping_erase`
|

`hx_lvar_mapping_clear`
|

`hx_lvar_mapping_size`
|

`hx_lvar_mapping_free`
|

`hx_lvar_mapping_new`
|

`hx_udcall_map_begin`
|

`hx_udcall_map_end`
|

`hx_udcall_map_next`
|

`hx_udcall_map_prev`
|

`hx_udcall_map_first`
|

`hx_udcall_map_second`
|

`hx_udcall_map_find`
|

`hx_udcall_map_insert`
|

`hx_udcall_map_erase`
|

`hx_udcall_map_clear`
|

`hx_udcall_map_size`
|

`hx_udcall_map_free`
|

`hx_udcall_map_new`
|

`hx_user_cmts_begin`
|

`hx_user_cmts_end`
|

`hx_user_cmts_next`
|

`hx_user_cmts_prev`
|

`hx_user_cmts_first`
|

`hx_user_cmts_second`
|

`hx_user_cmts_find`
|

`hx_user_cmts_insert`
|

`hx_user_cmts_erase`
|

`hx_user_cmts_clear`
|

`hx_user_cmts_size`
|

`hx_user_cmts_free`
|

`hx_user_cmts_new`
|

`hx_user_iflags_begin`
|

`hx_user_iflags_end`
|

`hx_user_iflags_next`
|

`hx_user_iflags_prev`
|

`hx_user_iflags_first`
|

`hx_user_iflags_second`
|

`hx_user_iflags_find`
|

`hx_user_iflags_insert`
|

`hx_user_iflags_erase`
|

`hx_user_iflags_clear`
|

`hx_user_iflags_size`
|

`hx_user_iflags_free`
|

`hx_user_iflags_new`
|

`hx_user_unions_begin`
|

`hx_user_unions_end`
|

`hx_user_unions_next`
|

`hx_user_unions_prev`
|

`hx_user_unions_first`
|

`hx_user_unions_second`
|

`hx_user_unions_find`
|

`hx_user_unions_insert`
|

`hx_user_unions_erase`
|

`hx_user_unions_clear`
|

`hx_user_unions_size`
|

`hx_user_unions_free`
|

`hx_user_unions_new`
|

`hx_user_labels_begin`
|

`hx_user_labels_end`
|

`hx_user_labels_next`
|

`hx_user_labels_prev`
|

`hx_user_labels_first`
|

`hx_user_labels_second`
|

`hx_user_labels_find`
|

`hx_user_labels_insert`
|

`hx_user_labels_erase`
|

`hx_user_labels_clear`
|

`hx_user_labels_size`
|

`hx_user_labels_free`
|

`hx_user_labels_new`
|

`hx_eamap_begin`
|

`hx_eamap_end`
|

`hx_eamap_next`
|

`hx_eamap_prev`
|

`hx_eamap_first`
|

`hx_eamap_second`
|

`hx_eamap_find`
|

`hx_eamap_insert`
|

`hx_eamap_erase`
|

`hx_eamap_clear`
|

`hx_eamap_size`
|

`hx_eamap_free`
|

`hx_eamap_new`
|

`hx_boundaries_begin`
|

`hx_boundaries_end`
|

`hx_boundaries_next`
|

`hx_boundaries_prev`
|

`hx_boundaries_first`
|

`hx_boundaries_second`
|

`hx_boundaries_find`
|

`hx_boundaries_insert`
|

`hx_boundaries_erase`
|

`hx_boundaries_clear`
|

`hx_boundaries_size`
|

`hx_boundaries_free`
|

`hx_boundaries_new`
|

`hx_block_chains_begin`
|

`hx_block_chains_end`
|

`hx_block_chains_next`
|

`hx_block_chains_prev`
|

`hx_block_chains_get`
|

`hx_block_chains_find`
|

`hx_block_chains_insert`
|

`hx_block_chains_erase`
|

`hx_block_chains_clear`
|

`hx_block_chains_size`
|

`hx_block_chains_free`
|

`hx_block_chains_new`
|

`hx_hexrays_alloc`
|

`hx_hexrays_free`
|

`hx_valrng_t_clear`
|

`hx_valrng_t_copy`
|

`hx_valrng_t_assign`
|

`hx_valrng_t_compare`
|

`hx_valrng_t_set_eq`
|

`hx_valrng_t_set_cmp`
|

`hx_valrng_t_reduce_size`
|

`hx_valrng_t_intersect_with`
|

`hx_valrng_t_unite_with`
|

`hx_valrng_t_inverse`
|

`hx_valrng_t_has`
|

`hx_valrng_t_print`
|

`hx_valrng_t_dstr`
|

`hx_valrng_t_cvt_to_single_value`
|

`hx_valrng_t_cvt_to_cmp`
|

`hx_get_merror_desc`
|

`hx_must_mcode_close_block`
|

`hx_is_mcode_propagatable`
|

`hx_negate_mcode_relation`
|

`hx_swap_mcode_relation`
|

`hx_get_signed_mcode`
|

`hx_get_unsigned_mcode`
|

`hx_mcode_modifies_d`
|

`hx_operand_locator_t_compare`
|

`hx_vd_printer_t_print`
|

`hx_file_printer_t_print`
|

`hx_qstring_printer_t_print`
|

`hx_dstr`
|

`hx_is_type_correct`
|

`hx_is_small_udt`
|

`hx_is_nonbool_type`
|

`hx_is_bool_type`
|

`hx_partial_type_num`
|

`hx_get_float_type`
|

`hx_get_int_type_by_width_and_sign`
|

`hx_get_unk_type`
|

`hx_dummy_ptrtype`
|

`hx_get_member_type`
|

`hx_make_pointer`
|

`hx_create_typedef`
|

`hx_get_type`
|

`hx_set_type`
|

`hx_vdloc_t_dstr`
|

`hx_vdloc_t_compare`
|

`hx_vdloc_t_is_aliasable`
|

`hx_print_vdloc`
|

`hx_arglocs_overlap`
|

`hx_lvar_locator_t_compare`
|

`hx_lvar_locator_t_dstr`
|

`hx_lvar_t_dstr`
|

`hx_lvar_t_is_promoted_arg`
|

`hx_lvar_t_accepts_type`
|

`hx_lvar_t_set_lvar_type`
|

`hx_lvar_t_set_width`
|

`hx_lvar_t_append_list`
|

`hx_lvar_t_append_list_`
|

`hx_lvars_t_find_stkvar`
|

`hx_lvars_t_find`
|

`hx_lvars_t_find_lvar`
|

`hx_restore_user_lvar_settings`
|

`hx_save_user_lvar_settings`
|

`hx_modify_user_lvars`
|

`hx_modify_user_lvar_info`
|

`hx_locate_lvar`
|

`hx_restore_user_defined_calls`
|

`hx_save_user_defined_calls`
|

`hx_parse_user_call`
|

`hx_convert_to_user_call`
|

`hx_install_microcode_filter`
|

`hx_udc_filter_t_cleanup`
|

`hx_udc_filter_t_init`
|

`hx_udc_filter_t_apply`
|

`hx_bitset_t_bitset_t`
|

`hx_bitset_t_copy`
|

`hx_bitset_t_add`
|

`hx_bitset_t_add_`
|

`hx_bitset_t_add__`
|

`hx_bitset_t_sub`
|

`hx_bitset_t_sub_`
|

`hx_bitset_t_sub__`
|

`hx_bitset_t_cut_at`
|

`hx_bitset_t_shift_down`
|

`hx_bitset_t_has`
|

`hx_bitset_t_has_all`
|

`hx_bitset_t_has_any`
|

`hx_bitset_t_dstr`
|

`hx_bitset_t_empty`
|

`hx_bitset_t_count`
|

`hx_bitset_t_count_`
|

`hx_bitset_t_last`
|

`hx_bitset_t_fill_with_ones`
|

`hx_bitset_t_fill_gaps`
|

`hx_bitset_t_has_common`
|

`hx_bitset_t_intersect`
|

`hx_bitset_t_is_subset_of`
|

`hx_bitset_t_compare`
|

`hx_bitset_t_goup`
|

`hx_ivl_t_dstr`
|

`hx_ivl_t_compare`
|

`hx_ivlset_t_add`
|

`hx_ivlset_t_add_`
|

`hx_ivlset_t_addmasked`
|

`hx_ivlset_t_sub`
|

`hx_ivlset_t_sub_`
|

`hx_ivlset_t_has_common`
|

`hx_ivlset_t_print`
|

`hx_ivlset_t_dstr`
|

`hx_ivlset_t_count`
|

`hx_ivlset_t_has_common_`
|

`hx_ivlset_t_contains`
|

`hx_ivlset_t_includes`
|

`hx_ivlset_t_intersect`
|

`hx_ivlset_t_compare`
|

`hx_rlist_t_print`
|

`hx_rlist_t_dstr`
|

`hx_mlist_t_addmem`
|

`hx_mlist_t_print`
|

`hx_mlist_t_dstr`
|

`hx_mlist_t_compare`
|

`hx_get_temp_regs`
|

`hx_is_kreg`
|

`hx_reg2mreg`
|

`hx_mreg2reg`
|

`hx_get_mreg_name`
|

`hx_install_optinsn_handler`
|

`hx_remove_optinsn_handler`
|

`hx_install_optblock_handler`
|

`hx_remove_optblock_handler`
|

`hx_simple_graph_t_compute_dominators`
|

`hx_simple_graph_t_compute_immediate_dominators`
|

`hx_simple_graph_t_depth_first_preorder`
|

`hx_simple_graph_t_depth_first_postorder`
|

`hx_simple_graph_t_goup`
|

`hx_mutable_graph_t_resize`
|

`hx_mutable_graph_t_goup`
|

`hx_mutable_graph_t_del_edge`
|

`hx_lvar_ref_t_compare`
|

`hx_lvar_ref_t_var`
|

`hx_stkvar_ref_t_compare`
|

`hx_stkvar_ref_t_get_stkvar`
|

`hx_fnumber_t_print`
|

`hx_fnumber_t_dstr`
|

`hx_mop_t_copy`
|

`hx_mop_t_assign`
|

`hx_mop_t_swap`
|

`hx_mop_t_erase`
|

`hx_mop_t_print`
|

`hx_mop_t_dstr`
|

`hx_mop_t_create_from_mlist`
|

`hx_mop_t_create_from_ivlset`
|

`hx_mop_t_create_from_vdloc`
|

`hx_mop_t_create_from_scattered_vdloc`
|

`hx_mop_t_create_from_insn`
|

`hx_mop_t_make_number`
|

`hx_mop_t_make_fpnum`
|

`hx_mop_t__make_gvar`
|

`hx_mop_t_make_gvar`
|

`hx_mop_t_make_reg_pair`
|

`hx_mop_t_make_helper`
|

`hx_mop_t_is_bit_reg`
|

`hx_mop_t_may_use_aliased_memory`
|

`hx_mop_t_is01`
|

`hx_mop_t_is_sign_extended_from`
|

`hx_mop_t_is_zero_extended_from`
|

`hx_mop_t_equal_mops`
|

`hx_mop_t_lexcompare`
|

`hx_mop_t_for_all_ops`
|

`hx_mop_t_for_all_scattered_submops`
|

`hx_mop_t_is_constant`
|

`hx_mop_t_get_stkoff`
|

`hx_mop_t_make_low_half`
|

`hx_mop_t_make_high_half`
|

`hx_mop_t_make_first_half`
|

`hx_mop_t_make_second_half`
|

`hx_mop_t_shift_mop`
|

`hx_mop_t_change_size`
|

`hx_mop_t_preserve_side_effects`
|

`hx_mop_t_apply_ld_mcode`
|

`hx_mcallarg_t_print`
|

`hx_mcallarg_t_dstr`
|

`hx_mcallarg_t_set_regarg`
|

`hx_mcallinfo_t_lexcompare`
|

`hx_mcallinfo_t_set_type`
|

`hx_mcallinfo_t_get_type`
|

`hx_mcallinfo_t_print`
|

`hx_mcallinfo_t_dstr`
|

`hx_mcases_t_compare`
|

`hx_mcases_t_print`
|

`hx_mcases_t_dstr`
|

`hx_vivl_t_extend_to_cover`
|

`hx_vivl_t_intersect`
|

`hx_vivl_t_print`
|

`hx_vivl_t_dstr`
|

`hx_chain_t_print`
|

`hx_chain_t_dstr`
|

`hx_chain_t_append_list`
|

`hx_chain_t_append_list_`
|

`hx_block_chains_t_get_chain`
|

`hx_block_chains_t_print`
|

`hx_block_chains_t_dstr`
|

`hx_graph_chains_t_for_all_chains`
|

`hx_graph_chains_t_release`
|

`hx_minsn_t_init`
|

`hx_minsn_t_copy`
|

`hx_minsn_t_set_combined`
|

`hx_minsn_t_swap`
|

`hx_minsn_t_print`
|

`hx_minsn_t_dstr`
|

`hx_minsn_t_setaddr`
|

`hx_minsn_t_optimize_subtree`
|

`hx_minsn_t_for_all_ops`
|

`hx_minsn_t_for_all_insns`
|

`hx_minsn_t__make_nop`
|

`hx_minsn_t_equal_insns`
|

`hx_minsn_t_lexcompare`
|

`hx_minsn_t_is_noret_call`
|

`hx_minsn_t_is_helper`
|

`hx_minsn_t_find_call`
|

`hx_minsn_t_has_side_effects`
|

`hx_minsn_t_find_opcode`
|

`hx_minsn_t_find_ins_op`
|

`hx_minsn_t_find_num_op`
|

`hx_minsn_t_modifies_d`
|

`hx_minsn_t_is_between`
|

`hx_minsn_t_may_use_aliased_memory`
|

`hx_minsn_t_serialize`
|

`hx_minsn_t_deserialize`
|

`hx_getf_reginsn`
|

`hx_getb_reginsn`
|

`hx_mblock_t_init`
|

`hx_mblock_t_print`
|

`hx_mblock_t_dump`
|

`hx_mblock_t_vdump_block`
|

`hx_mblock_t_insert_into_block`
|

`hx_mblock_t_remove_from_block`
|

`hx_mblock_t_for_all_insns`
|

`hx_mblock_t_for_all_ops`
|

`hx_mblock_t_for_all_uses`
|

`hx_mblock_t_optimize_insn`
|

`hx_mblock_t_optimize_block`
|

`hx_mblock_t_build_lists`
|

`hx_mblock_t_optimize_useless_jump`
|

`hx_mblock_t_append_use_list`
|

`hx_mblock_t_append_def_list`
|

`hx_mblock_t_build_use_list`
|

`hx_mblock_t_build_def_list`
|

`hx_mblock_t_find_first_use`
|

`hx_mblock_t_find_redefinition`
|

`hx_mblock_t_is_rhs_redefined`
|

`hx_mblock_t_find_access`
|

`hx_mblock_t_get_valranges`
|

`hx_mblock_t_get_valranges_`
|

`hx_mblock_t_get_reginsn_qty`
|

`hx_mba_ranges_t_range_contains`
|

`hx_mba_t_stkoff_vd2ida`
|

`hx_mba_t_stkoff_ida2vd`
|

`hx_mba_t_idaloc2vd`
|

`hx_mba_t_idaloc2vd_`
|

`hx_mba_t_vd2idaloc`
|

`hx_mba_t_vd2idaloc_`
|

`hx_mba_t_term`
|

`hx_mba_t_get_curfunc`
|

`hx_mba_t_set_maturity`
|

`hx_mba_t_optimize_local`
|

`hx_mba_t_build_graph`
|

`hx_mba_t_get_graph`
|

`hx_mba_t_analyze_calls`
|

`hx_mba_t_optimize_global`
|

`hx_mba_t_alloc_lvars`
|

`hx_mba_t_dump`
|

`hx_mba_t_vdump_mba`
|

`hx_mba_t_print`
|

`hx_mba_t_verify`
|

`hx_mba_t_mark_chains_dirty`
|

`hx_mba_t_insert_block`
|

`hx_mba_t_remove_block`
|

`hx_mba_t_copy_block`
|

`hx_mba_t_remove_empty_and_unreachable_blocks`
|

`hx_mba_t_merge_blocks`
|

`hx_mba_t_for_all_ops`
|

`hx_mba_t_for_all_insns`
|

`hx_mba_t_for_all_topinsns`
|

`hx_mba_t_find_mop`
|

`hx_mba_t_create_helper_call`
|

`hx_mba_t_get_func_output_lists`
|

`hx_mba_t_arg`
|

`hx_mba_t_alloc_fict_ea`
|

`hx_mba_t_map_fict_ea`
|

`hx_mba_t_serialize`
|

`hx_mba_t_deserialize`
|

`hx_mba_t_save_snapshot`
|

`hx_mba_t_alloc_kreg`
|

`hx_mba_t_free_kreg`
|

`hx_mba_t_inline_func`
|

`hx_mba_t_locate_stkpnt`
|

`hx_mba_t_set_lvar_name`
|

`hx_mbl_graph_t_is_accessed_globally`
|

`hx_mbl_graph_t_get_ud`
|

`hx_mbl_graph_t_get_du`
|

`hx_cdg_insn_iterator_t_next`
|

`hx_codegen_t_clear`
|

`hx_codegen_t_emit`
|

`hx_codegen_t_emit_`
|

`hx_change_hexrays_config`
|

`hx_get_hexrays_version`
|

`hx_open_pseudocode`
|

`hx_close_pseudocode`
|

`hx_get_widget_vdui`
|

`hx_decompile_many`
|

`hx_hexrays_failure_t_desc`
|

`hx_send_database`
|

`hx_gco_info_t_append_to_list`
|

`hx_get_current_operand`
|

`hx_remitem`
|

`hx_negated_relation`
|

`hx_swapped_relation`
|

`hx_get_op_signness`
|

`hx_asgop`
|

`hx_asgop_revert`
|

`hx_cnumber_t_print`
|

`hx_cnumber_t_value`
|

`hx_cnumber_t_assign`
|

`hx_cnumber_t_compare`
|

`hx_var_ref_t_compare`
|

`hx_ctree_visitor_t_apply_to`
|

`hx_ctree_visitor_t_apply_to_exprs`
|

`hx_ctree_parentee_t_recalc_parent_types`
|

`hx_cfunc_parentee_t_calc_rvalue_type`
|

`hx_citem_locator_t_compare`
|

`hx_citem_t_contains_expr`
|

`hx_citem_t_contains_label`
|

`hx_citem_t_find_parent_of`
|

`hx_citem_t_find_closest_addr`
|

`hx_cexpr_t_assign`
|

`hx_cexpr_t_compare`
|

`hx_cexpr_t_replace_by`
|

`hx_cexpr_t_cleanup`
|

`hx_cexpr_t_put_number`
|

`hx_cexpr_t_print1`
|

`hx_cexpr_t_calc_type`
|

`hx_cexpr_t_equal_effect`
|

`hx_cexpr_t_is_child_of`
|

`hx_cexpr_t_contains_operator`
|

`hx_cexpr_t_get_high_nbit_bound`
|

`hx_cexpr_t_get_low_nbit_bound`
|

`hx_cexpr_t_requires_lvalue`
|

`hx_cexpr_t_has_side_effects`
|

`hx_cexpr_t_maybe_ptr`
|

`hx_cexpr_t_dstr`
|

`hx_cif_t_assign`
|

`hx_cif_t_compare`
|

`hx_cloop_t_assign`
|

`hx_cfor_t_compare`
|

`hx_cwhile_t_compare`
|

`hx_cdo_t_compare`
|

`hx_creturn_t_compare`
|

`hx_cthrow_t_compare`
|

`hx_cgoto_t_compare`
|

`hx_casm_t_compare`
|

`hx_cinsn_t_assign`
|

`hx_cinsn_t_compare`
|

`hx_cinsn_t_replace_by`
|

`hx_cinsn_t_cleanup`
|

`hx_cinsn_t_new_insn`
|

`hx_cinsn_t_create_if`
|

`hx_cinsn_t_print`
|

`hx_cinsn_t_print1`
|

`hx_cinsn_t_is_ordinary_flow`
|

`hx_cinsn_t_contains_insn`
|

`hx_cinsn_t_collect_free_breaks`
|

`hx_cinsn_t_collect_free_continues`
|

`hx_cinsn_t_dstr`
|

`hx_cblock_t_compare`
|

`hx_carglist_t_compare`
|

`hx_ccase_t_compare`
|

`hx_ccases_t_compare`
|

`hx_cswitch_t_compare`
|

`hx_ccatch_t_compare`
|

`hx_ctry_t_compare`
|

`hx_ctree_item_t_get_udm`
|

`hx_ctree_item_t_get_edm`
|

`hx_ctree_item_t_get_lvar`
|

`hx_ctree_item_t_get_ea`
|

`hx_ctree_item_t_get_label_num`
|

`hx_ctree_item_t_print`
|

`hx_ctree_item_t_dstr`
|

`hx_lnot`
|

`hx_new_block`
|

`hx_vcreate_helper`
|

`hx_vcall_helper`
|

`hx_make_num`
|

`hx_make_ref`
|

`hx_dereference`
|

`hx_save_user_labels`
|

`hx_save_user_cmts`
|

`hx_save_user_numforms`
|

`hx_save_user_iflags`
|

`hx_save_user_unions`
|

`hx_restore_user_labels`
|

`hx_restore_user_cmts`
|

`hx_restore_user_numforms`
|

`hx_restore_user_iflags`
|

`hx_restore_user_unions`
|

`hx_cfunc_t_build_c_tree`
|

`hx_cfunc_t_verify`
|

`hx_cfunc_t_print_dcl`
|

`hx_cfunc_t_print_func`
|

`hx_cfunc_t_get_func_type`
|

`hx_cfunc_t_get_lvars`
|

`hx_cfunc_t_get_stkoff_delta`
|

`hx_cfunc_t_find_label`
|

`hx_cfunc_t_remove_unused_labels`
|

`hx_cfunc_t_get_user_cmt`
|

`hx_cfunc_t_set_user_cmt`
|

`hx_cfunc_t_get_user_iflags`
|

`hx_cfunc_t_set_user_iflags`
|

`hx_cfunc_t_has_orphan_cmts`
|

`hx_cfunc_t_del_orphan_cmts`
|

`hx_cfunc_t_get_user_union_selection`
|

`hx_cfunc_t_set_user_union_selection`
|

`hx_cfunc_t_save_user_labels`
|

`hx_cfunc_t_save_user_cmts`
|

`hx_cfunc_t_save_user_numforms`
|

`hx_cfunc_t_save_user_iflags`
|

`hx_cfunc_t_save_user_unions`
|

`hx_cfunc_t_get_line_item`
|

`hx_cfunc_t_get_warnings`
|

`hx_cfunc_t_get_eamap`
|

`hx_cfunc_t_get_boundaries`
|

`hx_cfunc_t_get_pseudocode`
|

`hx_cfunc_t_refresh_func_ctext`
|

`hx_cfunc_t_gather_derefs`
|

`hx_cfunc_t_find_item_coords`
|

`hx_cfunc_t_cleanup`
|

`hx_close_hexrays_waitbox`
|

`hx_decompile`
|

`hx_gen_microcode`
|

`hx_create_cfunc`
|

`hx_mark_cfunc_dirty`
|

`hx_clear_cached_cfuncs`
|

`hx_has_cached_cfunc`
|

`hx_get_ctype_name`
|

`hx_create_field_name`
|

`hx_install_hexrays_callback`
|

`hx_remove_hexrays_callback`
|

`hx_vdui_t_set_locked`
|

`hx_vdui_t_refresh_view`
|

`hx_vdui_t_refresh_ctext`
|

`hx_vdui_t_switch_to`
|

`hx_vdui_t_get_number`
|

`hx_vdui_t_get_current_label`
|

`hx_vdui_t_clear`
|

`hx_vdui_t_refresh_cpos`
|

`hx_vdui_t_get_current_item`
|

`hx_vdui_t_ui_rename_lvar`
|

`hx_vdui_t_rename_lvar`
|

`hx_vdui_t_ui_set_call_type`
|

`hx_vdui_t_ui_set_lvar_type`
|

`hx_vdui_t_set_lvar_type`
|

`hx_vdui_t_set_noptr_lvar`
|

`hx_vdui_t_ui_edit_lvar_cmt`
|

`hx_vdui_t_set_lvar_cmt`
|

`hx_vdui_t_ui_map_lvar`
|

`hx_vdui_t_ui_unmap_lvar`
|

`hx_vdui_t_map_lvar`
|

`hx_vdui_t_set_udm_type`
|

`hx_vdui_t_rename_udm`
|

`hx_vdui_t_set_global_type`
|

`hx_vdui_t_rename_global`
|

`hx_vdui_t_rename_label`
|

`hx_vdui_t_jump_enter`
|

`hx_vdui_t_ctree_to_disasm`
|

`hx_vdui_t_calc_cmt_type`
|

`hx_vdui_t_edit_cmt`
|

`hx_vdui_t_edit_func_cmt`
|

`hx_vdui_t_del_orphan_cmts`
|

`hx_vdui_t_set_num_radix`
|

`hx_vdui_t_set_num_enum`
|

`hx_vdui_t_set_num_stroff`
|

`hx_vdui_t_invert_sign`
|

`hx_vdui_t_invert_bits`
|

`hx_vdui_t_collapse_item`
|

`hx_vdui_t_collapse_lvars`
|

`hx_vdui_t_split_item`
|

`hx_select_udt_by_offset`
|

`hx_catchexpr_t_compare`
|

`hx_mba_t_split_block`
|

`hx_mba_t_remove_blocks`
|

`hx_cfunc_t_recalc_item_addresses`
|

`hx_obsolete_int64_emulator_t_mop_value`
|

`hx_obsolete_int64_emulator_t_minsn_value`
|

`hx_int64_emulator_t__mop_value`
|

`hx_int64_emulator_t__minsn_value`
|

`hx_cfunc_t_serialize`
|

`hx_cfunc_t_deserialize`
|

`hx_mblock_t_verify_insn`
|

`hx_vdui_t_ui_noprop_lvar`
|

`is_small_struni`
|

`mbl_array_t`
|

`is_allowed_on_small_struni`
|

## Exceptions

`DecompilationFailure`
|
Common base class for all non-exit exceptions.

## Classes

`hexwarns_t`
|

`user_numforms_t`
|

`ctree_items_t`
|

`user_labels_t`
|

`user_unions_t`
|

`user_cmts_t`
|

`user_iflags_t`
|

`cinsnptrvec_t`
|

`eamap_t`
|

`boundaries_t`
|

`cfuncptr_t`
|

`qvector_history_t`
|

`history_t`
|

`cinsn_list_t_iterator`
|

`cinsn_list_t`
|

`qvector_carg_t`
|

`qvector_ccase_t`
|

`qvector_catchexprs_t`
|

`qvector_ccatchvec_t`
|

`cblock_posvec_t`
|

`ui_stroff_ops_t`
|

`array_of_bitsets`
|

`mopvec_t`
|

`mcallargs_t`
|

`block_chains_vec_t`
|

`lvar_mapping_t`
|

`qvector_lvar_t`
|

`lvar_saved_infos_t`
|

`Hexrays_Hooks`
|

`valrng_t`
|

`hexrays_failure_t`
|

`vd_failure_t`
|

`vd_interr_t`
|

`operand_locator_t`
|

`number_format_t`
|

`vd_printer_t`
|

`vc_printer_t`
|

`qstring_printer_t`
|

`vdloc_t`
|

`lvar_locator_t`
|

`lvar_t`
|

`lvars_t`
|

`lvar_saved_info_t`
|

`lvar_uservec_t`
|

`user_lvar_modifier_t`
|

`udcall_t`
|

`microcode_filter_t`
|

`udc_filter_t`
|

`bitset_t`
|

`iterator`
|

`node_bitset_t`
|

`array_of_node_bitset_t`
|

`ivl_t`
|

`ivl_with_name_t`
|

`ivlset_visitor_t`
|

`ivlset_t`
|

`rlist_t`
|

`mlist_t`
|

`optinsn_t`
|

`optblock_t`
|

`simple_graph_t`
|

`op_parent_info_t`
|

`minsn_visitor_t`
|

`mop_visitor_t`
|

`scif_visitor_t`
|

`mlist_mop_visitor_t`
|

`lvar_ref_t`
|

`stkvar_ref_t`
|

`scif_t`
|

`mnumber_t`
|

`fnumber_t`
|

`mop_t`
|

`mop_pair_t`
|

`mop_addr_t`
|

`mcallarg_t`
|

`mcallinfo_t`
|

`mcases_t`
|

`voff_t`
|

`vivl_t`
|

`chain_t`
|

`block_chains_t`
|

`chain_visitor_t`
|

`graph_chains_t`
|

`minsn_t`
|

`intval64_t`
|

`int64_emulator_t`
|

`mblock_t`
|

`hexwarn_t`
|

`mba_ranges_t`
|

`mba_range_iterator_t`
|

`mba_t`
|

`chain_keeper_t`
|

`mbl_graph_t`
|

`cdg_insn_iterator_t`
|

`codegen_t`
|

`gco_info_t`
|

`cnumber_t`
|

`var_ref_t`
|

`treeloc_t`
|

`citem_cmt_t`
|

`citem_locator_t`
|

`bit_bound_t`
|

`citem_t`
|

`cexpr_t`
|

`ceinsn_t`
|

`cif_t`
|

`cloop_t`
|

`cfor_t`
|

`cwhile_t`
|

`cdo_t`
|

`creturn_t`
|

`cgoto_t`
|

`casm_t`
|

`cinsn_t`
|

`cblock_t`
|

`carg_t`
|

`carglist_t`
|

`ccase_t`
|

`ccases_t`
|

`cswitch_t`
|

`catchexpr_t`
|

`ccatch_t`
|

`ctry_t`
|

`cthrow_t`
|

`cblock_pos_t`
|

`ctree_visitor_t`
|

`ctree_parentee_t`
|

`cfunc_parentee_t`
|

`ctree_anchor_t`
|

`ctree_item_t`
|

`cfunc_t`
|

`ctext_position_t`
|

`history_item_t`
|

`vdui_t`
|

`ui_stroff_op_t`
|

`ui_stroff_applicator_t`
|

`user_numforms_iterator_t`
|

`lvar_mapping_iterator_t`
|

`udcall_map_iterator_t`
|

`user_cmts_iterator_t`
|

`user_iflags_iterator_t`
|

`user_unions_iterator_t`
|

`user_labels_iterator_t`
|

`eamap_iterator_t`
|

`boundaries_iterator_t`
|

`block_chains_iterator_t`
|

`array_of_ivlsets`
|

## Functions

`get_widget_vdui`(→ vdui_t *)
|
Get the vdui_t instance associated to the TWidget

`init_hexrays_plugin`(→ bool)
|
Check that your plugin is compatible with hex-rays decompiler. This function must be called before calling any other decompiler function.

`boundaries_find`(→ boundaries_iterator_t)
|
Find the specified key in boundaries_t.

`boundaries_insert`(→ boundaries_iterator_t)
|
Insert new (cinsn_t *, rangeset_t) pair into boundaries_t.

`term_hexrays_plugin`(→ None)
|
Stop working with hex-rays decompiler.

`debug_hexrays_ctree`(→ None)
|

`qswap`(→ None)
|

`hexrays_alloc`(→ void *)
|

`hexrays_free`(→ None)
|

`max_vlr_value`(→ uvlr_t)
|

`min_vlr_svalue`(→ uvlr_t)
|

`max_vlr_svalue`(→ uvlr_t)
|

`is_unsigned_cmpop`(→ bool)
|

`is_signed_cmpop`(→ bool)
|

`is_cmpop_with_eq`(→ bool)
|

`is_cmpop_without_eq`(→ bool)
|

`is_may_access`(→ bool)
|

`get_merror_desc`(→ str)
|
Get textual description of an error code

`must_mcode_close_block`(→ bool)
|
Must an instruction with the given opcode be the last one in a block? Such opcodes are called closing opcodes.

`is_mcode_propagatable`(→ bool)
|
May opcode be propagated? Such opcodes can be used in sub-instructions (nested instructions) There is a handful of non-propagatable opcodes, like jumps, ret, nop, etc All other regular opcodes are propagatable and may appear in a nested instruction.

`is_mcode_addsub`(→ bool)
|

`is_mcode_xdsu`(→ bool)
|

`is_mcode_set`(→ bool)
|

`is_mcode_set1`(→ bool)
|

`is_mcode_j1`(→ bool)
|

`is_mcode_jcond`(→ bool)
|

`is_mcode_convertible_to_jmp`(→ bool)
|

`is_mcode_convertible_to_set`(→ bool)
|

`is_mcode_call`(→ bool)
|

`is_mcode_fpu`(→ bool)
|

`is_mcode_commutative`(→ bool)
|

`is_mcode_shift`(→ bool)
|

`is_mcode_divmod`(→ bool)
|

`has_mcode_seloff`(→ bool)
|

`set2jcnd`(→ mcode_t)
|

`jcnd2set`(→ mcode_t)
|

`negate_mcode_relation`(→ mcode_t)
|

`swap_mcode_relation`(→ mcode_t)
|

`get_signed_mcode`(→ mcode_t)
|

`get_unsigned_mcode`(→ mcode_t)
|

`is_signed_mcode`(→ bool)
|

`is_unsigned_mcode`(→ bool)
|

`mcode_modifies_d`(→ bool)
|

`dstr`(→ str)
|
Print the specified type info. This function can be used from a debugger by typing "tif->dstr()"

`is_type_correct`(→ bool)
|
Verify a type string.

`is_small_udt`(→ bool)
|
Is a small structure or union?

`is_nonbool_type`(→ bool)
|
Is definitely a non-boolean type?

`is_bool_type`(→ bool)
|
Is a boolean type?

`is_ptr_or_array`(→ bool)
|
Is a pointer or array type?

`is_paf`(→ bool)
|
Is a pointer, array, or function type?

`is_inplace_def`(→ bool)
|
Is struct/union/enum definition (not declaration)?

`partial_type_num`(→ int)
|
Calculate number of partial subtypes.

`get_float_type`(→ tinfo_t)
|
Get a type of a floating point value with the specified width

`get_int_type_by_width_and_sign`(→ tinfo_t)
|
Create a type info by width and sign. Returns a simple type (examples: int, short) with the given width and sign.

`get_unk_type`(→ tinfo_t)
|
Create a partial type info by width. Returns a partially defined type (examples: _DWORD, _BYTE) with the given width.

`dummy_ptrtype`(→ tinfo_t)
|
Generate a dummy pointer type

`make_pointer`(→ tinfo_t)
|
Create a pointer type. This function performs the following conversion: "type" -> "type*"

`create_typedef`(→ tinfo_t)
|
This function has the following signatures:

`get_type`(→ bool)
|
Get a global type. Global types are types of addressable objects and struct/union/enum types

`set_type`(→ bool)
|
Set a global type.

`print_vdloc`(→ str)
|
Print vdloc. Since vdloc does not always carry the size info, we pass it as NBYTES..

`arglocs_overlap`(→ bool)
|
Do two arglocs overlap?

`restore_user_lvar_settings`(→ bool)
|
Restore user defined local variable settings in the database.

`save_user_lvar_settings`(→ None)
|
Save user defined local variable settings into the database.

`modify_user_lvars`(→ bool)
|
Modify saved local variable settings.

`modify_user_lvar_info`(→ bool)
|
Modify saved local variable settings of one variable.

`locate_lvar`(→ bool)
|
Find a variable by name.

`rename_lvar`(→ bool)
|
Rename a local variable.

`restore_user_defined_calls`(→ bool)
|
Restore user defined function calls from the database.

`save_user_defined_calls`(→ None)
|
Save user defined local function calls into the database.

`parse_user_call`(→ bool)
|
Convert function type declaration into internal structure

`convert_to_user_call`(→ merror_t)
|
try to generate user-defined call for an instruction

`install_microcode_filter`(→ bool)
|
register/unregister non-standard microcode generator

`get_temp_regs`(→ mlist_t const &)
|
Get list of temporary registers. Tempregs are temporary registers that are used during code generation. They do not map to regular processor registers. They are used only to store temporary values during execution of one instruction. Tempregs may not be used to pass a value from one block to another. In other words, at the end of a block all tempregs must be dead.

`is_kreg`(→ bool)
|
Is a kernel register? Kernel registers are temporary registers that can be used freely. They may be used to store values that cross instruction or basic block boundaries. Kernel registers do not map to regular processor registers. See also mba_t::alloc_kreg()

`reg2mreg`(→ mreg_t)
|
Map a processor register to a microregister.

`mreg2reg`(→ int)
|
Map a microregister to a processor register.

`get_mreg_name`(→ str)
|
Get the microregister name.

`lexcompare`(→ int)
|

`getf_reginsn`(→ minsn_t *)
|
Skip assertions forward.

`getb_reginsn`(→ minsn_t *)
|
Skip assertions backward.

`change_hexrays_config`(→ bool)
|
Parse DIRECTIVE and update the current configuration variables. For the syntax see hexrays.cfg

`get_hexrays_version`(→ str)
|
Get decompiler version. The returned string is of the form ...

`open_pseudocode`(→ vdui_t *)
|
Open pseudocode window. The specified function is decompiled and the pseudocode window is opened.

`close_pseudocode`(→ bool)
|
Close pseudocode window.

`decompile_many`(→ bool)
|
Batch decompilation. Decompile all or the specified functions

`send_database`(→ None)
|
Send the database to Hex-Rays. This function sends the current database to the Hex-Rays server. The database is sent in the compressed form over an encrypted (SSL) connection.

`get_current_operand`(→ bool)
|
Get the instruction operand under the cursor. This function determines the operand that is under the cursor in the active disassembly listing. If the operand refers to a register or stack variable, it returns true.

`remitem`(→ None)
|

`negated_relation`(→ ctype_t)
|
Negate a comparison operator. For example, cot_sge becomes cot_slt.

`swapped_relation`(→ ctype_t)
|
Swap a comparison operator. For example, cot_sge becomes cot_sle.

`get_op_signness`(→ type_sign_t)
|
Get operator sign. Meaningful for sign-dependent operators, like cot_sdiv.

`asgop`(→ ctype_t)
|
Convert plain operator into assignment operator. For example, cot_add returns cot_asgadd.

`asgop_revert`(→ ctype_t)
|
Convert assignment operator into plain operator. For example, cot_asgadd returns cot_add

`op_uses_x`(→ bool)
|
Does operator use the 'x' field of cexpr_t?

`op_uses_y`(→ bool)
|
Does operator use the 'y' field of cexpr_t?

`op_uses_z`(→ bool)
|
Does operator use the 'z' field of cexpr_t?

`is_binary`(→ bool)
|
Is binary operator?

`is_unary`(→ bool)
|
Is unary operator?

`is_relational`(→ bool)
|
Is comparison operator?

`is_assignment`(→ bool)
|
Is assignment operator?

`accepts_udts`(→ bool)
|

`is_prepost`(→ bool)
|
Is pre/post increment/decrement operator?

`is_commutative`(→ bool)
|
Is commutative operator?

`is_additive`(→ bool)
|
Is additive operator?

`is_multiplicative`(→ bool)
|
Is multiplicative operator?

`is_bitop`(→ bool)
|
Is bit related operator?

`is_logical`(→ bool)
|
Is logical operator?

`is_loop`(→ bool)
|
Is loop statement code?

`is_break_consumer`(→ bool)
|
Does a break statement influence the specified statement code?

`is_lvalue`(→ bool)
|
Is Lvalue operator?

`accepts_small_udts`(→ bool)
|
Is the operator allowed on small structure or union?

`save_user_labels`(→ None)
|
Save user defined labels into the database.

`save_user_cmts`(→ None)
|
Save user defined comments into the database.

`save_user_numforms`(→ None)
|
Save user defined number formats into the database.

`save_user_iflags`(→ None)
|
Save user defined citem iflags into the database.

`save_user_unions`(→ None)
|
Save user defined union field selections into the database.

`restore_user_labels`(→ user_labels_t *)
|
Restore user defined labels from the database.

`restore_user_cmts`(→ user_cmts_t *)
|
Restore user defined comments from the database.

`restore_user_numforms`(→ user_numforms_t *)
|
Restore user defined number formats from the database.

`restore_user_iflags`(→ user_iflags_t *)
|
Restore user defined citem iflags from the database.

`restore_user_unions`(→ user_unions_t *)
|
Restore user defined union field selections from the database.

`close_hexrays_waitbox`(→ None)
|
Close the waitbox displayed by the decompiler. Useful if DECOMP_NO_HIDE was used during decompilation.

`decompile`(ea[, hf, flags])
|
Decompile a snippet or a function.

`decompile_func`(→ cfuncptr_t)
|
Decompile a function. Multiple decompilations of the same function return the same object.

`gen_microcode`(→ mba_t *)
|
Generate microcode of an arbitrary code snippet

`create_empty_mba`(→ mba_t *)
|
Create an empty microcode object.

`create_cfunc`(→ cfuncptr_t)
|
Create a new cfunc_t object.

`mark_cfunc_dirty`(→ bool)
|
Flush the cached decompilation results. Erases a cache entry for the specified function.

`clear_cached_cfuncs`(→ None)
|
Flush all cached decompilation results.

`has_cached_cfunc`(→ bool)
|
Do we have a cached decompilation result for 'ea'?

`get_ctype_name`(→ str)
|

`create_field_name`(→ str)
|

`select_udt_by_offset`(→ int)
|
Select UDT

`user_numforms_first`(→ operand_locator_t const &)
|
Get reference to the current map key.

`user_numforms_second`(→ number_format_t &)
|
Get reference to the current map value.

`user_numforms_find`(→ user_numforms_iterator_t)
|
Find the specified key in user_numforms_t.

`user_numforms_insert`(→ user_numforms_iterator_t)
|
Insert new (operand_locator_t, number_format_t) pair into user_numforms_t.

`user_numforms_begin`(→ user_numforms_iterator_t)
|
Get iterator pointing to the beginning of user_numforms_t.

`user_numforms_end`(→ user_numforms_iterator_t)
|
Get iterator pointing to the end of user_numforms_t.

`user_numforms_next`(→ user_numforms_iterator_t)
|
Move to the next element.

`user_numforms_prev`(→ user_numforms_iterator_t)
|
Move to the previous element.

`user_numforms_erase`(→ None)
|
Erase current element from user_numforms_t.

`user_numforms_clear`(→ None)
|
Clear user_numforms_t.

`user_numforms_size`(→ int)
|
Get size of user_numforms_t.

`user_numforms_free`(→ None)
|
Delete user_numforms_t instance.

`user_numforms_new`(→ user_numforms_t *)
|
Create a new user_numforms_t instance.

`lvar_mapping_first`(→ lvar_locator_t const &)
|
Get reference to the current map key.

`lvar_mapping_second`(→ lvar_locator_t &)
|
Get reference to the current map value.

`lvar_mapping_find`(→ lvar_mapping_iterator_t)
|
Find the specified key in lvar_mapping_t.

`lvar_mapping_insert`(→ lvar_mapping_iterator_t)
|
Insert new (lvar_locator_t, lvar_locator_t) pair into lvar_mapping_t.

`lvar_mapping_begin`(→ lvar_mapping_iterator_t)
|
Get iterator pointing to the beginning of lvar_mapping_t.

`lvar_mapping_end`(→ lvar_mapping_iterator_t)
|
Get iterator pointing to the end of lvar_mapping_t.

`lvar_mapping_next`(→ lvar_mapping_iterator_t)
|
Move to the next element.

`lvar_mapping_prev`(→ lvar_mapping_iterator_t)
|
Move to the previous element.

`lvar_mapping_erase`(→ None)
|
Erase current element from lvar_mapping_t.

`lvar_mapping_clear`(→ None)
|
Clear lvar_mapping_t.

`lvar_mapping_size`(→ int)
|
Get size of lvar_mapping_t.

`lvar_mapping_free`(→ None)
|
Delete lvar_mapping_t instance.

`lvar_mapping_new`(→ lvar_mapping_t *)
|
Create a new lvar_mapping_t instance.

`udcall_map_first`(→ ea_t const &)
|
Get reference to the current map key.

`udcall_map_second`(→ udcall_t &)
|
Get reference to the current map value.

`udcall_map_find`(→ udcall_map_iterator_t)
|
Find the specified key in udcall_map_t.

`udcall_map_insert`(→ udcall_map_iterator_t)
|
Insert new (ea_t, udcall_t) pair into udcall_map_t.

`udcall_map_begin`(→ udcall_map_iterator_t)
|
Get iterator pointing to the beginning of udcall_map_t.

`udcall_map_end`(→ udcall_map_iterator_t)
|
Get iterator pointing to the end of udcall_map_t.

`udcall_map_next`(→ udcall_map_iterator_t)
|
Move to the next element.

`udcall_map_prev`(→ udcall_map_iterator_t)
|
Move to the previous element.

`udcall_map_erase`(→ None)
|
Erase current element from udcall_map_t.

`udcall_map_clear`(→ None)
|
Clear udcall_map_t.

`udcall_map_size`(→ int)
|
Get size of udcall_map_t.

`udcall_map_free`(→ None)
|
Delete udcall_map_t instance.

`udcall_map_new`(→ udcall_map_t *)
|
Create a new udcall_map_t instance.

`user_cmts_first`(→ treeloc_t const &)
|
Get reference to the current map key.

`user_cmts_second`(→ citem_cmt_t &)
|
Get reference to the current map value.

`user_cmts_find`(→ user_cmts_iterator_t)
|
Find the specified key in user_cmts_t.

`user_cmts_insert`(→ user_cmts_iterator_t)
|
Insert new (treeloc_t, citem_cmt_t) pair into user_cmts_t.

`user_cmts_begin`(→ user_cmts_iterator_t)
|
Get iterator pointing to the beginning of user_cmts_t.

`user_cmts_end`(→ user_cmts_iterator_t)
|
Get iterator pointing to the end of user_cmts_t.

`user_cmts_next`(→ user_cmts_iterator_t)
|
Move to the next element.

`user_cmts_prev`(→ user_cmts_iterator_t)
|
Move to the previous element.

`user_cmts_erase`(→ None)
|
Erase current element from user_cmts_t.

`user_cmts_clear`(→ None)
|
Clear user_cmts_t.

`user_cmts_size`(→ int)
|
Get size of user_cmts_t.

`user_cmts_free`(→ None)
|
Delete user_cmts_t instance.

`user_cmts_new`(→ user_cmts_t *)
|
Create a new user_cmts_t instance.

`user_iflags_first`(→ citem_locator_t const &)
|
Get reference to the current map key.

`user_iflags_second`(→ int32 &)
|
Get reference to the current map value.

`user_iflags_find`(→ user_iflags_iterator_t)
|
Find the specified key in user_iflags_t.

`user_iflags_insert`(→ user_iflags_iterator_t)
|
Insert new (citem_locator_t, int32) pair into user_iflags_t.

`user_iflags_begin`(→ user_iflags_iterator_t)
|
Get iterator pointing to the beginning of user_iflags_t.

`user_iflags_end`(→ user_iflags_iterator_t)
|
Get iterator pointing to the end of user_iflags_t.

`user_iflags_next`(→ user_iflags_iterator_t)
|
Move to the next element.

`user_iflags_prev`(→ user_iflags_iterator_t)
|
Move to the previous element.

`user_iflags_erase`(→ None)
|
Erase current element from user_iflags_t.

`user_iflags_clear`(→ None)
|
Clear user_iflags_t.

`user_iflags_size`(→ int)
|
Get size of user_iflags_t.

`user_iflags_free`(→ None)
|
Delete user_iflags_t instance.

`user_iflags_new`(→ user_iflags_t *)
|
Create a new user_iflags_t instance.

`user_unions_first`(→ ea_t const &)
|
Get reference to the current map key.

`user_unions_second`(→ intvec_t &)
|
Get reference to the current map value.

`user_unions_find`(→ user_unions_iterator_t)
|
Find the specified key in user_unions_t.

`user_unions_insert`(→ user_unions_iterator_t)
|
Insert new (ea_t, intvec_t) pair into user_unions_t.

`user_unions_begin`(→ user_unions_iterator_t)
|
Get iterator pointing to the beginning of user_unions_t.

`user_unions_end`(→ user_unions_iterator_t)
|
Get iterator pointing to the end of user_unions_t.

`user_unions_next`(→ user_unions_iterator_t)
|
Move to the next element.

`user_unions_prev`(→ user_unions_iterator_t)
|
Move to the previous element.

`user_unions_erase`(→ None)
|
Erase current element from user_unions_t.

`user_unions_clear`(→ None)
|
Clear user_unions_t.

`user_unions_size`(→ int)
|
Get size of user_unions_t.

`user_unions_free`(→ None)
|
Delete user_unions_t instance.

`user_unions_new`(→ user_unions_t *)
|
Create a new user_unions_t instance.

`user_labels_first`(→ int const &)
|
Get reference to the current map key.

`user_labels_second`(→ str)
|
Get reference to the current map value.

`user_labels_find`(→ user_labels_iterator_t)
|
Find the specified key in user_labels_t.

`user_labels_insert`(→ user_labels_iterator_t)
|
Insert new (int, qstring) pair into user_labels_t.

`user_labels_begin`(→ user_labels_iterator_t)
|
Get iterator pointing to the beginning of user_labels_t.

`user_labels_end`(→ user_labels_iterator_t)
|
Get iterator pointing to the end of user_labels_t.

`user_labels_next`(→ user_labels_iterator_t)
|
Move to the next element.

`user_labels_prev`(→ user_labels_iterator_t)
|
Move to the previous element.

`user_labels_erase`(→ None)
|
Erase current element from user_labels_t.

`user_labels_clear`(→ None)
|
Clear user_labels_t.

`user_labels_size`(→ int)
|
Get size of user_labels_t.

`user_labels_free`(→ None)
|
Delete user_labels_t instance.

`user_labels_new`(→ user_labels_t *)
|
Create a new user_labels_t instance.

`eamap_first`(→ ea_t const &)
|
Get reference to the current map key.

`eamap_second`(→ cinsnptrvec_t &)
|
Get reference to the current map value.

`eamap_find`(→ eamap_iterator_t)
|
Find the specified key in eamap_t.

`eamap_insert`(→ eamap_iterator_t)
|
Insert new (ea_t, cinsnptrvec_t) pair into eamap_t.

`eamap_begin`(→ eamap_iterator_t)
|
Get iterator pointing to the beginning of eamap_t.

`eamap_end`(→ eamap_iterator_t)
|
Get iterator pointing to the end of eamap_t.

`eamap_next`(→ eamap_iterator_t)
|
Move to the next element.

`eamap_prev`(→ eamap_iterator_t)
|
Move to the previous element.

`eamap_erase`(→ None)
|
Erase current element from eamap_t.

`eamap_clear`(→ None)
|
Clear eamap_t.

`eamap_size`(→ int)
|
Get size of eamap_t.

`eamap_free`(→ None)
|
Delete eamap_t instance.

`eamap_new`(→ eamap_t *)
|
Create a new eamap_t instance.

`boundaries_first`(→ cinsn_t *const &)
|
Get reference to the current map key.

`boundaries_second`(→ rangeset_t &)
|
Get reference to the current map value.

`boundaries_begin`(→ boundaries_iterator_t)
|
Get iterator pointing to the beginning of boundaries_t.

`boundaries_end`(→ boundaries_iterator_t)
|
Get iterator pointing to the end of boundaries_t.

`boundaries_next`(→ boundaries_iterator_t)
|
Move to the next element.

`boundaries_prev`(→ boundaries_iterator_t)
|
Move to the previous element.

`boundaries_erase`(→ None)
|
Erase current element from boundaries_t.

`boundaries_clear`(→ None)
|
Clear boundaries_t.

`boundaries_size`(→ int)
|
Get size of boundaries_t.

`boundaries_free`(→ None)
|
Delete boundaries_t instance.

`boundaries_new`(→ boundaries_t *)
|
Create a new boundaries_t instance.

`block_chains_get`(→ chain_t &)
|
Get reference to the current set value.

`block_chains_find`(→ block_chains_iterator_t)
|
Find the specified key in set block_chains_t.

`block_chains_insert`(→ block_chains_iterator_t)
|
Insert new (chain_t) into set block_chains_t.

`block_chains_begin`(→ block_chains_iterator_t)
|
Get iterator pointing to the beginning of block_chains_t.

`block_chains_end`(→ block_chains_iterator_t)
|
Get iterator pointing to the end of block_chains_t.

`block_chains_next`(→ block_chains_iterator_t)
|
Move to the next element.

`block_chains_prev`(→ block_chains_iterator_t)
|
Move to the previous element.

`block_chains_erase`(→ None)
|
Erase current element from block_chains_t.

`block_chains_clear`(→ None)
|
Clear block_chains_t.

`block_chains_size`(→ int)
|
Get size of block_chains_t.

`block_chains_free`(→ None)
|
Delete block_chains_t instance.

`block_chains_new`(→ block_chains_t *)
|
Create a new block_chains_t instance.

`decompile`(ea[, hf, flags])
|
Decompile a snippet or a function.

`citem_to_specific_type`(self)
|
cast the citem_t object to its more specific type, either cexpr_t or cinsn_t.

`property_op_to_typename`(self)
|

`cexpr_operands`(self)
|
return a dictionary with the operands of a cexpr_t.

`cinsn_details`(self)
|
return the details pointer for the cinsn_t object depending on the value of its op member. this is one of the cblock_t, cif_t, etc. objects.

`cfunc_type`(self)
|
Get the function's return type tinfo_t object.

`lnot`(e)
|
Logically negate the specified expression. The specified expression will be logically negated. For example, "x == y" is converted into "x != y" by this function.

`make_ref`(e)
|
Create a reference. This function performs the following conversion: "obj" => "&obj". It can handle casts, annihilate "&*", and process other special cases.

`dereference`(e, ptrsize[, is_float])
|
Dereference a pointer. This function dereferences a pointer expression. It performs the following conversion: "ptr" => "*ptr" It can handle discrepancies in the pointer type and the access size.

`call_helper`(rettype, args, *rest)
|
Create a helper call.

`new_block`()
|
Create a new block-statement.

`make_num`(*args)
|
Create a number expression

`create_helper`(*args)
|
Create a helper object..

`install_hexrays_callback`(callback)
|
Install handler for decompiler events.

`remove_hexrays_callback`(callback)
|
Uninstall handler for decompiler events.

## Module Contents

ida_hexrays.get_widget_vdui(f:TWidget*)→vdui_t*
Get the vdui_t instance associated to the TWidget
Parameters:
f – pointer to window
Returns:
a vdui_t *, or nullptr
ida_hexrays.init_hexrays_plugin(flags:int=0)→bool
Check that your plugin is compatible with hex-rays decompiler. This function must be called before calling any other decompiler function.
Parameters:
flags – reserved, must be 0
Returns:
true if the decompiler exists and is compatible with your plugin
ida_hexrays.boundaries_find(map:boundaries_t, key:cinsn_t)→boundaries_iterator_t
Find the specified key in boundaries_t.
ida_hexrays.boundaries_insert(map:boundaries_t, key:cinsn_t, val:rangeset_t)→boundaries_iterator_t
Insert new (cinsn_t *, rangeset_t) pair into boundaries_t.
ida_hexrays.term_hexrays_plugin()→None
Stop working with hex-rays decompiler.
classida_hexrays.hexwarns_t(*args)
Bases: `object`
thisownpush_back(*args)→hexwarn_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→hexwarn_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:hexwarns_t)→Noneextract()→hexwarn_t*inject(s:hexwarn_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:hexwarn_t, x:hexwarn_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:hexwarn_t)→booladd_unique(x:hexwarn_t)→boolappend(x:hexwarn_t)→Noneextend(x:hexwarns_t)→Nonefrontbackclassida_hexrays.user_numforms_t
Bases: `object`
thisownat(_Keyval:operand_locator_t)→number_format_t&size()→intida_hexrays.debug_hexrays_ctree(level:int, msg:str)→Noneclassida_hexrays.ctree_items_t(*args)
Bases: `object`
thisownpush_back(*args)→citem_t*&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→citem_t*const&qclear()→Noneclear()→Noneresize(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:ctree_items_t)→Noneextract()→citem_t**inject(s:citem_t**, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:qvector::iterator, x:citem_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:citem_t)→booladd_unique(x:citem_t)→boolappend(x:citem_t)→Noneextend(x:ctree_items_t)→Nonefrontbackclassida_hexrays.user_labels_t
Bases: `object`
thisownat(_Keyval:intconst&)→_qstring&size()→intclassida_hexrays.user_unions_t
Bases: `object`
thisownat(_Keyval:unsignedlonglongconst&)→qvector&size()→intclassida_hexrays.user_cmts_t
Bases: `object`
thisownat(_Keyval:treeloc_t)→citem_cmt_t&size()→intclassida_hexrays.user_iflags_t
Bases: `object`
thisownat(_Keyval:citem_locator_t)→int&size()→intclassida_hexrays.cinsnptrvec_t(*args)
Bases: `object`
thisownpush_back(*args)→cinsn_t*&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→cinsn_t*const&qclear()→Noneclear()→Noneresize(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:cinsnptrvec_t)→Noneextract()→cinsn_t**inject(s:cinsn_t**, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:qvector::iterator, x:cinsn_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:cinsn_t)→booladd_unique(x:cinsn_t)→boolappend(x:cinsn_t)→Noneextend(x:cinsnptrvec_t)→Nonefrontbackclassida_hexrays.eamap_t
Bases: `object`
thisownat(_Keyval:unsignedlonglongconst&)→cinsnptrvec_t&size()→intclassida_hexrays.boundaries_t
Bases: `object`
thisownat(_Keyval:cinsn_t)→rangeset_t&size()→intclassida_hexrays.cfuncptr_t(*args)
Bases: `object`
thisownreset()→Noneentry_ea:ida_idaapi.ea_tmba:mba_t*body:cinsn_targidx:intvec_t&maturity:ctree_maturity_tuser_labels:user_labels_t*user_cmts:user_cmts_t*numforms:user_numforms_t*user_iflags:user_iflags_t*user_unions:user_unions_t*refcnt:intstatebits:inthdrlines:inttreeitems:citem_pointers_trelease()→Nonebuild_c_tree()→Noneverify(aul:allow_unused_labels_t, even_without_debugger:bool)→Noneprint_dcl()→Noneprint_func(vp:vc_printer_t)→Noneget_func_type(type:tinfo_t)→boolget_lvars()→lvars_t*get_stkoff_delta()→intfind_label(label:int)→citem_t*remove_unused_labels()→Noneget_user_cmt(loc:treeloc_t, rt:cmt_retrieval_type_t)→strset_user_cmt(loc:treeloc_t, cmt:str)→Noneget_user_iflags(loc:citem_locator_t)→intset_user_iflags(loc:citem_locator_t, iflags:int)→Nonehas_orphan_cmts()→booldel_orphan_cmts()→intget_user_union_selection(ea:ida_idaapi.ea_t, path:intvec_t)→boolset_user_union_selection(ea:ida_idaapi.ea_t, path:intvec_t)→Nonesave_user_labels()→None
Save user defined labels into the database.
save_user_cmts()→None
Save user defined comments into the database.
save_user_numforms()→None
Save user defined number formats into the database.
save_user_iflags()→None
Save user defined citem iflags into the database.
save_user_unions()→None
Save user defined union field selections into the database.
get_line_item(line:str, x:int, is_ctree_line:bool, phead:ctree_item_t, pitem:ctree_item_t, ptail:ctree_item_t)→boolget_warnings()→hexwarns_t&get_eamap()→eamap_t&get_boundaries()→boundaries_t&get_pseudocode()→strvec_tconst&refresh_func_ctext()→Nonerecalc_item_addresses()→Nonegather_derefs(ci:ctree_item_t, udm:udt_type_data_t=None)→boolfind_item_coords(*args)
This method has the following signatures:

-
find_item_coords(item: citem_t) -> Tuple[int, int]

-
find_item_coords(item: citem_t, x: int_pointer, y: int_pointer) -> bool

NOTE: The second form is retained for backward-compatibility, but we strongly recommend using the first.
Parameters:
item – The item to find coordinates for in the pseudocode listing
locked()→boolserialize()→booldeserialize(mba:mba_t, bytes:ucharconst*)→cfunc_t*classida_hexrays.qvector_history_t(*args)
Bases: `object`
thisownpush_back(*args)→history_item_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→history_item_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_history_t)→Noneextract()→history_item_t*inject(s:history_item_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:history_item_t, x:history_item_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:history_item_t)→booladd_unique(x:history_item_t)→boolappend(x:history_item_t)→Noneextend(x:qvector_history_t)→Nonefrontbackclassida_hexrays.history_t
Bases: `qvector_history_t`
thisownpop()→history_item_ttop(*args)→history_item_t&push(v:history_item_t)→Noneclassida_hexrays.cinsn_list_t_iterator
Bases: `object`
thisowncur:cinsn_tconst&nextclassida_hexrays.cinsn_list_t(*args)
Bases: `object`
thisownswap(x:cinsn_list_t)→Noneempty()→boolsize()→intfront(*args)→cinsn_tconst&back(*args)→cinsn_tconst&rbegin(*args)→qlist::const_reverse_iteratorrend(*args)→qlist::const_reverse_iteratorpush_front(x:cinsn_t)→Nonepush_back(*args)→cinsn_t&clear()→Nonepop_front()→Nonepop_back()→Nonesplice(pos:qlist::iterator, other:cinsn_list_t, first:qlist::iterator, last:qlist::iterator)→Noneremove(v:cinsn_t)→boolfind(item)index(item)at(index)begin()→cinsn_list_t_iteratorend()→cinsn_list_t_iteratorinsert(*args)→cinsn_list_t_iteratorerase(p:cinsn_list_t_iterator)→Noneclassida_hexrays.qvector_carg_t(*args)
Bases: `object`
thisownpush_back(*args)→carg_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→carg_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_carg_t)→Noneextract()→carg_t*inject(s:carg_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:carg_t, x:carg_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:carg_t)→booladd_unique(x:carg_t)→boolappend(x:carg_t)→Noneextend(x:qvector_carg_t)→Nonefrontbackclassida_hexrays.qvector_ccase_t(*args)
Bases: `object`
thisownpush_back(*args)→ccase_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→ccase_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_ccase_t)→Noneextract()→ccase_t*inject(s:ccase_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:ccase_t, x:ccase_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:ccase_t)→booladd_unique(x:ccase_t)→boolappend(x:ccase_t)→Noneextend(x:qvector_ccase_t)→Nonefrontbackclassida_hexrays.qvector_catchexprs_t(*args)
Bases: `object`
thisownpush_back(*args)→catchexpr_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→catchexpr_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_catchexprs_t)→Noneextract()→catchexpr_t*inject(s:catchexpr_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:catchexpr_t, x:catchexpr_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:catchexpr_t)→booladd_unique(x:catchexpr_t)→boolappend(x:catchexpr_t)→Noneextend(x:qvector_catchexprs_t)→Nonefrontbackclassida_hexrays.qvector_ccatchvec_t(*args)
Bases: `object`
thisownpush_back(*args)→ccatch_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→ccatch_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_ccatchvec_t)→Noneextract()→ccatch_t*inject(s:ccatch_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:ccatch_t, x:ccatch_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:ccatch_t)→booladd_unique(x:ccatch_t)→boolappend(x:ccatch_t)→Noneextend(x:qvector_ccatchvec_t)→Nonefrontbackclassida_hexrays.cblock_posvec_t(*args)
Bases: `object`
thisownpush_back(*args)→cblock_pos_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→cblock_pos_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:cblock_posvec_t)→Noneextract()→cblock_pos_t*inject(s:cblock_pos_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:cblock_pos_t, x:cblock_pos_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:cblock_pos_t)→Noneextend(x:cblock_posvec_t)→Nonefrontbackclassida_hexrays.ui_stroff_ops_t(*args)
Bases: `object`
thisownpush_back(*args)→ui_stroff_op_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→ui_stroff_op_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:ui_stroff_ops_t)→Noneextract()→ui_stroff_op_t*inject(s:ui_stroff_op_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:ui_stroff_op_t, x:ui_stroff_op_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:ui_stroff_op_t)→booladd_unique(x:ui_stroff_op_t)→boolappend(x:ui_stroff_op_t)→Noneextend(x:ui_stroff_ops_t)→Nonefrontbackida_hexrays.qswap(a:cinsn_t, b:cinsn_t)→Noneclassida_hexrays.array_of_bitsets(*args)
Bases: `object`
thisownpush_back(*args)→bitset_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→bitset_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:array_of_bitsets)→Noneextract()→bitset_t*inject(s:bitset_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:bitset_t, x:bitset_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:bitset_t)→booladd_unique(x:bitset_t)→boolappend(x:bitset_t)→Noneextend(x:array_of_bitsets)→Nonefrontbackclassida_hexrays.mopvec_t(*args)
Bases: `object`
thisownpush_back(*args)→mop_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→mop_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:mopvec_t)→Noneextract()→mop_t*inject(s:mop_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:mop_t, x:mop_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:mop_t)→booladd_unique(x:mop_t)→boolappend(x:mop_t)→Noneextend(x:mopvec_t)→Nonefrontbackclassida_hexrays.mcallargs_t(*args)
Bases: `object`
thisownpush_back(*args)→mcallarg_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→mcallarg_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:mcallargs_t)→Noneextract()→mcallarg_t*inject(s:mcallarg_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:mcallarg_t, x:mcallarg_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:mcallarg_t)→booladd_unique(x:mcallarg_t)→boolappend(x:mcallarg_t)→Noneextend(x:mcallargs_t)→Nonefrontbackclassida_hexrays.block_chains_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→block_chains_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→block_chains_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:block_chains_vec_t)→Noneextract()→block_chains_t*inject(s:block_chains_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:block_chains_t, x:block_chains_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:block_chains_t)→Noneextend(x:block_chains_vec_t)→Nonefrontbackclassida_hexrays.lvar_mapping_t
Bases: `object`
thisownat(_Keyval:lvar_locator_t)→lvar_locator_t&size()→intclassida_hexrays.qvector_lvar_t(*args)
Bases: `object`
thisownpush_back(*args)→lvar_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→lvar_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_lvar_t)→Noneextract()→lvar_t*inject(s:lvar_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:lvar_t, x:lvar_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:lvar_t)→booladd_unique(x:lvar_t)→boolappend(x:lvar_t)→Noneextend(x:qvector_lvar_t)→Nonefrontbackclassida_hexrays.lvar_saved_infos_t(*args)
Bases: `object`
thisownpush_back(*args)→lvar_saved_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→lvar_saved_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:lvar_saved_infos_t)→Noneextract()→lvar_saved_info_t*inject(s:lvar_saved_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:lvar_saved_info_t, x:lvar_saved_info_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:lvar_saved_info_t)→booladd_unique(x:lvar_saved_info_t)→boolappend(x:lvar_saved_info_t)→Noneextend(x:lvar_saved_infos_t)→Nonefrontbackclassida_hexrays.Hexrays_Hooks(_flags:int=0, _hkcb_flags:int=1)
Bases: `object`
thisownhook()→boolunhook()→boolflowchart(fc:qflow_chart_t, mba:mba_t, reachable_blocks:bitset_t, decomp_flags:int)→int
Flowchart has been generated.
Parameters:

-
fc – (qflow_chart_t *)

-
mba – (mba_t *)

-
reachable_blocks – (bitset_t *)

-
decomp_flags – (int)

Returns:
Microcode error code
stkpnts(mba:mba_t, _sps:stkpnts_t*)→int
SP change points have been calculated.
Parameters:
mba – (mba_t *)
Returns:
Microcode error code This event is generated for each inlined range as well.
prolog(mba:mba_t, fc:qflow_chart_t, reachable_blocks:bitset_t, decomp_flags:int)→int
Prolog analysis has been finished.
Parameters:

-
mba – (mba_t *)

-
fc – (qflow_chart_t *)

-
reachable_blocks – (const bitset_t *)

-
decomp_flags – (int)

Returns:
Microcode error code This event is generated for each inlined range as well.
microcode(mba:mba_t)→int
Microcode has been generated.
Parameters:
mba – (mba_t *)
Returns:
Microcode error code
preoptimized(mba:mba_t)→int
Microcode has been preoptimized.
Parameters:
mba – (mba_t *)
Returns:
Microcode error code
locopt(mba:mba_t)→int
Basic block level optimization has been finished.
Parameters:
mba – (mba_t *)
Returns:
Microcode error code
prealloc(mba:mba_t)→int
Local variables: preallocation step begins.
Parameters:
mba – (mba_t *) This event may occur several times. Should return: 1 if modified microcode Negative values are Microcode error code
glbopt(mba:mba_t)→int
Global optimization has been finished. If microcode is modified, MERR_LOOP must be returned. It will cause a complete restart of the optimization.
Parameters:
mba – (mba_t *)
Returns:
Microcode error code
pre_structural(ct:control_graph_t*, cfunc:cfunc_t, g:simple_graph_t)→int
Structure analysis is starting.
Parameters:

-
ct – (control_graph_t *) in/out: control graph

-
cfunc – (cfunc_t *) in: the current function

-
g – (const simple_graph_t *) in: control flow graph

Returns:
Microcode error code; MERR_BLOCK means that the analysis has been performed by a plugin
structural(ct:control_graph_t*)→int
Structural analysis has been finished.
Parameters:
ct – (control_graph_t *)
maturity(cfunc:cfunc_t, new_maturity:ctree_maturity_t)→int
Ctree maturity level is being changed.
Parameters:

-
cfunc – (cfunc_t *)

-
new_maturity – (ctree_maturity_t)

interr(errcode:int)→int
Internal error has occurred.
Parameters:
errcode – (int )
combine(blk:mblock_t, insn:minsn_t)→int
Trying to combine instructions of basic block.
Parameters:

-
blk – (mblock_t *)

-
insn – (minsn_t *) Should return: 1 if combined the current instruction with a preceding one -1 if the instruction should not be combined 0 else

print_func(cfunc:cfunc_t, vp:vc_printer_t)→int
Printing ctree and generating text.
Parameters:

-
cfunc – (cfunc_t *)

-
vp – (vc_printer_t *) Returns: 1 if text has been generated by the plugin It is forbidden to modify ctree at this event.

func_printed(cfunc:cfunc_t)→int
Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.
Parameters:
cfunc – (cfunc_t *)
resolve_stkaddrs(mba:mba_t)→int
The optimizer is about to resolve stack addresses.
Parameters:
mba – (mba_t *)
build_callinfo(blk:mblock_t, type:tinfo_t)→PyObject*
Analyzing a call instruction.
Parameters:

-
blk – (mblock_t *) blk->tail is the call.

-
type – (tinfo_t *) buffer for the output type.

callinfo_built(blk:mblock_t)→int
A call instruction has been anallyzed.
Parameters:
blk – (mblock_t *) blk->tail is the call.
calls_done(mba:mba_t)→int
All calls have been analyzed.
Parameters:
mba – (mba_t *) This event is generated immediately after analyzing all calls, before any optimizitions, call unmerging and block merging.
begin_inlining(cdg:codegen_t, decomp_flags:int)→int
Starting to inline outlined functions.
Parameters:

-
cdg – (codegen_t *)

-
decomp_flags – (int)

Returns:
Microcode error code This is an opportunity to inline other ranges.
inlining_func(cdg:codegen_t, blk:int, mbr:mba_ranges_t)→int
A set of ranges is going to be inlined.
Parameters:

-
cdg – (codegen_t *)

-
blk – (int) the block containing call/jump to inline

-
mbr – (mba_ranges_t *) the range to inline

inlined_func(cdg:codegen_t, blk:int, mbr:mba_ranges_t, i1:int, i2:int)→int
A set of ranges got inlined.
Parameters:

-
cdg – (codegen_t *)

-
blk – (int) the block containing call/jump to inline

-
mbr – (mba_ranges_t *) the range to inline

-
i1 – (int) blknum of the first inlined block

-
i2 – (int) blknum of the last inlined block (excluded)

collect_warnings(cfunc:cfunc_t)→int
Collect warning messages from plugins. These warnings will be displayed at the function header, after the user-defined comments.
Parameters:
cfunc – (cfunc_t *)
open_pseudocode(vu:vdui_t)→int
New pseudocode view has been opened.
Parameters:
vu – (vdui_t *)
switch_pseudocode(vu:vdui_t)→int
Existing pseudocode view has been reloaded with a new function. Its text has not been refreshed yet, only cfunc and mba pointers are ready.
Parameters:
vu – (vdui_t *)
refresh_pseudocode(vu:vdui_t)→int
Existing pseudocode text has been refreshed. Adding/removing pseudocode lines is forbidden in this event.
Parameters:
vu – (vdui_t *) See also hxe_text_ready, which happens earlier
close_pseudocode(vu:vdui_t)→int
Pseudocode view is being closed.
Parameters:
vu – (vdui_t *)
keyboard(vu:vdui_t, key_code:int, shift_state:int)→int
Keyboard has been hit.
Parameters:

-
vu – (vdui_t *)

-
key_code – (int) VK_…

-
shift_state – (int) Should return: 1 if the event has been handled

right_click(vu:vdui_t)→int
Mouse right click. Use hxe_populating_popup instead, in case you want to add items in the popup menu.
Parameters:
vu – (vdui_t *)
double_click(vu:vdui_t, shift_state:int)→int
Mouse double click.
Parameters:

-
vu – (vdui_t *)

-
shift_state – (int) Should return: 1 if the event has been handled

curpos(vu:vdui_t)→int
Current cursor position has been changed. (for example, by left-clicking or using keyboard)
Parameters:
vu – (vdui_t *)
create_hint(vu:vdui_t)→PyObject*
Create a hint for the current item.
Parameters:
vu – (vdui_t *)
Returns:
0: continue collecting hints with other subscribers
Returns:
1: stop collecting hints
text_ready(vu:vdui_t)→int
Decompiled text is ready.
Parameters:
vu – (vdui_t *) This event can be used to modify the output text (sv). Obsolete. Please use hxe_func_printed instead.
populating_popup(widget:TWidget*, popup_handle:TPopupMenu*, vu:vdui_t)→int
Populating popup menu. We can add menu items now.
Parameters:

-
widget – (TWidget *)

-
popup_handle – (TPopupMenu *)

-
vu – (vdui_t *)

lvar_name_changed(vu:vdui_t, v:lvar_t, name:str, is_user_name:bool)→int
Local variable got renamed.
Parameters:

-
vu – (vdui_t *)

-
v – (lvar_t *)

-
name – (const char *)

-
is_user_name – (bool) Please note that it is possible to read/write user settings for lvars directly from the idb.

lvar_type_changed(vu:vdui_t, v:lvar_t, tinfo:tinfo_t)→int
Local variable type got changed.
Parameters:

-
vu – (vdui_t *)

-
v – (lvar_t *)

-
tinfo – (const tinfo_t *) Please note that it is possible to read/write user settings for lvars directly from the idb.

lvar_cmt_changed(vu:vdui_t, v:lvar_t, cmt:str)→int
Local variable comment got changed.
Parameters:

-
vu – (vdui_t *)

-
v – (lvar_t *)

-
cmt – (const char *) Please note that it is possible to read/write user settings for lvars directly from the idb.

lvar_mapping_changed(vu:vdui_t, frm:lvar_t, to:lvar_t)→int
Local variable mapping got changed.
Parameters:

-
vu – (vdui_t *)

-
to – (lvar_t *) Please note that it is possible to read/write user settings for lvars directly from the idb.

cmt_changed(cfunc:cfunc_t, loc:treeloc_t, cmt:str)→int
Comment got changed.
Parameters:

-
cfunc – (cfunc_t *)

-
loc – (const treeloc_t *)

-
cmt – (const char *)

mba_maturity(mba:mba_t, reqmat:mba_maturity_t)→int
Maturity level of an MBA was changed.
Parameters:

-
mba – (mba_t *)

-
reqmat – (mba_maturity_t) requested maturity level

Returns:
Microcode error code
ida_hexrays.MAX_SUPPORTED_STACK_SIZEida_hexrays.hexrays_alloc(size:int)→void*ida_hexrays.hexrays_free(ptr:void*)→Noneida_hexrays.MAX_VLR_SIZEida_hexrays.max_vlr_value(size:int)→uvlr_tida_hexrays.min_vlr_svalue(size:int)→uvlr_tida_hexrays.max_vlr_svalue(size:int)→uvlr_tida_hexrays.CMP_NZida_hexrays.CMP_Zida_hexrays.CMP_AEida_hexrays.CMP_Bida_hexrays.CMP_Aida_hexrays.CMP_BEida_hexrays.CMP_GTida_hexrays.CMP_GEida_hexrays.CMP_LTida_hexrays.CMP_LEida_hexrays.is_unsigned_cmpop(cmpop:cmpop_t)→boolida_hexrays.is_signed_cmpop(cmpop:cmpop_t)→boolida_hexrays.is_cmpop_with_eq(cmpop:cmpop_t)→boolida_hexrays.is_cmpop_without_eq(cmpop:cmpop_t)→boolclassida_hexrays.valrng_t(*args)
Bases: `object`
thisownswap(r:valrng_t)→Nonecompare(r:valrng_t)→intset_none()→Noneset_all()→Noneset_unk()→Noneset_eq(v:uvlr_t)→Noneset_cmp(cmp:cmpop_t, _value:uvlr_t)→Nonereduce_size(new_size:int)→boolintersect_with(r:valrng_t)→boolunite_with(r:valrng_t)→boolinverse()→Noneempty()→boolall_values()→boolis_unknown()→boolhas(v:uvlr_t)→booldstr()→strcvt_to_single_value()→boolcvt_to_cmp()→boolget_size()→intmax_value()→uvlr_tmin_svalue()→uvlr_tmax_svalue()→uvlr_tida_hexrays.cvarida_hexrays.MAX_VLR_VALUEida_hexrays.MAX_VLR_SVALUEida_hexrays.MIN_VLR_SVALUEida_hexrays.is_may_access(maymust:maymust_t)→boolida_hexrays.MERR_OK
ok
ida_hexrays.MERR_BLOCK
no error, switch to new block
ida_hexrays.MERR_INTERR
internal error
ida_hexrays.MERR_INSN
cannot convert to microcode
ida_hexrays.MERR_MEM
not enough memory
ida_hexrays.MERR_BADBLK
bad block found
ida_hexrays.MERR_BADSP
positive sp value has been found
ida_hexrays.MERR_PROLOG
prolog analysis failed
ida_hexrays.MERR_SWITCH
wrong switch idiom
ida_hexrays.MERR_EXCEPTION
exception analysis failed
ida_hexrays.MERR_HUGESTACK
stack frame is too big
ida_hexrays.MERR_LVARS
local variable allocation failed
ida_hexrays.MERR_BITNESS
16-bit functions cannot be decompiled
ida_hexrays.MERR_BADCALL
could not determine call arguments
ida_hexrays.MERR_BADFRAME
function frame is wrong
ida_hexrays.MERR_UNKTYPE
undefined type s (currently unused error code)
ida_hexrays.MERR_BADIDB
inconsistent database information
ida_hexrays.MERR_SIZEOF
wrong basic type sizes in compiler settings
ida_hexrays.MERR_REDO
redecompilation has been requested
ida_hexrays.MERR_CANCELED
decompilation has been cancelled
ida_hexrays.MERR_RECDEPTH
max recursion depth reached during lvar allocation
ida_hexrays.MERR_OVERLAP
variables would overlap: s
ida_hexrays.MERR_PARTINIT
partially initialized variable s
ida_hexrays.MERR_COMPLEX
too complex function
ida_hexrays.MERR_LICENSE
no license available
ida_hexrays.MERR_ONLY32
only 32-bit functions can be decompiled for the current database
ida_hexrays.MERR_ONLY64
only 64-bit functions can be decompiled for the current database
ida_hexrays.MERR_BUSY
already decompiling a function
ida_hexrays.MERR_FARPTR
far memory model is supported only for pc
ida_hexrays.MERR_EXTERN
special segments cannot be decompiled
ida_hexrays.MERR_FUNCSIZE
too big function
ida_hexrays.MERR_BADRANGES
bad input ranges
ida_hexrays.MERR_BADARCH
current architecture is not supported
ida_hexrays.MERR_DSLOT
bad instruction in the delay slot
ida_hexrays.MERR_STOP
no error, stop the analysis
ida_hexrays.MERR_CLOUD
cloud: s
ida_hexrays.MERR_EMULATOR
emulator: s
ida_hexrays.MERR_MAX_ERRida_hexrays.MERR_LOOP
internal code: redo last loop (never reported)
ida_hexrays.get_merror_desc(code:merror_t, mba:mba_t)→str
Get textual description of an error code
Parameters:

-
code – Microcode error code

-
mba – the microcode array

Returns:
the error address
classida_hexrays.hexrays_failure_t(*args)
Bases: `object`
thisowncode:merror_t
Microcode error code
errea:ida_idaapi.ea_t
associated address
str:hexrays_failure_t.str
string information
desc()→strida_hexrays.MUST_ACCESSida_hexrays.MAY_ACCESSida_hexrays.MAYMUST_ACCESS_MASKida_hexrays.ONE_ACCESS_TYPEida_hexrays.INCLUDE_SPOILED_REGSida_hexrays.EXCLUDE_PASS_REGSida_hexrays.FULL_XDSUida_hexrays.WITH_ASSERTSida_hexrays.EXCLUDE_VOLATILEida_hexrays.INCLUDE_UNUSED_SRCida_hexrays.INCLUDE_DEAD_RETREGSida_hexrays.INCLUDE_RESTRICTEDida_hexrays.CALL_SPOILS_ONLY_ARGSclassida_hexrays.vd_failure_t(*args)
Bases: `object`
thisownhf:hexrays_failure_tdesc()→strclassida_hexrays.vd_interr_t(ea:ida_idaapi.ea_t, buf:str)
Bases: `vd_failure_t`
thisownida_hexrays.m_nopida_hexrays.m_stxida_hexrays.m_ldxida_hexrays.m_ldcida_hexrays.m_movida_hexrays.m_negida_hexrays.m_lnotida_hexrays.m_bnotida_hexrays.m_xdsida_hexrays.m_xduida_hexrays.m_lowida_hexrays.m_highida_hexrays.m_addida_hexrays.m_subida_hexrays.m_mulida_hexrays.m_udivida_hexrays.m_sdivida_hexrays.m_umodida_hexrays.m_smodida_hexrays.m_orida_hexrays.m_andida_hexrays.m_xorida_hexrays.m_shlida_hexrays.m_shrida_hexrays.m_sarida_hexrays.m_cfaddida_hexrays.m_ofaddida_hexrays.m_cfshlida_hexrays.m_cfshrida_hexrays.m_setsida_hexrays.m_setoida_hexrays.m_setpida_hexrays.m_setnzida_hexrays.m_setzida_hexrays.m_setaeida_hexrays.m_setbida_hexrays.m_setaida_hexrays.m_setbeida_hexrays.m_setgida_hexrays.m_setgeida_hexrays.m_setlida_hexrays.m_setleida_hexrays.m_jcndida_hexrays.m_jnzida_hexrays.m_jzida_hexrays.m_jaeida_hexrays.m_jbida_hexrays.m_jaida_hexrays.m_jbeida_hexrays.m_jgida_hexrays.m_jgeida_hexrays.m_jlida_hexrays.m_jleida_hexrays.m_jtblida_hexrays.m_ijmpida_hexrays.m_gotoida_hexrays.m_callida_hexrays.m_icallida_hexrays.m_retida_hexrays.m_pushida_hexrays.m_popida_hexrays.m_undida_hexrays.m_extida_hexrays.m_f2iida_hexrays.m_f2uida_hexrays.m_i2fida_hexrays.m_u2fida_hexrays.m_f2fida_hexrays.m_fnegida_hexrays.m_faddida_hexrays.m_fsubida_hexrays.m_fmulida_hexrays.m_fdivida_hexrays.must_mcode_close_block(mcode:mcode_t, including_calls:bool)→bool
Must an instruction with the given opcode be the last one in a block? Such opcodes are called closing opcodes.
Parameters:

-
mcode – instruction opcode

-
including_calls – should m_call/m_icall be considered as the closing opcodes? If this function returns true, the opcode cannot appear in the middle of a block. Calls are a special case: unknown calls (is_unknown_call) are considered as closing opcodes.

ida_hexrays.is_mcode_propagatable(mcode:mcode_t)→bool
May opcode be propagated? Such opcodes can be used in sub-instructions (nested instructions) There is a handful of non-propagatable opcodes, like jumps, ret, nop, etc All other regular opcodes are propagatable and may appear in a nested instruction.
ida_hexrays.is_mcode_addsub(mcode:mcode_t)→boolida_hexrays.is_mcode_xdsu(mcode:mcode_t)→boolida_hexrays.is_mcode_set(mcode:mcode_t)→boolida_hexrays.is_mcode_set1(mcode:mcode_t)→boolida_hexrays.is_mcode_j1(mcode:mcode_t)→boolida_hexrays.is_mcode_jcond(mcode:mcode_t)→boolida_hexrays.is_mcode_convertible_to_jmp(mcode:mcode_t)→boolida_hexrays.is_mcode_convertible_to_set(mcode:mcode_t)→boolida_hexrays.is_mcode_call(mcode:mcode_t)→boolida_hexrays.is_mcode_fpu(mcode:mcode_t)→boolida_hexrays.is_mcode_commutative(mcode:mcode_t)→boolida_hexrays.is_mcode_shift(mcode:mcode_t)→boolida_hexrays.is_mcode_divmod(op:mcode_t)→boolida_hexrays.has_mcode_seloff(op:mcode_t)→boolida_hexrays.set2jcnd(code:mcode_t)→mcode_tida_hexrays.jcnd2set(code:mcode_t)→mcode_tida_hexrays.negate_mcode_relation(code:mcode_t)→mcode_tida_hexrays.swap_mcode_relation(code:mcode_t)→mcode_tida_hexrays.get_signed_mcode(code:mcode_t)→mcode_tida_hexrays.get_unsigned_mcode(code:mcode_t)→mcode_tida_hexrays.is_signed_mcode(code:mcode_t)→boolida_hexrays.is_unsigned_mcode(code:mcode_t)→boolida_hexrays.mcode_modifies_d(mcode:mcode_t)→boolclassida_hexrays.operand_locator_t(_ea:ida_idaapi.ea_t, _opnum:int)
Bases: `object`
thisownea:ida_idaapi.ea_t
address of the original processor instruction
opnum:int
operand number in the instruction
compare(r:operand_locator_t)→intida_hexrays.mr_noneida_hexrays.mr_cfida_hexrays.mr_zfida_hexrays.mr_sfida_hexrays.mr_ofida_hexrays.mr_pfida_hexrays.cc_countida_hexrays.mr_ccida_hexrays.mr_firstclassida_hexrays.number_format_t(_opnum:int=0)
Bases: `object`
thisownflags32:flags_t
low 32-bit of flags (for compatibility)
opnum:char
operand number: 0..UA_MAXOP
props:char
properties: combination of NF_ bits (Number format property bits)
serial:uchar
for enums: constant serial number
org_nbytes:char
original number size in bytes
type_name:str
for stroffs: structure for offsetof() for enums: enum name
flags:flags64_t
ida flags, which describe number radix, enum, etc
get_radix()→int
Get number radix
Returns:
2,8,10, or 16
is_fixed()→bool
Is number representation fixed? Fixed representation cannot be modified by the decompiler
is_hex()→bool
Is a hexadecimal number?
is_dec()→bool
Is a decimal number?
is_oct()→bool
Is a octal number?
is_enum()→bool
Is a symbolic constant?
is_char()→bool
Is a character constant?
is_stroff()→bool
Is a structure field offset?
is_numop()→bool
Is a number?
needs_to_be_inverted()→bool
Does the number need to be negated or bitwise negated? Returns true if the user requested a negation but it is not done yet
has_unmutable_type()→boolida_hexrays.NF_FIXED
number format has been defined by the user
ida_hexrays.NF_NEGDONE
temporary internal bit: negation has been performed
ida_hexrays.NF_BINVDONE
temporary internal bit: inverting bits is done
ida_hexrays.NF_NEGATE
The user asked to negate the constant.
ida_hexrays.NF_BITNOT
The user asked to invert bits of the constant.
ida_hexrays.NF_VALID
internal bit: stroff or enum is valid for enums: this bit is set immediately for stroffs: this bit is set at the end of decompilation
classida_hexrays.vd_printer_t
Bases: `object`
thisowntmpbuf:strhdrlines:int
number of header lines (prototype+typedef+lvars) valid at the end of print process
classida_hexrays.vc_printer_t(f:cfunc_t)
Bases: `vd_printer_t`
thisownfunc:cfunc_tconst*
cfunc_t to generate text for
lastchar:char
internal: last printed character
oneliner()→bool
Are we generating one-line text representation?
Returns:
true if the output will occupy one line without line breaks
classida_hexrays.qstring_printer_t(f:cfunc_t, tags:bool)
Bases: `vc_printer_t`
thisownwith_tags:bool
Generate output with color tags.
s:str
Reference to the output string
get_s()→strida_hexrays.dstr(tif:tinfo_t)→str
Print the specified type info. This function can be used from a debugger by typing “tif->dstr()”
ida_hexrays.is_type_correct(ptr:type_tconst*)→bool
Verify a type string.
Returns:
true if type string is correct
ida_hexrays.is_small_udt(tif:tinfo_t)→bool
Is a small structure or union?
Returns:
true if the type is a small UDT (user defined type). Small UDTs fit into a register (or pair or registers) as a rule.
ida_hexrays.is_nonbool_type(type:tinfo_t)→bool
Is definitely a non-boolean type?
Returns:
true if the type is a non-boolean type (non bool and well defined)
ida_hexrays.is_bool_type(type:tinfo_t)→bool
Is a boolean type?
Returns:
true if the type is a boolean type
ida_hexrays.is_ptr_or_array(t:type_t)→bool
Is a pointer or array type?
ida_hexrays.is_paf(t:type_t)→bool
Is a pointer, array, or function type?
ida_hexrays.is_inplace_def(type:tinfo_t)→bool
Is struct/union/enum definition (not declaration)?
ida_hexrays.partial_type_num(type:tinfo_t)→int
Calculate number of partial subtypes.
Returns:
number of partial subtypes. The bigger is this number, the uglier is the type.
ida_hexrays.get_float_type(width:int)→tinfo_t
Get a type of a floating point value with the specified width
Parameters:
width – width of the desired type
Returns:
type info object
ida_hexrays.get_int_type_by_width_and_sign(srcwidth:int, sign:type_sign_t)→tinfo_t
Create a type info by width and sign. Returns a simple type (examples: int, short) with the given width and sign.
Parameters:

-
srcwidth – size of the type in bytes

-
sign – sign of the type

ida_hexrays.get_unk_type(size:int)→tinfo_t
Create a partial type info by width. Returns a partially defined type (examples: _DWORD, _BYTE) with the given width.
Parameters:
size – size of the type in bytes. Must be a power of 2 (1, 2, 4, 8, 16). For non-power-of-2 sizes, returns an empty tinfo_t. Use make_valid_size() to round up arbitrary sizes before calling.
ida_hexrays.dummy_ptrtype(ptrsize:int, isfp:bool)→tinfo_t
Generate a dummy pointer type
Parameters:

-
ptrsize – size of pointed object

-
isfp – is floating point object?

ida_hexrays.make_pointer(type:tinfo_t)→tinfo_t
Create a pointer type. This function performs the following conversion: “type” -> “type*”
Parameters:
type – object type.
Returns:
“type*”. for example, if ‘char’ is passed as the argument,
ida_hexrays.create_typedef(*args)→tinfo_t
This function has the following signatures:

-
create_typedef(name: str) -> tinfo_t

-
create_typedef(n: int) -> tinfo_t

# 0: create_typedef(name: str) -> tinfo_t

Create a reference to a named type.
Returns:
type which refers to the specified name. For example, if name is “DWORD”, the type info which refers to “DWORD” is created.

# 1: create_typedef(n: int) -> tinfo_t

Create a reference to an ordinal type.
Returns:
type which refers to the specified ordinal. For example, if n is 1, the type info which refers to ordinal type 1 is created.
ida_hexrays.GUESSED_NONEida_hexrays.GUESSED_WEAKida_hexrays.GUESSED_FUNCida_hexrays.GUESSED_DATAida_hexrays.TS_NOELLida_hexrays.TS_SHRINKida_hexrays.TS_DONTREFida_hexrays.TS_MASKida_hexrays.get_type(id:int, tif:tinfo_t, guess:type_source_t)→bool
Get a global type. Global types are types of addressable objects and struct/union/enum types
Parameters:

-
id – address or id of the object

-
tif – buffer for the answer

-
guess – what kind of types to consider

Returns:
success
ida_hexrays.set_type(id:int, tif:tinfo_t, source:type_source_t, force:bool=False)→bool
Set a global type.
Parameters:

-
id – address or id of the object

-
tif – new type info

-
source – where the type comes from

-
force – true means to set the type as is, false means to merge the new type with the possibly existing old type info.

Returns:
success
classida_hexrays.vdloc_t
Bases: `ida_typeinf.argloc_t`
thisownreg1()→int
Get the register info. Use when atype() == ALOC_REG1 or ALOC_REG2
set_reg1(r1:int)→None
Set register location.
compare(r:vdloc_t)→intis_aliasable(mb:mba_t, size:int)→boolida_hexrays.print_vdloc(loc:vdloc_t, nbytes:int)→str
Print vdloc. Since vdloc does not always carry the size info, we pass it as NBYTES..
ida_hexrays.arglocs_overlap(loc1:vdloc_t, w1:int, loc2:vdloc_t, w2:int)→bool
Do two arglocs overlap?
classida_hexrays.lvar_locator_t(*args)
Bases: `object`
thisownlocation:vdloc_t
Variable location.
defea:ida_idaapi.ea_t
Definition address. Usually, this is the address of the instruction that initializes the variable. In some cases it can be a fictional address.
get_stkoff()→int
Get offset of the varialbe in the stack frame.
Returns:
a non-negative value for stack variables. The value is an offset from the bottom of the stack frame in terms of vd-offsets. negative values mean error (not a stack variable)
is_reg1()→bool
Is variable located on one register?
is_reg2()→bool
Is variable located on two registers?
is_reg_var()→bool
Is variable located on register(s)?
is_stk_var()→bool
Is variable located on the stack?
is_scattered()→bool
Is variable scattered?
get_reg1()→mreg_t
Get the register number of the variable.
get_reg2()→mreg_t
Get the number of the second register (works only for ALOC_REG2 lvars)
get_scattered()→scattered_aloc_t&
Get information about scattered variable.
compare(r:lvar_locator_t)→intclassida_hexrays.lvar_t(*args, **kwargs)
Bases: `lvar_locator_t`
thisownname:str
variable name. use mba_t::set_nice_lvar_name() and mba_t::set_user_lvar_name() to modify it
cmt:str
variable comment string
tif:tinfo_t
variable type
width:int
variable size in bytes
defblk:int
first block defining the variable. 0 for args, -1 if unknown
divisor:uint64
max known divisor of the variable
used()→bool
Is the variable used in the code?
typed()→bool
Has the variable a type?
mreg_done()→bool
Have corresponding microregs been replaced by references to this variable?
has_nice_name()→bool
Does the variable have a nice name?
is_unknown_width()→bool
Do we know the width of the variable?
has_user_info()→bool
Has any user-defined information?
has_user_name()→bool
Has user-defined name?
has_user_type()→bool
Has user-defined type?
is_result_var()→bool
Is the function result?
is_arg_var()→bool
Is the function argument?
is_fake_var()→bool
Is fake return variable?
is_overlapped_var()→bool
Is overlapped variable?
is_floating_var()→bool
Used by a fpu insn?
is_spoiled_var()→bool
Is spoiled var? (meaningful only during lvar allocation)
is_noptr_var()→bool
Variable type should not be a pointer.
is_mapdst_var()→bool
Other variable(s) map to this var?
is_thisarg()→bool
Is ‘this’ argument of a C++ member function?
is_split_var()→bool
Is a split variable?
has_regname()→bool
Has a register name? (like _RAX)
in_asm()→bool
Is variable used in an instruction translated into __asm?
is_dummy_arg()→bool
Is a dummy argument (added to fill a hole in the argument list)
is_notarg()→bool
Is a local variable? (local variable cannot be an input argument)
is_automapped()→bool
Was the variable automatically mapped to another variable?
is_used_byref()→bool
Was the address of the variable taken?
is_decl_unused()→bool
Was declared as __unused by the user? See CVAR_UNUSED.
is_shared()→bool
Is lvar mapped to several chains.
was_scattered_arg()→bool
Was lvar transformed from a scattered argument?
is_noprop()→bool
Is it forbidden to propagate the variable?
set_used()→Noneclear_used()→Noneset_typed()→Noneset_non_typed()→Noneclr_user_info()→Noneset_user_name()→Noneset_user_type()→Noneclr_user_type()→Noneclr_user_name()→Noneset_mreg_done()→Noneclr_mreg_done()→Noneset_unknown_width()→Noneclr_unknown_width()→Noneset_arg_var()→Noneclr_arg_var()→Noneset_fake_var()→Noneclr_fake_var()→Noneset_overlapped_var()→Noneclr_overlapped_var()→Noneset_floating_var()→Noneclr_floating_var()→Noneset_spoiled_var()→Noneclr_spoiled_var()→Noneset_mapdst_var()→Noneclr_mapdst_var()→Noneset_noptr_var()→Noneclr_noptr_var()→Noneset_thisarg()→Noneclr_thisarg()→Noneset_split_var()→Noneclr_split_var()→Noneset_dummy_arg()→Noneclr_dummy_arg()→Noneset_notarg()→Noneclr_notarg()→Noneset_automapped()→Noneclr_automapped()→Noneset_used_byref()→Noneclr_used_byref()→Noneset_decl_unused()→Noneclr_decl_unused()→Noneset_shared()→Noneclr_shared()→Noneset_scattered_arg()→Noneclr_scattered_arg()→Noneset_noprop()→Noneclr_noprop()→Nonehas_common(v:lvar_t)→bool
Do variables overlap?
has_common_bit(loc:vdloc_t, width2:asize_t)→bool
Does the variable overlap with the specified location?
type()→tinfo_t&
Get variable type.
accepts_type(t:tinfo_t, may_change_thisarg:bool=False)→bool
Check if the variable accept the specified type. Some types are forbidden (void, function types, wrong arrays, etc)
set_lvar_type(t:tinfo_t, may_fail:bool=False)→bool
Set variable type Note: this function does not modify the idb, only the lvar instance in the memory. For permanent changes see modify_user_lvars() Also, the variable type is not considered as final by the decompiler and may be modified later by the type derivation. In some cases set_final_var_type() may work better, but it does not do persistent changes to the database neither.
Parameters:

-
t – new type

-
may_fail – if false and type is bad, interr

Returns:
success
set_final_lvar_type(t:tinfo_t)→None
Set final variable type.
set_width(w:int, svw_flags:int=0)→bool
Change the variable width. We call the variable size ‘width’, it is represents the number of bytes. This function may change the variable type using set_lvar_type().
Parameters:

-
w – new width

-
svw_flags – combination of SVW_… bits

Returns:
success
append_list(mba:mba_t, lst:mlist_t, pad_if_scattered:bool=False)→None
Append local variable to mlist.
Parameters:

-
mba – ptr to the current mba_t

-
lst – list to append to

-
pad_if_scattered – if true, append padding bytes in case of scattered lvar

is_aliasable(mba:mba_t)→bool
Is the variable aliasable?
Parameters:
mba – ptr to the current mba_t Aliasable variables may be modified indirectly (through a pointer)
ida_hexrays.SVW_INTida_hexrays.SVW_FLOATida_hexrays.SVW_SOFTclassida_hexrays.lvars_t
Bases: `qvector_lvar_t`
thisownfind_input_lvar(argloc:vdloc_t, _size:int)→int
Find an input variable at the specified location.
Parameters:

-
argloc – variable location

-
_size – variable size in bytes

Returns:
-1 if failed, otherwise an index into ‘vars’
find_input_reg(reg:int, _size:int=1)→int
Find an input register variable.
Parameters:

-
reg – register to find

-
_size – variable size in bytes

Returns:
-1 if failed, otherwise an index into ‘vars’
find_stkvar(spoff:int, width:int)→int
Find a stack variable at the specified location.
Parameters:

-
spoff – offset from the minimal sp

-
width – variable size in bytes

Returns:
-1 if failed, otherwise an index into ‘vars’
find(ll:lvar_locator_t)→lvar_t*
Find a variable at the specified location.
Parameters:
ll – variable location
Returns:
pointer to variable or nullptr
find_lvar(location:vdloc_t, width:int, defblk:int=-1)→int
Find a variable at the specified location.
Parameters:

-
location – variable location

-
width – variable size in bytes

-
defblk – definition block of the lvar. -1 means any block

Returns:
-1 if failed, otherwise an index into ‘vars’
classida_hexrays.lvar_saved_info_t
Bases: `object`
thisownll:lvar_locator_t
Variable locator.
name:str
Name.
type:tinfo_t
Type.
cmt:str
Comment.
size:ssize_t
Type size (if not initialized then -1)
flags:int
saved user lvar info property bits
has_info()→boolis_kept()→boolclear_keep()→Noneset_keep()→Noneis_split_lvar()→boolset_split_lvar()→Noneclr_split_lvar()→Noneis_noptr_lvar()→boolset_noptr_lvar()→Noneclr_noptr_lvar()→Noneis_nomap_lvar()→boolset_nomap_lvar()→Noneclr_nomap_lvar()→Noneis_unused_lvar()→boolset_unused_lvar()→Noneclr_unused_lvar()→Noneis_noprop_lvar()→boolset_noprop_lvar()→Noneclr_noprop_lvar()→Noneida_hexrays.LVINF_KEEP
preserve saved user settings regardless of vars for example, if a var loses all its user-defined attributes or even gets destroyed, keep its lvar_saved_info_t. this is used for ephemeral variables that get destroyed by macro recognition.
ida_hexrays.LVINF_SPLIT
split allocation of a new variable. forces the decompiler to create a new variable at ll.defea
ida_hexrays.LVINF_NOPTR
variable type should not be a pointer
ida_hexrays.LVINF_NOMAP
forbid automatic mapping of the variable
ida_hexrays.LVINF_UNUSED
unused argument, corresponds to CVAR_UNUSED
ida_hexrays.LVINF_NOPROP
don’t propagate assignments to this lvar (CVAR_NOPROP)
classida_hexrays.lvar_uservec_t
Bases: `object`
thisownlvvec:lvar_saved_infos_t
User-specified names, types, comments for lvars. Variables without user-specified info are not present in this vector.
lmaps:lvar_mapping_t
Local variable mapping (used for merging variables)
stkoff_delta:int
Delta to add to IDA stack offset to calculate Hex-Rays stack offsets. Should be set by the caller before calling save_user_lvar_settings();
ulv_flags:int
Various flags. Possible values are from lvar_uservec_t property bits.
swap(r:lvar_uservec_t)→Noneclear()→Noneempty()→boolfind_info(vloc:lvar_locator_t)→lvar_saved_info_t*
find saved user settings for given var
keep_info(v:lvar_t)→None
Preserve user settings for given var.
ida_hexrays.ULV_PRECISE_DEFEA
Use precise defea’s for lvar locations.
ida_hexrays.restore_user_lvar_settings(lvinf:lvar_uservec_t, func_ea:ida_idaapi.ea_t)→bool
Restore user defined local variable settings in the database.
Parameters:

-
lvinf – ptr to output buffer

-
func_ea – entry address of the function

Returns:
success
ida_hexrays.save_user_lvar_settings(func_ea:ida_idaapi.ea_t, lvinf:lvar_uservec_t)→None
Save user defined local variable settings into the database.
Parameters:

-
func_ea – entry address of the function

-
lvinf – user-specified info about local variables

classida_hexrays.user_lvar_modifier_t
Bases: `object`
thisownmodify_lvars(lvinf:lvar_uservec_t)→bool
Modify lvar settings. Returns: true-modified
ida_hexrays.modify_user_lvars(entry_ea:ida_idaapi.ea_t, mlv:user_lvar_modifier_t)→bool
Modify saved local variable settings.
Parameters:

-
entry_ea – function start address

-
mlv – local variable modifier

Returns:
true if modified variables
ida_hexrays.modify_user_lvar_info(func_ea:ida_idaapi.ea_t, mli_flags:uint, info:lvar_saved_info_t)→bool
Modify saved local variable settings of one variable.
Parameters:

-
func_ea – function start address

-
mli_flags – bits that specify which attrs defined by INFO are to be set

-
info – local variable info attrs

Returns:
true if modified, false if invalid MLI_FLAGS passed
ida_hexrays.MLI_NAME
apply lvar name
ida_hexrays.MLI_TYPE
apply lvar type
ida_hexrays.MLI_CMT
apply lvar comment
ida_hexrays.MLI_SET_FLAGS
set LVINF_… bits
ida_hexrays.MLI_CLR_FLAGS
clear LVINF_… bits
ida_hexrays.locate_lvar(out:lvar_locator_t, func_ea:ida_idaapi.ea_t, varname:str)→bool
Find a variable by name.
Parameters:

-
out – output buffer for the variable locator

-
func_ea – function start address

-
varname – variable name

Returns:
success Since VARNAME is not always enough to find the variable, it may decompile the function.
ida_hexrays.rename_lvar(func_ea:ida_idaapi.ea_t, oldname:str, newname:str)→bool
Rename a local variable.
Parameters:

-
func_ea – function start address

-
oldname – old name of the variable

-
newname – new name of the variable

Returns:
success This is a convenience function. For bulk renaming consider using modify_user_lvars.
classida_hexrays.udcall_t
Bases: `object`
thisownname:strtif:tinfo_tcompare(r:udcall_t)→intempty()→boolida_hexrays.restore_user_defined_calls(udcalls:udcall_map_t*, func_ea:ida_idaapi.ea_t)→bool
Restore user defined function calls from the database.
Parameters:

-
udcalls – ptr to output buffer

-
func_ea – entry address of the function

Returns:
success
ida_hexrays.save_user_defined_calls(func_ea:ida_idaapi.ea_t, udcalls:udcall_map_tconst&)→None
Save user defined local function calls into the database.
Parameters:

-
func_ea – entry address of the function

-
udcalls – user-specified info about user defined function calls

ida_hexrays.parse_user_call(udc:udcall_t, decl:str, silent:bool)→bool
Convert function type declaration into internal structure
Parameters:

-
udc –

-
pointer to output structure

-
decl –

-
function type declaration

-
silent –

-
if TRUE: do not show warning in case of incorrect type

Returns:
success
ida_hexrays.convert_to_user_call(udc:udcall_t, cdg:codegen_t)→merror_t
try to generate user-defined call for an instruction
Returns:
Microcode error code code: MERR_OK - user-defined call generated else - error (MERR_INSN == inacceptable udc.tif)
classida_hexrays.microcode_filter_t
Bases: `object`
thisownmatch(cdg:codegen_t)→bool
check if the filter object is to be applied
Returns:
success
apply(cdg:codegen_t)→merror_t
generate microcode for an instruction
Returns:
MERR_… code: MERR_OK - user-defined microcode generated, go to the next instruction MERR_INSN - not generated - the caller should try the standard way else - error
ida_hexrays.install_microcode_filter(filter:microcode_filter_t, install:bool=True)→bool
register/unregister non-standard microcode generator
Parameters:

-
filter –

-
microcode generator object

-
install –

-
TRUE - register the object, FALSE - unregister

Returns:
success
classida_hexrays.udc_filter_t
Bases: `microcode_filter_t`
thisowncleanup()→None
Cleanup the filter This function properly clears type information associated to this filter.
match(cdg:codegen_t)→bool
return true if the filter object should be applied to given instruction
apply(cdg:codegen_t)→merror_t
generate microcode for an instruction
Returns:
MERR_… code: MERR_OK - user-defined microcode generated, go to the next instruction MERR_INSN - not generated - the caller should try the standard way else - error
empty()→boolinstall()→Noneremove()→boolinit(decl:str)→boolclassida_hexrays.bitset_t(*args)
Bases: `object`
thisownswap(r:bitset_t)→Nonecopy(m:bitset_t)→bitset_t&add(*args)→bool
This function has the following signatures:

-
add(bit: int) -> bool

-
add(bit: int, width: int) -> bool

-
add(ml: const bitset_t &) -> bool

# 0: add(bit: int) -> bool

# 1: add(bit: int, width: int) -> bool

# 2: add(ml: const bitset_t &) -> bool
sub(*args)→bool
This function has the following signatures:

-
sub(bit: int) -> bool

-
sub(bit: int, width: int) -> bool

-
sub(ml: const bitset_t &) -> bool

# 0: sub(bit: int) -> bool

# 1: sub(bit: int, width: int) -> bool

# 2: sub(ml: const bitset_t &) -> bool
cut_at(maxbit:int)→boolshift_down(shift:int)→Nonehas(bit:int)→boolhas_all(bit:int, width:int)→boolhas_any(bit:int, width:int)→booldstr()→strempty()→boolcount(*args)→int
This function has the following signatures:

-
count() -> int

-
count(bit: int) -> int

# 0: count() -> int

# 1: count(bit: int) -> int
last()→intclear()→Nonefill_with_ones(maxbit:int)→Nonehas_common(ml:bitset_t)→boolintersect(ml:bitset_t)→boolis_subset_of(ml:bitset_t)→boolincludes(ml:bitset_t)→boolcompare(r:bitset_t)→intitat(n:int)→bitset_t::iteratorbegin()→bitset_t::iteratorend()→bitset_t::iteratorfront()→intback()→intinc(p:iterator, n:int=1)→Noneitv(it:iterator)→intida_hexrays.bitset_widthida_hexrays.bitset_alignida_hexrays.bitset_shiftclassida_hexrays.iterator(n:int=-1)
Bases: `object`
thisownclassida_hexrays.node_bitset_t(*args)
Bases: `bitset_t`
thisownclassida_hexrays.array_of_node_bitset_t
Bases: `object`
thisownclassida_hexrays.ivl_t(_off:uint64=0, _size:uint64=0)
Bases: `object`
thisownoff:uint64size:uint64empty()→boolvalid()→boolend()→uint64last()→uint64clear()→Nonedstr()→strextend_to_cover(r:ivl_t)→boolintersect(r:ivl_t)→Noneoverlap(ivl:ivl_t)→boolincludes(ivl:ivl_t)→boolcontains(off2:uint64)→boolcompare(r:ivl_t)→intclassida_hexrays.ivl_with_name_t
Bases: `object`
thisownivl:ivl_twhole:strpart:strclassida_hexrays.ivlset_visitor_t
Bases: `object`
thisownvisit_ivl(ivl:ivl_t)→intclassida_hexrays.ivlset_t(*args)
Bases: `object`
thisownswap(r:ivlset_t)→Nonegetivl(idx:int)→ivl_tconst&lastivl()→ivl_tconst&nivls()→intempty()→boolclear()→Noneqclear()→Noneall_values()→boolset_all_values()→Nonesingle_value(*args)→bool
This function has the following signatures:

-
single_value() -> bool

-
single_value(v: uint64) -> bool

# 0: single_value() -> bool

# 1: single_value(v: uint64) -> bool
add(*args)→bool
This function has the following signatures:

-
add(ivl: const ivl_t &) -> bool

-
add(ea: ida_idaapi.ea_t, size: asize_t) -> bool

-
add(ivs: const ivlset_t &) -> bool

# 0: add(ivl: const ivl_t &) -> bool

# 1: add(ea: ida_idaapi.ea_t, size: asize_t) -> bool

# 2: add(ivs: const ivlset_t &) -> bool
addmasked(ivs:ivlset_t, mask:ivl_t)→boolsub(*args)→bool
This function has the following signatures:

-
sub(ivl: const ivl_t &) -> bool

-
sub(ea: ida_idaapi.ea_t, size: asize_t) -> bool

-
sub(ivs: const ivlset_t &) -> bool

# 0: sub(ivl: const ivl_t &) -> bool

# 1: sub(ea: ida_idaapi.ea_t, size: asize_t) -> bool

# 2: sub(ivs: const ivlset_t &) -> bool
count()→asize_thas_common(*args)→bool
This function has the following signatures:

-
has_common(ivs: const ivlset_t &) -> bool

-
has_common(ivl: const ivl_t &, strict: bool=false) -> bool

# 0: has_common(ivs: const ivlset_t &) -> bool

# 1: has_common(ivl: const ivl_t &, strict: bool=false) -> bool
contains(off:uint64)→boolincludes(ivs:ivlset_t)→boolintersect(ivs:ivlset_t)→boolis_subset_of(ivs:ivlset_t)→boolcompare(r:ivlset_t)→intbegin(*args)→ivlset_t::iterator
This function has the following signatures:

-
begin() -> const_iterator

-
begin() -> iterator

# 0: begin() -> const_iterator

# 1: begin() -> iterator
end(*args)→ivlset_t::iterator
This function has the following signatures:

-
end() -> const_iterator

-
end() -> iterator

# 0: end() -> const_iterator

# 1: end() -> iterator
dstr()→strclassida_hexrays.rlist_t(*args)
Bases: `bitset_t`
thisowndstr()→strclassida_hexrays.mlist_t(*args)
Bases: `object`
thisownreg:rlist_tmem:ivlset_tswap(r:mlist_t)→Noneaddmem(ea:ida_idaapi.ea_t, size:asize_t)→booladd(*args)→bool
This function has the following signatures:

-
add(r: mreg_t, size: int) -> bool

-
add(r: const rlist_t &) -> bool

-
add(ivl: const ivl_t &) -> bool

-
add(lst: const mlist_t &) -> bool

# 0: add(r: mreg_t, size: int) -> bool

# 1: add(r: const rlist_t &) -> bool

# 2: add(ivl: const ivl_t &) -> bool

# 3: add(lst: const mlist_t &) -> bool
sub(*args)→bool
This function has the following signatures:

-
sub(r: mreg_t, size: int) -> bool

-
sub(ivl: const ivl_t &) -> bool

-
sub(lst: const mlist_t &) -> bool

# 0: sub(r: mreg_t, size: int) -> bool

# 1: sub(ivl: const ivl_t &) -> bool

# 2: sub(lst: const mlist_t &) -> bool
count()→asize_tdstr()→strempty()→boolclear()→Nonehas(r:mreg_t)→boolhas_all(r:mreg_t, size:int)→boolhas_any(r:mreg_t, size:int)→boolhas_memory()→boolhas_common(lst:mlist_t)→boolincludes(lst:mlist_t)→boolintersect(lst:mlist_t)→boolis_subset_of(lst:mlist_t)→boolcompare(r:mlist_t)→intida_hexrays.get_temp_regs()→mlist_tconst&
Get list of temporary registers. Tempregs are temporary registers that are used during code generation. They do not map to regular processor registers. They are used only to store temporary values during execution of one instruction. Tempregs may not be used to pass a value from one block to another. In other words, at the end of a block all tempregs must be dead.
ida_hexrays.is_kreg(r:mreg_t)→bool
Is a kernel register? Kernel registers are temporary registers that can be used freely. They may be used to store values that cross instruction or basic block boundaries. Kernel registers do not map to regular processor registers. See also mba_t::alloc_kreg()
ida_hexrays.reg2mreg(reg:int)→mreg_t
Map a processor register to a microregister.
Parameters:
reg – processor register number
Returns:
microregister register id or mr_none
ida_hexrays.mreg2reg(reg:mreg_t, width:int)→int
Map a microregister to a processor register.
Parameters:

-
reg – microregister number

-
width – size of microregister in bytes

Returns:
processor register id or -1
ida_hexrays.get_mreg_name(reg:mreg_t, width:int, ud:void*=None)→str
Get the microregister name.
Parameters:

-
reg – microregister number

-
width – size of microregister in bytes. may be bigger than the real register size.

-
ud – reserved, must be nullptr

Returns:
width of the printed register. this value may be less than the WIDTH argument.
classida_hexrays.optinsn_t
Bases: `object`
thisownfunc(blk:mblock_t, ins:minsn_t, optflags:int)→int
Optimize an instruction.
Parameters:

-
blk – current basic block. maybe nullptr, which means that the instruction must be optimized without context

-
ins – instruction to optimize; it is always a top-level instruction. the callback may not delete the instruction but may convert it into nop (see mblock_t::make_nop). to optimize sub-instructions, visit them using minsn_visitor_t. sub-instructions may not be converted into nop but can be converted to “mov x,x”. for example: add x,0,x => mov x,x this callback may change other instructions in the block, but should do this with care, e.g. to no break the propagation algorithm if called with OPTI_NO_LDXOPT.

-
optflags – combination of optimization flags bits

Returns:
number of changes made to the instruction. if after this call the instruction’s use/def lists have changed, you must mark the block level lists as dirty (see mark_lists_dirty)
install()→Noneremove()→boolclassida_hexrays.optblock_t
Bases: `object`
thisownfunc(blk:mblock_t)→int
Optimize a block. This function usually performs the optimizations that require analyzing the entire block and/or its neighbors. For example it can recognize patterns and perform conversions like: b0: b0: … … jnz x, 0, @b2 => jnz x, 0, @b2 b1: b1: add x, 0, y mov x, y … …
Parameters:
blk – Basic block to optimize as a whole.
Returns:
number of changes made to the block. See also mark_lists_dirty.
install()→Noneremove()→boolclassida_hexrays.simple_graph_t(*args, **kwargs)
Bases: `ida_gdl.gdl_graph_t`
thisowntitle:strcolored_gdl_edges:boolcompute_dominators(domin:array_of_node_bitset_t, post:bool=False)→Nonecompute_immediate_dominators(domin:array_of_node_bitset_t, idomin:intvec_t, post:bool=False)→Nonedepth_first_preorder(pre:node_ordering_t)→intdepth_first_postorder(post:node_ordering_t)→intbegin()→simple_graph_t::iteratorend()→simple_graph_t::iteratorfront()→intinc(p:simple_graph_t::iterator&, n:int=1)→Nonegoup(node:int)→intclassida_hexrays.op_parent_info_t(_mba:mba_t=None, _blk:mblock_t=None, _topins:minsn_t=None)
Bases: `object`
thisownmba:mba_t*blk:mblock_t*topins:minsn_t*curins:minsn_t*classida_hexrays.minsn_visitor_t(_mba:mba_t=None, _blk:mblock_t=None, _topins:minsn_t=None)
Bases: `op_parent_info_t`
thisownvisit_minsn()→intclassida_hexrays.mop_visitor_t(_mba:mba_t=None, _blk:mblock_t=None, _topins:minsn_t=None)
Bases: `op_parent_info_t`
thisownprune:bool
Should skip sub-operands of the current operand? visit_mop() may set ‘prune=true’ for that.
visit_mop(op:mop_t, type:tinfo_t, is_target:bool)→intclassida_hexrays.scif_visitor_t
Bases: `object`
thisownvisit_scif_mop(r:mop_t, off:int)→intclassida_hexrays.mlist_mop_visitor_t
Bases: `object`
thisowntopins:minsn_t*curins:minsn_t*changed:boollist:mlist_t*prune:bool
Should skip sub-operands of the current operand? visit_mop() may set ‘prune=true’ for that.
visit_mop(op:mop_t)→intclassida_hexrays.lvar_ref_t(*args)
Bases: `object`
thisownmba:mba_t*const
Pointer to the parent mba_t object. Since we need to access the ‘mba->vars’ array in order to retrieve the referenced variable, we keep a pointer to mba_t here. Note: this means this class and consequently mop_t, minsn_t, mblock_t are specific to a mba_t object and cannot migrate between them. fortunately this is not something we need to do. second, lvar_ref_t’s appear only after MMAT_LVARS.
off:int
offset from the beginning of the variable
idx:int
index into mba->vars
compare(r:lvar_ref_t)→intswap(r:lvar_ref_t)→Nonevar()→lvar_t&
Retrieve the referenced variable.
ida_hexrays.mop_z
none
ida_hexrays.mop_r
register (they exist until MMAT_LVARS)
ida_hexrays.mop_n
immediate number constant
ida_hexrays.mop_str
immediate string constant (user representation)
ida_hexrays.mop_d
result of another instruction
ida_hexrays.mop_S
local stack variable (they exist until MMAT_LVARS)
ida_hexrays.mop_v
global variable
ida_hexrays.mop_b
micro basic block (mblock_t)
ida_hexrays.mop_f
list of arguments
ida_hexrays.mop_l
local variable
ida_hexrays.mop_a
mop_addr_t: address of operand (mop_l, mop_v, mop_S, mop_r)
ida_hexrays.mop_h
helper function
ida_hexrays.mop_c
mcases
ida_hexrays.mop_fn
floating point constant
ida_hexrays.mop_p
operand pair
ida_hexrays.mop_sc
scattered
ida_hexrays.NOSIZE
wrong or unexisting operand size
classida_hexrays.stkvar_ref_t(m:mba_t, o:int)
Bases: `object`
thisownmba:mba_t*const
Pointer to the parent mba_t object. We need it in order to retrieve the referenced stack variable. See notes for lvar_ref_t::mba.
off:int
Offset to the stack variable from the bottom of the stack frame. It is called ‘decompiler stkoff’ and it is different from IDA stkoff. See a note and a picture about ‘decompiler stkoff’ below.
compare(r:stkvar_ref_t)→intswap(r:stkvar_ref_t)→Noneget_stkvar(udm:udm_t=None, p_idaoff:uval_t*=None)→ssize_t
Retrieve the referenced stack variable.
Parameters:

-
udm – stkvar, may be nullptr

-
p_idaoff – if specified, will hold IDA stkoff after the call.

Returns:
index of stkvar in the frame or -1
classida_hexrays.scif_t(_mba:mba_t, tif:tinfo_t, n:str=None)
Bases: `vdloc_t`
thisownmba:mba_t*
Pointer to the parent mba_t object. Some operations may convert a scattered operand into something simpler, (a stack operand, for example). We will need to create stkvar_ref_t at that moment, this is why we need this pointer. See notes for lvar_ref_t::mba.
name:str
Usually scattered operands are created from a function prototype, which has the name information. We preserve it and use it to name the corresponding local variable.
type:tinfo_t
Scattered operands always have type info assigned to them because without it we won’t be able to manipulte them.
classida_hexrays.mnumber_t(*args)
Bases: `operand_locator_t`
thisownvalue:uint64org_value:uint64compare(r:mnumber_t)→intupdate_value(val64:uint64)→Noneclassida_hexrays.fnumber_t
Bases: `object`
thisownfnum:fpvalue_t
Internal representation of the number.
nbytes:int
Original size of the constant in bytes.
dereference_uint16()→uint16*dereference_const_uint16()→uint16const*compare(r:fnumber_t)→intcalc_max_exp()→intis_nan()→boolida_hexrays.SHINS_NUMADDR
display definition addresses for numbers
ida_hexrays.SHINS_VALNUM
display value numbers
ida_hexrays.SHINS_SHORT
do not display use-def chains and other attrs
ida_hexrays.SHINS_LDXEA
display address of ldx expressions (not used)
ida_hexrays.NO_SIDEFF
change operand size but ignore side effects if you decide to keep the changed operand, handle_new_size() must be called
ida_hexrays.WITH_SIDEFF
change operand size and handle side effects
ida_hexrays.ONLY_SIDEFF
only handle side effects
ida_hexrays.ANY_REGSIZE
any register size is permitted
ida_hexrays.ANY_FPSIZE
any size of floating operand is permitted
classida_hexrays.mop_t(*args)
Bases: `object`
thisownt:mopt_t
Operand type.
oprops:uint8
Operand properties.
valnum:uint16
Value number. Zero means unknown. Operands with the same value number are equal.
size:int
Operand size. Usually it is 1,2,4,8 or NOSIZE but for UDTs other sizes are permitted
set_impptr_done()→Noneset_udt()→Noneset_undef_val()→Noneset_lowaddr()→Noneset_for_abi()→Noneis_impptr_done()→boolis_udt()→boolprobably_floating()→boolis_undef_val()→boolis_lowaddr()→boolis_for_abi()→boolis_ccflags()→boolis_pcval()→boolis_glbaddr_from_fixup()→boolassign(rop:mop_t)→mop_t&zero()→Noneswap(rop:mop_t)→Noneerase()→Noneerase_but_keep_size()→Nonedstr()→strcreate_from_mlist(mba:mba_t, lst:mlist_t, fullsize:int)→bool
Create operand from mlist_t. Example: if LST contains 4 bits for R0.4, our operand will be (t=mop_r, r=R0, size=4)
Parameters:

-
mba – pointer to microcode

-
lst – list of locations

-
fullsize – mba->fullsize

Returns:
success
create_from_ivlset(mba:mba_t, ivs:ivlset_t, fullsize:int)→bool
Create operand from ivlset_t. Example: if IVS contains [glbvar..glbvar+4), our operand will be (t=mop_v, g=&glbvar, size=4)
Parameters:

-
mba – pointer to microcode

-
ivs – set of memory intervals

-
fullsize – mba->fullsize

Returns:
success
create_from_vdloc(mba:mba_t, loc:vdloc_t, _size:int)→None
Create operand from vdloc_t. Example: if LOC contains (type=ALOC_REG1, r=R0), our operand will be (t=mop_r, r=R0, size=_SIZE)
Parameters:

-
mba – pointer to microcode

-
loc – location

-
_size – operand size Note: this function cannot handle scattered locations.

Returns:
success
create_from_scattered_vdloc(mba:mba_t, name:str, type:tinfo_t, loc:vdloc_t)→None
Create operand from scattered vdloc_t. Example: if LOC is (ALOC_DIST, {EAX.4, EDX.4}) and TYPE is _LARGE_INTEGER, our operand will be (t=mop_sc, scif={EAX.4, EDX.4})
Parameters:

-
mba – pointer to microcode

-
name – name of the operand, if available

-
type – type of the operand, must be present

-
loc – a scattered location

Returns:
success
create_from_insn(m:minsn_t)→None
Create operand from an instruction. This function creates a nested instruction that can be used as an operand. Example: if m=”add x,y,z”, our operand will be (t=mop_d,d=m). The destination operand of ‘add’ (z) is lost.
Parameters:
m – instruction to embed into operand. may not be nullptr.
make_number(*args)→None
Create an integer constant operand.
Parameters:

-
_value – value to store in the operand

-
_size – size of the value in bytes (1,2,4,8)

-
_ea – address of the processor instruction that made the value

-
opnum – operand number of the processor instruction

make_fpnum(bytes:voidconst*)→bool
Create a floating point constant operand.
Parameters:
bytes – pointer to the floating point value as used by the current processor (e.g. for x86 it must be in IEEE 754)
Returns:
success
make_reg(*args)→None
This function has the following signatures:

-
make_reg(reg: mreg_t) -> None

-
make_reg(reg: mreg_t, _size: int) -> None

# 0: make_reg(reg: mreg_t) -> None

Create a register operand.

# 1: make_reg(reg: mreg_t, _size: int) -> None
make_gvar(ea:ida_idaapi.ea_t)→None
Create a global variable operand.
make_stkvar(mba:mba_t, off:int)→Nonemake_reg_pair(loreg:int, hireg:int, halfsize:int)→None
Create pair of registers.
Parameters:

-
loreg – register holding the low part of the value

-
hireg – register holding the high part of the value

-
halfsize – the size of each of loreg/hireg

make_insn(ins:minsn_t)→None
Create a nested instruction.
make_blkref(blknum:int)→None
Create a global variable operand.
make_helper(name:str)→None
Create a helper operand. A helper operand usually keeps a built-in function name like “va_start” It is essentially just an arbitrary identifier without any additional info.
empty()→boolis_glbvar()→bool
Is a global variable?
is_stkvar()→bool
Is a stack variable?
is_reg(*args)→bool
This function has the following signatures:

-
is_reg() -> bool

-
is_reg(_r: mreg_t) -> bool

-
is_reg(_r: mreg_t, _size: int) -> bool

# 0: is_reg() -> bool

Is a register operand? See also get_mreg_name()

# 1: is_reg(_r: mreg_t) -> bool

Is the specified register?

# 2: is_reg(_r: mreg_t, _size: int) -> bool

Is the specified register of the specified size?
is_arglist()→bool
Is a list of arguments?
is_cc()→bool
Is a condition code?
is_bit_reg(*args)→bool
This function has the following signatures:

-
is_bit_reg() -> bool

-
is_bit_reg(reg: mreg_t) -> bool

# 0: is_bit_reg() -> bool

# 1: is_bit_reg(reg: mreg_t) -> bool

Is a bit register? This includes condition codes and eventually other bit registers
is_kreg()→bool
Is a kernel register?
is_mblock(*args)→bool
This function has the following signatures:

-
is_mblock() -> bool

-
is_mblock(serial: int) -> bool

# 0: is_mblock() -> bool

Is a block reference?

# 1: is_mblock(serial: int) -> bool

Is a block reference to the specified block?
is_scattered()→bool
Is a scattered operand?
is_glbaddr(*args)→bool
This function has the following signatures:

-
is_glbaddr() -> bool

-
is_glbaddr(ea: ida_idaapi.ea_t) -> bool

# 0: is_glbaddr() -> bool

Is address of a global memory cell?

# 1: is_glbaddr(ea: ida_idaapi.ea_t) -> bool

Is address of the specified global memory cell?
is_stkaddr()→bool
Is address of a stack variable?
is_insn(*args)→bool
This function has the following signatures:

-
is_insn() -> bool

-
is_insn(code: mcode_t) -> bool

# 0: is_insn() -> bool

Is a sub-instruction?

# 1: is_insn(code: mcode_t) -> bool

Is a sub-instruction with the specified opcode?
has_side_effects(include_ldx_and_divs:bool=False)→bool
Has any side effects?
Parameters:
include_ldx_and_divs – consider ldx/div/mod as having side effects?
may_use_aliased_memory()→bool
Is it possible for the operand to use aliased memory?
is01()→bool
Are the possible values of the operand only 0 and 1? This function returns true for 0/1 constants, bit registers, the result of ‘set’ insns, etc.
is_sign_extended_from(nbytes:int)→bool
Does the high part of the operand consist of the sign bytes?
Parameters:
nbytes – number of bytes that were sign extended. the remaining size-nbytes high bytes must be sign bytes Example: is_sign_extended_from(xds.4(op.1), 1) -> true because the high 3 bytes are certainly sign bits
is_zero_extended_from(nbytes:int)→bool
Does the high part of the operand consist of zero bytes?
Parameters:
nbytes – number of bytes that were zero extended. the remaining size-nbytes high bytes must be zero Example: is_zero_extended_from(xdu.8(op.1), 2) -> true because the high 6 bytes are certainly zero
is_extended_from(nbytes:int, is_signed:bool)→bool
Does the high part of the operand consist of zero or sign bytes?
equal_mops(rop:mop_t, eqflags:int)→bool
Compare operands. This is the main comparison function for operands.
Parameters:

-
rop – operand to compare with

-
eqflags – combination of comparison bits bits

lexcompare(rop:mop_t)→intfor_all_ops(mv:mop_visitor_t, type:tinfo_t=None, is_target:bool=False)→int
Visit the operand and all its sub-operands. This function visits the current operand as well.
Parameters:

-
mv – visitor object

-
type – operand type

-
is_target – is a destination operand?

for_all_scattered_submops(sv:scif_visitor_t)→int
Visit all sub-operands of a scattered operand. This function does not visit the current operand, only its sub-operands. All sub-operands are synthetic and are destroyed after the visitor. This function works only with scattered operands.
Parameters:
sv – visitor object
value(is_signed:bool)→uint64
Retrieve value of a constant integer operand. These functions can be called only for mop_n operands. See is_constant() that can be called on any operand.
signed_value()→int64unsigned_value()→uint64update_numop_value(val:uint64)→Noneis_constant(is_signed:bool=True)→bool
Retrieve value of a constant integer operand.
Parameters:
is_signed – should treat the value as signed
Returns:
true if the operand is mop_n
is_equal_to(n:uint64, is_signed:bool=True)→boolis_zero()→boolis_one()→boolis_positive_constant()→boolis_negative_constant()→boolget_stkvar(udm:udm_t=None, p_idaoff:uval_t*=None)→ssize_t
Retrieve the referenced stack variable.
Parameters:

-
udm – stkvar, may be nullptr

-
p_idaoff – if specified, will hold IDA stkoff after the call.

Returns:
index of stkvar in the frame or -1
get_stkoff(p_vdoff:sval_t*)→bool
Get the referenced stack offset. This function can also handle mop_sc if it is entirely mapped into a continuous stack region.
Parameters:
p_vdoff – the output buffer
Returns:
success
get_insn(code:mcode_t)→minsn_t*
Get subinstruction of the operand. If the operand has a subinstruction with the specified opcode, return it.
Parameters:
code – desired opcode
Returns:
pointer to the instruction or nullptr
make_low_half(width:int)→bool
Make the low part of the operand. This function takes into account the memory endianness (byte sex)
Parameters:
width – the desired size of the operand part in bytes
Returns:
success
make_high_half(width:int)→bool
Make the high part of the operand. This function takes into account the memory endianness (byte sex)
Parameters:
width – the desired size of the operand part in bytes
Returns:
success
make_first_half(width:int)→bool
Make the first part of the operand. This function does not care about the memory endianness
Parameters:
width – the desired size of the operand part in bytes
Returns:
success
make_second_half(width:int)→bool
Make the second part of the operand. This function does not care about the memory endianness
Parameters:
width – the desired size of the operand part in bytes
Returns:
success
shift_mop(offset:int)→bool
Shift the operand. This function shifts only the beginning of the operand. The operand size will be changed. Examples: shift_mop(AH.1, -1) -> AX.2 shift_mop(qword_00000008.8, 4) -> dword_0000000C.4 shift_mop(xdu.8(op.4), 4) -> #0.4 shift_mop(#0x12345678.4, 3) -> #12.1
Parameters:
offset – shift count (the number of bytes to shift)
Returns:
success
change_size(nsize:int, sideff:side_effect_t=WITH_SIDEFF)→bool
Change the operand size. Examples: change_size(AL.1, 2) -> AX.2 change_size(qword_00000008.8, 4) -> dword_00000008.4 change_size(xdu.8(op.4), 4) -> op.4 change_size(#0x12345678.4, 1) -> #0x78.1
Parameters:

-
nsize – new operand size

-
sideff – may modify the database because of the size change?

Returns:
success
double_size(sideff:side_effect_t=WITH_SIDEFF)→boolpreserve_side_effects(blk:mblock_t, top:minsn_t, moved_calls:bool*=None)→bool
Move subinstructions with side effects out of the operand. If we decide to delete an instruction operand, it is a good idea to call this function. Alternatively we should skip such operands by calling mop_t::has_side_effects() For example, if we transform: jnz x, x, @blk => goto @blk then we must call this function before deleting the X operands.
Parameters:

-
blk – current block

-
top – top level instruction that contains our operand

-
moved_calls – pointer to the boolean that will track if all side effects get handled correctly. must be false initially.

Returns:
false failed to preserve a side effect, it is not safe to delete the operand true no side effects or successfully preserved them
apply_ld_mcode(mcode:mcode_t, ea:ida_idaapi.ea_t, newsize:int)→None
Apply a unary opcode to the operand.
Parameters:

-
mcode – opcode to apply. it must accept ‘l’ and ‘d’ operands but not ‘r’. examples: m_low/m_high/m_xds/m_xdu

-
ea – value of minsn_t::ea for the newly created insruction

-
newsize – new operand size Example: apply_ld_mcode(m_low) will convert op => low(op)

apply_xdu(ea:ida_idaapi.ea_t, newsize:int)→Noneapply_xds(ea:ida_idaapi.ea_t, newsize:int)→Noneobj_idreplace_by(o)meminfopropertynnnpropertydpropertyspropertyfpropertylpropertyapropertycpropertyfpcpropertypairpropertyscifpropertyrpropertygpropertybpropertycstrpropertyhelperida_hexrays.OPROP_IMPDONE
imported operand (a pointer) has been dereferenced
ida_hexrays.OPROP_UDT
a struct or union
ida_hexrays.OPROP_FLOAT
possibly floating value
ida_hexrays.OPROP_CCFLAGS
mop_n: a pc-relative value mop_a: an address obtained from a relocation else: value of a condition code register (like mr_cc)
ida_hexrays.OPROP_UDEFVAL
uses undefined value
ida_hexrays.OPROP_LOWADDR
a low address offset
ida_hexrays.OPROP_ABI
is used to organize arg/retval of a call such operands should be combined more carefully than others at least on BE platforms
ida_hexrays.lexcompare(a:mop_t, b:mop_t)→intclassida_hexrays.mop_pair_t
Bases: `object`
thisownlop:mop_t
low operand
hop:mop_t
high operand
classida_hexrays.mop_addr_t(*args)
Bases: `mop_t`
thisowninsize:intoutsize:intlexcompare(ra:mop_addr_t)→intclassida_hexrays.mcallarg_t(*args)
Bases: `mop_t`
thisownea:ida_idaapi.ea_t
address where the argument was initialized. BADADDR means unknown.
type:tinfo_t
formal argument type
name:str
formal argument name
argloc:argloc_t
ida argloc
flags:int
FAI_…
copy_mop(op:mop_t)→Nonedstr()→strset_regarg(*args)→None
This function has the following signatures:

-
set_regarg(mr: mreg_t, sz: int, tif: const tinfo_t &) -> None

-
set_regarg(mr: mreg_t, tif: const tinfo_t &) -> None

-
set_regarg(mr: mreg_t, dt: char, sign: type_sign_t=type_unsigned) -> None

# 0: set_regarg(mr: mreg_t, sz: int, tif: const tinfo_t &) -> None

# 1: set_regarg(mr: mreg_t, tif: const tinfo_t &) -> None

# 2: set_regarg(mr: mreg_t, dt: char, sign: type_sign_t=type_unsigned) -> None
make_int(val:int, val_ea:ida_idaapi.ea_t, opno:int=0)→Nonemake_uint(val:int, val_ea:ida_idaapi.ea_t, opno:int=0)→Noneida_hexrays.ROLE_UNK
unknown function role
ida_hexrays.ROLE_EMPTY
empty, does not do anything (maybe spoils regs)
ida_hexrays.ROLE_MEMSET
memset(void *dst, uchar value, size_t count);
ida_hexrays.ROLE_MEMSET32
memset32(void *dst, uint32 value, size_t count);
ida_hexrays.ROLE_MEMSET64
memset64(void *dst, uint64 value, size_t count);
ida_hexrays.ROLE_MEMCPY
memcpy(void *dst, const void *src, size_t count);
ida_hexrays.ROLE_STRCPY
strcpy(char *dst, const char *src);
ida_hexrays.ROLE_STRLEN
strlen(const char *src);
ida_hexrays.ROLE_STRCAT
strcat(char *dst, const char *src);
ida_hexrays.ROLE_TAIL
char *tail(const char *str);
ida_hexrays.ROLE_BUG
BUG() helper macro: never returns, causes exception.
ida_hexrays.ROLE_ALLOCA
alloca() function
ida_hexrays.ROLE_BSWAP
bswap() function (any size)
ida_hexrays.ROLE_PRESENT
present() function (used in patterns)
ida_hexrays.ROLE_CONTAINING_RECORD
CONTAINING_RECORD() macro.
ida_hexrays.ROLE_FASTFAIL
__fastfail()
ida_hexrays.ROLE_READFLAGS
__readeflags, __readcallersflags
ida_hexrays.ROLE_IS_MUL_OK
is_mul_ok
ida_hexrays.ROLE_SATURATED_MUL
saturated_mul
ida_hexrays.ROLE_BITTEST
[lock] bt
ida_hexrays.ROLE_BITTESTANDSET
[lock] bts
ida_hexrays.ROLE_BITTESTANDRESET
[lock] btr
ida_hexrays.ROLE_BITTESTANDCOMPLEMENT
[lock] btc
ida_hexrays.ROLE_VA_ARG
va_arg() macro
ida_hexrays.ROLE_VA_COPY
va_copy() function
ida_hexrays.ROLE_VA_START
va_start() function
ida_hexrays.ROLE_VA_END
va_end() function
ida_hexrays.ROLE_ROL
rotate left
ida_hexrays.ROLE_ROR
rotate right
ida_hexrays.ROLE_CFSUB3
carry flag after subtract with carry
ida_hexrays.ROLE_OFSUB3
overflow flag after subtract with carry
ida_hexrays.ROLE_ABS
integer absolute value
ida_hexrays.ROLE_3WAYCMP0
3-way compare helper, returns -1/0/1
ida_hexrays.ROLE_3WAYCMP1
3-way compare helper, returns 0/1/2
ida_hexrays.ROLE_WMEMCPY
wchar_t *wmemcpy(wchar_t *dst, const wchar_t *src, size_t n)
ida_hexrays.ROLE_WMEMSET
wchar_t *wmemset(wchar_t *dst, wchar_t wc, size_t n)
ida_hexrays.ROLE_WCSCPY
wchar_t *wcscpy(wchar_t *dst, const wchar_t *src);
ida_hexrays.ROLE_WCSLEN
size_t wcslen(const wchar_t *s)
ida_hexrays.ROLE_WCSCAT
wchar_t *wcscat(wchar_t *dst, const wchar_t *src)
ida_hexrays.ROLE_SSE_CMP4
e.g. _mm_cmpgt_ss
ida_hexrays.ROLE_SSE_CMP8
e.g. _mm_cmpgt_sd
ida_hexrays.FUNC_NAME_MEMCPYida_hexrays.FUNC_NAME_WMEMCPYida_hexrays.FUNC_NAME_MEMSETida_hexrays.FUNC_NAME_WMEMSETida_hexrays.FUNC_NAME_MEMSET32ida_hexrays.FUNC_NAME_MEMSET64ida_hexrays.FUNC_NAME_STRCPYida_hexrays.FUNC_NAME_WCSCPYida_hexrays.FUNC_NAME_STRLENida_hexrays.FUNC_NAME_WCSLENida_hexrays.FUNC_NAME_STRCATida_hexrays.FUNC_NAME_WCSCATida_hexrays.FUNC_NAME_TAILida_hexrays.FUNC_NAME_VA_ARGida_hexrays.FUNC_NAME_EMPTYida_hexrays.FUNC_NAME_PRESENTida_hexrays.FUNC_NAME_CONTAINING_RECORDida_hexrays.FUNC_NAME_MORESTACKclassida_hexrays.mcallinfo_t(*args)
Bases: `object`
thisowncallee:ida_idaapi.ea_t
address of the called function, if known
solid_args:int
number of solid args. there may be variadic args in addtion
call_spd:int
sp value at call insn
stkargs_top:int
first offset past stack arguments
cc:callcnv_t
calling convention
args:mcallargs_t
call arguments
retregs:mopvec_t
return register(s) (e.g., AX, AX:DX, etc.) this vector is built from return_regs
return_type:tinfo_t
type of the returned value
return_argloc:argloc_t
location of the returned value
return_regs:mlist_t
list of values returned by the function
spoiled:mlist_t
list of spoiled locations (includes RETURN_REGS)
pass_regs:mlist_t
passthrough registers (subset of SPOILED) The called function only partially updates the register, preserving the previous values in other parts. For example, the bit set operation like PC’s _bittestandset().
visible_memory:ivlset_t
what memory is visible to the call?
dead_regs:mlist_t
registers defined by the function but never used. upon propagation we do the following: * dead_regs += return_regs * retregs.clear() since the call is propagated
flags:int
combination of Call properties… bits
role:funcrole_t
function role
fti_attrs:type_attrs_t
extended function attributes
lexcompare(f:mcallinfo_t)→intset_type(type:tinfo_t)→boolget_type()→tinfo_tis_vararg()→booldstr()→strida_hexrays.FCI_PROP
call has been propagated
ida_hexrays.FCI_DEAD
some return registers were determined dead
ida_hexrays.FCI_FINAL
call type is final, should not be changed
ida_hexrays.FCI_NORET
call does not return
ida_hexrays.FCI_PURE
pure function
ida_hexrays.FCI_NOSIDE
call does not have side effects
ida_hexrays.FCI_SPLOK
spoiled/visible_memory lists have been optimized. for some functions we can reduce them as soon as information about the arguments becomes available. in order not to try optimize them again we use this bit.
ida_hexrays.FCI_HASCALL
A function is an synthetic helper combined from several instructions and at least one of them was a call to a real functions
ida_hexrays.FCI_HASFMT
A variadic function with recognized printf- or scanf-style format string
ida_hexrays.FCI_EXPLOCS
all arglocs are specified explicitly
classida_hexrays.mcases_t
Bases: `object`
thisownvalues:casevec_t
expression values for each target
targets:intvec_t
target block numbers
swap(r:mcases_t)→Nonecompare(r:mcases_t)→intempty()→boolsize()→intresize(s:int)→Nonedstr()→strclassida_hexrays.voff_t(*args)
Bases: `object`
thisownoff:int
register number or stack offset
type:mopt_t
mop_r - register, mop_S - stack, mop_z - undefined
set(_type:mopt_t, _off:int)→Noneset_stkoff(stkoff:int)→Noneset_reg(mreg:mreg_t)→Noneundef()→Nonedefined()→boolis_reg()→boolis_stkoff()→boolget_reg()→mreg_tget_stkoff()→intinc(delta:int)→Noneadd(width:int)→voff_tdiff(r:voff_t)→intcompare(r:voff_t)→intclassida_hexrays.vivl_t(*args)
Bases: `voff_t`
thisownsize:int
Interval size in bytes.
set(*args)→None
This function has the following signatures:

-
set(_type: mopt_t, _off: int, _size: int=0) -> None

-
set(voff: const voff_t &, _size: int) -> None

# 0: set(_type: mopt_t, _off: int, _size: int=0) -> None

# 1: set(voff: const voff_t &, _size: int) -> None
set_stkoff(stkoff:int, sz:int=0)→Noneset_reg(mreg:mreg_t, sz:int=0)→Noneextend_to_cover(r:vivl_t)→bool
Extend a value interval using another value interval of the same type
Returns:
success
intersect(r:vivl_t)→int
Intersect value intervals the same type
Returns:
size of the resulting intersection
overlap(r:vivl_t)→bool
Do two value intervals overlap?
includes(r:vivl_t)→bool
Does our value interval include another?
contains(voff2:voff_t)→bool
Does our value interval contain the specified value offset?
compare(r:vivl_t)→intdstr()→strclassida_hexrays.chain_t(*args)
Bases: `ida_pro.intvec_t`
thisownwidth:int
size of the value in bytes
varnum:int
allocated variable index (-1 - not allocated yet)
flags:uchar
combination Chain properties bits
set_value(r:chain_t)→Nonekey()→voff_tconst&is_inited()→boolis_reg()→boolis_stkoff()→boolis_replaced()→boolis_overlapped()→boolis_fake()→boolis_passreg()→boolis_term()→boolset_inited(b:bool)→Noneset_replaced(b:bool)→Noneset_overlapped(b:bool)→Noneset_term(b:bool)→Noneget_reg()→mreg_tget_stkoff()→intoverlap(r:chain_t)→boolincludes(r:chain_t)→boolendoff()→voff_tconstdstr()→strappend_list(mba:mba_t, list:mlist_t)→None
Append the contents of the chain to the specified list of locations.
clear_varnum()→Noneida_hexrays.CHF_INITED
is chain initialized? (valid only after lvar allocation)
ida_hexrays.CHF_REPLACED
chain operands have been replaced?
ida_hexrays.CHF_OVER
overlapped chain
ida_hexrays.CHF_FAKE
fake chain created by widen_chains()
ida_hexrays.CHF_PASSTHRU
pass-thru chain, must use the input variable to the block
ida_hexrays.CHF_TERM
terminating chain; the variable does not survive across the block
classida_hexrays.block_chains_t
Bases: `object`
thisownget_reg_chain(reg:mreg_t, width:int=1)→chain_t*
Get chain for the specified register
Parameters:

-
reg – register number

-
width – size of register in bytes

get_stk_chain(off:int, width:int=1)→chain_t*
Get chain for the specified stack offset
Parameters:

-
off – stack offset

-
width – size of stack value in bytes

get_chain(*args)→chain_t*
This function has the following signatures:

-
get_chain(k: const voff_t &, width: int=1) -> const chain_t *

-
get_chain(k: const voff_t &, width: int=1) -> chain_t *

-
get_chain(ch: const chain_t &) -> const chain_t *

-
get_chain(ch: const chain_t &) -> chain_t *

# 0: get_chain(k: const voff_t &, width: int=1) -> const chain_t *

Get chain for the specified value offset.

# 1: get_chain(k: const voff_t &, width: int=1) -> chain_t *

# 2: get_chain(ch: const chain_t &) -> const chain_t *

Get chain similar to the specified chain

# 3: get_chain(ch: const chain_t &) -> chain_t *
dstr()→strclassida_hexrays.chain_visitor_t
Bases: `object`
thisownparent:block_chains_t*
parent of the current chain
visit_chain(nblock:int, ch:chain_t)→intclassida_hexrays.graph_chains_t
Bases: `block_chains_vec_t`
thisownfor_all_chains(cv:chain_visitor_t, gca_flags:int)→int
Visit all chains
Parameters:

-
cv – chain visitor

-
gca_flags – combination of GCA_ bits

is_locked()→bool
Are the chains locked? It is a good idea to lock the chains before using them. This ensures that they won’t be recalculated and reallocated during the use. See the chain_keeper_t class for that.
acquire()→None
Lock the chains.
release()→None
Unlock the chains.
swap(r:graph_chains_t)→Noneida_hexrays.GCA_EMPTY
include empty chains
ida_hexrays.GCA_SPEC
include chains for special registers
ida_hexrays.GCA_ALLOC
enumerate only allocated chains
ida_hexrays.GCA_NALLOC
enumerate only non-allocated chains
ida_hexrays.GCA_OFIRST
consider only chains of the first block
ida_hexrays.GCA_OLAST
consider only chains of the last block
classida_hexrays.minsn_t(*args)
Bases: `object`
thisownopcode:mcode_t
instruction opcode
iprops:int
combination of instruction property bits bits
next:minsn_t*
next insn in doubly linked list. check also nexti()
prev:minsn_t*
prev insn in doubly linked list. check also previ()
ea:ida_idaapi.ea_t
instruction address
l:mop_t
left operand
r:mop_t
right operand
d:mop_t
destination operand
is_optional()→boolis_combined()→boolis_farcall()→boolis_cleaning_pop()→boolis_extstx()→boolis_tailcall()→boolis_fpinsn()→boolis_assert()→boolis_persistent()→boolis_wild_match()→boolis_propagatable()→boolis_ignlowsrc()→boolis_inverted_jx()→boolwas_noret_icall()→boolis_multimov()→boolis_combinable()→boolwas_split()→boolis_mbarrier()→boolwas_unmerged()→boolwas_unpaired()→boolset_optional()→Noneclr_combined()→Noneset_farcall()→Noneset_cleaning_pop()→Noneset_extstx()→Noneset_tailcall()→Noneclr_tailcall()→Noneset_fpinsn()→Noneclr_fpinsn()→Noneset_assert()→Noneclr_assert()→Noneset_persistent()→Noneset_wild_match()→Noneclr_propagatable()→Noneset_ignlowsrc()→Noneclr_ignlowsrc()→Noneset_inverted_jx()→Noneset_noret_icall()→Noneclr_noret_icall()→Noneset_multimov()→Noneclr_multimov()→Noneset_combinable()→Noneclr_combinable()→Noneset_mbarrier()→Noneset_unmerged()→Noneset_split_size(s:int)→Noneget_split_size()→intswap(m:minsn_t)→None
Swap two instructions. The prev/next fields are not modified by this function because it would corrupt the doubly linked list.
dstr()→str
Get displayable text without tags in a static buffer.
setaddr(new_ea:ida_idaapi.ea_t)→None
Change the instruction address. This function modifies subinstructions as well.
optimize_solo(optflags:int=0)→int
Optimize one instruction without context. This function does not have access to the instruction context (the previous and next instructions in the list, the block number, etc). It performs only basic optimizations that are available without this info.
Parameters:
optflags – combination of optimization flags bits
Returns:
number of changes, 0-unchanged See also mblock_t::optimize_insn()
optimize_subtree(blk:mblock_t, top:minsn_t, parent:minsn_t, converted_call:ea_t*, optflags:int=2)→int
Optimize instruction in its context. Do not use this function, use mblock_t::optimize()
for_all_ops(mv:mop_visitor_t)→int
Visit all instruction operands. This function visits subinstruction operands as well.
Parameters:
mv – operand visitor
Returns:
non-zero value returned by mv.visit_mop() or zero
for_all_insns(mv:minsn_visitor_t)→int
Visit all instructions. This function visits the instruction itself and all its subinstructions.
Parameters:
mv – instruction visitor
Returns:
non-zero value returned by mv.visit_mop() or zero
equal_insns(m:minsn_t, eqflags:int)→bool
Compare instructions. This is the main comparison function for instructions.
Parameters:

-
m – instruction to compare with

-
eqflags – combination of comparison bits bits

lexcompare(ri:minsn_t)→intis_noret_call(flags:int=0)→bool
Is a non-returing call?
Parameters:
flags – combination of NORET_… bits
is_unknown_call()→bool
Is an unknown call? Unknown calls are calls without the argument list (mcallinfo_t). Usually the argument lists are determined by mba_t::analyze_calls(). Unknown calls exist until the MMAT_CALLS maturity level. See also mblock_t::is_call_block
is_helper(name:str)→bool
Is a helper call with the specified name? Helper calls usually have well-known function names (see Well known function names) but they may have any other name. The decompiler does not assume any special meaning for non-well-known names.
find_call(with_helpers:bool=False)→minsn_t*
Find a call instruction. Check for the current instruction and its subinstructions.
Parameters:
with_helpers – consider helper calls as well?
contains_call(with_helpers:bool=False)→bool
Does the instruction contain a call?
has_side_effects(include_ldx_and_divs:bool=False)→bool
Does the instruction have a side effect?
Parameters:
include_ldx_and_divs – consider ldx/div/mod as having side effects? stx is always considered as having side effects. Apart from ldx/std only call may have side effects.
get_role()→funcrole_t
Get the function role of a call.
is_memcpy()→boolis_memset()→boolis_alloca()→boolis_bswap()→boolis_readflags()→boolcontains_opcode(mcode:mcode_t)→bool
Does the instruction have the specified opcode? This function searches subinstructions as well.
Parameters:
mcode – opcode to search for.
find_opcode(mcode:mcode_t)→minsn_t*
Find a (sub)insruction with the specified opcode.
Parameters:
mcode – opcode to search for.
find_ins_op(op:mcode_t=m_nop)→minsn_t*
Find an operand that is a subinsruction with the specified opcode. This function checks only the ‘l’ and ‘r’ operands of the current insn.
Parameters:
op – opcode to search for
Returns:
&l or &r or nullptr
find_num_op()→mop_t*
Find a numeric operand of the current instruction. This function checks only the ‘l’ and ‘r’ operands of the current insn.
Returns:
&l or &r or nullptr
is_mov()→boolis_like_move()→boolmodifies_d()→bool
Does the instruction modify its ‘d’ operand? Some instructions (e.g. m_stx) do not modify the ‘d’ operand.
modifies_pair_mop()→boolis_between(m1:minsn_t, m2:minsn_t)→bool
Is the instruction in the specified range of instructions?
Parameters:

-
m1 – beginning of the range in the doubly linked list

-
m2 – end of the range in the doubly linked list (excluded, may be nullptr) This function assumes that m1 and m2 belong to the same basic block and they are top level instructions.

is_after(m:minsn_t)→bool
Is the instruction after the specified one?
Parameters:
m – the instruction to compare against in the list
may_use_aliased_memory()→bool
Is it possible for the instruction to use aliased memory?
serialize(b:bytevec_t*)→int
Serialize an instruction
Parameters:
b – the output buffer
Returns:
the serialization format that was used to store info
deserialize(bytes:ucharconst*, format_version:int)→bool
Deserialize an instruction
Parameters:

-
bytes – pointer to serialized data

-
format_version – serialization format version. this value is returned by minsn_t::serialize()

Returns:
success
obj_idreplace_by(o)meminfoida_hexrays.IPROP_OPTIONAL
optional instruction
ida_hexrays.IPROP_PERSIST
persistent insn; they are not destroyed
ida_hexrays.IPROP_WILDMATCH
match multiple insns
ida_hexrays.IPROP_CLNPOP
the purpose of the instruction is to clean stack (e.g. “pop ecx” is often used for that)
ida_hexrays.IPROP_FPINSN
floating point insn
ida_hexrays.IPROP_FARCALL
call of a far function using push cs/call sequence
ida_hexrays.IPROP_TAILCALL
tail call
ida_hexrays.IPROP_ASSERT
assertion: usually mov #val, op. assertions are used to help the optimizer. assertions are ignored when generating ctree
ida_hexrays.IPROP_SPLIT
the instruction has been split:
ida_hexrays.IPROP_SPLIT1
into 1 byte
ida_hexrays.IPROP_SPLIT2
into 2 bytes
ida_hexrays.IPROP_SPLIT4
into 4 bytes
ida_hexrays.IPROP_SPLIT8
into 8 bytes
ida_hexrays.IPROP_COMBINED
insn has been modified because of a partial reference
ida_hexrays.IPROP_EXTSTX
this is m_ext propagated into m_stx
ida_hexrays.IPROP_IGNLOWSRC
low part of the instruction source operand has been created artificially (this bit is used only for ‘and x, 80…’)
ida_hexrays.IPROP_INV_JX
inverted conditional jump
ida_hexrays.IPROP_WAS_NORET
was noret icall
ida_hexrays.IPROP_MULTI_MOV
bits that can be set by plugins:

the minsn was generated as part of insn that moves multiple registers (example: STM on ARM may transfer multiple registers)
ida_hexrays.IPROP_DONT_PROP
may not propagate
ida_hexrays.IPROP_DONT_COMB
may not combine this instruction with others
ida_hexrays.IPROP_MBARRIER
this instruction acts as a memory barrier (instructions accessing memory may not be reordered past it)
ida_hexrays.IPROP_UNMERGED
‘goto’ instruction was transformed info ‘call’
ida_hexrays.IPROP_UNPAIRED
instruction is a result of del_dest_pairs() transformation
ida_hexrays.OPTI_ADDREXPRS
optimize all address expressions (&x+N; &x-&y)
ida_hexrays.OPTI_MINSTKREF
may update minstkref
ida_hexrays.OPTI_COMBINSNS
may combine insns (only for optimize_insn)
ida_hexrays.OPTI_NO_LDXOPT
the function is called after the propagation attempt, we do not optimize low/high(ldx) in this case
ida_hexrays.OPTI_NO_VALRNG
forbid using valranges
ida_hexrays.EQ_IGNSIZE
ignore source operand sizes
ida_hexrays.EQ_IGNCODE
ignore instruction opcodes
ida_hexrays.EQ_CMPDEST
compare instruction destinations
ida_hexrays.EQ_OPTINSN
optimize mop_d operands
ida_hexrays.NORET_IGNORE_WAS_NORET_ICALLida_hexrays.NORET_FORBID_ANALYSISida_hexrays.getf_reginsn(ins:minsn_t)→minsn_t*
Skip assertions forward.
ida_hexrays.getb_reginsn(ins:minsn_t)→minsn_t*
Skip assertions backward.
classida_hexrays.intval64_t(v:uint64=0, _s:int=1)
Bases: `object`
thisownval:uint64size:intsval()→int64uval()→uint64sext(target_sz:int)→intval64_tzext(target_sz:int)→intval64_tlow(target_sz:int)→intval64_thigh(target_sz:int)→intval64_tsdiv(o:intval64_t)→intval64_tsmod(o:intval64_t)→intval64_tsar(o:intval64_t)→intval64_tclassida_hexrays.int64_emulator_t
Bases: `object`
thisownget_mop_value(mop:mop_t)→intval64_tmop_value(mop:mop_t)→intval64_tminsn_value(insn:minsn_t)→intval64_tida_hexrays.BLT_NONE
unknown block type
ida_hexrays.BLT_STOP
stops execution regularly (must be the last block)
ida_hexrays.BLT_0WAY
does not have successors (tail is a noret function)
ida_hexrays.BLT_1WAY
passes execution to one block (regular or goto block)
ida_hexrays.BLT_2WAY
passes execution to two blocks (conditional jump)
ida_hexrays.BLT_NWAY
passes execution to many blocks (switch idiom)
ida_hexrays.BLT_XTRN
external block (out of function address)
classida_hexrays.mblock_t(*args, **kwargs)
Bases: `object`
thisownnextb:mblock_t*
next block in the doubly linked list
prevb:mblock_t*
previous block in the doubly linked list
flags:int
combination of Basic block properties bits
start:ida_idaapi.ea_t
start address
end:ida_idaapi.ea_t
end address note: we cannot rely on start/end addresses very much because instructions are propagated between blocks
head:minsn_t*
pointer to the first instruction of the block
tail:minsn_t*
pointer to the last instruction of the block
mba:mba_t*
the parent micro block array
serial:int
block number
type:mblock_type_t
block type (BLT_NONE - not computed yet)
dead_at_start:mlist_t
data that is dead at the block entry
mustbuse:mlist_t
data that must be used by the block
maybuse:mlist_t
data that may be used by the block
mustbdef:mlist_t
data that must be defined by the block
maybdef:mlist_t
data that may be defined by the block
dnu:mlist_t
data that is defined but not used in the block
maxbsp:int
maximal sp value in the block (0…stacksize)
minbstkref:int
lowest stack location accessible with indirect addressing (offset from the stack bottom) initially it is 0 (not computed)
minbargref:int
the same for arguments
predset:intvec_t
control flow graph: list of our predecessors use npred() and pred() to access it
succset:intvec_t
control flow graph: list of our successors use nsucc() and succ() to access it
mark_lists_dirty()→Nonerequest_propagation()→Noneneeds_propagation()→boolrequest_demote64()→Nonelists_dirty()→boollists_ready()→boolmake_lists_ready()→intnpred()→int
Get number of block predecessors.
nsucc()→int
Get number of block successors.
pred(n:int)→intsucc(n:int)→intempty()→booldump()→None
Dump block info. This function is useful for debugging, see mba_t::dump for info
dump_block(title:str)→Noneverify_insn(m:minsn_t)→None
Verify an instruction. This function will generate an internal error if something is wrong with the instruction.
insert_into_block(nm:minsn_t, om:minsn_t)→minsn_t*
Insert instruction into the doubly linked list
Parameters:

-
nm – new instruction

-
om – existing instruction, part of the doubly linked list if nullptr, then the instruction will be inserted at the beginning of the list NM will be inserted immediately after OM

Returns:
pointer to NM
remove_from_block(m:minsn_t)→minsn_t*
Remove instruction from the doubly linked list
Parameters:
m – instruction to remove The removed instruction is not deleted, the caller gets its ownership
Returns:
pointer to the next instruction
for_all_insns(mv:minsn_visitor_t)→int
Visit all instructions. This function visits subinstructions too.
Parameters:
mv – instruction visitor
Returns:
zero or the value returned by mv.visit_insn() See also mba_t::for_all_topinsns()
for_all_ops(mv:mop_visitor_t)→int
Visit all operands. This function visit subinstruction operands too.
Parameters:
mv – operand visitor
Returns:
zero or the value returned by mv.visit_mop()
for_all_uses(list:mlist_t, i1:minsn_t, i2:minsn_t, mmv:mlist_mop_visitor_t)→int
Visit all operands that use LIST.
Parameters:

-
list – ptr to the list of locations. it may be modified: parts that get redefined by the instructions in [i1,i2) will be deleted.

-
i1 – starting instruction. must be a top level insn.

-
i2 – ending instruction (excluded). must be a top level insn.

-
mmv – operand visitor

Returns:
zero or the value returned by mmv.visit_mop()
optimize_insn(*args)→int
Optimize one instruction in the context of the block.
Parameters:

-
m – pointer to a top level instruction

-
optflags – combination of optimization flags bits

Returns:
number of changes made to the block This function may change other instructions in the block too. However, it will not destroy top level instructions (it may convert them to nop’s). This function performs only intrablock modifications. See also minsn_t::optimize_solo()
optimize_block()→int
Optimize a basic block. Usually there is no need to call this function explicitly because the decompiler will call it itself if optinsn_t::func or optblock_t::func return non-zero.
Returns:
number of changes made to the block
build_lists(kill_deads:bool)→int
Build def-use lists and eliminate deads.
Parameters:
kill_deads – do delete dead instructions?
Returns:
the number of eliminated instructions Better mblock_t::call make_lists_ready() rather than this function.
optimize_useless_jump()→int
Remove a jump at the end of the block if it is useless. This function preserves any side effects when removing a useless jump. Both conditional and unconditional jumps are handled (and jtbl too). This function deletes useless jumps, not only replaces them with a nop. (please note that optimize_insn does not handle useless jumps).
Returns:
number of changes made to the block
append_use_list(*args)→None
Append use-list of an operand. This function calculates list of locations that may or must be used by the operand and appends it to LIST.
Parameters:

-
list – ptr to the output buffer. we will append to it.

-
op – operand to calculate the use list of

-
maymust – should we calculate ‘may-use’ or ‘must-use’ list? see maymust_t for more details.

-
mask – if only part of the operand should be considered, a bitmask can be used to specify which part. example: op=AX,mask=0xFF means that we will consider only AL.

append_def_list(list:mlist_t, op:mop_t, maymust:maymust_t)→None
Append def-list of an operand. This function calculates list of locations that may or must be modified by the operand and appends it to LIST.
Parameters:

-
list – ptr to the output buffer. we will append to it.

-
op – operand to calculate the def list of

-
maymust – should we calculate ‘may-def’ or ‘must-def’ list? see maymust_t for more details.

build_use_list(ins:minsn_t, maymust:maymust_t)→mlist_t
Build use-list of an instruction. This function calculates list of locations that may or must be used by the instruction. Examples: “ldx ds.2, eax.4, ebx.4”, may-list: all aliasable memory “ldx ds.2, eax.4, ebx.4”, must-list: empty Since LDX uses EAX for indirect access, it may access any aliasable memory. On the other hand, we cannot tell for sure which memory cells will be accessed, this is why the must-list is empty.
Parameters:

-
ins – instruction to calculate the use list of

-
maymust – should we calculate ‘may-use’ or ‘must-use’ list? see maymust_t for more details.

Returns:
the calculated use-list
build_def_list(ins:minsn_t, maymust:maymust_t)→mlist_t
Build def-list of an instruction. This function calculates list of locations that may or must be modified by the instruction. Examples: “stx ebx.4, ds.2, eax.4”, may-list: all aliasable memory “stx ebx.4, ds.2, eax.4”, must-list: empty Since STX uses EAX for indirect access, it may modify any aliasable memory. On the other hand, we cannot tell for sure which memory cells will be modified, this is why the must-list is empty.
Parameters:

-
ins – instruction to calculate the def list of

-
maymust – should we calculate ‘may-def’ or ‘must-def’ list? see maymust_t for more details.

Returns:
the calculated def-list
is_used(*args)→bool
Is the list used by the specified instruction range?
Parameters:

-
list – list of locations. LIST may be modified by the function: redefined locations will be removed from it.

-
i1 – starting instruction of the range (must be a top level insn)

-
i2 – end instruction of the range (must be a top level insn) i2 is excluded from the range. it can be specified as nullptr. i1 and i2 must belong to the same block.

-
maymust – should we search in ‘may-access’ or ‘must-access’ mode?

find_first_use(*args)→minsn_t*
This function has the following signatures:

-
find_first_use(list: mlist_t *, i1: const minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> const minsn_t *

-
find_first_use(list: mlist_t *, i1: minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> minsn_t *

# 0: find_first_use(list: mlist_t *, i1: const minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> const minsn_t *

Find the first insn that uses the specified list in the insn range.
Returns:
pointer to such instruction or nullptr. Upon return LIST will contain only locations not redefined by insns [i1..result]

# 1: find_first_use(list: mlist_t *, i1: minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> minsn_t *
is_redefined(*args)→bool
Is the list redefined by the specified instructions?
Parameters:

-
list – list of locations to check.

-
i1 – starting instruction of the range (must be a top level insn)

-
i2 – end instruction of the range (must be a top level insn) i2 is excluded from the range. it can be specified as nullptr. i1 and i2 must belong to the same block.

-
maymust – should we search in ‘may-access’ or ‘must-access’ mode?

find_redefinition(*args)→minsn_t*
This function has the following signatures:

-
find_redefinition(list: const mlist_t &, i1: const minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> const minsn_t *

-
find_redefinition(list: const mlist_t &, i1: minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> minsn_t *

# 0: find_redefinition(list: const mlist_t &, i1: const minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> const minsn_t *

Find the first insn that redefines any part of the list in the insn range.
Returns:
pointer to such instruction or nullptr.

# 1: find_redefinition(list: const mlist_t &, i1: minsn_t *, i2: const minsn_t *, maymust: maymust_t=MAY_ACCESS) -> minsn_t *
is_rhs_redefined(ins:minsn_t, i1:minsn_t, i2:minsn_t)→bool
Is the right hand side of the instruction redefined the insn range? “right hand side” corresponds to the source operands of the instruction.
Parameters:

-
ins – instruction to consider

-
i1 – starting instruction of the range (must be a top level insn)

-
i2 – end instruction of the range (must be a top level insn) i2 is excluded from the range. it can be specified as nullptr. i1 and i2 must belong to the same block.

find_access(op:mop_t, parent:minsn_t**, mend:minsn_t, fdflags:int)→minsn_t*
Find the instruction that accesses the specified operand. This function search inside one block.
Parameters:

-
op – operand to search for

-
parent – ptr to ptr to a top level instruction. in: denotes the beginning of the search range. out: denotes the parent of the found instruction.

-
mend – end instruction of the range (must be a top level insn) mend is excluded from the range. it can be specified as nullptr. parent and mend must belong to the same block.

-
fdflags – combination of bits for mblock_t::find_access bits

Returns:
the instruction that accesses the operand. this instruction may be a sub-instruction. to find out the top level instruction, check out *parent. nullptr means ‘not found’.
find_def(op:mop_t, p_i1:minsn_t**, i2:minsn_t, fdflags:int)→minsn_t*find_use(op:mop_t, p_i1:minsn_t**, i2:minsn_t, fdflags:int)→minsn_t*get_valranges(*args)→bool
This function has the following signatures:

-
get_valranges(res: valrng_t *, vivl: const vivl_t &, vrflags: int) -> bool

-
get_valranges(res: valrng_t *, vivl: const vivl_t &, m: const minsn_t *, vrflags: int) -> bool

# 0: get_valranges(res: valrng_t *, vivl: const vivl_t &, vrflags: int) -> bool

Find possible values for a block.

# 1: get_valranges(res: valrng_t *, vivl: const vivl_t &, m: const minsn_t *, vrflags: int) -> bool

Find possible values for an instruction.
make_nop(m:minsn_t)→None
Erase the instruction (convert it to nop) and mark the lists dirty. This is the recommended function to use because it also marks the block use-def lists dirty.
get_reginsn_qty()→int
Calculate number of regular instructions in the block. Assertions are skipped by this function.
Returns:
Number of non-assertion instructions in the block.
is_call_block()→boolis_unknown_call()→boolis_nway()→boolis_branch()→boolis_simple_goto_block()→boolis_simple_jcnd_block()→boolpreds()succs()ida_hexrays.MBL_PRIV
private block - no instructions except the specified are accepted (used in patterns)
ida_hexrays.MBL_NONFAKE
regular block
ida_hexrays.MBL_FAKE
fake block
ida_hexrays.MBL_GOTO
this block is a goto target
ida_hexrays.MBL_TCAL
aritifical call block for tail calls
ida_hexrays.MBL_PUSH
needs “convert push/pop instructions”
ida_hexrays.MBL_DMT64
needs “demote 64bits”
ida_hexrays.MBL_COMB
needs “combine” pass
ida_hexrays.MBL_PROP
needs ‘propagation’ pass
ida_hexrays.MBL_DEAD
needs “eliminate deads” pass
ida_hexrays.MBL_LIST
use/def lists are ready (not dirty)
ida_hexrays.MBL_INCONST
inconsistent lists: we are building them
ida_hexrays.MBL_CALL
call information has been built
ida_hexrays.MBL_BACKPROP
performed backprop_cc
ida_hexrays.MBL_NORET
dead end block: doesn’t return execution control
ida_hexrays.MBL_DSLOT
block for delay slot
ida_hexrays.MBL_VALRANGES
should optimize using value ranges
ida_hexrays.MBL_KEEP
do not remove even if unreachable
ida_hexrays.MBL_INLINED
block was inlined, not originally part of mbr
ida_hexrays.MBL_EXTFRAME
an inlined block with an external frame
ida_hexrays.FD_BACKWARD
search direction
ida_hexrays.FD_FORWARD
search direction
ida_hexrays.FD_USE
look for use
ida_hexrays.FD_DEF
look for definition
ida_hexrays.FD_DIRTY
ignore possible implicit definitions by function calls and indirect memory access
ida_hexrays.VR_AT_START
get value ranges before the instruction or at the block start (if M is nullptr)
ida_hexrays.VR_AT_END
get value ranges after the instruction or at the block end, just after the last instruction (if M is nullptr)
ida_hexrays.VR_EXACT
find exact match. if not set, the returned valrng size will be >= vivl.size
ida_hexrays.WARN_VARARG_REGS
0 cannot handle register arguments in vararg function, discarded them
ida_hexrays.WARN_ILL_PURGED
1 odd caller purged bytes d, correcting
ida_hexrays.WARN_ILL_FUNCTYPE
2 invalid function type ‘s’ has been ignored
ida_hexrays.WARN_VARARG_TCAL
3 cannot handle tail call to vararg
ida_hexrays.WARN_VARARG_NOSTK
4 call vararg without local stack
ida_hexrays.WARN_VARARG_MANY
5 too many varargs, some ignored
ida_hexrays.WARN_ADDR_OUTARGS
6 cannot handle address arithmetics in outgoing argument area of stack frame - unused
ida_hexrays.WARN_DEP_UNK_CALLS
7 found interdependent unknown calls
ida_hexrays.WARN_ILL_ELLIPSIS
8 erroneously detected ellipsis type has been ignored
ida_hexrays.WARN_GUESSED_TYPE
9 using guessed type s;
ida_hexrays.WARN_EXP_LINVAR
10 failed to expand a linear variable
ida_hexrays.WARN_WIDEN_CHAINS
11 failed to widen chains
ida_hexrays.WARN_BAD_PURGED
12 inconsistent function type and number of purged bytes
ida_hexrays.WARN_CBUILD_LOOPS
13 too many cbuild loops
ida_hexrays.WARN_NO_SAVE_REST
14 could not find valid save-restore pair for s
ida_hexrays.WARN_ODD_INPUT_REG
15 odd input register s
ida_hexrays.WARN_ODD_ADDR_USE
16 odd use of a variable address
ida_hexrays.WARN_MUST_RET_FP
17 function return type is incorrect (must be floating point)
ida_hexrays.WARN_ILL_FPU_STACK
18 inconsistent fpu stack
ida_hexrays.WARN_SELFREF_PROP
19 self-referencing variable has been detected
ida_hexrays.WARN_WOULD_OVERLAP
20 variables would overlap: s
ida_hexrays.WARN_ARRAY_INARG
21 array has been used for an input argument
ida_hexrays.WARN_MAX_ARGS
22 too many input arguments, some ignored
ida_hexrays.WARN_BAD_FIELD_TYPE
23 incorrect structure member type for s::s, ignored
ida_hexrays.WARN_WRITE_CONST
24 write access to const memory at a has been detected
ida_hexrays.WARN_BAD_RETVAR
25 wrong return variable
ida_hexrays.WARN_FRAG_LVAR
26 fragmented variable at s may be wrong
ida_hexrays.WARN_HUGE_STKOFF
27 exceedingly huge offset into the stack frame
ida_hexrays.WARN_UNINITED_REG
28 reference to an uninitialized register has been removed: s
ida_hexrays.WARN_FIXED_INSN
29 fixed broken insn
ida_hexrays.WARN_WRONG_VA_OFF
30 wrong offset of va_list variable
ida_hexrays.WARN_CR_NOFIELD
31 CONTAINING_RECORD: no field ‘s’ in struct ‘s’ at d
ida_hexrays.WARN_CR_BADOFF
32 CONTAINING_RECORD: too small offset d for struct ‘s’
ida_hexrays.WARN_BAD_STROFF
33 user specified stroff has not been processed: s
ida_hexrays.WARN_BAD_VARSIZE
34 inconsistent variable size for ‘s’
ida_hexrays.WARN_UNSUPP_REG
35 unsupported processor register ‘s’
ida_hexrays.WARN_UNALIGNED_ARG
36 unaligned function argument ‘s’
ida_hexrays.WARN_BAD_STD_TYPE
37 corrupted or unexisting local type ‘s’
ida_hexrays.WARN_BAD_CALL_SP
38 bad sp value at call
ida_hexrays.WARN_MISSED_SWITCH
39 wrong markup of switch jump, skipped it
ida_hexrays.WARN_BAD_SP
40 positive sp value a has been found
ida_hexrays.WARN_BAD_STKPNT
41 wrong sp change point
ida_hexrays.WARN_UNDEF_LVAR
42 variable ‘s’ is possibly undefined
ida_hexrays.WARN_JUMPOUT
43 control flows out of bounds
ida_hexrays.WARN_BAD_VALRNG
44 values range analysis failed
ida_hexrays.WARN_BAD_SHADOW
45 ignored the value written to the shadow area of the succeeding call
ida_hexrays.WARN_OPT_VALRNG
46 conditional instruction was optimized away because s
ida_hexrays.WARN_RET_LOCREF
47 returning address of temporary local variable ‘s’
ida_hexrays.WARN_BAD_MAPDST
48 too short map destination ‘s’ for variable ‘s’
ida_hexrays.WARN_BAD_INSN
49 bad instruction
ida_hexrays.WARN_ODD_ABI
50 encountered odd instruction for the current ABI
ida_hexrays.WARN_UNBALANCED_STACK
51 unbalanced stack, ignored a potential tail call
ida_hexrays.WARN_OPT_VALRNG2
52 mask 0xX is shortened because s <= 0xX”
ida_hexrays.WARN_OPT_VALRNG3
53 masking with 0XX was optimized away because s <= 0xX
ida_hexrays.WARN_OPT_USELESS_JCND
54 simplified comparisons for ‘s’: s became s
ida_hexrays.WARN_SUBFRAME_OVERFLOW
55 call arguments overflow the function chunk frame
ida_hexrays.WARN_OPT_VALRNG4
56 the cases s were optimized away because s
ida_hexrays.WARN_FRAME_ACCESS
57 illegal frame access
ida_hexrays.WARN_MAX
may be used in notes as a placeholder when the warning id is not available
classida_hexrays.hexwarn_t
Bases: `object`
thisownea:ida_idaapi.ea_t
Address where the warning occurred.
id:warnid_t
Warning id.
text:str
Fully formatted text of the warning.
compare(r:hexwarn_t)→intida_hexrays.MMAT_ZERO
microcode does not exist
ida_hexrays.MMAT_GENERATED
generated microcode
ida_hexrays.MMAT_PREOPTIMIZED
preoptimized pass is complete
ida_hexrays.MMAT_LOCOPT
local optimization of each basic block is complete. control flow graph is ready too.
ida_hexrays.MMAT_CALLS
detected call arguments. see also hxe_calls_done
ida_hexrays.MMAT_GLBOPT1
performed the first pass of global optimization
ida_hexrays.MMAT_GLBOPT2
most global optimization passes are done
ida_hexrays.MMAT_GLBOPT3
completed all global optimization. microcode is fixed now.
ida_hexrays.MMAT_LVARS
allocated local variables
ida_hexrays.MMIDX_GLBLOW
global memory: low part
ida_hexrays.MMIDX_LVARS
stack: local variables
ida_hexrays.MMIDX_RETADDR
stack: return address
ida_hexrays.MMIDX_SHADOW
stack: shadow arguments
ida_hexrays.MMIDX_ARGS
stack: regular stack arguments
ida_hexrays.MMIDX_GLBHIGH
global memory: high part
classida_hexrays.mba_ranges_t(*args)
Bases: `object`
thisownpfn:func_t*
function to decompile. if not null, then function mode.
ranges:rangevec_t
snippet mode: ranges to decompile. function mode: list of outlined ranges
start()→ida_idaapi.ea_tempty()→boolclear()→Noneis_snippet()→boolis_fragmented()→boolclassida_hexrays.mba_range_iterator_t
Bases: `object`
thisownrii:range_chunk_iterator_tfii:func_tail_iterator_tis_snippet()→boolset(mbr:mba_ranges_t)→boolnext()→boolchunk()→range_tconst&classida_hexrays.mba_t(*args, **kwargs)
Bases: `object`
thisownprecise_defeas()→booloptimized()→boolshort_display()→boolshow_reduction()→boolgraph_insns()→boolloaded_gdl()→boolshould_beautify()→boolrtype_refined()→boolmay_refine_rettype()→booldisplay_numaddrs()→booldisplay_valnums()→booldisplay_ea()→boolis_pattern()→boolis_thunk()→boolsaverest_done()→boolcallinfo_built()→boolreally_alloc()→boollvars_allocated()→boolchain_varnums_ok()→boolreturns_fpval()→boolhas_passregs()→boolgenerated_asserts()→boolpropagated_asserts()→booldeleted_pairs()→boolcommon_stkvars_stkargs()→boollvar_names_ok()→boollvars_renamed()→boolhas_over_chains()→boolvalranges_done()→boolargidx_ok()→boolargidx_sorted()→boolcode16_bit_removed()→boolhas_stack_retval()→boolhas_outlines()→boolis_ctr()→boolis_dtr()→boolis_cdtr()→boolprop_complex()→boolget_mba_flags()→intget_mba_flags2()→intset_mba_flags(f:int)→Noneclr_mba_flags(f:int)→Noneset_mba_flags2(f:int)→Noneclr_mba_flags2(f:int)→Noneclr_cdtr()→Nonecalc_shins_flags()→intstkoff_vd2ida(off:int)→intstkoff_ida2vd(off:int)→intargbase()→intidaloc2vd(loc:argloc_t, width:int)→vdloc_tvd2idaloc(*args)→argloc_t
This function has the following signatures:

-
vd2idaloc(loc: const vdloc_t &, width: int) -> argloc_t

-
vd2idaloc(loc: const vdloc_t &, width: int, spd: int) -> argloc_t

# 0: vd2idaloc(loc: const vdloc_t &, width: int) -> argloc_t

# 1: vd2idaloc(loc: const vdloc_t &, width: int, spd: int) -> argloc_t
is_stkarg(v:lvar_t)→boolget_ida_argloc(v:lvar_t)→argloc_tmbr:mba_ranges_tentry_ea:ida_idaapi.ea_tlast_prolog_ea:ida_idaapi.ea_tfirst_epilog_ea:ida_idaapi.ea_tqty:int
number of basic blocks
npurged:int
-1 - unknown
cc:callcnv_t
calling convention
tmpstk_size:int
size of the temporary stack part (which dynamically changes with push/pops)
frsize:int
size of local stkvars range in the stack frame
frregs:int
size of saved registers range in the stack frame
fpd:int
frame pointer delta
pfn_flags:int
copy of func_t::flags
retsize:int
size of return address in the stack frame
shadow_args:int
size of shadow argument area
fullsize:int
Full stack size including incoming args.
stacksize:int
The maximal size of the function stack including bytes allocated for outgoing call arguments (up to retaddr)
inargoff:int
offset of the first stack argument; after fix_scattered_movs() INARGOFF may be less than STACKSIZE
minstkref:int
The lowest stack location whose address was taken.
minstkref_ea:ida_idaapi.ea_t
address with lowest minstkref (for debugging)
minargref:int
The lowest stack argument location whose address was taken This location and locations above it can be aliased It controls locations >= inargoff-shadow_args
spd_adjust:int
If sp>0, the max positive sp value.
gotoff_stkvars:ivlset_t
stkvars that hold .got offsets. considered to be unaliasable
restricted_memory:ivlset_taliased_memory:ivlset_t
aliased_memory+restricted_memory=ALLMEM
nodel_memory:mlist_t
global dead elimination may not delete references to this area
consumed_argregs:rlist_t
registers converted into stack arguments, should not be used as arguments
maturity:mba_maturity_t
current maturity level
reqmat:mba_maturity_t
required maturity level
final_type:bool
is the function type final? (specified by the user)
idb_type:tinfo_t
function type as retrieved from the database
idb_spoiled:reginfovec_t
MBA_SPLINFO && final_type: info in ida format.
spoiled_list:mlist_t
MBA_SPLINFO && !final_type: info in vd format.
fti_flags:int
FTI_… constants for the current function.
label:str
name of the function or pattern (colored)
vars:lvars_t
local variables
argidx:intvec_t
input arguments (indexes into ‘vars’)
retvaridx:int
index of variable holding the return value -1 means none
error_ea:ida_idaapi.ea_t
during microcode generation holds ins.ea
error_strarg:strblocks:mblock_t*
double linked list of blocks
natural:mblock_t**
natural order of blocks
std_ivls:ivl_with_name_t[6]
we treat memory as consisting of 6 parts see memreg_index_t
notes:hexwarns_toccurred_warns:uchar[32]write_to_const_detected()→boolbad_call_sp_detected()→boolregargs_is_not_aligned()→boolhas_bad_sp()→boolterm()→Noneget_curfunc()→func_t*use_frame()→boolis_snippet()→boolset_maturity(mat:mba_maturity_t)→merror_t
Set maturity level.
Parameters:
mat – new maturity level
Returns:
error code Plugins may use this function to skip some parts of the analysis. The maturity level cannot be decreased.
optimize_local(locopt_bits:int)→int
Optimize each basic block locally
Parameters:
locopt_bits – combination of Bits for optimize_local() bits
Returns:
number of changes. 0 means nothing changed This function is called by the decompiler, usually there is no need to call it explicitly.
build_graph()→merror_t
Build control flow graph. This function may be called only once. It calculates the type of each basic block and the adjacency list. optimize_local() calls this function if necessary. You need to call this function only before MMAT_LOCOPT.
Returns:
error code
get_graph()→mbl_graph_t*
Get control graph. Call build_graph() if you need the graph before MMAT_LOCOPT.
analyze_calls(acflags:int)→int
Analyze calls and determine calling conventions.
Parameters:
acflags – permitted actions that are necessary for successful detection of calling conventions. See Bits for analyze_calls()
Returns:
number of calls. -1 means error.
optimize_global()→merror_t
Optimize microcode globally. This function applies various optimization methods until we reach the fixed point. After that it preallocates lvars unless reqmat forbids it.
Returns:
error code
alloc_lvars()→None
Allocate local variables. Must be called only immediately after optimize_global(), with no modifications to the microcode. Converts registers, stack variables, and similar operands into mop_l. This call will not fail because all necessary checks were performed in optimize_global(). After this call the microcode reaches its final state.
dump()→None
Dump microcode to a file. The file will be created in the directory pointed by IDA_DUMPDIR envvar. Dump will be created only if IDA is run under debugger.
dump_mba(_verify:bool, title:str)→Noneverify(always:bool)→None
Verify microcode consistency.
Parameters:
always – if false, the check will be performed only if ida runs under debugger If any inconsistency is discovered, an internal error will be generated. We strongly recommend you to call this function before returing control to the decompiler from your callbacks, in the case if you modified the microcode. If the microcode is inconsistent, this function will generate an internal error. We provide the source code of this function in the plugins/hexrays_sdk/verifier directory for your reference.
mark_chains_dirty()→None
Mark the microcode use-def chains dirty. Call this function is any inter-block data dependencies got changed because of your modifications to the microcode. Failing to do so may cause an internal error.
get_mblock(n:uint)→mblock_t*
Get basic block by its serial number.
insert_block(bblk:int)→mblock_t*
Insert a block in the middle of the mbl array. The very first block of microcode must be empty, it is the entry block. The very last block of microcode must be BLT_STOP, it is the exit block. Therefore inserting a new block before the entry point or after the exit block is not a good idea.
Parameters:
bblk – the new block will be inserted before BBLK
Returns:
ptr to the new block
split_block(blk:mblock_t, start_insn:minsn_t)→mblock_t*
Split a block: insert a new one after the block, move some instructions to new block
Parameters:

-
blk – block to be split

-
start_insn – all instructions to be moved to new block: starting with this one up to the end

Returns:
ptr to the new block
remove_block(blk:mblock_t)→bool
Delete a block.
Parameters:
blk – block to delete
Returns:
true if at least one of the other blocks became empty or unreachable
remove_blocks(start_blk:int, end_blk:int)→boolcopy_block(blk:mblock_t, new_serial:int, cpblk_flags:int=3)→mblock_t*
Make a copy of a block. This function makes a simple copy of the block. It does not fix the predecessor and successor lists, they must be fixed if necessary.
Parameters:

-
blk – block to copy

-
new_serial – position of the copied block

-
cpblk_flags – combination of Batch decompilation bits… bits

Returns:
pointer to the new copy
remove_empty_and_unreachable_blocks()→bool
Delete all empty and unreachable blocks. Blocks marked with MBL_KEEP won’t be deleted.
merge_blocks()→bool
Merge blocks. This function merges blocks constituting linear flow. It calls remove_empty_and_unreachable_blocks() as well.
Returns:
true if changed any blocks
for_all_ops(mv:mop_visitor_t)→int
Visit all operands of all instructions.
Parameters:
mv – operand visitor
Returns:
non-zero value returned by mv.visit_mop() or zero
for_all_insns(mv:minsn_visitor_t)→int
Visit all instructions. This function visits all instruction and subinstructions.
Parameters:
mv – instruction visitor
Returns:
non-zero value returned by mv.visit_mop() or zero
for_all_topinsns(mv:minsn_visitor_t)→int
Visit all top level instructions.
Parameters:
mv – instruction visitor
Returns:
non-zero value returned by mv.visit_mop() or zero
find_mop(ctx:op_parent_info_t, ea:ida_idaapi.ea_t, is_dest:bool, list:mlist_t)→mop_t*
Find an operand in the microcode. This function tries to find the operand that matches LIST. Any operand that overlaps with LIST is considered as a match.
Parameters:

-
ctx – context information for the result

-
ea – desired address of the operand. BADADDR means to accept any address.

-
is_dest – search for destination operand? this argument may be ignored if the exact match could not be found

-
list – list of locations the correspond to the operand

Returns:
pointer to the operand or nullptr.
create_helper_call(ea:ida_idaapi.ea_t, helper:str, rettype:tinfo_t=None, callargs:mcallargs_t=None, out:mop_t=None)→minsn_t*
Create a call of a helper function.
Parameters:

-
ea – The desired address of the instruction

-
helper – The helper name

-
rettype – The return type (nullptr or empty type means ‘void’)

-
callargs – The helper arguments (nullptr-no arguments)

-
out – The operand where the call result should be stored. If this argument is not nullptr, “mov helper_call(), out” will be generated. Otherwise “call helper()” will be generated. Note: the size of this operand must be equal to the RETTYPE size

Returns:
pointer to the created instruction or nullptr if error
get_func_output_lists(*args)→None
Prepare the lists of registers & memory that are defined/killed by a function
Parameters:

-
return_regs – defined regs to return (eax,edx)

-
spoiled – spoiled regs (flags,ecx,mem)

-
type – the function type

-
call_ea – the call insn address (if known)

-
tail_call – is it the tail call?

arg(n:int)→lvar_t&
Get input argument of the decompiled function.
Parameters:
n – argument number (0..nargs-1)
alloc_fict_ea(real_ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Allocate a fictional address. This function can be used to allocate a new unique address for a new instruction, if re-using any existing address leads to conflicts. For example, if the last instruction of the function modifies R0 and falls through to the next function, it will be a tail call: LDM R0!, {R4,R7} end of the function start of another function In this case R0 generates two different lvars at the same address: * one modified by LDM * another that represents the return value from the tail call

Another example: a third-party plugin makes a copy of an instruction. This may lead to the generation of two variables at the same address. Example 3: fictional addresses can be used for new instructions created while modifying the microcode. This function can be used to allocate a new unique address for a new instruction or a variable. The fictional address is selected from an unallocated address range.
Parameters:
real_ea – real instruction address (BADADDR is ok too)
Returns:
a unique fictional address
map_fict_ea(fict_ea:ida_idaapi.ea_t)→ida_idaapi.ea_t
Resolve a fictional address. This function provides a reverse of the mapping made by alloc_fict_ea().
Parameters:
fict_ea – fictional definition address
Returns:
the real instruction address
get_std_region(idx:memreg_index_t)→ivl_tconst&
Get information about various memory regions. We map the stack frame to the global memory, to some unused range.
get_lvars_region()→ivl_tconst&get_shadow_region()→ivl_tconst&get_args_region()→ivl_tconst&get_stack_region()→ivl_tserialize()→None
Serialize mbl array into a sequence of bytes.
staticdeserialize(bytes:ucharconst*)→mba_t*
Deserialize a byte sequence into mbl array.
Parameters:
bytes – pointer to the beginning of the byte sequence.
Returns:
new mbl array
save_snapshot(description:str)→None
Create and save microcode snapshot.
alloc_kreg(size:int, check_size:bool=True)→mreg_t
Allocate a kernel register.
Parameters:

-
size – size of the register in bytes

-
check_size – if true, only the sizes that correspond to a size of a basic type will be accepted.

Returns:
allocated register. mr_none means failure.
free_kreg(reg:mreg_t, size:int)→None
Free a kernel register. If wrong arguments are passed, this function will generate an internal error.
Parameters:

-
reg – a previously allocated kernel register

-
size – size of the register in bytes

inline_func(cdg:codegen_t, blknum:int, ranges:mba_ranges_t, decomp_flags:int=0, inline_flags:int=0)→merror_t
Inline a range. This function may be called only during the initial microcode generation phase.
Parameters:

-
cdg – the codegenerator object

-
blknum – the block contaning the call/jump instruction to inline

-
ranges – the set of ranges to inline. in the case of multiple calls to inline_func(), ranges will be compared using their start addresses. if two ranges have the same address, they will be considered the same.

-
decomp_flags – combination of decompile() flags bits

-
inline_flags – combination of inline_func() flags bits

Returns:
error code
locate_stkpnt(ea:ida_idaapi.ea_t)→stkpnt_tconst*set_lvar_name(v:lvar_t, name:str, flagbits:int)→boolset_nice_lvar_name(v:lvar_t, name:str)→boolset_user_lvar_name(v:lvar_t, name:str)→boolidb_nodeida_hexrays.MBA_PRCDEFS
use precise defeas for chain-allocated lvars
ida_hexrays.MBA_NOFUNC
function is not present, addresses might be wrong
ida_hexrays.MBA_PATTERN
microcode pattern, callinfo is present
ida_hexrays.MBA_LOADED
loaded gdl, no instructions (debugging)
ida_hexrays.MBA_RETFP
function returns floating point value
ida_hexrays.MBA_SPLINFO
(final_type ? idb_spoiled : spoiled_regs) is valid
ida_hexrays.MBA_PASSREGS
has mcallinfo_t::pass_regs
ida_hexrays.MBA_THUNK
thunk function
ida_hexrays.MBA_CMNSTK
stkvars+stkargs should be considered as one area
ida_hexrays.MBA_PREOPT
preoptimization stage complete
ida_hexrays.MBA_CMBBLK
request to combine blocks
ida_hexrays.MBA_ASRTOK
assertions have been generated
ida_hexrays.MBA_CALLS
callinfo has been built
ida_hexrays.MBA_ASRPROP
assertion have been propagated
ida_hexrays.MBA_SAVRST
save-restore analysis has been performed
ida_hexrays.MBA_RETREF
return type has been refined
ida_hexrays.MBA_GLBOPT
microcode has been optimized globally
ida_hexrays.MBA_LVARS0
lvar pre-allocation has been performed
ida_hexrays.MBA_LVARS1
lvar real allocation has been performed
ida_hexrays.MBA_DELPAIRS
pairs have been deleted once
ida_hexrays.MBA_CHVARS
can verify chain varnums
ida_hexrays.MBA_SHORT
use short display
ida_hexrays.MBA_COLGDL
display graph after each reduction
ida_hexrays.MBA_INSGDL
display instruction in graphs
ida_hexrays.MBA_NICE
apply transformations to c code
ida_hexrays.MBA_REFINE
may refine return value size
ida_hexrays.MBA_WINGR32
use wingraph32 (deprecated, see hexrays_config_t::use_external_graph)
ida_hexrays.MBA_NUMADDR
display definition addresses for numbers
ida_hexrays.MBA_VALNUM
display value numbers
ida_hexrays.MBA_SHOWEA
display EA in line prefix
ida_hexrays.MBA_INITIAL_FLAGSida_hexrays.MBA2_LVARNAMES_OK
may verify lvar_names?
ida_hexrays.MBA2_LVARS_RENAMED
accept empty names now?
ida_hexrays.MBA2_OVER_CHAINS
has overlapped chains?
ida_hexrays.MBA2_VALRNG_DONE
calculated valranges?
ida_hexrays.MBA2_IS_CTR
is constructor?
ida_hexrays.MBA2_IS_DTR
is destructor?
ida_hexrays.MBA2_ARGIDX_OK
may verify input argument list?
ida_hexrays.MBA2_NO_DUP_CALLS
forbid multiple calls with the same ea
ida_hexrays.MBA2_NO_DUP_LVARS
forbid multiple lvars with the same ea
ida_hexrays.MBA2_UNDEF_RETVAR
return value is undefined
ida_hexrays.MBA2_ARGIDX_SORTED
args finally sorted according to ABI (e.g. reverse stkarg order in Borland)
ida_hexrays.MBA2_CODE16_BIT
the code16 bit got removed
ida_hexrays.MBA2_STACK_RETVAL
the return value (or its part) is on the stack
ida_hexrays.MBA2_HAS_OUTLINES
calls to outlined code have been inlined
ida_hexrays.MBA2_NO_FRAME
do not use function frame info (only snippet mode)
ida_hexrays.MBA2_PROP_COMPLEX
allow propagation of more complex variable definitions
ida_hexrays.MBA2_DONT_VERIFY
Do not verify microcode. This flag is recomended to be set only when debugging decompiler plugins
ida_hexrays.MBA2_INITIAL_FLAGSida_hexrays.MBA2_ALL_FLAGSida_hexrays.NALT_VD
this index is not used by ida
ida_hexrays.LOCOPT_ALL
redo optimization for all blocks. if this bit is not set, only dirty blocks will be optimized
ida_hexrays.LOCOPT_REFINE
refine return type, ok to fail
ida_hexrays.LOCOPT_REFINE2
refine return type, try harder
ida_hexrays.ACFL_LOCOPT
perform local propagation (requires ACFL_BLKOPT)
ida_hexrays.ACFL_BLKOPT
perform interblock transformations
ida_hexrays.ACFL_GLBPROP
perform global propagation
ida_hexrays.ACFL_GLBDEL
perform dead code eliminition
ida_hexrays.ACFL_GUESS
may guess calling conventions
ida_hexrays.CPBLK_FAST
do not update minbstkref and minbargref
ida_hexrays.CPBLK_MINREF
update minbstkref and minbargref
ida_hexrays.CPBLK_OPTJMP
del the jump insn at the end of the block if it becomes useless
ida_hexrays.INLINE_EXTFRAME
Inlined function has its own (external) frame.
ida_hexrays.INLINE_DONTCOPY
Do not reuse old inlined copy even if it exists.
classida_hexrays.chain_keeper_t(_gc:graph_chains_t)
Bases: `object`
thisownfront()→block_chains_t&back()→block_chains_t&for_all_chains(cv:chain_visitor_t, gca:int)→intida_hexrays.GC_REGS_AND_STKVARS
registers and stkvars (restricted memory only)
ida_hexrays.GC_ASR
all the above and assertions
ida_hexrays.GC_XDSU
only registers calculated with FULL_XDSU
ida_hexrays.GC_END
number of chain types
ida_hexrays.GC_DIRTY_ALL
bitmask to represent all chains
classida_hexrays.mbl_graph_t(*args, **kwargs)
Bases: `simple_graph_t`
thisownis_ud_chain_dirty(gctype:gctype_t)→bool
Is the use-def chain of the specified kind dirty?
is_du_chain_dirty(gctype:gctype_t)→bool
Is the def-use chain of the specified kind dirty?
get_chain_stamp()→intget_ud(gctype:gctype_t)→graph_chains_t*
Get use-def chains.
get_du(gctype:gctype_t)→graph_chains_t*
Get def-use chains.
is_redefined_globally(*args)→bool
Is LIST redefined in the graph?
is_used_globally(*args)→bool
Is LIST used in the graph?
get_mblock(n:int)→mblock_t*classida_hexrays.cdg_insn_iterator_t(*args)
Bases: `object`
thisownmba:mba_tconst*ea:ida_idaapi.ea_tend:ida_idaapi.ea_tdslot:ida_idaapi.ea_tdslot_insn:insn_tsevered_branch:ida_idaapi.ea_tis_likely_dslot:boolok()→boolhas_dslot()→booldslot_with_xrefs()→boolis_severed_dslot()→boolstart(rng:range_t)→Nonenext(ins:insn_t*)→merror_tclassida_hexrays.codegen_t(*args, **kwargs)
Bases: `object`
thisownmba:mba_t*mb:mblock_t*insn:insn_tignore_micro:charii:cdg_insn_iterator_tclear()→Noneanalyze_prolog(fc:qflow_chart_t, reachable:bitset_t)→merror_t
Analyze prolog/epilog of the function to decompile. If prolog is found, allocate and fill ‘mba->pi’ structure.
Parameters:

-
fc – flow chart

-
reachable – bitmap of reachable blocks

Returns:
error code
gen_micro()→merror_t
Generate microcode for one instruction. The instruction is in INSN
Returns:
MERR_OK - all ok MERR_BLOCK - all ok, need to switch to new block MERR_BADBLK - delete current block and continue other error codes are fatal
load_operand(opnum:int, flags:int=0)→mreg_t
Generate microcode to load one operand.
Parameters:

-
opnum – number of INSN operand

-
flags – reserved for future use

Returns:
register containing the operand.
microgen_completed()→None
This method is called when the microcode generation is done.
prepare_gen_micro()→merror_t
Setup internal data to handle new instruction. This method should be called before calling gen_micro(). Usually gen_micro() is called by the decompiler. You have to call this function explicitly only if you yourself call gen_micro(). The instruction is in INSN
Returns:
MERR_OK - all ok other error codes are fatal
load_effective_address(n:int, flags:int=0)→mreg_t
Generate microcode to calculate the address of a memory operand.
Parameters:

-
n –

-
number of INSN operand

-
flags –

-
reserved for future use

Returns:
register containing the operand address. mr_none - failed (not a memory operand)
store_operand(n:int, mop:mop_t, flags:int=0, outins:minsn_t**=None)→bool
Generate microcode to store an operand. In case of success an arbitrary number of instructions can be generated (and even no instruction if the source and target are the same)
Parameters:

-
n –

-
number of target INSN operand

-
mop –

-
operand to be stored

-
flags –

-
reserved for future use

-
outins –

-
(OUT) the last generated instruction

Returns:
success
emit_micro_mvm(code:mcode_t, dtype:op_dtype_t, l:int, r:int, d:int, offsize:int)→minsn_t*
Emit one microinstruction. This variant takes a data type not a size.
emit(*args)→minsn_t*
This function has the following signatures:

-
emit(code: mcode_t, width: int, l: int, r: int, d: int, offsize: int) -> minsn_t *

-
emit(code: mcode_t, l: const mop_t *, r: const mop_t *, d: const mop_t *) -> minsn_t *

# 0: emit(code: mcode_t, width: int, l: int, r: int, d: int, offsize: int) -> minsn_t *

Emit one microinstruction. The L, R, D arguments usually mean the register number. However, they depend on CODE. For example: * for m_goto and m_jcnd L is the target address * for m_ldc L is the constant value to load
Returns:
created microinstruction. can be nullptr if the instruction got immediately optimized away.

# 1: emit(code: mcode_t, l: const mop_t *, r: const mop_t *, d: const mop_t *) -> minsn_t *

Emit one microinstruction. This variant accepts pointers to operands. It is more difficult to use but permits to create virtually any instruction. Operands may be nullptr when it makes sense. The ownership of the operands is not transferred to the decompiler, so it is ok to destroy them after this call.
ida_hexrays.change_hexrays_config(directive:str)→bool
Parse DIRECTIVE and update the current configuration variables. For the syntax see hexrays.cfg
ida_hexrays.get_hexrays_version()→str
Get decompiler version. The returned string is of the form ...
Returns:
pointer to version string. For example: “2.0.0.140605”
ida_hexrays.OPF_REUSE
reuse existing window
ida_hexrays.OPF_NEW_WINDOW
open new window
ida_hexrays.OPF_REUSE_ACTIVE
reuse existing window, only if the currently active widget is a pseudocode view
ida_hexrays.OPF_NO_WAIT
do not display waitbox if decompilation happens
ida_hexrays.OPF_WINDOW_MGMT_MASKida_hexrays.open_pseudocode(ea:ida_idaapi.ea_t, flags:int)→vdui_t*
Open pseudocode window. The specified function is decompiled and the pseudocode window is opened.
Parameters:

-
ea – function to decompile

-
flags – a combination of OPF_ flags

Returns:
false if failed
ida_hexrays.close_pseudocode(f:TWidget*)→bool
Close pseudocode window.
Parameters:
f – pointer to window
Returns:
false if failed
ida_hexrays.VDRUN_NEWFILE
Create a new file or overwrite existing file.
ida_hexrays.VDRUN_APPEND
Create a new file or append to existing file.
ida_hexrays.VDRUN_ONLYNEW
Fail if output file already exists.
ida_hexrays.VDRUN_SILENT
Silent decompilation.
ida_hexrays.VDRUN_SENDIDB
Send problematic databases to hex-rays.com.
ida_hexrays.VDRUN_MAYSTOP
The user can cancel decompilation.
ida_hexrays.VDRUN_CMDLINE
Called from ida’s command line.
ida_hexrays.VDRUN_STATS
Print statistics into vd_stats.txt.
ida_hexrays.VDRUN_LUMINA
Use lumina server.
ida_hexrays.VDRUN_PERF
Print performance stats to ida.log.
ida_hexrays.decompile_many(outfile:str, funcaddrs:uint64vec_t, flags:int)→bool
Batch decompilation. Decompile all or the specified functions
Parameters:

-
outfile – name of the output file

-
funcaddrs – list of functions to decompile. If nullptr or empty, then decompile all nonlib functions

-
flags – Batch decompilation bits

Returns:
true if no internal error occurred and the user has not cancelled decompilation
ida_hexrays.send_database(err:hexrays_failure_t, silent:bool)→None
Send the database to Hex-Rays. This function sends the current database to the Hex-Rays server. The database is sent in the compressed form over an encrypted (SSL) connection.
Parameters:

-
err – failure description object. Empty hexrays_failure_t object can be used if error information is not available.

-
silent – if false, a dialog box will be displayed before sending the database.

classida_hexrays.gco_info_t
Bases: `object`
thisownname:str
register or stkvar name
stkoff:int
if stkvar, stack offset
regnum:int
if register, the register id
size:int
operand size
flags:intis_reg()→boolis_use()→boolis_def()→boolappend_to_list(list:mlist_t, mba:mba_t)→bool
Append operand info to LIST. This function converts IDA register number or stack offset to a decompiler list.
Parameters:

-
list – list to append to

-
mba – microcode object

cvt_to_ivl()→vivl_t
Convert operand info to VIVL. The returned VIVL can be used, for example, in a call of get_valranges().
ida_hexrays.GCO_STK
a stack variable
ida_hexrays.GCO_REG
is register? otherwise a stack variable
ida_hexrays.GCO_USE
is source operand?
ida_hexrays.GCO_DEF
is destination operand?
ida_hexrays.get_current_operand(out:gco_info_t)→bool
Get the instruction operand under the cursor. This function determines the operand that is under the cursor in the active disassembly listing. If the operand refers to a register or stack variable, it returns true.
ida_hexrays.remitem(e:citem_t)→Noneida_hexrays.cot_emptyida_hexrays.cot_comma
x, y
ida_hexrays.cot_asg
x = y
ida_hexrays.cot_asgbor
x |= y
ida_hexrays.cot_asgxor
x ^= y
ida_hexrays.cot_asgband
x &= y
ida_hexrays.cot_asgadd
x += y
ida_hexrays.cot_asgsub
x -= y
ida_hexrays.cot_asgmul
x *= y
ida_hexrays.cot_asgsshr
x >>= y signed
ida_hexrays.cot_asgushr
x >>= y unsigned
ida_hexrays.cot_asgshl
x <<= y
ida_hexrays.cot_asgsdiv
x /= y signed
ida_hexrays.cot_asgudiv
x /= y unsigned
ida_hexrays.cot_asgsmod
x %= y signed
ida_hexrays.cot_asgumod
x %= y unsigned
ida_hexrays.cot_tern
x ? y : z
ida_hexrays.cot_lor
x || y
ida_hexrays.cot_land
x && y
ida_hexrays.cot_bor
x | y
ida_hexrays.cot_xor
x ^ y
ida_hexrays.cot_band
x & y
ida_hexrays.cot_eq
x == y int or fpu (see EXFL_FPOP)
ida_hexrays.cot_ne
x != y int or fpu (see EXFL_FPOP)
ida_hexrays.cot_sge
x >= y signed or fpu (see EXFL_FPOP)
ida_hexrays.cot_uge
x >= y unsigned
ida_hexrays.cot_sle
x <= y signed or fpu (see EXFL_FPOP)
ida_hexrays.cot_ule
x <= y unsigned
ida_hexrays.cot_sgt
x > y signed or fpu (see EXFL_FPOP)
ida_hexrays.cot_ugt
x > y unsigned
ida_hexrays.cot_slt
x < y signed or fpu (see EXFL_FPOP)
ida_hexrays.cot_ult
x < y unsigned
ida_hexrays.cot_sshr
x >> y signed
ida_hexrays.cot_ushr
x >> y unsigned
ida_hexrays.cot_shl
x << y
ida_hexrays.cot_add
x + y
ida_hexrays.cot_sub
x - y
ida_hexrays.cot_mul
x * y
ida_hexrays.cot_sdiv
x / y signed
ida_hexrays.cot_udiv
x / y unsigned
ida_hexrays.cot_smod
x % y signed
ida_hexrays.cot_umod
x % y unsigned
ida_hexrays.cot_fadd
x + y fp
ida_hexrays.cot_fsub
x - y fp
ida_hexrays.cot_fmul
x * y fp
ida_hexrays.cot_fdiv
x / y fp
ida_hexrays.cot_fneg
-x fp
ida_hexrays.cot_neg
-x
ida_hexrays.cot_cast
(type)x
ida_hexrays.cot_lnot
!x
ida_hexrays.cot_bnot
~x
ida_hexrays.cot_ptr
*x, access size in ‘ptrsize’
ida_hexrays.cot_ref
&x
ida_hexrays.cot_postinc
x++
ida_hexrays.cot_postdec
x-
ida_hexrays.cot_preinc
++x
ida_hexrays.cot_predec
-x
ida_hexrays.cot_call
x(…)
ida_hexrays.cot_idx
x[y]
ida_hexrays.cot_memref
x.m
ida_hexrays.cot_memptr
x->m, access size in ‘ptrsize’
ida_hexrays.cot_num
n
ida_hexrays.cot_fnum
fpc
ida_hexrays.cot_str
string constant (user representation)
ida_hexrays.cot_obj
obj_ea
ida_hexrays.cot_var
v
ida_hexrays.cot_insn
instruction in expression, internal representation only
ida_hexrays.cot_sizeof
sizeof(x)
ida_hexrays.cot_helper
arbitrary name
ida_hexrays.cot_type
arbitrary type
ida_hexrays.cot_lastida_hexrays.cit_empty
instruction types start here
ida_hexrays.cit_block
block-statement: { … }
ida_hexrays.cit_expr
expression-statement: expr;
ida_hexrays.cit_if
if-statement
ida_hexrays.cit_for
for-statement
ida_hexrays.cit_while
while-statement
ida_hexrays.cit_do
do-statement
ida_hexrays.cit_switch
switch-statement
ida_hexrays.cit_break
break-statement
ida_hexrays.cit_continue
continue-statement
ida_hexrays.cit_return
return-statement
ida_hexrays.cit_goto
goto-statement
ida_hexrays.cit_asm
asm-statement
ida_hexrays.cit_try
C++ try-statement.
ida_hexrays.cit_throw
C++ throw-statement.
ida_hexrays.cit_endida_hexrays.negated_relation(op:ctype_t)→ctype_t
Negate a comparison operator. For example, cot_sge becomes cot_slt.
ida_hexrays.swapped_relation(op:ctype_t)→ctype_t
Swap a comparison operator. For example, cot_sge becomes cot_sle.
ida_hexrays.get_op_signness(op:ctype_t)→type_sign_t
Get operator sign. Meaningful for sign-dependent operators, like cot_sdiv.
ida_hexrays.asgop(cop:ctype_t)→ctype_t
Convert plain operator into assignment operator. For example, cot_add returns cot_asgadd.
ida_hexrays.asgop_revert(cop:ctype_t)→ctype_t
Convert assignment operator into plain operator. For example, cot_asgadd returns cot_add
Returns:
cot_empty is the input operator is not an assignment operator.
ida_hexrays.op_uses_x(op:ctype_t)→bool
Does operator use the ‘x’ field of cexpr_t?
ida_hexrays.op_uses_y(op:ctype_t)→bool
Does operator use the ‘y’ field of cexpr_t?
ida_hexrays.op_uses_z(op:ctype_t)→bool
Does operator use the ‘z’ field of cexpr_t?
ida_hexrays.is_binary(op:ctype_t)→bool
Is binary operator?
ida_hexrays.is_unary(op:ctype_t)→bool
Is unary operator?
ida_hexrays.is_relational(op:ctype_t)→bool
Is comparison operator?
ida_hexrays.is_assignment(op:ctype_t)→bool
Is assignment operator?
ida_hexrays.accepts_udts(op:ctype_t)→boolida_hexrays.is_prepost(op:ctype_t)→bool
Is pre/post increment/decrement operator?
ida_hexrays.is_commutative(op:ctype_t)→bool
Is commutative operator?
ida_hexrays.is_additive(op:ctype_t)→bool
Is additive operator?
ida_hexrays.is_multiplicative(op:ctype_t)→bool
Is multiplicative operator?
ida_hexrays.is_bitop(op:ctype_t)→bool
Is bit related operator?
ida_hexrays.is_logical(op:ctype_t)→bool
Is logical operator?
ida_hexrays.is_loop(op:ctype_t)→bool
Is loop statement code?
ida_hexrays.is_break_consumer(op:ctype_t)→bool
Does a break statement influence the specified statement code?
ida_hexrays.is_lvalue(op:ctype_t)→bool
Is Lvalue operator?
ida_hexrays.accepts_small_udts(op:ctype_t)→bool
Is the operator allowed on small structure or union?
classida_hexrays.cnumber_t(_opnum:int=0)
Bases: `object`
thisownnf:number_format_t
how to represent it
value(type:tinfo_t)→uint64
Get value. This function will properly extend the number sign to 64bits depending on the type sign.
assign(v:uint64, nbytes:int, sign:type_sign_t)→None
Assign new value
Parameters:

-
v – new value

-
nbytes – size of the new value in bytes

-
sign – sign of the value

compare(r:cnumber_t)→intclassida_hexrays.var_ref_t
Bases: `object`
thisownmba:mba_t*
pointer to the underlying micro array
idx:int
index into lvars_t
compare(r:var_ref_t)→intida_hexrays.CMAT_ZERO
does not exist
ida_hexrays.CMAT_BUILT
just generated
ida_hexrays.CMAT_TRANS1
applied first wave of transformations
ida_hexrays.CMAT_NICE
nicefied expressions
ida_hexrays.CMAT_TRANS2
applied second wave of transformations
ida_hexrays.CMAT_CPA
corrected pointer arithmetic
ida_hexrays.CMAT_TRANS3
applied third wave of transformations
ida_hexrays.CMAT_CASTED
added necessary casts
ida_hexrays.CMAT_FINAL
ready-to-use
ida_hexrays.ITP_EMPTY
nothing
ida_hexrays.ITP_ARG1
, (64 entries are reserved for 64 call arguments)
ida_hexrays.ITP_ARG64ida_hexrays.ITP_BRACE1ida_hexrays.ITP_INNER_LASTida_hexrays.ITP_ASM
__asm-line
ida_hexrays.ITP_ELSE
else-line
ida_hexrays.ITP_DO
do-line
ida_hexrays.ITP_SEMI
semicolon
ida_hexrays.ITP_CURLY1
{
ida_hexrays.ITP_CURLY2
}
ida_hexrays.ITP_BRACE2
)
ida_hexrays.ITP_COLON
: (label)
ida_hexrays.ITP_BLOCK1
opening block comment. this comment is printed before the item (other comments are indented and printed after the item)
ida_hexrays.ITP_BLOCK2
closing block comment.
ida_hexrays.ITP_TRY
C++ try statement.
ida_hexrays.ITP_CASE
bit for switch cases
ida_hexrays.ITP_SIGN
if this bit is set too, then we have a negative case value
classida_hexrays.treeloc_t
Bases: `object`
thisownea:ida_idaapi.ea_titp:item_preciser_tida_hexrays.RETRIEVE_ONCE
Retrieve comment if it has not been used yet.
ida_hexrays.RETRIEVE_ALWAYS
Retrieve comment even if it has been used.
classida_hexrays.citem_cmt_t(*args)
Bases: `object`
thisownused:bool
the comment has been retrieved?
c_str()→strclassida_hexrays.citem_locator_t(*args)
Bases: `object`
thisownea:ida_idaapi.ea_t
citem address
op:ctype_t
citem operation
compare(r:citem_locator_t)→intclassida_hexrays.bit_bound_t(n:int=0, s:int=0)
Bases: `object`
thisownnbits:int16sbits:int16classida_hexrays.citem_t(o:ctype_t=cot_empty)
Bases: `object`
thisownea:ida_idaapi.ea_t
address that corresponds to the item. may be BADADDR
label_num:int
label number. -1 means no label. items of the expression types (cot_…) should not have labels at the final maturity level, but at the intermediate levels any ctree item may have a label. Labels must be unique. Usually they correspond to the basic block numbers.
index:int
an index in cfunc_t::treeitems. meaningful only after print_func()
swap(r:citem_t)→None
Swap two citem_t.
is_expr()→bool
Is an expression?
contains_expr(e:cexpr_t)→bool
Does the item contain an expression?
contains_label()→bool
Does the item contain a label?
find_parent_of(item:citem_t)→citem_t*
Find parent of the specified item.
Parameters:
item – Item to find the parent of. The search will be performed among the children of the item pointed by this.
Returns:
nullptr if not found
find_closest_addr(_ea:ida_idaapi.ea_t)→citem_t*print1(func:cfunc_t)→None
Print item into one line.
Parameters:
func – parent function. This argument is used to find out the referenced variable names.
Returns:
length of the generated text.
cinsn:cinsn_t*constcexpr:cexpr_t*constop
item type
obj_idreplace_by(o)meminfoclassida_hexrays.cexpr_t(*args)
Bases: `citem_t`
thisowntype:tinfo_t
expression type. must be carefully maintained
exflags:int
Expression attributes
cpadone()→bool
Pointer arithmetic correction done for this expression?
is_odd_lvalue()→boolis_fpop()→boolis_cstr()→boolis_undef_val()→boolis_jumpout()→boolis_vftable()→boolset_cpadone()→Noneset_vftable()→Noneswap(r:cexpr_t)→None
Swap two citem_t.
assign(r:cexpr_t)→cexpr_t&compare(r:cexpr_t)→intcleanup()→None
Cleanup the expression. This function properly deletes all children and sets the item type to cot_empty.
put_number(*args)→None
Assign a number to the expression.
Parameters:

-
func – current function

-
value – number value

-
nbytes – size of the number in bytes

-
sign – number sign

print1(func:cfunc_t)→None
Print expression into one line.
Parameters:
func – parent function. This argument is used to find out the referenced variable names.
calc_type(recursive:bool)→None
Calculate the type of the expression. Use this function to calculate the expression type when a new expression is built
Parameters:
recursive – if true, types of all children expression will be calculated before calculating our type
equal_effect(r:cexpr_t)→bool
Compare two expressions. This function tries to compare two expressions in an ‘intelligent’ manner. For example, it knows about commutitive operators and can ignore useless casts.
Parameters:
r – the expression to compare against the current expression
Returns:
true expressions can be considered equal
is_child_of(parent:citem_t)→bool
Verify if the specified item is our parent.
Parameters:
parent – possible parent item
Returns:
true if the specified item is our parent
contains_operator(needed_op:ctype_t, times:int=1)→bool
Check if the expression contains the specified operator.
Parameters:

-
needed_op – operator code to search for

-
times – how many times the operator code should be present

Returns:
true if the expression has at least TIMES children with NEEDED_OP
contains_comma(times:int=1)→bool
Does the expression contain a comma operator?
contains_insn(times:int=1)→bool
Does the expression contain an embedded statement operator?
contains_insn_or_label()→bool
Does the expression contain an embedded statement operator or a label?
contains_comma_or_insn_or_label(maxcommas:int=1)→bool
Does the expression contain a comma operator or an embedded statement operator or a label?
is_nice_expr()→bool
Is nice expression? Nice expressions do not contain comma operators, embedded statements, or labels.
is_nice_cond()→bool
Is nice condition?. Nice condition is a nice expression of the boolean type.
is_call_object_of(parent:citem_t)→bool
Is call object?
Returns:
true if our expression is the call object of the specified parent expression.
is_call_arg_of(parent:citem_t)→bool
Is call argument?
Returns:
true if our expression is a call argument of the specified parent expression.
get_type_sign()→type_sign_t
Get expression sign.
is_type_unsigned()→bool
Is expression unsigned?
is_type_signed()→bool
Is expression signed?
get_high_nbit_bound()→bit_bound_t
Get max number of bits that can really be used by the expression. For example, x % 16 can yield only 4 non-zero bits, higher bits are zero
get_low_nbit_bound()→int
Get min number of bits that are certainly required to represent the expression. For example, constant 16 always uses 5 bits: 10000.
requires_lvalue(child:cexpr_t)→bool
Check if the expression requires an lvalue.
Parameters:
child – The function will check if this child of our expression must be an lvalue.
Returns:
true if child must be an lvalue.
has_side_effects()→bool
Check if the expression has side effects. Calls, pre/post inc/dec, and assignments have side effects.
numval()→uint64
Get numeric value of the expression. This function can be called only on cot_num expressions!
is_const_value(_v:uint64)→bool
Check if the expression is a number with the specified value.
is_negative_const()→bool
Check if the expression is a negative number.
is_non_negative_const()→bool
Check if the expression is a non-negative number.
is_non_zero_const()→bool
Check if the expression is a non-zero number.
is_zero_const()→bool
Check if the expression is a zero.
get_const_value()→bool
Get expression value.
Returns:
true if the expression is a number.
maybe_ptr()→bool
May the expression be a pointer?
get_ptr_or_array()→cexpr_t*
Find pointer or array child.
find_op(_op:ctype_t)→cexpr_t*
Find the child with the specified operator.
find_num_op()→cexpr_t*
Find the operand with a numeric value.
theother(what:cexpr_t)→cexpr_t*
Get the other operand. This function returns the other operand (not the specified one) for binary expressions.
get_1num_op(o1:cexpr_t**, o2:cexpr_t**)→bool
Get pointers to operands. at last one operand should be a number o1 will be pointer to the number
dstr()→strget_v()→var_ref_t*set_v(v:var_ref_t)→Nonev
used for cot_var
propertynpropertyfpcpropertyxpropertyypropertyzpropertyapropertyinsnpropertympropertyptrsizepropertyobj_eapropertyrefwidthpropertyhelperpropertystringida_hexrays.EXFL_CPADONE
pointer arithmetic correction done
ida_hexrays.EXFL_LVALUE
expression is lvalue even if it doesn’t look like it
ida_hexrays.EXFL_FPOP
floating point operation
ida_hexrays.EXFL_ALONE
standalone helper
ida_hexrays.EXFL_CSTR
string literal
ida_hexrays.EXFL_PARTIAL
type of the expression is considered partial
ida_hexrays.EXFL_UNDEF
expression uses undefined value
ida_hexrays.EXFL_JUMPOUT
jump out-of-function
ida_hexrays.EXFL_VFTABLE
is ptr to vftable (used for cot_memptr, cot_memref)
ida_hexrays.EXFL_ALL
all currently defined bits
classida_hexrays.ceinsn_t
Bases: `object`
thisownexpr:cexpr_t
Expression of the statement.
ida_hexrays.CALC_CURLY_BRACES
print curly braces if necessary
ida_hexrays.NO_CURLY_BRACES
don’t print curly braces
ida_hexrays.USE_CURLY_BRACES
print curly braces without any checks
classida_hexrays.cif_t(*args)
Bases: `ceinsn_t`
thisownithen:cinsn_t*
Then-branch of the if-statement.
ielse:cinsn_t*
Else-branch of the if-statement. May be nullptr.
assign(r:cif_t)→cif_t&compare(r:cif_t)→intcleanup()→Noneclassida_hexrays.cloop_t(*args)
Bases: `ceinsn_t`
thisownbody:cinsn_t*assign(r:cloop_t)→cloop_t&cleanup()→Noneclassida_hexrays.cfor_t
Bases: `cloop_t`
thisowninit:cexpr_t
Initialization expression.
step:cexpr_t
Step expression.
compare(r:cfor_t)→intclassida_hexrays.cwhile_t
Bases: `cloop_t`
thisowncompare(r:cwhile_t)→intclassida_hexrays.cdo_t
Bases: `cloop_t`
thisowncompare(r:cdo_t)→intclassida_hexrays.creturn_t
Bases: `ceinsn_t`
thisowncompare(r:creturn_t)→intclassida_hexrays.cgoto_t
Bases: `object`
thisownlabel_num:int
Target label number.
compare(r:cgoto_t)→intclassida_hexrays.casm_t(*args)
Bases: `ida_pro.eavec_t`
thisowncompare(r:casm_t)→intone_insn()→boolclassida_hexrays.cinsn_t(*args)
Bases: `citem_t`
thisownctry:ctry_t*
details of try-statement
cthrow:cthrow_t*
details of throw-statement
swap(r:cinsn_t)→None
Swap two citem_t.
assign(r:cinsn_t)→cinsn_t&compare(r:cinsn_t)→intcleanup()→None
Cleanup the statement. This function properly deletes all children and sets the item type to cit_empty.
zero()→None
Overwrite with zeroes without cleaning memory or deleting children.
new_insn(insn_ea:ida_idaapi.ea_t)→cinsn_t&
Create a new statement. The current statement must be a block. The new statement will be appended to it.
Parameters:
insn_ea – statement address
create_if(cnd:cexpr_t)→cif_t&
Create a new if-statement. The current statement must be a block. The new statement will be appended to it.
Parameters:
cnd – if condition. It will be deleted after being copied.
print1(func:cfunc_t)→None
Print the statement into one line. Currently this function is not available.
Parameters:
func – parent function. This argument is used to find out the referenced variable names.
is_ordinary_flow()→bool
Check if the statement passes execution to the next statement.
Returns:
false if the statement breaks the control flow (like goto, return, etc)
contains_insn(type:ctype_t, times:int=1)→bool
Check if the statement contains a statement of the specified type.
Parameters:

-
type – statement opcode to look for

-
times – how many times TYPE should be present

Returns:
true if the statement has at least TIMES children with opcode == TYPE
collect_free_breaks(breaks:cinsnptrvec_t)→bool
Collect free break statements. This function finds all free break statements within the current statement. A break statement is free if it does not have a loop or switch parent that that is also within the current statement.
Parameters:
breaks – pointer to the variable where the vector of all found free break statements is returned. This argument can be nullptr.
Returns:
true if some free break statements have been found
collect_free_continues(continues:cinsnptrvec_t)→bool
Collect free continue statements. This function finds all free continue statements within the current statement. A continue statement is free if it does not have a loop parent that that is also within the current statement.
Parameters:
continues – pointer to the variable where the vector of all found free continue statements is returned. This argument can be nullptr.
Returns:
true if some free continue statements have been found
contains_free_break()→bool
Check if the statement has free break statements.
contains_free_continue()→bool
Check if the statement has free continue statements.
dstr()→strstaticinsn_is_epilog(insn:cinsn_t)→boolis_epilog()propertycblockpropertycexprpropertycifpropertycforpropertycwhilepropertycdopropertycswitchpropertycreturnpropertycgotopropertycasmclassida_hexrays.cblock_t
Bases: `cinsn_list_t`
thisowncompare(r:cblock_t)→intclassida_hexrays.carg_t
Bases: `cexpr_t`
thisownis_vararg:bool
is a vararg (matches …)
formal_type:tinfo_t
formal parameter type (if known)
consume_cexpr(e:cexpr_t)→Nonecompare(r:carg_t)→intclassida_hexrays.carglist_t(*args)
Bases: `qvector_carg_t`
thisownfunctype:tinfo_t
function object type
flags:int
call flags
compare(r:carglist_t)→intida_hexrays.CFL_FINAL
call type is final, should not be changed
ida_hexrays.CFL_HELPER
created from a decompiler helper function
ida_hexrays.CFL_NORET
call does not return
classida_hexrays.ccase_t
Bases: `cinsn_t`
thisownvalues:uint64vec_t
List of case values. if empty, then ‘default’ case
compare(r:ccase_t)→intsize()→intvalue(i:int)→uint64const&classida_hexrays.ccases_t
Bases: `qvector_ccase_t`
thisowncompare(r:ccases_t)→intclassida_hexrays.cswitch_t
Bases: `ceinsn_t`
thisownmvnf:cnumber_t
Maximal switch value and number format.
cases:ccases_t
Switch cases: values and instructions.
compare(r:cswitch_t)→intclassida_hexrays.catchexpr_t
Bases: `object`
thisownobj:cexpr_t
the caught object. if obj.op==cot_empty, no object. ideally, obj.op==cot_var
fake_type:str
if not empty, type of the caught object. ideally, obj.type should be enough. however, in some cases the detailed type info is not available.
compare(r:catchexpr_t)→intswap(r:catchexpr_t)→Noneis_catch_all()→boolclassida_hexrays.ccatch_t(*args, **kwargs)
Bases: `cblock_t`
thisownexprs:catchexprs_tcompare(r:ccatch_t)→intis_catch_all()→boolswap(r:ccatch_t)→Noneclassida_hexrays.ctry_t(*args, **kwargs)
Bases: `cblock_t`
thisowncatchs:ccatchvec_t
“catch all”, if present, must be the last element. wind-statements must have “catch all” and nothing else.
old_state:int
old state number (internal, MSVC related)
new_state:int
new state number (internal, MSVC related)
is_wind:bool
Is C++ wind statement? (not part of the C++ language) MSVC generates code like the following to keep track of constructed objects and destroy them upon an exception. Example: // an object is constructed at this point __wind { // some other code that may throw an exception } __unwind { // this code is executed only if there was an exception // in the __wind block. normally here we destroy the object // after that the exception is passed to the // exception handler, regular control flow is interrupted here. } // regular logic continues here, if there were no exceptions // also the object’s destructor is called
compare(r:ctry_t)→intclassida_hexrays.cthrow_t
Bases: `ceinsn_t`
thisowncompare(r:cthrow_t)→intclassida_hexrays.cblock_pos_t
Bases: `object`
thisownblk:cblock_t*p:cblock_t::iteratoris_first_insn()→boolinsn()→cinsn_t*prev_insn()→cinsn_t*classida_hexrays.ctree_visitor_t(_flags:int)
Bases: `object`
thisowncv_flags:int
Ctree visitor property bits
maintain_parents()→bool
Should the parent information by maintained?
must_prune()→bool
Should the traversal skip the children of the current item?
must_restart()→bool
Should the traversal restart?
is_postorder()→bool
Should the leave…() functions be called?
only_insns()→bool
Should all expressions be automatically pruned?
prune_now()→None
Prune children. This function may be called by a visitor() to skip all children of the current item.
clr_prune()→None
Do not prune children. This is an internal function, no need to call it.
set_restart()→None
Restart the travesal. Meaningful only in apply_to_exprs()
clr_restart()→None
Do not restart. This is an internal function, no need to call it.
parents:parents_t
Vector of parents of the current item.
bposvec:cblock_posvec_t
Vector of block positions. Only cit_block and cit_try parents have the corresponding element in this vector.
apply_to(item:citem_t, parent:citem_t)→int
Traverse ctree. The traversal will start at the specified item and continue until of one the visit_…() functions return a non-zero value.
Parameters:

-
item – root of the ctree to traverse

-
parent – parent of the specified item. can be specified as nullptr.

Returns:
0 or a non-zero value returned by a visit_…() function
apply_to_exprs(item:citem_t, parent:citem_t)→int
Traverse only expressions. The traversal will start at the specified item and continue until of one the visit_…() functions return a non-zero value.
Parameters:

-
item – root of the ctree to traverse

-
parent – parent of the specified item. can be specified as nullptr.

Returns:
0 or a non-zero value returned by a visit_…() function
parent_item()→citem_t*
Get parent of the current item as an item (statement or expression)
parent_expr()→cexpr_t*
Get parent of the current item as an expression.
parent_insn()→cinsn_t*
Get parent of the current item as a statement.
visit_insn(arg0:cinsn_t)→int
Visit a statement. This is a visitor function which should be overridden by a derived class to do some useful work. This visitor performs pre-order traserval, i.e. an item is visited before its children.
Returns:
0 to continue the traversal, nonzero to stop.
visit_expr(arg0:cexpr_t)→int
Visit an expression. This is a visitor function which should be overridden by a derived class to do some useful work. This visitor performs pre-order traserval, i.e. an item is visited before its children.
Returns:
0 to continue the traversal, nonzero to stop.
leave_insn(arg0:cinsn_t)→int
Visit a statement after having visited its children. This is a visitor function which should be overridden by a derived class to do some useful work. This visitor performs post-order traserval, i.e. an item is visited after its children.
Returns:
0 to continue the traversal, nonzero to stop.
leave_expr(arg0:cexpr_t)→int
Visit an expression after having visited its children. This is a visitor function which should be overridden by a derived class to do some useful work. This visitor performs post-order traserval, i.e. an item is visited after its children.
Returns:
0 to continue the traversal, nonzero to stop.
ida_hexrays.CV_FAST
do not maintain parent information
ida_hexrays.CV_PRUNE
this bit is set by visit…() to prune the walk
ida_hexrays.CV_PARENTS
maintain parent information
ida_hexrays.CV_POST
call the leave…() functions
ida_hexrays.CV_RESTART
restart enumeration at the top expr (apply_to_exprs)
ida_hexrays.CV_INSNS
visit only statements, prune all expressions do not use before the final ctree maturity because expressions may contain statements at intermediate stages (see cot_insn). Otherwise you risk missing statements embedded into expressions.
classida_hexrays.ctree_parentee_t(post:bool=False)
Bases: `ctree_visitor_t`
thisownrecalc_parent_types()→bool
Recalculate type of parent nodes. If a node type has been changed, the visitor must recalculate all parent types, otherwise the ctree becomes inconsistent. If during this recalculation a parent node is added/deleted, this function returns true. In this case the traversal must be stopped because the information about parent nodes is stale.
Returns:
false-ok to continue the traversal, true-must stop.
classida_hexrays.cfunc_parentee_t(f:cfunc_t, post:bool=False)
Bases: `ctree_parentee_t`
thisownfunc:cfunc_t*
Pointer to current function.
calc_rvalue_type(target:tinfo_t, e:cexpr_t)→bool
Calculate rvalue type. This function tries to determine the type of the specified item based on its context. For example, if the current expression is the right side of an assignment operator, the type of its left side will be returned. This function can be used to determine the ‘best’ type of the specified expression.
Parameters:

-
target – ‘best’ type of the expression will be returned here

-
e – expression to determine the desired type

Returns:
false if failed
classida_hexrays.ctree_anchor_t
Bases: `object`
thisownvalue:intget_index()→intget_itp()→item_preciser_tis_valid_anchor()→boolis_citem_anchor()→boolis_lvar_anchor()→boolis_itp_anchor()→boolis_blkcmt_anchor()→boolida_hexrays.ANCHOR_INDEXida_hexrays.ANCHOR_MASKida_hexrays.ANCHOR_CITEM
c-tree item
ida_hexrays.ANCHOR_LVAR
declaration of local variable
ida_hexrays.ANCHOR_ITP
item type preciser
ida_hexrays.ANCHOR_BLKCMT
block comment (for ctree items)
ida_hexrays.VDI_NONE
undefined
ida_hexrays.VDI_EXPR
c-tree item
ida_hexrays.VDI_LVAR
declaration of local variable
ida_hexrays.VDI_FUNC
the function itself (the very first line with the function prototype)
ida_hexrays.VDI_TAIL
cursor is at (beyond) the line end (commentable line)
classida_hexrays.ctree_item_t
Bases: `object`
thisowncitype:cursor_item_type_t
Item type.
it:citem_t*e:cexpr_t*
VDI_EXPR: Expression.
i:cinsn_t*
VDI_EXPR: Statement.
l:lvar_t*
VDI_LVAR: Local variable.
f:cfunc_t*
VDI_FUNC: Function.
get_udm(udm:udm_t=None, parent:tinfo_t=None, p_offset:uint64*=None)→int
Get type of a structure field. If the current item is a structure/union field, this function will return information about it.
Parameters:

-
udm – pointer to buffer for the udt member info.

-
parent – pointer to buffer for the struct/union type.

-
p_offset – pointer to the offset in bits inside udt.

Returns:
member index or -1 if failed Both output parameters can be nullptr.
get_edm(parent:tinfo_t)→int
Get type of an enum member. If the current item is a symbolic constant, this function will return information about it.
Parameters:
parent – pointer to buffer for the enum type.
Returns:
member index or -1 if failed
get_lvar()→lvar_t*
Get pointer to local variable. If the current item is a local variable, this function will return pointer to its definition.
Returns:
nullptr if failed
get_ea()→ida_idaapi.ea_t
Get address of the current item. Each ctree item has an address.
Returns:
BADADDR if failed
get_label_num(gln_flags:int)→int
Get label number of the current item.
Parameters:
gln_flags – Combination of get_label_num control bits
Returns:
-1 if failed or no label
is_citem()→bool
Is the current item is a ctree item?
dstr()→strloc:treeloc_t*const
VDI_TAIL: Line tail.
ida_hexrays.GLN_CURRENT
get label of the current item
ida_hexrays.GLN_GOTO_TARGET
get goto target
ida_hexrays.GLN_ALL
get both
ida_hexrays.FORBID_UNUSED_LABELS
Unused labels cause interr.
ida_hexrays.ALLOW_UNUSED_LABELS
Unused labels are permitted.
ida_hexrays.save_user_labels(func_ea:ida_idaapi.ea_t, user_labels:user_labels_t, func:cfunc_t=None)→None
Save user defined labels into the database.
Parameters:

-
func_ea – the entry address of the function, ignored if FUNC != nullptr

-
user_labels – collection of user defined labels

-
func – pointer to current function, if FUNC != nullptr, then save labels using a more stable method that preserves them even when the decompiler output drastically changes

ida_hexrays.save_user_cmts(func_ea:ida_idaapi.ea_t, user_cmts:user_cmts_t)→None
Save user defined comments into the database.
Parameters:

-
func_ea – the entry address of the function

-
user_cmts – collection of user defined comments

ida_hexrays.save_user_numforms(func_ea:ida_idaapi.ea_t, numforms:user_numforms_t)→None
Save user defined number formats into the database.
Parameters:

-
func_ea – the entry address of the function

-
numforms – collection of user defined comments

ida_hexrays.save_user_iflags(func_ea:ida_idaapi.ea_t, iflags:user_iflags_t)→None
Save user defined citem iflags into the database.
Parameters:

-
func_ea – the entry address of the function

-
iflags – collection of user defined citem iflags

ida_hexrays.save_user_unions(func_ea:ida_idaapi.ea_t, unions:user_unions_t)→None
Save user defined union field selections into the database.
Parameters:

-
func_ea – the entry address of the function

-
unions – collection of union field selections

ida_hexrays.restore_user_labels(func_ea:ida_idaapi.ea_t, func:cfunc_t=None)→user_labels_t*
Restore user defined labels from the database.
Parameters:

-
func_ea – the entry address of the function, ignored if FUNC != nullptr

-
func – pointer to current function

Returns:
collection of user defined labels. The returned object must be deleted by the caller using delete_user_labels()
ida_hexrays.restore_user_cmts(func_ea:ida_idaapi.ea_t)→user_cmts_t*
Restore user defined comments from the database.
Parameters:
func_ea – the entry address of the function
Returns:
collection of user defined comments. The returned object must be deleted by the caller using delete_user_cmts()
ida_hexrays.restore_user_numforms(func_ea:ida_idaapi.ea_t)→user_numforms_t*
Restore user defined number formats from the database.
Parameters:
func_ea – the entry address of the function
Returns:
collection of user defined number formats. The returned object must be deleted by the caller using delete_user_numforms()
ida_hexrays.restore_user_iflags(func_ea:ida_idaapi.ea_t)→user_iflags_t*
Restore user defined citem iflags from the database.
Parameters:
func_ea – the entry address of the function
Returns:
collection of user defined iflags. The returned object must be deleted by the caller using delete_user_iflags()
ida_hexrays.restore_user_unions(func_ea:ida_idaapi.ea_t)→user_unions_t*
Restore user defined union field selections from the database.
Parameters:
func_ea – the entry address of the function
Returns:
collection of union field selections The returned object must be deleted by the caller using delete_user_unions()
classida_hexrays.cfunc_t(*args, **kwargs)
Bases: `object`
thisownentry_ea:ida_idaapi.ea_t
function entry address
mba:mba_t*
underlying microcode
body:cinsn_t
function body, must be a block
argidx:intvec_t&
list of arguments (indexes into vars)
maturity:ctree_maturity_t
maturity level
user_labels:user_labels_t*
user-defined labels.
user_cmts:user_cmts_t*
user-defined comments.
numforms:user_numforms_t*
user-defined number formats.
user_iflags:user_iflags_t*
user-defined item flags ctree item iflags bits
user_unions:user_unions_t*
user-defined union field selections.
refcnt:int
reference count to this object. use cfuncptr_t
statebits:int
current cfunc_t state. see cfunc state bits
hdrlines:int
number of lines in the declaration area
treeitems:citem_pointers_t
vector of pointers to citem_t objects (nodes constituting the ctree)
release()→Nonebuild_c_tree()→None
Generate the function body. This function (re)generates the function body from the underlying microcode.
verify(aul:allow_unused_labels_t, even_without_debugger:bool)→None
Verify the ctree. This function verifies the ctree. If the ctree is malformed, an internal error is generated. Use it to verify the ctree after your modifications.
Parameters:

-
aul – Are unused labels acceptable?

-
even_without_debugger – if false and there is no debugger, the verification will be skipped

print_dcl()→None
Print function prototype.
print_func(vp:vc_printer_t)→None
Print function text.
Parameters:
vp – printer helper class to receive the generated text.
get_func_type(type:tinfo_t)→bool
Get the function type.
Parameters:
type – variable where the function type is returned
Returns:
false if failure
get_lvars()→lvars_t*
Get vector of local variables.
Returns:
pointer to the vector of local variables. If you modify this vector, the ctree must be regenerated in order to have correct cast operators. Use build_c_tree() for that. Removing lvars should be done carefully: all references in ctree and microcode must be corrected after that.
get_stkoff_delta()→int
Get stack offset delta. The local variable stack offsets retrieved by v.location.stkoff() should be adjusted before being used as stack frame offsets in IDA.
Returns:
the delta to apply. example: ida_stkoff = v.location.stkoff() - f->get_stkoff_delta()
find_label(label:int)→citem_t*
Find the label.
Returns:
pointer to the ctree item with the specified label number.
remove_unused_labels()→None
Remove unused labels. This function checks what labels are really used by the function and removes the unused ones. You must call it after deleting a goto statement.
get_user_cmt(loc:treeloc_t, rt:cmt_retrieval_type_t)→str
Retrieve a user defined comment.
Parameters:

-
loc – ctree location

-
rt – should already retrieved comments retrieved again?

Returns:
pointer to the comment string or nullptr
set_user_cmt(loc:treeloc_t, cmt:str)→None
Set a user defined comment. This function stores the specified comment in the cfunc_t structure. The save_user_cmts() function must be called after it.
Parameters:

-
loc – ctree location

-
cmt – new comment. if empty or nullptr, then an existing comment is deleted.

get_user_iflags(loc:citem_locator_t)→int
Retrieve citem iflags.
Parameters:
loc – citem locator
Returns:
ctree item iflags bits or 0
set_user_iflags(loc:citem_locator_t, iflags:int)→None
Set citem iflags.
Parameters:

-
loc – citem locator

-
iflags – new iflags

has_orphan_cmts()→bool
Check if there are orphan comments.
del_orphan_cmts()→int
Delete all orphan comments. The save_user_cmts() function must be called after this call.
get_user_union_selection(ea:ida_idaapi.ea_t, path:intvec_t)→bool
Retrieve a user defined union field selection.
Parameters:

-
ea – address

-
path – out: path describing the union selection.

Returns:
pointer to the path or nullptr
set_user_union_selection(ea:ida_idaapi.ea_t, path:intvec_t)→None
Set a union field selection. The save_user_unions() function must be called after calling this function.
Parameters:

-
ea – address

-
path – in: path describing the union selection.

save_user_labels()→None
Save user-defined labels into the database.
save_user_cmts()→None
Save user-defined comments into the database.
save_user_numforms()→None
Save user-defined number formats into the database.
save_user_iflags()→None
Save user-defined iflags into the database.
save_user_unions()→None
Save user-defined union field selections into the database.
get_line_item(line:str, x:int, is_ctree_line:bool, phead:ctree_item_t, pitem:ctree_item_t, ptail:ctree_item_t)→bool
Get ctree item for the specified cursor position.
Parameters:

-
line – line of decompilation text (element of sv)

-
x – x cursor coordinate in the line

-
is_ctree_line – does the line belong to statement area? (if not, it is assumed to belong to the declaration area)

-
phead – ptr to the first item on the line (used to attach block comments). May be nullptr

-
pitem – ptr to the current item. May be nullptr

-
ptail – ptr to the last item on the line (used to attach indented comments). May be nullptr

Returns:
false if failed to get the current item
get_warnings()→hexwarns_t&
Get information about decompilation warnings.
Returns:
reference to the vector of warnings
get_eamap()→eamap_t&
Get pointer to ea->insn map. This function initializes eamap if not done yet.
get_boundaries()→boundaries_t&
Get pointer to map of instruction boundaries. This function initializes the boundary map if not done yet.
get_pseudocode()→strvec_tconst&
Get pointer to decompilation output: the pseudocode. This function generates pseudocode if not done yet.
refresh_func_ctext()→None
Refresh ctext after a ctree modification. This function informs the decompiler that ctree (body) have been modified and ctext (sv) does not correspond to it anymore. It also refreshes the pseudocode windows if there is any.
recalc_item_addresses()→None
Recalculate item adresses. This function may be required after shuffling ctree items. For example, when adding or removing statements of a block, or changing ‘if’ statements.
gather_derefs(ci:ctree_item_t, udm:udt_type_data_t=None)→boollocked()→boolserialize()→bool
Serialize cfunc into a sequence of bytes.
staticdeserialize(mba:mba_t, bytes:ucharconst*)→cfunc_t*
Deserialize a byte sequence into cfunc_t
Parameters:

-
mba – the matching mba object

-
bytes – pointer to the beginning of the byte sequence.

Returns:
new cfunc_t object
find_item_coords(*args)
This method has the following signatures:

-
find_item_coords(item: citem_t) -> Tuple[int, int]

-
find_item_coords(item: citem_t, x: int_pointer, y: int_pointer) -> bool

NOTE: The second form is retained for backward-compatibility, but we strongly recommend using the first.
Parameters:
item – The item to find coordinates for in the pseudocode listing
ida_hexrays.CIT_COLLAPSED
display ctree item in collapsed form
ida_hexrays.CFS_BOUNDS
‘eamap’ and ‘boundaries’ are ready
ida_hexrays.CFS_TEXT
‘sv’ is ready (and hdrlines)
ida_hexrays.CFS_LVARS_HIDDEN
local variable definitions are collapsed
ida_hexrays.CFS_LOCKED
cfunc is temporarily locked
ida_hexrays.DECOMP_NO_WAIT
do not display waitbox
ida_hexrays.DECOMP_NO_CACHE
do not use decompilation cache (snippets are never cached)
ida_hexrays.DECOMP_NO_FRAME
do not use function frame info (only snippet mode)
ida_hexrays.DECOMP_WARNINGS
display warnings in the output window
ida_hexrays.DECOMP_ALL_BLKS
generate microcode for unreachable blocks
ida_hexrays.DECOMP_NO_HIDE
do not close display waitbox. see close_hexrays_waitbox()
ida_hexrays.DECOMP_GXREFS_DEFLT
the default behavior: do not update the global xrefs cache upon decompile() call, but when the pseudocode text is generated (e.g., through cfunc_t.get_pseudocode())
ida_hexrays.DECOMP_GXREFS_NOUPD
do not update the global xrefs cache
ida_hexrays.DECOMP_GXREFS_FORCE
update the global xrefs cache immediately
ida_hexrays.DECOMP_VOID_MBA
return empty mba object (to be used with gen_microcode)
ida_hexrays.DECOMP_OUTLINE
generate code for an outline
ida_hexrays.close_hexrays_waitbox()→None
Close the waitbox displayed by the decompiler. Useful if DECOMP_NO_HIDE was used during decompilation.
ida_hexrays.decompile(mbr:mba_ranges_t, hf:hexrays_failure_t=None, decomp_flags:int=0)→cfuncptr_t
Decompile a snippet or a function.
Parameters:

-
mbr – what to decompile

-
hf – extended error information (if failed)

-
decomp_flags – bitwise combination of decompile() flags… bits

Returns:
pointer to the decompilation result (a reference counted pointer). nullptr if failed.
ida_hexrays.decompile_func(pfn:func_t*, hf:hexrays_failure_t=None, decomp_flags:int=0)→cfuncptr_t
Decompile a function. Multiple decompilations of the same function return the same object.
Parameters:

-
pfn – pointer to function to decompile

-
hf – extended error information (if failed)

-
decomp_flags – bitwise combination of decompile() flags… bits

Returns:
pointer to the decompilation result (a reference counted pointer). nullptr if failed.
ida_hexrays.gen_microcode(mbr:mba_ranges_t, hf:hexrays_failure_t=None, retlist:mlist_t=None, decomp_flags:int=0, reqmat:mba_maturity_t=MMAT_GLBOPT3)→mba_t*
Generate microcode of an arbitrary code snippet
Parameters:

-
mbr – snippet ranges

-
hf – extended error information (if failed)

-
retlist – list of registers the snippet returns

-
decomp_flags – bitwise combination of decompile() flags… bits

-
reqmat – required microcode maturity

Returns:
pointer to the microcode, nullptr if failed.
ida_hexrays.create_empty_mba(mbr:mba_ranges_t, hf:hexrays_failure_t=None)→mba_t*
Create an empty microcode object.
ida_hexrays.create_cfunc(mba:mba_t)→cfuncptr_t
Create a new cfunc_t object.
Parameters:
mba – microcode object. After creating the cfunc object it takes the ownership of MBA.
ida_hexrays.mark_cfunc_dirty(ea:ida_idaapi.ea_t, close_views:bool=False)→bool
Flush the cached decompilation results. Erases a cache entry for the specified function.
Parameters:

-
ea – function to erase from the cache

-
close_views – close pseudocode windows that show the function

Returns:
if a cache entry existed.
ida_hexrays.clear_cached_cfuncs()→None
Flush all cached decompilation results.
ida_hexrays.has_cached_cfunc(ea:ida_idaapi.ea_t)→bool
Do we have a cached decompilation result for ‘ea’?
ida_hexrays.get_ctype_name(op:ctype_t)→strida_hexrays.create_field_name(*args)→strida_hexrays.hxe_flowchart
Flowchart has been generated.
ida_hexrays.hxe_stkpnts
SP change points have been calculated.
ida_hexrays.hxe_prolog
Prolog analysis has been finished.
ida_hexrays.hxe_microcode
Microcode has been generated.
ida_hexrays.hxe_preoptimized
Microcode has been preoptimized.
ida_hexrays.hxe_locopt
Basic block level optimization has been finished.
ida_hexrays.hxe_prealloc
Local variables: preallocation step begins.
ida_hexrays.hxe_glbopt
Global optimization has been finished. If microcode is modified, MERR_LOOP must be returned. It will cause a complete restart of the optimization.
ida_hexrays.hxe_pre_structural
Structure analysis is starting.
ida_hexrays.hxe_structural
Structural analysis has been finished.
ida_hexrays.hxe_maturity
Ctree maturity level is being changed.
ida_hexrays.hxe_interr
Internal error has occurred.
ida_hexrays.hxe_combine
Trying to combine instructions of basic block.
ida_hexrays.hxe_print_func
Printing ctree and generating text.
ida_hexrays.hxe_func_printed
Function text has been generated. Plugins may modify the text in cfunc_t::sv. However, it is too late to modify the ctree or microcode. The text uses regular color codes (see lines.hpp) COLOR_ADDR is used to store pointers to ctree items.
ida_hexrays.hxe_resolve_stkaddrs
The optimizer is about to resolve stack addresses.
ida_hexrays.hxe_build_callinfo
Analyzing a call instruction.
ida_hexrays.hxe_callinfo_built
A call instruction has been anallyzed.
ida_hexrays.hxe_calls_done
All calls have been analyzed.
ida_hexrays.hxe_begin_inlining
Starting to inline outlined functions.
ida_hexrays.hxe_inlining_func
A set of ranges is going to be inlined.
ida_hexrays.hxe_inlined_func
A set of ranges got inlined.
ida_hexrays.hxe_collect_warnings
Collect warning messages from plugins. These warnings will be displayed at the function header, after the user-defined comments.
ida_hexrays.hxe_open_pseudocode
New pseudocode view has been opened.
ida_hexrays.hxe_switch_pseudocode
Existing pseudocode view has been reloaded with a new function. Its text has not been refreshed yet, only cfunc and mba pointers are ready.
ida_hexrays.hxe_refresh_pseudocode
Existing pseudocode text has been refreshed. Adding/removing pseudocode lines is forbidden in this event.
ida_hexrays.hxe_close_pseudocode
Pseudocode view is being closed.
ida_hexrays.hxe_keyboard
Keyboard has been hit.
ida_hexrays.hxe_right_click
Mouse right click. Use hxe_populating_popup instead, in case you want to add items in the popup menu.
ida_hexrays.hxe_double_click
Mouse double click.
ida_hexrays.hxe_curpos
Current cursor position has been changed. (for example, by left-clicking or using keyboard)
ida_hexrays.hxe_create_hint
Create a hint for the current item.
ida_hexrays.hxe_text_ready
Decompiled text is ready.
ida_hexrays.hxe_populating_popup
Populating popup menu. We can add menu items now.
ida_hexrays.lxe_lvar_name_changed
Local variable got renamed.
ida_hexrays.lxe_lvar_type_changed
Local variable type got changed.
ida_hexrays.lxe_lvar_cmt_changed
Local variable comment got changed.
ida_hexrays.lxe_lvar_mapping_changed
Local variable mapping got changed.
ida_hexrays.hxe_cmt_changed
Comment got changed.
ida_hexrays.hxe_mba_maturity
Maturity level of an MBA was changed.
ida_hexrays.USE_KEYBOARD
Keyboard.
ida_hexrays.USE_MOUSE
Mouse.
classida_hexrays.ctext_position_t(_lnnum:int=-1, _x:int=0, _y:int=0)
Bases: `object`
thisownlnnum:int
Line number.
x:int
x coordinate of the cursor within the window
y:int
y coordinate of the cursor within the window
in_ctree(hdrlines:int)→bool
Is the cursor in the variable/type declaration area?
Parameters:
hdrlines – Number of lines of the declaration area
compare(r:ctext_position_t)→intida_hexrays.HEXRAYS_API_MAGICclassida_hexrays.history_item_t(*args)
Bases: `ctext_position_t`
thisownfunc_ea:ida_idaapi.ea_t
The entry address of the decompiled function.
curr_ea:ida_idaapi.ea_t
Current address.
end:ida_idaapi.ea_t
BADADDR-decompile a function; otherwise end of the range.
classida_hexrays.vdui_t(*args, **kwargs)
Bases: `object`
thisownflags:int
Properties of pseudocode window
visible()→bool
Is the pseudocode window visible? if not, it might be invisible or destroyed
valid()→bool
Does the pseudocode window contain valid code? It can become invalid if the function type gets changed in IDA.
locked()→bool
Does the pseudocode window contain valid code? We lock windows before modifying them, to avoid recursion due to the events generated by the IDA kernel.
Returns:
true: The window is locked and may have stale info
set_visible(v:bool)→Noneset_valid(v:bool)→Noneset_locked(v:bool)→boolview_idx:int
pseudocode window index (0..)
ct:TWidget*
pseudocode view
toplevel:TWidget*mba:mba_t*
pointer to underlying microcode
cfunc:cfuncptr_t
pointer to function object
last_code:merror_t
result of the last user action. See Microcode error code
cpos:ctext_position_t
Current ctext position.
head:ctree_item_t
First ctree item on the current line (for block comments)
item:ctree_item_t
Current ctree item.
tail:ctree_item_t
Tail ctree item on the current line (for indented comments)
refresh_view(redo_mba:bool)→None
Refresh pseudocode window. This is the highest level refresh function. It causes the most profound refresh possible and can lead to redecompilation of the current function. Please consider using refresh_ctext() if you need a more superficial refresh.
Parameters:
redo_mba – true means to redecompile the current function false means to rebuild ctree without regenerating microcode
refresh_ctext(activate:bool=True)→None
Refresh pseudocode window. This function refreshes the pseudocode window by regenerating its text from cfunc_t. Instead of this function use refresh_func_ctext(), which refreshes all pseudocode windows for the function.
switch_to(f:cfuncptr_t, activate:bool)→None
Display the specified pseudocode. This function replaces the pseudocode window contents with the specified cfunc_t.
Parameters:

-
f – pointer to the function to display.

-
activate – should the pseudocode window get focus?

in_ctree()→bool
Is the current item a statement?
Returns:
false if the cursor is in the local variable/type declaration area true if the cursor is in the statement area
get_number()→cnumber_t*
Get current number. If the current item is a number, return pointer to it.
Returns:
nullptr if the current item is not a number This function returns non-null for the cases of a ‘switch’ statement Also, if the current item is a casted number, then this function will succeed.
get_current_label()→int
Get current label. If there is a label under the cursor, return its number.
Returns:
-1 if there is no label under the cursor. prereq: get_current_item() has been called
clear()→None
Clear the pseudocode window. It deletes the current function and microcode.
refresh_cpos(idv:input_device_t)→bool
Refresh the current position. This function refreshes the cpos field.
Parameters:
idv – keyboard or mouse
Returns:
false if failed
get_current_item(idv:input_device_t)→bool
Get current item. This function refreshes the cpos, item, tail fields.
Parameters:
idv – keyboard or mouse
Returns:
false if failed
ui_rename_lvar(v:lvar_t)→bool
Rename local variable. This function displays a dialog box and allows the user to rename a local variable.
Parameters:
v – pointer to local variable
Returns:
false if failed or cancelled
rename_lvar(v:lvar_t, name:str, is_user_name:bool)→bool
Rename local variable. This function permanently renames a local variable.
Parameters:

-
v – pointer to local variable

-
name – new variable name

-
is_user_name – use true to save the new name into the database. use false to delete the saved name.

Returns:
false if failed
ui_set_call_type(e:cexpr_t)→bool
Set type of a function call This function displays a dialog box and allows the user to change the type of a function call
Parameters:
e – pointer to call expression
Returns:
false if failed or cancelled
ui_set_lvar_type(v:lvar_t)→bool
Set local variable type. This function displays a dialog box and allows the user to change the type of a local variable.
Parameters:
v – pointer to local variable
Returns:
false if failed or cancelled
set_lvar_type(v:lvar_t, type:tinfo_t)→bool
Set local variable type. This function permanently sets a local variable type and clears NOPTR flag if it was set before by function ‘set_noptr_lvar’
Parameters:

-
v – pointer to local variable

-
type – new variable type

Returns:
false if failed
set_noptr_lvar(v:lvar_t)→bool
Inform that local variable should have a non-pointer type This function permanently sets a corresponding variable flag (NOPTR) and removes type if it was set before by function ‘set_lvar_type’
Parameters:
v – pointer to local variable
Returns:
false if failed
ui_edit_lvar_cmt(v:lvar_t)→bool
Set local variable comment. This function displays a dialog box and allows the user to edit the comment of a local variable.
Parameters:
v – pointer to local variable
Returns:
false if failed or cancelled
set_lvar_cmt(v:lvar_t, cmt:str)→bool
Set local variable comment. This function permanently sets a variable comment.
Parameters:

-
v – pointer to local variable

-
cmt – new comment

Returns:
false if failed
ui_map_lvar(v:lvar_t)→bool
Map a local variable to another. This function displays a variable list and allows the user to select mapping.
Parameters:
v – pointer to local variable
Returns:
false if failed or cancelled
ui_unmap_lvar(v:lvar_t)→bool
Unmap a local variable. This function displays list of variables mapped to the specified variable and allows the user to select a variable to unmap.
Parameters:
v – pointer to local variable
Returns:
false if failed or cancelled
ui_noprop_lvar(v:lvar_t)→bool
Forbid variable propagation.
Parameters:
v – pointer to local variable
Returns:
false if failed or cancelled
map_lvar(frm:lvar_t, to:lvar_t)→bool
Map a local variable to another. This function permanently maps one lvar to another. All occurrences of the mapped variable are replaced by the new variable
Parameters:
to – the variable to map to. if nullptr, unmaps the variable
Returns:
false if failed
set_udm_type(udt_type:tinfo_t, udm_idx:int)→bool
Set structure field type. This function displays a dialog box and allows the user to change the type of a structure field.
Parameters:

-
udt_type – structure/union type

-
udm_idx – index of the structure/union member

Returns:
false if failed or cancelled
rename_udm(udt_type:tinfo_t, udm_idx:int)→bool
Rename structure field. This function displays a dialog box and allows the user to rename a structure field.
Parameters:

-
udt_type – structure/union type

-
udm_idx – index of the structure/union member

Returns:
false if failed or cancelled
set_global_type(ea:ida_idaapi.ea_t)→bool
Set global item type. This function displays a dialog box and allows the user to change the type of a global item (data or function).
Parameters:
ea – address of the global item
Returns:
false if failed or cancelled
rename_global(ea:ida_idaapi.ea_t)→bool
Rename global item. This function displays a dialog box and allows the user to rename a global item (data or function).
Parameters:
ea – address of the global item
Returns:
false if failed or cancelled
rename_label(label:int)→bool
Rename a label. This function displays a dialog box and allows the user to rename a statement label.
Parameters:
label – label number
Returns:
false if failed or cancelled
jump_enter(idv:input_device_t, omflags:int)→bool
Process the Enter key. This function jumps to the definition of the item under the cursor. If the current item is a function, it will be decompiled. If the current item is a global data, its disassemly text will be displayed.
Parameters:

-
idv – what cursor must be used, the keyboard or the mouse

-
omflags – OM_NEWWIN: new pseudocode window will open, 0: reuse the existing window

Returns:
false if failed
ctree_to_disasm()→bool
Jump to disassembly. This function jumps to the address in the disassembly window which corresponds to the current item. The current item is determined based on the current keyboard cursor position.
Returns:
false if failed
calc_cmt_type(lnnum:int, cmttype:cmt_type_t)→cmt_type_t
Check if the specified line can have a comment. Due to the coordinate system for comments: ([https://hex-rays.com/blog/coordinate-system-for-hex-rays](https://hex-rays.com/blog/coordinate-system-for-hex-rays)) some function lines cannot have comments. This function checks if a comment can be attached to the specified line.
Parameters:

-
lnnum – line number (0 based)

-
cmttype – comment types to check

Returns:
possible comment types
edit_cmt(loc:treeloc_t)→bool
Edit an indented comment. This function displays a dialog box and allows the user to edit the comment for the specified ctree location.
Parameters:
loc – comment location
Returns:
false if failed or cancelled
edit_func_cmt()→bool
Edit a function comment. This function displays a dialog box and allows the user to edit the function comment.
Returns:
false if failed or cancelled
del_orphan_cmts()→bool
Delete all orphan comments. Delete all orphan comments and refresh the screen.
Returns:
true
set_num_radix(base:int)→bool
Change number base. This function changes the current number representation.
Parameters:
base – number radix (10 or 16) 0 means a character constant
Returns:
false if failed
set_num_enum()→bool
Convert number to symbolic constant. This function displays a dialog box and allows the user to select a symbolic constant to represent the number.
Returns:
false if failed or cancelled
set_num_stroff()→bool
Convert number to structure field offset. Currently not implemented.
Returns:
false if failed or cancelled
invert_sign()→bool
Negate a number. This function negates the current number.
Returns:
false if failed.
invert_bits()→bool
Bitwise negate a number. This function inverts all bits of the current number.
Returns:
false if failed.
collapse_item(hide:bool)→bool
Collapse/uncollapse item. This function collapses the current item.
Returns:
false if failed.
collapse_lvars(hide:bool)→bool
Collapse/uncollapse local variable declarations.
Returns:
false if failed.
split_item(split:bool)→bool
Split/unsplit item. This function splits the current assignment expression.
Returns:
false if failed.
ida_hexrays.CMT_NONE
No comment is possible.
ida_hexrays.CMT_TAIL
Indented comment.
ida_hexrays.CMT_BLOCK1
Anterioir block comment.
ida_hexrays.CMT_BLOCK2
Posterior block comment.
ida_hexrays.CMT_LVAR
Local variable comment.
ida_hexrays.CMT_FUNC
Function comment.
ida_hexrays.CMT_ALL
All comments.
ida_hexrays.VDUI_VISIBLE
is visible?
ida_hexrays.VDUI_VALID
is valid?
classida_hexrays.ui_stroff_op_t
Bases: `object`
thisowntext:str
any text for the column “Operand” of widget
offset:int
operand offset, will be used when calculating the UDT path
classida_hexrays.ui_stroff_applicator_t
Bases: `object`
thisownapply(opnum:int, path:intvec_t, top_tif:tinfo_t, spath:str)→boolParameters:

-
opnum – operand ordinal number, see below

-
path – path describing the union selection, maybe empty

-
top_tif – tinfo_t of the selected toplevel UDT

-
spath – selected path

ida_hexrays.select_udt_by_offset(udts:qvectorconst*, ops:ui_stroff_ops_t, applicator:ui_stroff_applicator_t)→int
Select UDT
Parameters:

-
udts – list of UDT tinfo_t for the selection, if nullptr or empty then UDTs from the “Local types” will be used

-
ops – operands

-
applicator – callback will be called to apply the selection for every operand

ida_hexrays.hx_user_numforms_beginida_hexrays.hx_user_numforms_endida_hexrays.hx_user_numforms_nextida_hexrays.hx_user_numforms_previda_hexrays.hx_user_numforms_firstida_hexrays.hx_user_numforms_secondida_hexrays.hx_user_numforms_findida_hexrays.hx_user_numforms_insertida_hexrays.hx_user_numforms_eraseida_hexrays.hx_user_numforms_clearida_hexrays.hx_user_numforms_sizeida_hexrays.hx_user_numforms_freeida_hexrays.hx_user_numforms_newida_hexrays.hx_lvar_mapping_beginida_hexrays.hx_lvar_mapping_endida_hexrays.hx_lvar_mapping_nextida_hexrays.hx_lvar_mapping_previda_hexrays.hx_lvar_mapping_firstida_hexrays.hx_lvar_mapping_secondida_hexrays.hx_lvar_mapping_findida_hexrays.hx_lvar_mapping_insertida_hexrays.hx_lvar_mapping_eraseida_hexrays.hx_lvar_mapping_clearida_hexrays.hx_lvar_mapping_sizeida_hexrays.hx_lvar_mapping_freeida_hexrays.hx_lvar_mapping_newida_hexrays.hx_udcall_map_beginida_hexrays.hx_udcall_map_endida_hexrays.hx_udcall_map_nextida_hexrays.hx_udcall_map_previda_hexrays.hx_udcall_map_firstida_hexrays.hx_udcall_map_secondida_hexrays.hx_udcall_map_findida_hexrays.hx_udcall_map_insertida_hexrays.hx_udcall_map_eraseida_hexrays.hx_udcall_map_clearida_hexrays.hx_udcall_map_sizeida_hexrays.hx_udcall_map_freeida_hexrays.hx_udcall_map_newida_hexrays.hx_user_cmts_beginida_hexrays.hx_user_cmts_endida_hexrays.hx_user_cmts_nextida_hexrays.hx_user_cmts_previda_hexrays.hx_user_cmts_firstida_hexrays.hx_user_cmts_secondida_hexrays.hx_user_cmts_findida_hexrays.hx_user_cmts_insertida_hexrays.hx_user_cmts_eraseida_hexrays.hx_user_cmts_clearida_hexrays.hx_user_cmts_sizeida_hexrays.hx_user_cmts_freeida_hexrays.hx_user_cmts_newida_hexrays.hx_user_iflags_beginida_hexrays.hx_user_iflags_endida_hexrays.hx_user_iflags_nextida_hexrays.hx_user_iflags_previda_hexrays.hx_user_iflags_firstida_hexrays.hx_user_iflags_secondida_hexrays.hx_user_iflags_findida_hexrays.hx_user_iflags_insertida_hexrays.hx_user_iflags_eraseida_hexrays.hx_user_iflags_clearida_hexrays.hx_user_iflags_sizeida_hexrays.hx_user_iflags_freeida_hexrays.hx_user_iflags_newida_hexrays.hx_user_unions_beginida_hexrays.hx_user_unions_endida_hexrays.hx_user_unions_nextida_hexrays.hx_user_unions_previda_hexrays.hx_user_unions_firstida_hexrays.hx_user_unions_secondida_hexrays.hx_user_unions_findida_hexrays.hx_user_unions_insertida_hexrays.hx_user_unions_eraseida_hexrays.hx_user_unions_clearida_hexrays.hx_user_unions_sizeida_hexrays.hx_user_unions_freeida_hexrays.hx_user_unions_newida_hexrays.hx_user_labels_beginida_hexrays.hx_user_labels_endida_hexrays.hx_user_labels_nextida_hexrays.hx_user_labels_previda_hexrays.hx_user_labels_firstida_hexrays.hx_user_labels_secondida_hexrays.hx_user_labels_findida_hexrays.hx_user_labels_insertida_hexrays.hx_user_labels_eraseida_hexrays.hx_user_labels_clearida_hexrays.hx_user_labels_sizeida_hexrays.hx_user_labels_freeida_hexrays.hx_user_labels_newida_hexrays.hx_eamap_beginida_hexrays.hx_eamap_endida_hexrays.hx_eamap_nextida_hexrays.hx_eamap_previda_hexrays.hx_eamap_firstida_hexrays.hx_eamap_secondida_hexrays.hx_eamap_findida_hexrays.hx_eamap_insertida_hexrays.hx_eamap_eraseida_hexrays.hx_eamap_clearida_hexrays.hx_eamap_sizeida_hexrays.hx_eamap_freeida_hexrays.hx_eamap_newida_hexrays.hx_boundaries_beginida_hexrays.hx_boundaries_endida_hexrays.hx_boundaries_nextida_hexrays.hx_boundaries_previda_hexrays.hx_boundaries_firstida_hexrays.hx_boundaries_secondida_hexrays.hx_boundaries_findida_hexrays.hx_boundaries_insertida_hexrays.hx_boundaries_eraseida_hexrays.hx_boundaries_clearida_hexrays.hx_boundaries_sizeida_hexrays.hx_boundaries_freeida_hexrays.hx_boundaries_newida_hexrays.hx_block_chains_beginida_hexrays.hx_block_chains_endida_hexrays.hx_block_chains_nextida_hexrays.hx_block_chains_previda_hexrays.hx_block_chains_getida_hexrays.hx_block_chains_findida_hexrays.hx_block_chains_insertida_hexrays.hx_block_chains_eraseida_hexrays.hx_block_chains_clearida_hexrays.hx_block_chains_sizeida_hexrays.hx_block_chains_freeida_hexrays.hx_block_chains_newida_hexrays.hx_hexrays_allocida_hexrays.hx_hexrays_freeida_hexrays.hx_valrng_t_clearida_hexrays.hx_valrng_t_copyida_hexrays.hx_valrng_t_assignida_hexrays.hx_valrng_t_compareida_hexrays.hx_valrng_t_set_eqida_hexrays.hx_valrng_t_set_cmpida_hexrays.hx_valrng_t_reduce_sizeida_hexrays.hx_valrng_t_intersect_withida_hexrays.hx_valrng_t_unite_withida_hexrays.hx_valrng_t_inverseida_hexrays.hx_valrng_t_hasida_hexrays.hx_valrng_t_printida_hexrays.hx_valrng_t_dstrida_hexrays.hx_valrng_t_cvt_to_single_valueida_hexrays.hx_valrng_t_cvt_to_cmpida_hexrays.hx_get_merror_descida_hexrays.hx_must_mcode_close_blockida_hexrays.hx_is_mcode_propagatableida_hexrays.hx_negate_mcode_relationida_hexrays.hx_swap_mcode_relationida_hexrays.hx_get_signed_mcodeida_hexrays.hx_get_unsigned_mcodeida_hexrays.hx_mcode_modifies_dida_hexrays.hx_operand_locator_t_compareida_hexrays.hx_vd_printer_t_printida_hexrays.hx_file_printer_t_printida_hexrays.hx_qstring_printer_t_printida_hexrays.hx_dstrida_hexrays.hx_is_type_correctida_hexrays.hx_is_small_udtida_hexrays.hx_is_nonbool_typeida_hexrays.hx_is_bool_typeida_hexrays.hx_partial_type_numida_hexrays.hx_get_float_typeida_hexrays.hx_get_int_type_by_width_and_signida_hexrays.hx_get_unk_typeida_hexrays.hx_dummy_ptrtypeida_hexrays.hx_get_member_typeida_hexrays.hx_make_pointerida_hexrays.hx_create_typedefida_hexrays.hx_get_typeida_hexrays.hx_set_typeida_hexrays.hx_vdloc_t_dstrida_hexrays.hx_vdloc_t_compareida_hexrays.hx_vdloc_t_is_aliasableida_hexrays.hx_print_vdlocida_hexrays.hx_arglocs_overlapida_hexrays.hx_lvar_locator_t_compareida_hexrays.hx_lvar_locator_t_dstrida_hexrays.hx_lvar_t_dstrida_hexrays.hx_lvar_t_is_promoted_argida_hexrays.hx_lvar_t_accepts_typeida_hexrays.hx_lvar_t_set_lvar_typeida_hexrays.hx_lvar_t_set_widthida_hexrays.hx_lvar_t_append_listida_hexrays.hx_lvar_t_append_list_ida_hexrays.hx_lvars_t_find_stkvarida_hexrays.hx_lvars_t_findida_hexrays.hx_lvars_t_find_lvarida_hexrays.hx_restore_user_lvar_settingsida_hexrays.hx_save_user_lvar_settingsida_hexrays.hx_modify_user_lvarsida_hexrays.hx_modify_user_lvar_infoida_hexrays.hx_locate_lvarida_hexrays.hx_restore_user_defined_callsida_hexrays.hx_save_user_defined_callsida_hexrays.hx_parse_user_callida_hexrays.hx_convert_to_user_callida_hexrays.hx_install_microcode_filterida_hexrays.hx_udc_filter_t_cleanupida_hexrays.hx_udc_filter_t_initida_hexrays.hx_udc_filter_t_applyida_hexrays.hx_bitset_t_bitset_tida_hexrays.hx_bitset_t_copyida_hexrays.hx_bitset_t_addida_hexrays.hx_bitset_t_add_ida_hexrays.hx_bitset_t_add__ida_hexrays.hx_bitset_t_subida_hexrays.hx_bitset_t_sub_ida_hexrays.hx_bitset_t_sub__ida_hexrays.hx_bitset_t_cut_atida_hexrays.hx_bitset_t_shift_downida_hexrays.hx_bitset_t_hasida_hexrays.hx_bitset_t_has_allida_hexrays.hx_bitset_t_has_anyida_hexrays.hx_bitset_t_dstrida_hexrays.hx_bitset_t_emptyida_hexrays.hx_bitset_t_countida_hexrays.hx_bitset_t_count_ida_hexrays.hx_bitset_t_lastida_hexrays.hx_bitset_t_fill_with_onesida_hexrays.hx_bitset_t_fill_gapsida_hexrays.hx_bitset_t_has_commonida_hexrays.hx_bitset_t_intersectida_hexrays.hx_bitset_t_is_subset_ofida_hexrays.hx_bitset_t_compareida_hexrays.hx_bitset_t_goupida_hexrays.hx_ivl_t_dstrida_hexrays.hx_ivl_t_compareida_hexrays.hx_ivlset_t_addida_hexrays.hx_ivlset_t_add_ida_hexrays.hx_ivlset_t_addmaskedida_hexrays.hx_ivlset_t_subida_hexrays.hx_ivlset_t_sub_ida_hexrays.hx_ivlset_t_has_commonida_hexrays.hx_ivlset_t_printida_hexrays.hx_ivlset_t_dstrida_hexrays.hx_ivlset_t_countida_hexrays.hx_ivlset_t_has_common_ida_hexrays.hx_ivlset_t_containsida_hexrays.hx_ivlset_t_includesida_hexrays.hx_ivlset_t_intersectida_hexrays.hx_ivlset_t_compareida_hexrays.hx_rlist_t_printida_hexrays.hx_rlist_t_dstrida_hexrays.hx_mlist_t_addmemida_hexrays.hx_mlist_t_printida_hexrays.hx_mlist_t_dstrida_hexrays.hx_mlist_t_compareida_hexrays.hx_get_temp_regsida_hexrays.hx_is_kregida_hexrays.hx_reg2mregida_hexrays.hx_mreg2regida_hexrays.hx_get_mreg_nameida_hexrays.hx_install_optinsn_handlerida_hexrays.hx_remove_optinsn_handlerida_hexrays.hx_install_optblock_handlerida_hexrays.hx_remove_optblock_handlerida_hexrays.hx_simple_graph_t_compute_dominatorsida_hexrays.hx_simple_graph_t_compute_immediate_dominatorsida_hexrays.hx_simple_graph_t_depth_first_preorderida_hexrays.hx_simple_graph_t_depth_first_postorderida_hexrays.hx_simple_graph_t_goupida_hexrays.hx_mutable_graph_t_resizeida_hexrays.hx_mutable_graph_t_goupida_hexrays.hx_mutable_graph_t_del_edgeida_hexrays.hx_lvar_ref_t_compareida_hexrays.hx_lvar_ref_t_varida_hexrays.hx_stkvar_ref_t_compareida_hexrays.hx_stkvar_ref_t_get_stkvarida_hexrays.hx_fnumber_t_printida_hexrays.hx_fnumber_t_dstrida_hexrays.hx_mop_t_copyida_hexrays.hx_mop_t_assignida_hexrays.hx_mop_t_swapida_hexrays.hx_mop_t_eraseida_hexrays.hx_mop_t_printida_hexrays.hx_mop_t_dstrida_hexrays.hx_mop_t_create_from_mlistida_hexrays.hx_mop_t_create_from_ivlsetida_hexrays.hx_mop_t_create_from_vdlocida_hexrays.hx_mop_t_create_from_scattered_vdlocida_hexrays.hx_mop_t_create_from_insnida_hexrays.hx_mop_t_make_numberida_hexrays.hx_mop_t_make_fpnumida_hexrays.hx_mop_t__make_gvarida_hexrays.hx_mop_t_make_gvarida_hexrays.hx_mop_t_make_reg_pairida_hexrays.hx_mop_t_make_helperida_hexrays.hx_mop_t_is_bit_regida_hexrays.hx_mop_t_may_use_aliased_memoryida_hexrays.hx_mop_t_is01ida_hexrays.hx_mop_t_is_sign_extended_fromida_hexrays.hx_mop_t_is_zero_extended_fromida_hexrays.hx_mop_t_equal_mopsida_hexrays.hx_mop_t_lexcompareida_hexrays.hx_mop_t_for_all_opsida_hexrays.hx_mop_t_for_all_scattered_submopsida_hexrays.hx_mop_t_is_constantida_hexrays.hx_mop_t_get_stkoffida_hexrays.hx_mop_t_make_low_halfida_hexrays.hx_mop_t_make_high_halfida_hexrays.hx_mop_t_make_first_halfida_hexrays.hx_mop_t_make_second_halfida_hexrays.hx_mop_t_shift_mopida_hexrays.hx_mop_t_change_sizeida_hexrays.hx_mop_t_preserve_side_effectsida_hexrays.hx_mop_t_apply_ld_mcodeida_hexrays.hx_mcallarg_t_printida_hexrays.hx_mcallarg_t_dstrida_hexrays.hx_mcallarg_t_set_regargida_hexrays.hx_mcallinfo_t_lexcompareida_hexrays.hx_mcallinfo_t_set_typeida_hexrays.hx_mcallinfo_t_get_typeida_hexrays.hx_mcallinfo_t_printida_hexrays.hx_mcallinfo_t_dstrida_hexrays.hx_mcases_t_compareida_hexrays.hx_mcases_t_printida_hexrays.hx_mcases_t_dstrida_hexrays.hx_vivl_t_extend_to_coverida_hexrays.hx_vivl_t_intersectida_hexrays.hx_vivl_t_printida_hexrays.hx_vivl_t_dstrida_hexrays.hx_chain_t_printida_hexrays.hx_chain_t_dstrida_hexrays.hx_chain_t_append_listida_hexrays.hx_chain_t_append_list_ida_hexrays.hx_block_chains_t_get_chainida_hexrays.hx_block_chains_t_printida_hexrays.hx_block_chains_t_dstrida_hexrays.hx_graph_chains_t_for_all_chainsida_hexrays.hx_graph_chains_t_releaseida_hexrays.hx_minsn_t_initida_hexrays.hx_minsn_t_copyida_hexrays.hx_minsn_t_set_combinedida_hexrays.hx_minsn_t_swapida_hexrays.hx_minsn_t_printida_hexrays.hx_minsn_t_dstrida_hexrays.hx_minsn_t_setaddrida_hexrays.hx_minsn_t_optimize_subtreeida_hexrays.hx_minsn_t_for_all_opsida_hexrays.hx_minsn_t_for_all_insnsida_hexrays.hx_minsn_t__make_nopida_hexrays.hx_minsn_t_equal_insnsida_hexrays.hx_minsn_t_lexcompareida_hexrays.hx_minsn_t_is_noret_callida_hexrays.hx_minsn_t_is_helperida_hexrays.hx_minsn_t_find_callida_hexrays.hx_minsn_t_has_side_effectsida_hexrays.hx_minsn_t_find_opcodeida_hexrays.hx_minsn_t_find_ins_opida_hexrays.hx_minsn_t_find_num_opida_hexrays.hx_minsn_t_modifies_dida_hexrays.hx_minsn_t_is_betweenida_hexrays.hx_minsn_t_may_use_aliased_memoryida_hexrays.hx_minsn_t_serializeida_hexrays.hx_minsn_t_deserializeida_hexrays.hx_getf_reginsnida_hexrays.hx_getb_reginsnida_hexrays.hx_mblock_t_initida_hexrays.hx_mblock_t_printida_hexrays.hx_mblock_t_dumpida_hexrays.hx_mblock_t_vdump_blockida_hexrays.hx_mblock_t_insert_into_blockida_hexrays.hx_mblock_t_remove_from_blockida_hexrays.hx_mblock_t_for_all_insnsida_hexrays.hx_mblock_t_for_all_opsida_hexrays.hx_mblock_t_for_all_usesida_hexrays.hx_mblock_t_optimize_insnida_hexrays.hx_mblock_t_optimize_blockida_hexrays.hx_mblock_t_build_listsida_hexrays.hx_mblock_t_optimize_useless_jumpida_hexrays.hx_mblock_t_append_use_listida_hexrays.hx_mblock_t_append_def_listida_hexrays.hx_mblock_t_build_use_listida_hexrays.hx_mblock_t_build_def_listida_hexrays.hx_mblock_t_find_first_useida_hexrays.hx_mblock_t_find_redefinitionida_hexrays.hx_mblock_t_is_rhs_redefinedida_hexrays.hx_mblock_t_find_accessida_hexrays.hx_mblock_t_get_valrangesida_hexrays.hx_mblock_t_get_valranges_ida_hexrays.hx_mblock_t_get_reginsn_qtyida_hexrays.hx_mba_ranges_t_range_containsida_hexrays.hx_mba_t_stkoff_vd2idaida_hexrays.hx_mba_t_stkoff_ida2vdida_hexrays.hx_mba_t_idaloc2vdida_hexrays.hx_mba_t_idaloc2vd_ida_hexrays.hx_mba_t_vd2idalocida_hexrays.hx_mba_t_vd2idaloc_ida_hexrays.hx_mba_t_termida_hexrays.hx_mba_t_get_curfuncida_hexrays.hx_mba_t_set_maturityida_hexrays.hx_mba_t_optimize_localida_hexrays.hx_mba_t_build_graphida_hexrays.hx_mba_t_get_graphida_hexrays.hx_mba_t_analyze_callsida_hexrays.hx_mba_t_optimize_globalida_hexrays.hx_mba_t_alloc_lvarsida_hexrays.hx_mba_t_dumpida_hexrays.hx_mba_t_vdump_mbaida_hexrays.hx_mba_t_printida_hexrays.hx_mba_t_verifyida_hexrays.hx_mba_t_mark_chains_dirtyida_hexrays.hx_mba_t_insert_blockida_hexrays.hx_mba_t_remove_blockida_hexrays.hx_mba_t_copy_blockida_hexrays.hx_mba_t_remove_empty_and_unreachable_blocksida_hexrays.hx_mba_t_merge_blocksida_hexrays.hx_mba_t_for_all_opsida_hexrays.hx_mba_t_for_all_insnsida_hexrays.hx_mba_t_for_all_topinsnsida_hexrays.hx_mba_t_find_mopida_hexrays.hx_mba_t_create_helper_callida_hexrays.hx_mba_t_get_func_output_listsida_hexrays.hx_mba_t_argida_hexrays.hx_mba_t_alloc_fict_eaida_hexrays.hx_mba_t_map_fict_eaida_hexrays.hx_mba_t_serializeida_hexrays.hx_mba_t_deserializeida_hexrays.hx_mba_t_save_snapshotida_hexrays.hx_mba_t_alloc_kregida_hexrays.hx_mba_t_free_kregida_hexrays.hx_mba_t_inline_funcida_hexrays.hx_mba_t_locate_stkpntida_hexrays.hx_mba_t_set_lvar_nameida_hexrays.hx_mbl_graph_t_is_accessed_globallyida_hexrays.hx_mbl_graph_t_get_udida_hexrays.hx_mbl_graph_t_get_duida_hexrays.hx_cdg_insn_iterator_t_nextida_hexrays.hx_codegen_t_clearida_hexrays.hx_codegen_t_emitida_hexrays.hx_codegen_t_emit_ida_hexrays.hx_change_hexrays_configida_hexrays.hx_get_hexrays_versionida_hexrays.hx_open_pseudocodeida_hexrays.hx_close_pseudocodeida_hexrays.hx_get_widget_vduiida_hexrays.hx_decompile_manyida_hexrays.hx_hexrays_failure_t_descida_hexrays.hx_send_databaseida_hexrays.hx_gco_info_t_append_to_listida_hexrays.hx_get_current_operandida_hexrays.hx_remitemida_hexrays.hx_negated_relationida_hexrays.hx_swapped_relationida_hexrays.hx_get_op_signnessida_hexrays.hx_asgopida_hexrays.hx_asgop_revertida_hexrays.hx_cnumber_t_printida_hexrays.hx_cnumber_t_valueida_hexrays.hx_cnumber_t_assignida_hexrays.hx_cnumber_t_compareida_hexrays.hx_var_ref_t_compareida_hexrays.hx_ctree_visitor_t_apply_toida_hexrays.hx_ctree_visitor_t_apply_to_exprsida_hexrays.hx_ctree_parentee_t_recalc_parent_typesida_hexrays.hx_cfunc_parentee_t_calc_rvalue_typeida_hexrays.hx_citem_locator_t_compareida_hexrays.hx_citem_t_contains_exprida_hexrays.hx_citem_t_contains_labelida_hexrays.hx_citem_t_find_parent_ofida_hexrays.hx_citem_t_find_closest_addrida_hexrays.hx_cexpr_t_assignida_hexrays.hx_cexpr_t_compareida_hexrays.hx_cexpr_t_replace_byida_hexrays.hx_cexpr_t_cleanupida_hexrays.hx_cexpr_t_put_numberida_hexrays.hx_cexpr_t_print1ida_hexrays.hx_cexpr_t_calc_typeida_hexrays.hx_cexpr_t_equal_effectida_hexrays.hx_cexpr_t_is_child_ofida_hexrays.hx_cexpr_t_contains_operatorida_hexrays.hx_cexpr_t_get_high_nbit_boundida_hexrays.hx_cexpr_t_get_low_nbit_boundida_hexrays.hx_cexpr_t_requires_lvalueida_hexrays.hx_cexpr_t_has_side_effectsida_hexrays.hx_cexpr_t_maybe_ptrida_hexrays.hx_cexpr_t_dstrida_hexrays.hx_cif_t_assignida_hexrays.hx_cif_t_compareida_hexrays.hx_cloop_t_assignida_hexrays.hx_cfor_t_compareida_hexrays.hx_cwhile_t_compareida_hexrays.hx_cdo_t_compareida_hexrays.hx_creturn_t_compareida_hexrays.hx_cthrow_t_compareida_hexrays.hx_cgoto_t_compareida_hexrays.hx_casm_t_compareida_hexrays.hx_cinsn_t_assignida_hexrays.hx_cinsn_t_compareida_hexrays.hx_cinsn_t_replace_byida_hexrays.hx_cinsn_t_cleanupida_hexrays.hx_cinsn_t_new_insnida_hexrays.hx_cinsn_t_create_ifida_hexrays.hx_cinsn_t_printida_hexrays.hx_cinsn_t_print1ida_hexrays.hx_cinsn_t_is_ordinary_flowida_hexrays.hx_cinsn_t_contains_insnida_hexrays.hx_cinsn_t_collect_free_breaksida_hexrays.hx_cinsn_t_collect_free_continuesida_hexrays.hx_cinsn_t_dstrida_hexrays.hx_cblock_t_compareida_hexrays.hx_carglist_t_compareida_hexrays.hx_ccase_t_compareida_hexrays.hx_ccases_t_compareida_hexrays.hx_cswitch_t_compareida_hexrays.hx_ccatch_t_compareida_hexrays.hx_ctry_t_compareida_hexrays.hx_ctree_item_t_get_udmida_hexrays.hx_ctree_item_t_get_edmida_hexrays.hx_ctree_item_t_get_lvarida_hexrays.hx_ctree_item_t_get_eaida_hexrays.hx_ctree_item_t_get_label_numida_hexrays.hx_ctree_item_t_printida_hexrays.hx_ctree_item_t_dstrida_hexrays.hx_lnotida_hexrays.hx_new_blockida_hexrays.hx_vcreate_helperida_hexrays.hx_vcall_helperida_hexrays.hx_make_numida_hexrays.hx_make_refida_hexrays.hx_dereferenceida_hexrays.hx_save_user_labelsida_hexrays.hx_save_user_cmtsida_hexrays.hx_save_user_numformsida_hexrays.hx_save_user_iflagsida_hexrays.hx_save_user_unionsida_hexrays.hx_restore_user_labelsida_hexrays.hx_restore_user_cmtsida_hexrays.hx_restore_user_numformsida_hexrays.hx_restore_user_iflagsida_hexrays.hx_restore_user_unionsida_hexrays.hx_cfunc_t_build_c_treeida_hexrays.hx_cfunc_t_verifyida_hexrays.hx_cfunc_t_print_dclida_hexrays.hx_cfunc_t_print_funcida_hexrays.hx_cfunc_t_get_func_typeida_hexrays.hx_cfunc_t_get_lvarsida_hexrays.hx_cfunc_t_get_stkoff_deltaida_hexrays.hx_cfunc_t_find_labelida_hexrays.hx_cfunc_t_remove_unused_labelsida_hexrays.hx_cfunc_t_get_user_cmtida_hexrays.hx_cfunc_t_set_user_cmtida_hexrays.hx_cfunc_t_get_user_iflagsida_hexrays.hx_cfunc_t_set_user_iflagsida_hexrays.hx_cfunc_t_has_orphan_cmtsida_hexrays.hx_cfunc_t_del_orphan_cmtsida_hexrays.hx_cfunc_t_get_user_union_selectionida_hexrays.hx_cfunc_t_set_user_union_selectionida_hexrays.hx_cfunc_t_save_user_labelsida_hexrays.hx_cfunc_t_save_user_cmtsida_hexrays.hx_cfunc_t_save_user_numformsida_hexrays.hx_cfunc_t_save_user_iflagsida_hexrays.hx_cfunc_t_save_user_unionsida_hexrays.hx_cfunc_t_get_line_itemida_hexrays.hx_cfunc_t_get_warningsida_hexrays.hx_cfunc_t_get_eamapida_hexrays.hx_cfunc_t_get_boundariesida_hexrays.hx_cfunc_t_get_pseudocodeida_hexrays.hx_cfunc_t_refresh_func_ctextida_hexrays.hx_cfunc_t_gather_derefsida_hexrays.hx_cfunc_t_find_item_coordsida_hexrays.hx_cfunc_t_cleanupida_hexrays.hx_close_hexrays_waitboxida_hexrays.hx_decompileida_hexrays.hx_gen_microcodeida_hexrays.hx_create_cfuncida_hexrays.hx_mark_cfunc_dirtyida_hexrays.hx_clear_cached_cfuncsida_hexrays.hx_has_cached_cfuncida_hexrays.hx_get_ctype_nameida_hexrays.hx_create_field_nameida_hexrays.hx_install_hexrays_callbackida_hexrays.hx_remove_hexrays_callbackida_hexrays.hx_vdui_t_set_lockedida_hexrays.hx_vdui_t_refresh_viewida_hexrays.hx_vdui_t_refresh_ctextida_hexrays.hx_vdui_t_switch_toida_hexrays.hx_vdui_t_get_numberida_hexrays.hx_vdui_t_get_current_labelida_hexrays.hx_vdui_t_clearida_hexrays.hx_vdui_t_refresh_cposida_hexrays.hx_vdui_t_get_current_itemida_hexrays.hx_vdui_t_ui_rename_lvarida_hexrays.hx_vdui_t_rename_lvarida_hexrays.hx_vdui_t_ui_set_call_typeida_hexrays.hx_vdui_t_ui_set_lvar_typeida_hexrays.hx_vdui_t_set_lvar_typeida_hexrays.hx_vdui_t_set_noptr_lvarida_hexrays.hx_vdui_t_ui_edit_lvar_cmtida_hexrays.hx_vdui_t_set_lvar_cmtida_hexrays.hx_vdui_t_ui_map_lvarida_hexrays.hx_vdui_t_ui_unmap_lvarida_hexrays.hx_vdui_t_map_lvarida_hexrays.hx_vdui_t_set_udm_typeida_hexrays.hx_vdui_t_rename_udmida_hexrays.hx_vdui_t_set_global_typeida_hexrays.hx_vdui_t_rename_globalida_hexrays.hx_vdui_t_rename_labelida_hexrays.hx_vdui_t_jump_enterida_hexrays.hx_vdui_t_ctree_to_disasmida_hexrays.hx_vdui_t_calc_cmt_typeida_hexrays.hx_vdui_t_edit_cmtida_hexrays.hx_vdui_t_edit_func_cmtida_hexrays.hx_vdui_t_del_orphan_cmtsida_hexrays.hx_vdui_t_set_num_radixida_hexrays.hx_vdui_t_set_num_enumida_hexrays.hx_vdui_t_set_num_stroffida_hexrays.hx_vdui_t_invert_signida_hexrays.hx_vdui_t_invert_bitsida_hexrays.hx_vdui_t_collapse_itemida_hexrays.hx_vdui_t_collapse_lvarsida_hexrays.hx_vdui_t_split_itemida_hexrays.hx_select_udt_by_offsetida_hexrays.hx_catchexpr_t_compareida_hexrays.hx_mba_t_split_blockida_hexrays.hx_mba_t_remove_blocksida_hexrays.hx_cfunc_t_recalc_item_addressesida_hexrays.hx_obsolete_int64_emulator_t_mop_valueida_hexrays.hx_obsolete_int64_emulator_t_minsn_valueida_hexrays.hx_int64_emulator_t__mop_valueida_hexrays.hx_int64_emulator_t__minsn_valueida_hexrays.hx_cfunc_t_serializeida_hexrays.hx_cfunc_t_deserializeida_hexrays.hx_mblock_t_verify_insnida_hexrays.hx_vdui_t_ui_noprop_lvarclassida_hexrays.user_numforms_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.user_numforms_first(p:user_numforms_iterator_t)→operand_locator_tconst&
Get reference to the current map key.
ida_hexrays.user_numforms_second(p:user_numforms_iterator_t)→number_format_t&
Get reference to the current map value.
ida_hexrays.user_numforms_find(map:user_numforms_t, key:operand_locator_t)→user_numforms_iterator_t
Find the specified key in user_numforms_t.
ida_hexrays.user_numforms_insert(map:user_numforms_t, key:operand_locator_t, val:number_format_t)→user_numforms_iterator_t
Insert new (operand_locator_t, number_format_t) pair into user_numforms_t.
ida_hexrays.user_numforms_begin(map:user_numforms_t)→user_numforms_iterator_t
Get iterator pointing to the beginning of user_numforms_t.
ida_hexrays.user_numforms_end(map:user_numforms_t)→user_numforms_iterator_t
Get iterator pointing to the end of user_numforms_t.
ida_hexrays.user_numforms_next(p:user_numforms_iterator_t)→user_numforms_iterator_t
Move to the next element.
ida_hexrays.user_numforms_prev(p:user_numforms_iterator_t)→user_numforms_iterator_t
Move to the previous element.
ida_hexrays.user_numforms_erase(map:user_numforms_t, p:user_numforms_iterator_t)→None
Erase current element from user_numforms_t.
ida_hexrays.user_numforms_clear(map:user_numforms_t)→None
Clear user_numforms_t.
ida_hexrays.user_numforms_size(map:user_numforms_t)→int
Get size of user_numforms_t.
ida_hexrays.user_numforms_free(map:user_numforms_t)→None
Delete user_numforms_t instance.
ida_hexrays.user_numforms_new()→user_numforms_t*
Create a new user_numforms_t instance.
classida_hexrays.lvar_mapping_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.lvar_mapping_first(p:lvar_mapping_iterator_t)→lvar_locator_tconst&
Get reference to the current map key.
ida_hexrays.lvar_mapping_second(p:lvar_mapping_iterator_t)→lvar_locator_t&
Get reference to the current map value.
ida_hexrays.lvar_mapping_find(map:lvar_mapping_t, key:lvar_locator_t)→lvar_mapping_iterator_t
Find the specified key in lvar_mapping_t.
ida_hexrays.lvar_mapping_insert(map:lvar_mapping_t, key:lvar_locator_t, val:lvar_locator_t)→lvar_mapping_iterator_t
Insert new (lvar_locator_t, lvar_locator_t) pair into lvar_mapping_t.
ida_hexrays.lvar_mapping_begin(map:lvar_mapping_t)→lvar_mapping_iterator_t
Get iterator pointing to the beginning of lvar_mapping_t.
ida_hexrays.lvar_mapping_end(map:lvar_mapping_t)→lvar_mapping_iterator_t
Get iterator pointing to the end of lvar_mapping_t.
ida_hexrays.lvar_mapping_next(p:lvar_mapping_iterator_t)→lvar_mapping_iterator_t
Move to the next element.
ida_hexrays.lvar_mapping_prev(p:lvar_mapping_iterator_t)→lvar_mapping_iterator_t
Move to the previous element.
ida_hexrays.lvar_mapping_erase(map:lvar_mapping_t, p:lvar_mapping_iterator_t)→None
Erase current element from lvar_mapping_t.
ida_hexrays.lvar_mapping_clear(map:lvar_mapping_t)→None
Clear lvar_mapping_t.
ida_hexrays.lvar_mapping_size(map:lvar_mapping_t)→int
Get size of lvar_mapping_t.
ida_hexrays.lvar_mapping_free(map:lvar_mapping_t)→None
Delete lvar_mapping_t instance.
ida_hexrays.lvar_mapping_new()→lvar_mapping_t*
Create a new lvar_mapping_t instance.
classida_hexrays.udcall_map_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.udcall_map_first(p:udcall_map_iterator_t)→ea_tconst&
Get reference to the current map key.
ida_hexrays.udcall_map_second(p:udcall_map_iterator_t)→udcall_t&
Get reference to the current map value.
ida_hexrays.udcall_map_find(map:udcall_map_tconst*, key:ea_tconst&)→udcall_map_iterator_t
Find the specified key in udcall_map_t.
ida_hexrays.udcall_map_insert(map:udcall_map_t*, key:ea_tconst&, val:udcall_t)→udcall_map_iterator_t
Insert new (ea_t, udcall_t) pair into udcall_map_t.
ida_hexrays.udcall_map_begin(map:udcall_map_tconst*)→udcall_map_iterator_t
Get iterator pointing to the beginning of udcall_map_t.
ida_hexrays.udcall_map_end(map:udcall_map_tconst*)→udcall_map_iterator_t
Get iterator pointing to the end of udcall_map_t.
ida_hexrays.udcall_map_next(p:udcall_map_iterator_t)→udcall_map_iterator_t
Move to the next element.
ida_hexrays.udcall_map_prev(p:udcall_map_iterator_t)→udcall_map_iterator_t
Move to the previous element.
ida_hexrays.udcall_map_erase(map:udcall_map_t*, p:udcall_map_iterator_t)→None
Erase current element from udcall_map_t.
ida_hexrays.udcall_map_clear(map:udcall_map_t*)→None
Clear udcall_map_t.
ida_hexrays.udcall_map_size(map:udcall_map_t*)→int
Get size of udcall_map_t.
ida_hexrays.udcall_map_free(map:udcall_map_t*)→None
Delete udcall_map_t instance.
ida_hexrays.udcall_map_new()→udcall_map_t*
Create a new udcall_map_t instance.
classida_hexrays.user_cmts_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.user_cmts_first(p:user_cmts_iterator_t)→treeloc_tconst&
Get reference to the current map key.
ida_hexrays.user_cmts_second(p:user_cmts_iterator_t)→citem_cmt_t&
Get reference to the current map value.
ida_hexrays.user_cmts_find(map:user_cmts_t, key:treeloc_t)→user_cmts_iterator_t
Find the specified key in user_cmts_t.
ida_hexrays.user_cmts_insert(map:user_cmts_t, key:treeloc_t, val:citem_cmt_t)→user_cmts_iterator_t
Insert new (treeloc_t, citem_cmt_t) pair into user_cmts_t.
ida_hexrays.user_cmts_begin(map:user_cmts_t)→user_cmts_iterator_t
Get iterator pointing to the beginning of user_cmts_t.
ida_hexrays.user_cmts_end(map:user_cmts_t)→user_cmts_iterator_t
Get iterator pointing to the end of user_cmts_t.
ida_hexrays.user_cmts_next(p:user_cmts_iterator_t)→user_cmts_iterator_t
Move to the next element.
ida_hexrays.user_cmts_prev(p:user_cmts_iterator_t)→user_cmts_iterator_t
Move to the previous element.
ida_hexrays.user_cmts_erase(map:user_cmts_t, p:user_cmts_iterator_t)→None
Erase current element from user_cmts_t.
ida_hexrays.user_cmts_clear(map:user_cmts_t)→None
Clear user_cmts_t.
ida_hexrays.user_cmts_size(map:user_cmts_t)→int
Get size of user_cmts_t.
ida_hexrays.user_cmts_free(map:user_cmts_t)→None
Delete user_cmts_t instance.
ida_hexrays.user_cmts_new()→user_cmts_t*
Create a new user_cmts_t instance.
classida_hexrays.user_iflags_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.user_iflags_first(p:user_iflags_iterator_t)→citem_locator_tconst&
Get reference to the current map key.
ida_hexrays.user_iflags_second(p:user_iflags_iterator_t)→int32&
Get reference to the current map value.
ida_hexrays.user_iflags_find(map:user_iflags_t, key:citem_locator_t)→user_iflags_iterator_t
Find the specified key in user_iflags_t.
ida_hexrays.user_iflags_insert(map:user_iflags_t, key:citem_locator_t, val:int32const&)→user_iflags_iterator_t
Insert new (citem_locator_t, int32) pair into user_iflags_t.
ida_hexrays.user_iflags_begin(map:user_iflags_t)→user_iflags_iterator_t
Get iterator pointing to the beginning of user_iflags_t.
ida_hexrays.user_iflags_end(map:user_iflags_t)→user_iflags_iterator_t
Get iterator pointing to the end of user_iflags_t.
ida_hexrays.user_iflags_next(p:user_iflags_iterator_t)→user_iflags_iterator_t
Move to the next element.
ida_hexrays.user_iflags_prev(p:user_iflags_iterator_t)→user_iflags_iterator_t
Move to the previous element.
ida_hexrays.user_iflags_erase(map:user_iflags_t, p:user_iflags_iterator_t)→None
Erase current element from user_iflags_t.
ida_hexrays.user_iflags_clear(map:user_iflags_t)→None
Clear user_iflags_t.
ida_hexrays.user_iflags_size(map:user_iflags_t)→int
Get size of user_iflags_t.
ida_hexrays.user_iflags_free(map:user_iflags_t)→None
Delete user_iflags_t instance.
ida_hexrays.user_iflags_new()→user_iflags_t*
Create a new user_iflags_t instance.
classida_hexrays.user_unions_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.user_unions_first(p:user_unions_iterator_t)→ea_tconst&
Get reference to the current map key.
ida_hexrays.user_unions_second(p:user_unions_iterator_t)→intvec_t&
Get reference to the current map value.
ida_hexrays.user_unions_find(map:user_unions_t, key:ea_tconst&)→user_unions_iterator_t
Find the specified key in user_unions_t.
ida_hexrays.user_unions_insert(map:user_unions_t, key:ea_tconst&, val:intvec_t)→user_unions_iterator_t
Insert new (ea_t, intvec_t) pair into user_unions_t.
ida_hexrays.user_unions_begin(map:user_unions_t)→user_unions_iterator_t
Get iterator pointing to the beginning of user_unions_t.
ida_hexrays.user_unions_end(map:user_unions_t)→user_unions_iterator_t
Get iterator pointing to the end of user_unions_t.
ida_hexrays.user_unions_next(p:user_unions_iterator_t)→user_unions_iterator_t
Move to the next element.
ida_hexrays.user_unions_prev(p:user_unions_iterator_t)→user_unions_iterator_t
Move to the previous element.
ida_hexrays.user_unions_erase(map:user_unions_t, p:user_unions_iterator_t)→None
Erase current element from user_unions_t.
ida_hexrays.user_unions_clear(map:user_unions_t)→None
Clear user_unions_t.
ida_hexrays.user_unions_size(map:user_unions_t)→int
Get size of user_unions_t.
ida_hexrays.user_unions_free(map:user_unions_t)→None
Delete user_unions_t instance.
ida_hexrays.user_unions_new()→user_unions_t*
Create a new user_unions_t instance.
classida_hexrays.user_labels_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.user_labels_first(p:user_labels_iterator_t)→intconst&
Get reference to the current map key.
ida_hexrays.user_labels_second(p:user_labels_iterator_t)→str
Get reference to the current map value.
ida_hexrays.user_labels_find(map:user_labels_t, key:intconst&)→user_labels_iterator_t
Find the specified key in user_labels_t.
ida_hexrays.user_labels_insert(map:user_labels_t, key:intconst&, val:str)→user_labels_iterator_t
Insert new (int, qstring) pair into user_labels_t.
ida_hexrays.user_labels_begin(map:user_labels_t)→user_labels_iterator_t
Get iterator pointing to the beginning of user_labels_t.
ida_hexrays.user_labels_end(map:user_labels_t)→user_labels_iterator_t
Get iterator pointing to the end of user_labels_t.
ida_hexrays.user_labels_next(p:user_labels_iterator_t)→user_labels_iterator_t
Move to the next element.
ida_hexrays.user_labels_prev(p:user_labels_iterator_t)→user_labels_iterator_t
Move to the previous element.
ida_hexrays.user_labels_erase(map:user_labels_t, p:user_labels_iterator_t)→None
Erase current element from user_labels_t.
ida_hexrays.user_labels_clear(map:user_labels_t)→None
Clear user_labels_t.
ida_hexrays.user_labels_size(map:user_labels_t)→int
Get size of user_labels_t.
ida_hexrays.user_labels_free(map:user_labels_t)→None
Delete user_labels_t instance.
ida_hexrays.user_labels_new()→user_labels_t*
Create a new user_labels_t instance.
classida_hexrays.eamap_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.eamap_first(p:eamap_iterator_t)→ea_tconst&
Get reference to the current map key.
ida_hexrays.eamap_second(p:eamap_iterator_t)→cinsnptrvec_t&
Get reference to the current map value.
ida_hexrays.eamap_find(map:eamap_t, key:ea_tconst&)→eamap_iterator_t
Find the specified key in eamap_t.
ida_hexrays.eamap_insert(map:eamap_t, key:ea_tconst&, val:cinsnptrvec_t)→eamap_iterator_t
Insert new (ea_t, cinsnptrvec_t) pair into eamap_t.
ida_hexrays.eamap_begin(map:eamap_t)→eamap_iterator_t
Get iterator pointing to the beginning of eamap_t.
ida_hexrays.eamap_end(map:eamap_t)→eamap_iterator_t
Get iterator pointing to the end of eamap_t.
ida_hexrays.eamap_next(p:eamap_iterator_t)→eamap_iterator_t
Move to the next element.
ida_hexrays.eamap_prev(p:eamap_iterator_t)→eamap_iterator_t
Move to the previous element.
ida_hexrays.eamap_erase(map:eamap_t, p:eamap_iterator_t)→None
Erase current element from eamap_t.
ida_hexrays.eamap_clear(map:eamap_t)→None
Clear eamap_t.
ida_hexrays.eamap_size(map:eamap_t)→int
Get size of eamap_t.
ida_hexrays.eamap_free(map:eamap_t)→None
Delete eamap_t instance.
ida_hexrays.eamap_new()→eamap_t*
Create a new eamap_t instance.
classida_hexrays.boundaries_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.boundaries_first(p:boundaries_iterator_t)→cinsn_t*const&
Get reference to the current map key.
ida_hexrays.boundaries_second(p:boundaries_iterator_t)→rangeset_t&
Get reference to the current map value.
ida_hexrays.boundaries_begin(map:boundaries_t)→boundaries_iterator_t
Get iterator pointing to the beginning of boundaries_t.
ida_hexrays.boundaries_end(map:boundaries_t)→boundaries_iterator_t
Get iterator pointing to the end of boundaries_t.
ida_hexrays.boundaries_next(p:boundaries_iterator_t)→boundaries_iterator_t
Move to the next element.
ida_hexrays.boundaries_prev(p:boundaries_iterator_t)→boundaries_iterator_t
Move to the previous element.
ida_hexrays.boundaries_erase(map:boundaries_t, p:boundaries_iterator_t)→None
Erase current element from boundaries_t.
ida_hexrays.boundaries_clear(map:boundaries_t)→None
Clear boundaries_t.
ida_hexrays.boundaries_size(map:boundaries_t)→int
Get size of boundaries_t.
ida_hexrays.boundaries_free(map:boundaries_t)→None
Delete boundaries_t instance.
ida_hexrays.boundaries_new()→boundaries_t*
Create a new boundaries_t instance.
classida_hexrays.block_chains_iterator_t
Bases: `object`
thisownx:iterator_wordida_hexrays.block_chains_get(p:block_chains_iterator_t)→chain_t&
Get reference to the current set value.
ida_hexrays.block_chains_find(set:block_chains_t, val:chain_t)→block_chains_iterator_t
Find the specified key in set block_chains_t.
ida_hexrays.block_chains_insert(set:block_chains_t, val:chain_t)→block_chains_iterator_t
Insert new (chain_t) into set block_chains_t.
ida_hexrays.block_chains_begin(set:block_chains_t)→block_chains_iterator_t
Get iterator pointing to the beginning of block_chains_t.
ida_hexrays.block_chains_end(set:block_chains_t)→block_chains_iterator_t
Get iterator pointing to the end of block_chains_t.
ida_hexrays.block_chains_next(p:block_chains_iterator_t)→block_chains_iterator_t
Move to the next element.
ida_hexrays.block_chains_prev(p:block_chains_iterator_t)→block_chains_iterator_t
Move to the previous element.
ida_hexrays.block_chains_erase(set:block_chains_t, p:block_chains_iterator_t)→None
Erase current element from block_chains_t.
ida_hexrays.block_chains_clear(set:block_chains_t)→None
Clear block_chains_t.
ida_hexrays.block_chains_size(set:block_chains_t)→int
Get size of block_chains_t.
ida_hexrays.block_chains_free(set:block_chains_t)→None
Delete block_chains_t instance.
ida_hexrays.block_chains_new()→block_chains_t*
Create a new block_chains_t instance.
classida_hexrays.array_of_ivlsets(*args)
Bases: `object`
thisownpush_back(*args)→ivlset_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→ivlset_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:array_of_ivlsets)→Noneextract()→ivlset_t*inject(s:ivlset_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:ivlset_t, x:ivlset_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:ivlset_t)→booladd_unique(x:ivlset_t)→boolappend(x:ivlset_t)→Noneextend(x:array_of_ivlsets)→Nonefrontbackida_hexrays.is_small_struniida_hexrays.mbl_array_tida_hexrays.is_allowed_on_small_struniexceptionida_hexrays.DecompilationFailure
Bases: `Exception`

Common base class for all non-exit exceptions.
ida_hexrays.decompile(ea, hf=None, flags=0)
Decompile a snippet or a function.
Parameters:
hf – extended error information (if failed)
Returns:
pointer to the decompilation result (a reference counted pointer). nullptr if failed.
ida_hexrays.citem_to_specific_type(self)
cast the citem_t object to its more specific type, either cexpr_t or cinsn_t.
ida_hexrays.property_op_to_typename(self)ida_hexrays.cexpr_operands(self)
return a dictionary with the operands of a cexpr_t.
ida_hexrays.cinsn_details(self)
return the details pointer for the cinsn_t object depending on the value of its op member. this is one of the cblock_t, cif_t, etc. objects.
ida_hexrays.cfunc_type(self)
Get the function’s return type tinfo_t object.
ida_hexrays.lnot(e)
Logically negate the specified expression. The specified expression will be logically negated. For example, “x == y” is converted into “x != y” by this function.
Parameters:
e – expression to negate. After the call, e must not be used anymore because it can be changed by the function. The function return value must be used to refer to the expression.
Returns:
logically negated expression.
ida_hexrays.make_ref(e)
Create a reference. This function performs the following conversion: “obj” => “&obj”. It can handle casts, annihilate “&*”, and process other special cases.
ida_hexrays.dereference(e, ptrsize, is_float=False)
Dereference a pointer. This function dereferences a pointer expression. It performs the following conversion: “ptr” => “*ptr” It can handle discrepancies in the pointer type and the access size.
Parameters:

-
e – expression to deference

-
ptrsize – access size

Returns:
dereferenced expression
ida_hexrays.call_helper(rettype, args, *rest)
Create a helper call.
ida_hexrays.new_block()
Create a new block-statement.
ida_hexrays.make_num(*args)
Create a number expression
Parameters:

-
n – value

-
func – current function

-
ea – definition address of the number

-
opnum – operand number of the number (in the disassembly listing)

-
sign – number sign

-
size – size of number in bytes Please note that the type of the resulting expression can be anything because it can be inherited from the disassembly listing or taken from the user specified number representation in the pseudocode view.

ida_hexrays.create_helper(*args)
Create a helper object..
ida_hexrays.install_hexrays_callback(callback)
Install handler for decompiler events.
Parameters:
callback – handler to install
Returns:
false if failed
ida_hexrays.remove_hexrays_callback(callback)
Uninstall handler for decompiler events.
Parameters:
callback – handler to uninstall
Returns:
number of uninstalled handlers.
