# IDAPython stack frame API

- 官方来源：https://python.docs.hex-rays.com/ida_frame/index.html

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
- ida_frame
- View page source

# ida_frame

Routines to manipulate function stack frames, stack variables, register variables and local labels.
The frame is represented as a structure:

function arguments

return address (isn’t stored in func_t)

return address (isn’t stored in func_t) |

To access the structure of a function frame and stack variables, use: * tinfo_t::get_func_frame(const func_t *pfn) (the preferred way) * get_func_frame(tinfo_t *out, const func_t *pfn) * tinfo_t::get_udt_details() gives info about stack variables: their type, names, offset, etc

## Attributes

`FRAME_UDM_NAME_R`
|

`FRAME_UDM_NAME_S`
|

`FPC_ARGS`
|

`FPC_RETADDR`
|

`FPC_SAVREGS`
|

`FPC_LVARS`
|

`STKVAR_VALID_SIZE`
|
x.dtype contains correct variable type (for insns like 'lea' this bit must be off). In general, dr_O references do not allow to determine the variable size

`STKVAR_KEEP_EXISTING`
|
if a stack variable for this operand already exists then we do not create a new variable

`REGVAR_ERROR_OK`
|
all ok

`REGVAR_ERROR_ARG`
|
function arguments are bad

`REGVAR_ERROR_RANGE`
|
the definition range is bad

`REGVAR_ERROR_NAME`
|
the provided name(s) can't be accepted

## Classes

`xreflist_t`
|

`stkpnt_t`
|

`stkpnts_t`
|

`regvar_t`
|

`xreflist_entry_t`
|

## Functions

`is_funcarg_off`(→ bool)
|

`lvar_off`(→ int)
|

`add_frame`(→ bool)
|
Add function frame.

`del_frame`(→ bool)
|
Delete a function frame.

`set_frame_size`(→ bool)
|
Set size of function frame. Note: The returned size may not include all stack arguments. It does so only for __stdcall and __fastcall calling conventions. To get the entire frame size for all cases use frame.get_func_frame(pfn).get_size()

`get_frame_size`(→ asize_t)
|
Get full size of a function frame. This function takes into account size of local variables + size of saved registers + size of return address + number of purged bytes. The purged bytes correspond to the arguments of the functions with __stdcall and __fastcall calling conventions.

`get_frame_retsize`(→ int)
|
Get size of function return address.

`get_frame_part`(→ None)
|
Get offsets of the frame part in the frame.

`frame_off_args`(→ ida_idaapi.ea_t)
|
Get starting address of arguments section.

`frame_off_retaddr`(→ ida_idaapi.ea_t)
|
Get starting address of return address section.

`frame_off_savregs`(→ ida_idaapi.ea_t)
|
Get starting address of saved registers section.

`frame_off_lvars`(→ ida_idaapi.ea_t)
|
Get start address of local variables section.

`get_func_frame`(→ bool)
|
Get type of function frame

`soff_to_fpoff`(→ int)
|
Convert struct offsets into fp-relative offsets. This function converts the offsets inside the udt_type_data_t object into the frame pointer offsets (for example, EBP-relative).

`update_fpd`(→ bool)
|
Update frame pointer delta.

`set_purged`(→ bool)
|
Set the number of purged bytes for a function or data item (funcptr). This function will update the database and plan to reanalyze items referencing the specified address. It works only for processors with PR_PURGING bit in 16 and 32 bit modes.

`define_stkvar`(→ bool)
|
Define/redefine a stack variable.

`add_frame_member`(→ bool)
|
Add member to the frame type

`is_anonymous_member_name`(→ bool)
|
Is member name prefixed with "anonymous"?

`is_dummy_member_name`(→ bool)
|
Is member name an auto-generated name?

`is_special_frame_member`(→ bool)
|
Is stkvar with TID the return address slot or the saved registers slot ?

`set_frame_member_type`(→ bool)
|
Change type of the frame member

`delete_frame_members`(→ bool)
|
Delete frame members

`build_stkvar_name`(→ str)
|
Build automatic stack variable name.

`calc_stkvar_struc_offset`(→ ida_idaapi.ea_t)
|
Calculate offset of stack variable in the frame structure.

`calc_frame_offset`(→ int)
|
Calculate the offset of stack variable in the frame.

`free_regvar`(→ None)
|

`add_regvar`(→ int)
|
Define a register variable.

`find_regvar`(→ regvar_t *)
|
This function has the following signatures:

`has_regvar`(→ bool)
|
Is there a register variable definition?

`rename_regvar`(→ int)
|
Rename a register variable.

`set_regvar_cmt`(→ int)
|
Set comment for a register variable.

`del_regvar`(→ int)
|
Delete a register variable definition.

`add_auto_stkpnt`(→ bool)
|
Add automatic SP register change point.

`add_user_stkpnt`(→ bool)
|
Add user-defined SP register change point.

`del_stkpnt`(→ bool)
|
Delete SP register change point.

`get_spd`(→ int)
|
Get difference between the initial and current values of ESP.

`get_effective_spd`(→ int)
|
Get effective difference between the initial and current values of ESP. This function returns the sp-diff used by the instruction. The difference between get_spd() and get_effective_spd() is present only for instructions like "pop [esp+N]": they modify sp and use the modified value.

`get_sp_delta`(→ int)
|
Get modification of SP made at the specified location

`set_auto_spd`(→ bool)
|
Add such an automatic SP register change point so that at EA the new cumulative SP delta (that is, the difference between the initial and current values of SP) would be equal to NEW_SPD.

`recalc_spd`(→ bool)
|
Recalculate SP delta for an instruction that stops execution. The next instruction is not reached from the current instruction. We need to recalculate SP for the next instruction.

`recalc_spd_for_basic_block`(→ bool)
|
Recalculate SP delta for the current instruction. The typical code snippet to calculate SP delta in a proc module is:

`build_stkvar_xrefs`(→ None)
|
Fill 'out' with a list of all the xrefs made from function 'pfn' to specified range of the pfn's stack frame.

## Module Contents

classida_frame.xreflist_t(*args)
Bases: `object`
thisownpush_back(*args)→xreflist_entry_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→xreflist_entry_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:xreflist_t)→Noneextract()→xreflist_entry_t*inject(s:xreflist_entry_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:xreflist_entry_t, x:xreflist_entry_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:xreflist_entry_t)→booladd_unique(x:xreflist_entry_t)→boolappend(x:xreflist_entry_t)→Noneextend(x:xreflist_t)→Nonefrontbackida_frame.is_funcarg_off(pfn:func_tconst*, frameoff:int)→boolida_frame.lvar_off(pfn:func_tconst*, frameoff:int)→intida_frame.FRAME_UDM_NAME_Rida_frame.FRAME_UDM_NAME_Sclassida_frame.stkpnt_t
Bases: `object`
thisownea:ida_idaapi.ea_tspd:intcompare(r:stkpnt_t)→intclassida_frame.stkpnts_t
Bases: `object`
thisowncompare(r:stkpnts_t)→intida_frame.add_frame(pfn:func_t*, frsize:int, frregs:ushort, argsize:asize_t)→bool
Add function frame.
Parameters:

-
pfn – pointer to function structure

-
frsize – size of function local variables

-
frregs – size of saved registers

-
argsize – size of function arguments range which will be purged upon return. this parameter is used for __stdcall and __pascal calling conventions. for other calling conventions please pass 0.

Returns:
1: ok
Returns:
0: failed (no function, frame already exists)
ida_frame.del_frame(pfn:func_t*)→bool
Delete a function frame.
Parameters:
pfn – pointer to function structure
Returns:
success
ida_frame.set_frame_size(pfn:func_t*, frsize:asize_t, frregs:ushort, argsize:asize_t)→bool
Set size of function frame. Note: The returned size may not include all stack arguments. It does so only for __stdcall and __fastcall calling conventions. To get the entire frame size for all cases use frame.get_func_frame(pfn).get_size()
Parameters:

-
pfn – pointer to function structure

-
frsize – size of function local variables

-
frregs – size of saved registers

-
argsize – size of function arguments that will be purged from the stack upon return

Returns:
success
ida_frame.get_frame_size(pfn:func_tconst*)→asize_t
Get full size of a function frame. This function takes into account size of local variables + size of saved registers + size of return address + number of purged bytes. The purged bytes correspond to the arguments of the functions with __stdcall and __fastcall calling conventions.
Parameters:
pfn – pointer to function structure, may be nullptr
Returns:
size of frame in bytes or zero
ida_frame.get_frame_retsize(pfn:func_tconst*)→int
Get size of function return address.
Parameters:
pfn – pointer to function structure, can’t be nullptr
ida_frame.FPC_ARGSida_frame.FPC_RETADDRida_frame.FPC_SAVREGSida_frame.FPC_LVARSida_frame.get_frame_part(range:range_t, pfn:func_tconst*, part:frame_part_t)→None
Get offsets of the frame part in the frame.
Parameters:

-
range – pointer to the output buffer with the frame part start/end(exclusive) offsets, can’t be nullptr

-
pfn – pointer to function structure, can’t be nullptr

-
part – frame part

ida_frame.frame_off_args(pfn:func_tconst*)→ida_idaapi.ea_t
Get starting address of arguments section.
ida_frame.frame_off_retaddr(pfn:func_tconst*)→ida_idaapi.ea_t
Get starting address of return address section.
ida_frame.frame_off_savregs(pfn:func_tconst*)→ida_idaapi.ea_t
Get starting address of saved registers section.
ida_frame.frame_off_lvars(pfn:func_tconst*)→ida_idaapi.ea_t
Get start address of local variables section.
ida_frame.get_func_frame(out:tinfo_t, pfn:func_tconst*)→bool
Get type of function frame
Parameters:

-
out – type info

-
pfn – pointer to function structure

Returns:
success
ida_frame.soff_to_fpoff(pfn:func_t*, soff:int)→int
Convert struct offsets into fp-relative offsets. This function converts the offsets inside the udt_type_data_t object into the frame pointer offsets (for example, EBP-relative).
ida_frame.update_fpd(pfn:func_t*, fpd:asize_t)→bool
Update frame pointer delta.
Parameters:

-
pfn – pointer to function structure

-
fpd – new fpd value. cannot be bigger than the local variable range size.

Returns:
success
ida_frame.set_purged(ea:ida_idaapi.ea_t, nbytes:int, override_old_value:bool)→bool
Set the number of purged bytes for a function or data item (funcptr). This function will update the database and plan to reanalyze items referencing the specified address. It works only for processors with PR_PURGING bit in 16 and 32 bit modes.
Parameters:

-
ea – address of the function of item

-
nbytes – number of purged bytes

-
override_old_value – may overwrite old information about purged bytes

Returns:
success
ida_frame.STKVAR_VALID_SIZE
x.dtype contains correct variable type (for insns like ‘lea’ this bit must be off). In general, dr_O references do not allow to determine the variable size
ida_frame.STKVAR_KEEP_EXISTING
if a stack variable for this operand already exists then we do not create a new variable
ida_frame.define_stkvar(pfn:func_t*, name:str, off:int, tif:tinfo_t, repr:value_repr_t=None)→bool
Define/redefine a stack variable.
Parameters:

-
pfn – pointer to function

-
name – variable name, nullptr means autogenerate a name

-
off – offset of the stack variable in the frame. negative values denote local variables, positive - function arguments.

-
tif – variable type

-
repr – variable representation

Returns:
success
ida_frame.add_frame_member(pfn:func_tconst*, name:str, offset:int, tif:tinfo_t, repr:value_repr_t=None, etf_flags:uint=0)→bool
Add member to the frame type
Parameters:

-
pfn – pointer to function

-
name – variable name, nullptr means autogenerate a name

-
offset – member offset in the frame structure, in bytes

-
tif – variable type

-
repr – variable representation

Returns:
success
ida_frame.is_anonymous_member_name(name:str)→bool
Is member name prefixed with “anonymous”?
ida_frame.is_dummy_member_name(name:str)→bool
Is member name an auto-generated name?
ida_frame.is_special_frame_member(tid:tid_t)→bool
Is stkvar with TID the return address slot or the saved registers slot ?
Parameters:
tid – frame member type id return address or saved registers member?
ida_frame.set_frame_member_type(pfn:func_tconst*, offset:int, tif:tinfo_t, repr:value_repr_t=None, etf_flags:uint=0)→bool
Change type of the frame member
Parameters:

-
pfn – pointer to function

-
offset – member offset in the frame structure, in bytes

-
tif – variable type

-
repr – variable representation

Returns:
success
ida_frame.delete_frame_members(pfn:func_tconst*, start_offset:int, end_offset:int)→bool
Delete frame members
Parameters:

-
pfn – pointer to function

-
start_offset – member offset to start deletion from, in bytes

-
end_offset – member offset which not included in the deletion, in bytes

Returns:
success
ida_frame.build_stkvar_name(pfn:func_tconst*, v:int)→str
Build automatic stack variable name.
Parameters:

-
pfn – pointer to function (can’t be nullptr!)

-
v – value of variable offset

Returns:
length of stack variable name or -1
ida_frame.calc_stkvar_struc_offset(pfn:func_t*, insn:insn_tconst&, n:int)→ida_idaapi.ea_t
Calculate offset of stack variable in the frame structure.
Parameters:

-
pfn – pointer to function (cannot be nullptr)

-
insn – the instruction

-
n – 0..UA_MAXOP-1 operand number -1 if error, return BADADDR

Returns:
BADADDR if some error (issue a warning if stack frame is bad)
ida_frame.calc_frame_offset(pfn:func_t*, off:int, insn:insn_tconst*=None, op:op_tconst*=None)→int
Calculate the offset of stack variable in the frame.
Parameters:

-
pfn – pointer to function (cannot be nullptr)

-
off – the offset relative to stack pointer or frame pointer

-
insn – the instruction

-
op – the operand

Returns:
the offset in the frame
ida_frame.free_regvar(v:regvar_t)→Noneclassida_frame.regvar_t(*args)
Bases: `ida_range.range_t`
thisowncanon:char*
canonical register name (case-insensitive)
user:char*
user-defined register name
cmt:char*
comment to appear near definition
swap(r:regvar_t)→Noneida_frame.add_regvar(pfn:func_t*, ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, canon:str, user:str, cmt:str)→int
Define a register variable.
Parameters:

-
pfn – function in which the definition will be created

-
ea1 – range of addresses within the function where the definition will be used

-
ea2 – range of addresses within the function where the definition will be used

-
canon – name of a general register

-
user – user-defined name for the register

-
cmt – comment for the definition

Returns:
Register variable error codes
ida_frame.REGVAR_ERROR_OK
all ok
ida_frame.REGVAR_ERROR_ARG
function arguments are bad
ida_frame.REGVAR_ERROR_RANGE
the definition range is bad
ida_frame.REGVAR_ERROR_NAME
the provided name(s) can’t be accepted
ida_frame.find_regvar(*args)→regvar_t*
This function has the following signatures:

-
find_regvar(pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, canon: str, user: str) -> regvar_t *

-
find_regvar(pfn: func_t *, ea: ida_idaapi.ea_t, canon: str) -> regvar_t *

# 0: find_regvar(pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, canon: str, user: str) -> regvar_t *

Find a register variable definition (powerful version). One of ‘canon’ and ‘user’ should be nullptr. If both ‘canon’ and ‘user’ are nullptr it returns the first regvar definition in the range.
Returns:
nullptr-not found, otherwise ptr to regvar_t

# 1: find_regvar(pfn: func_t *, ea: ida_idaapi.ea_t, canon: str) -> regvar_t *

Find a register variable definition.
Returns:
nullptr-not found, otherwise ptr to regvar_t
ida_frame.has_regvar(pfn:func_t*, ea:ida_idaapi.ea_t)→bool
Is there a register variable definition?
Parameters:

-
pfn – function in question

-
ea – current address

ida_frame.rename_regvar(pfn:func_t*, v:regvar_t, user:str)→int
Rename a register variable.
Parameters:

-
pfn – function in question

-
v – variable to rename

-
user – new user-defined name for the register

Returns:
Register variable error codes
ida_frame.set_regvar_cmt(pfn:func_t*, v:regvar_t, cmt:str)→int
Set comment for a register variable.
Parameters:

-
pfn – function in question

-
v – variable to rename

-
cmt – new comment

Returns:
Register variable error codes
ida_frame.del_regvar(pfn:func_t*, ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, canon:str)→int
Delete a register variable definition.
Parameters:

-
pfn – function in question

-
ea1 – range of addresses within the function where the definition holds

-
ea2 – range of addresses within the function where the definition holds

-
canon – name of a general register

Returns:
Register variable error codes
ida_frame.add_auto_stkpnt(pfn:func_t*, ea:ida_idaapi.ea_t, delta:int)→bool
Add automatic SP register change point.
Parameters:

-
pfn – pointer to the function. may be nullptr.

-
ea – linear address where SP changes. usually this is the end of the instruction which modifies the stack pointer ( insn_t::ea+ insn_t::size)

-
delta – difference between old and new values of SP

Returns:
success
ida_frame.add_user_stkpnt(ea:ida_idaapi.ea_t, delta:int)→bool
Add user-defined SP register change point.
Parameters:

-
ea – linear address where SP changes

-
delta – difference between old and new values of SP

Returns:
success
ida_frame.del_stkpnt(pfn:func_t*, ea:ida_idaapi.ea_t)→bool
Delete SP register change point.
Parameters:

-
pfn – pointer to the function. may be nullptr.

-
ea – linear address

Returns:
success
ida_frame.get_spd(pfn:func_t*, ea:ida_idaapi.ea_t)→int
Get difference between the initial and current values of ESP.
Parameters:

-
pfn – pointer to the function. may be nullptr.

-
ea – linear address of the instruction

Returns:
0 or the difference, usually a negative number. returns the sp-diff before executing the instruction.
ida_frame.get_effective_spd(pfn:func_t*, ea:ida_idaapi.ea_t)→int
Get effective difference between the initial and current values of ESP. This function returns the sp-diff used by the instruction. The difference between get_spd() and get_effective_spd() is present only for instructions like “pop [esp+N]”: they modify sp and use the modified value.
Parameters:

-
pfn – pointer to the function. may be nullptr.

-
ea – linear address

Returns:
0 or the difference, usually a negative number
ida_frame.get_sp_delta(pfn:func_t*, ea:ida_idaapi.ea_t)→int
Get modification of SP made at the specified location
Parameters:

-
pfn – pointer to the function. may be nullptr.

-
ea – linear address

Returns:
0 if the specified location doesn’t contain a SP change point. otherwise return delta of SP modification.
ida_frame.set_auto_spd(pfn:func_t*, ea:ida_idaapi.ea_t, new_spd:int)→bool
Add such an automatic SP register change point so that at EA the new cumulative SP delta (that is, the difference between the initial and current values of SP) would be equal to NEW_SPD.
Parameters:

-
pfn – pointer to the function. may be nullptr.

-
ea – linear address of the instruction

-
new_spd – new value of the cumulative SP delta

Returns:
success
ida_frame.recalc_spd(cur_ea:ida_idaapi.ea_t)→bool
Recalculate SP delta for an instruction that stops execution. The next instruction is not reached from the current instruction. We need to recalculate SP for the next instruction. This function will create a new automatic SP register change point if necessary. It should be called from the emulator (emu.cpp) when auto_state == AU_USED if the current instruction doesn’t pass the execution flow to the next instruction.
Parameters:
cur_ea – linear address of the current instruction
Returns:
1: new stkpnt is added
Returns:
0: nothing is changed
ida_frame.recalc_spd_for_basic_block(pfn:func_t*, cur_ea:ida_idaapi.ea_t)→bool
Recalculate SP delta for the current instruction. The typical code snippet to calculate SP delta in a proc module is:
if ( may_trace_sp() && pfn != nullptr )if ( !recalc_spd_for_basic_block(pfn, insn.ea) )
trace_sp(pfn, insn);

where trace_sp() is a typical name for a function that emulates the SP change of an instruction.
Parameters:

-
pfn – pointer to the function

-
cur_ea – linear address of the current instruction

Returns:
true: the cumulative SP delta is set
Returns:
false: the instruction at CUR_EA passes flow to the next instruction. SP delta must be set as a result of emulating the current instruction.
classida_frame.xreflist_entry_t
Bases: `object`
thisownea:ida_idaapi.ea_t
Location of the insn referencing the stack frame member.
opnum:uchar
Number of the operand of that instruction.
type:uchar
The type of xref (cref_t & dref_t)
compare(r:xreflist_entry_t)→intida_frame.build_stkvar_xrefs(out:xreflist_t, pfn:func_t*, start_offset:int, end_offset:int)→None
Fill ‘out’ with a list of all the xrefs made from function ‘pfn’ to specified range of the pfn’s stack frame.
Parameters:

-
out – the list of xrefs to fill.

-
pfn – the function to scan.

-
start_offset – start frame structure offset, in bytes

-
end_offset – end frame structure offset, in bytes
