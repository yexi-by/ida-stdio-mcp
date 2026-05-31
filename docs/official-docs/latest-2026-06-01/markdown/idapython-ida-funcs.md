# IDAPython functions API

- 官方来源：https://python.docs.hex-rays.com/ida_funcs/index.html

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
- ida_funcs
- View page source

# ida_funcs

Routines for working with functions within the disassembled program.

This file also contains routines for working with library signatures (e.g. FLIRT). Each function consists of function chunks. At least one function chunk must be present in the function definition - the function entry chunk. Other chunks are called function tails. There may be several of them for a function. A function tail is a continuous range of addresses. It can be used in the definition of one or more functions. One function using the tail is singled out and called the tail owner. This function is considered as ‘possessing’ the tail. get_func() on a tail address will return the function possessing the tail. You can enumerate the functions using the tail by using func_parent_iterator_t. Each function chunk in the disassembly is represented as an “range” (a range of addresses, see range.hpp for details) with characteristics. A function entry must start with an instruction (code) byte.

## Attributes

`FUNC_NORET`
 |
Function doesn't return.

`FUNC_FAR`
 |
Far function.

`FUNC_LIB`
 |
Library function.

`FUNC_STATICDEF`
 |
Static function.

`FUNC_FRAME`
 |
Function uses frame pointer (BP)

`FUNC_USERFAR`
 |
User has specified far-ness of the function

`FUNC_HIDDEN`
 |
A hidden function chunk.

`FUNC_THUNK`
 |
Thunk (jump) function.

`FUNC_BOTTOMBP`
 |
BP points to the bottom of the stack frame.

`FUNC_NORET_PENDING`
 |
Function 'non-return' analysis must be performed. This flag is verified upon func_does_return()

`FUNC_SP_READY`
 |
SP-analysis has been performed. If this flag is on, the stack change points should not be not modified anymore. Currently this analysis is performed only for PC

`FUNC_FUZZY_SP`
 |
Function changes SP in untraceable way, for example: and esp, 0FFFFFFF0h

`FUNC_PROLOG_OK`
 |
Prolog analysis has been performed by last SP-analysis

`FUNC_PURGED_OK`
 |
'argsize' field has been validated. If this bit is clear and 'argsize' is 0, then we do not known the real number of bytes removed from the stack. This bit is handled by the processor module.

`FUNC_TAIL`
 |
This is a function tail. Other bits must be clear (except FUNC_HIDDEN).

`FUNC_LUMINA`
 |
Function info is provided by Lumina.

`FUNC_OUTLINE`
 |
Outlined code, not a real function.

`FUNC_REANALYZE`
 |
Function frame changed, request to reanalyze the function after the last insn is analyzed.

`FUNC_UNWIND`
 |
function is an exception unwind handler

`FUNC_CATCH`
 |
function is an exception catch handler

`MOVE_FUNC_OK`
 |
ok

`MOVE_FUNC_NOCODE`
 |
no instruction at 'newstart'

`MOVE_FUNC_BADSTART`
 |
bad new start address

`MOVE_FUNC_NOFUNC`
 |
no function at 'ea'

`MOVE_FUNC_REFUSED`
 |
a plugin refused the action

`FIND_FUNC_NORMAL`
 |
stop processing if undefined byte is encountered

`FIND_FUNC_DEFINE`
 |
create instruction if undefined byte is encountered

`FIND_FUNC_IGNOREFN`
 |
ignore existing function boundaries. by default the function returns function boundaries if ea belongs to a function.

`FIND_FUNC_KEEPBD`
 |
do not modify incoming function boundaries, just create instructions inside the boundaries.

`FIND_FUNC_UNDEF`
 |
function has instructions that pass execution flow to unexplored bytes. nfn->end_ea will have the address of the unexplored byte.

`FIND_FUNC_OK`
 |
ok, 'nfn' is ready for add_func()

`FIND_FUNC_EXIST`
 |
function exists already. its bounds are returned in 'nfn'.

`IDASGN_OK`
 |
ok

`IDASGN_BADARG`
 |
bad number of signature

`IDASGN_APPLIED`
 |
signature is already applied

`IDASGN_CURRENT`
 |
signature is currently being applied

`IDASGN_PLANNED`
 |
signature is planned to be applied

`LIBFUNC_FOUND`
 |
ok, library function is found

`LIBFUNC_NONE`
 |
no, this is not a library function

`LIBFUNC_DELAY`
 |
no decision because of lack of information

## Classes

`dyn_stkpnt_array`
 |

`dyn_regvar_array`
 |

`dyn_range_array`
 |

`dyn_ea_array`
 |

`dyn_regarg_array`
 |

`regarg_t`
 |

`func_t`
 |

`lock_func`
 |

`lock_func_with_tails_t`
 |

`func_tail_iterator_t`
 |

`func_item_iterator_t`
 |

`func_parent_iterator_t`
 |

## Functions

`free_regarg`(→ None)
 |

`is_func_entry`(→ bool)
 |
Does function describe a function entry chunk?

`is_func_tail`(→ bool)
 |
Does function describe a function tail chunk?

`lock_func_range`(→ None)
 |
Lock function pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved.

`is_func_locked`(→ bool)
 |
Is the function pointer locked?

`get_func`(→ func_t *)
 |
Get pointer to function structure by address.

`get_func_chunknum`(→ int)
 |
Get the containing tail chunk of 'ea'.

`func_contains`(→ bool)
 |
Does the given function contain the given address?

`is_same_func`(→ bool)
 |
Do two addresses belong to the same function?

`getn_func`(→ func_t *)
 |
Get pointer to function structure by number.

`get_func_qty`(→ int)
 |
Get total number of functions in the program.

`get_func_num`(→ int)
 |
Get ordinal number of a function.

`get_prev_func`(→ func_t *)
 |
Get pointer to the previous function.

`get_next_func`(→ func_t *)
 |
Get pointer to the next function.

`get_func_ranges`(→ ida_idaapi.ea_t)
 |
Get function ranges.

`get_func_cmt`(→ str)
 |
Get function comment.

`set_func_cmt`(→ bool)
 |
Set function comment. This function works with function chunks too.

`update_func`(→ bool)
 |
Update information about a function in the database (func_t). You must not change the function start and end addresses using this function. Use set_func_start() and set_func_end() for it.

`add_func_ex`(→ bool)
 |
Add a new function. If the fn->end_ea is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(..., FIND_FUNC_DEFINE).

`add_func`(→ bool)
 |
Add a new function. If the function end address is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(..., FIND_FUNC_DEFINE).

`del_func`(→ bool)
 |
Delete a function.

`set_func_start`(→ int)
 |
Move function chunk start address.

`set_func_end`(→ bool)
 |
Move function chunk end address.

`reanalyze_function`(→ None)
 |
Reanalyze a function. This function plans to analyzes all chunks of the given function. Optional parameters (ea1, ea2) may be used to narrow the analyzed range.

`find_func_bounds`(→ int)
 |
Determine the boundaries of a new function. This function tries to find the start and end addresses of a new function. It calls the module with processor_t::func_bounds in order to fine tune the function boundaries.

`get_func_name`(→ str)
 |
Get function name.

`calc_func_size`(→ asize_t)
 |
Calculate function size. This function takes into account all fragments of the function.

`get_func_bitness`(→ int)
 |
Get function bitness (which is equal to the function segment bitness). pfn==nullptr => returns 0

`get_func_bits`(→ int)
 |
Get number of bits in the function addressing.

`get_func_bytes`(→ int)
 |
Get number of bytes in the function addressing.

`is_visible_func`(→ bool)
 |
Is the function visible (not hidden)?

`is_finally_visible_func`(→ bool)
 |
Is the function visible (event after considering SCF_SHHID_FUNC)?

`set_visible_func`(→ None)
 |
Set visibility of function.

`set_func_name_if_jumpfunc`(→ int)
 |
Give a meaningful name to function if it consists of only 'jump' instruction.

`calc_thunk_func_target`(*args)
 |
Calculate target of a thunk function.

`func_does_return`(→ bool)
 |
Does the function return? To calculate the answer, FUNC_NORET flag and is_noret() are consulted The latter is required for imported functions in the .idata section. Since in .idata we have only function pointers but not functions, we have to introduce a special flag for them.

`reanalyze_noret_flag`(→ bool)
 |
Plan to reanalyze noret flag. This function does not remove FUNC_NORET if it is already present. It just plans to reanalysis.

`set_noret_insn`(→ bool)
 |
Signal a non-returning instruction. This function can be used by the processor module to tell the kernel about non-returning instructions (like call exit). The kernel will perform the global function analysis and find out if the function returns at all. This analysis will be done at the first call to func_does_return()

`get_fchunk`(→ func_t *)
 |
Get pointer to function chunk structure by address.

`getn_fchunk`(→ func_t *)
 |
Get pointer to function chunk structure by number.

`get_fchunk_qty`(→ int)
 |
Get total number of function chunks in the program.

`get_fchunk_num`(→ int)
 |
Get ordinal number of a function chunk in the global list of function chunks.

`get_prev_fchunk`(→ func_t *)
 |
Get pointer to the previous function chunk in the global list.

`get_next_fchunk`(→ func_t *)
 |
Get pointer to the next function chunk in the global list.

`append_func_tail`(→ bool)
 |
Append a new tail chunk to the function definition. If the tail already exists, then it will simply be added to the function tail list Otherwise a new tail will be created and its owner will be set to be our function If a new tail cannot be created, then this function will fail.

`remove_func_tail`(→ bool)
 |
Remove a function tail. If the tail belongs only to one function, it will be completely removed. Otherwise if the function was the tail owner, the first function using this tail becomes the owner of the tail.

`set_tail_owner`(→ bool)
 |
Set a new owner of a function tail. The new owner function must be already referring to the tail (after append_func_tail).

`func_tail_iterator_set`(→ bool)
 |

`func_tail_iterator_set_ea`(→ bool)
 |

`func_parent_iterator_set`(→ bool)
 |

`f_any`(→ bool)
 |
Helper function to accept any address.

`get_prev_func_addr`(→ ida_idaapi.ea_t)
 |

`get_next_func_addr`(→ ida_idaapi.ea_t)
 |

`read_regargs`(→ None)
 |

`add_regarg`(→ None)
 |

`plan_to_apply_idasgn`(→ int)
 |
Add a signature file to the list of planned signature files.

`apply_idasgn_to`(→ int)
 |
Apply a signature file to the specified address.

`get_idasgn_qty`(→ int)
 |
Get number of signatures in the list of planned and applied signatures.

`get_current_idasgn`(→ int)
 |
Get number of the current signature.

`calc_idasgn_state`(→ int)
 |
Get state of a signature in the list of planned signatures

`del_idasgn`(→ int)
 |
Remove signature from the list of planned signatures.

`get_idasgn_title`(→ str)
 |
Get full description of the signature by its short name.

`apply_startup_sig`(→ bool)
 |
Apply a startup signature file to the specified address.

`try_to_add_libfunc`(→ int)
 |
Apply the currently loaded signature file to the specified address. If a library function is found, then create a function and name it accordingly.

`get_fchunk_referer`(ea, idx)
 |

`get_idasgn_desc`(n)
 |
Get information about a signature in the list.

`get_idasgn_desc_with_matches`(n)
 |
Get information about a signature in the list.

`func_t__from_ptrval__`(→ func_t *)
 |

`calc_thunk_func_target`(*args)
 |
Calculate target of a thunk function.

## Module Contents

classida_funcs.dyn_stkpnt_array(_data:stkpnt_t*, _count:int)
Bases: `object`
thisowndata:stkpnt_t*count:intclassida_funcs.dyn_regvar_array(_data:regvar_t*, _count:int)
Bases: `object`
thisowndata:regvar_t*count:intclassida_funcs.dyn_range_array(_data:range_t, _count:int)
Bases: `object`
thisowndata:range_t*count:intclassida_funcs.dyn_ea_array(_data:unsignedlonglong*, _count:int)
Bases: `object`
thisowndata:unsignedlonglong*count:intclassida_funcs.dyn_regarg_array(_data:regarg_t, _count:int)
Bases: `object`
thisowndata:regarg_t*count:intida_funcs.free_regarg(v:regarg_t)→Noneclassida_funcs.regarg_t(*args)
Bases: `object`
thisownreg:inttype:type_t*name:char*swap(r:regarg_t)→Noneclassida_funcs.func_t(start:ida_idaapi.ea_t=0, end:ida_idaapi.ea_t=0, f:flags64_t=0)
Bases: `ida_range.range_t`
thisownflags:uint64
Function flags
is_far()→bool
Is a far function?
does_return()→bool
Does function return?
analyzed_sp()→bool
Has SP-analysis been performed?
need_prolog_analysis()→bool
Needs prolog analysis?
frame:int
netnode id of frame structure - see frame.hpp
frsize:asize_t
size of local variables part of frame in bytes. If FUNC_FRAME is set and fpd==0, the frame pointer (EBP) is assumed to point to the top of the local variables range.
frregs:ushort
size of saved registers in frame. This range is immediately above the local variables range.
argsize:asize_t
number of bytes purged from the stack upon returning
fpd:asize_t
frame pointer delta. (usually 0, i.e. realBP==typicalBP) use update_fpd() to modify it.
color:bgcolor_t
user defined function color
pntqty:int
number of SP change points
points:stkpnt_t*
array of SP change points. use …stkpnt…() functions to access this array.
regvarqty:int
number of register variables (-1-not read in yet) use find_regvar() to read register variables
regvars:regvar_t*
array of register variables. this array is sorted by: start_ea. use …regvar…() functions to access this array.
regargqty:int
number of register arguments. During analysis IDA tries to guess the register arguments. It stores store the guessing outcome in this field. As soon as it determines the final function prototype, regargqty is set to zero.
regargs:regarg_t*
unsorted array of register arguments. use …regarg…() functions to access this array. regargs are destroyed when the full function type is determined.
tailqty:int
number of function tails
tails:range_t*
array of tails, sorted by ea. use func_tail_iterator_t to access function tails.
owner:ida_idaapi.ea_t
the address of the main function possessing this tail
refqty:int
number of referers
referers:ea_t*
array of referers (function start addresses). use func_parent_iterator_t to access the referers.
addresses()
Alias for func_item_iterator_t(self).addresses()
code_items()
Alias for func_item_iterator_t(self).code_items()
data_items()
Alias for func_item_iterator_t(self).data_items()
head_items()
Alias for func_item_iterator_t(self).head_items()
not_tails()
Alias for func_item_iterator_t(self).not_tails()
get_frame_object()
Retrieve the function frame, in the form of a structure where frame offsets that are accessed by the program, as well as areas for “saved registers” and “return address”, are represented by structure members.

If the function has no associated frame, return None
Returns:
a ida_typeinf.tinfo_t object representing the frame, or None
get_name()
Get the function name
Returns:
the function name
get_prototype()
Retrieve the function prototype.

Once you have obtained the prototype, you can:

-
retrieve the return type through ida_typeinf.tinfo_t.get_rettype()

-
iterate on the arguments using ida_typeinf.tinfo_t.iter_func()

If the function has no associated prototype, return None
Returns:
a ida_typeinf.tinfo_t object representing the prototype, or None
frame_objectnameprototypeida_funcs.FUNC_NORET
Function doesn’t return.
ida_funcs.FUNC_FAR
Far function.
ida_funcs.FUNC_LIB
Library function.
ida_funcs.FUNC_STATICDEF
Static function.
ida_funcs.FUNC_FRAME
Function uses frame pointer (BP)
ida_funcs.FUNC_USERFAR
User has specified far-ness of the function
ida_funcs.FUNC_HIDDEN
A hidden function chunk.
ida_funcs.FUNC_THUNK
Thunk (jump) function.
ida_funcs.FUNC_BOTTOMBP
BP points to the bottom of the stack frame.
ida_funcs.FUNC_NORET_PENDING
Function ‘non-return’ analysis must be performed. This flag is verified upon func_does_return()
ida_funcs.FUNC_SP_READY
SP-analysis has been performed. If this flag is on, the stack change points should not be not modified anymore. Currently this analysis is performed only for PC
ida_funcs.FUNC_FUZZY_SP
Function changes SP in untraceable way, for example: and esp, 0FFFFFFF0h
ida_funcs.FUNC_PROLOG_OK
Prolog analysis has been performed by last SP-analysis
ida_funcs.FUNC_PURGED_OK
‘argsize’ field has been validated. If this bit is clear and ‘argsize’ is 0, then we do not known the real number of bytes removed from the stack. This bit is handled by the processor module.
ida_funcs.FUNC_TAIL
This is a function tail. Other bits must be clear (except FUNC_HIDDEN).
ida_funcs.FUNC_LUMINA
Function info is provided by Lumina.
ida_funcs.FUNC_OUTLINE
Outlined code, not a real function.
ida_funcs.FUNC_REANALYZE
Function frame changed, request to reanalyze the function after the last insn is analyzed.
ida_funcs.FUNC_UNWIND
function is an exception unwind handler
ida_funcs.FUNC_CATCH
function is an exception catch handler
ida_funcs.is_func_entry(pfn:func_t)→bool
Does function describe a function entry chunk?
ida_funcs.is_func_tail(pfn:func_t)→bool
Does function describe a function tail chunk?
ida_funcs.lock_func_range(pfn:func_t, lock:bool)→None
Lock function pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved.
classida_funcs.lock_func(_pfn:func_t)
Bases: `object`
thisownclassida_funcs.lock_func_with_tails_t(pfn:func_t)
Bases: `object`
thisownida_funcs.is_func_locked(pfn:func_t)→bool
Is the function pointer locked?
ida_funcs.get_func(ea:ida_idaapi.ea_t)→func_t*
Get pointer to function structure by address.
Parameters:
ea – any address in a function
Returns:
ptr to a function or nullptr. This function returns a function entry chunk.
ida_funcs.get_func_chunknum(pfn:func_t, ea:ida_idaapi.ea_t)→int
Get the containing tail chunk of ‘ea’.
Returns:
-1: means ‘does not contain ea’
Returns:
0: means the ‘pfn’ itself contains ea
Returns:
>0: the number of the containing function tail chunk
ida_funcs.func_contains(pfn:func_t, ea:ida_idaapi.ea_t)→bool
Does the given function contain the given address?
ida_funcs.is_same_func(ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t)→bool
Do two addresses belong to the same function?
ida_funcs.getn_func(n:int)→func_t*
Get pointer to function structure by number.
Parameters:
n – number of function, is in range 0..get_func_qty()-1
Returns:
ptr to a function or nullptr. This function returns a function entry chunk.
ida_funcs.get_func_qty()→int
Get total number of functions in the program.
ida_funcs.get_func_num(ea:ida_idaapi.ea_t)→int
Get ordinal number of a function.
Parameters:
ea – any address in the function
Returns:
number of function (0..get_func_qty()-1). -1 means ‘no function at the specified address’.
ida_funcs.get_prev_func(ea:ida_idaapi.ea_t)→func_t*
Get pointer to the previous function.
Parameters:
ea – any address in the program
Returns:
ptr to function or nullptr if previous function doesn’t exist
ida_funcs.get_next_func(ea:ida_idaapi.ea_t)→func_t*
Get pointer to the next function.
Parameters:
ea – any address in the program
Returns:
ptr to function or nullptr if next function doesn’t exist
ida_funcs.get_func_ranges(ranges:rangeset_t, pfn:func_t)→ida_idaapi.ea_t
Get function ranges.
Parameters:

-
ranges – buffer to receive the range info

-
pfn – ptr to function structure

Returns:
end address of the last function range (BADADDR-error)
ida_funcs.get_func_cmt(pfn:func_t, repeatable:bool)→str
Get function comment.
Parameters:

-
pfn – ptr to function structure

-
repeatable – get repeatable comment?

Returns:
size of comment or -1 In fact this function works with function chunks too.
ida_funcs.set_func_cmt(pfn:func_t, cmt:str, repeatable:bool)→bool
Set function comment. This function works with function chunks too.
Parameters:

-
pfn – ptr to function structure

-
cmt – comment string, may be multiline (with ‘

‘). Use empty str (“”) to delete comment :param repeatable: set repeatable comment?
ida_funcs.update_func(pfn:func_t)→bool
Update information about a function in the database (func_t). You must not change the function start and end addresses using this function. Use set_func_start() and set_func_end() for it.
Parameters:
pfn – ptr to function structure
Returns:
success
ida_funcs.add_func_ex(pfn:func_t)→bool
Add a new function. If the fn->end_ea is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(…, FIND_FUNC_DEFINE).
Parameters:
pfn – ptr to filled function structure
Returns:
success
ida_funcs.add_func(*args)→bool
Add a new function. If the function end address is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(…, FIND_FUNC_DEFINE).
Parameters:

-
ea1 – start address

-
ea2 – end address

Returns:
success
ida_funcs.del_func(ea:ida_idaapi.ea_t)→bool
Delete a function.
Parameters:
ea – any address in the function entry chunk
Returns:
success
ida_funcs.set_func_start(ea:ida_idaapi.ea_t, newstart:ida_idaapi.ea_t)→int
Move function chunk start address.
Parameters:

-
ea – any address in the function

-
newstart – new end address of the function

Returns:
Function move result codes
ida_funcs.MOVE_FUNC_OK
ok
ida_funcs.MOVE_FUNC_NOCODE
no instruction at ‘newstart’
ida_funcs.MOVE_FUNC_BADSTART
bad new start address
ida_funcs.MOVE_FUNC_NOFUNC
no function at ‘ea’
ida_funcs.MOVE_FUNC_REFUSED
a plugin refused the action
ida_funcs.set_func_end(ea:ida_idaapi.ea_t, newend:ida_idaapi.ea_t)→bool
Move function chunk end address.
Parameters:

-
ea – any address in the function

-
newend – new end address of the function

Returns:
success
ida_funcs.reanalyze_function(*args)→None
Reanalyze a function. This function plans to analyzes all chunks of the given function. Optional parameters (ea1, ea2) may be used to narrow the analyzed range.
Parameters:

-
pfn – pointer to a function

-
ea1 – start of the range to analyze

-
ea2 – end of range to analyze

-
analyze_parents – meaningful only if pfn points to a function tail. if true, all tail parents will be reanalyzed. if false, only the given tail will be reanalyzed.

ida_funcs.find_func_bounds(nfn:func_t, flags:int)→int
Determine the boundaries of a new function. This function tries to find the start and end addresses of a new function. It calls the module with processor_t::func_bounds in order to fine tune the function boundaries.
Parameters:

-
nfn – structure to fill with information nfn->start_ea points to the start address of the new function.

-
flags – Find function bounds flags

Returns:
Find function bounds result codes
ida_funcs.FIND_FUNC_NORMAL
stop processing if undefined byte is encountered
ida_funcs.FIND_FUNC_DEFINE
create instruction if undefined byte is encountered
ida_funcs.FIND_FUNC_IGNOREFN
ignore existing function boundaries. by default the function returns function boundaries if ea belongs to a function.
ida_funcs.FIND_FUNC_KEEPBD
do not modify incoming function boundaries, just create instructions inside the boundaries.
ida_funcs.FIND_FUNC_UNDEF
function has instructions that pass execution flow to unexplored bytes. nfn->end_ea will have the address of the unexplored byte.
ida_funcs.FIND_FUNC_OK
ok, ‘nfn’ is ready for add_func()
ida_funcs.FIND_FUNC_EXIST
function exists already. its bounds are returned in ‘nfn’.
ida_funcs.get_func_name(ea:ida_idaapi.ea_t)→str
Get function name.
Parameters:
ea – any address in the function
Returns:
length of the function name
ida_funcs.calc_func_size(pfn:func_t)→asize_t
Calculate function size. This function takes into account all fragments of the function.
Parameters:
pfn – ptr to function structure
ida_funcs.get_func_bitness(pfn:func_t)→int
Get function bitness (which is equal to the function segment bitness). pfn==nullptr => returns 0
Returns:
0: 16
Returns:
1: 32
Returns:
2: 64
ida_funcs.get_func_bits(pfn:func_t)→int
Get number of bits in the function addressing.
ida_funcs.get_func_bytes(pfn:func_t)→int
Get number of bytes in the function addressing.
ida_funcs.is_visible_func(pfn:func_t)→bool
Is the function visible (not hidden)?
ida_funcs.is_finally_visible_func(pfn:func_t)→bool
Is the function visible (event after considering SCF_SHHID_FUNC)?
ida_funcs.set_visible_func(pfn:func_t, visible:bool)→None
Set visibility of function.
ida_funcs.set_func_name_if_jumpfunc(pfn:func_t, oldname:str)→int
Give a meaningful name to function if it consists of only ‘jump’ instruction.
Parameters:

-
pfn – pointer to function (may be nullptr)

-
oldname – old name of function. if old name was in “j_…” form, then we may discard it and set a new name. if oldname is not known, you may pass nullptr.

Returns:
success
ida_funcs.calc_thunk_func_target(pfn:func_t)→ea_t*
Calculate target of a thunk function.
Parameters:
pfn – pointer to function (may not be nullptr)
Returns:
the target function or BADADDR
ida_funcs.func_does_return(callee:ida_idaapi.ea_t)→bool
Does the function return? To calculate the answer, FUNC_NORET flag and is_noret() are consulted The latter is required for imported functions in the .idata section. Since in .idata we have only function pointers but not functions, we have to introduce a special flag for them.
ida_funcs.reanalyze_noret_flag(ea:ida_idaapi.ea_t)→bool
Plan to reanalyze noret flag. This function does not remove FUNC_NORET if it is already present. It just plans to reanalysis.
ida_funcs.set_noret_insn(insn_ea:ida_idaapi.ea_t, noret:bool)→bool
Signal a non-returning instruction. This function can be used by the processor module to tell the kernel about non-returning instructions (like call exit). The kernel will perform the global function analysis and find out if the function returns at all. This analysis will be done at the first call to func_does_return()
Returns:
true if the instruction ‘noret’ flag has been changed
ida_funcs.get_fchunk(ea:ida_idaapi.ea_t)→func_t*
Get pointer to function chunk structure by address.
Parameters:
ea – any address in a function chunk
Returns:
ptr to a function chunk or nullptr. This function may return a function entry as well as a function tail.
ida_funcs.getn_fchunk(n:int)→func_t*
Get pointer to function chunk structure by number.
Parameters:
n – number of function chunk, is in range 0..get_fchunk_qty()-1
Returns:
ptr to a function chunk or nullptr. This function may return a function entry as well as a function tail.
ida_funcs.get_fchunk_qty()→int
Get total number of function chunks in the program.
ida_funcs.get_fchunk_num(ea:ida_idaapi.ea_t)→int
Get ordinal number of a function chunk in the global list of function chunks.
Parameters:
ea – any address in the function chunk
Returns:
number of function chunk (0..get_fchunk_qty()-1). -1 means ‘no function chunk at the specified address’.
ida_funcs.get_prev_fchunk(ea:ida_idaapi.ea_t)→func_t*
Get pointer to the previous function chunk in the global list.
Parameters:
ea – any address in the program
Returns:
ptr to function chunk or nullptr if previous function chunk doesn’t exist
ida_funcs.get_next_fchunk(ea:ida_idaapi.ea_t)→func_t*
Get pointer to the next function chunk in the global list.
Parameters:
ea – any address in the program
Returns:
ptr to function chunk or nullptr if next function chunk doesn’t exist
ida_funcs.append_func_tail(pfn:func_t, ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t)→bool
Append a new tail chunk to the function definition. If the tail already exists, then it will simply be added to the function tail list Otherwise a new tail will be created and its owner will be set to be our function If a new tail cannot be created, then this function will fail.
Parameters:

-
pfn – pointer to the function

-
ea1 – start of the tail. If a tail already exists at the specified address it must start at ‘ea1’

-
ea2 – end of the tail. If a tail already exists at the specified address it must end at ‘ea2’. If specified as BADADDR, IDA will determine the end address itself.

ida_funcs.remove_func_tail(pfn:func_t, tail_ea:ida_idaapi.ea_t)→bool
Remove a function tail. If the tail belongs only to one function, it will be completely removed. Otherwise if the function was the tail owner, the first function using this tail becomes the owner of the tail.
Parameters:

-
pfn – pointer to the function

-
tail_ea – any address inside the tail to remove

ida_funcs.set_tail_owner(fnt:func_t, new_owner:ida_idaapi.ea_t)→bool
Set a new owner of a function tail. The new owner function must be already referring to the tail (after append_func_tail).
Parameters:

-
fnt – pointer to the function tail

-
new_owner – the entry point of the new owner function

ida_funcs.func_tail_iterator_set(fti:func_tail_iterator_t, pfn:func_t, ea:ida_idaapi.ea_t)→boolida_funcs.func_tail_iterator_set_ea(fti:func_tail_iterator_t, ea:ida_idaapi.ea_t)→boolida_funcs.func_parent_iterator_set(fpi:func_parent_iterator_t, pfn:func_t)→boolida_funcs.f_any(arg1:flags64_t, arg2:void*)→bool
Helper function to accept any address.
classida_funcs.func_tail_iterator_t(*args)
Bases: `object`
thisownset(*args)→boolset_ea(ea:ida_idaapi.ea_t)→boolset_range(ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t)→boolchunk()→range_tconst&first()→boollast()→boolprev()→boolmain()→boolnextclassida_funcs.func_item_iterator_t(*args)
Bases: `object`
thisownset(*args)→bool
Set a function range. if pfn == nullptr then a segment range will be set.
set_range(ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t)→bool
Set an arbitrary range.
first()→boollast()→boolcurrent()→ida_idaapi.ea_tset_ea(_ea:ida_idaapi.ea_t)→boolchunk()→range_tconst&prev(func:testf_t*)→boolnext_addr()→boolnext_head()→boolnext_code()→boolnext_data()→boolnext_not_tail()→boolprev_addr()→boolprev_head()→boolprev_code()→boolprev_data()→boolprev_not_tail()→booldecode_prev_insn(out:insn_t*)→booldecode_preceding_insn(visited:eavec_t*, p_farref:bool*, out:insn_t*)→boolsucc(func:testf_t*)→bool
Similar to next(), but succ() iterates the chunks from low to high addresses, while next() iterates through chunks starting at the function entry chunk
succ_code()→boolnextaddresses()
Provide an iterator on addresses contained within the function
code_items()
Provide an iterator on code items contained within the function
data_items()
Provide an iterator on data items contained within the function
head_items()
Provide an iterator on item heads contained within the function
not_tails()
Provide an iterator on non-tail addresses contained within the function
classida_funcs.func_parent_iterator_t(*args)
Bases: `object`
thisownset(_fnt:func_t)→boolparent()→ida_idaapi.ea_tfirst()→boollast()→boolprev()→boolreset_fnt(_fnt:func_t)→Nonenextida_funcs.get_prev_func_addr(pfn:func_t, ea:ida_idaapi.ea_t)→ida_idaapi.ea_tida_funcs.get_next_func_addr(pfn:func_t, ea:ida_idaapi.ea_t)→ida_idaapi.ea_tida_funcs.read_regargs(pfn:func_t)→Noneida_funcs.add_regarg(pfn:func_t, reg:int, tif:tinfo_t, name:str)→Noneida_funcs.IDASGN_OK
ok
ida_funcs.IDASGN_BADARG
bad number of signature
ida_funcs.IDASGN_APPLIED
signature is already applied
ida_funcs.IDASGN_CURRENT
signature is currently being applied
ida_funcs.IDASGN_PLANNED
signature is planned to be applied
ida_funcs.plan_to_apply_idasgn(fname:str)→int
Add a signature file to the list of planned signature files.
Parameters:
fname – file name. should not contain directory part.
Returns:
0 if failed, otherwise number of planned (and applied) signatures
ida_funcs.apply_idasgn_to(signame:str, ea:ida_idaapi.ea_t, is_startup:bool)→int
Apply a signature file to the specified address.
Parameters:

-
signame – short name of signature file (the file name without path)

-
ea – address to apply the signature

-
is_startup – if set, then the signature is treated as a startup one for startup signature ida doesn’t rename the first function of the applied module.

Returns:
Library function codes
ida_funcs.get_idasgn_qty()→int
Get number of signatures in the list of planned and applied signatures.
Returns:
0..n
ida_funcs.get_current_idasgn()→int
Get number of the current signature.
Returns:
0..n-1
ida_funcs.calc_idasgn_state(n:int)→int
Get state of a signature in the list of planned signatures
Parameters:
n – number of signature in the list (0..get_idasgn_qty()-1)
Returns:
state of signature or IDASGN_BADARG
ida_funcs.del_idasgn(n:int)→int
Remove signature from the list of planned signatures.
Parameters:
n – number of signature in the list (0..get_idasgn_qty()-1)
Returns:
IDASGN_OK, IDASGN_BADARG, IDASGN_APPLIED
ida_funcs.get_idasgn_title(name:str)→str
Get full description of the signature by its short name.
Parameters:
name – short name of a signature
Returns:
size of signature description or -1
ida_funcs.apply_startup_sig(ea:ida_idaapi.ea_t, startup:str)→bool
Apply a startup signature file to the specified address.
Parameters:

-
ea – address to apply the signature to; usually idainfo::start_ea

-
startup – the name of the signature file without path and extension

Returns:
true if successfully applied the signature
ida_funcs.try_to_add_libfunc(ea:ida_idaapi.ea_t)→int
Apply the currently loaded signature file to the specified address. If a library function is found, then create a function and name it accordingly.
Parameters:
ea – any address in the program
Returns:
Library function codes
ida_funcs.LIBFUNC_FOUND
ok, library function is found
ida_funcs.LIBFUNC_NONE
no, this is not a library function
ida_funcs.LIBFUNC_DELAY
no decision because of lack of information
ida_funcs.get_fchunk_referer(ea:int, idx)ida_funcs.get_idasgn_desc(n)
Get information about a signature in the list. It returns: (name of signature, names of optional libraries)

See also: get_idasgn_desc_with_matches
Parameters:
n – number of signature in the list (0..get_idasgn_qty()-1)
Returns:
None on failure or tuple(signame, optlibs)
ida_funcs.get_idasgn_desc_with_matches(n)
Get information about a signature in the list. It returns: (name of signature, names of optional libraries, number of matches)
Parameters:
n – number of signature in the list (0..get_idasgn_qty()-1)
Returns:
None on failure or tuple(signame, optlibs, nmatches)
ida_funcs.func_t__from_ptrval__(ptrval:int)→func_t*ida_funcs.calc_thunk_func_target(*args)
Calculate target of a thunk function.
Parameters:

-
pfn – pointer to function (may not be nullptr)

-
fptr – out: will hold address of a function pointer (if indirect jump)

Returns:
the target function or BADADDR
