# IDAPython debugger API

- 官方来源：https://python.docs.hex-rays.com/ida_dbg/index.html

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
- ida_dbg
- View page source

# ida_dbg

Contains functions to control the debugging of a process.

See Debugger functions for a complete explanation of these functions. These functions are inlined for the kernel. They are not inlined for the user interface.

## Attributes

`dbg_null`
|

`dbg_process_start`
|

`dbg_process_exit`
|

`dbg_process_attach`
|

`dbg_process_detach`
|

`dbg_thread_start`
|

`dbg_thread_exit`
|

`dbg_library_load`
|

`dbg_library_unload`
|

`dbg_information`
|

`dbg_exception`
|

`dbg_suspend_process`
|
The process is now suspended.

`dbg_bpt`
|
A user defined breakpoint was reached.

`dbg_trace`
|
A step occurred (one instruction was executed). This event notification is only generated if step tracing is enabled.

`dbg_request_error`
|
An error occurred during the processing of a request.

`dbg_step_into`
|

`dbg_step_over`
|

`dbg_run_to`
|

`dbg_step_until_ret`
|

`dbg_bpt_changed`
|
Breakpoint has been changed.

`dbg_started_loading_bpts`
|
Started loading breakpoint info from idb.

`dbg_finished_loading_bpts`
|
Finished loading breakpoint info from idb.

`dbg_last`
|
The last debugger notification code.

`BPTEV_ADDED`
|
Breakpoint has been added.

`BPTEV_REMOVED`
|
Breakpoint has been removed.

`BPTEV_CHANGED`
|
Breakpoint has been modified.

`DSTATE_SUSP`
|
process is suspended and will not continue

`DSTATE_NOTASK`
|
no process is currently debugged

`DSTATE_RUN`
|
process is running

`DBGINV_MEMORY`
|
invalidate cached memory contents

`DBGINV_MEMCFG`
|
invalidate cached process segmentation

`DBGINV_REGS`
|
invalidate cached register values

`DBGINV_ALL`
|
invalidate everything

`DBGINV_REDRAW`
|
refresh the screen

`DBGINV_NONE`
|
invalidate nothing

`MOVBPT_OK`
|
moved ok

`MOVBPT_NOT_FOUND`
|
source bpt not found

`MOVBPT_DEST_BUSY`
|
destination location is busy (we already have such a bpt)

`MOVBPT_BAD_TYPE`
|
BPLT_ABS is not supported.

`BPLT_ABS`
|
absolute address: ea

`BPLT_REL`
|
relative address: module_path, offset

`BPLT_SYM`
|
symbolic: symbol_name, offset

`BPLT_SRC`
|
source level: filename, lineno

`BPT_BRK`
|
suspend execution upon hit

`BPT_TRACE`
|
add trace information upon hit

`BPT_UPDMEM`
|
refresh the memory layout and contents before evaluating bpt condition

`BPT_ENABLED`
|
enabled?

`BPT_LOWCND`
|
condition is calculated at low level (on the server side)

`BPT_TRACEON`
|
enable tracing when the breakpoint is reached

`BPT_TRACE_INSN`
|
instruction tracing

`BPT_TRACE_FUNC`
|
function tracing

`BPT_TRACE_BBLK`
|
basic block tracing

`BPT_TRACE_TYPES`
|
trace insns, functions, and basic blocks. if any of BPT_TRACE_TYPES bits are set but BPT_TRACEON is clear, then turn off tracing for the specified trace types

`BPT_ELANG_MASK`
|

`BPT_ELANG_SHIFT`
|
index of the extlang (scripting language) of the condition

`BKPT_BADBPT`
|
failed to write the bpt to the process memory (at least one location)

`BKPT_LISTBPT`
|
include in bpt list (user-defined bpt)

`BKPT_TRACE`
|
trace bpt; should not be deleted when the process gets suspended

`BKPT_ACTIVE`
|
active?

`BKPT_PARTIAL`
|
partially active? (some locations were not written yet)

`BKPT_CNDREADY`
|
condition has been compiled

`BKPT_FAKEPEND`
|
fake pending bpt: it is inactive but another bpt of the same type is active at the same address(es)

`BKPT_PAGE`
|
written to the process as a page bpt. Available only after writing the bpt to the process.

`BPTCK_NONE`
|
breakpoint does not exist

`BPTCK_NO`
|
breakpoint is disabled

`BPTCK_YES`
|
breakpoint is enabled

`BPTCK_ACT`
|
breakpoint is active (written to the process)

`ST_OVER_DEBUG_SEG`
|
step tracing will be disabled when IP is in a debugger segment

`ST_OVER_LIB_FUNC`
|
step tracing will be disabled when IP is in a library function

`ST_ALREADY_LOGGED`
|
step tracing will be disabled when IP is already logged

`ST_SKIP_LOOPS`
|
step tracing will try to skip loops already recorded

`ST_DIFFERENTIAL`
|
tracing: log only new instructions (not previously logged)

`ST_OPTIONS_MASK`
|
mask of available options, to ensure compatibility with newer IDA versions

`ST_OPTIONS_DEFAULT`
|

`IT_LOG_SAME_IP`
|
specific options for instruction tracing (see set_insn_trace_options())

`FT_LOG_RET`
|
specific options for function tracing (see set_func_trace_options())

`BT_LOG_INSTS`
|
specific options for basic block tracing (see set_bblk_trace_options())

`tev_none`
|
no event

`tev_insn`
|
an instruction trace

`tev_call`
|
a function call trace

`tev_ret`
|
a function return trace

`tev_bpt`
|
write, read/write, execution trace

`tev_mem`
|
memory layout changed

`tev_event`
|
debug event occurred

`tev_max`
|
first unused event type

`SAVE_ALL_VALUES`
|

`SAVE_DIFF`
|

`SAVE_NONE`
|

`DEC_NOTASK`
|
process does not exist

`DEC_ERROR`
|
error

`DEC_TIMEOUT`
|
timeout

`WFNE_ANY`
|
return the first event (even if it doesn't suspend the process)

`WFNE_SUSP`
|
wait until the process gets suspended

`WFNE_SILENT`
|
1: be silent, 0:display modal boxes if necessary

`WFNE_CONT`
|
continue from the suspended state

`WFNE_NOWAIT`
|
do not wait for any event, immediately return DEC_TIMEOUT (to be used with WFNE_CONT)

`WFNE_USEC`
|
timeout is specified in microseconds (minimum non-zero timeout is 40000us)

`DOPT_SEGM_MSGS`
|
log debugger segments modifications

`DOPT_START_BPT`
|
break on process start

`DOPT_THREAD_MSGS`
|
log thread starts/exits

`DOPT_THREAD_BPT`
|
break on thread start/exit

`DOPT_BPT_MSGS`
|
log breakpoints

`DOPT_LIB_MSGS`
|
log library loads/unloads

`DOPT_LIB_BPT`
|
break on library load/unload

`DOPT_INFO_MSGS`
|
log debugging info events

`DOPT_INFO_BPT`
|
break on debugging information

`DOPT_REAL_MEMORY`
|
do not hide breakpoint instructions

`DOPT_REDO_STACK`
|
reconstruct the stack

`DOPT_ENTRY_BPT`
|
break on program entry point

`DOPT_EXCDLG`
|
exception dialogs:

`EXCDLG_NEVER`
|
never display exception dialogs

`EXCDLG_UNKNOWN`
|
display for unknown exceptions

`EXCDLG_ALWAYS`
|
always display

`DOPT_LOAD_DINFO`
|
automatically load debug files (pdb)

`DOPT_END_BPT`
|
evaluate event condition on process end

`DOPT_TEMP_HWBPT`
|
when possible use hardware bpts for temp bpts

`DOPT_FAST_STEP`
|
prevent debugger memory refreshes when single-stepping

`DOPT_DISABLE_ASLR`
|
disable ASLR

`SRCIT_NONE`
|
unknown

`SRCIT_MODULE`
|
module

`SRCIT_FUNC`
|
function

`SRCIT_STMT`
|
a statement (if/while/for...)

`SRCIT_EXPR`
|
an expression (a+b*c)

`SRCIT_STTVAR`
|
static variable/code

`SRCIT_LOCVAR`
|
a stack, register, or register-relative local variable or parameter

`SRCDBG_PROV_VERSION`
|

`move_bpt_to_grp`
|

## Classes

`bpt_vec_t`
|

`tev_reg_values_t`
|

`tevinforeg_vec_t`
|

`memreg_infos_t`
|

`bptaddrs_t`
|

`bpt_location_t`
|

`bpt_t`
|

`tev_info_t`
|

`memreg_info_t`
|

`tev_reg_value_t`
|

`tev_info_reg_t`
|

`eval_ctx_t`
|

`dbg_deref_options_t`
|

`DBG_Hooks`
|

## Functions

`run_to`(→ bool)
|
Execute the process until the given address is reached. If no process is active, a new process is started. Technically, the debugger sets up a temporary breakpoint at the given address, and continues (or starts) the execution of the whole process. So, all threads continue their execution! sq{Type, Asynchronous function - available as Request, Notification, dbg_run_to}

`request_run_to`(→ bool)
|
Post a run_to() request.

`run_requests`(→ bool)
|
Execute requests until all requests are processed or an asynchronous function is called. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_running_request`(→ ui_notification_t)
|
Get the current running request. sq{Type, Synchronous function, Notification, none (synchronous function)}

`is_request_running`(→ bool)
|
Is a request currently running?

`get_running_notification`(→ dbg_notification_t)
|
Get the notification associated (if any) with the current running request. sq{Type, Synchronous function, Notification, none (synchronous function)}

`clear_requests_queue`(→ None)
|
Clear the queue of waiting requests. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_process_state`(→ int)
|
Return the state of the currently debugged process. sq{Type, Synchronous function, Notification, none (synchronous function)}

`is_valid_dstate`(→ bool)
|

`set_process_state`(→ int)
|
Set new state for the debugged process. Notifies the IDA kernel about the change of the debugged process state. For example, a debugger module could call this function when it knows that the process is suspended for a short period of time. Some IDA API calls can be made only when the process is suspended. The process state is usually restored before returning control to the caller. You must know that it is ok to change the process state, doing it at arbitrary moments may crash the application or IDA. sq{Type, Synchronous function, Notification, none (synchronous function)}

`invalidate_dbg_state`(→ int)
|
Invalidate cached debugger information. sq{Type, Synchronous function, Notification, none (synchronous function)}

`start_process`(→ int)
|
Start a process in the debugger. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_start}

`request_start_process`(→ int)
|
Post a start_process() request.

`suspend_process`(→ bool)
|
Suspend the process in the debugger. sq{ Type,

`request_suspend_process`(→ bool)
|
Post a suspend_process() request.

`continue_process`(→ bool)
|
Continue the execution of the process in the debugger. sq{Type, Synchronous function - available as Request, Notification, none (synchronous function)}

`request_continue_process`(→ bool)
|
Post a continue_process() request.

`continue_backwards`(→ bool)
|
Continue the execution of the process in the debugger backwards. Can only be used with debuggers that support time-travel debugging. sq{Type, Synchronous function - available as Request, Notification, none (synchronous function)}

`request_continue_backwards`(→ bool)
|
Post a continue_backwards() request.

`exit_process`(→ bool)
|
Terminate the debugging of the current process. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_exit}

`request_exit_process`(→ bool)
|
Post an exit_process() request.

`get_processes`(→ ssize_t)
|
Take a snapshot of running processes and return their description. sq{Type, Synchronous function, Notification, none (synchronous function)}

`attach_process`(→ int)
|
Attach the debugger to a running process. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_attach}

`request_attach_process`(→ int)
|
Post an attach_process() request.

`detach_process`(→ bool)
|
Detach the debugger from the debugged process. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_detach}

`request_detach_process`(→ bool)
|
Post a detach_process() request.

`is_debugger_busy`(→ bool)
|
Is the debugger busy?. Some debuggers do not accept any commands while the debugged application is running. For such a debugger, it is unsafe to do anything with the database (even simple queries like get_byte may lead to undesired consequences). Returns: true if the debugged application is running under such a debugger

`get_thread_qty`(→ int)
|
Get number of threads. sq{Type, Synchronous function, Notification, none (synchronous function)}

`getn_thread`(→ thid_t)
|
Get the ID of a thread. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_current_thread`(→ thid_t)
|
Get current thread ID. sq{Type, Synchronous function, Notification, none (synchronous function)}

`getn_thread_name`(→ str)
|
Get the NAME of a thread sq{Type, Synchronous function, Notification, none (synchronous function)}

`select_thread`(→ bool)
|
Select the given thread as the current debugged thread. All thread related execution functions will work on this thread. The process must be suspended to select a new thread. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_select_thread`(→ bool)
|
Post a select_thread() request.

`suspend_thread`(→ int)
|
Suspend thread. Suspending a thread may deadlock the whole application if the suspended was owning some synchronization objects. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_suspend_thread`(→ int)
|
Post a suspend_thread() request.

`resume_thread`(→ int)
|
Resume thread. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_resume_thread`(→ int)
|
Post a resume_thread() request.

`get_first_module`(→ bool)
|

`get_next_module`(→ bool)
|

`step_into`(→ bool)
|
Execute one instruction in the current thread. Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_into}

`request_step_into`(→ bool)
|
Post a step_into() request.

`step_over`(→ bool)
|
Execute one instruction in the current thread, but without entering into functions. Others threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_over}

`request_step_over`(→ bool)
|
Post a step_over() request.

`step_into_backwards`(→ bool)
|
Execute one instruction backwards in the current thread. Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_into}

`request_step_into_backwards`(→ bool)
|
Post a step_into_backwards() request.

`step_over_backwards`(→ bool)
|
Execute one instruction backwards in the current thread, but without entering into functions. Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_over}

`request_step_over_backwards`(→ bool)
|
Post a step_over_backwards() request.

`run_to_backwards`(→ bool)
|
Execute the process backwards until the given address is reached. Technically, the debugger sets up a temporary breakpoint at the given address, and continues (or starts) the execution of the whole process. sq{Type, Asynchronous function - available as Request, Notification, dbg_run_to}

`request_run_to_backwards`(→ bool)
|
Post a run_to_backwards() request.

`step_until_ret`(→ bool)
|
Execute instructions in the current thread until a function return instruction is executed (aka "step out"). Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_until_ret}

`request_step_until_ret`(→ bool)
|
Post a step_until_ret() request.

`set_resume_mode`(→ bool)
|
How to resume the application. Set resume mode but do not resume process.

`request_set_resume_mode`(→ bool)
|
Post a set_resume_mode() request.

`get_dbg_reg_info`(→ bool)
|
Get register information sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_sp_val`(→ uint64 *)
|
Get value of the SP register for the current thread. Requires a suspended debugger.

`get_ip_val`(→ uint64 *)
|
Get value of the IP (program counter) register for the current thread. Requires a suspended debugger.

`is_reg_integer`(→ bool)
|
Does a register contain an integer value? sq{Type, Synchronous function, Notification, none (synchronous function)}

`is_reg_float`(→ bool)
|
Does a register contain a floating point value? sq{Type, Synchronous function, Notification, none (synchronous function)}

`is_reg_custom`(→ bool)
|
Does a register contain a value of a custom data type? sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_bptloc_string`(→ int)
|

`get_bptloc_string`(→ str)
|

`get_bpt_qty`(→ int)
|
Get number of breakpoints. sq{Type, Synchronous function, Notification, none (synchronous function)}

`getn_bpt`(→ bool)
|
Get the characteristics of a breakpoint. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_bpt`(→ bool)
|
Get the characteristics of a breakpoint. sq{Type, Synchronous function, Notification, none (synchronous function)}

`exist_bpt`(→ bool)
|
Does a breakpoint exist at the given location?

`add_bpt`(→ bool)
|
This function has the following signatures:

`request_add_bpt`(→ bool)
|
This function has the following signatures:

`del_bpt`(→ bool)
|
This function has the following signatures:

`request_del_bpt`(→ bool)
|
This function has the following signatures:

`update_bpt`(→ bool)
|
Update modifiable characteristics of an existing breakpoint. To update the breakpoint location, use change_bptlocs() sq{Type, Synchronous function, Notification, none (synchronous function)}

`find_bpt`(→ bool)
|
Find a breakpoint by location. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`enable_bpt`(→ bool)
|

`disable_bpt`(→ bool)
|

`request_enable_bpt`(→ bool)
|

`request_disable_bpt`(→ bool)
|

`check_bpt`(→ int)
|
Check the breakpoint at the specified address.

`set_trace_size`(→ bool)
|
Specify the new size of the circular buffer. sq{Type, Synchronous function, Notification, none (synchronous function)}

`clear_trace`(→ None)
|
Clear all events in the trace buffer. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_clear_trace`(→ None)
|
Post a clear_trace() request.

`is_step_trace_enabled`(→ bool)
|
Get current state of step tracing. sq{Type, Synchronous function, Notification, none (synchronous function)}

`enable_step_trace`(→ bool)
|

`disable_step_trace`(→ bool)
|

`request_enable_step_trace`(→ bool)
|

`request_disable_step_trace`(→ bool)
|

`get_step_trace_options`(→ int)
|
Get current step tracing options. sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_step_trace_options`(→ None)
|
Modify step tracing options. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_set_step_trace_options`(→ None)
|
Post a set_step_trace_options() request.

`is_insn_trace_enabled`(→ bool)
|
Get current state of instruction tracing. sq{Type, Synchronous function, Notification, none (synchronous function)}

`enable_insn_trace`(→ bool)
|

`disable_insn_trace`(→ bool)
|

`request_enable_insn_trace`(→ bool)
|

`request_disable_insn_trace`(→ bool)
|

`get_insn_trace_options`(→ int)
|
Get current instruction tracing options. Also see IT_LOG_SAME_IP sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_insn_trace_options`(→ None)
|
Modify instruction tracing options. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_set_insn_trace_options`(→ None)
|
Post a set_insn_trace_options() request.

`is_func_trace_enabled`(→ bool)
|
Get current state of functions tracing. sq{Type, Synchronous function, Notification, none (synchronous function)}

`enable_func_trace`(→ bool)
|

`disable_func_trace`(→ bool)
|

`request_enable_func_trace`(→ bool)
|

`request_disable_func_trace`(→ bool)
|

`get_func_trace_options`(→ int)
|
Get current function tracing options. Also see FT_LOG_RET sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_func_trace_options`(→ None)
|
Modify function tracing options. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

`request_set_func_trace_options`(→ None)
|
Post a set_func_trace_options() request.

`enable_bblk_trace`(→ bool)
|

`disable_bblk_trace`(→ bool)
|

`request_enable_bblk_trace`(→ bool)
|

`request_disable_bblk_trace`(→ bool)
|

`is_bblk_trace_enabled`(→ bool)
|

`get_bblk_trace_options`(→ int)
|
Get current basic block tracing options. Also see BT_LOG_INSTS sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_bblk_trace_options`(→ None)
|
Modify basic block tracing options (see BT_LOG_INSTS)

`request_set_bblk_trace_options`(→ None)
|
Post a set_bblk_trace_options() request.

`get_tev_qty`(→ int)
|
Get number of trace events available in trace buffer. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_tev_info`(→ bool)
|
Get main information about a trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_insn_tev_reg_val`(→ bool)
|
Read a register value from an instruction trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_insn_tev_reg_mem`(→ bool)
|
Read the memory pointed by register values from an instruction trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_insn_tev_reg_result`(→ bool)
|
Read the resulting register value from an instruction trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_call_tev_callee`(→ ida_idaapi.ea_t)
|
Get the called function from a function call trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_ret_tev_return`(→ ida_idaapi.ea_t)
|
Get the return address from a function return trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_bpt_tev_ea`(→ ida_idaapi.ea_t)
|
Get the address associated to a read, read/write or execution trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_tev_memory_info`(→ bool)
|
Get the memory layout, if any, for the specified tev object. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_tev_event`(→ bool)
|
Get the corresponding debug event, if any, for the specified tev object. sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_trace_base_address`(→ ida_idaapi.ea_t)
|
Get the base address of the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_trace_base_address`(→ None)
|
Set the base address of the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_thread`(→ None)
|
Add a thread to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_del_thread`(→ None)
|
Delete a thread from the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_tev`(→ None)
|
Add a new trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_many_tevs`(→ bool)
|
Add many new trace elements to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_insn_tev`(→ bool)
|
Add a new instruction trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_bpt_tev`(→ bool)
|
Add a new breakpoint trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_call_tev`(→ None)
|
Add a new call trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_ret_tev`(→ None)
|
Add a new return trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`dbg_add_debug_event`(→ None)
|
Add a new debug event to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}

`load_trace_file`(→ str)
|
Load a recorded trace file in the 'Tracing' window. If the call succeeds and 'buf' is not null, the description of the trace stored in the binary trace file will be returned in 'buf'

`save_trace_file`(→ bool)
|
Save the current trace in the specified file.

`is_valid_trace_file`(→ bool)
|
Is the specified file a valid trace file for the current database?

`set_trace_file_desc`(→ bool)
|
Change the description of the specified trace file.

`get_trace_file_desc`(→ str)
|
Get the file header of the specified trace file.

`choose_trace_file`(→ str)
|
Show the choose trace dialog.

`diff_trace_file`(→ bool)
|
Show difference between the current trace and the one from 'filename'.

`graph_trace`(→ bool)
|
Show the trace callgraph.

`set_highlight_trace_options`(→ None)
|
Set highlight trace parameters.

`set_trace_platform`(→ None)
|
Set platform name of current trace.

`get_trace_platform`(→ str)
|
Get platform name of current trace.

`set_trace_dynamic_register_set`(→ None)
|
Set dynamic register set of current trace.

`get_trace_dynamic_register_set`(→ None)
|
Get dynamic register set of current trace.

`wait_for_next_event`(→ dbg_event_code_t)
|
Wait for the next event.

`get_debug_event`(→ debug_event_t const *)
|
Get the current debugger event.

`set_debugger_options`(→ uint)
|
Set debugger options. Replaces debugger options with the specification combination Debugger options

`set_remote_debugger`(→ None)
|
Set remote debugging options. Should be used before starting the debugger.

`get_process_options2`(→ qstring *, qstring *, ...)
|

`retrieve_exceptions`(→ excvec_t *)
|
Retrieve the exception information. You may freely modify the returned vector and add/edit/delete exceptions You must call store_exceptions() after any modifications Note: exceptions with code zero, multiple exception codes or names are prohibited

`store_exceptions`(→ bool)
|
Update the exception information stored in the debugger module by invoking its dbg->set_exception_info callback

`define_exception`(→ str)
|
Convenience function: define new exception code.

`create_source_viewer`(→ source_view_t *)
|
Create a source code view.

`get_dbg_byte`(→ uint32 *)
|
Get one byte of the debugged process memory.

`put_dbg_byte`(→ bool)
|
Change one byte of the debugged process memory.

`invalidate_dbgmem_config`(→ None)
|
Invalidate the debugged process memory configuration. Call this function if the debugged process might have changed its memory layout (allocated more memory, for example)

`invalidate_dbgmem_contents`(→ None)
|
Invalidate the debugged process memory contents. Call this function each time the process has been stopped or the process memory is modified. If ea == BADADDR, then the whole memory contents will be invalidated

`is_debugger_on`(→ bool)
|
Is the debugger currently running?

`is_debugger_memory`(→ bool)
|
Is the address mapped to debugger memory?

`get_tev_ea`(→ ida_idaapi.ea_t)
|

`get_tev_type`(→ int)
|

`get_tev_tid`(→ int)
|

`bring_debugger_to_front`(→ None)
|

`set_manual_regions`(→ None)
|

`edit_manual_regions`(→ None)
|

`enable_manual_regions`(→ None)
|

`handle_debug_event`(→ int)
|

`add_virt_module`(→ bool)
|

`del_virt_module`(→ bool)
|

`internal_ioctl`(→ int)
|

`get_dbg_memory_info`(→ int)
|

`set_bpt_group`(→ bool)
|
Move a bpt into a folder in the breakpoint dirtree if the folder didn't exists, it will be created sq{Type, Synchronous function, Notification, none (synchronous function)}

`set_bptloc_group`(→ bool)
|
Move a bpt into a folder in the breakpoint dirtree based on the bpt_location find_bpt is called to retrieve the bpt and then set_bpt_group if the folder didn't exists, it will be created sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_bpt_group`(→ str)
|
Retrieve the absolute path to the folder of the bpt based on the bpt_location find_bpt is called to retrieve the bpt sq{Type, Synchronous function, Notification, none (synchronous function)}

`rename_bptgrp`(→ bool)
|
Rename a folder of bpt dirtree sq{Type, Synchronous function, Notification, none (synchronous function)}

`del_bptgrp`(→ bool)
|
Delete a folder, bpt that were part of this folder are moved to the root folder sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_grp_bpts`(→ ssize_t)
|
Retrieve a copy of the bpts stored in a folder sq{Type, Synchronous function, Notification, none (synchronous function)}

`enable_bptgrp`(→ int)
|
Enable (or disable) all bpts in a folder sq{Type, Synchronous function, Notification, none (synchronous function)}

`get_local_vars`(→ bool)
|

`srcdbg_request_step_into`(→ bool)
|

`srcdbg_request_step_over`(→ bool)
|

`srcdbg_request_step_until_ret`(→ bool)
|

`hide_all_bpts`(→ int)
|

`read_dbg_memory`(→ ssize_t)
|

`get_module_info`(→ bool)
|

`dbg_bin_search`(→ str)
|

`load_debugger`(→ bool)
|

`collect_stack_trace`(→ bool)
|

`get_global_var`(→ bool)
|

`get_local_var`(→ bool)
|

`get_srcinfo_provider`(→ srcinfo_provider_t *)
|

`get_current_source_file`(→ str)
|

`get_current_source_line`(→ int)
|

`add_path_mapping`(→ None)
|

`srcdbg_step_into`(→ bool)
|

`srcdbg_step_over`(→ bool)
|

`srcdbg_step_until_ret`(→ bool)
|

`set_debugger_event_cond`(→ None)
|

`get_debugger_event_cond`(→ str)
|

`set_process_options`(→ None)
|
Set process options. Any of the arguments may be nullptr, which means 'do not modify'

`get_process_options`(→ qstring *, qstring *, qstring *, ...)
|
Get process options. Any of the arguments may be nullptr

`get_manual_regions`(*args)
|
Returns the manual memory regions

`dbg_is_loaded`()
|
Checks if a debugger is loaded

`refresh_debugger_memory`()
|
Refreshes the debugger memory

`list_bptgrps`(→ List[str])
|
Retrieve the list of absolute path of all folders of bpt dirtree.

`internal_get_sreg_base`(tid, sreg_value)
|
Get the sreg base, for the given thread.

`write_dbg_memory`(→ ssize_t)
|

`dbg_can_query`()
|
This function can be used to check if the debugger can be queried:

`set_reg_val`(→ bool)
|
Set a register value by name

`request_set_reg_val`(→ PyObject *)
|
Post a set_reg_val() request.

`get_reg_val`(*args)
|
Get a register value.

`get_reg_vals`(→ ida_idd.regvals_t)
|
Fetch live registers values for the thread

`get_tev_reg_val`(tev, reg)
|

`get_tev_reg_mem_qty`(tev)
|

`get_tev_reg_mem`(tev, idx)
|

`get_tev_reg_mem_ea`(tev, idx)
|

`send_dbg_command`(command)
|
Send a direct command to the debugger backend, and

## Module Contents

classida_dbg.bpt_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→bpt_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→bpt_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:bpt_vec_t)→Noneextract()→bpt_t*inject(s:bpt_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:bpt_t, x:bpt_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:bpt_t)→Noneextend(x:bpt_vec_t)→Nonefrontbackclassida_dbg.tev_reg_values_t(*args)
Bases: `object`
thisownpush_back(*args)→tev_reg_value_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→tev_reg_value_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:tev_reg_values_t)→Noneextract()→tev_reg_value_t*inject(s:tev_reg_value_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:tev_reg_value_t, x:tev_reg_value_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:tev_reg_value_t)→Noneextend(x:tev_reg_values_t)→Nonefrontbackclassida_dbg.tevinforeg_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→tev_info_reg_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→tev_info_reg_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:tevinforeg_vec_t)→Noneextract()→tev_info_reg_t*inject(s:tev_info_reg_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:tev_info_reg_t, x:tev_info_reg_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:tev_info_reg_t)→Noneextend(x:tevinforeg_vec_t)→Nonefrontbackclassida_dbg.memreg_infos_t(*args)
Bases: `object`
thisownpush_back(*args)→memreg_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→memreg_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:memreg_infos_t)→Noneextract()→memreg_info_t*inject(s:memreg_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:memreg_info_t, x:memreg_info_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:memreg_info_t)→Noneextend(x:memreg_infos_t)→Nonefrontbackida_dbg.run_to(*args)→bool
Execute the process until the given address is reached. If no process is active, a new process is started. Technically, the debugger sets up a temporary breakpoint at the given address, and continues (or starts) the execution of the whole process. So, all threads continue their execution! sq{Type, Asynchronous function - available as Request, Notification, dbg_run_to}
Parameters:

-
ea – target address

-
pid – not used yet. please do not specify this parameter.

-
tid – not used yet. please do not specify this parameter.

ida_dbg.request_run_to(*args)→bool
Post a run_to() request.
ida_dbg.dbg_nullida_dbg.dbg_process_startida_dbg.dbg_process_exitida_dbg.dbg_process_attachida_dbg.dbg_process_detachida_dbg.dbg_thread_startida_dbg.dbg_thread_exitida_dbg.dbg_library_loadida_dbg.dbg_library_unloadida_dbg.dbg_informationida_dbg.dbg_exceptionida_dbg.dbg_suspend_process
The process is now suspended.
ida_dbg.dbg_bpt
A user defined breakpoint was reached.
ida_dbg.dbg_trace
A step occurred (one instruction was executed). This event notification is only generated if step tracing is enabled.
ida_dbg.dbg_request_error
An error occurred during the processing of a request.
ida_dbg.dbg_step_intoida_dbg.dbg_step_overida_dbg.dbg_run_toida_dbg.dbg_step_until_retida_dbg.dbg_bpt_changed
Breakpoint has been changed.
ida_dbg.dbg_started_loading_bpts
Started loading breakpoint info from idb.
ida_dbg.dbg_finished_loading_bpts
Finished loading breakpoint info from idb.
ida_dbg.dbg_last
The last debugger notification code.
ida_dbg.BPTEV_ADDED
Breakpoint has been added.
ida_dbg.BPTEV_REMOVED
Breakpoint has been removed.
ida_dbg.BPTEV_CHANGED
Breakpoint has been modified.
ida_dbg.run_requests()→bool
Execute requests until all requests are processed or an asynchronous function is called. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
false if not all requests could be processed (indicates an asynchronous function was started)
ida_dbg.get_running_request()→ui_notification_t
Get the current running request. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
ui_null if no running request
ida_dbg.is_request_running()→bool
Is a request currently running?
ida_dbg.get_running_notification()→dbg_notification_t
Get the notification associated (if any) with the current running request. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
dbg_null if no running request
ida_dbg.clear_requests_queue()→None
Clear the queue of waiting requests. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.get_process_state()→int
Return the state of the currently debugged process. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
one of Debugged process states
ida_dbg.DSTATE_SUSP
process is suspended and will not continue
ida_dbg.DSTATE_NOTASK
no process is currently debugged
ida_dbg.DSTATE_RUN
process is running
ida_dbg.is_valid_dstate(state:int)→boolida_dbg.DBGINV_MEMORY
invalidate cached memory contents
ida_dbg.DBGINV_MEMCFG
invalidate cached process segmentation
ida_dbg.DBGINV_REGS
invalidate cached register values
ida_dbg.DBGINV_ALL
invalidate everything
ida_dbg.DBGINV_REDRAW
refresh the screen
ida_dbg.DBGINV_NONE
invalidate nothing
ida_dbg.set_process_state(newstate:int, p_thid:thid_t*, dbginv:int)→int
Set new state for the debugged process. Notifies the IDA kernel about the change of the debugged process state. For example, a debugger module could call this function when it knows that the process is suspended for a short period of time. Some IDA API calls can be made only when the process is suspended. The process state is usually restored before returning control to the caller. You must know that it is ok to change the process state, doing it at arbitrary moments may crash the application or IDA. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
newstate – new process state (one of Debugged process states) if DSTATE_NOTASK is passed then the state is not changed

-
p_thid – ptr to new thread id. may be nullptr or pointer to NO_THREAD. the pointed variable will contain the old thread id upon return

-
dbginv – Debugged process invalidation options

Returns:
old debugger state (one of Debugged process states)
ida_dbg.invalidate_dbg_state(dbginv:int)→int
Invalidate cached debugger information. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
dbginv – Debugged process invalidation options
Returns:
current debugger state (one of Debugged process states)
ida_dbg.start_process(path:str=None, args:str=None, sdir:str=None)→int
Start a process in the debugger. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_start}
Parameters:

-
path – path to the executable to start

-
args – arguments to pass to process

-
sdir – starting directory for the process

Returns:
-1: impossible to create the process
Returns:
0: the starting of the process was cancelled by the user
Returns:
1: the process was properly started
ida_dbg.request_start_process(path:str=None, args:str=None, sdir:str=None)→int
Post a start_process() request.
ida_dbg.suspend_process()→bool
Suspend the process in the debugger. sq{ Type, * Synchronous function (if in a notification handler) * Asynchronous function (everywhere else) * available as Request, Notification, * none (if in a notification handler) * dbg_suspend_process (everywhere else) }
ida_dbg.request_suspend_process()→bool
Post a suspend_process() request.
ida_dbg.continue_process()→bool
Continue the execution of the process in the debugger. sq{Type, Synchronous function - available as Request, Notification, none (synchronous function)}
ida_dbg.request_continue_process()→bool
Post a continue_process() request.
ida_dbg.continue_backwards()→bool
Continue the execution of the process in the debugger backwards. Can only be used with debuggers that support time-travel debugging. sq{Type, Synchronous function - available as Request, Notification, none (synchronous function)}
ida_dbg.request_continue_backwards()→bool
Post a continue_backwards() request.
ida_dbg.exit_process()→bool
Terminate the debugging of the current process. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_exit}
ida_dbg.request_exit_process()→bool
Post an exit_process() request.
ida_dbg.get_processes(proclist:procinfo_vec_t)→ssize_t
Take a snapshot of running processes and return their description. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
proclist – array with information about each running process
Returns:
number of processes or -1 on error
ida_dbg.attach_process(*args)→int
Attach the debugger to a running process. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_attach}
Parameters:

-
pid – PID of the process to attach to. If NO_PROCESS, a dialog box will interactively ask the user for the process to attach to.

-
event_id – event to trigger upon attaching

Returns:
-4: debugger was not inited
Returns:
-3: the attaching is not supported
Returns:
-2: impossible to find a compatible process
Returns:
-1: impossible to attach to the given process (process died, privilege needed, not supported by the debugger plugin, …)
Returns:
0: the user cancelled the attaching to the process
Returns:
1: the debugger properly attached to the process
ida_dbg.request_attach_process(pid:pid_t, event_id:int)→int
Post an attach_process() request.
ida_dbg.detach_process()→bool
Detach the debugger from the debugged process. sq{Type, Asynchronous function - available as Request, Notification, dbg_process_detach}
ida_dbg.request_detach_process()→bool
Post a detach_process() request.
ida_dbg.is_debugger_busy()→bool
Is the debugger busy?. Some debuggers do not accept any commands while the debugged application is running. For such a debugger, it is unsafe to do anything with the database (even simple queries like get_byte may lead to undesired consequences). Returns: true if the debugged application is running under such a debugger
ida_dbg.get_thread_qty()→int
Get number of threads. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.getn_thread(n:int)→thid_t
Get the ID of a thread. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
n – number of thread, is in range 0..get_thread_qty()-1
Returns:
NO_THREAD if the thread doesn’t exist.
ida_dbg.get_current_thread()→thid_t
Get current thread ID. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.getn_thread_name(n:int)→str
Get the NAME of a thread sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
n – number of thread, is in range 0..get_thread_qty()-1 or -1 for the current thread
Returns:
thread name or nullptr if the thread doesn’t exist.
ida_dbg.select_thread(tid:thid_t)→bool
Select the given thread as the current debugged thread. All thread related execution functions will work on this thread. The process must be suspended to select a new thread. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
Parameters:
tid – ID of the thread to select
Returns:
false if the thread doesn’t exist.
ida_dbg.request_select_thread(tid:thid_t)→bool
Post a select_thread() request.
ida_dbg.suspend_thread(tid:thid_t)→int
Suspend thread. Suspending a thread may deadlock the whole application if the suspended was owning some synchronization objects. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
Parameters:
tid – thread id
Returns:
-1: network error
Returns:
0: failed
Returns:
1: ok
ida_dbg.request_suspend_thread(tid:thid_t)→int
Post a suspend_thread() request.
ida_dbg.resume_thread(tid:thid_t)→int
Resume thread. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
Parameters:
tid – thread id
Returns:
-1: network error
Returns:
0: failed
Returns:
1: ok
ida_dbg.request_resume_thread(tid:thid_t)→int
Post a resume_thread() request.
ida_dbg.get_first_module(modinfo:modinfo_t)→boolida_dbg.get_next_module(modinfo:modinfo_t)→boolida_dbg.step_into()→bool
Execute one instruction in the current thread. Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_into}
ida_dbg.request_step_into()→bool
Post a step_into() request.
ida_dbg.step_over()→bool
Execute one instruction in the current thread, but without entering into functions. Others threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_over}
ida_dbg.request_step_over()→bool
Post a step_over() request.
ida_dbg.step_into_backwards()→bool
Execute one instruction backwards in the current thread. Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_into}
ida_dbg.request_step_into_backwards()→bool
Post a step_into_backwards() request.
ida_dbg.step_over_backwards()→bool
Execute one instruction backwards in the current thread, but without entering into functions. Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_over}
ida_dbg.request_step_over_backwards()→bool
Post a step_over_backwards() request.
ida_dbg.run_to_backwards(*args)→bool
Execute the process backwards until the given address is reached. Technically, the debugger sets up a temporary breakpoint at the given address, and continues (or starts) the execution of the whole process. sq{Type, Asynchronous function - available as Request, Notification, dbg_run_to}
Parameters:

-
ea – target address

-
pid – not used yet. please do not specify this parameter.

-
tid – not used yet. please do not specify this parameter.

ida_dbg.request_run_to_backwards(*args)→bool
Post a run_to_backwards() request.
ida_dbg.step_until_ret()→bool
Execute instructions in the current thread until a function return instruction is executed (aka “step out”). Other threads are kept suspended. sq{Type, Asynchronous function - available as Request, Notification, dbg_step_until_ret}
ida_dbg.request_step_until_ret()→bool
Post a step_until_ret() request.
ida_dbg.set_resume_mode(tid:thid_t, mode:resume_mode_t)→bool
How to resume the application. Set resume mode but do not resume process.
ida_dbg.request_set_resume_mode(tid:thid_t, mode:resume_mode_t)→bool
Post a set_resume_mode() request.
ida_dbg.get_dbg_reg_info(regname:str, ri:register_info_t)→bool
Get register information sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.get_sp_val()→uint64*
Get value of the SP register for the current thread. Requires a suspended debugger.
ida_dbg.get_ip_val()→uint64*
Get value of the IP (program counter) register for the current thread. Requires a suspended debugger.
ida_dbg.is_reg_integer(regname:str)→bool
Does a register contain an integer value? sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.is_reg_float(regname:str)→bool
Does a register contain a floating point value? sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.is_reg_custom(regname:str)→bool
Does a register contain a value of a custom data type? sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.set_bptloc_string(s:str)→intida_dbg.get_bptloc_string(i:int)→strida_dbg.MOVBPT_OK
moved ok
ida_dbg.MOVBPT_NOT_FOUND
source bpt not found
ida_dbg.MOVBPT_DEST_BUSY
destination location is busy (we already have such a bpt)
ida_dbg.MOVBPT_BAD_TYPE
BPLT_ABS is not supported.
classida_dbg.bptaddrs_t
Bases: `object`
thisownbpt:bpt_t*ida_dbg.BPLT_ABS
absolute address: ea
ida_dbg.BPLT_REL
relative address: module_path, offset
ida_dbg.BPLT_SYM
symbolic: symbol_name, offset
ida_dbg.BPLT_SRC
source level: filename, lineno
classida_dbg.bpt_location_t
Bases: `object`
thisowninfo:ida_idaapi.ea_tindex:intloctype:bpt_loctype_ttype()→bpt_loctype_t
Get bpt type.
is_empty_path()→bool
No path/filename specified? (BPLT_REL, BPLT_SRC)
path()→str
Get path/filename (BPLT_REL, BPLT_SRC)
symbol()→str
Get symbol name (BPLT_SYM)
lineno()→int
Get line number (BPLT_SRC)
offset()→int
Get offset (BPLT_REL, BPLT_SYM)
ea()→ida_idaapi.ea_t
Get address (BPLT_ABS)
valid()→bool
Locations that are absolute+BADADDR, are considered invalid.
set_abs_bpt(a:ida_idaapi.ea_t)→None
Specify an absolute address location.
set_src_bpt(fn:str, _lineno:int)→None
Specify a source level location.
set_sym_bpt(_symbol:str, _offset:int=0)→None
Specify a symbolic location.
set_rel_bpt(mod:str, _offset:int)→None
Specify a relative address location.
compare(r:bpt_location_t)→int
Lexically compare two breakpoint locations. Bpt locations are first compared based on type (i.e. BPLT_ABS < BPLT_REL). BPLT_ABS locations are compared based on their ea values. For all other location types, locations are first compared based on their string (path/filename/symbol), then their offset/lineno.
classida_dbg.bpt_t
Bases: `object`
thisowncb:int
size of this structure
loc:bpt_location_t
Location.
pid:pid_t
breakpoint process id
tid:thid_t
breakpoint thread id
ea:ida_idaapi.ea_t
Address, if known. For BPLT_SRC, index into an internal data struct.
type:bpttype_t
Breakpoint type.
pass_count:int
Number of times the breakpoint is hit before stopping (default is 0: stop always)
flags:int
Breakpoint property bits
props:int
Internal breakpoint properties
size:int
Size of the breakpoint (0 for software breakpoints)
cndidx:int
Internal number of the condition (<0-none)
bptid:inode_t
Internal breakpoint id.
is_hwbpt()→bool
Is hardware breakpoint?
enabled()→bool
Is breakpoint enabled?
is_low_level()→bool
Is bpt condition calculated at low level?
badbpt()→bool
Failed to write bpt to process memory?
listbpt()→bool
Include in the bpt list?
is_compiled()→bool
Condition has been compiled?
is_active()→bool
Written completely to process?
is_partially_active()→bool
Written partially to process?
is_inactive()→bool
Not written to process at all?
is_page_bpt()→bool
Page breakpoint?
get_size()→int
Get bpt size.
set_abs_bpt(a:ida_idaapi.ea_t)→None
Set bpt location to an absolute address.
set_src_bpt(fn:str, lineno:int)→None
Set bpt location to a source line.
set_sym_bpt(sym:str, o:int)→None
Set bpt location to a symbol.
set_rel_bpt(mod:str, o:int)→None
Set bpt location to a relative address.
is_absbpt()→bool
Is absolute address breakpoint?
is_relbpt()→bool
Is relative address breakpoint?
is_symbpt()→bool
Is symbolic breakpoint?
is_srcbpt()→bool
Is source level breakpoint?
is_tracemodebpt()→bool
Does breakpoint trace anything?
is_traceonbpt()→bool
Is this a tracing breakpoint, and is tracing enabled?
is_traceoffbpt()→bool
Is this a tracing breakpoint, and is tracing disabled?
set_trace_action(enable:bool, trace_types:int)→bool
Configure tracing options.
get_cnd_elang_idx()→intcondition:PyObject*elang:PyObject*ida_dbg.BPT_BRK
suspend execution upon hit
ida_dbg.BPT_TRACE
add trace information upon hit
ida_dbg.BPT_UPDMEM
refresh the memory layout and contents before evaluating bpt condition
ida_dbg.BPT_ENABLED
enabled?
ida_dbg.BPT_LOWCND
condition is calculated at low level (on the server side)
ida_dbg.BPT_TRACEON
enable tracing when the breakpoint is reached
ida_dbg.BPT_TRACE_INSN
instruction tracing
ida_dbg.BPT_TRACE_FUNC
function tracing
ida_dbg.BPT_TRACE_BBLK
basic block tracing
ida_dbg.BPT_TRACE_TYPES
trace insns, functions, and basic blocks. if any of BPT_TRACE_TYPES bits are set but BPT_TRACEON is clear, then turn off tracing for the specified trace types
ida_dbg.BPT_ELANG_MASKida_dbg.BPT_ELANG_SHIFT
index of the extlang (scripting language) of the condition
ida_dbg.BKPT_BADBPT
failed to write the bpt to the process memory (at least one location)
ida_dbg.BKPT_LISTBPT
include in bpt list (user-defined bpt)
ida_dbg.BKPT_TRACE
trace bpt; should not be deleted when the process gets suspended
ida_dbg.BKPT_ACTIVE
active?
ida_dbg.BKPT_PARTIAL
partially active? (some locations were not written yet)
ida_dbg.BKPT_CNDREADY
condition has been compiled
ida_dbg.BKPT_FAKEPEND
fake pending bpt: it is inactive but another bpt of the same type is active at the same address(es)
ida_dbg.BKPT_PAGE
written to the process as a page bpt. Available only after writing the bpt to the process.
ida_dbg.get_bpt_qty()→int
Get number of breakpoints. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.getn_bpt(n:int, bpt:bpt_t)→bool
Get the characteristics of a breakpoint. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of breakpoint, is in range 0..get_bpt_qty()-1

-
bpt – filled with the characteristics.

Returns:
false if no breakpoint exists
ida_dbg.get_bpt(ea:ida_idaapi.ea_t, bpt:bpt_t)→bool
Get the characteristics of a breakpoint. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
ea – any address in the breakpoint range

-
bpt – if not nullptr, is filled with the characteristics.

Returns:
false if no breakpoint exists
ida_dbg.exist_bpt(ea:ida_idaapi.ea_t)→bool
Does a breakpoint exist at the given location?
ida_dbg.add_bpt(*args)→bool
This function has the following signatures:

-
add_bpt(ea: ida_idaapi.ea_t, size: asize_t=0, type: bpttype_t=BPT_DEFAULT) -> bool

-
add_bpt(bpt: const bpt_t &) -> bool

# 0: add_bpt(ea: ida_idaapi.ea_t, size: asize_t=0, type: bpttype_t=BPT_DEFAULT) -> bool

Add a new breakpoint in the debugged process. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

# 1: add_bpt(bpt: const bpt_t &) -> bool

Add a new breakpoint in the debugged process. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
ida_dbg.request_add_bpt(*args)→bool
This function has the following signatures:

-
request_add_bpt(ea: ida_idaapi.ea_t, size: asize_t=0, type: bpttype_t=BPT_DEFAULT) -> bool

-
request_add_bpt(bpt: const bpt_t &) -> bool

# 0: request_add_bpt(ea: ida_idaapi.ea_t, size: asize_t=0, type: bpttype_t=BPT_DEFAULT) -> bool

Post an add_bpt(ea_t, asize_t, bpttype_t) request.

# 1: request_add_bpt(bpt: const bpt_t &) -> bool

Post an add_bpt(const bpt_t &) request.
ida_dbg.del_bpt(*args)→bool
This function has the following signatures:

-
del_bpt(ea: ida_idaapi.ea_t) -> bool

-
del_bpt(bptloc: const bpt_location_t &) -> bool

# 0: del_bpt(ea: ida_idaapi.ea_t) -> bool

Delete an existing breakpoint in the debugged process. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}

# 1: del_bpt(bptloc: const bpt_location_t &) -> bool

Delete an existing breakpoint in the debugged process. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
ida_dbg.request_del_bpt(*args)→bool
This function has the following signatures:

-
request_del_bpt(ea: ida_idaapi.ea_t) -> bool

-
request_del_bpt(bptloc: const bpt_location_t &) -> bool

# 0: request_del_bpt(ea: ida_idaapi.ea_t) -> bool

Post a del_bpt(ea_t) request.

# 1: request_del_bpt(bptloc: const bpt_location_t &) -> bool

Post a del_bpt(const bpt_location_t &) request.
ida_dbg.update_bpt(bpt:bpt_t)→bool
Update modifiable characteristics of an existing breakpoint. To update the breakpoint location, use change_bptlocs() sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.find_bpt(bptloc:bpt_location_t, bpt:bpt_t)→bool
Find a breakpoint by location. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
Parameters:

-
bptloc – Breakpoint location

-
bpt – bpt is filled if the breakpoint was found

ida_dbg.enable_bpt(*args)→boolida_dbg.disable_bpt(*args)→boolida_dbg.request_enable_bpt(*args)→boolida_dbg.request_disable_bpt(*args)→boolida_dbg.check_bpt(ea:ida_idaapi.ea_t)→int
Check the breakpoint at the specified address.
Returns:
one of Breakpoint status codes
ida_dbg.BPTCK_NONE
breakpoint does not exist
ida_dbg.BPTCK_NO
breakpoint is disabled
ida_dbg.BPTCK_YES
breakpoint is enabled
ida_dbg.BPTCK_ACT
breakpoint is active (written to the process)
ida_dbg.set_trace_size(size:int)→bool
Specify the new size of the circular buffer. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
size – if 0, buffer isn’t circular and events are never removed. If the new size is smaller than the existing number of trace events, a corresponding number of trace events are removed.
ida_dbg.clear_trace()→None
Clear all events in the trace buffer. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
ida_dbg.request_clear_trace()→None
Post a clear_trace() request.
ida_dbg.is_step_trace_enabled()→bool
Get current state of step tracing. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.enable_step_trace(enable:int=1)→boolida_dbg.disable_step_trace()→boolida_dbg.request_enable_step_trace(enable:int=1)→boolida_dbg.request_disable_step_trace()→boolida_dbg.ST_OVER_DEBUG_SEG
step tracing will be disabled when IP is in a debugger segment
ida_dbg.ST_OVER_LIB_FUNC
step tracing will be disabled when IP is in a library function
ida_dbg.ST_ALREADY_LOGGED
step tracing will be disabled when IP is already logged
ida_dbg.ST_SKIP_LOOPS
step tracing will try to skip loops already recorded
ida_dbg.ST_DIFFERENTIAL
tracing: log only new instructions (not previously logged)
ida_dbg.ST_OPTIONS_MASK
mask of available options, to ensure compatibility with newer IDA versions
ida_dbg.ST_OPTIONS_DEFAULTida_dbg.IT_LOG_SAME_IP
specific options for instruction tracing (see set_insn_trace_options())

instruction tracing will log new instructions even when IP doesn’t change
ida_dbg.FT_LOG_RET
specific options for function tracing (see set_func_trace_options())

function tracing will log returning instructions
ida_dbg.BT_LOG_INSTS
specific options for basic block tracing (see set_bblk_trace_options())

log all instructions in the current basic block
ida_dbg.get_step_trace_options()→int
Get current step tracing options. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
Step trace options
ida_dbg.set_step_trace_options(options:int)→None
Modify step tracing options. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
ida_dbg.request_set_step_trace_options(options:int)→None
Post a set_step_trace_options() request.
ida_dbg.is_insn_trace_enabled()→bool
Get current state of instruction tracing. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.enable_insn_trace(enable:bool=True)→boolida_dbg.disable_insn_trace()→boolida_dbg.request_enable_insn_trace(enable:bool=True)→boolida_dbg.request_disable_insn_trace()→boolida_dbg.get_insn_trace_options()→int
Get current instruction tracing options. Also see IT_LOG_SAME_IP sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.set_insn_trace_options(options:int)→None
Modify instruction tracing options. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
ida_dbg.request_set_insn_trace_options(options:int)→None
Post a set_insn_trace_options() request.
ida_dbg.is_func_trace_enabled()→bool
Get current state of functions tracing. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.enable_func_trace(enable:bool=True)→boolida_dbg.disable_func_trace()→boolida_dbg.request_enable_func_trace(enable:bool=True)→boolida_dbg.request_disable_func_trace()→boolida_dbg.get_func_trace_options()→int
Get current function tracing options. Also see FT_LOG_RET sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.set_func_trace_options(options:int)→None
Modify function tracing options. sq{Type, Synchronous function - available as request, Notification, none (synchronous function)}
ida_dbg.request_set_func_trace_options(options:int)→None
Post a set_func_trace_options() request.
ida_dbg.enable_bblk_trace(enable:bool=True)→boolida_dbg.disable_bblk_trace()→boolida_dbg.request_enable_bblk_trace(enable:bool=True)→boolida_dbg.request_disable_bblk_trace()→boolida_dbg.is_bblk_trace_enabled()→boolida_dbg.get_bblk_trace_options()→int
Get current basic block tracing options. Also see BT_LOG_INSTS sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.set_bblk_trace_options(options:int)→None
Modify basic block tracing options (see BT_LOG_INSTS)
ida_dbg.request_set_bblk_trace_options(options:int)→None
Post a set_bblk_trace_options() request.
ida_dbg.tev_none
no event
ida_dbg.tev_insn
an instruction trace
ida_dbg.tev_call
a function call trace
ida_dbg.tev_ret
a function return trace
ida_dbg.tev_bpt
write, read/write, execution trace
ida_dbg.tev_mem
memory layout changed
ida_dbg.tev_event
debug event occurred
ida_dbg.tev_max
first unused event type
classida_dbg.tev_info_t
Bases: `object`
thisowntype:tev_type_t
trace event type
tid:thid_t
thread where the event was recorded
ea:ida_idaapi.ea_t
address where the event occurred
classida_dbg.memreg_info_t
Bases: `object`
thisownea:ida_idaapi.ea_tget_bytes()→PyObject*bytesida_dbg.get_tev_qty()→int
Get number of trace events available in trace buffer. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.get_tev_info(n:int, tev_info:tev_info_t)→bool
Get main information about a trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.

-
tev_info – result

Returns:
success
ida_dbg.get_insn_tev_reg_val(n:int, regname:str, regval:regval_t)→bool
Read a register value from an instruction trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.

-
regname – name of desired register

-
regval – result

Returns:
false if not an instruction event.
ida_dbg.get_insn_tev_reg_mem(n:int, memmap:memreg_infos_t)→bool
Read the memory pointed by register values from an instruction trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.

-
memmap – result

Returns:
false if not an instruction event or no memory is available
ida_dbg.get_insn_tev_reg_result(n:int, regname:str, regval:regval_t)→bool
Read the resulting register value from an instruction trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.

-
regname – name of desired register

-
regval – result

Returns:
false if not an instruction trace event or register wasn’t modified.
ida_dbg.get_call_tev_callee(n:int)→ida_idaapi.ea_t
Get the called function from a function call trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.
Returns:
BADADDR if not a function call event.
ida_dbg.get_ret_tev_return(n:int)→ida_idaapi.ea_t
Get the return address from a function return trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.
Returns:
BADADDR if not a function return event.
ida_dbg.get_bpt_tev_ea(n:int)→ida_idaapi.ea_t
Get the address associated to a read, read/write or execution trace event. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.
Returns:
BADADDR if not a read, read/write or execution trace event.
ida_dbg.get_tev_memory_info(n:int, mi:meminfo_vec_t)→bool
Get the memory layout, if any, for the specified tev object. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.

-
mi – result

Returns:
false if the tev_t object is not of type tev_mem, true otherwise, with the new memory layout in “mi”.
ida_dbg.get_tev_event(n:int, d:debug_event_t)→bool
Get the corresponding debug event, if any, for the specified tev object. sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
n – number of trace event, is in range 0..get_tev_qty()-1. 0 represents the latest added trace event.

-
d – result

Returns:
false if the tev_t object doesn’t have any associated debug event, true otherwise, with the debug event in “d”.
ida_dbg.get_trace_base_address()→ida_idaapi.ea_t
Get the base address of the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
the base address of the currently loaded trace
ida_dbg.set_trace_base_address(ea:ida_idaapi.ea_t)→None
Set the base address of the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.dbg_add_thread(tid:thid_t)→None
Add a thread to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.dbg_del_thread(tid:thid_t)→None
Delete a thread from the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.dbg_add_tev(type:tev_type_t, tid:thid_t, address:ida_idaapi.ea_t)→None
Add a new trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
classida_dbg.tev_reg_value_t(*args)
Bases: `object`
thisownvalue:regval_treg_idx:intclassida_dbg.tev_info_reg_t
Bases: `object`
thisowninfo:tev_info_tregisters:tev_reg_values_tida_dbg.SAVE_ALL_VALUESida_dbg.SAVE_DIFFida_dbg.SAVE_NONEida_dbg.dbg_add_many_tevs(new_tevs:tevinforeg_vec_t)→bool
Add many new trace elements to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
false if the operation failed for any tev_info_t object
ida_dbg.dbg_add_insn_tev(tid:thid_t, ea:ida_idaapi.ea_t, save:save_reg_values_t=SAVE_DIFF)→bool
Add a new instruction trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
false if the operation failed, true otherwise
ida_dbg.dbg_add_bpt_tev(tid:thid_t, ea:ida_idaapi.ea_t, bp:ida_idaapi.ea_t)→bool
Add a new breakpoint trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
Returns:
false if the operation failed, true otherwise
ida_dbg.dbg_add_call_tev(tid:thid_t, caller:ida_idaapi.ea_t, callee:ida_idaapi.ea_t)→None
Add a new call trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.dbg_add_ret_tev(tid:thid_t, ret_insn:ida_idaapi.ea_t, return_to:ida_idaapi.ea_t)→None
Add a new return trace element to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.dbg_add_debug_event(event:debug_event_t)→None
Add a new debug event to the current trace. sq{Type, Synchronous function, Notification, none (synchronous function)}
ida_dbg.load_trace_file(filename:str)→str
Load a recorded trace file in the ‘Tracing’ window. If the call succeeds and ‘buf’ is not null, the description of the trace stored in the binary trace file will be returned in ‘buf’
ida_dbg.save_trace_file(filename:str, description:str)→bool
Save the current trace in the specified file.
ida_dbg.is_valid_trace_file(filename:str)→bool
Is the specified file a valid trace file for the current database?
ida_dbg.set_trace_file_desc(filename:str, description:str)→bool
Change the description of the specified trace file.
ida_dbg.get_trace_file_desc(filename:str)→str
Get the file header of the specified trace file.
ida_dbg.choose_trace_file()→str
Show the choose trace dialog.
ida_dbg.diff_trace_file(filename:str)→bool
Show difference between the current trace and the one from ‘filename’.
ida_dbg.graph_trace()→bool
Show the trace callgraph.
ida_dbg.set_highlight_trace_options(hilight:bool, color:bgcolor_t, diff:bgcolor_t)→None
Set highlight trace parameters.
ida_dbg.set_trace_platform(platform:str)→None
Set platform name of current trace.
ida_dbg.get_trace_platform()→str
Get platform name of current trace.
ida_dbg.set_trace_dynamic_register_set(idaregs:dynamic_register_set_t&)→None
Set dynamic register set of current trace.
ida_dbg.get_trace_dynamic_register_set(idaregs:dynamic_register_set_t*)→None
Get dynamic register set of current trace.
ida_dbg.DEC_NOTASK
process does not exist
ida_dbg.DEC_ERROR
error
ida_dbg.DEC_TIMEOUT
timeout
ida_dbg.WFNE_ANY
return the first event (even if it doesn’t suspend the process)
ida_dbg.WFNE_SUSP
wait until the process gets suspended
ida_dbg.WFNE_SILENT
1: be silent, 0:display modal boxes if necessary
ida_dbg.WFNE_CONT
continue from the suspended state
ida_dbg.WFNE_NOWAIT
do not wait for any event, immediately return DEC_TIMEOUT (to be used with WFNE_CONT)
ida_dbg.WFNE_USEC
timeout is specified in microseconds (minimum non-zero timeout is 40000us)
ida_dbg.DOPT_SEGM_MSGS
log debugger segments modifications
ida_dbg.DOPT_START_BPT
break on process start
ida_dbg.DOPT_THREAD_MSGS
log thread starts/exits
ida_dbg.DOPT_THREAD_BPT
break on thread start/exit
ida_dbg.DOPT_BPT_MSGS
log breakpoints
ida_dbg.DOPT_LIB_MSGS
log library loads/unloads
ida_dbg.DOPT_LIB_BPT
break on library load/unload
ida_dbg.DOPT_INFO_MSGS
log debugging info events
ida_dbg.DOPT_INFO_BPT
break on debugging information
ida_dbg.DOPT_REAL_MEMORY
do not hide breakpoint instructions
ida_dbg.DOPT_REDO_STACK
reconstruct the stack
ida_dbg.DOPT_ENTRY_BPT
break on program entry point
ida_dbg.DOPT_EXCDLG
exception dialogs:
ida_dbg.EXCDLG_NEVER
never display exception dialogs
ida_dbg.EXCDLG_UNKNOWN
display for unknown exceptions
ida_dbg.EXCDLG_ALWAYS
always display
ida_dbg.DOPT_LOAD_DINFO
automatically load debug files (pdb)
ida_dbg.DOPT_END_BPT
evaluate event condition on process end
ida_dbg.DOPT_TEMP_HWBPT
when possible use hardware bpts for temp bpts
ida_dbg.DOPT_FAST_STEP
prevent debugger memory refreshes when single-stepping
ida_dbg.DOPT_DISABLE_ASLR
disable ASLR
ida_dbg.wait_for_next_event(wfne:int, timeout:int)→dbg_event_code_t
Wait for the next event. This function (optionally) resumes the process execution, and waits for a debugger event until a possible timeout occurs.
Parameters:

-
wfne – combination of Wait for debugger event flags constants

-
timeout – number of seconds to wait, -1-infinity

Returns:
either an event_id_t (if > 0), or a dbg_event_code_t (if <= 0)
ida_dbg.get_debug_event()→debug_event_tconst*
Get the current debugger event.
ida_dbg.set_debugger_options(options:uint)→uint
Set debugger options. Replaces debugger options with the specification combination Debugger options
Returns:
the old debugger options
ida_dbg.set_remote_debugger(host:str, _pass:str, port:int=-1)→None
Set remote debugging options. Should be used before starting the debugger.
Parameters:

-
host – If empty, IDA will use local debugger. If nullptr, the host will not be set.

-
port – If -1, the default port number will be used

ida_dbg.get_process_options2()→qstring*,qstring*,launch_env_t*,qstring*,qstring*,qstring*,int*ida_dbg.retrieve_exceptions()→excvec_t*
Retrieve the exception information. You may freely modify the returned vector and add/edit/delete exceptions You must call store_exceptions() after any modifications Note: exceptions with code zero, multiple exception codes or names are prohibited
ida_dbg.store_exceptions()→bool
Update the exception information stored in the debugger module by invoking its dbg->set_exception_info callback
ida_dbg.define_exception(code:uint, name:str, desc:str, flags:int)→str
Convenience function: define new exception code.
Parameters:

-
code – exception code (cannot be 0)

-
name – exception name (cannot be empty or nullptr)

-
desc – exception description (maybe nullptr)

-
flags – combination of Exception info flags

Returns:
failure message or nullptr. You must call store_exceptions() if this function succeeds
classida_dbg.eval_ctx_t(_ea:ida_idaapi.ea_t)
Bases: `object`
thisownea:ida_idaapi.ea_tida_dbg.SRCIT_NONE
unknown
ida_dbg.SRCIT_MODULE
module
ida_dbg.SRCIT_FUNC
function
ida_dbg.SRCIT_STMT
a statement (if/while/for…)
ida_dbg.SRCIT_EXPR
an expression (a+b*c)
ida_dbg.SRCIT_STTVAR
static variable/code
ida_dbg.SRCIT_LOCVAR
a stack, register, or register-relative local variable or parameter
ida_dbg.SRCDBG_PROV_VERSIONida_dbg.create_source_viewer(out_ccv:TWidget**, parent:TWidget*, custview:TWidget*, sf:source_file_ptr, lines:strvec_t*, lnnum:int, colnum:int, flags:int)→source_view_t*
Create a source code view.
ida_dbg.get_dbg_byte(ea:ida_idaapi.ea_t)→uint32*
Get one byte of the debugged process memory.
Parameters:
ea – linear address
Returns:
success
Returns:
true: success
Returns:
false: address inaccessible or debugger not running
ida_dbg.put_dbg_byte(ea:ida_idaapi.ea_t, x:int)→bool
Change one byte of the debugged process memory.
Parameters:

-
ea – linear address

-
x – byte value

Returns:
true if the process memory has been modified
ida_dbg.invalidate_dbgmem_config()→None
Invalidate the debugged process memory configuration. Call this function if the debugged process might have changed its memory layout (allocated more memory, for example)
ida_dbg.invalidate_dbgmem_contents(ea:ida_idaapi.ea_t, size:asize_t)→None
Invalidate the debugged process memory contents. Call this function each time the process has been stopped or the process memory is modified. If ea == BADADDR, then the whole memory contents will be invalidated
ida_dbg.is_debugger_on()→bool
Is the debugger currently running?
ida_dbg.is_debugger_memory(ea:ida_idaapi.ea_t)→bool
Is the address mapped to debugger memory?
ida_dbg.get_tev_ea(n:int)→ida_idaapi.ea_tida_dbg.get_tev_type(n:int)→intida_dbg.get_tev_tid(n:int)→intida_dbg.bring_debugger_to_front()→Noneida_dbg.set_manual_regions(ranges:meminfo_vec_t)→Noneida_dbg.edit_manual_regions()→Noneida_dbg.enable_manual_regions(enable:bool)→Noneida_dbg.handle_debug_event(ev:debug_event_t, rqflags:int)→intida_dbg.add_virt_module(mod:modinfo_t)→boolida_dbg.del_virt_module(base:ea_tconst)→boolida_dbg.internal_ioctl(fn:int, buf:voidconst*, poutbuf:void**, poutsize:ssize_t*)→intida_dbg.get_dbg_memory_info(ranges:meminfo_vec_t)→intida_dbg.set_bpt_group(bpt:bpt_t, grp_name:str)→bool
Move a bpt into a folder in the breakpoint dirtree if the folder didn’t exists, it will be created sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
bpt – bpt that will be moved

-
grp_name – absolute path to the breakpoint dirtree folder

Returns:
success
ida_dbg.set_bptloc_group(bptloc:bpt_location_t, grp_name:str)→bool
Move a bpt into a folder in the breakpoint dirtree based on the bpt_location find_bpt is called to retrieve the bpt and then set_bpt_group if the folder didn’t exists, it will be created sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
bptloc – bptlocation of the bpt that will be moved

-
grp_name – absolute path to the breakpoint dirtree folder

Returns:
success
ida_dbg.get_bpt_group(bptloc:bpt_location_t)→str
Retrieve the absolute path to the folder of the bpt based on the bpt_location find_bpt is called to retrieve the bpt sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
bptloc – bptlocation of the bpt
Returns:
success
Returns:
true: breakpoint correctly moved to the directory
ida_dbg.rename_bptgrp(old_name:str, new_name:str)→bool
Rename a folder of bpt dirtree sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
old_name – absolute path to the folder to be renamed

-
new_name – absolute path of the new folder name

Returns:
success
ida_dbg.del_bptgrp(name:str)→bool
Delete a folder, bpt that were part of this folder are moved to the root folder sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:
name – full path to the folder to be deleted
Returns:
success
ida_dbg.get_grp_bpts(bpts:bpt_vec_t, grp_name:str)→ssize_t
Retrieve a copy of the bpts stored in a folder sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
bpts – : pointer to a vector where the copy of bpts are stored

-
grp_name – absolute path to the folder

Returns:
number of bpts present in the vector
ida_dbg.enable_bptgrp(bptgrp_name:str, enable:bool=True)→int
Enable (or disable) all bpts in a folder sq{Type, Synchronous function, Notification, none (synchronous function)}
Parameters:

-
bptgrp_name – absolute path to the folder

-
enable – by default true, enable bpts, false disable bpts

Returns:
-1: an error occurred
Returns:
0: no changes
Returns:
>0: numbers of bpts updated
ida_dbg.get_local_vars(prov:srcinfo_provider_t*, ea:ida_idaapi.ea_t, out:source_items_t*)→boolida_dbg.srcdbg_request_step_into()→boolida_dbg.srcdbg_request_step_over()→boolida_dbg.srcdbg_request_step_until_ret()→boolida_dbg.hide_all_bpts()→intida_dbg.read_dbg_memory(ea:ida_idaapi.ea_t, buffer:void*, size:int)→ssize_tida_dbg.get_module_info(ea:ida_idaapi.ea_t, modinfo:modinfo_t)→boolida_dbg.dbg_bin_search(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, data:compiled_binpat_vec_tconst&, srch_flags:int)→strida_dbg.load_debugger(dbgname:str, use_remote:bool)→boolida_dbg.collect_stack_trace(tid:thid_t, trace:call_stack_t)→boolida_dbg.get_global_var(prov:srcinfo_provider_t*, ea:ida_idaapi.ea_t, name:str, out:source_item_ptr*)→boolida_dbg.get_local_var(prov:srcinfo_provider_t*, ea:ida_idaapi.ea_t, name:str, out:source_item_ptr*)→boolida_dbg.get_srcinfo_provider(name:str)→srcinfo_provider_t*ida_dbg.get_current_source_file()→strida_dbg.get_current_source_line()→intida_dbg.add_path_mapping(src:str, dst:str)→Noneida_dbg.srcdbg_step_into()→boolida_dbg.srcdbg_step_over()→boolida_dbg.srcdbg_step_until_ret()→boolida_dbg.set_debugger_event_cond(evcond:str)→Noneida_dbg.get_debugger_event_cond()→strclassida_dbg.dbg_deref_options_t
Bases: `object`
thisownderef_limit:inthide_default_segments:boolida_dbg.set_process_options(*args)→None
Set process options. Any of the arguments may be nullptr, which means ‘do not modify’
ida_dbg.get_process_options()→qstring*,qstring*,qstring*,qstring*,qstring*,int*
Get process options. Any of the arguments may be nullptr
ida_dbg.get_manual_regions(*args)
Returns the manual memory regions

This function has the following signatures:

-
get_manual_regions() -> List[Tuple(ida_idaapi.ea_t, ida_idaapi.ea_t, str, str, ida_idaapi.ea_t, int, int)] Where each tuple holds (start_ea, end_ea, name, sclass, sbase, bitness, perm)

-
get_manual_regions(storage: meminfo_vec_t) -> None

ida_dbg.dbg_is_loaded()
Checks if a debugger is loaded
Returns:
Boolean
ida_dbg.refresh_debugger_memory()
Refreshes the debugger memory
Returns:
Nothing
classida_dbg.DBG_Hooks(_flags:int=0, _hkcb_flags:int=1)
Bases: `object`
thisownhook()→boolunhook()→booldbg_process_start(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, modinfo_name:str, modinfo_base:ida_idaapi.ea_t, modinfo_size:asize_t)→Nonedbg_process_exit(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, exit_code:int)→Nonedbg_process_attach(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, modinfo_name:str, modinfo_base:ida_idaapi.ea_t, modinfo_size:asize_t)→Nonedbg_process_detach(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t)→Nonedbg_thread_start(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t)→Nonedbg_thread_exit(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, exit_code:int)→Nonedbg_library_load(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, modinfo_name:str, modinfo_base:ida_idaapi.ea_t, modinfo_size:asize_t)→Nonedbg_library_unload(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, info:str)→Nonedbg_information(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, info:str)→Nonedbg_exception(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t, exc_code:int, exc_can_cont:bool, exc_ea:ida_idaapi.ea_t, exc_info:str)→intdbg_suspend_process()→None
The process is now suspended.
dbg_bpt(tid:thid_t, bptea:ida_idaapi.ea_t)→int
A user defined breakpoint was reached.
Parameters:

-
tid – (thid_t)

-
bptea – (::ea_t)

dbg_trace(tid:thid_t, ip:ida_idaapi.ea_t)→int
A step occurred (one instruction was executed). This event notification is only generated if step tracing is enabled.
Parameters:

-
tid – (thid_t) thread ID

-
ip – (::ea_t) current instruction pointer. usually points after the executed instruction

Returns:
1: do not log this trace event
Returns:
0: log it
dbg_request_error(failed_command:int, failed_dbg_notification:int)→None
An error occurred during the processing of a request.
Parameters:

-
failed_command – (ui_notification_t)

-
failed_dbg_notification – (dbg_notification_t)

dbg_step_into()→Nonedbg_step_over()→Nonedbg_run_to(pid:pid_t, tid:thid_t, ea:ida_idaapi.ea_t)→Nonedbg_step_until_ret()→Nonedbg_bpt_changed(bptev_code:int, bpt:bpt_t)→None
Breakpoint has been changed.
Parameters:

-
bptev_code – (int) Breakpoint modification events

-
bpt – (bpt_t *)

dbg_started_loading_bpts()→None
Started loading breakpoint info from idb.
dbg_finished_loading_bpts()→None
Finished loading breakpoint info from idb.
ida_dbg.list_bptgrps()→List[str]
Retrieve the list of absolute path of all folders of bpt dirtree. Synchronous function, Notification, none (synchronous function)
ida_dbg.internal_get_sreg_base(tid:int, sreg_value:int)
Get the sreg base, for the given thread.
Parameters:

-
tid – the thread ID

-
sreg_value – the sreg value

Returns:
The sreg base, or BADADDR on failure.
ida_dbg.write_dbg_memory(*args)→ssize_tida_dbg.dbg_can_query()This function can be used to check if the debugger can be queried:

-
debugger is loaded

-
process is suspended

-
process is not suspended but can take requests. In this case some requests like memory read/write, bpt management succeed and register querying will fail. Check if idaapi.get_process_state() < 0 to tell if the process is suspended

Returns:
Boolean
ida_dbg.set_reg_val(*args)→bool
Set a register value by name
This function has the following signatures:
1. set_reg_val(name: str, value: Union[int, float, bytes]) -> bool 1. set_reg_val(tid: int, regidx: int, value: Union[int, float, bytes]) -> bool

Depending on the register type, this will expect either an integer, a float or, in the case of large vector registers, a bytes sequence.
Parameters:

-
name – (1st form) the register name

-
tid – (2nd form) the thread ID

-
regidx – (2nd form) the register index

-
value – the register value

Returns:
success
ida_dbg.request_set_reg_val(regname:str, o:PyObject*)→PyObject*
Post a set_reg_val() request.
ida_dbg.get_reg_val(*args)
Get a register value.

This function has the following signatures:

-
get_reg_val(name: str) -> Union[int, float, bytes]

-
get_reg_val(name: str, regval: regval_t) -> bool

The first (and most user-friendly) form will return a value whose type is related to the register type. I.e., either an integer, a float or, in the case of large vector registers, a bytes sequence.
Parameters:
name – the register name
Returns:
the register value (1st form)
ida_dbg.get_reg_vals(tid:int, clsmask:int=-1)→ida_idd.regvals_t
Fetch live registers values for the thread
Parameters:

-
tid – The ID of the thread to read registers for

-
clsmask – An OR’ed mask of register classes to read values for (can be used to speed up the retrieval process)

Returns:
a list of register values (empty if an error occurs)
ida_dbg.get_tev_reg_val(tev, reg)ida_dbg.get_tev_reg_mem_qty(tev)ida_dbg.get_tev_reg_mem(tev, idx)ida_dbg.get_tev_reg_mem_ea(tev, idx)ida_dbg.send_dbg_command(command)
Send a direct command to the debugger backend, and retrieve the result as a string.

Note: any double-quotes in ‘command’ must be backslash-escaped. Note: this only works with some debugger backends: Bochs, WinDbg, GDB.

Returns: (True, ) on success, or (False, ) on failure
ida_dbg.move_bpt_to_grp
