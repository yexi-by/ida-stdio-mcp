# IDAPython debugger backend API

- 官方来源：https://python.docs.hex-rays.com/ida_idd/index.html

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
- ida_idd
- View page source

# ida_idd

Contains definition of the interface to IDD modules.

The interface consists of structures describing the target debugged processor and a debugging API.

## Attributes

`IDD_INTERFACE_VERSION`
|
The IDD interface version number.

`NO_THREAD`
|
No thread. in PROCESS_STARTED this value can be used to specify that the main thread has not been created. It will be initialized later by a THREAD_STARTED event.

`DEF_ADDRSIZE`
|

`REGISTER_READONLY`
|
the user cannot modify the current value of this register

`REGISTER_IP`
|
instruction pointer

`REGISTER_SP`
|
stack pointer

`REGISTER_FP`
|
frame pointer

`REGISTER_ADDRESS`
|
may contain an address

`REGISTER_CS`
|
code segment

`REGISTER_SS`
|
stack segment

`REGISTER_NOLF`
|
displays this register without returning to the next line, allowing the next register to be displayed to its right (on the same line)

`REGISTER_CUSTFMT`
|
register should be displayed using a custom data format. the format name is in bit_strings[0]; the corresponding regval_t will use bytevec_t

`NO_EVENT`
|
Not an interesting event. This event can be used if the debugger module needs to return an event but there are no valid events.

`PROCESS_STARTED`
|
New process has been started.

`PROCESS_EXITED`
|
Process has been stopped.

`THREAD_STARTED`
|
New thread has been started.

`THREAD_EXITED`
|
Thread has been stopped.

`BREAKPOINT`
|
Breakpoint has been reached. IDA will complain about unknown breakpoints, they should be reported as exceptions.

`STEP`
|
One instruction has been executed. Spurious events of this kind are silently ignored by IDA.

`EXCEPTION`
|
Exception.

`LIB_LOADED`
|
New library has been loaded.

`LIB_UNLOADED`
|
Library has been unloaded.

`INFORMATION`
|
User-defined information. This event can be used to return empty information This will cause IDA to call get_debug_event() immediately once more.

`PROCESS_ATTACHED`
|
Successfully attached to running process.

`PROCESS_DETACHED`
|
Successfully detached from process.

`PROCESS_SUSPENDED`
|
Process has been suspended. This event can be used by the debugger module to signal if the process spontaneously gets suspended (not because of an exception, breakpoint, or single step). IDA will silently switch to the 'suspended process' mode without displaying any messages.

`TRACE_FULL`
|
The trace buffer of the tracer module is full and IDA needs to read it before continuing

`STATUS_MASK`
|
additional info about process state

`BITNESS_CHANGED`
|
Debugger detected the process bitness changing.

`cvar`
|

`BPT_WRITE`
|
Write access.

`BPT_READ`
|
Read access.

`BPT_RDWR`
|
Read/write access.

`BPT_SOFT`
|
Software breakpoint.

`BPT_EXEC`
|
Execute instruction.

`BPT_DEFAULT`
|
Choose bpt type automatically.

`EXC_BREAK`
|
break on the exception

`EXC_HANDLE`
|
should be handled by the debugger?

`EXC_MSG`
|
instead of a warning, log the exception to the output window

`EXC_SILENT`
|
do not warn or log to the output window

`RVT_FLOAT`
|
floating point

`RVT_INT`
|
integer

`RVT_UNAVAILABLE`
|
unavailable; other values mean custom data type

`RESMOD_NONE`
|
no stepping, run freely

`RESMOD_INTO`
|
step into call (the most typical single stepping)

`RESMOD_OVER`
|
step over call

`RESMOD_OUT`
|
step out of the current function (run until return)

`RESMOD_SRCINTO`
|
until control reaches a different source line

`RESMOD_SRCOVER`
|
next source line in the current stack frame

`RESMOD_SRCOUT`
|
next source line in the previous stack frame

`RESMOD_USER`
|
step out to the user code

`RESMOD_HANDLE`
|
step into the exception handler

`RESMOD_BACKINTO`
|
step backwards into call (in time-travel debugging)

`RESMOD_MAX`
|

`STEP_TRACE`
|
lowest level trace. trace buffers are not maintained

`INSN_TRACE`
|
instruction tracing

`FUNC_TRACE`
|
function tracing

`BBLK_TRACE`
|
basic block tracing

`DRC_EVENTS`
|
success, there are pending events

`DRC_CRC`
|
success, but the input file crc does not match

`DRC_OK`
|
success

`DRC_NONE`
|
reaction to the event not implemented

`DRC_FAILED`
|
failed or false

`DRC_NETERR`
|
network error

`DRC_NOFILE`
|
file not found

`DRC_IDBSEG`
|
use idb segmentation

`DRC_NOPROC`
|
the process does not exist anymore

`DRC_NOCHG`
|
no changes

`DRC_ERROR`
|
unclassified error, may be complemented by errbuf

`DEBUGGER_ID_X86_IA32_WIN32_USER`
|
Userland win32 processes (win32 debugging APIs)

`DEBUGGER_ID_X86_IA32_LINUX_USER`
|
Userland linux processes (ptrace())

`DEBUGGER_ID_X86_IA32_MACOSX_USER`
|
Userland MAC OS X processes.

`DEBUGGER_ID_ARM_IPHONE_USER`
|
iPhone 1.x

`DEBUGGER_ID_X86_IA32_BOCHS`
|
BochsDbg.exe 32.

`DEBUGGER_ID_6811_EMULATOR`
|
MC6812 emulator (beta)

`DEBUGGER_ID_GDB_USER`
|
GDB remote.

`DEBUGGER_ID_WINDBG`
|
WinDBG using Microsoft Debug engine.

`DEBUGGER_ID_X86_DOSBOX_EMULATOR`
|
Dosbox MS-DOS emulator.

`DEBUGGER_ID_ARM_LINUX_USER`
|
Userland arm linux.

`DEBUGGER_ID_TRACE_REPLAYER`
|
Fake debugger to replay recorded traces.

`DEBUGGER_ID_X86_PIN_TRACER`
|
PIN Tracer module.

`DEBUGGER_ID_DALVIK_USER`
|
Dalvik.

`DEBUGGER_ID_XNU_USER`
|
XNU Kernel.

`DEBUGGER_ID_ARM_MACOS_USER`
|
Userland arm MAC OS.

`DBG_FLAG_REMOTE`
|
Remote debugger (requires remote host name unless DBG_FLAG_NOHOST)

`DBG_FLAG_NOHOST`
|
Remote debugger with does not require network params (host/port/pass). (a unique device connected to the machine)

`DBG_FLAG_FAKE_ATTACH`
|
PROCESS_ATTACHED is a fake event and does not suspend the execution

`DBG_FLAG_HWDATBPT_ONE`
|
Hardware data breakpoints are one byte size by default

`DBG_FLAG_CAN_CONT_BPT`
|
Debugger knows to continue from a bpt. This flag also means that the debugger module hides breakpoints from ida upon read_memory

`DBG_FLAG_NEEDPORT`
|
Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)

`DBG_FLAG_DONT_DISTURB`
|
Debugger can handle only get_debug_event(), request_pause(), exit_process() when the debugged process is running. The kernel may also call service functions (file I/O, map_address, etc)

`DBG_FLAG_SAFE`
|
The debugger is safe (probably because it just emulates the application without really running it)

`DBG_FLAG_CLEAN_EXIT`
|
IDA must suspend the application and remove all breakpoints before terminating the application. Usually this is not required because the application memory disappears upon termination.

`DBG_FLAG_USE_SREGS`
|
Take segment register values into account (non flat memory)

`DBG_FLAG_NOSTARTDIR`
|
Debugger module doesn't use startup directory.

`DBG_FLAG_NOPARAMETERS`
|
Debugger module doesn't use commandline parameters.

`DBG_FLAG_NOPASSWORD`
|
Remote debugger doesn't use password.

`DBG_FLAG_CONNSTRING`
|
Display "Connection string" instead of "Hostname" and hide the "Port" field.

`DBG_FLAG_SMALLBLKS`
|
If set, IDA uses 256-byte blocks for caching memory contents. Otherwise, 1024-byte blocks are used

`DBG_FLAG_MANMEMINFO`
|
If set, manual memory region manipulation commands will be available. Use this bit for debugger modules that cannot return memory layout information

`DBG_FLAG_EXITSHOTOK`
|
IDA may take a memory snapshot at PROCESS_EXITED event.

`DBG_FLAG_VIRTHREADS`
|
Thread IDs may be shuffled after each debug event. (to be used for virtual threads that represent cpus for windbg kmode)

`DBG_FLAG_LOWCNDS`
|
Low level breakpoint conditions are supported.

`DBG_FLAG_DEBTHREAD`
|
Supports creation of a separate thread in ida for the debugger (the debthread). Most debugger functions will be called from debthread (exceptions are marked below) The debugger module may directly call only THREAD_SAFE functions. To call other functions please use execute_sync(). The debthread significantly increases debugging speed, especially if debug events occur frequently.

`DBG_FLAG_DEBUG_DLL`
|
Can debug standalone DLLs. For example, Bochs debugger can debug any snippet of code

`DBG_FLAG_FAKE_MEMORY`
|
get_memory_info()/read_memory()/write_memory() work with the idb. (there is no real process to read from, as for the replayer module) the kernel will not call these functions if this flag is set. however, third party plugins may call them, they must be implemented.

`DBG_FLAG_ANYSIZE_HWBPT`
|
The debugger supports arbitrary size hardware breakpoints.

`DBG_FLAG_TRACER_MODULE`
|
The module is a tracer, not a full featured debugger module.

`DBG_FLAG_PREFER_SWBPTS`
|
Prefer to use software breakpoints.

`DBG_FLAG_LAZY_WATCHPTS`
|
Watchpoints are triggered before the offending instruction is executed. The debugger must temporarily disable the watchpoint and single-step before resuming.

`DBG_FLAG_FAST_STEP`
|
Do not refresh memory layout info after single stepping.

`DBG_FLAG_ADD_ENVS`
|
The debugger supports launching processes with environment variables.

`DBG_FLAG_MERGE_ENVS`
|
The debugger supports merge or replace setting for environment variables (only makes sense if DBG_FLAG_ADD_ENVS is set)

`DBG_FLAG_DISABLE_ASLR`
|
The debugger supports ASLR disabling (address space layout randomization)

`DBG_FLAG_TTD`
|
The debugger is a time travel debugger and supports continuing backwards.

`DBG_FLAG_FULL_INSTR_BPT`
|
Setting a breakpoint in the middle of an instruction will also break.

`DBG_HAS_GET_PROCESSES`
|
supports ev_get_processes

`DBG_HAS_ATTACH_PROCESS`
|
supports ev_attach_process

`DBG_HAS_DETACH_PROCESS`
|
supports ev_detach_process

`DBG_HAS_REQUEST_PAUSE`
|
supports ev_request_pause

`DBG_HAS_SET_EXCEPTION_INFO`
|
supports ev_set_exception_info

`DBG_HAS_THREAD_SUSPEND`
|
supports ev_thread_suspend

`DBG_HAS_THREAD_CONTINUE`
|
supports ev_thread_continue

`DBG_HAS_SET_RESUME_MODE`
|
supports ev_set_resume_mode. Cannot be set inside the debugger_t::init_debugger()

`DBG_HAS_THREAD_GET_SREG_BASE`
|
supports ev_thread_get_sreg_base

`DBG_HAS_CHECK_BPT`
|
supports ev_check_bpt

`DBG_HAS_OPEN_FILE`
|
supports ev_open_file, ev_close_file, ev_read_file, ev_write_file

`DBG_HAS_UPDATE_CALL_STACK`
|
supports ev_update_call_stack

`DBG_HAS_APPCALL`
|
supports ev_appcall, ev_cleanup_appcall

`DBG_HAS_REXEC`
|
supports ev_rexec

`DBG_HAS_MAP_ADDRESS`
|
supports ev_map_address. Avoid using this bit, especially together with DBG_FLAG_DEBTHREAD because it may cause big slow downs

`DBG_RESMOD_STEP_INTO`
|
RESMOD_INTO is available

`DBG_RESMOD_STEP_OVER`
|
RESMOD_OVER is available

`DBG_RESMOD_STEP_OUT`
|
RESMOD_OUT is available

`DBG_RESMOD_STEP_SRCINTO`
|
RESMOD_SRCINTO is available

`DBG_RESMOD_STEP_SRCOVER`
|
RESMOD_SRCOVER is available

`DBG_RESMOD_STEP_SRCOUT`
|
RESMOD_SRCOUT is available

`DBG_RESMOD_STEP_USER`
|
RESMOD_USER is available

`DBG_RESMOD_STEP_HANDLE`
|
RESMOD_HANDLE is available

`DBG_RESMOD_STEP_BACKINTO`
|
RESMOD_BACKINTO is available

`DBG_PROC_IS_DLL`
|
database contains a DLL (not EXE)

`DBG_PROC_IS_GUI`
|
using gui version of ida

`DBG_PROC_32BIT`
|
application is 32-bit

`DBG_PROC_64BIT`
|
application is 64-bit

`DBG_NO_TRACE`
|
do not trace the application (mac/linux)

`DBG_HIDE_WINDOW`
|
application should be hidden on startup (windows)

`DBG_SUSPENDED`
|
application should be suspended on startup (mac)

`DBG_NO_ASLR`
|
disable ASLR (linux)

`BPT_OK`
|
breakpoint can be set

`BPT_INTERNAL_ERR`
|
interr occurred when verifying breakpoint

`BPT_BAD_TYPE`
|
bpt type is not supported

`BPT_BAD_ALIGN`
|
alignment is invalid

`BPT_BAD_ADDR`
|
ea is invalid

`BPT_BAD_LEN`
|
bpt len is invalid

`BPT_TOO_MANY`
|
reached max number of supported breakpoints

`BPT_READ_ERROR`
|
failed to read memory at bpt ea

`BPT_WRITE_ERROR`
|
failed to write memory at bpt ea

`BPT_SKIP`
|
update_bpts(): do not process bpt

`BPT_PAGE_OK`
|
update_bpts(): ok, added a page bpt

`APPCALL_MANUAL`
|
Only set up the appcall, do not run. debugger_t::cleanup_appcall will not be generated by ida!

`APPCALL_DEBEV`
|
Return debug event information.

`APPCALL_TIMEOUT`
|
Appcall with timeout. If timed out, errbuf will contain "timeout". See SET_APPCALL_TIMEOUT and GET_APPCALL_TIMEOUT

`RQ_MASKING`
|
masking step handler: unless errors, tmpbpt handlers won't be generated should be used only with request_internal_step()

`RQ_SUSPEND`
|
suspending step handler: suspends the app handle_debug_event: suspends the app

`RQ_NOSUSP`
|
running step handler: continues the app

`RQ_IGNWERR`
|
ignore breakpoint write failures

`RQ_SILENT`
|
all: no dialog boxes

`RQ_VERBOSE`
|
all: display dialog boxes

`RQ_SWSCREEN`
|
handle_debug_event: switch screens

`RQ__NOTHRRF`
|
handle_debug_event: do not refresh threads

`RQ_PROCEXIT`
|
snapshots: the process is exiting

`RQ_IDAIDLE`
|
handle_debug_event: ida is idle

`RQ_SUSPRUN`
|
handle_debug_event: suspend at PROCESS_STARTED

`RQ_RESUME`
|
handle_debug_event: resume application

`RQ_RESMOD`
|
resume_mode_t

`RQ_RESMOD_SHIFT`
|

`NO_PROCESS`
|
No process.

`NO_THREAD`
|
No thread. in PROCESS_STARTED this value can be used to specify that the main thread has not been created. It will be initialized later by a THREAD_STARTED event.

`dbg_can_query`
|

`Appcall`
|

## Classes

`excvec_t`
|

`procinfo_vec_t`
|

`call_stack_info_vec_t`
|

`meminfo_vec_template_t`
|

`regvals_t`
|

`process_info_t`
|

`debapp_attrs_t`
|

`register_info_t`
|

`memory_info_t`
|

`meminfo_vec_t`
|

`scattered_segm_t`
|

`launch_env_t`
|

`modinfo_t`
|

`bptaddr_t`
|

`excinfo_t`
|

`debug_event_t`
|

`exception_info_t`
|

`regval_t`
|

`call_stack_info_t`
|

`call_stack_t`
|

`thread_name_t`
|

`debugger_t`
|

`dyn_register_info_array`
|

`Appcall_array__`
|
This class is used with Appcall.array() method

`Appcall_callable__`
|
Helper class to issue appcalls using a natural syntax:

`Appcall_consts__`
|
Helper class used by Appcall.Consts attribute

`Appcall__`
|

## Functions

`set_debug_event_code`(→ None)
|

`get_debug_event_name`(→ str)
|
get debug event name

`dbg_appcall`(→ error_t)
|
Call a function from the debugged application.

`cleanup_appcall`(→ error_t)
|
Cleanup after manual appcall.

`cpu2ieee`(→ int)
|
Convert a floating point number in CPU native format to IDA's internal format.

`ieee2cpu`(→ int)
|
Convert a floating point number in IDA's internal format to CPU native format.

`get_dbg`(→ debugger_t *)
|

`dbg_get_registers`()
|
This function returns the register definition from the currently loaded debugger.

`dbg_get_thread_sreg_base`(tid, sreg_value)
|
Returns the segment register base value

`dbg_read_memory`(ea, sz)
|
Reads from the debugee's memory at the specified ea

`dbg_write_memory`(ea, buffer)
|
Writes a buffer to the debugee's memory

`dbg_get_name`()
|
This function returns the current debugger's name.

`dbg_get_memory_info`()
|
This function returns the memory configuration of a debugged process.

`appcall`(→ PyObject *)
|

`get_event_module_name`(→ str)
|

`get_event_module_base`(→ ida_idaapi.ea_t)
|

`get_event_module_size`(→ asize_t)
|

`get_event_exc_info`(→ str)
|

`get_event_info`(→ str)
|

`get_event_bpt_hea`(→ ida_idaapi.ea_t)
|

`get_event_exc_code`(→ uint)
|

`get_event_exc_ea`(→ ida_idaapi.ea_t)
|

`can_exc_continue`(→ bool)
|

## Module Contents

classida_idd.excvec_t(*args)
Bases: `object`
thisownpush_back(*args)→exception_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→exception_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:excvec_t)→Noneextract()→exception_info_t*inject(s:exception_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:exception_info_t, x:exception_info_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:exception_info_t)→Noneextend(x:excvec_t)→Nonefrontbackclassida_idd.procinfo_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→process_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→process_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:procinfo_vec_t)→Noneextract()→process_info_t*inject(s:process_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:process_info_t, x:process_info_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:process_info_t)→Noneextend(x:procinfo_vec_t)→Nonefrontbackclassida_idd.call_stack_info_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→call_stack_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→call_stack_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:call_stack_info_vec_t)→Noneextract()→call_stack_info_t*inject(s:call_stack_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:call_stack_info_t, x:call_stack_info_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:call_stack_info_t)→booladd_unique(x:call_stack_info_t)→boolappend(x:call_stack_info_t)→Noneextend(x:call_stack_info_vec_t)→Nonefrontbackclassida_idd.meminfo_vec_template_t(*args)
Bases: `object`
thisownpush_back(*args)→memory_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→memory_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:meminfo_vec_template_t)→Noneextract()→memory_info_t*inject(s:memory_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:memory_info_t, x:memory_info_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:memory_info_t)→booladd_unique(x:memory_info_t)→boolappend(x:memory_info_t)→Noneextend(x:meminfo_vec_template_t)→Nonefrontbackclassida_idd.regvals_t(*args)
Bases: `object`
thisownpush_back(*args)→regval_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→regval_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:regvals_t)→Noneextract()→regval_t*inject(s:regval_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:regval_t, x:regval_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:regval_t)→booladd_unique(x:regval_t)→boolappend(x:regval_t)→Noneextend(x:regvals_t)→Nonefrontbackida_idd.IDD_INTERFACE_VERSION
The IDD interface version number.
ida_idd.NO_THREAD
No thread. in PROCESS_STARTED this value can be used to specify that the main thread has not been created. It will be initialized later by a THREAD_STARTED event.
classida_idd.process_info_t
Bases: `object`
thisownpid:pid_t
process id
name:str
process name
classida_idd.debapp_attrs_t
Bases: `object`
thisowncbsize:int
control field: size of this structure
addrsize:int
address size of the process. Since 64-bit debuggers usually can debug 32-bit applications, we cannot rely on sizeof(ea_t) to detect the current address size. The following variable should be used instead. It is initialized with 8 for 64-bit debuggers but they should adjust it as soon as they learn that a 32-bit application is being debugged. For 32-bit debuggers it is initialized with 4.
platform:str
platform name process is running/debugging under. (is used as a key value in exceptions.cfg)
is_be:intida_idd.DEF_ADDRSIZEclassida_idd.register_info_t
Bases: `object`
thisownname:str
Register name.
flags:int
Register info attribute flags
register_class_mask:uchar
mask of register classes
dtype:op_dtype_t
Register size (see Operand value types)
default_bit_strings_mask:int
mask of default bits
bit_strings
strings corresponding to each bit of the register. (nullptr = no bit, same name = multi-bits mask)
register_classida_idd.REGISTER_READONLY
the user cannot modify the current value of this register
ida_idd.REGISTER_IP
instruction pointer
ida_idd.REGISTER_SP
stack pointer
ida_idd.REGISTER_FP
frame pointer
ida_idd.REGISTER_ADDRESS
may contain an address
ida_idd.REGISTER_CS
code segment
ida_idd.REGISTER_SS
stack segment
ida_idd.REGISTER_NOLF
displays this register without returning to the next line, allowing the next register to be displayed to its right (on the same line)
ida_idd.REGISTER_CUSTFMT
register should be displayed using a custom data format. the format name is in bit_strings[0]; the corresponding regval_t will use bytevec_t
classida_idd.memory_info_t
Bases: `ida_range.range_t`
thisownname:str
Memory range name.
sclass:str
Memory range class name.
sbase:ida_idaapi.ea_t
Segment base (meaningful only for segmented architectures, e.g. 16-bit x86) The base is specified in paragraphs (i.e. shifted to the right by 4)
bitness:uchar
Number of bits in segment addresses (0-16-bit, 1-32-bit, 2-64-bit)
perm:uchar
Memory range permissions (0-no information): see segment.hpp.
classida_idd.meminfo_vec_t
Bases: `meminfo_vec_template_t`
thisownclassida_idd.scattered_segm_t
Bases: `ida_range.range_t`
thisownname:str
name of the segment
classida_idd.launch_env_t
Bases: `object`
thisownmerge:boolset(envvar:str, value:str)→Noneenvs()→PyObject*ida_idd.NO_EVENT
Not an interesting event. This event can be used if the debugger module needs to return an event but there are no valid events.
ida_idd.PROCESS_STARTED
New process has been started.
ida_idd.PROCESS_EXITED
Process has been stopped.
ida_idd.THREAD_STARTED
New thread has been started.
ida_idd.THREAD_EXITED
Thread has been stopped.
ida_idd.BREAKPOINT
Breakpoint has been reached. IDA will complain about unknown breakpoints, they should be reported as exceptions.
ida_idd.STEP
One instruction has been executed. Spurious events of this kind are silently ignored by IDA.
ida_idd.EXCEPTION
Exception.
ida_idd.LIB_LOADED
New library has been loaded.
ida_idd.LIB_UNLOADED
Library has been unloaded.
ida_idd.INFORMATION
User-defined information. This event can be used to return empty information This will cause IDA to call get_debug_event() immediately once more.
ida_idd.PROCESS_ATTACHED
Successfully attached to running process.
ida_idd.PROCESS_DETACHED
Successfully detached from process.
ida_idd.PROCESS_SUSPENDED
Process has been suspended. This event can be used by the debugger module to signal if the process spontaneously gets suspended (not because of an exception, breakpoint, or single step). IDA will silently switch to the ‘suspended process’ mode without displaying any messages.
ida_idd.TRACE_FULL
The trace buffer of the tracer module is full and IDA needs to read it before continuing
ida_idd.STATUS_MASK
additional info about process state
ida_idd.BITNESS_CHANGED
Debugger detected the process bitness changing.
ida_idd.set_debug_event_code(ev:debug_event_t, id:event_id_t)→Noneclassida_idd.modinfo_t
Bases: `object`
thisownname:str
full name of the module
base:ida_idaapi.ea_t
module base address. if unknown pass BADADDR
size:asize_t
module size. if unknown pass 0
rebase_to:ida_idaapi.ea_t
if not BADADDR, rebase the program to that address
classida_idd.bptaddr_t
Bases: `object`
thisownhea:ida_idaapi.ea_t
Possible address referenced by hardware breakpoints.
kea:ida_idaapi.ea_t
Address of the triggered bpt from the kernel’s point of view. (for some systems with special memory mappings, the triggered ea might be different from event ea). Use to BADADDR for flat memory model.
classida_idd.excinfo_t
Bases: `object`
thisowncode:int
Exception code.
can_cont:bool
Can execution of the process continue after this exception?
ea:ida_idaapi.ea_t
Possible address referenced by the exception.
info:str
Exception message.
classida_idd.debug_event_t(*args)
Bases: `object`
thisownpid:pid_t
Process where the event occurred.
tid:thid_t
Thread where the event occurred.
ea:ida_idaapi.ea_t
Address where the event occurred.
handled:bool
Is event handled by the debugger? (from the system’s point of view) Meaningful for EXCEPTION events
copy(r:debug_event_t)→debug_event_t&clear()→None
clear the dependent information (see below), set event code to NO_EVENT
clear_all()→Noneeid()→event_id_t
Event code.
set_eid(id:event_id_t)→None
Set event code. If the new event code is compatible with the old one then the dependent information (see below) will be preserved. Otherwise the event will be cleared and the new event code will be set.
is_bitness_changed()→bool
process bitness
set_bitness_changed(on:bool=True)→Nonemodinfo()→modinfo_t&
Information that depends on the event code:

< PROCESS_STARTED, PROCESS_ATTACHED, LIB_LOADED PROCESS_EXITED, THREAD_EXITED
info()→str
BREAKPOINT
bpt()→bptaddr_t&
EXCEPTION
exc()→excinfo_t&exit_code()→intconst&
THREAD_STARTED (thread name) LIB_UNLOADED (unloaded library name) INFORMATION (will be displayed in the output window if not empty)
set_modinfo(id:event_id_t)→modinfo_t&set_exit_code(id:event_id_t, code:int)→Noneset_info(id:event_id_t)→strset_bpt()→bptaddr_t&set_exception()→excinfo_t&bpt_ea()→ida_idaapi.ea_t
On some systems with special memory mappings the triggered ea might be different from the actual ea. Calculate the address to use.
ida_idd.get_debug_event_name(dev:debug_event_t)→str
get debug event name
classida_idd.exception_info_t(*args)
Bases: `object`
thisowncode:uint
exception code
flags:int
Exception info flags
break_on()→bool
Should we break on the exception?
handle()→bool
Should we handle the exception?
name:str
Exception standard name.
desc:str
Long message used to display info about the exception.
ida_idd.cvarida_idd.BPT_WRITE
Write access.
ida_idd.BPT_READ
Read access.
ida_idd.BPT_RDWR
Read/write access.
ida_idd.BPT_SOFT
Software breakpoint.
ida_idd.BPT_EXEC
Execute instruction.
ida_idd.BPT_DEFAULT
Choose bpt type automatically.
ida_idd.EXC_BREAK
break on the exception
ida_idd.EXC_HANDLE
should be handled by the debugger?
ida_idd.EXC_MSG
instead of a warning, log the exception to the output window
ida_idd.EXC_SILENT
do not warn or log to the output window
classida_idd.regval_t(*args)
Bases: `object`
thisownrvtype:int
one of Register value types
ival:uint64
RVT_INT.
use_bytevec()→boolclear()→None
Clear register value.
swap(r:regval_t)→None
Set this = r and r = this.
set_int(x:uint64)→Noneset_float(v:bytevec_tconst&)→Noneset_bytes(*args)→bytevec_t&set_unavailable()→Nonebytes(*args)→bytevec_tconst&get_data(*args)→voidconst*get_data_size()→intset_pyval(o:PyObject*, dtype:op_dtype_t)→boolpyval(dtype:op_dtype_t)→PyObject*ida_idd.RVT_FLOAT
floating point
ida_idd.RVT_INT
integer
ida_idd.RVT_UNAVAILABLE
unavailable; other values mean custom data type
classida_idd.call_stack_info_t
Bases: `object`
thisowncallea:ida_idaapi.ea_t
the address of the call instruction. for the 0th frame this is usually just the current value of EIP.
funcea:ida_idaapi.ea_t
the address of the called function
fp:ida_idaapi.ea_t
the value of the frame pointer of the called function
funcok:bool
is the function present?
classida_idd.call_stack_t
Bases: `call_stack_info_vec_t`
thisownida_idd.dbg_appcall(retval:idc_value_t*, func_ea:ida_idaapi.ea_t, tid:thid_t, ptif:tinfo_t, argv:idc_value_t*, argnum:int)→error_t
Call a function from the debugged application.
Parameters:
retval – function return value

-
for APPCALL_MANUAL, r will hold the new stack point value

-
for APPCALL_DEBEV, r will hold the exception information upon failure and the return code will be eExecThrow

Parameters:

-
func_ea – address to call

-
tid – thread to use. NO_THREAD means to use the current thread

-
ptif – pointer to type of the function to call

-
argv – array of arguments

-
argnum – number of actual arguments

Returns:
eOk if successful, otherwise an error code
ida_idd.cleanup_appcall(tid:thid_t)→error_t
Cleanup after manual appcall.
Parameters:
tid – thread to use. NO_THREAD means to use the current thread The application state is restored as it was before calling the last appcall(). Nested appcalls are supported.
Returns:
eOk if successful, otherwise an error code
classida_idd.thread_name_t
Bases: `object`
thisowntid:thid_t
thread
name:str
new thread name
ida_idd.RESMOD_NONE
no stepping, run freely
ida_idd.RESMOD_INTO
step into call (the most typical single stepping)
ida_idd.RESMOD_OVER
step over call
ida_idd.RESMOD_OUT
step out of the current function (run until return)
ida_idd.RESMOD_SRCINTO
until control reaches a different source line
ida_idd.RESMOD_SRCOVER
next source line in the current stack frame
ida_idd.RESMOD_SRCOUT
next source line in the previous stack frame
ida_idd.RESMOD_USER
step out to the user code
ida_idd.RESMOD_HANDLE
step into the exception handler
ida_idd.RESMOD_BACKINTO
step backwards into call (in time-travel debugging)
ida_idd.RESMOD_MAXida_idd.STEP_TRACE
lowest level trace. trace buffers are not maintained
ida_idd.INSN_TRACE
instruction tracing
ida_idd.FUNC_TRACE
function tracing
ida_idd.BBLK_TRACE
basic block tracing
ida_idd.DRC_EVENTS
success, there are pending events
ida_idd.DRC_CRC
success, but the input file crc does not match
ida_idd.DRC_OK
success
ida_idd.DRC_NONE
reaction to the event not implemented
ida_idd.DRC_FAILED
failed or false
ida_idd.DRC_NETERR
network error
ida_idd.DRC_NOFILE
file not found
ida_idd.DRC_IDBSEG
use idb segmentation
ida_idd.DRC_NOPROC
the process does not exist anymore
ida_idd.DRC_NOCHG
no changes
ida_idd.DRC_ERROR
unclassified error, may be complemented by errbuf
classida_idd.debugger_t
Bases: `object`
thisownversion:int
Expected kernel version, should be IDD_INTERFACE_VERSION
name:str
Short debugger name like win32 or linux.
id:int
one of Debugger API module id
processor:str
Required processor name. Used for instant debugging to load the correct processor module
flags:uint64is_remote()→boolmust_have_hostname()→boolcan_continue_from_bpt()→boolmay_disturb()→boolis_safe()→booluse_sregs()→boolcache_block_size()→intuse_memregs()→boolmay_take_exit_snapshot()→boolvirtual_threads()→boolsupports_lowcnds()→boolsupports_debthread()→boolcan_debug_standalone_dlls()→boolfake_memory()→boolis_ttd()→boolhas_get_processes()→boolhas_attach_process()→boolhas_detach_process()→boolhas_request_pause()→boolhas_set_exception_info()→boolhas_thread_suspend()→boolhas_thread_continue()→boolhas_set_resume_mode()→boolhas_thread_get_sreg_base()→boolhas_check_bpt()→boolhas_open_file()→boolhas_update_call_stack()→boolhas_appcall()→boolhas_rexec()→boolhas_map_address()→boolhas_soft_bpt()→booldefault_regclasses:int
Mask of default printed register classes.
regs(idx:int)→register_info_t&memory_page_size:int
Size of a memory page. Usually 4K.
bpt_size:uchar
Size of the software breakpoint instruction in bytes.
filetype:uchar
Input file type for the instant debugger. This value will be used after attaching to a new process.
resume_modes:ushort
Resume modes
is_resmod_avail(resmod:int)→boolev_init_debugger
Initialize debugger. This event is generated in the main thread.
ev_term_debugger
Terminate debugger. This event is generated in the main thread.
ev_get_processes
Return information about the running processes. This event is generated in the main thread. Available if DBG_HAS_GET_PROCESSES is set
ev_start_process
Start an executable to debug. This event is generated in debthread. Must be implemented.
ev_attach_process
Attach to an existing running process. event_id should be equal to -1 if not attaching to a crashed process. This event is generated in debthread. Available if DBG_HAS_ATTACH_PROCESS is set
ev_detach_process
Detach from the debugged process. May be generated while the process is running or is suspended. Must detach from the process in all cases. The kernel will repeatedly call get_debug_event() until PROCESS_DETACHED is received. In this mode, all other events will be automatically handled and process will be resumed. This event is generated from debthread. Available if DBG_HAS_DETACH_PROCESS is set
ev_get_debapp_attrs
Retrieve process- and debugger-specific runtime attributes. This event is generated in the main thread.
ev_rebase_if_required_to
Rebase database if the debugged program has been rebased by the system. This event is generated in the main thread.
ev_request_pause
Prepare to pause the process. Normally the next get_debug_event() will pause the process If the process is sleeping, then the pause will not occur until the process wakes up. If the debugger module does not react to this event, then it will be impossible to pause the program. This event is generated in debthread. Available if DBG_HAS_REQUEST_PAUSE is set
ev_exit_process
Stop the process. May be generated while the process is running or suspended. Must terminate the process in any case. The kernel will repeatedly call get_debug_event() until PROCESS_EXITED is received. In this mode, all other events will be automatically handled and process will be resumed. This event is generated in debthread. Must be implemented.
ev_get_debug_event
Get a pending debug event and suspend the process. This event will be generated regularly by IDA. This event is generated in debthread. IMPORTANT: the BREAKPOINT/EXCEPTION/STEP events must be reported only after reporting other pending events for a thread. Must be implemented.
ev_resume
Continue after handling the event. This event is generated in debthread. Must be implemented.
ev_set_backwards
Set whether the debugger should continue backwards or forwards. This event is generated in debthread. Available if DBG_FLAG_TTD is set
ev_set_exception_info
Set exception handling. This event is generated in debthread or the main thread. Available if DBG_HAS_SET_EXCEPTION_INFO is set
ev_suspended
This event will be generated by the kernel each time it has suspended the debuggee process and refreshed the database. The debugger module may add information to the database if necessary. The reason for introducing this event is that when an event like LOAD_DLL happens, the database does not reflect the memory state yet and therefore we cannot add information about the DLL into the database in the get_debug_event() function. Only when the kernel has adjusted the database we can do it. Example: for loaded PE DLLs we can add the exported function names to the list of debug names (see set_debug_names()). This event is generated in the main thread.
ev_thread_suspend
Suspend a running thread Available if DBG_HAS_THREAD_SUSPEND is set
ev_thread_continue
Resume a suspended thread Available if DBG_HAS_THREAD_CONTINUE is set
ev_set_resume_mode
Specify resume action Available if DBG_HAS_SET_RESUME_MODE is set
ev_read_registers
Read thread registers. This event is generated in debthread. Must be implemented.
ev_write_register
Write one thread register. This event is generated in debthread. Must be implemented.
ev_thread_get_sreg_base
Get information about the base of a segment register. Currently used by the IBM PC module to resolve references like fs:0. This event is generated in debthread. Available if DBG_HAS_THREAD_GET_SREG_BASE is set
ev_get_memory_info
Get information on the memory ranges. The debugger module fills ‘ranges’. The returned vector must be sorted. This event is generated in debthread. Must be implemented.
ev_read_memory
Read process memory. This event is generated in debthread.
ev_write_memory
Write process memory. This event is generated in debthread.
ev_check_bpt
Is it possible to set breakpoint? This event is generated in debthread or in the main thread if debthread is not running yet. It is generated to verify hardware breakpoints. Available if DBG_HAS_CHECK_BPT is set
ev_update_bpts
Add/del breakpoints. bpts array contains nadd bpts to add, followed by ndel bpts to del. This event is generated in debthread.
ev_update_lowcnds
Update low-level (server side) breakpoint conditions. This event is generated in debthread.
ev_open_fileev_close_fileev_read_fileev_write_fileev_map_address
Map process address. The debugger module may ignore this event. This event is generated in debthread. IDA will generate this event only if DBG_HAS_MAP_ADDRESS is set.
ev_get_debmod_extensions
Get pointer to debugger specific events. This event returns a pointer to a structure that holds pointers to debugger module specific events. For information on the structure layout, please check the corresponding debugger module. Most debugger modules return nullptr because they do not have any extensions. Available extensions may be generated from plugins. This event is generated in the main thread.
ev_update_call_stack
Calculate the call stack trace for the given thread. This event is generated when the process is suspended and should fill the ‘trace’ object with the information about the current call stack. If this event returns DRC_NONE, IDA will try to invoke a processor-specific mechanism (see processor_t::ev_update_call_stack). If the current processor module does not implement stack tracing, then IDA will fall back to a generic algorithm (based on the frame pointer chain) to calculate the trace. This event is ideal if the debugging targets manage stack frames in a peculiar way, requiring special analysis. This event is generated in the main thread. Available if DBG_HAS_UPDATE_CALL_STACK is set
ev_appcall
Call application function. This event calls a function from the debugged application. This event is generated in debthread Available if HAS_APPCALL is set
ev_cleanup_appcall
Cleanup after appcall(). The debugger module must keep the stack blob in the memory until this event is generated. It will be generated by the kernel for each successful appcall(). There is an exception: if APPCALL_MANUAL, IDA may not call cleanup_appcall. If the user selects to terminate a manual appcall, then cleanup_appcall will be generated. Otherwise, the debugger module should terminate the appcall when the generated event returns. This event is generated in debthread. Available if HAS_APPCALL is set
ev_eval_lowcnd
Evaluate a low level breakpoint condition at ‘ea’. Other evaluation errors are displayed in a dialog box. This call is used by IDA when the process has already been temporarily suspended for some reason and IDA has to decide whether the process should be resumed or definitely suspended because of a breakpoint with a low level condition. This event is generated in debthread.
ev_send_ioctl
Perform a debugger-specific event. This event is generated in debthread
ev_dbg_enable_trace
Enable/Disable tracing. The kernel will generated this event if the debugger plugin set DBG_FLAG_TRACER_MODULE. TRACE_FLAGS can be a set of STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE. This event is generated in the main thread.
ev_is_tracing_enabled
Is tracing enabled? The kernel will generated this event if the debugger plugin set DBG_FLAG_TRACER_MODULE. TRACE_BIT can be one of the following: STEP_TRACE, INSN_TRACE, BBLK_TRACE or FUNC_TRACE
ev_rexec
Execute a command on the remote computer. Available if DBG_HAS_REXEC is set
ev_get_srcinfo_path
Get the path to a file containing source debug info for the given module. This allows srcinfo providers to call into the debugger when looking for debug info. It is useful in certain cases like the iOS debugger, which is a remote debugger but the remote debugserver does not provide dwarf info. So, we allow the debugger client to decide where to look for debug info locally.
ev_bin_search
Search for a binary pattern in the program.
ev_get_dynamic_register_set
Ask debuger to send dynamic register set
ev_set_dbg_options
Set debugger options (parameters that are specific to the debugger module).
init_debugger(hostname:str, portnum:int, password:str)→boolterm_debugger()→boolget_processes(procs:procinfo_vec_t)→drc_tstart_process(path:str, args:str, envs:launch_env_t, startdir:str, dbg_proc_flags:int, input_path:str, input_file_crc32:int)→drc_tattach_process(pid:pid_t, event_id:int, dbg_proc_flags:int)→drc_tdetach_process()→drc_tget_debapp_attrs(out_pattrs:debapp_attrs_t)→boolrebase_if_required_to(new_base:ida_idaapi.ea_t)→Nonerequest_pause()→drc_texit_process()→drc_tget_debug_event(event:debug_event_t, timeout_ms:int)→gdecode_tresume(event:debug_event_t)→drc_tset_backwards(backwards:bool)→drc_tset_exception_info(info:exception_info_t, qty:int)→Nonesuspended(dlls_added:bool, thr_names:thread_name_vec_t*=None)→Nonethread_suspend(tid:thid_t)→drc_tthread_continue(tid:thid_t)→drc_tset_resume_mode(tid:thid_t, resmod:resume_mode_t)→drc_tread_registers(tid:thid_t, clsmask:int, values:regval_t)→drc_twrite_register(tid:thid_t, regidx:int, value:regval_t)→drc_tthread_get_sreg_base(answer:ea_t*, tid:thid_t, sreg_value:int)→drc_tget_memory_info(ranges:meminfo_vec_t)→drc_tread_memory(nbytes:size_t*, ea:ida_idaapi.ea_t, buffer:void*, size:int)→drc_twrite_memory(nbytes:size_t*, ea:ida_idaapi.ea_t, buffer:voidconst*, size:int)→drc_tcheck_bpt(bptvc:int*, type:bpttype_t, ea:ida_idaapi.ea_t, len:int)→drc_tupdate_bpts(nbpts:int*, bpts:update_bpt_info_t*, nadd:int, ndel:int)→drc_tupdate_lowcnds(nupdated:int*, lowcnds:lowcnd_tconst*, nlowcnds:int)→drc_topen_file(file:str, fsize:uint64*, readonly:bool)→intclose_file(fn:int)→Noneread_file(fn:int, off:qoff64_t, buf:void*, size:int)→ssize_twrite_file(fn:int, off:qoff64_t, buf:voidconst*)→ssize_tmap_address(off:ida_idaapi.ea_t, regs:regval_t, regnum:int)→ida_idaapi.ea_tget_debmod_extensions()→voidconst*update_call_stack(tid:thid_t, trace:call_stack_t)→drc_tcleanup_appcall(tid:thid_t)→drc_teval_lowcnd(tid:thid_t, ea:ida_idaapi.ea_t)→drc_tsend_ioctl(fn:int, buf:voidconst*, poutbuf:void**, poutsize:ssize_t*)→drc_tdbg_enable_trace(tid:thid_t, enable:bool, trace_flags:int)→boolis_tracing_enabled(tid:thid_t, tracebit:int)→boolrexec(cmdline:str)→intget_srcinfo_path(path:str, base:ida_idaapi.ea_t)→boolbin_search(start_ea:ida_idaapi.ea_t, end_ea:ida_idaapi.ea_t, data:compiled_binpat_vec_tconst&, srch_flags:int)→drc_tget_dynamic_register_set(regset:dynamic_register_set_t*)→boolhave_set_options()→boolregisters
Array of registers. Use regs() to access it.
nregisters
Number of registers.
regclasses
Array of register class names.
bpt_bytes
A software breakpoint instruction.
ida_idd.DEBUGGER_ID_X86_IA32_WIN32_USER
Userland win32 processes (win32 debugging APIs)
ida_idd.DEBUGGER_ID_X86_IA32_LINUX_USER
Userland linux processes (ptrace())
ida_idd.DEBUGGER_ID_X86_IA32_MACOSX_USER
Userland MAC OS X processes.
ida_idd.DEBUGGER_ID_ARM_IPHONE_USER
iPhone 1.x
ida_idd.DEBUGGER_ID_X86_IA32_BOCHS
BochsDbg.exe 32.
ida_idd.DEBUGGER_ID_6811_EMULATOR
MC6812 emulator (beta)
ida_idd.DEBUGGER_ID_GDB_USER
GDB remote.
ida_idd.DEBUGGER_ID_WINDBG
WinDBG using Microsoft Debug engine.
ida_idd.DEBUGGER_ID_X86_DOSBOX_EMULATOR
Dosbox MS-DOS emulator.
ida_idd.DEBUGGER_ID_ARM_LINUX_USER
Userland arm linux.
ida_idd.DEBUGGER_ID_TRACE_REPLAYER
Fake debugger to replay recorded traces.
ida_idd.DEBUGGER_ID_X86_PIN_TRACER
PIN Tracer module.
ida_idd.DEBUGGER_ID_DALVIK_USER
Dalvik.
ida_idd.DEBUGGER_ID_XNU_USER
XNU Kernel.
ida_idd.DEBUGGER_ID_ARM_MACOS_USER
Userland arm MAC OS.
ida_idd.DBG_FLAG_REMOTE
Remote debugger (requires remote host name unless DBG_FLAG_NOHOST)
ida_idd.DBG_FLAG_NOHOST
Remote debugger with does not require network params (host/port/pass). (a unique device connected to the machine)
ida_idd.DBG_FLAG_FAKE_ATTACH
PROCESS_ATTACHED is a fake event and does not suspend the execution
ida_idd.DBG_FLAG_HWDATBPT_ONE
Hardware data breakpoints are one byte size by default
ida_idd.DBG_FLAG_CAN_CONT_BPT
Debugger knows to continue from a bpt. This flag also means that the debugger module hides breakpoints from ida upon read_memory
ida_idd.DBG_FLAG_NEEDPORT
Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)
ida_idd.DBG_FLAG_DONT_DISTURB
Debugger can handle only get_debug_event(), request_pause(), exit_process() when the debugged process is running. The kernel may also call service functions (file I/O, map_address, etc)
ida_idd.DBG_FLAG_SAFE
The debugger is safe (probably because it just emulates the application without really running it)
ida_idd.DBG_FLAG_CLEAN_EXIT
IDA must suspend the application and remove all breakpoints before terminating the application. Usually this is not required because the application memory disappears upon termination.
ida_idd.DBG_FLAG_USE_SREGS
Take segment register values into account (non flat memory)
ida_idd.DBG_FLAG_NOSTARTDIR
Debugger module doesn’t use startup directory.
ida_idd.DBG_FLAG_NOPARAMETERS
Debugger module doesn’t use commandline parameters.
ida_idd.DBG_FLAG_NOPASSWORD
Remote debugger doesn’t use password.
ida_idd.DBG_FLAG_CONNSTRING
Display “Connection string” instead of “Hostname” and hide the “Port” field.
ida_idd.DBG_FLAG_SMALLBLKS
If set, IDA uses 256-byte blocks for caching memory contents. Otherwise, 1024-byte blocks are used
ida_idd.DBG_FLAG_MANMEMINFO
If set, manual memory region manipulation commands will be available. Use this bit for debugger modules that cannot return memory layout information
ida_idd.DBG_FLAG_EXITSHOTOK
IDA may take a memory snapshot at PROCESS_EXITED event.
ida_idd.DBG_FLAG_VIRTHREADS
Thread IDs may be shuffled after each debug event. (to be used for virtual threads that represent cpus for windbg kmode)
ida_idd.DBG_FLAG_LOWCNDS
Low level breakpoint conditions are supported.
ida_idd.DBG_FLAG_DEBTHREAD
Supports creation of a separate thread in ida for the debugger (the debthread). Most debugger functions will be called from debthread (exceptions are marked below) The debugger module may directly call only THREAD_SAFE functions. To call other functions please use execute_sync(). The debthread significantly increases debugging speed, especially if debug events occur frequently.
ida_idd.DBG_FLAG_DEBUG_DLL
Can debug standalone DLLs. For example, Bochs debugger can debug any snippet of code
ida_idd.DBG_FLAG_FAKE_MEMORY
get_memory_info()/read_memory()/write_memory() work with the idb. (there is no real process to read from, as for the replayer module) the kernel will not call these functions if this flag is set. however, third party plugins may call them, they must be implemented.
ida_idd.DBG_FLAG_ANYSIZE_HWBPT
The debugger supports arbitrary size hardware breakpoints.
ida_idd.DBG_FLAG_TRACER_MODULE
The module is a tracer, not a full featured debugger module.
ida_idd.DBG_FLAG_PREFER_SWBPTS
Prefer to use software breakpoints.
ida_idd.DBG_FLAG_LAZY_WATCHPTS
Watchpoints are triggered before the offending instruction is executed. The debugger must temporarily disable the watchpoint and single-step before resuming.
ida_idd.DBG_FLAG_FAST_STEP
Do not refresh memory layout info after single stepping.
ida_idd.DBG_FLAG_ADD_ENVS
The debugger supports launching processes with environment variables.
ida_idd.DBG_FLAG_MERGE_ENVS
The debugger supports merge or replace setting for environment variables (only makes sense if DBG_FLAG_ADD_ENVS is set)
ida_idd.DBG_FLAG_DISABLE_ASLR
The debugger supports ASLR disabling (address space layout randomization)
ida_idd.DBG_FLAG_TTD
The debugger is a time travel debugger and supports continuing backwards.
ida_idd.DBG_FLAG_FULL_INSTR_BPT
Setting a breakpoint in the middle of an instruction will also break.
ida_idd.DBG_HAS_GET_PROCESSES
supports ev_get_processes
ida_idd.DBG_HAS_ATTACH_PROCESS
supports ev_attach_process
ida_idd.DBG_HAS_DETACH_PROCESS
supports ev_detach_process
ida_idd.DBG_HAS_REQUEST_PAUSE
supports ev_request_pause
ida_idd.DBG_HAS_SET_EXCEPTION_INFO
supports ev_set_exception_info
ida_idd.DBG_HAS_THREAD_SUSPEND
supports ev_thread_suspend
ida_idd.DBG_HAS_THREAD_CONTINUE
supports ev_thread_continue
ida_idd.DBG_HAS_SET_RESUME_MODE
supports ev_set_resume_mode. Cannot be set inside the debugger_t::init_debugger()
ida_idd.DBG_HAS_THREAD_GET_SREG_BASE
supports ev_thread_get_sreg_base
ida_idd.DBG_HAS_CHECK_BPT
supports ev_check_bpt
ida_idd.DBG_HAS_OPEN_FILE
supports ev_open_file, ev_close_file, ev_read_file, ev_write_file
ida_idd.DBG_HAS_UPDATE_CALL_STACK
supports ev_update_call_stack
ida_idd.DBG_HAS_APPCALL
supports ev_appcall, ev_cleanup_appcall
ida_idd.DBG_HAS_REXEC
supports ev_rexec
ida_idd.DBG_HAS_MAP_ADDRESS
supports ev_map_address. Avoid using this bit, especially together with DBG_FLAG_DEBTHREAD because it may cause big slow downs
ida_idd.DBG_RESMOD_STEP_INTO
RESMOD_INTO is available
ida_idd.DBG_RESMOD_STEP_OVER
RESMOD_OVER is available
ida_idd.DBG_RESMOD_STEP_OUT
RESMOD_OUT is available
ida_idd.DBG_RESMOD_STEP_SRCINTO
RESMOD_SRCINTO is available
ida_idd.DBG_RESMOD_STEP_SRCOVER
RESMOD_SRCOVER is available
ida_idd.DBG_RESMOD_STEP_SRCOUT
RESMOD_SRCOUT is available
ida_idd.DBG_RESMOD_STEP_USER
RESMOD_USER is available
ida_idd.DBG_RESMOD_STEP_HANDLE
RESMOD_HANDLE is available
ida_idd.DBG_RESMOD_STEP_BACKINTO
RESMOD_BACKINTO is available
ida_idd.DBG_PROC_IS_DLL
database contains a DLL (not EXE)
ida_idd.DBG_PROC_IS_GUI
using gui version of ida
ida_idd.DBG_PROC_32BIT
application is 32-bit
ida_idd.DBG_PROC_64BIT
application is 64-bit
ida_idd.DBG_NO_TRACE
do not trace the application (mac/linux)
ida_idd.DBG_HIDE_WINDOW
application should be hidden on startup (windows)
ida_idd.DBG_SUSPENDED
application should be suspended on startup (mac)
ida_idd.DBG_NO_ASLR
disable ASLR (linux)
ida_idd.BPT_OK
breakpoint can be set
ida_idd.BPT_INTERNAL_ERR
interr occurred when verifying breakpoint
ida_idd.BPT_BAD_TYPE
bpt type is not supported
ida_idd.BPT_BAD_ALIGN
alignment is invalid
ida_idd.BPT_BAD_ADDR
ea is invalid
ida_idd.BPT_BAD_LEN
bpt len is invalid
ida_idd.BPT_TOO_MANY
reached max number of supported breakpoints
ida_idd.BPT_READ_ERROR
failed to read memory at bpt ea
ida_idd.BPT_WRITE_ERROR
failed to write memory at bpt ea
ida_idd.BPT_SKIP
update_bpts(): do not process bpt
ida_idd.BPT_PAGE_OK
update_bpts(): ok, added a page bpt
ida_idd.APPCALL_MANUAL
Only set up the appcall, do not run. debugger_t::cleanup_appcall will not be generated by ida!
ida_idd.APPCALL_DEBEV
Return debug event information.
ida_idd.APPCALL_TIMEOUT
Appcall with timeout. If timed out, errbuf will contain “timeout”. See SET_APPCALL_TIMEOUT and GET_APPCALL_TIMEOUT
ida_idd.RQ_MASKING
masking step handler: unless errors, tmpbpt handlers won’t be generated should be used only with request_internal_step()
ida_idd.RQ_SUSPEND
suspending step handler: suspends the app handle_debug_event: suspends the app
ida_idd.RQ_NOSUSP
running step handler: continues the app
ida_idd.RQ_IGNWERR
ignore breakpoint write failures
ida_idd.RQ_SILENT
all: no dialog boxes
ida_idd.RQ_VERBOSE
all: display dialog boxes
ida_idd.RQ_SWSCREEN
handle_debug_event: switch screens
ida_idd.RQ__NOTHRRF
handle_debug_event: do not refresh threads
ida_idd.RQ_PROCEXIT
snapshots: the process is exiting
ida_idd.RQ_IDAIDLE
handle_debug_event: ida is idle
ida_idd.RQ_SUSPRUN
handle_debug_event: suspend at PROCESS_STARTED
ida_idd.RQ_RESUME
handle_debug_event: resume application
ida_idd.RQ_RESMOD
resume_mode_t
ida_idd.RQ_RESMOD_SHIFTida_idd.cpu2ieee(ieee_out:fpvalue_t*, cpu_fpval:voidconst*, size:int)→int
Convert a floating point number in CPU native format to IDA’s internal format.
Parameters:

-
ieee_out – output buffer

-
cpu_fpval – floating point number in CPU native format

-
size – size of cpu_fpval in bytes (size of the input buffer)

Returns:
Floating point/IEEE Conversion codes
ida_idd.ieee2cpu(cpu_fpval_out:void*, ieee:fpvalue_tconst&, size:int)→int
Convert a floating point number in IDA’s internal format to CPU native format.
Parameters:

-
cpu_fpval_out – output buffer

-
ieee – floating point number of IDA’s internal format

-
size – size of cpu_fpval in bytes (size of the output buffer)

Returns:
Floating point/IEEE Conversion codes
classida_idd.dyn_register_info_array(_data:register_info_t, _count:int)
Bases: `object`
thisowndata:register_info_t*count:intida_idd.get_dbg()→debugger_t*ida_idd.dbg_get_registers()
This function returns the register definition from the currently loaded debugger. Basically, it returns an array of structure similar to to idd.hpp / register_info_t
Returns:
None if no debugger is loaded
Returns:
tuple(name, flags, class, dtype, bit_strings, default_bit_strings_mask) The bit_strings can be a tuple of strings or None (if the register does not have bit_strings)
ida_idd.dbg_get_thread_sreg_base(tid, sreg_value)
Returns the segment register base value
Parameters:

-
tid – thread id

-
sreg_value – segment register (selector) value

Returns:
The base as an ‘ea’, or None on failure
ida_idd.dbg_read_memory(ea, sz)
Reads from the debugee’s memory at the specified ea
Parameters:

-
ea – the debuggee’s memory address

-
sz – the amount of data to read

Returns:
The read buffer (as bytes), or None on failure
ida_idd.dbg_write_memory(ea, buffer)
Writes a buffer to the debugee’s memory
Parameters:

-
ea – the debuggee’s memory address

-
buf – a bytes object to write

Returns:
Boolean
ida_idd.dbg_get_name()
This function returns the current debugger’s name.
Returns:
Debugger name or None if no debugger is active
ida_idd.dbg_get_memory_info()
This function returns the memory configuration of a debugged process.
Returns:
tuple(start_ea, end_ea, name, sclass, sbase, bitness, perm), or None if no debugger is active
ida_idd.appcall(func_ea:ida_idaapi.ea_t, tid:thid_t, _type_or_none:bytevec_tconst&, _fields:bytevec_tconst&, arg_list:PyObject*)→PyObject*ida_idd.get_event_module_name(ev:debug_event_t)→strida_idd.get_event_module_base(ev:debug_event_t)→ida_idaapi.ea_tida_idd.get_event_module_size(ev:debug_event_t)→asize_tida_idd.get_event_exc_info(ev:debug_event_t)→strida_idd.get_event_info(ev:debug_event_t)→strida_idd.get_event_bpt_hea(ev:debug_event_t)→ida_idaapi.ea_tida_idd.get_event_exc_code(ev:debug_event_t)→uintida_idd.get_event_exc_ea(ev:debug_event_t)→ida_idaapi.ea_tida_idd.can_exc_continue(ev:debug_event_t)→boolida_idd.NO_PROCESS=4294967295
No process.
ida_idd.NO_THREAD=0
No thread. in PROCESS_STARTED this value can be used to specify that the main thread has not been created. It will be initialized later by a THREAD_STARTED event.
ida_idd.dbg_can_queryclassida_idd.Appcall_array__(tp)
Bases: `object`

This class is used with Appcall.array() method
pack(L)
Packs a list or tuple into a byref buffer
try_to_convert_to_list(obj)
Is this object a list? We check for the existance of attribute zero and attribute self.size-1
unpack(buf, as_list=True)
Unpacks an array back into a list or an object
classida_idd.Appcall_callable__(ea, tinfo_or_typestr=None, fields=None)
Bases: `object`
Helper class to issue appcalls using a natural syntax:
appcall.FunctionNameInTheDatabase(arguments, ….)
or
appcall[“Function@8”](arguments, …)
or
f8 = appcall[“Function@8”] f8(arg1, arg2, …)
or
o = appcall.obj() i = byref(5) appcall.funcname(arg1, i, “hello”, o)
timeout
An Appcall instance can change its timeout value with this attribute
options
Sets the Appcall options locally to this Appcall instance
ea
Returns or sets the EA associated with this object
tif
Returns the tinfo_t object
size
Returns the size of the type
type
Returns the typestring
fields
Returns the field names
retrieve(src=None, flags=0)
Unpacks a typed object from the database if an ea is given or from a string if a string was passed :param src: the address of the object or a string :returns: Returns a tuple of boolean and object or error number (Bool, Error | Object).
store(obj, dest_ea=None, base_ea=0, flags=0)
Packs an object into a given ea if provided or into a string if no address was passed. :param obj: The object to pack :param dest_ea: If packing to idb this will be the store location :param base_ea: If packing to a buffer, this will be the base that will be used to relocate the pointers
Returns:
Tuple(Boolean, packed_string or error code) if packing to a string
Returns:
a return code is returned (0 indicating success) if packing to the database
classida_idd.Appcall_consts__(default=None)
Bases: `object`

Helper class used by Appcall.Consts attribute It is used to retrieve constants via attribute access
classida_idd.Appcall__
Bases: `object`
APPCALL_MANUAL=1
Only set up the appcall, do not run. debugger_t::cleanup_appcall will not be generated by ida!
APPCALL_DEBEV=2
Return debug event information.
APPCALL_TIMEOUT=4
Appcall with timeout. If timed out, errbuf will contain “timeout”. See SET_APPCALL_TIMEOUT and GET_APPCALL_TIMEOUT
Consts
Use Appcall.Consts.CONST_NAME to access constants
staticproto(name_or_ea, proto_or_tinfo, flags=None)
Allows you to instantiate an appcall (callable object) with the desired prototype :param name_or_ea: The name of the function (will be resolved with LocByName()) :param proto_or_tinfo: function prototype as a string or type of the function as tinfo_t object :returns: a callbable Appcall instance with the given prototypes and flags, or

an exception if the prototype could not be parsed or the address is not resolvable.

staticvalueof(name, default=0)
If the name could not be resolved then the default value will be returned
Returns:
the numeric value of a given name string.
staticint64(v)
Whenever a 64bit number is needed use this method to construct an object
staticbyref(val)
Method to create references to immutable objects Currently we support references to int/strings Objects need not be passed by reference (this will be done automatically)
staticbuffer(str=None, size=0, fill='\x00')
Creates a string buffer. The returned value (r) will be a byref object. Use r.value to get the contents and r.size to get the buffer’s size
staticobj(**kwds)
Returns an empty object or objects with attributes as passed via its keywords arguments
staticcstr(val)staticUTF16(s)unicodestaticarray(type_name)
Defines an array type. Later you need to pack() / unpack()
statictypedobj(typedecl_or_tinfo, ea=None)
Returns an appcall object for a type (can be given as tinfo_t object or as a string declaration) One can then use retrieve() member method :param ea: Optional parameter that later can be used to retrieve the type :returns: Appcall object or raises ValueError exception
staticset_appcall_options(opt)
Method to change the Appcall options globally (not per Appcall)
staticget_appcall_options()
Return the global Appcall options
staticcleanup_appcall(tid=0)
Cleanup after manual appcall.
Parameters:
tid – thread to use. NO_THREAD means to use the current thread The application state is restored as it was before calling the last appcall(). Nested appcalls are supported.
Returns:
eOk if successful, otherwise an error code
ida_idd.Appcall
