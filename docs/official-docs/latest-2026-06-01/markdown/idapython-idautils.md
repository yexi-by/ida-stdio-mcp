# IDAPython utility iterators

- 官方来源：https://python.docs.hex-rays.com/idautils/index.html

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
- idautils
- View page source

# idautils

idautils.py - High level utility functions for IDA

## Attributes

`GetInputFileMD5`
 |

`cpu`
 |
This is a special class instance used to access the registers as if they were attributes of this object.

`procregs`
 |
This object is used to access the processor registers. It is useful when decoding instructions and you want to see which instruction is which.

## Classes

`Strings`
 |
Allows iterating over the string list. The set of strings will not be

`peutils_t`
 |
PE utility class. Retrieves PE information from the database.

## Functions

`CodeRefsTo`(ea, flow)
 |
Get a list of code references to 'ea'

`CodeRefsFrom`(ea, flow)
 |
Get a list of code references from 'ea'

`DataRefsTo`(ea)
 |
Get a list of data references to 'ea'

`DataRefsFrom`(ea)
 |
Get a list of data references from 'ea'

`XrefTypeName`(typecode)
 |
Convert cross-reference type codes to readable names

`XrefsFrom`(ea[, flags])
 |
Return all references from address 'ea'

`XrefsTo`(ea[, flags])
 |
Return all references to address 'ea'

`Threads`()
 |
Returns all thread IDs for the current debugee

`Heads`([start, end])
 |
Get a list of heads (instructions or data items)

`Functions`([start, end])
 |
Get a list of functions

`Chunks`(start)
 |
Get a list of function chunks

`Modules`()
 |
Returns a list of module objects with name,size,base and the rebase_to attributes

`Names`()
 |
Returns a list of names

`Segments`()
 |
Get list of segments (sections) in the binary image

`Entries`()
 |
Returns a list of entry points (exports)

`FuncItems`(start)
 |
Get a list of function items (instruction or data items inside function boundaries)

`Structs`()
 |
Get a list of structures

`StructMembers`(sid)
 |
Get a list of structure members information (or stack vars if given a frame).

`DecodePrecedingInstruction`(ea)
 |
Decode preceding instruction in the execution flow.

`DecodePreviousInstruction`(ea)
 |
Decodes the previous instruction and returns an insn_t like class

`DecodeInstruction`(ea)
 |
Decodes an instruction and returns an insn_t like class

`GetDataList`(ea, count[, itemsize])
 |
Get data list - INTERNAL USE ONLY

`PutDataList`(ea, datalist[, itemsize])
 |
Put data list - INTERNAL USE ONLY

`MapDataList`(ea, length, func[, wordsize])
 |
Map through a list of data words in the database

`GetIdbDir`()
 |
Get IDB directory

`GetRegisterList`()
 |
Returns the register list

`GetInstructionList`()
 |
Returns the instruction list of the current processor module

`Assemble`(ea, line)
 |
Assembles one or more lines (does not display an message dialogs)

`ProcessUiActions`(actions[, flags])
 |

## Module Contents

idautils.CodeRefsTo(ea, flow:bool)
Get a list of code references to ‘ea’
Parameters:

-
ea – Target address

-
flow – Follow normal code flow or not

Returns:
list of references (may be empty list)

Example:

```text
for ref in CodeRefsTo(get_screen_ea(), 1):
 print(ref)

```

idautils.CodeRefsFrom(ea, flow:bool)
Get a list of code references from ‘ea’
Parameters:

-
ea – Target address

-
flow – Follow normal code flow or not

Returns:
list of references (may be empty list)

Example:

```text
for ref in CodeRefsFrom(get_screen_ea(), 1):
 print(ref)

```

idautils.DataRefsTo(ea)
Get a list of data references to ‘ea’
Parameters:
ea – Target address
Returns:
list of references (may be empty list)

Example:

```text
for ref in DataRefsTo(get_screen_ea()):
 print(ref)

```

idautils.DataRefsFrom(ea)
Get a list of data references from ‘ea’
Parameters:
ea – Target address
Returns:
list of references (may be empty list)

Example:

```text
for ref in DataRefsFrom(get_screen_ea()):
 print(ref)

```

idautils.XrefTypeName(typecode)
Convert cross-reference type codes to readable names
Parameters:
typecode – cross-reference type code
idautils.XrefsFrom(ea, flags=0)
Return all references from address ‘ea’
Parameters:

-
ea – Reference address

-
flags – one of ida_xref.XREF_ALL (default), ida_xref.XREF_FAR, ida_xref.XREF_DATA

Example::for xref in XrefsFrom(here(), 0):
print(xref.type, XrefTypeName(xref.type), ‘from’, hex(xref.frm), ‘to’, hex(xref.to))
idautils.XrefsTo(ea, flags=0)
Return all references to address ‘ea’
Parameters:

-
ea – Reference address

-
flags – one of ida_xref.XREF_ALL (default), ida_xref.XREF_FAR, ida_xref.XREF_DATA

Example::for xref in XrefsTo(here(), 0):
print(xref.type, XrefTypeName(xref.type), ‘from’, hex(xref.frm), ‘to’, hex(xref.to))
idautils.Threads()
Returns all thread IDs for the current debugee
idautils.Heads(start=None, end=None)
Get a list of heads (instructions or data items)
Parameters:

-
start – start address (default: inf.min_ea)

-
end – end address (default: inf.max_ea)

Returns:
list of heads between start and end
idautils.Functions(start=None, end=None)
Get a list of functions
Parameters:

-
start – start address (default: inf.min_ea)

-
end – end address (default: inf.max_ea)

Returns:
list of function entrypoints between start and end

NOTE: The last function that starts before ‘end’ is included even if it extends beyond ‘end’. Any function that has its chunks scattered in multiple segments will be reported multiple times, once in each segment as they are listed.
idautils.Chunks(start)
Get a list of function chunks See also ida_funcs.func_tail_iterator_t
Parameters:
start – address of the function
Returns:
list of function chunks (tuples of the form (start_ea, end_ea)) belonging to the function
idautils.Modules()
Returns a list of module objects with name,size,base and the rebase_to attributes
idautils.Names()
Returns a list of names
Returns:
List of tuples (ea, name)
idautils.Segments()
Get list of segments (sections) in the binary image
Returns:
List of segment start addresses.
idautils.Entries()
Returns a list of entry points (exports)
Returns:
List of tuples (index, ordinal, ea, name)
idautils.FuncItems(start)
Get a list of function items (instruction or data items inside function boundaries) See also ida_funcs.func_item_iterator_t
Parameters:
start – address of the function
Returns:
ea of each item in the function
idautils.Structs()
Get a list of structures
Returns:
List of tuples (ordinal, sid, name)
idautils.StructMembers(sid)
Get a list of structure members information (or stack vars if given a frame).
Parameters:
sid – ID of the structure.
Returns:
List of tuples (offset_in_bytes, name, size_in_bytes)

NOTE: If ‘sid’ does not refer to a valid structure, an exception will be raised. NOTE: This will not return ‘holes’ in structures/stack frames; it only returns defined structure members.
idautils.DecodePrecedingInstruction(ea)
Decode preceding instruction in the execution flow.
Parameters:
ea – address to decode
Returns:
(None or the decode instruction, farref) farref will contain ‘true’ if followed an xref, false otherwise
idautils.DecodePreviousInstruction(ea)
Decodes the previous instruction and returns an insn_t like class
Parameters:
ea – address to decode
Returns:
None or a new insn_t instance
idautils.DecodeInstruction(ea)
Decodes an instruction and returns an insn_t like class
Parameters:
ea – address to decode
Returns:
None or a new insn_t instance
idautils.GetDataList(ea, count, itemsize=1)
Get data list - INTERNAL USE ONLY
idautils.PutDataList(ea, datalist, itemsize=1)
Put data list - INTERNAL USE ONLY
idautils.MapDataList(ea, length, func, wordsize=1)
Map through a list of data words in the database
Parameters:

-
ea – start address

-
length – number of words to map

-
func – mapping function

-
wordsize – size of words to map [default: 1 byte]

Returns:
None
idautils.GetInputFileMD5classidautils.Strings(default_setup=False)
Bases: `object`

Allows iterating over the string list. The set of strings will not be modified, unless asked explicitly at setup()-time. This string list also is used by the “String window” so it may be changed when this window is updated.
Example:
s = Strings()
for i in s:
print(“%x: len=%d type=%d -> ‘%s’” % (i.ea, i.length, i.strtype, str(i)))
classStringItem(si)
Bases: `object`

Class representing each string item.
ea
String ea
strtype
string type (STRTYPE_xxxxx)
length
string length
is_1_byte_encoding()clear_cache()
Clears the string list cache
size=0refresh()
Refreshes the string list
setup(strtypes=[ida_nalt.STRTYPE_C], minlen=5, only_7bit=True, ignore_instructions=False, display_only_existing_strings=False)idautils.GetIdbDir()
Get IDB directory

This function returns directory path of the current IDB database
idautils.GetRegisterList()
Returns the register list
idautils.GetInstructionList()
Returns the instruction list of the current processor module
idautils.Assemble(ea, line)
Assembles one or more lines (does not display an message dialogs) If line is a list then this function will attempt to assemble all the lines This function will turn on batch mode temporarily so that no messages are displayed on the screen
Parameters:
ea – start address
Returns:
(False, “Error message”) or (True, asm_buf) or (True, [asm_buf1, asm_buf2, asm_buf3])
idautils.ProcessUiActions(actions, flags=0)Parameters:

-
actions – A string containing a list of actions separated by semicolon, a list or a tuple

-
flags – flags to be passed to process_ui_action()

Returns:
Boolean. Returns False if the action list was empty or execute_ui_requests() failed.
classidautils.peutils_t
Bases: `object`

PE utility class. Retrieves PE information from the database.

Constants from pe.h
PE_NODE='$PEheader'PE_ALT_DBG_FPOSPE_ALT_IMAGEBASEPE_ALT_PEHDR_OFFPE_ALT_NEFLAGSPE_ALT_TDS_LOADEDPE_ALT_PSXDLLimagebase
Loading address (usually pe.imagebase)
header_offset
Offset of PE header
header
Returns the complete PE header as an instance of peheader_t (defined in the SDK).
idautils.cpu
This is a special class instance used to access the registers as if they were attributes of this object. For example to access the EAX register:

print(“%x” % cpu.Eax)

idautils.procregs
This object is used to access the processor registers. It is useful when decoding instructions and you want to see which instruction is which. For example:

x = idautils.DecodeInstruction(here()) if x[0] == procregs.Esp:

print(“This operand is the register ESP)
