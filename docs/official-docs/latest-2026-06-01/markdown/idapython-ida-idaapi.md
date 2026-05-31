# IDAPython core constants/API

- 官方来源：https://python.docs.hex-rays.com/ida_idaapi/index.html

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
- ida_idaapi
- View page source

# ida_idaapi

## Attributes

`BADADDR`
|

`BADADDR32`
|

`BADADDR64`
|

`BADSEL`
|

`SIZE_MAX`
|

`ea_t`
|

`integer_types`
|

`SEEK_SET`
|

`SEEK_CUR`
|

`SEEK_END`
|

`PLUGIN_MOD`
|

`PLUGIN_DRAW`
|

`PLUGIN_SEG`
|

`PLUGIN_UNL`
|

`PLUGIN_HIDE`
|

`PLUGIN_DBG`
|

`PLUGIN_PROC`
|

`PLUGIN_FIX`
|

`PLUGIN_MULTI`
|

`PLUGIN_SKIP`
|

`PLUGIN_OK`
|

`PLUGIN_KEEP`
|

`PY_ICID_INT64`
|
int64 object

`PY_ICID_BYREF`
|
byref object

`PY_ICID_OPAQUE`
|
opaque object

`ST_OVER_DEBUG_SEG`
|
step tracing will be disabled when IP is in a debugger segment

`ST_OVER_LIB_FUNC`
|
step tracing will be disabled when IP is in a library function

`as_unicode`
|

`IDAPython_Completion`
|

`NW_OPENIDB`
|
Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)

`NW_CLOSEIDB`
|
Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)

`NW_INITIDA`
|
Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)

`NW_TERMIDA`
|
Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)

`NW_REMOVE`
|
Use this flag with other flags to uninstall a notifywhen callback

`HBF_CALL_WITH_NEW_EXEC`
|

`HBF_VOLATILE_METHOD_SET`
|

## Classes

`pyidc_opaque_object_t`
|
This is the base class for all PythonIDC opaque objects

`py_clinked_object_t`
|
This is a utility and base class for C linked objects

`object_t`
|
Helper class used to initialize empty objects

`plugin_t`
|
Base class for all scripted plugins.

`plugmod_t`
|
Base class for all scripted multi-plugins.

`pyidc_cvt_helper__`
|
This is a special helper object that helps detect which kind

`PyIdc_cvt_int64__`
|
Helper class for explicitly representing VT_INT64 values

`PyIdc_cvt_refclass__`
|
Helper class for representing references to immutable objects

`IDAPython_displayhook`
|

`loader_input_t`
|
A helper class to work with linput_t related functions.

## Functions

`require`(modulename[, package])
|
Load, or reload a module.

`replfun`(func)
|

`as_cstr`(val)
|
Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())

`as_UTF16`(s)
|
Convenience function to convert a string into appropriate unicode format

`as_uint32`(v)
|
Returns a number as an unsigned int32 number

`as_int32`(v)
|
Returns a number as a signed int32 number

`as_signed`(v[, nbits])
|
Returns a number as signed. The number of bits are specified by the user.

`TRUNC`(ea)
|
Truncate EA for the current application bitness

`copy_bits`(v, s[, e])
|
Copy bits from a value

`struct_unpack`(buffer[, signed, offs])
|
Unpack a buffer given its length and offset using struct.unpack_from().

`IDAPython_ExecSystem`(cmd)
|
Executes a command with popen().

`IDAPython_FormatExc`(etype[, value, tb, limit])
|
This function is used to format an exception given the

`IDAPython_ExecScript`(path, g[, print_error, script_args])
|
Run the specified script.

`IDAPython_LoadProcMod`(path, g[, print_error])
|
Load processor module.

`IDAPython_UnLoadProcMod`(script, g[, print_error])
|
Unload processor module.

`IDAPython_GetDocstrings`(obj)
|

`notify_when`(when, callback)
|
Register a callback that will be called when an event happens.

`parse_command_line3`(→ PyObject *)
|

`set_script_timeout`(timeout)
|
Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.

`disable_script_timeout`()
|
Disables the script timeout and hides the script wait box.

`enable_extlang_python`(enable)
|
Enables or disables Python extlang.

`enable_python_cli`(→ None)
|

`format_basestring`(→ str)
|

`pygc_refresh`(→ None)
|

`pygc_create_groups`(→ PyObject *)
|

`pygc_delete_groups`(→ PyObject *)
|

`pygc_set_groups_visibility`(→ PyObject *)
|

`pycim_get_widget`(→ TWidget *)
|

`pycim_view_close`(→ None)
|

## Module Contents

ida_idaapi.BADADDRida_idaapi.BADADDR32ida_idaapi.BADADDR64ida_idaapi.BADSELida_idaapi.SIZE_MAXida_idaapi.ea_tida_idaapi.integer_typesida_idaapi.require(modulename, package=None)
Load, or reload a module.

When under heavy development, a user’s tool might consist of multiple modules. If those are imported using the standard ‘import’ mechanism, there is no guarantee that the Python implementation will re-read and re-evaluate the module’s Python code. In fact, it usually doesn’t. What should be done instead is ‘reload()’-ing that module.

This is a simple helper function that will do just that: In case the module doesn’t exist, it ‘import’s it, and if it does exist, ‘reload()’s it.

The importing module (i.e., the module calling require()) will have the loaded module bound to its globals(), under the name ‘modulename’. (If require() is called from the command line, the importing module will be ‘__main__’.)

For more information, see: .
ida_idaapi.replfun(func)ida_idaapi.SEEK_SET=0ida_idaapi.SEEK_CUR=1ida_idaapi.SEEK_END=2ida_idaapi.PLUGIN_MOD=1ida_idaapi.PLUGIN_DRAW=2ida_idaapi.PLUGIN_SEG=4ida_idaapi.PLUGIN_UNL=8ida_idaapi.PLUGIN_HIDE=16ida_idaapi.PLUGIN_DBG=32ida_idaapi.PLUGIN_PROC=64ida_idaapi.PLUGIN_FIX=128ida_idaapi.PLUGIN_MULTI=256ida_idaapi.PLUGIN_SKIP=0ida_idaapi.PLUGIN_OK=1ida_idaapi.PLUGIN_KEEP=2ida_idaapi.PY_ICID_INT64=0
int64 object
ida_idaapi.PY_ICID_BYREF=1
byref object
ida_idaapi.PY_ICID_OPAQUE=2
opaque object
ida_idaapi.ST_OVER_DEBUG_SEG=1
step tracing will be disabled when IP is in a debugger segment
ida_idaapi.ST_OVER_LIB_FUNC=2
step tracing will be disabled when IP is in a library function
classida_idaapi.pyidc_opaque_object_t
Bases: `object`

This is the base class for all PythonIDC opaque objects
classida_idaapi.py_clinked_object_t(lnk=None)
Bases: `pyidc_opaque_object_t`

This is a utility and base class for C linked objects
copy()
Returns a new copy of this class
assign(other)
Overwrite me. This method allows you to assign an instance contents to anothers :returns: Boolean
clink
Returns the C link as a PyObject
clink_ptr
Returns the C link pointer as a number
classida_idaapi.object_t(**kwds)
Bases: `object`

Helper class used to initialize empty objects
classida_idaapi.plugin_t
Bases: `pyidc_opaque_object_t`

Base class for all scripted plugins.
run(arg)term()classida_idaapi.plugmod_t
Bases: `pyidc_opaque_object_t`

Base class for all scripted multi-plugins.
classida_idaapi.pyidc_cvt_helper__(cvt_id, value)
Bases: `object`

This is a special helper object that helps detect which kind of object is this python object wrapping and how to convert it back and from IDC. This object is characterized by its special attribute and its value
valueclassida_idaapi.PyIdc_cvt_int64__(v)
Bases: `pyidc_cvt_helper__`

Helper class for explicitly representing VT_INT64 values
classida_idaapi.PyIdc_cvt_refclass__(v)
Bases: `pyidc_cvt_helper__`

Helper class for representing references to immutable objects
cstr()
Returns the string as a C string (up to the zero termination)
ida_idaapi.as_cstr(val)
Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref()) It scans for the first x00 and returns the string value up to that point.
ida_idaapi.as_UTF16(s)
Convenience function to convert a string into appropriate unicode format
ida_idaapi.as_unicodeida_idaapi.as_uint32(v)
Returns a number as an unsigned int32 number
ida_idaapi.as_int32(v)
Returns a number as a signed int32 number
ida_idaapi.as_signed(v, nbits=32)
Returns a number as signed. The number of bits are specified by the user. The MSB holds the sign.
ida_idaapi.TRUNC(ea)
Truncate EA for the current application bitness
ida_idaapi.copy_bits(v, s, e=-1)
Copy bits from a value :param v: the value :param s: starting bit (0-based) :param e: ending bit
ida_idaapi.struct_unpack(buffer, signed=False, offs=0)
Unpack a buffer given its length and offset using struct.unpack_from(). This function will know how to unpack the given buffer by using the lookup table ‘__struct_unpack_table’ If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.
ida_idaapi.IDAPython_ExecSystem(cmd)
Executes a command with popen().
ida_idaapi.IDAPython_FormatExc(etype, value=None, tb=None, limit=None)
This function is used to format an exception given the values returned by a PyErr_Fetch()
ida_idaapi.IDAPython_ExecScript(path, g, print_error=True, script_args=None)
Run the specified script.

This function is used by the low-level plugin code.
ida_idaapi.IDAPython_LoadProcMod(path, g, print_error=True)
Load processor module.
ida_idaapi.IDAPython_UnLoadProcMod(script, g, print_error=True)
Unload processor module.
ida_idaapi.IDAPython_GetDocstrings(obj)ida_idaapi.IDAPython_Completionida_idaapi.NW_OPENIDB=1
Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)
ida_idaapi.NW_CLOSEIDB=2
Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)
ida_idaapi.NW_INITIDA=4
Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)
ida_idaapi.NW_TERMIDA=8
Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)
ida_idaapi.NW_REMOVE=16
Use this flag with other flags to uninstall a notifywhen callback
ida_idaapi.notify_when(when, callback)
Register a callback that will be called when an event happens. :param when: one of NW_XXXX constants :param callback: This callback prototype varies depending on the ‘when’ parameter:

The general callback format:
def notify_when_callback(nw_code)
In the case of NW_OPENIDB:
def notify_when_callback(nw_code, is_old_database)

Returns:
Boolean
classida_idaapi.IDAPython_displayhookorig_displayhookformat_seq(num_printer, storage, item, opn, cls)format_item(num_printer, storage, item)displayhook_format(item)displayhook(item)ida_idaapi.HBF_CALL_WITH_NEW_EXECida_idaapi.HBF_VOLATILE_METHOD_SETida_idaapi.parse_command_line3(cmdline:str)→PyObject*ida_idaapi.set_script_timeout(timeout)
Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses. See also L{disable_script_timeout}.
Parameters:
timeout – This value is in seconds. If this value is set to zero then the script will never timeout.
Returns:
Returns the old timeout value
ida_idaapi.disable_script_timeout()
Disables the script timeout and hides the script wait box. Calling L{set_script_timeout} will not have any effects until the script is compiled and executed again
Returns:
None
ida_idaapi.enable_extlang_python(enable)
Enables or disables Python extlang. When enabled, all expressions will be evaluated by Python.
Parameters:
enable – Set to True to enable, False otherwise
ida_idaapi.enable_python_cli(enable:bool)→Noneida_idaapi.format_basestring(_in:PyObject*)→strida_idaapi.pygc_refresh(_self:PyObject*)→Noneida_idaapi.pygc_create_groups(_self:PyObject*, groups_infos:PyObject*)→PyObject*ida_idaapi.pygc_delete_groups(_self:PyObject*, groups:PyObject*, new_current:PyObject*)→PyObject*ida_idaapi.pygc_set_groups_visibility(_self:PyObject*, groups:PyObject*, expand:PyObject*, new_current:PyObject*)→PyObject*ida_idaapi.pycim_get_widget(_self:PyObject*)→TWidget*ida_idaapi.pycim_view_close(_self:PyObject*)→Noneclassida_idaapi.loader_input_t(pycapsule=None)
Bases: `object`

A helper class to work with linput_t related functions. This class is also used by file loaders scripts.
thisownclose()
Closes the file
open(filename, remote=False)
Opens a file (or a remote file)
Parameters:

-
filename – the file name

-
remote – whether the file is local, or remote

Returns:
Boolean
set_linput(linput)
Links the current loader_input_t instance to a linput_t instance
Parameters:
linput – the linput_t to link to
staticfrom_linput(linput:linput_t*)→loader_input_t*staticfrom_capsule(pycapsule:PyObject*)→loader_input_t*staticfrom_fp(fp)
A static method to construct an instance from a FILE*
Parameters:
fp – a FILE pointer
Returns:
a new instance, or None
get_linput()→linput_t*open_memory(start:ea_t, size:int)
Create a linput for process memory (By internally calling idaapi.create_memory_linput()) This linput will use dbg->read_memory() to read data
Parameters:

-
start – starting address of the input

-
size – size of the memory range to represent as linput if unknown, may be passed as 0

seek(offset:int, whence=SEEK_SET)
Set input source position
Parameters:

-
offset – the seek offset

-
whence – the position to seek from

Returns:
the new position (not 0 as fseek!)
tell()
Returns the current position
getz(size:int, fpos:int=-1)
Returns a zero terminated string at the given position
Parameters:

-
size – maximum size of the string

-
fpos – if != -1 then seek will be performed before reading

Returns:
The string or None on failure.
gets(len:int)
Reads a line from the input file. Returns the read line or None
Parameters:
len – the maximum line length
Returns:
a str, or None
read(size:int=-1)
Read up to size bytes (all data if size is negative). Return an empty bytes object on EOF.
Parameters:
size – the maximum number of bytes to read
Returns:
a bytes object
opened()
Checks if the file is opened or not
readbytes(size:int, big_endian:bool)
Similar to read() but it respect the endianness
Parameters:

-
size – the maximum number of bytes to read

-
big_endian – endianness

Returns:
a str, or None
file2base(pos:int, ea1:ea_t, ea2:ea_t, patchable:bool)
Load portion of file into the database This function will include (ea1..ea2) into the addressing space of the program (make it enabled)
Parameters:

-
li – pointer ot input source

-
pos – position in the file

-
ea1 – start of range of destination linear addresses

-
ea2 – end of range of destination linear addresses

-
patchable – should the kernel remember correspondance of file offsets to linear addresses.

Returns:
1-ok,0-read error, a warning is displayed
size()→int64filename()→PyObject*get_byte()
Reads a single byte from the file. Returns None if EOF or the read byte
