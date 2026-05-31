# IDAPython database loader/save API

- 官方来源：https://python.docs.hex-rays.com/ida_loader/index.html

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
- ida_loader
- View page source

# ida_loader

Definitions of IDP, LDR, PLUGIN module interfaces.

This file also contains: * functions to load files into the database * functions to generate output files * high level functions to work with the database (open, save, close)

The LDR interface consists of one structure: loader_t The IDP interface consists of one structure: processor_t The PLUGIN interface consists of one structure: plugin_t Modules can’t use standard FILE* functions. They must use functions from Modules can’t use standard memory allocation functions. They must use functions from The exported entry #1 in the module should point to the appropriate structure. (loader_t for LDR module, for example)

## Attributes

`LDRF_RELOAD`
|
loader recognizes NEF_RELOAD flag

`LDRF_REQ_PROC`
|
Requires a processor to be set. if this bit is not set, load_file() must call set_processor_type(..., SETPROC_LOADER)

`ACCEPT_ARCHIVE`
|
Specify that a file format is served by archive loader See loader_t::accept_file

`ACCEPT_CONTINUE`
|
Specify that the function must be called another time See loader_t::accept_file

`ACCEPT_FIRST`
|
Specify that a file format should be place first in "load file" dialog box. See loader_t::accept_file

`NEF_SEGS`
|
Create segments.

`NEF_RSCS`
|
Load resources.

`NEF_NAME`
|
Rename entries.

`NEF_MAN`
|
Manual load.

`NEF_FILL`
|
Fill segment gaps.

`NEF_IMPS`
|
Create import segment.

`NEF_FIRST`
|
This is the first file loaded into the database.

`NEF_CODE`
|
for load_binary_file(): load as a code segment

`NEF_RELOAD`
|
reload the file at the same place:

`NEF_FLAT`
|
Autocreate FLAT group (PE)

`NEF_MINI`
|
Create mini database (do not copy segment bytes from the input file; use only the file header metadata)

`NEF_LOPT`
|
Display additional loader options dialog.

`NEF_LALL`
|
Load all segments without questions.

`DLLEXT`
|

`LOADER_DLL`
|

`OFILE_MAP`
|
MAP file.

`OFILE_EXE`
|
Executable file.

`OFILE_IDC`
|
IDC file.

`OFILE_LST`
|
Disassembly listing.

`OFILE_ASM`
|
Assembly.

`OFILE_DIF`
|
Difference.

`GENFLG_MAPSEG`
|
OFILE_MAP: generate map of segments

`GENFLG_MAPNAME`
|
OFILE_MAP: include dummy names

`GENFLG_MAPDMNG`
|
OFILE_MAP: demangle names

`GENFLG_MAPLOC`
|
OFILE_MAP: include local names

`GENFLG_IDCTYPE`
|
OFILE_IDC: gen only information about types

`GENFLG_ASMTYPE`
|
OFILE_ASM,OFILE_LST: gen information about types too

`GENFLG_GENHTML`
|
OFILE_ASM,OFILE_LST: generate html (ui_genfile_callback will be used)

`GENFLG_ASMINC`
|
OFILE_ASM,OFILE_LST: gen information only about types

`FILEREG_PATCHABLE`
|
means that the input file may be patched (i.e. no compression, no iterated data, etc)

`FILEREG_NOTPATCHABLE`
|
the data is kept in some encoded form in the file.

`PLUGIN_DLL`
|
Pattern to find plugin files.

`MODULE_ENTRY_LOADER`
|

`MODULE_ENTRY_PLUGIN`
|

`MODULE_ENTRY_IDP`
|

`IDP_DLL`
|

`MAX_DATABASE_DESCRIPTION`
|
Maximum database snapshot description length.

`SSF_AUTOMATIC`
|
automatic snapshot

`SSUF_DESC`
|
Update the description.

`SSUF_PATH`
|
Update the path.

`SSUF_FLAGS`
|
Update the flags.

`DBFL_KILL`
|
delete unpacked database

`DBFL_COMP`
|
collect garbage

`DBFL_BAK`
|
create backup file (if !DBFL_KILL)

`DBFL_TEMP`
|
temporary database

`PATH_TYPE_CMD`
|
full path to the file specified in the command line

`PATH_TYPE_IDB`
|
full path of IDB file

`PATH_TYPE_ID0`
|
full path of ID0 file

## Classes

`qvector_snapshotvec_t`
|

`loader_t`
|

`idp_name_t`
|

`idp_desc_t`
|

`plugin_info_t`
|

`snapshot_t`
|

## Functions

`load_binary_file`(→ bool)
|
Load a binary file into the database. This function usually is called from ui.

`process_archive`(→ str)
|
Calls loader_t::process_archive() For parameters and return value description look at loader_t::process_archive(). Additional parameter 'loader' is a pointer to load_info_t structure.

`gen_file`(→ int)
|
Generate an output file. OFILE_EXE:

`file2base`(→ int)
|
Load portion of file into the database. This function will include (ea1..ea2) into the addressing space of the program (make it enabled).

`base2file`(→ int)
|
Unload database to a binary file. This function works for wide byte processors too.

`get_basic_file_type`(→ filetype_t)
|
Get the input file type. This function can recognize libraries and zip files.

`get_file_type_name`(→ str)
|
Get name of the current file type. The current file type is kept in idainfo::filetype.

`set_import_ordinal`(→ None)
|
Set information about the ordinal import entry. This function performs 'modnode.altset(ord, ea2node(ea));'

`set_import_name`(→ None)
|
Set information about the named import entry. This function performs 'modnode.supset_ea(ea, name);'

`load_ids_module`(→ int)
|
Load and apply IDS file. This function loads the specified IDS file and applies it to the database. If the program imports functions from a module with the same name as the name of the ids file being loaded, then only functions from this module will be affected. Otherwise (i.e. when the program does not import a module with this name) any function in the program may be affected.

`get_plugin_options`(→ str)
|
Get plugin options from the command line. If the user has specified the options in the -Oplugin_name:options format, them this function will return the 'options' part of it The 'plugin' parameter should denote the plugin name Returns nullptr if there we no options specified

`find_plugin`(→ plugin_t *)
|
Find a user-defined plugin and optionally load it.

`get_fileregion_offset`(→ qoff64_t)
|
Get offset in the input file which corresponds to the given ea. If the specified ea can't be mapped into the input file offset, return -1.

`get_fileregion_ea`(→ ida_idaapi.ea_t)
|
Get linear address which corresponds to the specified input file offset. If can't be found, return BADADDR

`gen_exe_file`(→ int)
|
Generate an exe file (unload the database in binary form).

`reload_file`(→ bool)
|
Reload the input file. This function reloads the byte values from the input file. It doesn't modify the segmentation, names, comments, etc.

`build_snapshot_tree`(→ bool)
|
Build the snapshot tree.

`flush_buffers`(→ int)
|
Flush buffers to the disk.

`is_trusted_idb`(→ bool)
|
Is the database considered as trusted?

`save_database`(→ bool)
|
Save current database using a new file name.

`is_database_flag`(→ bool)
|
Get the current database flag

`set_database_flag`(→ None)
|
Set or clear database flag

`clr_database_flag`(→ None)
|

`get_path`(→ str)
|
Get the file path

`set_path`(→ None)
|
Set the file path

`get_elf_debug_file_directory`(→ str)
|
Get the value of the ELF_DEBUG_FILE_DIRECTORY configuration directive.

`mem2base`(mem, ea, fpos)
|
Load database from the memory.

`load_plugin`(name)
|
Loads a plugin

`run_plugin`(plg, arg)
|
Runs a plugin

`load_and_run_plugin`(→ bool)
|
Load & run a plugin.

`extract_module_from_archive`(→ PyObject *)
|
Extract a module for an archive file. Parse an archive file, show the list of modules to the user, allow him to select a module, extract the selected module to a file (if the extract module is an archive, repeat the process). This function can handle ZIP, AR, AIXAR, OMFLIB files. The temporary file will be automatically deleted by IDA at the end.

## Module Contents

classida_loader.qvector_snapshotvec_t(*args)
Bases: `object`
thisownpush_back(*args)→snapshot_t*&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→snapshot_t*const&qclear()→Noneclear()→Noneresize(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_snapshotvec_t)→Noneextract()→snapshot_t**inject(s:snapshot_t**, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:qvector::iterator, x:snapshot_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:snapshot_t)→booladd_unique(x:snapshot_t)→boolappend(x:snapshot_t)→Noneextend(x:qvector_snapshotvec_t)→Nonefrontbackclassida_loader.loader_t
Bases: `object`
thisownversion:int
api version, should be IDP_INTERFACE_VERSION
flags:int
Loader flags
ida_loader.LDRF_RELOAD
loader recognizes NEF_RELOAD flag
ida_loader.LDRF_REQ_PROC
Requires a processor to be set. if this bit is not set, load_file() must call set_processor_type(…, SETPROC_LOADER)
ida_loader.ACCEPT_ARCHIVE
Specify that a file format is served by archive loader See loader_t::accept_file
ida_loader.ACCEPT_CONTINUE
Specify that the function must be called another time See loader_t::accept_file
ida_loader.ACCEPT_FIRST
Specify that a file format should be place first in “load file” dialog box. See loader_t::accept_file
ida_loader.NEF_SEGS
Create segments.
ida_loader.NEF_RSCS
Load resources.
ida_loader.NEF_NAME
Rename entries.
ida_loader.NEF_MAN
Manual load.
ida_loader.NEF_FILL
Fill segment gaps.
ida_loader.NEF_IMPS
Create import segment.
ida_loader.NEF_FIRST
This is the first file loaded into the database.
ida_loader.NEF_CODE
for load_binary_file(): load as a code segment
ida_loader.NEF_RELOAD
reload the file at the same place: * don’t create segments * don’t create fixup info * don’t import segments * etc.

Load only the bytes into the base. A loader should have the LDRF_RELOAD bit set.
ida_loader.NEF_FLAT
Autocreate FLAT group (PE)
ida_loader.NEF_MINI
Create mini database (do not copy segment bytes from the input file; use only the file header metadata)
ida_loader.NEF_LOPT
Display additional loader options dialog.
ida_loader.NEF_LALL
Load all segments without questions.
ida_loader.DLLEXTida_loader.LOADER_DLLida_loader.load_binary_file(filename:str, li:linput_t*, _neflags:ushort, fileoff:qoff64_t, basepara:ida_idaapi.ea_t, binoff:ida_idaapi.ea_t, nbytes:uint64)→bool
Load a binary file into the database. This function usually is called from ui.
Parameters:

-
filename – the name of input file as is (if the input file is from library, then this is the name from the library)

-
li – loader input source

-
_neflags – Load file flags. For the first file, the flag NEF_FIRST must be set.

-
fileoff – Offset in the input file

-
basepara – Load address in paragraphs

-
binoff – Load offset (load_address=(basepara<<4)+binoff)

-
nbytes – Number of bytes to load from the file.

-
0: up to the end of the file

Returns:
true: ok
Returns:
false: failed (couldn’t open the file)
ida_loader.process_archive(temp_file:str, li:linput_t*, module_name:str, neflags:ushort*, defmember:str, loader:load_info_tconst*)→str
Calls loader_t::process_archive() For parameters and return value description look at loader_t::process_archive(). Additional parameter ‘loader’ is a pointer to load_info_t structure.
ida_loader.OFILE_MAP
MAP file.
ida_loader.OFILE_EXE
Executable file.
ida_loader.OFILE_IDC
IDC file.
ida_loader.OFILE_LST
Disassembly listing.
ida_loader.OFILE_ASM
Assembly.
ida_loader.OFILE_DIF
Difference.
ida_loader.gen_file(otype:ofile_type_t, fp:FILE*, ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, flags:int)→int
Generate an output file. OFILE_EXE:
Parameters:

-
otype – type of output file.

-
fp – the output file handle

-
ea1 – start address. For some file types this argument is ignored

-
ea2 – end address. For some file types this argument is ignored as usual in ida, the end address of the range is not included

-
flags – Generate file flags

Returns:
number of the generated lines. -1 if an error occurred
Returns:
0: can’t generate exe file
Returns:
1: ok
ida_loader.GENFLG_MAPSEG
OFILE_MAP: generate map of segments
ida_loader.GENFLG_MAPNAME
OFILE_MAP: include dummy names
ida_loader.GENFLG_MAPDMNG
OFILE_MAP: demangle names
ida_loader.GENFLG_MAPLOC
OFILE_MAP: include local names
ida_loader.GENFLG_IDCTYPE
OFILE_IDC: gen only information about types
ida_loader.GENFLG_ASMTYPE
OFILE_ASM,OFILE_LST: gen information about types too
ida_loader.GENFLG_GENHTML
OFILE_ASM,OFILE_LST: generate html (ui_genfile_callback will be used)
ida_loader.GENFLG_ASMINC
OFILE_ASM,OFILE_LST: gen information only about types
ida_loader.file2base(li:linput_t*, pos:qoff64_t, ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, patchable:int)→int
Load portion of file into the database. This function will include (ea1..ea2) into the addressing space of the program (make it enabled).
Parameters:

-
li – pointer of input source

-
pos – position in the file

-
ea1 – range of destination linear addresses

-
ea2 – range of destination linear addresses

-
patchable – should the kernel remember correspondence of file offsets to linear addresses.

Returns:
1: ok
Returns:
0: read error, a warning is displayed
ida_loader.FILEREG_PATCHABLE
means that the input file may be patched (i.e. no compression, no iterated data, etc)
ida_loader.FILEREG_NOTPATCHABLE
the data is kept in some encoded form in the file.
ida_loader.base2file(fp:FILE*, pos:qoff64_t, ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t)→int
Unload database to a binary file. This function works for wide byte processors too.
Parameters:

-
fp – pointer to file

-
pos – position in the file

-
ea1 – range of source linear addresses

-
ea2 – range of source linear addresses

Returns:
1-ok(always), write error leads to immediate exit
ida_loader.get_basic_file_type(li:linput_t*)→filetype_t
Get the input file type. This function can recognize libraries and zip files.
ida_loader.get_file_type_name()→str
Get name of the current file type. The current file type is kept in idainfo::filetype.
Returns:
size of answer, this function always succeeds
ida_loader.set_import_ordinal(modnode:int, ea:ida_idaapi.ea_t, ord:int)→None
Set information about the ordinal import entry. This function performs ‘modnode.altset(ord, ea2node(ea));’
Parameters:

-
modnode – node with information about imported entries

-
ea – linear address of the entry

-
ord – ordinal number of the entry

ida_loader.set_import_name(modnode:int, ea:ida_idaapi.ea_t, name:str)→None
Set information about the named import entry. This function performs ‘modnode.supset_ea(ea, name);’
Parameters:

-
modnode – node with information about imported entries

-
ea – linear address of the entry

-
name – name of the entry

ida_loader.load_ids_module(fname:char*)→int
Load and apply IDS file. This function loads the specified IDS file and applies it to the database. If the program imports functions from a module with the same name as the name of the ids file being loaded, then only functions from this module will be affected. Otherwise (i.e. when the program does not import a module with this name) any function in the program may be affected.
Parameters:
fname – name of file to apply
Returns:
1: ok
Returns:
0: some error (a message is displayed). if the ids file does not exist, no message is displayed
ida_loader.get_plugin_options(plugin:str)→str
Get plugin options from the command line. If the user has specified the options in the -Oplugin_name:options format, them this function will return the ‘options’ part of it The ‘plugin’ parameter should denote the plugin name Returns nullptr if there we no options specified
ida_loader.PLUGIN_DLL
Pattern to find plugin files.
ida_loader.MODULE_ENTRY_LOADERida_loader.MODULE_ENTRY_PLUGINida_loader.MODULE_ENTRY_IDPclassida_loader.idp_name_t
Bases: `object`
thisownlname:str
long processor name
sname:str
short processor name
hidden:bool
is hidden
classida_loader.idp_desc_t
Bases: `object`
thisownpath:str
module file name
mtime:time_t
time of last modification
family:str
processor’s family
names:idp_names_t
processor names
is_script:bool
the processor module is a script
checked:bool
internal, for cache management
ida_loader.IDP_DLLclassida_loader.plugin_info_t
Bases: `object`
thisownnext:plugin_info_t*
next plugin information
path:char*
full path to the plugin
org_name:char*
original short name of the plugin
name:char*
short name of the plugin it will appear in the menu
org_hotkey:ushort
original hotkey to run the plugin
hotkey:ushort
current hotkey to run the plugin
arg:int
argument used to call the plugin
entry:plugin_t*
pointer to the plugin if it is already loaded
dllmem:idadll_tflags:int
a copy of plugin_t::flags
comment:char*
a copy of plugin_t::comment
idaplg_name:str
“name” provided by ida-plugin.json or basename of path (without extension)
ida_loader.find_plugin(name:str, load_if_needed:bool=False)→plugin_t*
Find a user-defined plugin and optionally load it.
Parameters:

-
name – short plugin name without path and extension, or absolute path to the file name

-
load_if_needed – if the plugin is not present in the memory, try to load it

Returns:
pointer to plugin description block
ida_loader.get_fileregion_offset(ea:ida_idaapi.ea_t)→qoff64_t
Get offset in the input file which corresponds to the given ea. If the specified ea can’t be mapped into the input file offset, return -1.
ida_loader.get_fileregion_ea(offset:qoff64_t)→ida_idaapi.ea_t
Get linear address which corresponds to the specified input file offset. If can’t be found, return BADADDR
ida_loader.gen_exe_file(fp:FILE*)→int
Generate an exe file (unload the database in binary form).
Returns:
fp the output file handle. if fp == nullptr then return:

-
1: can generate an executable file

-
0: can’t generate an executable file

Returns:
1: ok
Returns:
0: failed
ida_loader.reload_file(file:str, is_remote:bool)→bool
Reload the input file. This function reloads the byte values from the input file. It doesn’t modify the segmentation, names, comments, etc.
Parameters:
file – name of the input file. if file == nullptr then returns:

-
1: can reload the input file

-
0: can’t reload the input file

Parameters:
is_remote – is the file located on a remote computer with the debugger server?
Returns:
success
ida_loader.MAX_DATABASE_DESCRIPTION
Maximum database snapshot description length.
classida_loader.snapshot_t
Bases: `object`
thisownid:qtime64_t
snapshot ID. This value is computed using qgettimeofday()
flags:uint16
Snapshot flags
desc:char[128]
snapshot description
filename:char[QMAXPATH]
snapshot file name
children:snapshots_t
snapshot children
clear()→Noneida_loader.SSF_AUTOMATIC
automatic snapshot
ida_loader.build_snapshot_tree(root:snapshot_t)→bool
Build the snapshot tree.
Parameters:
root – snapshot root that will contain the snapshot tree elements.
Returns:
success
ida_loader.SSUF_DESC
Update the description.
ida_loader.SSUF_PATH
Update the path.
ida_loader.SSUF_FLAGS
Update the flags.
ida_loader.flush_buffers()→int
Flush buffers to the disk.
ida_loader.is_trusted_idb()→bool
Is the database considered as trusted?
ida_loader.save_database(outfile:str=None, flags:int=0, root:snapshot_t=None, attr:snapshot_t=None)→bool
Save current database using a new file name.
Parameters:

-
outfile – output database file name; nullptr means the current path

-
flags – Database flags; 0 means the current flags

-
root – optional: snapshot tree root.

-
attr – optional: snapshot attributes

Returns:
success
ida_loader.DBFL_KILL
delete unpacked database
ida_loader.DBFL_COMP
collect garbage
ida_loader.DBFL_BAK
create backup file (if !DBFL_KILL)
ida_loader.DBFL_TEMP
temporary database
ida_loader.is_database_flag(dbfl:int)→bool
Get the current database flag
Parameters:
dbfl – flag Database flags
Returns:
the state of the flag (set or cleared)
ida_loader.set_database_flag(dbfl:int, cnd:bool=True)→None
Set or clear database flag
Parameters:

-
dbfl – flag Database flags

-
cnd – set if true or clear flag otherwise

ida_loader.clr_database_flag(dbfl:int)→Noneida_loader.PATH_TYPE_CMD
full path to the file specified in the command line
ida_loader.PATH_TYPE_IDB
full path of IDB file
ida_loader.PATH_TYPE_ID0
full path of ID0 file
ida_loader.get_path(pt:path_type_t)→str
Get the file path
Parameters:
pt – file path type Types of the file pathes
Returns:
file path, never returns nullptr
ida_loader.set_path(pt:path_type_t, path:str)→None
Set the file path
Parameters:

-
pt – file path type Types of the file pathes

-
path – new file path, use nullptr or empty string to clear the file path

ida_loader.get_elf_debug_file_directory()→str
Get the value of the ELF_DEBUG_FILE_DIRECTORY configuration directive.
ida_loader.mem2base(mem, ea, fpos)
Load database from the memory.
Parameters:

-
mem – the buffer

-
ea – start linear addresses

-
fpos – position in the input file the data is taken from. if == -1, then no file position correspond to the data.

Returns:
1, or 0 in case of failure
ida_loader.load_plugin(name)
Loads a plugin
Parameters:
name – short plugin name without path and extension, or absolute path to the file name
Returns:
An opaque object representing the loaded plugin, or None if plugin could not be loaded
ida_loader.run_plugin(plg, arg)
Runs a plugin
Parameters:

-
plg – A plugin object (returned by load_plugin())

-
arg – the code to pass to the plugin’s “run()” function

Returns:
Boolean
ida_loader.load_and_run_plugin(name:str, arg:int)→bool
Load & run a plugin.
ida_loader.extract_module_from_archive(fname:str, is_remote:bool=False)→PyObject*
Extract a module for an archive file. Parse an archive file, show the list of modules to the user, allow him to select a module, extract the selected module to a file (if the extract module is an archive, repeat the process). This function can handle ZIP, AR, AIXAR, OMFLIB files. The temporary file will be automatically deleted by IDA at the end.
Parameters:
is_remote – is the input file remote?
Returns:
true: ok
Returns:
false: something bad happened (error message has been displayed to the user)
