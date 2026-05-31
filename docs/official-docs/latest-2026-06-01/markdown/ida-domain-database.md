# IDA Domain database API

- 官方来源：https://ida-domain.docs.hex-rays.com/ref/database/

Skip to content

 IDA Domain API

 Database

 Initializing search

 hexrayssa/ida-domain

 IDA Domain API

 hexrayssa/ida-domain

- Intro
- Getting Started
- FAQ
- Examples
- Usage
 Usage

- Overview
- llms.txt

- API Reference
 API Reference

- Database Database
 Table of contents

- `` database

- `` CompilerInformation

- `` byte_size_bits
- `` double_size_bits
- `` enum_size_bits
- `` int_size_bits
- `` long_long_size_bits
- `` long_size_bits
- `` name
- `` short_size_bits

- `` Database

- `` architecture
- `` base_address
- `` bitness
- `` bytes
- `` comments
- `` compiler_information
- `` crc32
- `` current_ea
- `` entries
- `` execution_mode
- `` filesize
- `` format
- `` functions
- `` heads
- `` hooks
- `` imports
- `` instructions
- `` load_time
- `` maximum_ea
- `` md5
- `` metadata
- `` microcode
- `` minimum_ea
- `` module
- `` names
- `` path
- `` pseudocode
- `` save_on_close
- `` segments
- `` sha256
- `` signature_files
- `` start_ip
- `` strings
- `` types
- `` xrefs
- `` close
- `` execute_script
- `` hook
- `` is_open
- `` is_valid_ea
- `` open
- `` unhook

- `` DatabaseMetadata

- `` architecture
- `` base_address
- `` bitness
- `` compiler_information
- `` crc32
- `` execution_mode
- `` filesize
- `` format
- `` load_time
- `` md5
- `` module
- `` path
- `` sha256

- `` ExecutionMode

- `` Kernel
- `` User

- `` IdaCommandOptions

- `` auto_analysis
- `` compiler
- `` db_compression
- `` debug_flags
- `` disable_fpp
- `` disable_mouse
- `` empty_database
- `` entry_point
- `` file_member
- `` file_type
- `` first_pass_directives
- `` jit_debugger
- `` load_resources
- `` loading_address
- `` log_file
- `` new_database
- `` no_segmentation
- `` output_database
- `` plugin_options
- `` processor
- `` run_debugger
- `` script_args
- `` script_file
- `` second_pass_directives
- `` windows_dir
- `` build_args

- Flowchart
- Bytes
- Comments
- Entries
- Hooks
- Functions
- Heads
- Imports
- Instructions
- Microcode
- Pseudocode
- Names
- Operands
- Segments
- Signature Files
- Strings
- Types
- Xrefs

 Table of contents

- `` database

- `` CompilerInformation

- `` byte_size_bits
- `` double_size_bits
- `` enum_size_bits
- `` int_size_bits
- `` long_long_size_bits
- `` long_size_bits
- `` name
- `` short_size_bits

- `` Database

- `` architecture
- `` base_address
- `` bitness
- `` bytes
- `` comments
- `` compiler_information
- `` crc32
- `` current_ea
- `` entries
- `` execution_mode
- `` filesize
- `` format
- `` functions
- `` heads
- `` hooks
- `` imports
- `` instructions
- `` load_time
- `` maximum_ea
- `` md5
- `` metadata
- `` microcode
- `` minimum_ea
- `` module
- `` names
- `` path
- `` pseudocode
- `` save_on_close
- `` segments
- `` sha256
- `` signature_files
- `` start_ip
- `` strings
- `` types
- `` xrefs
- `` close
- `` execute_script
- `` hook
- `` is_open
- `` is_valid_ea
- `` open
- `` unhook

- `` DatabaseMetadata

- `` architecture
- `` base_address
- `` bitness
- `` compiler_information
- `` crc32
- `` execution_mode
- `` filesize
- `` format
- `` load_time
- `` md5
- `` module
- `` path
- `` sha256

- `` ExecutionMode

- `` Kernel
- `` User

- `` IdaCommandOptions

- `` auto_analysis
- `` compiler
- `` db_compression
- `` debug_flags
- `` disable_fpp
- `` disable_mouse
- `` empty_database
- `` entry_point
- `` file_member
- `` file_type
- `` first_pass_directives
- `` jit_debugger
- `` load_resources
- `` loading_address
- `` log_file
- `` new_database
- `` no_segmentation
- `` output_database
- `` plugin_options
- `` processor
- `` run_debugger
- `` script_args
- `` script_file
- `` second_pass_directives
- `` windows_dir
- `` build_args

# `Database`

## ``database

Classes:

- `CompilerInformation` –

Compiler information for the current database.

- `Database` –

Provides access and control over the loaded IDA database.

- `DatabaseMetadata` –

Metadata information about the current database.

- `ExecutionMode` –

Enumeration Execution Modes

- `IdaCommandOptions` –

Configuration for building IDA command line arguments.

### ``CompilerInformation`dataclass`

```text
CompilerInformation(
 name: str,
 byte_size_bits: int,
 short_size_bits: int,
 enum_size_bits: int,
 int_size_bits: int,
 long_size_bits: int,
 double_size_bits: int,
 long_long_size_bits: int,
)

```

Compiler information for the current database.

Attributes:

- `byte_size_bits` (`int`) –

- `double_size_bits` (`int`) –

- `enum_size_bits` (`int`) –

- `int_size_bits` (`int`) –

- `long_long_size_bits` (`int`) –

- `long_size_bits` (`int`) –

- `name` (`str`) –

- `short_size_bits` (`int`) –

#### ``byte_size_bits`instance-attribute`

```text
byte_size_bits: int

```

#### ``double_size_bits`instance-attribute`

```text
double_size_bits: int

```

#### ``enum_size_bits`instance-attribute`

```text
enum_size_bits: int

```

#### ``int_size_bits`instance-attribute`

```text
int_size_bits: int

```

#### ``long_long_size_bits`instance-attribute`

```text
long_long_size_bits: int

```

#### ``long_size_bits`instance-attribute`

```text
long_size_bits: int

```

#### ``name`instance-attribute`

```text
name: str

```

#### ``short_size_bits`instance-attribute`

```text
short_size_bits: int

```

### ``Database

```text
Database(hooks: Optional[HooksList] = None)

```

Provides access and control over the loaded IDA database.

This class supports context manager protocol for automatic resource cleanup. When used as a context manager, the database is automatically closed on exit.

Parameters:

- `hooks` (`HooksList`, default: `None` ) –

A list of hook instances to associate with this database. Defaults to an empty list.

Warning
Direct instantiation is discouraged. Use `Database.open()` instead.

Database lifecycle behavior differs based on execution context:

- Library mode: You can open/close databases programmatically
- IDA mode: You can only obtain a handle to the currently open database by calling `Database.open()` without arguments
Example

```text
# Library mode: Open and automatically close a database
with Database.open("path/to/file.exe", save_on_close=True) as db:
 print(f"Loaded: {db.path}")
# Database is automatically closed here

# Library mode: Manual control
db = Database.open("path/to/file.exe", save_on_close=True)
db.close()

# IDA mode: Get handle to current database
db = Database.open() # or Database.open(None)

```

Methods:

- `close` –

Closes the currently open database.

- `execute_script` –

Execute the specified python script

- `hook` –

Activate (hook) all registered event handler instances.

- `is_open` –

Checks if the database is loaded.

- `is_valid_ea` –

Check if the specified address is valid.

- `open` –

Opens or connects to an IDA database.

- `unhook` –

Deactivate (unhook) all registered event handler instances.

Attributes:

- `architecture` (`Optional[str]`) –

The processor architecture.

- `base_address` (`Optional[ea_t]`) –

The image base address of this database.

- `bitness` (`Optional[int]`) –

The application bitness (32/64).

- `bytes` (`Bytes`) –

Handler that provides access to byte-level memory operations.

- `comments` (`Comments`) –

Handler that provides access to user comment-related operations.

- `compiler_information` (`CompilerInformation`) –

Compiler information for current database.

- `crc32` (`Optional[int]`) –

The CRC32 checksum of the input file.

- `current_ea` (`ea_t`) –

The current effective address (equivalent to the "screen EA" in IDA GUI).

- `entries` (`Entries`) –

Handler that provides access to entries operations.

- `execution_mode` (`ExecutionMode`) –

The execution mode, user or kernel mode.

- `filesize` (`Optional[int]`) –

The input file size.

- `format` (`Optional[str]`) –

The file format type.

- `functions` (`Functions`) –

Handler that provides access to function-related operations.

- `heads` (`Heads`) –

Handler that provides access to user heads operations.

- `hooks` (`HooksList`) –

Returns the list of associated hook instances.

- `imports` (`Imports`) –

Handler that provides access to import operations.

- `instructions` (`Instructions`) –

Handler that provides access to instruction-related operations.

- `load_time` (`Optional[str]`) –

The database load time.

- `maximum_ea` (`ea_t`) –

The maximum effective address from this database.

- `md5` (`Optional[str]`) –

The MD5 hash of the input file.

- `metadata` (`DatabaseMetadata`) –

Map of key-value metadata about the current database.

- `microcode` (`Microcode`) –

Handler that provides access to microcode operations.

- `minimum_ea` (`ea_t`) –

The minimum effective address from this database.

- `module` (`Optional[str]`) –

The module name.

- `names` (`Names`) –

Handler that provides access to name-related operations.

- `path` (`Optional[str]`) –

The input file path.

- `pseudocode` (`Pseudocode`) –

Handler that provides access to pseudocode/decompiler operations.

- `save_on_close` –

- `segments` (`Segments`) –

Handler that provides access to memory segment-related operations.

- `sha256` (`Optional[str]`) –

The SHA256 hash of the input file.

- `signature_files` (`SignatureFiles`) –

Handler that provides access to signature file operations.

- `start_ip` (`ea_t`) –

The start instruction pointer value

- `strings` (`Strings`) –

Handler that provides access to string-related operations.

- `types` (`Types`) –

Handler that provides access to type-related operations.

- `xrefs` (`Xrefs`) –

Handler that provides access to cross-reference (xref) operations.

#### ``architecture`property`

```text
architecture: Optional[str]

```

The processor architecture.

#### ``base_address`property`

```text
base_address: Optional[ea_t]

```

The image base address of this database.

#### ``bitness`property`

```text
bitness: Optional[int]

```

The application bitness (32/64).

#### ``bytes`property`

```text
bytes: Bytes

```

Handler that provides access to byte-level memory operations.

#### ``comments`property`

```text
comments: Comments

```

Handler that provides access to user comment-related operations.

#### ``compiler_information`property`

```text
compiler_information: CompilerInformation

```

Compiler information for current database.

#### ``crc32`property`

```text
crc32: Optional[int]

```

The CRC32 checksum of the input file.

#### ``current_ea`property``writable`

```text
current_ea: ea_t

```

The current effective address (equivalent to the "screen EA" in IDA GUI).

#### ``entries`property`

```text
entries: Entries

```

Handler that provides access to entries operations.

#### ``execution_mode`property`

```text
execution_mode: ExecutionMode

```

The execution mode, user or kernel mode.

#### ``filesize`property`

```text
filesize: Optional[int]

```

The input file size.

#### ``format`property`

```text
format: Optional[str]

```

The file format type.

#### ``functions`property`

```text
functions: Functions

```

Handler that provides access to function-related operations.

#### ``heads`property`

```text
heads: Heads

```

Handler that provides access to user heads operations.

#### ``hooks`property`

```text
hooks: HooksList

```

Returns the list of associated hook instances.

#### ``imports`property`

```text
imports: Imports

```

Handler that provides access to import operations.

#### ``instructions`property`

```text
instructions: Instructions

```

Handler that provides access to instruction-related operations.

#### ``load_time`property`

```text
load_time: Optional[str]

```

The database load time.

#### ``maximum_ea`property`

```text
maximum_ea: ea_t

```

The maximum effective address from this database.

#### ``md5`property`

```text
md5: Optional[str]

```

The MD5 hash of the input file.

#### ``metadata`property`

```text
metadata: DatabaseMetadata

```

Map of key-value metadata about the current database. Dynamically built from DatabaseMetadata dataclass fields. Returns metadata with original property types preserved.

#### ``microcode`property`

```text
microcode: Microcode

```

Handler that provides access to microcode operations.

#### ``minimum_ea`property`

```text
minimum_ea: ea_t

```

The minimum effective address from this database.

#### ``module`property`

```text
module: Optional[str]

```

The module name.

#### ``names`property`

```text
names: Names

```

Handler that provides access to name-related operations.

#### ``path`property`

```text
path: Optional[str]

```

The input file path.

#### ``pseudocode`property`

```text
pseudocode: Pseudocode

```

Handler that provides access to pseudocode/decompiler operations.

#### ``save_on_close`instance-attribute`

```text
save_on_close = True

```

#### ``segments`property`

```text
segments: Segments

```

Handler that provides access to memory segment-related operations.

#### ``sha256`property`

```text
sha256: Optional[str]

```

The SHA256 hash of the input file.

#### ``signature_files`property`

```text
signature_files: SignatureFiles

```

Handler that provides access to signature file operations.

#### ``start_ip`property``writable`

```text
start_ip: ea_t

```

The start instruction pointer value

#### ``strings`property`

```text
strings: Strings

```

Handler that provides access to string-related operations.

#### ``types`property`

```text
types: Types

```

Handler that provides access to type-related operations.

#### ``xrefs`property`

```text
xrefs: Xrefs

```

Handler that provides access to cross-reference (xref) operations.

#### ``close

```text
close(save: Optional[bool] = None) -> None

```

Closes the currently open database.

Parameters:

- `save` (`Optional[bool]`, default: `None` ) –

If provided, saves/discards changes accordingly. If None, uses the save_on_close setting from open().

Note
This function is available only when running IDA as a library. When running inside the IDA GUI, we have no control on the database lifecycle.

#### ``execute_script

```text
execute_script(file_path: str) -> None

```

Execute the specified python script

Parameters:

- `file_path` (`str`) –

The script file path

Raises:

- `DatabaseError` –

If script execution fails.

#### ``hook

```text
hook() -> None

```

Activate (hook) all registered event handler instances.

This method associates each hook instance with the current database instance and calls their `hook()` method. Hooks are automatically hooked when the database is opened (including when used as a context manager).

Typically, you do not need to call this method manually—hooks are managed automatically upon database entry.

#### ``is_open

```text
is_open() -> bool

```

Checks if the database is loaded.

Returns:

- `bool` –

True if a database is open, false otherwise.

#### ``is_valid_ea

```text
is_valid_ea(ea: ea_t, strict_check: bool = True) -> bool

```

Check if the specified address is valid.

Parameters:

- `ea` (`ea_t`) –

The effective address to validate.

- `strict_check` (`bool`, default: `True` ) –

If True, validates ea is mapped (ida_bytes.is_mapped). If False, only validates ea is within database range.

Returns:

- `bool` –

True if address is valid according to the check level.

#### ``open`classmethod`

```text
open(
 path: str = '',
 args: Optional[IdaCommandOptions] = None,
 save_on_close: bool = True,
 hooks: Optional[HooksList] = None,
) -> Database

```

Opens or connects to an IDA database.

This method has two distinct behaviors depending on the execution context:

Library mode (IDA as a library): Opens a new database from the specified file path. Full control over the database lifecycle including opening and closing.

IDA GUI mode (running inside IDA): Returns a handle to the currently open database. Set `path` to None.

Parameters:

- `path` (`str`, default: `''` ) –

Path to the binary file to analyze. - Library mode: Required path to the file - IDA GUI mode: Must be None to reference the currently open database Defaults to None.

- `args` (`Optional[IdaCommandOptions]`, default: `None` ) –

Additional arguments to pass to the IDA kernel when opening the database (e.g., processor type, loading address, analysis options). Only applicable in library mode. Defaults to None.

- `save_on_close` (`bool`, default: `True` ) –

Whether to save changes when closing the database. This is used automatically when exiting a context manager, but can be overridden in explicit `close()` calls. Defaults to False.

- `hooks` (`Optional[HooksList]`, default: `None` ) –

List of hook instances to associate with the database. Hooks are automatically enabled before opening and disabled after closing. Defaults to an empty list.

Returns:

- `Database` ( `Database` ) –

A Database instance connected to the specified or current database.

Raises:

- `DatabaseError` –

If the database cannot be opened or if `path` is provided when running inside IDA GUI.

Example

```text
# Library mode: Open a new database with custom options
with Database.open(
 "malware.exe",
 args={"processor": "arm", "load_addr": 0x1000},
 save_on_close=True
) as db:
 # Analyze the binary
 pass # Automatically saved and closed

# IDA GUI mode: Get current database
db = Database.open() # path=None
# Work with the currently open database

```

#### ``unhook

```text
unhook() -> None

```

Deactivate (unhook) all registered event handler instances.

This method calls `unhook()` on each registered hook and disassociates them from the database instance. Hooks are automatically unhooked when the database is closed, including when used with the database as a context manager.

Typically, you do not need to call this method manually—hooks are managed automatically upon database exit.

### ``DatabaseMetadata`dataclass`

```text
DatabaseMetadata(
 path: Optional[str] = None,
 module: Optional[str] = None,
 base_address: Optional[ea_t] = None,
 filesize: Optional[int] = None,
 md5: Optional[str] = None,
 sha256: Optional[str] = None,
 crc32: Optional[int] = None,
 architecture: Optional[str] = None,
 bitness: Optional[int] = None,
 format: Optional[str] = None,
 load_time: Optional[str] = None,
 compiler_information: Optional[str] = None,
 execution_mode: Optional[str] = None,
)

```

Metadata information about the current database.

Attributes:

- `architecture` (`Optional[str]`) –

- `base_address` (`Optional[ea_t]`) –

- `bitness` (`Optional[int]`) –

- `compiler_information` (`Optional[str]`) –

- `crc32` (`Optional[int]`) –

- `execution_mode` (`Optional[str]`) –

- `filesize` (`Optional[int]`) –

- `format` (`Optional[str]`) –

- `load_time` (`Optional[str]`) –

- `md5` (`Optional[str]`) –

- `module` (`Optional[str]`) –

- `path` (`Optional[str]`) –

- `sha256` (`Optional[str]`) –

#### ``architecture`class-attribute``instance-attribute`

```text
architecture: Optional[str] = None

```

#### ``base_address`class-attribute``instance-attribute`

```text
base_address: Optional[ea_t] = None

```

#### ``bitness`class-attribute``instance-attribute`

```text
bitness: Optional[int] = None

```

#### ``compiler_information`class-attribute``instance-attribute`

```text
compiler_information: Optional[str] = None

```

#### ``crc32`class-attribute``instance-attribute`

```text
crc32: Optional[int] = None

```

#### ``execution_mode`class-attribute``instance-attribute`

```text
execution_mode: Optional[str] = None

```

#### ``filesize`class-attribute``instance-attribute`

```text
filesize: Optional[int] = None

```

#### ``format`class-attribute``instance-attribute`

```text
format: Optional[str] = None

```

#### ``load_time`class-attribute``instance-attribute`

```text
load_time: Optional[str] = None

```

#### ``md5`class-attribute``instance-attribute`

```text
md5: Optional[str] = None

```

#### ``module`class-attribute``instance-attribute`

```text
module: Optional[str] = None

```

#### ``path`class-attribute``instance-attribute`

```text
path: Optional[str] = None

```

#### ``sha256`class-attribute``instance-attribute`

```text
sha256: Optional[str] = None

```

### ``ExecutionMode

 Bases: `Enum`

Enumeration Execution Modes

Attributes:

- `Kernel` –

- `User` –

#### ``Kernel`class-attribute``instance-attribute`

```text
Kernel = 'Kernel Mode'

```

#### ``User`class-attribute``instance-attribute`

```text
User = 'User Mode'

```

### ``IdaCommandOptions`dataclass`

```text
IdaCommandOptions(
 auto_analysis: bool = True,
 loading_address: Optional[int] = None,
 new_database: bool = False,
 compiler: Optional[str] = None,
 first_pass_directives: List[str] = list(),
 second_pass_directives: List[str] = list(),
 disable_fpp: bool = False,
 entry_point: Optional[int] = None,
 jit_debugger: Optional[bool] = None,
 log_file: Optional[str] = None,
 disable_mouse: bool = False,
 plugin_options: Optional[str] = None,
 output_database: Optional[str] = None,
 processor: Optional[str] = None,
 db_compression: Optional[str] = None,
 run_debugger: Optional[str] = None,
 load_resources: bool = False,
 script_file: Optional[str] = None,
 script_args: List[str] = list(),
 file_type: Optional[str] = None,
 file_member: Optional[str] = None,
 empty_database: bool = False,
 windows_dir: Optional[str] = None,
 no_segmentation: bool = False,
 debug_flags: Union[int, List[str]] = 0,
)

```

Configuration for building IDA command line arguments.

Set the desired options as attributes, then call `build_args()` to generate the command line string. Attributes correspond to IDA switches.
Example

```text
opts = IdaCommandOptions(
 auto_analysis=False,
 processor="arm",
 script_file="myscript.py",
 script_args=["arg1", "arg2"],
 debug_flags=["queue", "debugger"]
)
args = opts.build_args()

```

Attributes:

- `auto_analysis` (`bool`) –

If False, disables auto analysis (-a). Default: True (auto analysis enabled).

- `loading_address` (`Optional[int]`) –

Address (in paragraphs, 16 bytes each) to load the file at (-b). Default: None (not set).

- `new_database` (`bool`) –

If True, deletes the old database and creates a new one (-c). Default: False.

- `compiler` (`Optional[str]`) –

Compiler identifier string for the database (-C). Default: None.

- `first_pass_directives` (`List[str]`) –

Directives for first pass configuration (-d). Default: [].

- `second_pass_directives` (`List[str]`) –

Directives for second pass configuration (-D). Default: [].

- `disable_fpp` (`bool`) –

If True, disables FPP instructions (IBM PC only) (-f). Default: False.

- `entry_point` (`Optional[int]`) –

Entry point address (-i). Default: None (not set).

- `jit_debugger` (`Optional[bool]`) –

If set, enables/disables IDA as just-in-time debugger (-I). Default: None.

- `log_file` (`Optional[str]`) –

Path to the log file (-L). Default: None.

- `disable_mouse` (`bool`) –

If True, disables mouse support in text mode (-M). Default: False.

- `plugin_options` (`Optional[str]`) –

Options to pass to plugins (-O). Default: None.

- `output_database` (`Optional[str]`) –

Output database path (-o). Implies new_database. Default: None.

- `processor` (`Optional[str]`) –

Processor type identifier (-p). Default: None.

- `db_compression` (`Optional[str]`) –

Database compression ('compress', 'pack', 'no_pack') (-P). Default: None.

- `run_debugger` (`Optional[str]`) –

Debugger options string to run immediately (-r). Default: None.

- `load_resources` (`bool`) –

If True, loads MS Windows exe resources (-R). Default: False.

- `script_file` (`Optional[str]`) –

Script file to execute on database open (-S). Default: None.

- `script_args` (`List[str]`) –

Arguments to pass to the script (-S). Default: [].

- `file_type` (`Optional[str]`) –

File type prefix for input (-T). Default: None.

- `file_member` (`Optional[str]`) –

Archive member name, used with file_type (-T). Default: None.

- `empty_database` (`bool`) –

If True, creates an empty database (-t). Default: False.

- `windows_dir` (`Optional[str]`) –

MS Windows directory path (-W). Default: None.

- `no_segmentation` (`bool`) –

If True, disables segmentation (-x). Default: False.

- `debug_flags` (`Union[int, List[str]]`) –

Debug flags as integer or list of names (-z). Default: 0.

Methods:

- `build_args` –

Construct the command line arguments string from the configured options.

#### ``auto_analysis`class-attribute``instance-attribute`

```text
auto_analysis: bool = True

```

If False, disables auto analysis (-a). Default: True (enabled).

#### ``compiler`class-attribute``instance-attribute`

```text
compiler: Optional[str] = None

```

Compiler identifier string for the database (-C).

#### ``db_compression`class-attribute``instance-attribute`

```text
db_compression: Optional[str] = None

```

Database compression: 'compress', 'pack', or 'no_pack' (-P).

#### ``debug_flags`class-attribute``instance-attribute`

```text
debug_flags: Union[int, List[str]] = 0

```

Debug flags as integer value or list of flag names (-z).

#### ``disable_fpp`class-attribute``instance-attribute`

```text
disable_fpp: bool = False

```

If True, disables FPP instructions (IBM PC only) (-f).

#### ``disable_mouse`class-attribute``instance-attribute`

```text
disable_mouse: bool = False

```

If True, disables mouse support in text mode (-M).

#### ``empty_database`class-attribute``instance-attribute`

```text
empty_database: bool = False

```

If True, creates an empty database (-t).

#### ``entry_point`class-attribute``instance-attribute`

```text
entry_point: Optional[int] = None

```

Entry point address (-i).

#### ``file_member`class-attribute``instance-attribute`

```text
file_member: Optional[str] = None

```

Archive member name, used with file_type (-T).

#### ``file_type`class-attribute``instance-attribute`

```text
file_type: Optional[str] = None

```

File type prefix for input (-T).

#### ``first_pass_directives`class-attribute``instance-attribute`

```text
first_pass_directives: List[str] = field(
 default_factory=list
)

```

Directives for first pass configuration (-d).

#### ``jit_debugger`class-attribute``instance-attribute`

```text
jit_debugger: Optional[bool] = None

```

If set, enables/disables IDA as just-in-time debugger (-I).

#### ``load_resources`class-attribute``instance-attribute`

```text
load_resources: bool = False

```

If True, loads MS Windows exe resources (-R).

#### ``loading_address`class-attribute``instance-attribute`

```text
loading_address: Optional[int] = None

```

Address (in paragraphs, 16 bytes each) to load the file at (-b).

#### ``log_file`class-attribute``instance-attribute`

```text
log_file: Optional[str] = None

```

Path to the log file (-L).

#### ``new_database`class-attribute``instance-attribute`

```text
new_database: bool = False

```

If True, deletes the old database and creates a new one (-c).

#### ``no_segmentation`class-attribute``instance-attribute`

```text
no_segmentation: bool = False

```

If True, disables segmentation (-x).

#### ``output_database`class-attribute``instance-attribute`

```text
output_database: Optional[str] = None

```

Output database path (-o). Implies new_database.

#### ``plugin_options`class-attribute``instance-attribute`

```text
plugin_options: Optional[str] = None

```

Options to pass to plugins (-O).

#### ``processor`class-attribute``instance-attribute`

```text
processor: Optional[str] = None

```

Processor type identifier (-p).

#### ``run_debugger`class-attribute``instance-attribute`

```text
run_debugger: Optional[str] = None

```

Debugger options string to run immediately (-r).

#### ``script_args`class-attribute``instance-attribute`

```text
script_args: List[str] = field(default_factory=list)

```

Arguments to pass to the script file (-S).

#### ``script_file`class-attribute``instance-attribute`

```text
script_file: Optional[str] = None

```

Script file to execute when database opens (-S).

#### ``second_pass_directives`class-attribute``instance-attribute`

```text
second_pass_directives: List[str] = field(
 default_factory=list
)

```

Directives for second pass configuration (-D).

#### ``windows_dir`class-attribute``instance-attribute`

```text
windows_dir: Optional[str] = None

```

MS Windows directory path (-W).

#### ``build_args

```text
build_args() -> str

```

Construct the command line arguments string from the configured options.

Returns:

- `str` ( `str` ) –

All command line arguments for IDA, separated by spaces.

 Back to top

 Previous
 llms.txt

 Next
 Flowchart

 Copyright © 2025 Hex-Rays
 Made with Material for MkDocs
