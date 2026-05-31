# IDAPython type system API

- 官方来源：https://python.docs.hex-rays.com/ida_typeinf/index.html

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
- ida_typeinf
- View page source

# ida_typeinf

Type information in IDA.

In IDA, types are represented by and manipulated through tinfo_t objects. A tinfo_t can represent a simple type (e.g., int, float), a complex type (a structure, enum, union, typedef), or even an array, or a function prototype. The key types in this file are:

-
til_t - a type info library. Holds type information in serialized form.

-
tinfo_t - information about a type (simple, complex, …)

# Glossary All throughout this file, there are certain terms that will keep appearing:

-
udt: “user-defined type”: a structure or union - but not enums. See udt_type_data_t

-
udm: “udt member”: i.e., a structure or union member. See udm_t

-
edm: “enum member”: i.e., an enumeration member - i.e., an enumerator. See edm_t

# Under the hood The tinfo_t type provides a lot of useful methods already, but it’s possible to achieve even more by retrieving its contents into the container classes:

-
udt_type_data_t - for structures & unions. See tinfo_t::get_udt_details . Essentially, a vector of udm_t

-
enum_type_data_t - for enumerations. See tinfo_t::get_enum_details . Essentially, a vector of edm_t

-
ptr_type_data_t - for pointers. See tinfo_t::get_ptr_details

-
array_type_data_t - for arrays. See tinfo_t::get_array_details

-
func_type_data_t - for function prototypes. See tinfo_t::get_func_details

-
bitfield_type_data_t - for bitfields. See tinfo_t::get_bitfield_details

# Attached & detached tinfo_t objects tinfo_t objects can be attached to a til_t library, or can be created without using any til_t. Here is an example, assigning a function prototype: func_type_data_t func_info; funcarg_t argc; argc.name = “argc”; argc.type = tinfo_t(BT_INT); func_info.push_back(argc); funcarg_t argv; argc.name = “argv”; argc.type = tinfo_t(“const char **”); func_info.push_back(argv) tinfo_t tif; if ( tif.create_func(func_info) ) { ea_t ea = // get address of “main” apply_tinfo(ea, tif, TINFO_DEFINITE); } This code manipulates a “detached” tinfo_t object, which does not depend on any til_t file. However, any complex type will require a til_t file. In IDA, there is always a default til_t file for each idb file. This til_t file can be specified by nullptr. On the other hand, the following code manipulates an “attached” tinfo_t object, and any operation that modifies it, will also modify it in the hosting til_t: tinfo_t tif; Load type from the “Local Types” til_t. Note: we could have used get_idati() instead of nullptr if ( tif.get_named_type(nullptr, “my_struct_t”) ) tif.add_udm(“extra_field”, “unsigned long long”); You can check if a tinfo_t instance is attached to a type in a til_t file by calling tinfo_t::is_typeref

## Attributes

`DEFMASK64`
|
default bitmask 64bits

`RESERVED_BYTE`
|
multifunctional purpose

`TAH_BYTE`
|
type attribute header byte

`FAH_BYTE`
|
function argument attribute header byte

`MAX_DECL_ALIGN`
|

`TAH_HASATTRS`
|
has extended attributes

`TAUDT_UNALIGNED`
|
struct: unaligned struct

`TAUDT_MSSTRUCT`
|
struct: gcc msstruct attribute

`TAUDT_CPPOBJ`
|
struct: a C++ object, not simple pod type

`TAUDT_VFTABLE`
|
struct: is virtual function table

`TAUDT_FIXED`
|
struct: fixed field offsets, stored in serialized form; cannot be set for unions

`TAUDT_TUPLE`
|
tuple: tuples are like structs but are returned differently from functions

`TAUDT_IFACE`
|

`TAFLD_BASECLASS`
|
field: do not include but inherit from the current field

`TAFLD_UNALIGNED`
|
field: unaligned field

`TAFLD_VIRTBASE`
|
field: virtual base (not supported yet)

`TAFLD_VFTABLE`
|
field: ptr to virtual function table

`TAFLD_METHOD`
|
denotes a udt member function

`TAFLD_GAP`
|
field: gap member (displayed as padding in type details)

`TAFLD_REGCMT`
|
field: the comment is regular (if not set, it is repeatable)

`TAFLD_FRAME_R`
|
frame: function return address frame slot

`TAFLD_FRAME_S`
|
frame: function saved registers frame slot

`TAFLD_BYTIL`
|
field: was the member created due to the type system

`TAPTR_PTR32`
|
ptr: __ptr32

`TAPTR_PTR64`
|
ptr: __ptr64

`TAPTR_RESTRICT`
|
ptr: __restrict

`TAPTR_SHIFTED`
|
ptr: __shifted(parent_struct, delta)

`TAENUM_64BIT`
|
enum: store 64-bit values

`TAENUM_UNSIGNED`
|
enum: unsigned

`TAENUM_SIGNED`
|
enum: signed

`TAENUM_OCT`
|
enum: octal representation, if BTE_HEX

`TAENUM_BIN`
|
enum: binary representation, if BTE_HEX only one of OCT/BIN bits can be set. they are meaningful only if BTE_HEX is used.

`TAENUM_NUMSIGN`
|
enum: signed representation, if BTE_HEX

`TAENUM_LZERO`
|
enum: print numbers with leading zeros (only for HEX/OCT/BIN)

`TAH_ALL`
|
all defined bits

`cvar`
|

`TYPE_BASE_MASK`
|
the low 4 bits define the basic type

`TYPE_FLAGS_MASK`
|
type flags - they have different meaning depending on the basic type

`TYPE_MODIF_MASK`
|
modifiers.

`TYPE_FULL_MASK`
|
basic type with type flags

`BT_UNK`
|
unknown

`BT_VOID`
|
void

`BTMT_SIZE0`
|
BT_VOID - normal void; BT_UNK - don't use

`BTMT_SIZE12`
|
size = 1 byte if BT_VOID; 2 if BT_UNK

`BTMT_SIZE48`
|
size = 4 bytes if BT_VOID; 8 if BT_UNK

`BTMT_SIZE128`
|
size = 16 bytes if BT_VOID; unknown if BT_UNK (IN struct alignment - see below)

`BT_INT8`
|
__int8

`BT_INT16`
|
__int16

`BT_INT32`
|
__int32

`BT_INT64`
|
__int64

`BT_INT128`
|
__int128 (for alpha & future use)

`BT_INT`
|
natural int. (size provided by idp module)

`BTMT_UNKSIGN`
|
unknown signedness

`BTMT_SIGNED`
|
signed

`BTMT_USIGNED`
|
unsigned

`BTMT_UNSIGNED`
|

`BTMT_CHAR`
|
specify char or segment register

`BT_BOOL`
|
bool

`BTMT_DEFBOOL`
|
size is model specific or unknown(?)

`BTMT_BOOL1`
|
size 1 byte

`BTMT_BOOL2`
|
size 2 bytes - !inf_is_64bit()

`BTMT_BOOL8`
|
size 8 bytes - inf_is_64bit()

`BTMT_BOOL4`
|
size 4 bytes

`BT_FLOAT`
|
float

`BTMT_FLOAT`
|
float (4 bytes)

`BTMT_DOUBLE`
|
double (8 bytes)

`BTMT_LNGDBL`
|
long double (compiler specific)

`BTMT_SPECFLT`
|
float (variable size). if processor_t::use_tbyte() then use processor_t::tbyte_size, otherwise 2 bytes

`BT_PTR`
|
pointer. has the following format: [db sizeof(ptr)]; [tah-typeattrs]; type_t...

`BTMT_DEFPTR`
|
default for model

`BTMT_NEAR`
|
near

`BTMT_FAR`
|
far

`BTMT_CLOSURE`
|
closure.

`BT_ARRAY`
|
array

`BTMT_NONBASED`
|
set

`BTMT_ARRESERV`
|
reserved bit

`BT_FUNC`
|
function. format:

`BTMT_DEFCALL`
|
call method - default for model or unknown

`BTMT_NEARCALL`
|
function returns by retn

`BTMT_FARCALL`
|
function returns by retf

`BTMT_INTCALL`
|
function returns by iret in this case cc MUST be 'unknown'

`BT_COMPLEX`
|
struct/union/enum/typedef. format:

`BTMT_STRUCT`
|
struct: MCNT records: type_t; [sdacl-typeattrs];

`BTMT_UNION`
|
union: MCNT records: type_t...

`BTMT_ENUM`
|
enum: next byte bte_t (see below) N records: de delta(s) OR blocks (see below)

`BTMT_TYPEDEF`
|
named reference always p_string name

`BT_BITFIELD`
|
bitfield (only in struct) ['bitmasked' enum see below] next byte is dt ((size in bits << 1) | (unsigned ? 1 : 0))

`BTMT_BFLDI8`
|
__int8

`BTMT_BFLDI16`
|
__int16

`BTMT_BFLDI32`
|
__int32

`BTMT_BFLDI64`
|
__int64

`BT_RESERVED`
|
RESERVED.

`BTM_CONST`
|
const

`BTM_VOLATILE`
|
volatile

`BTE_SIZE_MASK`
|
storage size.

`BTE_RESERVED`
|
must be 0, in order to distinguish from a tah-byte

`BTE_BITMASK`
|
'subarrays'. In this case ANY record has the following format:

`BTE_OUT_MASK`
|
output style mask

`BTE_HEX`
|
hex

`BTE_CHAR`
|
char or hex

`BTE_SDEC`
|
signed decimal

`BTE_UDEC`
|
unsigned decimal

`BTE_ALWAYS`
|
this bit MUST be present

`BT_SEGREG`
|
segment register

`BT_UNK_BYTE`
|
1 byte

`BT_UNK_WORD`
|
2 bytes

`BT_UNK_DWORD`
|
4 bytes

`BT_UNK_QWORD`
|
8 bytes

`BT_UNK_OWORD`
|
16 bytes

`BT_UNKNOWN`
|
unknown size - for parameters

`BTF_BYTE`
|
byte

`BTF_UNK`
|
unknown

`BTF_VOID`
|
void

`BTF_INT8`
|
signed byte

`BTF_CHAR`
|
signed char

`BTF_UCHAR`
|
unsigned char

`BTF_UINT8`
|
unsigned byte

`BTF_INT16`
|
signed short

`BTF_UINT16`
|
unsigned short

`BTF_INT32`
|
signed int

`BTF_UINT32`
|
unsigned int

`BTF_INT64`
|
signed long

`BTF_UINT64`
|
unsigned long

`BTF_INT128`
|
signed 128-bit value

`BTF_UINT128`
|
unsigned 128-bit value

`BTF_INT`
|
int, unknown signedness

`BTF_UINT`
|
unsigned int

`BTF_SINT`
|
signed int

`BTF_BOOL`
|
boolean

`BTF_FLOAT`
|
float

`BTF_DOUBLE`
|
double

`BTF_LDOUBLE`
|
long double

`BTF_TBYTE`
|
see BTMT_SPECFLT

`BTF_STRUCT`
|
struct

`BTF_UNION`
|
union

`BTF_ENUM`
|
enum

`BTF_TYPEDEF`
|
typedef

`TA_ORG_TYPEDEF`
|
the original typedef name (simple string)

`TA_ORG_ARRDIM`
|
the original array dimension (pack_dd)

`TA_FORMAT`
|
info about the 'format' argument. 3 times pack_dd: format_functype_t, argument number of 'format', argument number of '...'

`TA_VALUE_REPR`
|
serialized value_repr_t (used for scalars and arrays)

`no_sign`
|
no sign, or unknown

`type_signed`
|
signed type

`type_unsigned`
|
unsigned type

`TIL_ZIP`
|
pack buckets using zip

`TIL_MAC`
|
til has macro table

`TIL_ESI`
|
extended sizeof info (short, long, longlong)

`TIL_UNI`
|
universal til for any compiler

`TIL_ORD`
|
type ordinal numbers are present

`TIL_ALI`
|
type aliases are present (this bit is used only on the disk)

`TIL_MOD`
|
til has been modified, should be saved

`TIL_STM`
|
til has extra streams

`TIL_SLD`
|
sizeof(long double)

`TIL_ECC`
|
extended callcnv_t

`TIL_ADD_FAILED`
|
see errbuf

`TIL_ADD_OK`
|
some tils were added

`TIL_ADD_ALREADY`
|
the base til was already added

`CM_MASK`
|

`CM_UNKNOWN`
|
unknown

`CM_N8_F16`
|
if sizeof(int)<=2: near 1 byte, far 2 bytes

`CM_N64`
|
if sizeof(int)>2: near 8 bytes, far 8 bytes

`CM_N16_F32`
|
near 2 bytes, far 4 bytes

`CM_N32_F48`
|
near 4 bytes, far 6 bytes

`CM_M_MASK`
|

`CM_M_NN`
|
small: code=near, data=near (or unknown if CM_UNKNOWN)

`CM_M_FF`
|
large: code=far, data=far

`CM_M_NF`
|
compact: code=near, data=far

`CM_M_FN`
|
medium: code=far, data=near

`CM_CC_MASK`
|

`CM_CC_INVALID`
|
this value is invalid

`CM_CC_UNKNOWN`
|
unknown calling convention

`CM_CC_VOIDARG`
|
function without arguments if has other cc and argnum == 0, represent as f() - unknown list

`CM_CC_CDECL`
|
stack

`CM_CC_ELLIPSIS`
|
cdecl + ellipsis

`CM_CC_STDCALL`
|
stack, purged

`CM_CC_PASCAL`
|
stack, purged, reverse order of args

`CM_CC_FASTCALL`
|
stack, purged (x86), first args are in regs (compiler-dependent)

`CM_CC_THISCALL`
|
stack, purged (x86), first arg is in reg (compiler-dependent)

`CM_CC_SWIFT`
|
(Swift) arguments and return values in registers (compiler-dependent)

`CM_CC_SPOILED`
|
This is NOT a cc! Mark of __spoil record the low nibble is count and after n {spoilreg_t} present real cm_t byte. if n == BFA_FUNC_MARKER, the next byte is the function attribute byte.

`CM_CC_GOLANG`
|
(Go) arguments and return value reg/stack depending on version

`CM_CC_RESERVE3`
|
reserved; used for internal needs

`CM_CC_SPECIALE`
|
CM_CC_SPECIAL with ellipsis

`CM_CC_SPECIALP`
|
Equal to CM_CC_SPECIAL, but with purged stack.

`CM_CC_SPECIAL`
|
usercall: locations of all arguments and the return value are explicitly specified

`CM_CC_LAST_USERCALL`
|

`CM_CC_GOSTK`
|
(Go) arguments and return value in stack

`CM_CC_FIRST_PLAIN_CUSTOM`
|

`BFA_NORET`
|
__noreturn

`BFA_PURE`
|
__pure

`BFA_HIGH`
|
high level prototype (with possibly hidden args)

`BFA_STATIC`
|
static

`BFA_VIRTUAL`
|
virtual

`BFA_FUNC_MARKER`
|
This is NOT a cc! (used internally as a marker)

`BFA_FUNC_EXT_FORMAT`
|
This is NOT a real attribute (used internally as marker for extended format)

`ALOC_NONE`
|
none

`ALOC_STACK`
|
stack offset

`ALOC_DIST`
|
distributed (scattered)

`ALOC_REG1`
|
one register (and offset within it)

`ALOC_REG2`
|
register pair

`ALOC_RREL`
|
register relative

`ALOC_STATIC`
|
global address

`ALOC_CUSTOM`
|
custom argloc (7 or higher)

`PRALOC_VERIFY`
|
interr if illegal argloc

`PRALOC_STKOFF`
|
print stack offsets

`C_PC_TINY`
|

`C_PC_SMALL`
|

`C_PC_COMPACT`
|

`C_PC_MEDIUM`
|

`C_PC_LARGE`
|

`C_PC_HUGE`
|

`C_PC_FLAT`
|

`CCI_VARARG`
|
is variadic?

`CCI_PURGE`
|
purges arguments?

`CCI_USER`
|
is usercall? not tested

`ARGREGS_POLICY_UNDEFINED`
|

`ARGREGS_GP_ONLY`
|
GP registers used for all arguments.

`ARGREGS_INDEPENDENT`
|
FP/GP registers used separately (like gcc64)

`ARGREGS_BY_SLOTS`
|
fixed FP/GP register per each slot (like vc64)

`ARGREGS_FP_MASKS_GP`
|
FP register also consumes one or more GP regs but not vice versa (aix ppc ABI)

`ARGREGS_MIPS_O32`
|
MIPS ABI o32.

`ARGREGS_RISCV`
|
Risc-V API FP arguments are passed in GP registers if FP registers are exhausted and GP ones are not. Wide FP arguments are passed in GP registers. Variadic FP arguments are passed in GP registers.

`SETCOMP_OVERRIDE`
|
may override old compiler info

`SETCOMP_ONLY_ID`
|
cc has only 'id' field; the rest will be set to defaults corresponding to the program bitness

`SETCOMP_ONLY_ABI`
|
ignore cc field complete, use only abiname

`SETCOMP_BY_USER`
|
invoked by user, cannot be replaced by module/loader

`MAX_FUNC_ARGS`
|
max number of function arguments

`MAX_ARRAY_NELEMS`
|
max number of array elements

`ABS_UNK`
|

`ABS_NO`
|

`ABS_YES`
|

`SC_UNK`
|
unknown

`SC_TYPE`
|
typedef

`SC_EXT`
|
extern

`SC_STAT`
|
static

`SC_REG`
|
register

`SC_AUTO`
|
auto

`SC_FRIEND`
|
friend

`SC_VIRT`
|
virtual

`HTI_CPP`
|
C++ mode (not implemented)

`HTI_INT`
|
debug: print internal representation of types

`HTI_EXT`
|
debug: print external representation of types

`HTI_LEX`
|
debug: print tokens

`HTI_UNP`
|
debug: check the result by unpacking it

`HTI_TST`
|
test mode: discard the result

`HTI_FIL`
|
"input" is file name, otherwise "input" contains a C declaration

`HTI_MAC`
|
define macros from the base tils

`HTI_NWR`
|
no warning messages

`HTI_NER`
|
ignore all errors but display them

`HTI_DCL`
|
don't complain about redeclarations

`HTI_NDC`
|
don't decorate names

`HTI_PAK`
|
explicit structure pack value (#pragma pack)

`HTI_PAK_SHIFT`
|
shift for HTI_PAK. This field should be used if you want to remember an explicit pack value for each structure/union type. See HTI_PAK... definitions

`HTI_PAKDEF`
|
default pack value

`HTI_PAK1`
|
#pragma pack(1)

`HTI_PAK2`
|
#pragma pack(2)

`HTI_PAK4`
|
#pragma pack(4)

`HTI_PAK8`
|
#pragma pack(8)

`HTI_PAK16`
|
#pragma pack(16)

`HTI_HIGH`
|
assume high level prototypes (with hidden args, etc)

`HTI_LOWER`
|
lower the function prototypes

`HTI_RAWARGS`
|
leave argument names unchanged (do not remove underscores)

`HTI_RELAXED`
|
accept references to unknown namespaces

`HTI_NOBASE`
|
do not inspect base tils

`HTI_SEMICOLON`
|
do not complain if the terminating semicolon is absent

`HTI_STANDALONE`
|
should parse standalone declaration, it may contain qualified name and type names, strictly speaking it is not a valid C++ code, IDA Pro specific

`HTI_VOID_OK`
|
accept void as a standalone type

`HTI_NO_MANGLE`
|
don't mangle name (see HTI_NDC)

`PT_SIL`
|
silent, no messages

`PT_NDC`
|
don't decorate names

`PT_TYP`
|
return declared type information

`PT_VAR`
|
return declared object information

`PT_PACKMASK`
|
mask for pack alignment values

`PT_HIGH`
|
assume high level prototypes (with hidden args, etc)

`PT_LOWER`
|
lower the function prototypes

`PT_REPLACE`
|
replace the old type (used in idc)

`PT_RAWARGS`
|
leave argument names unchanged (do not remove underscores)

`PT_RELAXED`
|
accept references to unknown namespaces

`PT_EMPTY`
|
accept empty decl

`PT_SEMICOLON`
|
append the terminating semicolon

`PT_SYMBOL`
|
accept a symbol name and return its type. e.g. "LoadLibrary" will return its prototype

`PT_VOID_OK`
|
accept void as a standalone type

`PT_NO_MANGLE`
|
don't mangle name (see PT_NDC)

`PRTYPE_1LINE`
|
print to one line

`PRTYPE_MULTI`
|
print to many lines

`PRTYPE_TYPE`
|
print type declaration (not variable declaration)

`PRTYPE_PRAGMA`
|
print pragmas for alignment

`PRTYPE_SEMI`
|
append ; to the end

`PRTYPE_CPP`
|
use c++ name (only for print_type())

`PRTYPE_DEF`
|
tinfo_t: print definition, if available

`PRTYPE_NOARGS`
|
tinfo_t: do not print function argument names

`PRTYPE_NOARRS`
|
tinfo_t: print arguments with FAI_ARRAY as pointers

`PRTYPE_NORES`
|
tinfo_t: never resolve types (meaningful with PRTYPE_DEF)

`PRTYPE_RESTORE`
|
tinfo_t: print restored types for FAI_ARRAY and FAI_STRUCT

`PRTYPE_NOREGEX`
|
do not apply regular expressions to beautify name

`PRTYPE_COLORED`
|
add color tag COLOR_SYMBOL for any parentheses, commas and colons

`PRTYPE_METHODS`
|
tinfo_t: print udt methods

`PRTYPE_1LINCMT`
|
print comments even in the one line mode

`PRTYPE_HEADER`
|
print only type header (only for definitions)

`PRTYPE_OFFSETS`
|
print udt member offsets

`PRTYPE_MAXSTR`
|
limit the output length to 1024 bytes (the output may be slightly longer)

`PRTYPE_TAIL`
|
print only the definition tail (only for definitions, exclusive with PRTYPE_HEADER)

`PRTYPE_ARGLOCS`
|
print function arglocs (not only for usercall)

`NTF_TYPE`
|
type name

`NTF_SYMU`
|
symbol, name is unmangled ('func')

`NTF_SYMM`
|
symbol, name is mangled ('_func'); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used

`NTF_NOBASE`
|
don't inspect base tils (for get_named_type)

`NTF_REPLACE`
|
replace original type (for set_named_type)

`NTF_UMANGLED`
|
name is unmangled (don't use this flag)

`NTF_NOCUR`
|
don't inspect current til file (for get_named_type)

`NTF_64BIT`
|
value is 64-bit

`NTF_FIXNAME`
|
force-validate the name of the type when setting (set_named_type, set_numbered_type only)

`NTF_IDBENC`
|
the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly (set_named_type, set_numbered_type only)

`NTF_CHKSYNC`
|
check that synchronization to IDB passed OK (set_numbered_type, set_named_type)

`NTF_NO_NAMECHK`
|
do not validate type name (set_numbered_type, set_named_type)

`NTF_COPY`
|
save a new type definition, not a typeref (tinfo_t::set_numbered_type, tinfo_t::set_named_type)

`TERR_OK`
|
ok

`TERR_SAVE_ERROR`
|
failed to save

`TERR_SERIALIZE`
|
failed to serialize

`TERR_BAD_NAME`
|
name s is not acceptable

`TERR_BAD_ARG`
|
bad argument

`TERR_BAD_TYPE`
|
bad type

`TERR_BAD_SIZE`
|
bad size d

`TERR_BAD_INDEX`
|
bad index d

`TERR_BAD_ARRAY`
|
arrays are forbidden as function arguments

`TERR_BAD_BF`
|
bitfields are forbidden as function arguments

`TERR_BAD_OFFSET`
|
bad member offset s

`TERR_BAD_UNIVAR`
|
unions cannot have variable sized members

`TERR_BAD_VARLAST`
|
variable sized member must be the last member in the structure

`TERR_OVERLAP`
|
the member overlaps with other members that cannot be deleted

`TERR_BAD_SUBTYPE`
|
recursive structure nesting is forbidden

`TERR_BAD_VALUE`
|
value 0xI64X is not acceptable

`TERR_NO_BMASK`
|
bitmask 0xI64X is not found

`TERR_BAD_BMASK`
|
Bad enum member mask 0xI64X. The specified mask should not intersect with any existing mask in the enum. Zero masks are prohibited too.

`TERR_BAD_MSKVAL`
|
bad bmask and value combination (value=0xI64X; bitmask 0xI64X)

`TERR_BAD_REPR`
|
bad or incompatible field representation

`TERR_GRP_NOEMPTY`
|
could not delete group mask for not empty group 0xI64X

`TERR_DUPNAME`
|
duplicate name s

`TERR_UNION_BF`
|
unions cannot have bitfields

`TERR_BAD_TAH`
|
bad bits in the type attributes (TAH bits)

`TERR_BAD_BASE`
|
bad base class

`TERR_BAD_GAP`
|
bad gap

`TERR_NESTED`
|
recursive structure nesting is forbidden

`TERR_NOT_COMPAT`
|
the new type is not compatible with the old type

`TERR_BAD_LAYOUT`
|
failed to calculate the structure/union layout

`TERR_BAD_GROUPS`
|
bad group sizes for bitmask enum

`TERR_BAD_SERIAL`
|
enum value has too many serials

`TERR_ALIEN_NAME`
|
enum member name is used in another enum

`TERR_STOCK`
|
stock type info cannot be modified

`TERR_ENUM_SIZE`
|
bad enum size

`TERR_NOT_IMPL`
|
not implemented

`TERR_TYPE_WORSE`
|
the new type is worse than the old type

`TERR_BAD_FX_SIZE`
|
cannot extend struct beyond fixed size

`TERR_STRUCT_SIZE`
|
bad fixed structure size

`TERR_NOT_FOUND`
|
member not found

`TERR_COUNT`
|

`CCN_C`
|

`CCN_CPP`
|

`ADDTIL_DEFAULT`
|
default behavior

`ADDTIL_INCOMP`
|
load incompatible tils

`ADDTIL_SILENT`
|
do not ask any questions

`ADDTIL_FAILED`
|
something bad, the warning is displayed

`ADDTIL_OK`
|
ok, til is loaded

`ADDTIL_COMP`
|
ok, but til is not compatible with the current compiler

`ADDTIL_ABORTED`
|
til was not loaded (incompatible til rejected by user)

`TINFO_GUESSED`
|
this is a guessed type

`TINFO_DEFINITE`
|
this is a definite type

`TINFO_DELAYFUNC`
|
if type is a function and no function exists at ea, schedule its creation and argument renaming to auto-analysis, otherwise try to create it immediately

`TINFO_STRICT`
|
never convert given type to another one before applying

`GUESS_FUNC_FAILED`
|
couldn't guess the function type

`GUESS_FUNC_TRIVIAL`
|
the function type doesn't have interesting info

`GUESS_FUNC_OK`
|
ok, some non-trivial information is gathered

`STI_PCHAR`
|
char *

`STI_PUCHAR`
|
uint8 *

`STI_PCCHAR`
|
const char *

`STI_PCUCHAR`
|
const uint8 *

`STI_PBYTE`
|
_BYTE *

`STI_PINT`
|
int *

`STI_PUINT`
|
unsigned int *

`STI_PVOID`
|
void *

`STI_PPVOID`
|
void **

`STI_PCVOID`
|
const void *

`STI_ACHAR`
|
char[]

`STI_AUCHAR`
|
uint8[]

`STI_ACCHAR`
|
const char[]

`STI_ACUCHAR`
|
const uint8[]

`STI_FPURGING`
|
void __userpurge(int)

`STI_FDELOP`
|
void __cdecl(void *)

`STI_MSGSEND`
|
void *(void *, const char *, ...)

`STI_AEABI_LCMP`
|
int __fastcall __pure(int64 x, int64 y)

`STI_AEABI_ULCMP`
|
int __fastcall __pure(uint64 x, uint64 y)

`STI_DONT_USE`
|
unused stock type id; should not be used

`STI_SIZE_T`
|
size_t

`STI_SSIZE_T`
|
ssize_t

`STI_AEABI_MEMCPY`
|
void __fastcall(void *, const void *, size_t)

`STI_AEABI_MEMSET`
|
void __fastcall(void *, size_t, int)

`STI_AEABI_MEMCLR`
|
void __fastcall(void *, size_t)

`STI_RTC_CHECK_2`
|
int16 __fastcall(int16 x)

`STI_RTC_CHECK_4`
|
int32 __fastcall(int32 x)

`STI_RTC_CHECK_8`
|
int64 __fastcall(int64 x)

`STI_COMPLEX64`
|
struct complex64_t { float real, imag; }

`STI_COMPLEX128`
|
struct complex128_t { double real, imag; }

`STI_PUNKNOWN`
|
_UNKNOWN *

`STI_LAST`
|

`ETF_NO_SAVE`
|
don't save to til (normally typerefs are saved to til) A call with ETF_NO_SAVE must be followed by a call without it. Otherwise there may be inconsistencies between the memory and the type library.

`ETF_NO_LAYOUT`
|
don't calc type layout before editing

`ETF_MAY_DESTROY`
|
may destroy other members

`ETF_COMPATIBLE`
|
new type must be compatible with the old

`ETF_FUNCARG`
|
udm - member is a function argument (cannot create arrays)

`ETF_FORCENAME`
|
anyway use name, see below for more usage description

`ETF_AUTONAME`
|
udm - generate a member name if was not specified (add_udm, set_udm_type)

`ETF_BYTIL`
|
udm - new type was created by the type subsystem

`ETF_NO_ARRAY`
|
add_udm, set_udm_type - do not convert type to an array on the size mismatch

`GTD_CALC_LAYOUT`
|
calculate udt layout

`GTD_NO_LAYOUT`
|
don't calculate udt layout please note that udt layout may have been calculated earlier

`GTD_DEL_BITFLDS`
|
delete udt bitfields

`GTD_CALC_ARGLOCS`
|
calculate func arg locations

`GTD_NO_ARGLOCS`
|
don't calculate func arg locations please note that the locations may have been calculated earlier

`GTS_NESTED`
|
nested type (embedded into a udt)

`GTS_BASECLASS`
|
is baseclass of a udt

`SUDT_SORT`
|
fields are not sorted by offset, sort them first

`SUDT_ALIGN`
|
recalculate field alignments, struct packing, etc to match the offsets and size info

`SUDT_GAPS`
|
allow to fill gaps with additional members (_BYTE[])

`SUDT_UNEX`
|
references to nonexistent member types are acceptable; in this case it is better to set the corresponding udm_t::fda field to the type alignment. If this field is not set, ida will try to guess the alignment.

`SUDT_FAST`
|
serialize without verifying offsets and alignments

`SUDT_CONST`
|
only for serialize_udt: make type const

`SUDT_VOLATILE`
|
only for serialize_udt: make type volatile

`SUDT_TRUNC`
|
serialize: truncate useless strings from fields, fldcmts

`SUDT_SERDEF`
|
serialize: if a typeref, serialize its definition

`COMP_MASK`
|

`COMP_UNK`
|
Unknown.

`COMP_MS`
|
Visual C++.

`COMP_BC`
|
Borland C++.

`COMP_WATCOM`
|
Watcom C++.

`COMP_GNU`
|
GNU C++.

`COMP_VISAGE`
|
Visual Age C++.

`COMP_BP`
|
Delphi.

`COMP_UNSURE`
|
uncertain compiler id

`BADSIZE`
|
bad type size

`FIRST_NONTRIVIAL_TYPID`
|
Denotes the first bit describing a nontrivial type.

`TYPID_ISREF`
|
Identifies that a type that is a typeref.

`TYPID_SHIFT`
|
First type detail bit.

`STRMEM_MASK`
|

`STRMEM_OFFSET`
|
get member by offset

`STRMEM_INDEX`
|
get member by number

`STRMEM_AUTO`
|
get member by offset if struct, or get member by index if union

`STRMEM_NAME`
|
get member by name

`STRMEM_TYPE`
|
get member by type.

`STRMEM_SIZE`
|
get member by size.

`STRMEM_MINS`
|
get smallest member by size.

`STRMEM_MAXS`
|
get biggest member by size.

`STRMEM_LOWBND`
|
get member by offset or the next member (lower bound)

`STRMEM_NEXT`
|
get next member after the offset

`STRMEM_VFTABLE`
|
can be combined with STRMEM_OFFSET, STRMEM_AUTO get vftable instead of the base class

`STRMEM_SKIP_EMPTY`
|
can be combined with STRMEM_OFFSET, STRMEM_AUTO skip empty members (i.e. having zero size) only last empty member can be returned

`STRMEM_CASTABLE_TO`
|
can be combined with STRMEM_TYPE: member type must be castable to the specified type

`STRMEM_ANON`
|
can be combined with STRMEM_NAME: look inside anonymous members too.

`STRMEM_SKIP_GAPS`
|
can be combined with STRMEM_OFFSET, STRMEM_LOWBND skip gap members

`TCMP_EQUAL`
|
are types equal?

`TCMP_IGNMODS`
|
ignore const/volatile modifiers

`TCMP_AUTOCAST`
|
can t1 be cast into t2 automatically?

`TCMP_MANCAST`
|
can t1 be cast into t2 manually?

`TCMP_CALL`
|
can t1 be called with t2 type?

`TCMP_DELPTR`
|
remove pointer from types before comparing

`TCMP_DECL`
|
compare declarations without resolving them

`TCMP_ANYBASE`
|
accept any base class when casting

`TCMP_SKIPTHIS`
|
skip the first function argument in comparison

`TCMP_DEEP_UDT`
|
compare udt by member/attributes

`FAI_HIDDEN`
|
hidden argument

`FAI_RETPTR`
|
pointer to return value. implies hidden

`FAI_STRUCT`
|
was initially a structure

`FAI_ARRAY`
|
was initially an array; see "__org_typedef" or "__org_arrdim" type attributes to determine the original type

`FAI_UNUSED`
|
argument is not used by the function

`FTI_SPOILED`
|
information about spoiled registers is present

`FTI_NORET`
|
noreturn

`FTI_PURE`
|
__pure

`FTI_HIGH`
|
high level prototype (with possibly hidden args)

`FTI_STATIC`
|
static

`FTI_VIRTUAL`
|
virtual

`FTI_CALLTYPE`
|
mask for FTI_*CALL

`FTI_DEFCALL`
|
default call

`FTI_NEARCALL`
|
near call

`FTI_FARCALL`
|
far call

`FTI_INTCALL`
|
interrupt call

`FTI_ARGLOCS`
|
info about argument locations has been calculated (stkargs and retloc too)

`FTI_EXPLOCS`
|
all arglocs are specified explicitly

`FTI_CONST`
|
const member function

`FTI_CTOR`
|
constructor

`FTI_DTOR`
|
destructor

`FTI_ALL`
|
all defined bits

`CC_CDECL_OK`
|
can use __cdecl calling convention?

`CC_ALLOW_ARGPERM`
|
disregard argument order?

`CC_ALLOW_REGHOLES`
|
allow holes in register argument list?

`CC_HAS_ELLIPSIS`
|
function has a variable list of arguments?

`CC_GOLANG_OK`
|
can use __golang calling convention

`FMTFUNC_PRINTF`
|

`FMTFUNC_SCANF`
|

`FMTFUNC_STRFTIME`
|

`FMTFUNC_STRFMON`
|

`MAX_ENUM_SERIAL`
|
Max number of identical constants allowed for one enum type.

`FRB_MASK`
|
Mask for the value type (* means requires additional info):

`FRB_UNK`
|
Unknown.

`FRB_NUMB`
|
Binary number.

`FRB_NUMO`
|
Octal number.

`FRB_NUMH`
|
Hexadecimal number.

`FRB_NUMD`
|
Decimal number.

`FRB_FLOAT`
|
Floating point number (for interpreting an integer type as a floating value)

`FRB_CHAR`
|
Char.

`FRB_SEG`
|
Segment.

`FRB_ENUM`
|
*Enumeration

`FRB_OFFSET`
|
*Offset

`FRB_STRLIT`
|
*String literal (used for arrays)

`FRB_STROFF`
|
*Struct offset

`FRB_CUSTOM`
|
*Custom data type

`FRB_INVSIGN`
|
Invert sign (0x01 is represented as -0xFF)

`FRB_INVBITS`
|
Invert bits (0x01 is represented as ~0xFE)

`FRB_SIGNED`
|
Force signed representation.

`FRB_LZERO`
|
Toggle leading zeros (used for integers)

`FRB_TABFORM`
|
has additional tabular parameters

`STRUC_SEPARATOR`
|
structname.fieldname

`VTBL_SUFFIX`
|

`VTBL_LAYOUT_SUFFIX`
|

`VTBL_MEMNAME`
|

`TPOS_LNNUM`
|

`TPOS_REGCMT`
|

`TVIS_TYPE`
|
new type info is present

`TVIS_NAME`
|
new name is present (only for funcargs and udt members)

`TVIS_CMT`
|
new comment is present (only for udt members)

`TVIS_RPTCMT`
|
the new comment is repeatable

`TVST_PRUNE`
|
don't visit children of current type

`TVST_DEF`
|
visit type definition (meaningful for typerefs)

`TVST_LEVEL`
|

`PIO_NOATTR_FAIL`
|
missing attributes are not ok

`PIO_IGNORE_PTRS`
|
do not follow pointers

`UTP_ENUM`
|

`UTP_STRUCT`
|

`VALSTR_OPEN`
|
printed opening curly brace '{'

`PDF_INCL_DEPS`
|
Include all type dependencies.

`PDF_DEF_FWD`
|
Allow forward declarations.

`PDF_DEF_BASE`
|
Include base types: __int8, __int16, etc..

`PDF_HEADER_CMT`
|
Prepend output with a descriptive comment.

`PDF_NO_ANON_NAME`
|
Ignore types with anonymous name.

`PT_FILE`
|

`PT_STANDALONE`
|

`cvar`
|

`sc_auto`
|

`sc_ext`
|

`sc_friend`
|

`sc_reg`
|

`sc_stat`
|

`sc_type`
|

`sc_unk`
|

`sc_virt`
|

`TERR_SAVE`
|

`TERR_WRONGNAME`
|

`BADORD`
|

`enum_member_vec_t`
|

`enum_member_t`
|

`udt_member_t`
|

## Classes

`funcargvec_t`
|

`reginfovec_t`
|

`edmvec_t`
|

`argpartvec_t`
|

`valstrvec_t`
|

`regobjvec_t`
|

`type_attrs_t`
|

`udtmembervec_template_t`
|

`qvector_simd_info_vec_t`
|

`type_attr_t`
|

`til_t`
|

`rrel_t`
|

`argloc_t`
|

`argpart_t`
|

`scattered_aloc_t`
|

`aloc_visitor_t`
|

`const_aloc_visitor_t`
|

`stkarg_area_info_t`
|

`custom_callcnv_t`
|

`callregs_t`
|

`tinfo_t`
|

`simd_info_t`
|

`simd_info_vec_t`
|

`ptr_type_data_t`
|

`array_type_data_t`
|

`funcarg_t`
|

`func_type_data_t`
|

`edm_t`
|

`enum_type_data_t`
|

`typedef_type_data_t`
|

`custom_data_type_info_t`
|

`value_repr_t`
|

`udm_t`
|

`udtmembervec_t`
|

`udt_type_data_t`
|

`udm_visitor_t`
|

`bitfield_type_data_t`
|

`type_mods_t`
|

`tinfo_visitor_t`
|

`regobj_t`
|

`regobjs_t`
|

`argtinfo_helper_t`
|

`lowertype_helper_t`
|

`ida_lowertype_helper_t`
|

`valstr_t`
|

`valstrs_t`
|

`text_sink_t`
|

`til_symbol_t`
|

`predicate_t`
|

`til_type_ref_t`
|

## Functions

`deserialize_tinfo`(→ bool)
|

`is_type_const`(→ bool)
|
See BTM_CONST.

`is_type_volatile`(→ bool)
|
See BTM_VOLATILE.

`get_base_type`(→ type_t)
|
Get basic type bits (TYPE_BASE_MASK)

`get_type_flags`(→ type_t)
|
Get type flags (TYPE_FLAGS_MASK)

`get_full_type`(→ type_t)
|
Get basic type bits + type flags (TYPE_FULL_MASK)

`is_typeid_last`(→ bool)
|
Is the type_t the last byte of type declaration? (there are no additional bytes after a basic type, see _BT_LAST_BASIC)

`is_type_partial`(→ bool)
|
Identifies an unknown or void type with a known size (see Basic type: unknown & void)

`is_type_void`(→ bool)
|
See BTF_VOID.

`is_type_unknown`(→ bool)
|
See BT_UNKNOWN.

`is_type_ptr`(→ bool)
|
See BT_PTR.

`is_type_complex`(→ bool)
|
See BT_COMPLEX.

`is_type_func`(→ bool)
|
See BT_FUNC.

`is_type_array`(→ bool)
|
See BT_ARRAY.

`is_type_typedef`(→ bool)
|
See BTF_TYPEDEF.

`is_type_sue`(→ bool)
|
Is the type a struct/union/enum?

`is_type_struct`(→ bool)
|
See BTF_STRUCT.

`is_type_union`(→ bool)
|
See BTF_UNION.

`is_type_struni`(→ bool)
|
Is the type a struct or union?

`is_type_enum`(→ bool)
|
See BTF_ENUM.

`is_type_bitfld`(→ bool)
|
See BT_BITFIELD.

`is_type_int`(→ bool)
|
Does the type_t specify one of the basic types in Basic type: integer?

`is_type_int128`(→ bool)
|
Does the type specify a 128-bit value? (signed or unsigned, see Basic type: integer)

`is_type_int64`(→ bool)
|
Does the type specify a 64-bit value? (signed or unsigned, see Basic type: integer)

`is_type_int32`(→ bool)
|
Does the type specify a 32-bit value? (signed or unsigned, see Basic type: integer)

`is_type_int16`(→ bool)
|
Does the type specify a 16-bit value? (signed or unsigned, see Basic type: integer)

`is_type_char`(→ bool)
|
Does the type specify a char value? (signed or unsigned, see Basic type: integer)

`is_type_paf`(→ bool)
|
Is the type a pointer, array, or function type?

`is_type_ptr_or_array`(→ bool)
|
Is the type a pointer or array type?

`is_type_floating`(→ bool)
|
Is the type a floating point type?

`is_type_integral`(→ bool)
|
Is the type an integral type (char/short/int/long/bool)?

`is_type_ext_integral`(→ bool)
|
Is the type an extended integral type? (integral or enum)

`is_type_arithmetic`(→ bool)
|
Is the type an arithmetic type? (floating or integral)

`is_type_ext_arithmetic`(→ bool)
|
Is the type an extended arithmetic type? (arithmetic or enum)

`is_type_uint`(→ bool)
|
See BTF_UINT.

`is_type_uchar`(→ bool)
|
See BTF_UCHAR.

`is_type_uint16`(→ bool)
|
See BTF_UINT16.

`is_type_uint32`(→ bool)
|
See BTF_UINT32.

`is_type_uint64`(→ bool)
|
See BTF_UINT64.

`is_type_uint128`(→ bool)
|
See BTF_UINT128.

`is_type_ldouble`(→ bool)
|
See BTF_LDOUBLE.

`is_type_double`(→ bool)
|
See BTF_DOUBLE.

`is_type_float`(→ bool)
|
See BTF_FLOAT.

`is_type_tbyte`(→ bool)
|
See BTF_FLOAT.

`is_type_bool`(→ bool)
|
See BTF_BOOL.

`is_tah_byte`(→ bool)
|
The TAH byte (type attribute header byte) denotes the start of type attributes. (see "tah-typeattrs" in the type bit definitions)

`is_sdacl_byte`(→ bool)
|
Identify an sdacl byte. The first sdacl byte has the following format: 11xx000x. The sdacl bytes are appended to udt fields. They indicate the start of type attributes (as the tah-bytes do). The sdacl bytes are used in the udt headers instead of the tah-byte. This is done for compatibility with old databases, they were already using sdacl bytes in udt headers and as udt field postfixes. (see "sdacl-typeattrs" in the type bit definitions)

`append_argloc`(→ bool)
|
Serialize argument location

`extract_argloc`(→ bool)
|
Deserialize an argument location. Argument FORBID_STKOFF checks location type. It can be used, for example, to check the return location of a function that cannot return a value in the stack

`resolve_typedef`(→ type_t const *)
|

`is_restype_void`(→ bool)
|

`is_restype_enum`(→ bool)
|

`is_restype_struni`(→ bool)
|

`is_restype_struct`(→ bool)
|

`get_scalar_bt`(→ type_t)
|

`new_til`(→ til_t *)
|
Initialize a til.

`load_til`(→ str)
|
Load til from a file without adding it to the database list (see also add_til). Failure to load base tils are reported into 'errbuf'. They do not prevent loading of the main til.

`compact_til`(→ bool)
|
Collect garbage in til. Must be called before storing the til.

`store_til`(→ bool)
|
Store til to a file. If the til contains garbage, it will be collected before storing the til. Your plugin should call compact_til() before calling store_til().

`free_til`(→ None)
|
Free memory allocated by til.

`load_til_header`(→ str)
|
Get human-readable til description.

`is_code_far`(→ bool)
|
Does the given model specify far code?

`is_data_far`(→ bool)
|
Does the given model specify far data?

`verify_argloc`(→ int)
|
Verify argloc_t.

`optimize_argloc`(→ bool)
|
Verify and optimize scattered argloc into simple form. All new arglocs must be processed by this function.

`print_argloc`(→ int)
|
Convert an argloc to human readable form.

`for_all_arglocs`(→ int)
|
Compress larger argloc types and initiate the aloc visitor.

`for_all_const_arglocs`(→ int)
|
See for_all_arglocs()

`is_user_cc`(→ bool)
|
Does the calling convention specify argument locations explicitly?

`is_vararg_cc`(→ bool)
|
Does the calling convention use ellipsis?

`is_purging_cc`(→ bool)
|
Does the calling convention clean the stack arguments upon return?

`is_golang_cc`(→ bool)
|
GO language calling convention (return value in stack)?

`is_custom_callcnv`(→ bool)
|
Is custom calling convention?

`is_swift_cc`(→ bool)
|
Swift calling convention (arguments and return values in registers)?

`get_stkarg_area_info`(→ bool)
|
Some calling conventions foresee special areas on the stack for call arguments. This structure lists their sizes.

`get_custom_callcnv`(→ custom_callcnv_t const *)
|
Retrieve custom calling convention details.

`find_custom_callcnv`(→ callcnv_t)
|
Find a calling convention by its name

`get_custom_callcnvs`(→ int)
|
Get all custom calling conventions

`get_comp`(→ comp_t)
|
Get compiler bits.

`get_compiler_name`(→ str)
|
Get full compiler name.

`get_compiler_abbr`(→ str)
|
Get abbreviated compiler name.

`get_compilers`(→ None)
|
Get names of all built-in compilers.

`is_comp_unsure`(→ comp_t)
|
See COMP_UNSURE.

`default_compiler`(→ comp_t)
|
Get compiler specified by inf.cc.

`is_gcc`(→ bool)
|
Is the target compiler COMP_GNU?

`is_gcc32`(→ bool)
|
Is the target compiler 32 bit gcc?

`is_gcc64`(→ bool)
|
Is the target compiler 64 bit gcc?

`gcc_layout`(→ bool)
|
Should use the struct/union layout as done by gcc?

`set_compiler`(→ bool)
|
Change current compiler.

`set_compiler_id`(→ bool)
|
Set the compiler id (see Compiler IDs)

`set_abi_name`(→ bool)
|
Set abi name (see Compiler IDs)

`get_abi_name`(→ str)
|
Get ABI name.

`append_abi_opts`(→ bool)
|
Add/remove/check ABI option General form of full abi name: abiname-opt1-opt2-... or -opt1-opt2-...

`remove_abi_opts`(→ bool)
|

`set_compiler_string`(→ bool)
|

`use_golang_cc`(→ bool)
|
is GOLANG calling convention used by default?

`switch_to_golang`(→ None)
|
switch to GOLANG calling convention (to be used as default CC)

`convert_pt_flags_to_hti`(→ int)
|
Convert Type parsing flags to Type formatting flags. Type parsing flags lesser than 0x10 don't have stable meaning and will be ignored (more on these flags can be seen in idc.idc)

`parse_decl`(→ str)
|
Parse ONE declaration. If the input string contains more than one declaration, the first complete type declaration (PT_TYP) or the last variable declaration (PT_VAR) will be used.

`parse_decls`(→ int)
|
Parse many declarations and store them in a til. If there are any errors, they will be printed using 'printer'. This function uses default include path and predefined macros from the database settings. It always uses the HTI_DCL bit.

`print_type`(→ str)
|
Get type declaration for the specified address.

`tinfo_errstr`(→ str)
|
Helper function to convert an error code into a printable string. Additional arguments are handled using the functions from err.h

`del_named_type`(→ bool)
|
Delete information about a symbol.

`first_named_type`(→ str)
|
Enumerate types.

`next_named_type`(→ str)
|
Enumerate types.

`copy_named_type`(→ int)
|
Copy a named type from one til to another. This function will copy the specified type and all dependent types from the source type library to the destination library.

`decorate_name`(→ str)
|
Decorate/undecorate a C symbol name.

`gen_decorate_name`(→ str)
|
Generic function for decorate_name() (may be used in IDP modules)

`calc_c_cpp_name`(→ str)
|
Get C or C++ form of the name.

`enable_numbered_types`(→ bool)
|
Enable the use of numbered types in til. Currently it is impossible to disable numbered types once they are enabled

`alloc_type_ordinals`(→ int)
|
Allocate a range of ordinal numbers for new types.

`alloc_type_ordinal`(→ int)
|
alloc_type_ordinals(ti, 1)

`get_ordinal_limit`(→ int)
|
Get number of allocated ordinals + 1. If there are no allocated ordinals, return 0. To enumerate all ordinals, use: for ( uint32 i = 1; i < limit; ++i )

`get_ordinal_count`(→ int)
|
Get number of allocated ordinals.

`del_numbered_type`(→ bool)
|
Delete a numbered type.

`set_type_alias`(→ bool)
|
Create a type alias. Redirects all references to source type to the destination type. This is equivalent to instantaneous replacement all references to srctype by dsttype.

`get_alias_target`(→ int)
|
Find the final alias destination. If the ordinal has not been aliased, return the specified ordinal itself If failed, returns 0.

`get_type_ordinal`(→ int)
|
Get type ordinal by its name.

`get_numbered_type_name`(→ str)
|
Get type name (if exists) by its ordinal. If the type is anonymous, returns "". If failed, returns nullptr

`create_numbered_type_name`(→ str)
|
Create anonymous name for numbered type. This name can be used to reference a numbered type by its ordinal Ordinal names have the following format: '#' + set_de(ord) Returns: -1 if error, otherwise the name length

`is_ordinal_name`(→ bool)
|
Check if the name is an ordinal name. Ordinal names have the following format: '#' + set_de(ord)

`is_type_choosable`(→ bool)
|
Check if a struct/union type is choosable

`set_type_choosable`(→ None)
|
Enable/disable 'choosability' flag for a struct/union type

`get_vftable_ea`(→ ida_idaapi.ea_t)
|
Get address of a virtual function table.

`get_vftable_ordinal`(→ int)
|
Get ordinal number of the virtual function table.

`set_vftable_ea`(→ bool)
|
Set the address of a vftable instance for a vftable type.

`del_vftable_ea`(→ bool)
|
Delete the address of a vftable instance for a vftable type.

`deref_ptr`(→ bool)
|
Dereference a pointer.

`add_til`(→ int)
|
Load a til file and add it the database type libraries list. IDA will also apply function prototypes for matching function names.

`del_til`(→ bool)
|
Unload a til file.

`apply_named_type`(→ bool)
|
Apply the specified named type to the address.

`apply_tinfo`(→ bool)
|
Apply the specified type to the specified address. This function sets the type and tries to convert the item at the specified address to conform the type.

`apply_cdecl`(→ bool)
|
Apply the specified type to the address. This function parses the declaration and calls apply_tinfo()

`apply_callee_tinfo`(→ bool)
|
Apply the type of the called function to the calling instruction. This function will append parameter comments and rename the local variables of the calling function. It also stores information about the instructions that initialize call arguments in the database. Use get_arg_addrs() to retrieve it if necessary. Alternatively it is possible to hook to processor_t::arg_addrs_ready event.

`apply_once_tinfo_and_name`(→ bool)
|
Apply the specified type and name to the address. This function checks if the address already has a type. If the old type

`guess_tinfo`(→ int)
|
Generate a type information about the id from the disassembly. id can be a structure/union/enum id or an address.

`set_c_header_path`(→ None)
|
Set include directory path the target compiler.

`get_c_header_path`(→ str)
|
Get the include directory path of the target compiler.

`set_c_macros`(→ None)
|
Set predefined macros for the target compiler.

`get_c_macros`(→ str)
|
Get predefined macros for the target compiler.

`get_idati`(→ til_t *)
|
Pointer to the local type library - this til is private for each IDB file Functions that accept til_t* default to idati when is nullptr provided.

`get_idainfo_by_type`(→ size_t *, flags64_t *, ...)
|
Extract information from a tinfo_t.

`get_tinfo_by_flags`(→ bool)
|
Get tinfo object that corresponds to data flags

`copy_tinfo_t`(→ None)
|

`detach_tinfo_t`(→ bool)
|

`clear_tinfo_t`(→ None)
|

`create_tinfo`(→ bool)
|

`verify_tinfo`(→ int)
|

`get_tinfo_details`(→ bool)
|

`get_tinfo_size`(→ int)
|

`get_tinfo_pdata`(→ int)
|

`get_tinfo_property`(→ int)
|

`get_tinfo_property4`(→ int)
|

`set_tinfo_property`(→ int)
|

`set_tinfo_property4`(→ int)
|

`serialize_tinfo`(→ bool)
|

`find_tinfo_udt_member`(→ int)
|

`print_tinfo`(→ str)
|

`dstr_tinfo`(→ str)
|

`visit_subtypes`(→ int)
|

`compare_tinfo`(→ bool)
|

`lexcompare_tinfo`(→ int)
|

`get_stock_tinfo`(→ bool)
|

`read_tinfo_bitfield_value`(→ uint64)
|

`write_tinfo_bitfield_value`(→ uint64)
|

`get_tinfo_attr`(→ bool)
|

`set_tinfo_attr`(→ bool)
|

`del_tinfo_attr`(→ bool)
|

`get_tinfo_attrs`(→ bool)
|

`set_tinfo_attrs`(→ bool)
|

`score_tinfo`(→ int)
|

`save_tinfo`(→ tinfo_code_t)
|

`append_tinfo_covered`(→ bool)
|

`calc_tinfo_gaps`(→ bool)
|

`value_repr_t__from_opinfo`(→ bool)
|

`value_repr_t__print_`(→ str)
|

`udt_type_data_t__find_member`(→ ssize_t)
|

`udt_type_data_t__get_best_fit_member`(→ ssize_t)
|

`udt_type_data_t__deduplicate_members`(→ bool)
|

`get_tinfo_by_edm_name`(→ ssize_t)
|

`remove_pointer`(→ tinfo_t)
|
BT_PTR: If the current type is a pointer, return the pointed object. If the current type is not a pointer, return the current type. See also get_ptrarr_object() and get_pointed_object()

`guess_func_cc`(→ callcnv_t)
|
Use func_type_data_t::guess_cc()

`dump_func_type_data`(→ str)
|
Use func_type_data_t::dump()

`calc_arglocs`(→ bool)
|

`calc_varglocs`(→ bool)
|

`stroff_as_size`(→ bool)
|
Should display a structure offset expression as the structure size?

`visit_stroff_udms`(→ adiff_t *)
|
Visit structure fields in a stroff expression or in a reference to a struct data variable. This function can be used to enumerate all components of an expression like 'a.b.c'.

`is_one_bit_mask`(→ bool)
|
Is bitmask one bit?

`inf_pack_stkargs`(→ bool)
|

`inf_big_arg_align`(→ bool)
|

`inf_huge_arg_align`(→ bool)
|

`unpack_idcobj_from_idb`(→ error_t)
|
Collection of register objects.

`unpack_idcobj_from_bv`(→ error_t)
|
Read a typed idc object from the byte vector.

`pack_idcobj_to_idb`(→ error_t)
|
Write a typed idc object to the database.

`pack_idcobj_to_bv`(→ error_t)
|
Write a typed idc object to the byte vector. Byte vector may be non-empty, this function will append data to it

`apply_tinfo_to_stkarg`(→ bool)
|
Helper function for the processor modules. to be called from processor_t::use_stkarg_type

`gen_use_arg_tinfos`(→ None)
|
Do not call this function directly, use argtinfo_helper_t.

`func_has_stkframe_hole`(→ bool)
|
Looks for a hole at the beginning of the stack arguments. Will make use of the IDB's func_t function at that place (if present) to help determine the presence of such a hole.

`lower_type`(→ int)
|
Lower type. Inspect the type and lower all function subtypes using lower_func_type().

`replace_ordinal_typerefs`(→ int)
|
Replace references to ordinal types by name references. This function 'unties' the type from the current local type library and makes it easier to export it.

`begin_type_updating`(→ None)
|
Mark the beginning of a large update operation on the types. Can be used with add_enum_member(), add_struc_member, etc... Also see end_type_updating()

`end_type_updating`(→ None)
|
Mark the end of a large update operation on the types (see begin_type_updating())

`get_named_type_tid`(→ tid_t)
|
Get named local type TID

`get_tid_name`(→ str)
|
Get a type name for the specified TID

`get_tid_ordinal`(→ int)
|
Get type ordinal number for TID

`get_udm_by_fullname`(→ ssize_t)
|
Get udt member by full name

`get_idainfo_by_udm`(→ bool)
|
Calculate IDA info from udt member

`create_enum_type`(→ tid_t)
|
Create type enum

`calc_number_of_children`(→ int)
|
Calculate max number of lines of a formatted c data, when expanded (PTV_EXPAND).

`get_enum_member_expr`(→ str)
|
Return a C expression that can be used to represent an enum member. If the value does not correspond to any single enum member, this function tries to find a bitwise combination of enum members that correspond to it. If more than half of value bits do not match any enum members, it fails.

`choose_named_type`(→ bool)
|
Choose a type from a type library.

`calc_retloc`(→ bool)
|
This function has the following signatures:

`choose_local_tinfo`(→ int)
|

`choose_local_tinfo_and_delta`(→ int)
|

`register_custom_callcnv`(→ custom_callcnv_t *)
|
Register a calling convention

`unregister_custom_callcnv`(→ custom_callcnv_t *)
|
Unregister a calling convention

`idc_parse_decl`(→ Tuple[str, bytes, bytes])
|

`calc_type_size`(til, type)
|
Returns the size of a type

`apply_type`(→ bool)
|
Apply the specified type to the address

`get_arg_addrs`(caller)
|
Retrieve addresses of argument initialization instructions

`unpack_object_from_idb`(til, type, fields, ea[, pio_flags])
|
Unpacks from the database at 'ea' to an object.

`unpack_object_from_bv`(til, type, fields, bytes[, ...])
|
Unpacks a buffer into an object.

`pack_object_to_idb`(obj, til, type, fields, ea[, pio_flags])
|
Write a typed object to the database.

`pack_object_to_bv`(obj, til, type, fields, base_ea[, ...])
|
Packs a typed object to a string

`idc_parse_types`(→ int)
|

`idc_get_type_raw`(→ PyObject *)
|

`idc_get_local_type_raw`(→ Tuple[bytes, bytes])
|

`idc_guess_type`(→ str)
|

`idc_get_type`(→ str)
|

`idc_set_local_type`(→ int)
|

`idc_get_local_type`(→ str)
|

`idc_print_type`(→ str)
|

`idc_get_local_type_name`(→ str)
|

`get_named_type`(til, name, ntf_flags)
|
Get a type data by its name.

`get_named_type64`(→ Union[Tuple[int, bytes, bytes, str, ...)
|
Get a named type from a type library.

`print_decls`(→ int)
|
Print types (and possibly their dependencies) in a format suitable for using in

`remove_tinfo_pointer`(→ Tuple[bool, str])
|
Remove pointer of a type. (i.e. convert "char *" into "char"). Optionally remove

`get_numbered_type`(→ Union[Tuple[bytes, bytes, str, ...)
|
Get a type from a type library, by its ordinal

`set_numbered_type`(→ tinfo_code_t)
|

## Module Contents

ida_typeinf.DEFMASK64
default bitmask 64bits
ida_typeinf.deserialize_tinfo(tif:tinfo_t, til:til_t, ptype:type_tconst**, pfields:p_listconst**, pfldcmts:p_listconst**, cmt:str=None)→boolclassida_typeinf.funcargvec_t(*args)
Bases: `object`
thisownpush_back(*args)→funcarg_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→funcarg_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:funcargvec_t)→Noneextract()→funcarg_t*inject(s:funcarg_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:funcarg_t, x:funcarg_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:funcarg_t)→booladd_unique(x:funcarg_t)→boolappend(x:funcarg_t)→Noneextend(x:funcargvec_t)→Nonefrontbackclassida_typeinf.reginfovec_t(*args)
Bases: `object`
thisownpush_back(*args)→reg_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→reg_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:reginfovec_t)→Noneextract()→reg_info_t*inject(s:reg_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:reg_info_t, x:reg_info_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:reg_info_t)→booladd_unique(x:reg_info_t)→boolappend(x:reg_info_t)→Noneextend(x:reginfovec_t)→Nonefrontbackclassida_typeinf.edmvec_t(*args)
Bases: `object`
thisownpush_back(*args)→edm_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→edm_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:edmvec_t)→Noneextract()→edm_t*inject(s:edm_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:edm_t, x:edm_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:edm_t)→booladd_unique(x:edm_t)→boolappend(x:edm_t)→Noneextend(x:edmvec_t)→Nonefrontbackclassida_typeinf.argpartvec_t(*args)
Bases: `object`
thisownpush_back(*args)→argpart_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→argpart_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:argpartvec_t)→Noneextract()→argpart_t*inject(s:argpart_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:argpart_t, x:argpart_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:argpart_t)→booladd_unique(x:argpart_t)→boolappend(x:argpart_t)→Noneextend(x:argpartvec_t)→Nonefrontbackclassida_typeinf.valstrvec_t(*args)
Bases: `object`
thisownpush_back(*args)→valstr_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→valstr_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:valstrvec_t)→Noneextract()→valstr_t*inject(s:valstr_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:valstr_t, x:valstr_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:valstr_t)→Noneextend(x:valstrvec_t)→Nonefrontbackclassida_typeinf.regobjvec_t(*args)
Bases: `object`
thisownpush_back(*args)→regobj_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→regobj_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:regobjvec_t)→Noneextract()→regobj_t*inject(s:regobj_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:regobj_t, x:regobj_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:regobj_t)→Noneextend(x:regobjvec_t)→Nonefrontbackclassida_typeinf.type_attrs_t(*args)
Bases: `object`
thisownpush_back(*args)→type_attr_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→type_attr_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:type_attrs_t)→Noneextract()→type_attr_t*inject(s:type_attr_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:type_attr_t, x:type_attr_t)→qvector::iteratorerase(*args)→qvector::iteratorappend(x:type_attr_t)→Noneextend(x:type_attrs_t)→Nonefrontbackclassida_typeinf.udtmembervec_template_t(*args)
Bases: `object`
thisownpush_back(*args)→udm_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→udm_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:udtmembervec_template_t)→Noneextract()→udm_t*inject(s:udm_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:udm_t, x:udm_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:udm_t)→booladd_unique(x:udm_t)→boolappend(x:udm_t)→Noneextend(x:udtmembervec_template_t)→Nonefrontbackclassida_typeinf.qvector_simd_info_vec_t(*args)
Bases: `object`
thisownpush_back(*args)→simd_info_t&pop_back()→Nonesize()→intempty()→boolat(_idx:int)→simd_info_tconst&qclear()→Noneclear()→Noneresize(*args)→Nonegrow(*args)→Nonecapacity()→intreserve(cnt:int)→Nonetruncate()→Noneswap(r:qvector_simd_info_vec_t)→Noneextract()→simd_info_t*inject(s:simd_info_t, len:int)→Nonebegin(*args)→qvector::const_iteratorend(*args)→qvector::const_iteratorinsert(it:simd_info_t, x:simd_info_t)→qvector::iteratorerase(*args)→qvector::iteratorfind(*args)→qvector::const_iteratorhas(x:simd_info_t)→booladd_unique(x:simd_info_t)→boolappend(x:simd_info_t)→Noneextend(x:qvector_simd_info_vec_t)→Nonefrontbackida_typeinf.RESERVED_BYTE
multifunctional purpose
ida_typeinf.is_type_const(t:type_t)→bool
See BTM_CONST.
ida_typeinf.is_type_volatile(t:type_t)→bool
See BTM_VOLATILE.
ida_typeinf.get_base_type(t:type_t)→type_t
Get basic type bits (TYPE_BASE_MASK)
ida_typeinf.get_type_flags(t:type_t)→type_t
Get type flags (TYPE_FLAGS_MASK)
ida_typeinf.get_full_type(t:type_t)→type_t
Get basic type bits + type flags (TYPE_FULL_MASK)
ida_typeinf.is_typeid_last(t:type_t)→bool
Is the type_t the last byte of type declaration? (there are no additional bytes after a basic type, see _BT_LAST_BASIC)
ida_typeinf.is_type_partial(t:type_t)→bool
Identifies an unknown or void type with a known size (see Basic type: unknown & void)
ida_typeinf.is_type_void(t:type_t)→bool
See BTF_VOID.
ida_typeinf.is_type_unknown(t:type_t)→bool
See BT_UNKNOWN.
ida_typeinf.is_type_ptr(t:type_t)→bool
See BT_PTR.
ida_typeinf.is_type_complex(t:type_t)→bool
See BT_COMPLEX.
ida_typeinf.is_type_func(t:type_t)→bool
See BT_FUNC.
ida_typeinf.is_type_array(t:type_t)→bool
See BT_ARRAY.
ida_typeinf.is_type_typedef(t:type_t)→bool
See BTF_TYPEDEF.
ida_typeinf.is_type_sue(t:type_t)→bool
Is the type a struct/union/enum?
ida_typeinf.is_type_struct(t:type_t)→bool
See BTF_STRUCT.
ida_typeinf.is_type_union(t:type_t)→bool
See BTF_UNION.
ida_typeinf.is_type_struni(t:type_t)→bool
Is the type a struct or union?
ida_typeinf.is_type_enum(t:type_t)→bool
See BTF_ENUM.
ida_typeinf.is_type_bitfld(t:type_t)→bool
See BT_BITFIELD.
ida_typeinf.is_type_int(bt:type_t)→bool
Does the type_t specify one of the basic types in Basic type: integer?
ida_typeinf.is_type_int128(t:type_t)→bool
Does the type specify a 128-bit value? (signed or unsigned, see Basic type: integer)
ida_typeinf.is_type_int64(t:type_t)→bool
Does the type specify a 64-bit value? (signed or unsigned, see Basic type: integer)
ida_typeinf.is_type_int32(t:type_t)→bool
Does the type specify a 32-bit value? (signed or unsigned, see Basic type: integer)
ida_typeinf.is_type_int16(t:type_t)→bool
Does the type specify a 16-bit value? (signed or unsigned, see Basic type: integer)
ida_typeinf.is_type_char(t:type_t)→bool
Does the type specify a char value? (signed or unsigned, see Basic type: integer)
ida_typeinf.is_type_paf(t:type_t)→bool
Is the type a pointer, array, or function type?
ida_typeinf.is_type_ptr_or_array(t:type_t)→bool
Is the type a pointer or array type?
ida_typeinf.is_type_floating(t:type_t)→bool
Is the type a floating point type?
ida_typeinf.is_type_integral(t:type_t)→bool
Is the type an integral type (char/short/int/long/bool)?
ida_typeinf.is_type_ext_integral(t:type_t)→bool
Is the type an extended integral type? (integral or enum)
ida_typeinf.is_type_arithmetic(t:type_t)→bool
Is the type an arithmetic type? (floating or integral)
ida_typeinf.is_type_ext_arithmetic(t:type_t)→bool
Is the type an extended arithmetic type? (arithmetic or enum)
ida_typeinf.is_type_uint(t:type_t)→bool
See BTF_UINT.
ida_typeinf.is_type_uchar(t:type_t)→bool
See BTF_UCHAR.
ida_typeinf.is_type_uint16(t:type_t)→bool
See BTF_UINT16.
ida_typeinf.is_type_uint32(t:type_t)→bool
See BTF_UINT32.
ida_typeinf.is_type_uint64(t:type_t)→bool
See BTF_UINT64.
ida_typeinf.is_type_uint128(t:type_t)→bool
See BTF_UINT128.
ida_typeinf.is_type_ldouble(t:type_t)→bool
See BTF_LDOUBLE.
ida_typeinf.is_type_double(t:type_t)→bool
See BTF_DOUBLE.
ida_typeinf.is_type_float(t:type_t)→bool
See BTF_FLOAT.
ida_typeinf.is_type_tbyte(t:type_t)→bool
See BTF_FLOAT.
ida_typeinf.is_type_bool(t:type_t)→bool
See BTF_BOOL.
ida_typeinf.TAH_BYTE
type attribute header byte
ida_typeinf.FAH_BYTE
function argument attribute header byte
ida_typeinf.MAX_DECL_ALIGNida_typeinf.TAH_HASATTRS
has extended attributes
ida_typeinf.TAUDT_UNALIGNED
struct: unaligned struct
ida_typeinf.TAUDT_MSSTRUCT
struct: gcc msstruct attribute
ida_typeinf.TAUDT_CPPOBJ
struct: a C++ object, not simple pod type
ida_typeinf.TAUDT_VFTABLE
struct: is virtual function table
ida_typeinf.TAUDT_FIXED
struct: fixed field offsets, stored in serialized form; cannot be set for unions
ida_typeinf.TAUDT_TUPLE
tuple: tuples are like structs but are returned differently from functions
ida_typeinf.TAUDT_IFACEida_typeinf.TAFLD_BASECLASS
field: do not include but inherit from the current field
ida_typeinf.TAFLD_UNALIGNED
field: unaligned field
ida_typeinf.TAFLD_VIRTBASE
field: virtual base (not supported yet)
ida_typeinf.TAFLD_VFTABLE
field: ptr to virtual function table
ida_typeinf.TAFLD_METHOD
denotes a udt member function
ida_typeinf.TAFLD_GAP
field: gap member (displayed as padding in type details)
ida_typeinf.TAFLD_REGCMT
field: the comment is regular (if not set, it is repeatable)
ida_typeinf.TAFLD_FRAME_R
frame: function return address frame slot
ida_typeinf.TAFLD_FRAME_S
frame: function saved registers frame slot
ida_typeinf.TAFLD_BYTIL
field: was the member created due to the type system
ida_typeinf.TAPTR_PTR32
ptr: __ptr32
ida_typeinf.TAPTR_PTR64
ptr: __ptr64
ida_typeinf.TAPTR_RESTRICT
ptr: __restrict
ida_typeinf.TAPTR_SHIFTED
ptr: __shifted(parent_struct, delta)
ida_typeinf.TAENUM_64BIT
enum: store 64-bit values
ida_typeinf.TAENUM_UNSIGNED
enum: unsigned
ida_typeinf.TAENUM_SIGNED
enum: signed
ida_typeinf.TAENUM_OCT
enum: octal representation, if BTE_HEX
ida_typeinf.TAENUM_BIN
enum: binary representation, if BTE_HEX only one of OCT/BIN bits can be set. they are meaningful only if BTE_HEX is used.
ida_typeinf.TAENUM_NUMSIGN
enum: signed representation, if BTE_HEX
ida_typeinf.TAENUM_LZERO
enum: print numbers with leading zeros (only for HEX/OCT/BIN)
ida_typeinf.TAH_ALL
all defined bits
ida_typeinf.is_tah_byte(t:type_t)→bool
The TAH byte (type attribute header byte) denotes the start of type attributes. (see “tah-typeattrs” in the type bit definitions)
ida_typeinf.is_sdacl_byte(t:type_t)→bool
Identify an sdacl byte. The first sdacl byte has the following format: 11xx000x. The sdacl bytes are appended to udt fields. They indicate the start of type attributes (as the tah-bytes do). The sdacl bytes are used in the udt headers instead of the tah-byte. This is done for compatibility with old databases, they were already using sdacl bytes in udt headers and as udt field postfixes. (see “sdacl-typeattrs” in the type bit definitions)
classida_typeinf.type_attr_t
Bases: `object`
thisownkey:str
one-symbol keys are reserved to be used by the kernel the ones starting with an underscore are reserved too
value:bytevec_t
attribute bytes
ida_typeinf.cvarida_typeinf.TYPE_BASE_MASK
the low 4 bits define the basic type
ida_typeinf.TYPE_FLAGS_MASK
type flags - they have different meaning depending on the basic type
ida_typeinf.TYPE_MODIF_MASK
modifiers. * for BT_ARRAY see Derived type: array * BT_VOID can have them ONLY in ‘void *’
ida_typeinf.TYPE_FULL_MASK
basic type with type flags
ida_typeinf.BT_UNK
unknown
ida_typeinf.BT_VOID
void
ida_typeinf.BTMT_SIZE0
BT_VOID - normal void; BT_UNK - don’t use
ida_typeinf.BTMT_SIZE12
size = 1 byte if BT_VOID; 2 if BT_UNK
ida_typeinf.BTMT_SIZE48
size = 4 bytes if BT_VOID; 8 if BT_UNK
ida_typeinf.BTMT_SIZE128
size = 16 bytes if BT_VOID; unknown if BT_UNK (IN struct alignment - see below)
ida_typeinf.BT_INT8
__int8
ida_typeinf.BT_INT16
__int16
ida_typeinf.BT_INT32
__int32
ida_typeinf.BT_INT64
__int64
ida_typeinf.BT_INT128
__int128 (for alpha & future use)
ida_typeinf.BT_INT
natural int. (size provided by idp module)
ida_typeinf.BTMT_UNKSIGN
unknown signedness
ida_typeinf.BTMT_SIGNED
signed
ida_typeinf.BTMT_USIGNED
unsigned
ida_typeinf.BTMT_UNSIGNEDida_typeinf.BTMT_CHAR
specify char or segment register * BT_INT8 - char * BT_INT - segment register * other BT_INT… - don’t use
ida_typeinf.BT_BOOL
bool
ida_typeinf.BTMT_DEFBOOL
size is model specific or unknown(?)
ida_typeinf.BTMT_BOOL1
size 1 byte
ida_typeinf.BTMT_BOOL2
size 2 bytes - !inf_is_64bit()
ida_typeinf.BTMT_BOOL8
size 8 bytes - inf_is_64bit()
ida_typeinf.BTMT_BOOL4
size 4 bytes
ida_typeinf.BT_FLOAT
float
ida_typeinf.BTMT_FLOAT
float (4 bytes)
ida_typeinf.BTMT_DOUBLE
double (8 bytes)
ida_typeinf.BTMT_LNGDBL
long double (compiler specific)
ida_typeinf.BTMT_SPECFLT
float (variable size). if processor_t::use_tbyte() then use processor_t::tbyte_size, otherwise 2 bytes
ida_typeinf.BT_PTR
pointer. has the following format: [db sizeof(ptr)]; [tah-typeattrs]; type_t…
ida_typeinf.BTMT_DEFPTR
default for model
ida_typeinf.BTMT_NEAR
near
ida_typeinf.BTMT_FAR
far
ida_typeinf.BTMT_CLOSURE
closure. * if ptr to BT_FUNC - __closure. in this case next byte MUST be RESERVED_BYTE, and after it BT_FUNC * else the next byte contains sizeof(ptr) allowed values are 1 - ph.max_ptr_size * if value is bigger than ph.max_ptr_size, based_ptr_name_and_size() is called to find out the typeinfo
ida_typeinf.BT_ARRAY
array
ida_typeinf.BTMT_NONBASEDset
array base==0 format: dt num_elem; [tah-typeattrs]; type_t… if num_elem==0 then the array size is unknown

format: da num_elem, base; [tah-typeattrs]; type_t…
ida_typeinf.BTMT_ARRESERV
reserved bit
ida_typeinf.BT_FUNC
function. format: optional: CM_CC_SPOILED | num_of_spoiled_regs

if num_of_spoiled_reg == BFA_FUNC_MARKER:
::bfa_byte if (bfa_byte & BFA_FUNC_EXT_FORMAT) != 0

::fti_bits (only low bits: FTI_SPOILED,…,FTI_VIRTUAL) num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)

else
bfa_byte is function attribute byte (see Function attribute byte…)
else:
num_of_spoiled_reg times: spoiled reg info (see extract_spoiledreg)

cm_t … calling convention and memory model [tah-typeattrs]; type_t … return type; [serialized argloc_t of returned value (if CM_CC_SPECIAL{PE} && !return void); if !CM_CC_VOIDARG:

dt N (N=number of parameters) if ( N == 0 ) if CM_CC_ELLIPSIS or CM_CC_SPECIALE

func(…)

else
parameters are unknown

elseN records:
type_t … (i.e. type of each parameter) [serialized argloc_t (if CM_CC_SPECIAL{PE})] (i.e. place of each parameter) [FAH_BYTE + de( funcarg_t::flags )]

ida_typeinf.BTMT_DEFCALL
call method - default for model or unknown
ida_typeinf.BTMT_NEARCALL
function returns by retn
ida_typeinf.BTMT_FARCALL
function returns by retf
ida_typeinf.BTMT_INTCALL
function returns by iret in this case cc MUST be ‘unknown’
ida_typeinf.BT_COMPLEX
struct/union/enum/typedef. format: [dt N (N=field count) if !BTMT_TYPEDEF] if N == 0:

p_string name (unnamed types have names “anon_…”) [sdacl-typeattrs];

else, for struct & union:if N == 0x7FFE // Support for high (i.e., > 4095) members count
N = deserialize_de()

ALPOW = N & 0x7 MCNT = N >> 3 if MCNT == 0

empty struct

if ALPOW == 0
ALIGN = get_default_align()
else
ALIGN = (1 << (ALPOW - 1))

[sdacl-typeattrs];
else, for enums:if N == 0x7FFE // Support for high enum entries count.
N = deserialize_de()

[tah-typeattrs];
ida_typeinf.BTMT_STRUCT
struct: MCNT records: type_t; [sdacl-typeattrs];
ida_typeinf.BTMT_UNION
union: MCNT records: type_t…
ida_typeinf.BTMT_ENUM
enum: next byte bte_t (see below) N records: de delta(s) OR blocks (see below)
ida_typeinf.BTMT_TYPEDEF
named reference always p_string name
ida_typeinf.BT_BITFIELD
bitfield (only in struct) [‘bitmasked’ enum see below] next byte is dt ((size in bits << 1) | (unsigned ? 1 : 0))
ida_typeinf.BTMT_BFLDI8
__int8
ida_typeinf.BTMT_BFLDI16
__int16
ida_typeinf.BTMT_BFLDI32
__int32
ida_typeinf.BTMT_BFLDI64
__int64
ida_typeinf.BT_RESERVED
RESERVED.
ida_typeinf.BTM_CONST
const
ida_typeinf.BTM_VOLATILE
volatile
ida_typeinf.BTE_SIZE_MASK
storage size. * if == 0 then inf_get_cc_size_e() * else 1 << (n -1) = 1,2,4,8 * n == 5,6,7 are reserved
ida_typeinf.BTE_RESERVED
must be 0, in order to distinguish from a tah-byte
ida_typeinf.BTE_BITMASK
‘subarrays’. In this case ANY record has the following format: * ‘de’ mask (has name) * ‘dt’ cnt * cnt records of ‘de’ values (cnt CAN be 0)
ida_typeinf.BTE_OUT_MASK
output style mask
ida_typeinf.BTE_HEX
hex
ida_typeinf.BTE_CHAR
char or hex
ida_typeinf.BTE_SDEC
signed decimal
ida_typeinf.BTE_UDEC
unsigned decimal
ida_typeinf.BTE_ALWAYS
this bit MUST be present
ida_typeinf.BT_SEGREG
segment register
ida_typeinf.BT_UNK_BYTE
1 byte
ida_typeinf.BT_UNK_WORD
2 bytes
ida_typeinf.BT_UNK_DWORD
4 bytes
ida_typeinf.BT_UNK_QWORD
8 bytes
ida_typeinf.BT_UNK_OWORD
16 bytes
ida_typeinf.BT_UNKNOWN
unknown size - for parameters
ida_typeinf.BTF_BYTE
byte
ida_typeinf.BTF_UNK
unknown
ida_typeinf.BTF_VOID
void
ida_typeinf.BTF_INT8
signed byte
ida_typeinf.BTF_CHAR
signed char
ida_typeinf.BTF_UCHAR
unsigned char
ida_typeinf.BTF_UINT8
unsigned byte
ida_typeinf.BTF_INT16
signed short
ida_typeinf.BTF_UINT16
unsigned short
ida_typeinf.BTF_INT32
signed int
ida_typeinf.BTF_UINT32
unsigned int
ida_typeinf.BTF_INT64
signed long
ida_typeinf.BTF_UINT64
unsigned long
ida_typeinf.BTF_INT128
signed 128-bit value
ida_typeinf.BTF_UINT128
unsigned 128-bit value
ida_typeinf.BTF_INT
int, unknown signedness
ida_typeinf.BTF_UINT
unsigned int
ida_typeinf.BTF_SINT
signed int
ida_typeinf.BTF_BOOL
boolean
ida_typeinf.BTF_FLOAT
float
ida_typeinf.BTF_DOUBLE
double
ida_typeinf.BTF_LDOUBLE
long double
ida_typeinf.BTF_TBYTE
see BTMT_SPECFLT
ida_typeinf.BTF_STRUCT
struct
ida_typeinf.BTF_UNION
union
ida_typeinf.BTF_ENUM
enum
ida_typeinf.BTF_TYPEDEF
typedef
ida_typeinf.TA_ORG_TYPEDEF
the original typedef name (simple string)
ida_typeinf.TA_ORG_ARRDIM
the original array dimension (pack_dd)
ida_typeinf.TA_FORMAT
info about the ‘format’ argument. 3 times pack_dd: format_functype_t, argument number of ‘format’, argument number of ‘…’
ida_typeinf.TA_VALUE_REPR
serialized value_repr_t (used for scalars and arrays)
ida_typeinf.append_argloc(out:qtype*, vloc:argloc_t)→bool
Serialize argument location
ida_typeinf.extract_argloc(vloc:argloc_t, ptype:type_tconst**, forbid_stkoff:bool)→bool
Deserialize an argument location. Argument FORBID_STKOFF checks location type. It can be used, for example, to check the return location of a function that cannot return a value in the stack
ida_typeinf.resolve_typedef(til:til_t, type:type_tconst*)→type_tconst*ida_typeinf.is_restype_void(til:til_t, type:type_tconst*)→boolida_typeinf.is_restype_enum(til:til_t, type:type_tconst*)→boolida_typeinf.is_restype_struni(til:til_t, type:type_tconst*)→boolida_typeinf.is_restype_struct(til:til_t, type:type_tconst*)→boolida_typeinf.get_scalar_bt(size:int)→type_tclassida_typeinf.til_t
Bases: `object`
thisownname:char*
short file name (without path and extension)
desc:char*
human readable til description
nbases:int
number of base tils
flags:int
Type info library property bits
is_dirty()→bool
Has the til been modified? (TIL_MOD)
set_dirty()→None
Mark the til as modified (TIL_MOD)
find_base(n:str)→til_t*
Find the base til with the provided name
Parameters:
n – the base til name
Returns:
the found til_t, or nullptr
cc:compiler_info_t
information about the target compiler
nrefs:int
number of references to the til
nstreams:int
number of extra streams
streams:til_stream_t**
symbol stream storage
base(n:int)→til_t*import_type(src)
Import a type (and all its dependencies) into this type info library.
Parameters:
src – The type to import
Returns:
the imported copy, or None
named_types()
Returns a generator over the named types contained in this type library.

Every iteration returns a fresh new tinfo_t object
Returns:
a tinfo_t-producing generator
numbered_types()
Returns a generator over the numbered types contained in this type library.

Every iteration returns a fresh new tinfo_t object
Returns:
a tinfo_t-producing generator
get_named_type(name)
Retrieves a tinfo_t representing the named type in this type library.
Parameters:
name – a type name
Returns:
a new tinfo_t object, or None if not found
get_numbered_type(ordinal)
Retrieves a tinfo_t representing the numbered type in this type library.
Parameters:
ordinal – a type ordinal
Returns:
a new tinfo_t object, or None if not found
get_type_names()type_namesida_typeinf.no_sign
no sign, or unknown
ida_typeinf.type_signed
signed type
ida_typeinf.type_unsigned
unsigned type
ida_typeinf.TIL_ZIP
pack buckets using zip
ida_typeinf.TIL_MAC
til has macro table
ida_typeinf.TIL_ESI
extended sizeof info (short, long, longlong)
ida_typeinf.TIL_UNI
universal til for any compiler
ida_typeinf.TIL_ORD
type ordinal numbers are present
ida_typeinf.TIL_ALI
type aliases are present (this bit is used only on the disk)
ida_typeinf.TIL_MOD
til has been modified, should be saved
ida_typeinf.TIL_STM
til has extra streams
ida_typeinf.TIL_SLD
sizeof(long double)
ida_typeinf.TIL_ECC
extended callcnv_t
ida_typeinf.new_til(name:str, desc:str)→til_t*
Initialize a til.
ida_typeinf.TIL_ADD_FAILED
see errbuf
ida_typeinf.TIL_ADD_OK
some tils were added
ida_typeinf.TIL_ADD_ALREADY
the base til was already added
ida_typeinf.load_til(name:str, tildir:str=None)→str
Load til from a file without adding it to the database list (see also add_til). Failure to load base tils are reported into ‘errbuf’. They do not prevent loading of the main til.
Parameters:
name – filename of the til. If it’s an absolute path, tildir is ignored.

-
NB: the file extension is forced to .til

Parameters:
tildir – directory where to load the til from. nullptr means default til subdirectories.
Returns:
pointer to resulting til, nullptr if failed and error message is in errbuf
ida_typeinf.compact_til(ti:til_t)→bool
Collect garbage in til. Must be called before storing the til.
Returns:
true if any memory was freed
ida_typeinf.store_til(ti:til_t, tildir:str, name:str)→bool
Store til to a file. If the til contains garbage, it will be collected before storing the til. Your plugin should call compact_til() before calling store_til().
Parameters:

-
ti – type library to store

-
tildir – directory where to store the til. nullptr means current directory.

-
name – filename of the til. If it’s an absolute path, tildir is ignored.

-
NB: the file extension is forced to .til

Returns:
success
ida_typeinf.free_til(ti:til_t)→None
Free memory allocated by til.
ida_typeinf.load_til_header(tildir:str, name:str)→str
Get human-readable til description.
ida_typeinf.is_code_far(cm:cm_t)→bool
Does the given model specify far code?
ida_typeinf.is_data_far(cm:cm_t)→bool
Does the given model specify far data?
classida_typeinf.rrel_t
Bases: `object`
thisownoff:int
displacement from the address pointed by the register
reg:int
register index (into ph.reg_names)
ida_typeinf.CM_MASKida_typeinf.CM_UNKNOWN
unknown
ida_typeinf.CM_N8_F16
if sizeof(int)<=2: near 1 byte, far 2 bytes
ida_typeinf.CM_N64
if sizeof(int)>2: near 8 bytes, far 8 bytes
ida_typeinf.CM_N16_F32
near 2 bytes, far 4 bytes
ida_typeinf.CM_N32_F48
near 4 bytes, far 6 bytes
ida_typeinf.CM_M_MASKida_typeinf.CM_M_NN
small: code=near, data=near (or unknown if CM_UNKNOWN)
ida_typeinf.CM_M_FF
large: code=far, data=far
ida_typeinf.CM_M_NF
compact: code=near, data=far
ida_typeinf.CM_M_FN
medium: code=far, data=near
ida_typeinf.CM_CC_MASKida_typeinf.CM_CC_INVALID
this value is invalid
ida_typeinf.CM_CC_UNKNOWN
unknown calling convention
ida_typeinf.CM_CC_VOIDARG
function without arguments if has other cc and argnum == 0, represent as f() - unknown list
ida_typeinf.CM_CC_CDECL
stack
ida_typeinf.CM_CC_ELLIPSIS
cdecl + ellipsis
ida_typeinf.CM_CC_STDCALL
stack, purged
ida_typeinf.CM_CC_PASCAL
stack, purged, reverse order of args
ida_typeinf.CM_CC_FASTCALL
stack, purged (x86), first args are in regs (compiler-dependent)
ida_typeinf.CM_CC_THISCALL
stack, purged (x86), first arg is in reg (compiler-dependent)
ida_typeinf.CM_CC_SWIFT
(Swift) arguments and return values in registers (compiler-dependent)
ida_typeinf.CM_CC_SPOILED
This is NOT a cc! Mark of __spoil record the low nibble is count and after n {spoilreg_t} present real cm_t byte. if n == BFA_FUNC_MARKER, the next byte is the function attribute byte.
ida_typeinf.CM_CC_GOLANG
(Go) arguments and return value reg/stack depending on version
ida_typeinf.CM_CC_RESERVE3
reserved; used for internal needs
ida_typeinf.CM_CC_SPECIALE
CM_CC_SPECIAL with ellipsis
ida_typeinf.CM_CC_SPECIALP
Equal to CM_CC_SPECIAL, but with purged stack.
ida_typeinf.CM_CC_SPECIAL
usercall: locations of all arguments and the return value are explicitly specified
ida_typeinf.CM_CC_LAST_USERCALLida_typeinf.CM_CC_GOSTK
(Go) arguments and return value in stack
ida_typeinf.CM_CC_FIRST_PLAIN_CUSTOMida_typeinf.BFA_NORET
__noreturn
ida_typeinf.BFA_PURE
__pure
ida_typeinf.BFA_HIGH
high level prototype (with possibly hidden args)
ida_typeinf.BFA_STATIC
static
ida_typeinf.BFA_VIRTUAL
virtual
ida_typeinf.BFA_FUNC_MARKER
This is NOT a cc! (used internally as a marker)
ida_typeinf.BFA_FUNC_EXT_FORMAT
This is NOT a real attribute (used internally as marker for extended format)
ida_typeinf.ALOC_NONE
none
ida_typeinf.ALOC_STACK
stack offset
ida_typeinf.ALOC_DIST
distributed (scattered)
ida_typeinf.ALOC_REG1
one register (and offset within it)
ida_typeinf.ALOC_REG2
register pair
ida_typeinf.ALOC_RREL
register relative
ida_typeinf.ALOC_STATIC
global address
ida_typeinf.ALOC_CUSTOM
custom argloc (7 or higher)
classida_typeinf.argloc_t(*args)
Bases: `object`
thisownswap(r:argloc_t)→None
Assign this == r and r == this.
atype()→argloc_type_t
Get type (Argument location types)
is_reg1()→bool
See ALOC_REG1.
is_reg2()→bool
See ALOC_REG2.
is_reg()→bool
is_reg1() || is_reg2()
is_rrel()→bool
See ALOC_RREL.
is_ea()→bool
See ALOC_STATIC.
is_stkoff()→bool
See ALOC_STACK.
is_scattered()→bool
See ALOC_DIST.
has_reg()→bool
TRUE if argloc has a register part.
has_stkoff()→bool
TRUE if argloc has a stack part.
is_mixed_scattered()→bool
mixed scattered: consists of register and stack parts
in_stack()→bool
TRUE if argloc is in stack entirely.
is_fragmented()→bool
is_scattered() || is_reg2()
is_custom()→bool
See ALOC_CUSTOM.
is_badloc()→bool
See ALOC_NONE.
reg1()→int
Get the register info. Use when atype() == ALOC_REG1 or ALOC_REG2
regoff()→int
Get offset from the beginning of the register in bytes. Use when atype() == ALOC_REG1
reg2()→int
Get info for the second register. Use when atype() == ALOC_REG2
get_reginfo()→int
Get all register info. Use when atype() == ALOC_REG1 or ALOC_REG2
stkoff()→int
Get the stack offset. Use if atype() == ALOC_STACK
get_ea()→ida_idaapi.ea_t
Get the global address. Use when atype() == ALOC_STATIC
scattered()→scattered_aloc_t&
Get scattered argument info. Use when atype() == ALOC_DIST
get_rrel()→rrel_t&
Get register-relative info. Use when atype() == ALOC_RREL
get_custom()→void*
Get custom argloc info. Use if atype() == ALOC_CUSTOM
get_biggest()→argloc_t::biggest_t
Get largest element in internal union.
set_reg1(reg:int, off:int=0)→None
Set register location.
set_reg2(_reg1:int, _reg2:int)→None
Set secondary register location.
set_stkoff(off:int)→None
Set stack offset location.
set_ea(_ea:ida_idaapi.ea_t)→None
Set static ea location.
consume_rrel(p:rrel_t)→None
Set register-relative location - can’t be nullptr.
set_badloc()→None
Set to invalid location.
calc_offset()→int
Calculate offset that can be used to compare 2 similar arglocs.
advance(delta:int)→bool
Move the location to point ‘delta’ bytes further.
align_reg_high(size:int, _slotsize:int)→None
Set register offset to align it to the upper part of _SLOTSIZE.
align_stkoff_high(size:int, _slotsize:int)→None
Set stack offset to align to the upper part of _SLOTSIZE.
compare(r:argloc_t)→intconsume_scattered(p:scattered_aloc_t)→None
Set distributed argument location.
classida_typeinf.argpart_t(*args)
Bases: `argloc_t`
thisownoff:ushort
offset from the beginning of the argument
size:ushort
the number of bytes
bad_offset()→bool
Does this argpart have a valid offset?
bad_size()→bool
Does this argpart have a valid size?
swap(r:argpart_t)→None
Assign this = r and r = this.
classida_typeinf.scattered_aloc_t
Bases: `argpartvec_t`
thisownida_typeinf.verify_argloc(vloc:argloc_t, size:int, gaps:rangeset_t)→int
Verify argloc_t.
Parameters:

-
vloc – argloc to verify

-
size – total size of the variable

-
gaps – if not nullptr, specifies gaps in structure definition. these gaps should not map to any argloc, but everything else must be covered

Returns:
0 if ok, otherwise an interr code.
ida_typeinf.optimize_argloc(vloc:argloc_t, size:int, gaps:rangeset_t)→bool
Verify and optimize scattered argloc into simple form. All new arglocs must be processed by this function.
Returns:
true: success
Returns:
false: the input argloc was illegal
ida_typeinf.print_argloc(vloc:argloc_t, size:int=0, vflags:int=0)→int
Convert an argloc to human readable form.
ida_typeinf.PRALOC_VERIFY
interr if illegal argloc
ida_typeinf.PRALOC_STKOFF
print stack offsets
classida_typeinf.aloc_visitor_t
Bases: `object`
thisownvisit_location(v:argloc_t, off:int, size:int)→intida_typeinf.for_all_arglocs(vv:aloc_visitor_t, vloc:argloc_t, size:int, off:int=0)→int
Compress larger argloc types and initiate the aloc visitor.
classida_typeinf.const_aloc_visitor_t
Bases: `object`
thisownvisit_location(v:argloc_t, off:int, size:int)→intida_typeinf.for_all_const_arglocs(vv:const_aloc_visitor_t, vloc:argloc_t, size:int, off:int=0)→int
See for_all_arglocs()
ida_typeinf.is_user_cc(cc:callcnv_t)→bool
Does the calling convention specify argument locations explicitly?
ida_typeinf.is_vararg_cc(cc:callcnv_t)→bool
Does the calling convention use ellipsis?
ida_typeinf.is_purging_cc(cc:callcnv_t)→bool
Does the calling convention clean the stack arguments upon return?
ida_typeinf.is_golang_cc(cc:callcnv_t)→bool
GO language calling convention (return value in stack)?
ida_typeinf.is_custom_callcnv(cc:callcnv_t)→bool
Is custom calling convention?
ida_typeinf.is_swift_cc(cc:callcnv_t)→bool
Swift calling convention (arguments and return values in registers)?
ida_typeinf.get_stkarg_area_info(out:stkarg_area_info_t, cc:callcnv_t)→bool
Some calling conventions foresee special areas on the stack for call arguments. This structure lists their sizes.
classida_typeinf.stkarg_area_info_t(*args)
Bases: `object`
thisowncb:intstkarg_offset:int
Offset from the SP to the first stack argument (can include linkage area) examples: pc: 0, hppa: -0x34, ppc aix: 0x18
shadow_size:int
Size of the shadow area. explanations at: [https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly](https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly) examples: x64 Visual Studio C++: 0x20, x64 gcc: 0, ppc aix: 0x20
linkage_area:int
Size of the linkage area. explanations at: [https://www.ibm.com/docs/en/xl-fortran-aix/16.1.0?topic=conventions-linkage-area](https://www.ibm.com/docs/en/xl-fortran-aix/16.1.0?topic=conventions-linkage-area) examples: pc: 0, hppa: 0, ppc aix: 0x18 (equal to stkarg_offset)
ida_typeinf.C_PC_TINYida_typeinf.C_PC_SMALLida_typeinf.C_PC_COMPACTida_typeinf.C_PC_MEDIUMida_typeinf.C_PC_LARGEida_typeinf.C_PC_HUGEida_typeinf.C_PC_FLATclassida_typeinf.custom_callcnv_t(*args)
Bases: `object`
thisownflags:uint64name:str
the name is used as a keyword in the function prototype
abibits:int
abibits to be used for the calling convention
is_vararg()→boolis_purging()→boolis_usercall()→boolvalidate_func(fti:func_type_data_t, reterr:str)→bool
Validate a function prototype. This function is used during parsing or deserializing a function prototype to verify semantic limitations of the prototype (for example, returning arrays is forbidden in C)
Parameters:

-
fti – function prototype

-
reterr – buffer for error message

calc_retloc(fti:func_type_data_t)→bool
Calculate the location of the return value. This function must fill fti->retloc.
Parameters:
fti – function prototype
Returns:
success
calc_arglocs(fti:func_type_data_t)→bool
Calculate the argument locations. This function must fill all fti->at(i).argloc instances. It may be called for variadic functions too, in calc_varglocs fails.
Parameters:
fti – function prototype
Returns:
success
find_varargs(fti:func_type_data_t, call_ea:ida_idaapi.ea_t, blk:mblock_t*)→ssize_t
Discover variadic arguments. This function is called only for variadic functions. It is currently used by the decompiler.
Parameters:

-
fti – function prototype. find_varargs() should append the discovered variadic arguments to it.

-
call_ea – address of the call instruction

-
blk – microcode block with the call instruction

Returns:
>0 - total number of arguments after the call <0 - failure ==0 - means to use the standard algorithm to discover variadic args
calc_varglocs(fti:func_type_data_t, regs:regobjs_t, stkargs:relobj_t, nfixed:int)→bool
Calculate the argument locations for a variadic function. This function must fill all fti->at(i).argloc instances and provide more detailed info about registers and stkargs.
Parameters:

-
fti – function prototype

-
regs – buffer for hidden register arguments, may be nullptr

-
stkargs – buffer for hidden stack arguments, may be nullptr

-
nfixed – number of fixed arguments

Returns:
success
get_cc_regs(out:callregs_t)→bool
Retrieve generic information about call registers.
get_stkarg_area_info(out:stkarg_area_info_t)→bool
Retrieve generic information about stack arguments.
calc_purged_bytes(*args)→int
Calculate the number of purged bytes
Parameters:

-
fti – function prototype

-
call_ea – address of the call instruction (not used yet)

decorate_name(name:str, should_decorate:bool, cc:callcnv_t, type:tinfo_t)→bool
Function to be overloaded for custom calling conventions.

Decorate a function name. Some compilers decorate names depending on the calling convention. This function provides the means to handle it for custom callcnvs. Please note that this is about name decoration (C), not name mangling (C++).
lower_func_type(fti:func_type_data_t)→int
Lower a function type. See lower_type() for more explanations.
Parameters:
fti – function prototype
Returns:
=0-ok, 2-made substantial changes
ida_typeinf.CCI_VARARG
is variadic?
ida_typeinf.CCI_PURGE
purges arguments?
ida_typeinf.CCI_USER
is usercall? not tested
ida_typeinf.get_custom_callcnv(callcnv:callcnv_t)→custom_callcnv_tconst*
Retrieve custom calling convention details.
ida_typeinf.find_custom_callcnv(name:str)→callcnv_t
Find a calling convention by its name
Returns:
CM_CC_INVALID is not found
ida_typeinf.get_custom_callcnvs(names:qstrvec_t*, codes:callcnvs_t*)→int
Get all custom calling conventions
Parameters:

-
names – output buffer for the convention names

-
codes – output buffer for the convention codes The two output buffers correspond to each other.

Returns:
number of the calling conventions added to the output buffers
ida_typeinf.ARGREGS_POLICY_UNDEFINEDida_typeinf.ARGREGS_GP_ONLY
GP registers used for all arguments.
ida_typeinf.ARGREGS_INDEPENDENT
FP/GP registers used separately (like gcc64)
ida_typeinf.ARGREGS_BY_SLOTS
fixed FP/GP register per each slot (like vc64)
ida_typeinf.ARGREGS_FP_MASKS_GP
FP register also consumes one or more GP regs but not vice versa (aix ppc ABI)
ida_typeinf.ARGREGS_MIPS_O32
MIPS ABI o32.
ida_typeinf.ARGREGS_RISCV
Risc-V API FP arguments are passed in GP registers if FP registers are exhausted and GP ones are not. Wide FP arguments are passed in GP registers. Variadic FP arguments are passed in GP registers.
classida_typeinf.callregs_t(*args)
Bases: `object`
thisownpolicy:argreg_policy_t
argument policy
nregs:int
max number of registers that can be used in a call
gpregs:intvec_t
array of gp registers (general purpose)
fpregs:intvec_t
array of fp registers (floating point)
swap(r:callregs_t)→None
swap two instances
init_regs(cc:callcnv_t)→bool
Init policy & registers for given CC.
by_slots()→boolset(_policy:argreg_policy_t, gprs:intconst*, fprs:intconst*)→None
Init policy & registers (arrays are -1-terminated)
GPREGSFPREGSappend_registers(kind:callregs_t::reg_kind_t, first_reg:int, last_reg:int)→Noneset_registers(kind:callregs_t::reg_kind_t, first_reg:int, last_reg:int)→Nonereset()→None
Set policy and registers to invalid values.
staticregcount(cc:callcnv_t)→int
Get max number of registers may be used in a function call.
reginds(gp_ind:int*, fp_ind:int*, r:int)→bool
Get register indexes within GP/FP arrays. (-1 -> is not present in the corresponding array)
ida_typeinf.get_comp(comp:comp_t)→comp_t
Get compiler bits.
ida_typeinf.get_compiler_name(id:comp_t)→str
Get full compiler name.
ida_typeinf.get_compiler_abbr(id:comp_t)→str
Get abbreviated compiler name.
ida_typeinf.get_compilers(ids:compvec_t*, names:qstrvec_t*, abbrs:qstrvec_t*)→None
Get names of all built-in compilers.
ida_typeinf.is_comp_unsure(comp:comp_t)→comp_t
See COMP_UNSURE.
ida_typeinf.default_compiler()→comp_t
Get compiler specified by inf.cc.
ida_typeinf.is_gcc()→bool
Is the target compiler COMP_GNU?
ida_typeinf.is_gcc32()→bool
Is the target compiler 32 bit gcc?
ida_typeinf.is_gcc64()→bool
Is the target compiler 64 bit gcc?
ida_typeinf.gcc_layout()→bool
Should use the struct/union layout as done by gcc?
ida_typeinf.set_compiler(cc:compiler_info_t, flags:int, abiname:str=None)→bool
Change current compiler.
Parameters:

-
cc – compiler to switch to

-
flags – Set compiler flags

-
abiname – ABI name

Returns:
success
ida_typeinf.SETCOMP_OVERRIDE
may override old compiler info
ida_typeinf.SETCOMP_ONLY_ID
cc has only ‘id’ field; the rest will be set to defaults corresponding to the program bitness
ida_typeinf.SETCOMP_ONLY_ABI
ignore cc field complete, use only abiname
ida_typeinf.SETCOMP_BY_USER
invoked by user, cannot be replaced by module/loader
ida_typeinf.set_compiler_id(id:comp_t, abiname:str=None)→bool
Set the compiler id (see Compiler IDs)
ida_typeinf.set_abi_name(abiname:str, user_level:bool=False)→bool
Set abi name (see Compiler IDs)
ida_typeinf.get_abi_name()→str
Get ABI name.
Returns:
length of the name (>=0)
ida_typeinf.append_abi_opts(abi_opts:str, user_level:bool=False)→bool
Add/remove/check ABI option General form of full abi name: abiname-opt1-opt2-… or -opt1-opt2-…
Parameters:

-
abi_opts –

-
ABI options to add/remove in form opt1-opt2-…

-
user_level –

-
initiated by user if TRUE (==SETCOMP_BY_USER)

Returns:
success
ida_typeinf.remove_abi_opts(abi_opts:str, user_level:bool=False)→boolida_typeinf.set_compiler_string(compstr:str, user_level:bool)→boolParameters:

-
compstr –

-
compiler description in form :

-
user_level –

-
initiated by user if TRUE

Returns:
success
ida_typeinf.use_golang_cc()→bool
is GOLANG calling convention used by default?
ida_typeinf.switch_to_golang()→None
switch to GOLANG calling convention (to be used as default CC)
ida_typeinf.MAX_FUNC_ARGS
max number of function arguments
ida_typeinf.MAX_ARRAY_NELEMS
max number of array elements
ida_typeinf.ABS_UNKida_typeinf.ABS_NOida_typeinf.ABS_YESida_typeinf.SC_UNK
unknown
ida_typeinf.SC_TYPE
typedef
ida_typeinf.SC_EXT
extern
ida_typeinf.SC_STAT
static
ida_typeinf.SC_REG
register
ida_typeinf.SC_AUTO
auto
ida_typeinf.SC_FRIEND
friend
ida_typeinf.SC_VIRT
virtual
ida_typeinf.HTI_CPP
C++ mode (not implemented)
ida_typeinf.HTI_INT
debug: print internal representation of types
ida_typeinf.HTI_EXT
debug: print external representation of types
ida_typeinf.HTI_LEX
debug: print tokens
ida_typeinf.HTI_UNP
debug: check the result by unpacking it
ida_typeinf.HTI_TST
test mode: discard the result
ida_typeinf.HTI_FIL
“input” is file name, otherwise “input” contains a C declaration
ida_typeinf.HTI_MAC
define macros from the base tils
ida_typeinf.HTI_NWR
no warning messages
ida_typeinf.HTI_NER
ignore all errors but display them
ida_typeinf.HTI_DCL
don’t complain about redeclarations
ida_typeinf.HTI_NDC
don’t decorate names
ida_typeinf.HTI_PAK
explicit structure pack value (#pragma pack)
ida_typeinf.HTI_PAK_SHIFT
shift for HTI_PAK. This field should be used if you want to remember an explicit pack value for each structure/union type. See HTI_PAK… definitions
ida_typeinf.HTI_PAKDEF
default pack value
ida_typeinf.HTI_PAK1
#pragma pack(1)
ida_typeinf.HTI_PAK2
#pragma pack(2)
ida_typeinf.HTI_PAK4
#pragma pack(4)
ida_typeinf.HTI_PAK8
#pragma pack(8)
ida_typeinf.HTI_PAK16
#pragma pack(16)
ida_typeinf.HTI_HIGH
assume high level prototypes (with hidden args, etc)
ida_typeinf.HTI_LOWER
lower the function prototypes
ida_typeinf.HTI_RAWARGS
leave argument names unchanged (do not remove underscores)
ida_typeinf.HTI_RELAXED
accept references to unknown namespaces
ida_typeinf.HTI_NOBASE
do not inspect base tils
ida_typeinf.HTI_SEMICOLON
do not complain if the terminating semicolon is absent
ida_typeinf.HTI_STANDALONE
should parse standalone declaration, it may contain qualified name and type names, strictly speaking it is not a valid C++ code, IDA Pro specific
ida_typeinf.HTI_VOID_OK
accept void as a standalone type
ida_typeinf.HTI_NO_MANGLE
don’t mangle name (see HTI_NDC)
ida_typeinf.convert_pt_flags_to_hti(pt_flags:int)→int
Convert Type parsing flags to Type formatting flags. Type parsing flags lesser than 0x10 don’t have stable meaning and will be ignored (more on these flags can be seen in idc.idc)
ida_typeinf.parse_decl(out_tif:tinfo_t, til:til_t, decl:str, pt_flags:int)→str
Parse ONE declaration. If the input string contains more than one declaration, the first complete type declaration (PT_TYP) or the last variable declaration (PT_VAR) will be used.
Parameters:

-
out_tif – type info

-
til – type library to use. may be nullptr

-
decl – C declaration to parse

-
pt_flags – combination of Type parsing flags bits

Returns:
true: ok
Returns:
false: declaration is bad, the error message is displayed if !PT_SIL
ida_typeinf.PT_SIL
silent, no messages
ida_typeinf.PT_NDC
don’t decorate names
ida_typeinf.PT_TYP
return declared type information
ida_typeinf.PT_VAR
return declared object information
ida_typeinf.PT_PACKMASK
mask for pack alignment values
ida_typeinf.PT_HIGH
assume high level prototypes (with hidden args, etc)
ida_typeinf.PT_LOWER
lower the function prototypes
ida_typeinf.PT_REPLACE
replace the old type (used in idc)
ida_typeinf.PT_RAWARGS
leave argument names unchanged (do not remove underscores)
ida_typeinf.PT_RELAXED
accept references to unknown namespaces
ida_typeinf.PT_EMPTY
accept empty decl
ida_typeinf.PT_SEMICOLON
append the terminating semicolon
ida_typeinf.PT_SYMBOL
accept a symbol name and return its type. e.g. “LoadLibrary” will return its prototype
ida_typeinf.PT_VOID_OK
accept void as a standalone type
ida_typeinf.PT_NO_MANGLE
don’t mangle name (see PT_NDC)
ida_typeinf.parse_decls(til:til_t, input:str, printer:printer_t*, hti_flags:int)→int
Parse many declarations and store them in a til. If there are any errors, they will be printed using ‘printer’. This function uses default include path and predefined macros from the database settings. It always uses the HTI_DCL bit.
Parameters:

-
til – type library to store the result

-
input – input string or file name (see hti_flags)

-
printer – function to output error messages (use msg or nullptr or your own callback)

-
hti_flags – combination of Type formatting flags

Returns:
number of errors, 0 means ok.
ida_typeinf.print_type(ea:ida_idaapi.ea_t, prtype_flags:int)→str
Get type declaration for the specified address.
Parameters:

-
ea – address

-
prtype_flags – combination of Type printing flags

Returns:
success
ida_typeinf.PRTYPE_1LINE
print to one line
ida_typeinf.PRTYPE_MULTI
print to many lines
ida_typeinf.PRTYPE_TYPE
print type declaration (not variable declaration)
ida_typeinf.PRTYPE_PRAGMA
print pragmas for alignment
ida_typeinf.PRTYPE_SEMI
append ; to the end
ida_typeinf.PRTYPE_CPP
use c++ name (only for print_type())
ida_typeinf.PRTYPE_DEF
tinfo_t: print definition, if available
ida_typeinf.PRTYPE_NOARGS
tinfo_t: do not print function argument names
ida_typeinf.PRTYPE_NOARRS
tinfo_t: print arguments with FAI_ARRAY as pointers
ida_typeinf.PRTYPE_NORES
tinfo_t: never resolve types (meaningful with PRTYPE_DEF)
ida_typeinf.PRTYPE_RESTORE
tinfo_t: print restored types for FAI_ARRAY and FAI_STRUCT
ida_typeinf.PRTYPE_NOREGEX
do not apply regular expressions to beautify name
ida_typeinf.PRTYPE_COLORED
add color tag COLOR_SYMBOL for any parentheses, commas and colons
ida_typeinf.PRTYPE_METHODS
tinfo_t: print udt methods
ida_typeinf.PRTYPE_1LINCMT
print comments even in the one line mode
ida_typeinf.PRTYPE_HEADER
print only type header (only for definitions)
ida_typeinf.PRTYPE_OFFSETS
print udt member offsets
ida_typeinf.PRTYPE_MAXSTR
limit the output length to 1024 bytes (the output may be slightly longer)
ida_typeinf.PRTYPE_TAIL
print only the definition tail (only for definitions, exclusive with PRTYPE_HEADER)
ida_typeinf.PRTYPE_ARGLOCS
print function arglocs (not only for usercall)
ida_typeinf.NTF_TYPE
type name
ida_typeinf.NTF_SYMU
symbol, name is unmangled (‘func’)
ida_typeinf.NTF_SYMM
symbol, name is mangled (‘_func’); only one of NTF_TYPE and NTF_SYMU, NTF_SYMM can be used
ida_typeinf.NTF_NOBASE
don’t inspect base tils (for get_named_type)
ida_typeinf.NTF_REPLACE
replace original type (for set_named_type)
ida_typeinf.NTF_UMANGLED
name is unmangled (don’t use this flag)
ida_typeinf.NTF_NOCUR
don’t inspect current til file (for get_named_type)
ida_typeinf.NTF_64BIT
value is 64-bit
ida_typeinf.NTF_FIXNAME
force-validate the name of the type when setting (set_named_type, set_numbered_type only)
ida_typeinf.NTF_IDBENC
the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly (set_named_type, set_numbered_type only)
ida_typeinf.NTF_CHKSYNC
check that synchronization to IDB passed OK (set_numbered_type, set_named_type)
ida_typeinf.NTF_NO_NAMECHK
do not validate type name (set_numbered_type, set_named_type)
ida_typeinf.NTF_COPY
save a new type definition, not a typeref (tinfo_t::set_numbered_type, tinfo_t::set_named_type)
ida_typeinf.TERR_OK
ok
ida_typeinf.TERR_SAVE_ERROR
failed to save
ida_typeinf.TERR_SERIALIZE
failed to serialize
ida_typeinf.TERR_BAD_NAME
name s is not acceptable
ida_typeinf.TERR_BAD_ARG
bad argument
ida_typeinf.TERR_BAD_TYPE
bad type
ida_typeinf.TERR_BAD_SIZE
bad size d
ida_typeinf.TERR_BAD_INDEX
bad index d
ida_typeinf.TERR_BAD_ARRAY
arrays are forbidden as function arguments
ida_typeinf.TERR_BAD_BF
bitfields are forbidden as function arguments
ida_typeinf.TERR_BAD_OFFSET
bad member offset s
ida_typeinf.TERR_BAD_UNIVAR
unions cannot have variable sized members
ida_typeinf.TERR_BAD_VARLAST
variable sized member must be the last member in the structure
ida_typeinf.TERR_OVERLAP
the member overlaps with other members that cannot be deleted
ida_typeinf.TERR_BAD_SUBTYPE
recursive structure nesting is forbidden
ida_typeinf.TERR_BAD_VALUE
value 0xI64X is not acceptable
ida_typeinf.TERR_NO_BMASK
bitmask 0xI64X is not found
ida_typeinf.TERR_BAD_BMASK
Bad enum member mask 0xI64X. The specified mask should not intersect with any existing mask in the enum. Zero masks are prohibited too.
ida_typeinf.TERR_BAD_MSKVAL
bad bmask and value combination (value=0xI64X; bitmask 0xI64X)
ida_typeinf.TERR_BAD_REPR
bad or incompatible field representation
ida_typeinf.TERR_GRP_NOEMPTY
could not delete group mask for not empty group 0xI64X
ida_typeinf.TERR_DUPNAME
duplicate name s
ida_typeinf.TERR_UNION_BF
unions cannot have bitfields
ida_typeinf.TERR_BAD_TAH
bad bits in the type attributes (TAH bits)
ida_typeinf.TERR_BAD_BASE
bad base class
ida_typeinf.TERR_BAD_GAP
bad gap
ida_typeinf.TERR_NESTED
recursive structure nesting is forbidden
ida_typeinf.TERR_NOT_COMPAT
the new type is not compatible with the old type
ida_typeinf.TERR_BAD_LAYOUT
failed to calculate the structure/union layout
ida_typeinf.TERR_BAD_GROUPS
bad group sizes for bitmask enum
ida_typeinf.TERR_BAD_SERIAL
enum value has too many serials
ida_typeinf.TERR_ALIEN_NAME
enum member name is used in another enum
ida_typeinf.TERR_STOCK
stock type info cannot be modified
ida_typeinf.TERR_ENUM_SIZE
bad enum size
ida_typeinf.TERR_NOT_IMPL
not implemented
ida_typeinf.TERR_TYPE_WORSE
the new type is worse than the old type
ida_typeinf.TERR_BAD_FX_SIZE
cannot extend struct beyond fixed size
ida_typeinf.TERR_STRUCT_SIZE
bad fixed structure size
ida_typeinf.TERR_NOT_FOUND
member not found
ida_typeinf.TERR_COUNTida_typeinf.tinfo_errstr(code:tinfo_code_t)→str
Helper function to convert an error code into a printable string. Additional arguments are handled using the functions from err.h
ida_typeinf.del_named_type(ti:til_t, name:str, ntf_flags:int)→bool
Delete information about a symbol.
Parameters:

-
ti – type library

-
name – name of symbol

-
ntf_flags – combination of Flags for named types

Returns:
success
ida_typeinf.first_named_type(ti:til_t, ntf_flags:int)→str
Enumerate types.
Parameters:

-
ti – type library. nullptr means the local type library for the current database.

-
ntf_flags – combination of Flags for named types

Returns:
Type or symbol names, depending of ntf_flags. Returns mangled names. Never returns anonymous types. To include them, enumerate types by ordinals.
ida_typeinf.next_named_type(ti:til_t, name:str, ntf_flags:int)→str
Enumerate types.
Parameters:

-
ti – type library. nullptr means the local type library for the current database.

-
name – the current name. the name that follows this one will be returned.

-
ntf_flags – combination of Flags for named types

Returns:
Type or symbol names, depending of ntf_flags. Returns mangled names. Never returns anonymous types. To include them, enumerate types by ordinals.
ida_typeinf.copy_named_type(dsttil:til_t, srctil:til_t, name:str)→int
Copy a named type from one til to another. This function will copy the specified type and all dependent types from the source type library to the destination library.
Parameters:

-
dsttil – Destination til. It must have original types enabled

-
srctil – Source til.

-
name – name of the type to copy

Returns:
ordinal number of the copied type. 0 means error
ida_typeinf.decorate_name(*args)→str
Decorate/undecorate a C symbol name.
Parameters:

-
out – output buffer

-
name – name of symbol

-
should_decorate – true-decorate name, false-undecorate

-
cc – calling convention

-
type – name type (nullptr-unknown)

Returns:
success
ida_typeinf.gen_decorate_name(name:str, should_decorate:bool, cc:callcnv_t, type:tinfo_t)→str
Generic function for decorate_name() (may be used in IDP modules)
ida_typeinf.calc_c_cpp_name(name:str, type:tinfo_t, ccn_flags:int)→str
Get C or C++ form of the name.
Parameters:

-
name – original (mangled or decorated) name

-
type – name type if known, otherwise nullptr

-
ccn_flags – one of C/C++ naming flags

ida_typeinf.CCN_Cida_typeinf.CCN_CPPida_typeinf.enable_numbered_types(ti:til_t, enable:bool)→bool
Enable the use of numbered types in til. Currently it is impossible to disable numbered types once they are enabled
ida_typeinf.alloc_type_ordinals(ti:til_t, qty:int)→int
Allocate a range of ordinal numbers for new types.
Parameters:

-
ti – type library

-
qty – number of ordinals to allocate

Returns:
the first ordinal. 0 means failure.
ida_typeinf.alloc_type_ordinal(ti:til_t)→int
alloc_type_ordinals(ti, 1)
ida_typeinf.get_ordinal_limit(ti:til_t=None)→int
Get number of allocated ordinals + 1. If there are no allocated ordinals, return 0. To enumerate all ordinals, use: for ( uint32 i = 1; i < limit; ++i )
Parameters:
ti – type library; nullptr means the local types for the current database.
Returns:
uint32(-1) if ordinals have not been enabled for the til. For local types (idati), ordinals are always enabled.
ida_typeinf.get_ordinal_count(ti:til_t=None)→int
Get number of allocated ordinals.
Parameters:
ti – type library; nullptr means the local types for the current database.
Returns:
0 if ordinals have not been enabled for the til.
ida_typeinf.del_numbered_type(ti:til_t, ordinal:int)→bool
Delete a numbered type.
ida_typeinf.set_type_alias(ti:til_t, src_ordinal:int, dst_ordinal:int)→bool
Create a type alias. Redirects all references to source type to the destination type. This is equivalent to instantaneous replacement all references to srctype by dsttype.
ida_typeinf.get_alias_target(ti:til_t, ordinal:int)→int
Find the final alias destination. If the ordinal has not been aliased, return the specified ordinal itself If failed, returns 0.
ida_typeinf.get_type_ordinal(ti:til_t, name:str)→int
Get type ordinal by its name.
ida_typeinf.get_numbered_type_name(ti:til_t, ordinal:int)→str
Get type name (if exists) by its ordinal. If the type is anonymous, returns “”. If failed, returns nullptr
ida_typeinf.create_numbered_type_name(ord:int)→str
Create anonymous name for numbered type. This name can be used to reference a numbered type by its ordinal Ordinal names have the following format: ‘#’ + set_de(ord) Returns: -1 if error, otherwise the name length
ida_typeinf.is_ordinal_name(name:str, ord:uint32*=None)→bool
Check if the name is an ordinal name. Ordinal names have the following format: ‘#’ + set_de(ord)
ida_typeinf.is_type_choosable(ti:til_t, ordinal:int)→bool
Check if a struct/union type is choosable
Parameters:

-
ti – type library

-
ordinal – ordinal number of a UDT type

ida_typeinf.set_type_choosable(ti:til_t, ordinal:int, value:bool)→None
Enable/disable ‘choosability’ flag for a struct/union type
Parameters:

-
ti – type library

-
ordinal – ordinal number of a UDT type

-
value – flag value

ida_typeinf.get_vftable_ea(ordinal:int)→ida_idaapi.ea_t
Get address of a virtual function table.
Parameters:
ordinal – ordinal number of a vftable type.
Returns:
address of the corresponding virtual function table in the current database.
ida_typeinf.get_vftable_ordinal(vftable_ea:ida_idaapi.ea_t)→int
Get ordinal number of the virtual function table.
Parameters:
vftable_ea – address of a virtual function table.
Returns:
ordinal number of the corresponding vftable type. 0 - failure.
ida_typeinf.set_vftable_ea(ordinal:int, vftable_ea:ida_idaapi.ea_t)→bool
Set the address of a vftable instance for a vftable type.
Parameters:

-
ordinal – ordinal number of the corresponding vftable type.

-
vftable_ea – address of a virtual function table.

Returns:
success
ida_typeinf.del_vftable_ea(ordinal:int)→bool
Delete the address of a vftable instance for a vftable type.
Parameters:
ordinal – ordinal number of a vftable type.
Returns:
success
ida_typeinf.deref_ptr(ptr_ea:ea_t*, tif:tinfo_t, closure_obj:ea_t*=None)→bool
Dereference a pointer.
Parameters:
ptr_ea – in/out parameter

-
in: address of the pointer

-
out: the pointed address

Parameters:

-
tif – type of the pointer

-
closure_obj – closure object (not used yet)

Returns:
success
ida_typeinf.add_til(name:str, flags:int)→int
Load a til file and add it the database type libraries list. IDA will also apply function prototypes for matching function names.
Parameters:

-
name – til name

-
flags – combination of Load TIL flags

Returns:
one of Load TIL result codes
ida_typeinf.ADDTIL_DEFAULT
default behavior
ida_typeinf.ADDTIL_INCOMP
load incompatible tils
ida_typeinf.ADDTIL_SILENT
do not ask any questions
ida_typeinf.ADDTIL_FAILED
something bad, the warning is displayed
ida_typeinf.ADDTIL_OK
ok, til is loaded
ida_typeinf.ADDTIL_COMP
ok, but til is not compatible with the current compiler
ida_typeinf.ADDTIL_ABORTED
til was not loaded (incompatible til rejected by user)
ida_typeinf.del_til(name:str)→bool
Unload a til file.
ida_typeinf.apply_named_type(ea:ida_idaapi.ea_t, name:str)→bool
Apply the specified named type to the address.
Parameters:

-
ea – linear address

-
name – the type name, e.g. “FILE”

Returns:
success
ida_typeinf.apply_tinfo(ea:ida_idaapi.ea_t, tif:tinfo_t, flags:int)→bool
Apply the specified type to the specified address. This function sets the type and tries to convert the item at the specified address to conform the type.
Parameters:

-
ea – linear address

-
tif – new type

-
flags – combination of Apply tinfo flags

Returns:
success
ida_typeinf.TINFO_GUESSED
this is a guessed type
ida_typeinf.TINFO_DEFINITE
this is a definite type
ida_typeinf.TINFO_DELAYFUNC
if type is a function and no function exists at ea, schedule its creation and argument renaming to auto-analysis, otherwise try to create it immediately
ida_typeinf.TINFO_STRICT
never convert given type to another one before applying
ida_typeinf.apply_cdecl(til:til_t, ea:ida_idaapi.ea_t, decl:str, flags:int=0)→bool
Apply the specified type to the address. This function parses the declaration and calls apply_tinfo()
Parameters:

-
til – type library

-
ea – linear address

-
decl – type declaration in C form

-
flags – flags to pass to apply_tinfo (TINFO_DEFINITE is always passed)

Returns:
success
ida_typeinf.apply_callee_tinfo(caller:ida_idaapi.ea_t, tif:tinfo_t)→bool
Apply the type of the called function to the calling instruction. This function will append parameter comments and rename the local variables of the calling function. It also stores information about the instructions that initialize call arguments in the database. Use get_arg_addrs() to retrieve it if necessary. Alternatively it is possible to hook to processor_t::arg_addrs_ready event.
Parameters:

-
caller – linear address of the calling instruction. must belong to a function.

-
tif – type info

Returns:
success
ida_typeinf.apply_once_tinfo_and_name(dea:ida_idaapi.ea_t, tif:tinfo_t, name:str)→bool
Apply the specified type and name to the address. This function checks if the address already has a type. If the old type does not exist or the new type is ‘better’ than the old type, then the new type will be applied. A type is considered better if it has more information (e.g. BTMT_STRUCT is better than BT_INT). The same logic is with the name: if the address already have a meaningful name, it will be preserved. Only if the old name does not exist or it is a dummy name like byte_123, it will be replaced by the new name.
Parameters:

-
dea – linear address

-
tif – new type

-
name – new name for the address

Returns:
success
ida_typeinf.guess_tinfo(out:tinfo_t, id:tid_t)→int
Generate a type information about the id from the disassembly. id can be a structure/union/enum id or an address.
Returns:
one of Guess tinfo codes
ida_typeinf.GUESS_FUNC_FAILED
couldn’t guess the function type
ida_typeinf.GUESS_FUNC_TRIVIAL
the function type doesn’t have interesting info
ida_typeinf.GUESS_FUNC_OK
ok, some non-trivial information is gathered
ida_typeinf.set_c_header_path(incdir:str)→None
Set include directory path the target compiler.
ida_typeinf.get_c_header_path()→str
Get the include directory path of the target compiler.
ida_typeinf.set_c_macros(macros:str)→None
Set predefined macros for the target compiler.
ida_typeinf.get_c_macros()→str
Get predefined macros for the target compiler.
ida_typeinf.get_idati()→til_t*
Pointer to the local type library - this til is private for each IDB file Functions that accept til_t* default to idati when is nullptr provided.
ida_typeinf.get_idainfo_by_type(tif:tinfo_t)→size_t*,flags64_t*,opinfo_t*,size_t*
Extract information from a tinfo_t.
Parameters:
tif – the type to inspect
ida_typeinf.get_tinfo_by_flags(out:tinfo_t, flags:flags64_t)→bool
Get tinfo object that corresponds to data flags
Parameters:

-
out – type info

-
flags – simple flags (byte, word, …, zword)

ida_typeinf.STI_PCHAR
char *
ida_typeinf.STI_PUCHAR
uint8 *
ida_typeinf.STI_PCCHAR
const char *
ida_typeinf.STI_PCUCHAR
const uint8 *
ida_typeinf.STI_PBYTE
_BYTE *
ida_typeinf.STI_PINT
int *
ida_typeinf.STI_PUINT
unsigned int *
ida_typeinf.STI_PVOID
void *
ida_typeinf.STI_PPVOID
void **
ida_typeinf.STI_PCVOID
const void *
ida_typeinf.STI_ACHAR
char[]
ida_typeinf.STI_AUCHAR
uint8[]
ida_typeinf.STI_ACCHAR
const char[]
ida_typeinf.STI_ACUCHAR
const uint8[]
ida_typeinf.STI_FPURGING
void __userpurge(int)
ida_typeinf.STI_FDELOP
void __cdecl(void *)
ida_typeinf.STI_MSGSEND
void *(void *, const char *, …)
ida_typeinf.STI_AEABI_LCMP
int __fastcall __pure(int64 x, int64 y)
ida_typeinf.STI_AEABI_ULCMP
int __fastcall __pure(uint64 x, uint64 y)
ida_typeinf.STI_DONT_USE
unused stock type id; should not be used
ida_typeinf.STI_SIZE_T
size_t
ida_typeinf.STI_SSIZE_T
ssize_t
ida_typeinf.STI_AEABI_MEMCPY
void __fastcall(void *, const void *, size_t)
ida_typeinf.STI_AEABI_MEMSET
void __fastcall(void *, size_t, int)
ida_typeinf.STI_AEABI_MEMCLR
void __fastcall(void *, size_t)
ida_typeinf.STI_RTC_CHECK_2
int16 __fastcall(int16 x)
ida_typeinf.STI_RTC_CHECK_4
int32 __fastcall(int32 x)
ida_typeinf.STI_RTC_CHECK_8
int64 __fastcall(int64 x)
ida_typeinf.STI_COMPLEX64
struct complex64_t { float real, imag; }
ida_typeinf.STI_COMPLEX128
struct complex128_t { double real, imag; }
ida_typeinf.STI_PUNKNOWN
_UNKNOWN *
ida_typeinf.STI_LASTida_typeinf.ETF_NO_SAVE
don’t save to til (normally typerefs are saved to til) A call with ETF_NO_SAVE must be followed by a call without it. Otherwise there may be inconsistencies between the memory and the type library.
ida_typeinf.ETF_NO_LAYOUT
don’t calc type layout before editing
ida_typeinf.ETF_MAY_DESTROY
may destroy other members
ida_typeinf.ETF_COMPATIBLE
new type must be compatible with the old
ida_typeinf.ETF_FUNCARG
udm - member is a function argument (cannot create arrays)
ida_typeinf.ETF_FORCENAME
anyway use name, see below for more usage description
ida_typeinf.ETF_AUTONAME
udm - generate a member name if was not specified (add_udm, set_udm_type)
ida_typeinf.ETF_BYTIL
udm - new type was created by the type subsystem
ida_typeinf.ETF_NO_ARRAY
add_udm, set_udm_type - do not convert type to an array on the size mismatch
ida_typeinf.GTD_CALC_LAYOUT
calculate udt layout
ida_typeinf.GTD_NO_LAYOUT
don’t calculate udt layout please note that udt layout may have been calculated earlier
ida_typeinf.GTD_DEL_BITFLDS
delete udt bitfields
ida_typeinf.GTD_CALC_ARGLOCS
calculate func arg locations
ida_typeinf.GTD_NO_ARGLOCS
don’t calculate func arg locations please note that the locations may have been calculated earlier
ida_typeinf.GTS_NESTED
nested type (embedded into a udt)
ida_typeinf.GTS_BASECLASS
is baseclass of a udt
ida_typeinf.SUDT_SORT
fields are not sorted by offset, sort them first
ida_typeinf.SUDT_ALIGN
recalculate field alignments, struct packing, etc to match the offsets and size info
ida_typeinf.SUDT_GAPS
allow to fill gaps with additional members (_BYTE[])
ida_typeinf.SUDT_UNEX
references to nonexistent member types are acceptable; in this case it is better to set the corresponding udm_t::fda field to the type alignment. If this field is not set, ida will try to guess the alignment.
ida_typeinf.SUDT_FAST
serialize without verifying offsets and alignments
ida_typeinf.SUDT_CONST
only for serialize_udt: make type const
ida_typeinf.SUDT_VOLATILE
only for serialize_udt: make type volatile
ida_typeinf.SUDT_TRUNC
serialize: truncate useless strings from fields, fldcmts
ida_typeinf.SUDT_SERDEF
serialize: if a typeref, serialize its definition
ida_typeinf.copy_tinfo_t(_this:tinfo_t, r:tinfo_t)→Noneida_typeinf.detach_tinfo_t(_this:tinfo_t)→boolida_typeinf.clear_tinfo_t(_this:tinfo_t)→Noneida_typeinf.create_tinfo(_this:tinfo_t, bt:type_t, bt2:type_t, ptr:void*)→boolida_typeinf.verify_tinfo(typid:typid_t)→intida_typeinf.get_tinfo_details(typid:typid_t, bt2:type_t, buf:void*)→boolida_typeinf.get_tinfo_size(p_effalign:uint32*, typid:typid_t, gts_code:int)→intida_typeinf.get_tinfo_pdata(outptr:void*, typid:typid_t, what:int)→intida_typeinf.get_tinfo_property(typid:typid_t, gta_prop:int)→intida_typeinf.get_tinfo_property4(typid:typid_t, gta_prop:int, p1:int, p2:int, p3:int, p4:int)→intida_typeinf.set_tinfo_property(tif:tinfo_t, sta_prop:int, x:int)→intida_typeinf.set_tinfo_property4(tif:tinfo_t, sta_prop:int, p1:int, p2:int, p3:int, p4:int)→intida_typeinf.serialize_tinfo(type:qtype*, fields:qtype*, fldcmts:qtype*, tif:tinfo_t, sudt_flags:int)→boolida_typeinf.find_tinfo_udt_member(udm:udm_t, typid:typid_t, strmem_flags:int)→intida_typeinf.print_tinfo(prefix:str, indent:int, cmtindent:int, flags:int, tif:tinfo_t, name:str, cmt:str)→strida_typeinf.dstr_tinfo(tif:tinfo_t)→strida_typeinf.visit_subtypes(visitor:tinfo_visitor_t, out:type_mods_t, tif:tinfo_t, name:str, cmt:str)→intida_typeinf.compare_tinfo(t1:typid_t, t2:typid_t, tcflags:int)→boolida_typeinf.lexcompare_tinfo(t1:typid_t, t2:typid_t, arg3:int)→intida_typeinf.get_stock_tinfo(tif:tinfo_t, id:stock_type_id_t)→boolida_typeinf.read_tinfo_bitfield_value(typid:typid_t, v:uint64, bitoff:int)→uint64ida_typeinf.write_tinfo_bitfield_value(typid:typid_t, dst:uint64, v:uint64, bitoff:int)→uint64ida_typeinf.get_tinfo_attr(typid:typid_t, key:str, bv:bytevec_t*, all_attrs:bool)→boolida_typeinf.set_tinfo_attr(tif:tinfo_t, ta:type_attr_t, may_overwrite:bool)→boolida_typeinf.del_tinfo_attr(tif:tinfo_t, key:str, make_copy:bool)→boolida_typeinf.get_tinfo_attrs(typid:typid_t, tav:type_attrs_t, include_ref_attrs:bool)→boolida_typeinf.set_tinfo_attrs(tif:tinfo_t, ta:type_attrs_t)→boolida_typeinf.score_tinfo(tif:tinfo_t)→intida_typeinf.save_tinfo(tif:tinfo_t, til:til_t, ord:int, name:str, ntf_flags:int)→tinfo_code_tida_typeinf.append_tinfo_covered(out:rangeset_t, typid:typid_t, offset:uint64)→boolida_typeinf.calc_tinfo_gaps(out:rangeset_t, typid:typid_t)→boolida_typeinf.value_repr_t__from_opinfo(_this:value_repr_t, flags:flags64_t, afl:aflags_t, opinfo:opinfo_t, ap:array_parameters_t)→boolida_typeinf.value_repr_t__print_(_this:value_repr_t, colored:bool)→strida_typeinf.udt_type_data_t__find_member(_this:udt_type_data_t, udm:udm_t, strmem_flags:int)→ssize_tida_typeinf.udt_type_data_t__get_best_fit_member(_this:udt_type_data_t, disp:asize_t)→ssize_tida_typeinf.udt_type_data_t__deduplicate_members(_this:udt_type_data_t)→boolida_typeinf.get_tinfo_by_edm_name(tif:tinfo_t, til:til_t, mname:str)→ssize_tclassida_typeinf.tinfo_t(*args, ordinal=None, name=None, tid=None, til=None)
Bases: `object`
thisownclear()→None
Clear contents of this tinfo, and remove from the type system.
swap(r:tinfo_t)→None
Assign this = r and r = this.
get_named_type(*args)→bool
This function has the following signatures:

-
get_named_type(til: const til_t *, name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool

-
get_named_type(name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool

# 0: get_named_type(til: const til_t *, name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool

Create a tinfo_t object for an existing named type.

# 1: get_named_type(name: str, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true, try_ordinal: bool=true) -> bool
get_numbered_type(*args)→bool
This function has the following signatures:

-
get_numbered_type(til: const til_t *, ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool

-
get_numbered_type(ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool

# 0: get_numbered_type(til: const til_t *, ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool

Create a tinfo_t object for an existing ordinal type.

# 1: get_numbered_type(ordinal: int, decl_type: type_t=BTF_TYPEDEF, resolve: bool=true) -> bool
detach()→bool
Detach tinfo_t from the underlying type. After calling this finction, tinfo_t will lose its link to the underlying named or numbered type (if any) and will become a reference to a unique type. After that, any modifications to tinfo_t will affect only its type.
is_correct()→bool
Is the type object correct? It is possible to create incorrect types. For example, we can define a function that returns an enum and then delete the enum type. If this function returns false, the type should not be used in disassembly. Please note that this function does not verify all involved types: for example, pointers to undefined types are permitted.
get_realtype(full:bool=False)→type_t
Get the resolved base type. Deserialization options: * if full=true, the referenced type will be deserialized fully, this may not always be desirable (slows down things) * if full=false, we just return the base type, the referenced type will be resolved again later if necessary (this may lead to multiple resolvings of the same type) imho full=false is a better approach because it does not perform unnecessary actions just in case. however, in some cases the caller knows that it is very likely that full type info will be required. in those cases full=true makes sense
get_decltype()→type_t
Get declared type (without resolving type references; they are returned as is). Obviously this is a very fast function and should be used instead of get_realtype() if possible. Please note that for typerefs this function will return BTF_TYPEDEF. To determine if a typeref is a typedef, use is_typedef()
empty()→bool
Was tinfo_t initialized with some type info or not?
present()→bool
Is the type really present? (not a reference to a missing type, for example)
get_size(p_effalign:uint32*=None, gts_code:int=0)→int
Get the type size in bytes.
Parameters:

-
p_effalign – buffer for the alignment value

-
gts_code – combination of GTS_… constants

Returns:
BADSIZE in case of problems
get_unpadded_size()→int
Get the type size in bytes without the final padding, in bytes. For some UDTs get_unpadded_size() != get_size()
get_alignment()→int
Get type alignment This function returns the effective type alignment. Zero means error.
get_sign()→type_sign_t
Get type sign.
is_signed()→bool
Is this a signed type?
is_unsigned()→bool
Is this an unsigned type?
get_declalign()→uchar
Get declared alignment of the type.
is_typeref()→bool
Is this type a type reference?
has_details()→bool
Does this type refer to a nontrivial type?
get_type_name()→bool
Does a type refer to a name? If yes, fill the provided buffer with the type name and return true. Names are returned for numbered types too: either a user-defined nice name or, if a user-provided name does not exist, an ordinal name (like #xx, see create_numbered_type_name()).
get_nice_type_name()→bool
Get the beautified type name. Get the referenced name and apply regular expressions from goodname.cfg to beautify the name
build_anon_type_name()→bool
Generate a name like $hex_numbers based on the field types and names.
rename_type(name:str, ntf_flags:int=0)→tinfo_code_t
Rename a type
Parameters:

-
name – new type name

-
ntf_flags – Flags for named types

get_final_type_name()→bool
Use in the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3…TYPEn).
Returns:
the name of the last type in the chain (TYPEn). if there is no chain, returns TYPE1
get_next_type_name()→bool
Use In the case of typedef chain (TYPE1 -> TYPE2 -> TYPE3…TYPEn).
Returns:
the name of the next type in the chain (TYPE2). if there is no chain, returns failure
get_tid()→tid_t
Get the type tid Each type in the local type library has a so-called tid associated with it. The tid is used to collect xrefs to the type. The tid is created when the type is created in the local type library and does not change afterwards. It can be passed to xref-related functions instead of the address.
Returns:
tid or BADADDR
force_tid()→tid_t
Get the type tid. Create if it does not exist yet. If the type comes from a base til, the type will be copied to the local til and a new tid will be created for it. (if the type comes from a base til, it does not have a tid yet). If the type comes from the local til, this function is equivalent to get_tid()
Returns:
tid or BADADDR
get_ordinal()→int
Get type ordinal (only if the type was created as a numbered type, 0 if none)
get_final_ordinal()→int
Get final type ordinal (0 if none)
get_til()→til_t*
Get the type library for tinfo_t.
is_from_subtil()→bool
Was the named type found in some base type library (not the top level type library)? If yes, it usually means that the type comes from some loaded type library, not the local type library for the database
is_forward_decl()→bool
Is this a forward declaration? Forward declarations are placeholders: the type definition does not exist
get_forward_type()→type_t
Get type of a forward declaration. For a forward declaration this function returns its base type. In other cases it returns BT_UNK
is_forward_struct()→boolis_forward_union()→boolis_forward_enum()→boolis_typedef()→bool
Is this a typedef? This function will return true for a reference to a local type that is declared as a typedef.
get_type_cmt()→int
Get type comment
Returns:
0-failed, 1-returned regular comment, 2-returned repeatable comment
get_type_rptcmt()→bool
Get type comment only if it is repeatable.
is_decl_const()→bool
is_type_const(get_decltype())
is_decl_volatile()→bool
is_type_volatile(get_decltype())
is_decl_void()→bool
is_type_void(get_decltype())
is_decl_partial()→bool
is_type_partial(get_decltype())
is_decl_unknown()→bool
is_type_unknown(get_decltype())
is_decl_last()→bool
is_typeid_last(get_decltype())
is_decl_ptr()→bool
is_type_ptr(get_decltype())
is_decl_array()→bool
is_type_array(get_decltype())
is_decl_func()→bool
is_type_func(get_decltype())
is_decl_complex()→bool
is_type_complex(get_decltype())
is_decl_typedef()→bool
is_type_typedef(get_decltype())
is_decl_sue()→bool
is_type_sue(get_decltype())
is_decl_struct()→bool
is_type_struct(get_decltype())
is_decl_union()→bool
is_type_union(get_decltype())
is_decl_udt()→bool
is_type_struni(get_decltype())
is_decl_enum()→bool
is_type_enum(get_decltype())
is_decl_bitfield()→bool
is_type_bitfld(get_decltype())
is_decl_int128()→bool
is_type_int128(get_decltype())
is_decl_int64()→bool
is_type_int64(get_decltype())
is_decl_int32()→bool
is_type_int32(get_decltype())
is_decl_int16()→bool
is_type_int16(get_decltype())
is_decl_int()→bool
is_type_int(get_decltype())
is_decl_char()→bool
is_type_char(get_decltype())
is_decl_uint()→bool
is_type_uint(get_decltype())
is_decl_uchar()→bool
is_type_uchar(get_decltype())
is_decl_uint16()→bool
is_type_uint16(get_decltype())
is_decl_uint32()→bool
is_type_uint32(get_decltype())
is_decl_uint64()→bool
is_type_uint64(get_decltype())
is_decl_uint128()→bool
is_type_uint128(get_decltype())
is_decl_ldouble()→bool
is_type_ldouble(get_decltype())
is_decl_double()→bool
is_type_double(get_decltype())
is_decl_float()→bool
is_type_float(get_decltype())
is_decl_tbyte()→bool
is_type_tbyte(get_decltype())
is_decl_floating()→bool
is_type_floating(get_decltype())
is_decl_bool()→bool
is_type_bool(get_decltype())
is_decl_paf()→bool
is_type_paf(get_decltype())
is_well_defined()→bool
!(empty()) && !(is_decl_partial()) && !(is_punknown())
is_const()→bool
is_type_const(get_realtype())
is_volatile()→bool
is_type_volatile(get_realtype())
is_void()→bool
is_type_void(get_realtype())
is_partial()→bool
is_type_partial(get_realtype())
is_unknown()→bool
is_type_unknown(get_realtype())
is_ptr()→bool
is_type_ptr(get_realtype())
is_array()→bool
is_type_array(get_realtype())
is_func()→bool
is_type_func(get_realtype())
is_complex()→bool
is_type_complex(get_realtype())
is_struct()→bool
is_type_struct(get_realtype())
is_union()→bool
is_type_union(get_realtype())
is_udt()→bool
is_type_struni(get_realtype())
is_enum()→bool
is_type_enum(get_realtype())
is_sue()→bool
is_type_sue(get_realtype())
is_bitfield()→bool
is_type_bitfld(get_realtype())
is_int128()→bool
is_type_int128(get_realtype())
is_int64()→bool
is_type_int64(get_realtype())
is_int32()→bool
is_type_int32(get_realtype())
is_int16()→bool
is_type_int16(get_realtype())
is_int()→bool
is_type_int(get_realtype())
is_char()→bool
is_type_char(get_realtype())
is_uint()→bool
is_type_uint(get_realtype())
is_uchar()→bool
is_type_uchar(get_realtype())
is_uint16()→bool
is_type_uint16(get_realtype())
is_uint32()→bool
is_type_uint32(get_realtype())
is_uint64()→bool
is_type_uint64(get_realtype())
is_uint128()→bool
is_type_uint128(get_realtype())
is_ldouble()→bool
is_type_ldouble(get_realtype())
is_double()→bool
is_type_double(get_realtype())
is_float()→bool
is_type_float(get_realtype())
is_tbyte()→bool
is_type_tbyte(get_realtype())
is_bool()→bool
is_type_bool(get_realtype())
is_paf()→bool
is_type_paf(get_realtype())
is_ptr_or_array()→bool
is_type_ptr_or_array(get_realtype())
is_integral()→bool
is_type_integral(get_realtype())
is_ext_integral()→bool
is_type_ext_integral(get_realtype())
is_floating()→bool
is_type_floating(get_realtype())
is_arithmetic()→bool
is_type_arithmetic(get_realtype())
is_ext_arithmetic()→bool
is_type_ext_arithmetic(get_realtype())
is_scalar()→bool
Does the type represent a single number?
get_ptr_details(pi:ptr_type_data_t)→bool
Get the pointer info.
get_array_details(ai:array_type_data_t)→bool
Get the array specific info.
get_enum_details(ei:enum_type_data_t)→bool
Get the enum specific info.
get_bitfield_details(bi:bitfield_type_data_t)→bool
Get the bitfield specific info.
get_udt_details(udt:udt_type_data_t, gtd:gtd_udt_t=GTD_CALC_LAYOUT)→bool
Get the udt specific info.
get_func_details(fi:func_type_data_t, gtd:gtd_func_t=GTD_CALC_ARGLOCS)→bool
Get only the function specific info for this tinfo_t.
is_funcptr()→bool
Is this pointer to a function?
is_shifted_ptr()→bool
Is a shifted pointer?
is_varstruct()→bool
Is a variable-size structure?
is_varmember()→bool
Can the type be of a variable struct member? This function checks for: is_array() && array.nelems==0 Such a member can be only the very last member of a structure
get_ptrarr_objsize()→int
BT_PTR & BT_ARRAY: get size of pointed object or array element. On error returns -1
get_ptrarr_object()→tinfo_t
BT_PTR & BT_ARRAY: get the pointed object or array element. If the current type is not a pointer or array, return empty type info.
get_pointed_object()→tinfo_t
BT_PTR: get type of pointed object. If the current type is not a pointer, return empty type info. See also get_ptrarr_object() and remove_pointer()
is_pvoid()→bool
Is “void *”? This function does not check the pointer attributes and type modifiers
is_punknown()→bool
Is “_UNKNOWN *”? This function does not check the pointer attributes and type modifiers
get_array_element()→tinfo_t
BT_ARRAY: get type of array element. See also get_ptrarr_object()
get_final_element()→tinfo_t
repeat recursively: if an array, return the type of its element; else return the type itself.
get_array_nelems()→int
BT_ARRAY: get number of elements (-1 means error)
get_nth_arg(n:int)→tinfo_t
BT_FUNC or BT_PTR BT_FUNC: Get type of n-th arg (-1 means return type, see get_rettype())
get_rettype()→tinfo_t
BT_FUNC or BT_PTR BT_FUNC: Get the function’s return type
get_nargs()→int
BT_FUNC or BT_PTR BT_FUNC: Calculate number of arguments (-1 - error)
get_cc()→callcnv_t
BT_FUNC or BT_PTR BT_FUNC: Get calling convention
is_user_cc()→bool
is_user_cc(get_cc())
is_vararg_cc()→bool
is_vararg_cc(get_cc())
is_purging_cc()→bool
is_purging_cc(get_cc())
calc_purged_bytes()→int
BT_FUNC: Calculate number of purged bytes
is_high_func()→bool
BT_FUNC: Is high level type?
get_methods(methods:udtmembervec_t)→bool
BT_COMPLEX: get a list of member functions declared in this udt.
Returns:
false if no member functions exist
get_bit_buckets(buckets:range64vec_t)→bool
::BT_STRUCT: get bit buckets Bit buckets are used to layout bitfields
Returns:
false if wrong type was passed
find_udm(*args)→int
This function has the following signatures:

-
find_udm(udm: udm_t *, strmem_flags: int) -> int

-
find_udm(offset: uint64, strmem_flags: int=0) -> int

-
find_udm(name: str, strmem_flags: int=0) -> int

# 0: find_udm(udm: udm_t *, strmem_flags: int) -> int

BTF_STRUCT,BTF_UNION: Find a udt member. * at the specified offset (STRMEM_OFFSET) * with the specified index (STRMEM_INDEX) * with the specified type (STRMEM_TYPE) * with the specified name (STRMEM_NAME)
Returns:
the index of the found member or -1

# 1: find_udm(offset: uint64, strmem_flags: int=0) -> int

BTF_STRUCT,BTF_UNION: Find an udt member at the specified offset
Returns:
the index of the found member or -1

# 2: find_udm(name: str, strmem_flags: int=0) -> int

BTF_STRUCT,BTF_UNION: Find an udt member by name
Returns:
the index of the found member or -1
get_udm(*args)→Tuple[int,udm_t]|Tuple[None,None]
Retrieve a structure/union member with either the specified name or the specified index, in the specified tinfo_t object.

This function has the following signatures:

-
get_udm(index: int)

-
get_udm(name: str)

Parameters:

-
index – a member index (1st form)

-
name – a member name (2nd form)

Returns:
a tuple (int, udm_t), or (-1, None) if member not found
get_udm_by_offset(offset:int)
Retrieve a structure/union member with the specified offset, in the specified tinfo_t object.
Parameters:
offset – the member offset
Returns:
a tuple (int, udm_t), or (-1, None) if member not found
get_udt_nmembers()→int
Get number of udt members. -1-error.
is_empty_udt()→bool
Is an empty struct/union? (has no fields)
is_small_udt()→bool
Is a small udt? (can fit a register or a pair of registers)
get_udt_taudt_bits()→int
Get udt_type_data_t::taudt_bits.
is_unaligned_struct()→bool
Is an unaligned struct.
is_msstruct()→bool
Is gcc msstruct attribute applied.
is_cpp_struct()→bool
Is a c++ object, not simple pod type.
is_vftable()→bool
Is a vftable type?
is_fixed_struct()→bool
Is a structure with fixed offsets?
is_tuple()→bool
Is a tuple?
is_iface()→bool
Is an interface?
requires_qualifier(name:str, offset:uint64)→bool
Requires full qualifier? (name is not unique)
Parameters:

-
name – field name

-
offset – field offset in bits

Returns:
if the name is not unique, returns true
append_covered(out:rangeset_t, offset:uint64=0)→bool
Calculate set of covered bytes for the type
Parameters:

-
out – pointer to the output buffer. covered bytes will be appended to it.

-
offset – delta in bytes to add to all calculations. used internally during recursion.

calc_gaps(out:rangeset_t)→bool
Calculate set of padding bytes for the type
Parameters:
out – pointer to the output buffer; old buffer contents will be lost.
is_one_fpval()→bool
Floating value or an object consisting of one floating member entirely.
is_sse_type()→bool
Is a SSE vector type?
is_anonymous_udt()→bool
Is an anonymous struct/union? We assume that types with names are anonymous if the name starts with $
has_vftable()→bool
Has a vftable?
has_union()→bool
Has a member of type “union”?
get_enum_nmembers()→int
Get number of enum members.
Returns:
BADSIZE if error
is_empty_enum()→bool
Is an empty enum? (has no constants)
get_enum_base_type()→type_t
Get enum base type (convert enum to integer type) Returns BT_UNK if failed to convert
is_bitmask_enum()→bool
Is bitmask enum?
Returns:
true for bitmask enum and false in other cases enum_type_data_t::is_bf()
get_enum_radix()→int
Get enum constant radix
Returns:
radix or 1 for BTE_CHAR enum_type_data_t::get_enum_radix()
get_enum_repr(repr:value_repr_t)→tinfo_code_t
Set the representation of enum members.
Parameters:
repr – value_repr_t
get_enum_width()→int
Get enum width
Returns:
width of enum base type in bytes, 0 - unspecified, or -1 enum_type_data_t::calc_nbytes()
calc_enum_mask()→uint64get_edm_by_value(value:int, bmask:int=DEFMASK64, serial:int=0)→Tuple[int,edm_t]
Retrieve an enumerator with the specified value, in the specified tinfo_t object.
Parameters:
value – the enumerator value
Returns:
a tuple (int, edm_t), or (-1, None) if member not found
get_edm_tid(idx:int)→tid_t
Get enum member TID
Parameters:
idx – enum member index
Returns:
tid or BADADDR The tid is used to collect xrefs to the member, it can be passed to xref-related functions instead of the address.
get_onemember_type()→tinfo_t
For objects consisting of one member entirely: return type of the member.
get_innermost_udm(bitoffset:uint64)→tinfo_t
Get the innermost member at the given offset
Parameters:
bitoffset – bit offset into the structure
Returns:
udt: with the innermost member
Returns:
empty: type if it is not a struct type or OFFSET could not be found
get_innermost_member_type(bitoffset:uint64)→tinfo_t
Get the innermost member type at the given offset
Parameters:
bitoffset – bit offset into the structure
Returns:
the: innermost member type
calc_score()→int
Calculate the type score (the higher - the nicer is the type)
dstr()→str
Function to facilitate debugging.
get_attrs(tav:type_attrs_t, all_attrs:bool=False)→bool
Get type attributes (all_attrs: include attributes of referenced types, if any)
set_attrs(tav:type_attrs_t)→bool
Set type attributes. If necessary, a new typid will be created. this function modifies tav! (returns old attributes, if any)
Returns:
false: bad attributes
set_attr(ta:type_attr_t, may_overwrite:bool=True)→bool
Set a type attribute. If necessary, a new typid will be created.
del_attrs()→None
Del all type attributes. typerefs cannot be modified by this function.
del_attr(key:str, make_copy:bool=True)→bool
Del a type attribute. typerefs cannot be modified by this function.
create_simple_type(decl_type:type_t)→boolcreate_ptr(*args)→boolcreate_array(*args)→boolcreate_typedef(*args)→Nonecreate_bitfield(*args)→boolparse(decl:str, til:til_t=None, pt_flags:int=0)→bool
Convenience function to parse a string with a type declaration
Parameters:

-
decl – a type declaration

-
til – type library to use

-
pt_flags – combination of Type parsing flags bits

create_udt(*args)→bool
Create an empty structure/union.
create_enum(*args)→bool
Create an empty enum.
create_func(*args)→boolget_udm_by_tid(udm:udm_t, tid:tid_t)→ssize_tget_edm_by_tid(edm:edm_t, tid:tid_t)→ssize_tget_type_by_tid(tid:tid_t)→boolget_by_edm_name(mname:str, til:til_t=None)→ssize_t
Retrieve enum tinfo using enum member name
Parameters:

-
mname – enum type member name

-
til – type library

Returns:
member index, otherwise returns -1. If the function fails, THIS object becomes empty.
set_named_type(til:til_t, name:str, ntf_flags:int=0)→tinfo_code_tset_symbol_type(til:til_t, name:str, ntf_flags:int=0)→tinfo_code_tset_numbered_type(til:til_t, ord:int, ntf_flags:int=0, name:str=None)→tinfo_code_tsave_type(*args)→tinfo_code_tcopy_type(*args)→tinfo_code_tcreate_forward_decl(til:til_t, decl_type:type_t, name:str, ntf_flags:int=0)→tinfo_code_t
Create a forward declaration. decl_type: BTF_STRUCT, BTF_UNION, or BTF_ENUM
staticget_stock(id:stock_type_id_t)→tinfo_t
Get stock type information. This function can be used to get tinfo_t for some common types. The same tinfo_t will be returned for the same id, thus saving memory and increasing the speed Please note that retrieving the STI_SIZE_T or STI_SSIZE_T stock type, will also have the side-effect of adding that type to the ‘idati’ TIL, under the well-known name ‘size_t’ or ‘ssize_t’ (respectively). The same is valid for STI_COMPLEX64 and STI_COMPLEX64 stock types with names ‘complex64_t’ and ‘complex128_t’ (respectively).
convert_array_to_ptr()→bool
Convert an array into a pointer. type[] => type *
remove_ptr_or_array()→bool
Replace the current type with the ptr obj or array element. This function performs one of the following conversions: * type[] => type * type* => type If the conversion is performed successfully, return true
read_bitfield_value(v:uint64, bitoff:int)→uint64write_bitfield_value(dst:uint64, v:uint64, bitoff:int)→uint64get_modifiers()→type_tset_modifiers(mod:type_t)→Noneset_const()→Noneset_volatile()→Noneclr_decl_const_volatile()→Noneclr_const()→boolclr_volatile()→boolclr_const_volatile()→boolset_type_alignment(declalign:uchar, etf_flags:uint=0)→tinfo_code_t
Set type alignment.
set_declalign(declalign:uchar)→boolchange_sign(sign:type_sign_t)→bool
Change the type sign. Works only for the types that may have sign.
calc_udt_aligns(sudt_flags:int=4)→bool
Calculate the udt alignments using the field offsets/sizes and the total udt size This function does not work on typerefs
set_methods(methods:udtmembervec_t)→bool
BT_COMPLEX: set the list of member functions. This function consumes ‘methods’ (makes it empty).
Returns:
false if this type is not a udt, or if the given list is empty
set_type_cmt(cmt:str, is_regcmt:bool=False, etf_flags:uint=0)→tinfo_code_t
Set type comment This function works only for non-trivial types
get_alias_target()→int
Get type alias If the type has no alias, return 0.
is_aliased()→boolset_type_alias(dest_ord:int)→bool
Set type alias Redirects all references to source type to the destination type. This is equivalent to instantaneous replacement all references to srctype by dsttype.
set_udt_alignment(sda:int, etf_flags:uint=0)→tinfo_code_t
Set declared structure alignment (sda) This alignment supersedes the alignment returned by get_declalign() and is really used when calculating the struct layout. However, the effective structure alignment may differ from sda because of packing. The type editing functions (they accept etf_flags) may overwrite this attribute.
set_udt_pack(pack:int, etf_flags:uint=0)→tinfo_code_t
Set structure packing. The value controls how little a structure member alignment can be. Example: if pack=1, then it is possible to align a double to a byte. __attribute__((aligned(1))) double x; However, if pack=3, a double will be aligned to 8 (2**3) even if requested to be aligned to a byte. pack==0 will have the same effect. The type editing functions (they accept etf_flags) may overwrite this attribute.
get_udm_tid(idx:int)→tid_t
Get udt member TID
Parameters:
idx – the index of udt the member
Returns:
tid or BADADDR The tid is used to collect xrefs to the member, it can be passed to xref-related functions instead of the address.
add_udm(*args)
Add a member to the current structure/union.

When creating a new structure/union from scratch, you might want to first call create_udt()

This method has the following signatures:

-
add_udm(udm: udm_t, etf_flags: int = 0, times: int = 1, idx: int = -1)

-
add_udm(name: str, type: type_t | tinfo_t | str, offset: int = 0, etf_flags: int = 0, times: int = 1, idx: int = -1)

In the 2nd form, the ‘type’ descriptor, can be one of:

-
type_t: if the type is simple (integral/floating/bool). E.g., BTF_INT

-
tinfo_t: can handle more complex types (structures, pointers, arrays, …)

-
str: a C type declaration

If an input argument is incorrect, the constructor may raise an exception
Parameters:

-
udm – The member, fully initialized (1st form)

-
name – Member name - must not be empty

-
type – Member type

-
offset – the member offset in bits. It is the caller’s responsibility to specify correct offsets.

-
etf_flags – an OR’ed combination of ETF_ flags

-
times – how many times to add the new member

-
idx – the index in the udm array where the new udm should be placed. If the specified index cannot be honored because it would spoil the udm sorting order, it is silently ignored.

del_udm(index:int, etf_flags:uint=0)→tinfo_code_t
Delete a structure/union member.
del_udms(idx1:int, idx2:int, etf_flags:uint=0)→tinfo_code_t
Delete structure/union members in the range [idx1, idx2)
rename_udm(index:int, name:str, etf_flags:uint=0)→tinfo_code_t
Rename a structure/union member. The new name must be unique.
set_udm_type(index:int, tif:tinfo_t, etf_flags:uint=0, repr:value_repr_t=None)→tinfo_code_t
Set type of a structure/union member.
Parameters:

-
index – member index in the udm array

-
tif – new type for the member

-
etf_flags – etf_flag_t

-
repr – new representation for the member (optional)

Returns:
tinfo_code_t
set_udm_cmt(index:int, cmt:str, is_regcmt:bool=False, etf_flags:uint=0)→tinfo_code_t
Set a comment for a structure/union member. A member may have just one comment, and it is either repeatable or regular.
set_udm_repr(index:int, repr:value_repr_t, etf_flags:uint=0)→tinfo_code_t
Set the representation of a structure/union member.
is_udm_by_til(idx:int)→bool
Was the member created due to the type system
Parameters:
idx – index of the member
set_udm_by_til(idx:int, on:bool=True, etf_flags:uint=0)→tinfo_code_t
The member is created due to the type system
Parameters:

-
idx – index of the member

-
etf_flags – etf_flag_t

set_fixed_struct(on:bool=True)→tinfo_code_t
Declare struct member offsets as fixed. For such structures, IDA will not recalculate the member offsets. If a member does not fit into its place anymore, it will be deleted. This function works only with structures (not unions).
set_struct_size(new_size:int)→tinfo_code_t
Explicitly specify the struct size. This function works only with fixed structures. The new struct size can be equal or higher the unpadded struct size (IOW, all existing members should fit into the specified size).
Parameters:
new_size – new structure size in bytes
expand_udt(idx:int, delta:adiff_t, etf_flags:uint=0)→tinfo_code_t
Expand/shrink a structure by adding/removing a gap before the specified member. For regular structures, either the gap can be accommodated by aligning the next member with an alignment directive, or an explicit “gap” member will be inserted. Also note that it is impossible to add a gap at the end of a regular structure. When it comes to fixed-layout structures, there is no need to either add new “gap” members or align existing members, since all members have a fixed offset. It is possible to add a gap at the end of a fixed-layout structure, by passing -1 as index.
Parameters:

-
idx – index of the member

-
delta – number of bytes to add or remove

-
etf_flags – etf_flag_t

set_tuple(on:bool=True)→tinfo_code_t
Declare struct as a tuple. Currently, tuples in IDA behave the same way as structures but they are returned in a different manner from functions. Also, 2 different tuples having the same members are considered to be equal. This function works only with structures (not unions).
set_iface(on:bool=True)→tinfo_code_t
Declare struct as an interface. This function works only with structures (not unions).
get_func_frame(pfn:func_tconst*)→bool
Create a tinfo_t object for the function frame
Parameters:
pfn – function
is_frame()→bool
Is a function frame?
get_frame_func()→ida_idaapi.ea_t
Get function address for the frame.
set_enum_width(nbytes:int, etf_flags:uint=0)→tinfo_code_t
Set the width of enum base type
Parameters:

-
nbytes – width of enum base type, allowed values: 0 (unspecified),1,2,4,8,16,32,64

-
etf_flags – etf_flag_t

set_enum_sign(sign:type_sign_t, etf_flags:uint=0)→tinfo_code_t
Set enum sign
Parameters:

-
sign – type_sign_t

-
etf_flags – etf_flag_t

ENUMBM_OFF
convert to ordinal enum
ENUMBM_ON
convert to bitmask enum
ENUMBM_AUTO
convert to bitmask if the outcome is nice and useful
set_enum_is_bitmask(*args)→tinfo_code_tset_enum_repr(repr:value_repr_t, etf_flags:uint=0)→tinfo_code_t
Set the representation of enum members.
Parameters:

-
repr – value_repr_t

-
etf_flags – etf_flag_t

set_enum_radix(radix:int, sign:bool, etf_flags:uint=0)→tinfo_code_t
Set enum radix to display constants
Parameters:

-
radix – radix 2, 4, 8, 16, with the special case 1 to display as character

-
sign – display as signed or unsigned

-
etf_flags – etf_flag_t

add_edm(*args)
Add an enumerator to the current enumeration.

When creating a new enumeration from scratch, you might want to first call create_enum()

This method has the following signatures:

-
add_edm(edm: edm_t, bmask: int = -1, etf_flags: int = 0, idx: int = -1)

-
add_edm(name: str, value: int, bmask: int = -1, etf_flags: int = 0, idx: int = -1)

If an input argument is incorrect, the constructor may raise an exception
Parameters:

-
edm – The member, fully initialized (1st form)

-
name – Enumerator name - must not be empty

-
value – Enumerator value

-
bmask – A bitmask to which the enumerator belongs

-
etf_flags – an OR’ed combination of ETF_ flags

-
idx – the index in the edm array where the new udm should be placed. If the specified index cannot be honored because it would spoil the edm sorting order, it is silently ignored.

del_edms(idx1:int, idx2:int, etf_flags:uint=0)→tinfo_code_t
Delete enum members
Parameters:

-
idx1 – index in edmvec_t

-
idx2 – index in edmvec_t or size_t(-1)

-
etf_flags – etf_flag_t Delete enum members in [idx1, idx2)

del_edm(*args)
Delete an enumerator with the specified name or the specified index, in the specified tinfo_t object.

This method has the following signatures:

-
del_edm(name: str) -> int

-
del_edm(index: int) -> int

Parameters:

-
name – an enumerator name (1st form)

-
index – an enumerator index (2nd form)

Returns:
TERR_OK in case of success, or another TERR_* value in case of error
del_edm_by_value(value:int, etf_flags:int=0, bmask:int=DEFMASK64, serial:int=0)
Delete an enumerator with the specified value, in the specified tinfo_t object.
Parameters:
value – the enumerator value
Returns:
TERR_OK in case of success, or another TERR_* value in case of error
rename_edm(idx:int, name:str, etf_flags:uint=0)→tinfo_code_t
Rename a enum member
Parameters:

-
idx – index in edmvec_t

-
name – new name

-
etf_flags – etf_flag_t ETF_FORCENAME may be used in case of TERR_ALIEN_NAME

set_edm_cmt(idx:int, cmt:str, etf_flags:uint=0)→tinfo_code_t
Set a comment for an enum member. Such comments are always considered as repeatable.
Parameters:

-
idx – index in edmvec_t

-
cmt – comment

-
etf_flags – etf_flag_t

edit_edm(*args)→tinfo_code_t
Change constant value and/or bitmask
Parameters:

-
idx – index in edmvec_t

-
value – old or new value

-
bmask – old or new bitmask

-
etf_flags – etf_flag_t

rename_funcarg(index:int, name:str, etf_flags:uint=0)→tinfo_code_t
Rename a function argument. The new name must be unique.
Parameters:

-
index – argument index in the function array

-
name – new name

-
etf_flags – etf_flag_t

set_funcarg_type(index:int, tif:tinfo_t, etf_flags:uint=0)→tinfo_code_t
Set type of a function argument.
Parameters:

-
index – argument index in the function array

-
tif – new type for the argument

-
etf_flags – etf_flag_t

Returns:
tinfo_code_t
set_func_rettype(tif:tinfo_t, etf_flags:uint=0)→tinfo_code_t
Set function return type .
Parameters:

-
tif – new type for the return type

-
etf_flags – etf_flag_t

Returns:
tinfo_code_t
del_funcargs(idx1:int, idx2:int, etf_flags:uint=0)→tinfo_code_t
Delete function arguments
Parameters:

-
idx1 – index in funcargvec_t

-
idx2 – index in funcargvec_t or size_t(-1)

-
etf_flags – etf_flag_t Delete function arguments in [idx1, idx2)

del_funcarg(idx:int, etf_flags:uint=0)→tinfo_code_tadd_funcarg(farg:funcarg_t, etf_flags:uint=0, idx:ssize_t=-1)→tinfo_code_t
Add a function argument.
Parameters:

-
farg – argument to add

-
etf_flags – type changing flags flags

-
idx – the index in the funcarg array where the new funcarg should be placed. if the specified index cannot be honored because it would spoil the funcarg sorting order, it is silently ignored.

set_func_cc(cc:callcnv_t, etf_flags:uint=0)→tinfo_code_t
Set function calling convention.
set_funcarg_loc(index:int, argloc:argloc_t, etf_flags:uint=0)→tinfo_code_t
Set location of a function argument.
Parameters:

-
index – argument index in the function array

-
argloc – new location for the argument

-
etf_flags – etf_flag_t

Returns:
tinfo_code_t
set_func_retloc(argloc:argloc_t, etf_flags:uint=0)→tinfo_code_t
Set location of function return value.
Parameters:

-
argloc – new location for the return value

-
etf_flags – etf_flag_t

Returns:
tinfo_code_t
compare(r:tinfo_t)→intcompare_with(r:tinfo_t, tcflags:int=0)→bool
Compare two types, based on given flags (see tinfo_t comparison flags)
equals_to(r:tinfo_t)→boolis_castable_to(target:tinfo_t)→boolis_manually_castable_to(target:tinfo_t)→boolserialize(*args)→PyObject*
Serialize tinfo_t object into a type string.
deserialize(*args)→bool
This function has the following signatures:

-
deserialize(til: const til_t , ptype: const type_t *, pfields: const p_list **=nullptr, pfldcmts: const p_list **=nullptr, cmt: str=nullptr) -> bool

-
deserialize(til: const til_t *, ptype: const qtype *, pfields: const qtype *=nullptr, pfldcmts: const qtype *=nullptr, cmt: str=nullptr) -> bool

# 0: deserialize(til: const til_t , ptype: const type_t *, pfields: const p_list **=nullptr, pfldcmts: const p_list **=nullptr, cmt: str=nullptr) -> bool

Deserialize a type string into a tinfo_t object.

# 1: deserialize(til: const til_t *, ptype: const qtype *, pfields: const qtype *=nullptr, pfldcmts: const qtype *=nullptr, cmt: str=nullptr) -> bool

Deserialize a type string into a tinfo_t object.
get_stkvar(insn:insn_tconst&, x:op_tconst, v:int)→ssize_t
Retrieve frame tinfo for a stack variable
Parameters:

-
insn – the instruction

-
x – reference to instruction operand, may be nullptr

-
v – immediate value in the operand (usually x.addr)

Returns:
returns the member index, otherwise returns -1. if the function fails, THIS object becomes empty.
copy()→tinfo_tget_attr(key:str, all_attrs:bool=True)→PyObject*
Get a type attribute.
get_edm(*args)→Tuple[int,edm_t]
Retrieve an enumerator with either the specified name or the specified index, in the specified tinfo_t object.

This function has the following signatures:

-
get_edm(index: int)

-
get_edm(name: str)

Parameters:

-
index – an enumerator index (1st form).

-
name – an enumerator name (2nd form).

Returns:
a tuple (int, edm_t), or (-1, None) if member not found
find_edm(*args)→ssize_titer_struct()
Iterate on the members composing this structure.

Example:

til = ida_typeinf.get_idati() tif = til.get_named_type(“my_struc”) for udm in tif.iter_struct():

print(f”{udm.name} at bit offset {udm.offset}”)

Will raise an exception if this type is not a structure.
Returns:
a udm_t-producing generator
iter_union()
Iterate on the members composing this union.

Example:

til = ida_typeinf.get_idati() tif = til.get_named_type(“my_union”) for udm in tif.iter_union():

print(f”{udm.name}, with type {udm.type}”)

Will raise an exception if this type is not a union.
Returns:
a udm_t-producing generator
iter_udt()
Iterate on the members composing this structure, or union.

Example:

til = ida_typeinf.get_idati() tif = til.get_named_type(“my_type”) for udm in tif.iter_udt():

print(f”{udm.name} at bit offset {udm.offset} with type {udm.type}”)

Will raise an exception if this type is not a structure, or union
Returns:
a udm_t-producing generator
iter_enum()
Iterate on the members composing this enumeration.

Example:

til = ida_typeinf.get_idati() tif = til.get_named_type(“my_enum”) for edm in tif.iter_enum():

print(f”{edm.name} = {edm.value}”)

Will raise an exception if this type is not an enumeration
Returns:
a edm_t-producing generator
iter_func()
Iterate on the arguments contained in this function prototype

Example:

address = … func = ida_funcs.get_func(address) func_type = func.prototype for arg in func_type.iter_func():

print(f”{arg.name}, of type {arg.type}”)

Will raise an exception if this type is not a function
Returns:
a funcarg_t-producing generator
get_edm_by_nameida_typeinf.COMP_MASKida_typeinf.COMP_UNK
Unknown.
ida_typeinf.COMP_MS
Visual C++.
ida_typeinf.COMP_BC
Borland C++.
ida_typeinf.COMP_WATCOM
Watcom C++.
ida_typeinf.COMP_GNU
GNU C++.
ida_typeinf.COMP_VISAGE
Visual Age C++.
ida_typeinf.COMP_BP
Delphi.
ida_typeinf.COMP_UNSURE
uncertain compiler id
ida_typeinf.BADSIZE
bad type size
ida_typeinf.FIRST_NONTRIVIAL_TYPID
Denotes the first bit describing a nontrivial type.
ida_typeinf.TYPID_ISREF
Identifies that a type that is a typeref.
ida_typeinf.TYPID_SHIFT
First type detail bit.
ida_typeinf.remove_pointer(tif:tinfo_t)→tinfo_t
BT_PTR: If the current type is a pointer, return the pointed object. If the current type is not a pointer, return the current type. See also get_ptrarr_object() and get_pointed_object()
ida_typeinf.STRMEM_MASKida_typeinf.STRMEM_OFFSET
get member by offset * in: udm->offset - is a member offset in bits
ida_typeinf.STRMEM_INDEX
get member by number * in: udm->offset - is a member number
ida_typeinf.STRMEM_AUTO
get member by offset if struct, or get member by index if union * nb: union: index is stored in the udm->offset field! * nb: struct: offset is in bytes (not in bits)!
ida_typeinf.STRMEM_NAME
get member by name * in: udm->name - the desired member name.
ida_typeinf.STRMEM_TYPE
get member by type. * in: udm->type - the desired member type. member types are compared with tinfo_t::equals_to()
ida_typeinf.STRMEM_SIZE
get member by size. * in: udm->size - the desired member size.
ida_typeinf.STRMEM_MINS
get smallest member by size.
ida_typeinf.STRMEM_MAXS
get biggest member by size.
ida_typeinf.STRMEM_LOWBND
get member by offset or the next member (lower bound) * in: udm->offset - is a member offset in bits
ida_typeinf.STRMEM_NEXT
get next member after the offset * in: udm->offset - is a member offset in bits
ida_typeinf.STRMEM_VFTABLE
can be combined with STRMEM_OFFSET, STRMEM_AUTO get vftable instead of the base class
ida_typeinf.STRMEM_SKIP_EMPTY
can be combined with STRMEM_OFFSET, STRMEM_AUTO skip empty members (i.e. having zero size) only last empty member can be returned
ida_typeinf.STRMEM_CASTABLE_TO
can be combined with STRMEM_TYPE: member type must be castable to the specified type
ida_typeinf.STRMEM_ANON
can be combined with STRMEM_NAME: look inside anonymous members too.
ida_typeinf.STRMEM_SKIP_GAPS
can be combined with STRMEM_OFFSET, STRMEM_LOWBND skip gap members
ida_typeinf.TCMP_EQUAL
are types equal?
ida_typeinf.TCMP_IGNMODS
ignore const/volatile modifiers
ida_typeinf.TCMP_AUTOCAST
can t1 be cast into t2 automatically?
ida_typeinf.TCMP_MANCAST
can t1 be cast into t2 manually?
ida_typeinf.TCMP_CALL
can t1 be called with t2 type?
ida_typeinf.TCMP_DELPTR
remove pointer from types before comparing
ida_typeinf.TCMP_DECL
compare declarations without resolving them
ida_typeinf.TCMP_ANYBASE
accept any base class when casting
ida_typeinf.TCMP_SKIPTHIS
skip the first function argument in comparison
ida_typeinf.TCMP_DEEP_UDT
compare udt by member/attributes
classida_typeinf.simd_info_t(*args)
Bases: `object`
thisownSIMD_VARIADICname:str
name of SIMD type (nullptr-undefined)
tif:tinfo_t
SIMD type (empty-undefined)
size:uint16
SIMD type size in bytes (0-undefined, 0xFFFF-variadic)
memtype:type_t
member type BTF_INT8/16/32/64/128, BTF_UINT8/16/32/64/128 BTF_INT - integrals of any size/sign BTF_FLOAT, BTF_DOUBLE BTF_TBYTE - floating: float16 for variadic any size for non-variadic BTF_UNION - union of integral and floating types BTF_UNK - undefined
is_variadic()→boolmatch_pattern(pattern:simd_info_t)→boolclassida_typeinf.simd_info_vec_t
Bases: `qvector_simd_info_vec_t`
thisownida_typeinf.guess_func_cc(fti:func_type_data_t, npurged:int, cc_flags:int)→callcnv_t
Use func_type_data_t::guess_cc()
ida_typeinf.dump_func_type_data(fti:func_type_data_t, praloc_bits:int)→str
Use func_type_data_t::dump()
ida_typeinf.calc_arglocs(fti:func_type_data_t)→boolida_typeinf.calc_varglocs(fti:func_type_data_t, regs:regobjs_t, stkargs:relobj_t, nfixed:int)→boolclassida_typeinf.ptr_type_data_t(*args)
Bases: `object`
thisownobj_type:tinfo_t
pointed object type
closure:tinfo_t
cannot have both closure and based_ptr_size
parent:tinfo_t
Parent struct.
delta:int
Offset from the beginning of the parent struct.
based_ptr_size:uchartaptr_bits:uchar
TAH bits.
swap(r:ptr_type_data_t)→None
Set this = r and r = this.
is_code_ptr()→bool
Are we pointing to code?
is_shifted()→boolclassida_typeinf.array_type_data_t(b:int=0, n:int=0)
Bases: `object`
thisownelem_type:tinfo_t
element type
base:int
array base
nelems:int
number of elements
swap(r:array_type_data_t)→None
set this = r and r = this
classida_typeinf.funcarg_t(*args)
Bases: `object`
thisownargloc:argloc_t
argument location
name:str
argument name (may be empty)
cmt:str
argument comment (may be empty)
type:tinfo_t
argument type
flags:int
Function argument property bits
ida_typeinf.FAI_HIDDEN
hidden argument
ida_typeinf.FAI_RETPTR
pointer to return value. implies hidden
ida_typeinf.FAI_STRUCT
was initially a structure
ida_typeinf.FAI_ARRAY
was initially an array; see “__org_typedef” or “__org_arrdim” type attributes to determine the original type
ida_typeinf.FAI_UNUSED
argument is not used by the function
classida_typeinf.func_type_data_t
Bases: `funcargvec_t`
thisownflags:int
Function type data property bits
rettype:tinfo_t
return type
retloc:argloc_t
return location
stkargs:int
size of stack arguments (not used in build_func_type)
spoiled:reginfovec_t
spoiled register information. if spoiled register info is present, it overrides the standard spoil info (eax, edx, ecx for x86)
get_explicit_cc()→callcnv_tget_cc()→callcnv_tset_cc(cc:callcnv_t)→Noneswap(r:func_type_data_t)→Noneis_high()→boolis_noret()→boolis_pure()→boolis_static()→boolis_virtual()→boolis_const()→boolis_ctor()→boolis_dtor()→boolget_call_method()→intis_vararg_cc()→boolis_golang_cc()→boolis_swift_cc()→boolis_user_cc()→boolguess_cc(purged:int, cc_flags:int)→callcnv_t
Guess function calling convention use the following info: argument locations and ‘stkargs’
dump(praloc_bits:int=2)→bool
Dump information that is not always visible in the function prototype. (argument locations, return location, total stkarg size)
find_argument(*args)→ssize_t
find argument by name
ida_typeinf.FTI_SPOILED
information about spoiled registers is present
ida_typeinf.FTI_NORET
noreturn
ida_typeinf.FTI_PURE
__pure
ida_typeinf.FTI_HIGH
high level prototype (with possibly hidden args)
ida_typeinf.FTI_STATIC
static
ida_typeinf.FTI_VIRTUAL
virtual
ida_typeinf.FTI_CALLTYPE
mask for FTI_*CALL
ida_typeinf.FTI_DEFCALL
default call
ida_typeinf.FTI_NEARCALL
near call
ida_typeinf.FTI_FARCALL
far call
ida_typeinf.FTI_INTCALL
interrupt call
ida_typeinf.FTI_ARGLOCS
info about argument locations has been calculated (stkargs and retloc too)
ida_typeinf.FTI_EXPLOCS
all arglocs are specified explicitly
ida_typeinf.FTI_CONST
const member function
ida_typeinf.FTI_CTOR
constructor
ida_typeinf.FTI_DTOR
destructor
ida_typeinf.FTI_ALL
all defined bits
ida_typeinf.CC_CDECL_OK
can use __cdecl calling convention?
ida_typeinf.CC_ALLOW_ARGPERM
disregard argument order?
ida_typeinf.CC_ALLOW_REGHOLES
allow holes in register argument list?
ida_typeinf.CC_HAS_ELLIPSIS
function has a variable list of arguments?
ida_typeinf.CC_GOLANG_OK
can use __golang calling convention
ida_typeinf.FMTFUNC_PRINTFida_typeinf.FMTFUNC_SCANFida_typeinf.FMTFUNC_STRFTIMEida_typeinf.FMTFUNC_STRFMONclassida_typeinf.edm_t(*args)
Bases: `object`
thisownname:strcmt:strvalue:uint64empty()→boolswap(r:edm_t)→Noneget_tid()→tid_tclassida_typeinf.enum_type_data_t(*args)
Bases: `edmvec_t`
thisowngroup_sizes:intvec_t
if present, specifies bitmask group sizes each non-trivial group starts with a mask member
taenum_bits:int
Type attributes for enums
bte:bte_t
enum member sizes (shift amount) and style. do not manually set BTE_BITMASK, use set_enum_is_bitmask()
get_enum_radix()→int
Get enum constant radix
Returns:
radix or 1 for BTE_CHAR
is_number_signed()→boolset_enum_radix(radix:int, sign:bool)→None
Set radix to display constants
Parameters:
radix – radix with the special case 1 to display as character
is_char()→boolis_dec()→boolis_hex()→boolis_oct()→boolis_bin()→boolis_udec()→boolis_shex()→boolis_soct()→boolis_sbin()→boolhas_lzero()→boolset_lzero(on:bool)→Nonecalc_mask()→uint64store_64bit_values()→boolis_bf()→bool
is bitmask or ordinary enum?
calc_nbytes()→int
get the width of enum in bytes
set_nbytes(nbytes:int)→bool
set enum width (nbytes)
is_group_mask_at(idx:int)→bool
is the enum member at IDX a non-trivial group mask? a trivial group consist of one bit and has just one member, which can be considered as a mask or a bitfield constant
Parameters:
idx – index
Returns:
success
is_valid_group_sizes()→bool
is valid group sizes
find_member(*args)→ssize_t
This function has the following signatures:

-
find_member(name: str, from: int=0, to: int=size_t(-1)) -> ssize_t

-
find_member(value: uint64, serial: uchar, from: int=0, to: int=size_t(-1), vmask: uint64=uint64(-1)) -> ssize_t

# 0: find_member(name: str, from: int=0, to: int=size_t(-1)) -> ssize_t

find member (constant or bmask) by name

# 1: find_member(value: uint64, serial: uchar, from: int=0, to: int=size_t(-1), vmask: uint64=uint64(-1)) -> ssize_t

find member (constant or bmask) by value
swap(r:enum_type_data_t)→None
swap two instances
add_constant(name:str, value:uint64, cmt:str=None)→None
add constant for regular enum
get_value_repr(repr:value_repr_t)→tinfo_code_t
get enum radix and other representation info
Parameters:
repr – value display info
set_value_repr(repr:value_repr_t)→tinfo_code_t
set enum radix and other representation info
Parameters:
repr – value display info
get_serial(index:int)→uchar
returns serial for the constant
get_max_serial(value:uint64)→uchar
return the maximum serial for the value
get_constant_group(*args)→PyObject*
get group parameters for the constant, valid for bitmask enum
Parameters:

-
group_start_index – index of the group mask

-
group_size – group size (>=1)

-
idx – constant index

Returns:
success
all_groups(skip_trivial=False)
Generate tuples for bitmask enum groups. Each tupple is: [0] enum member index of group start [1] group size Tupples may include or not the group with 1 element.
all_constants()
Generate tupples of all constants except of bitmasks. Each tupple is: [0] constant index [1] enum member index of group start [2] group size In case of regular enum the second element of tupple is 0 and the third element of tupple is the number of enum members.
classida_typeinf.typedef_type_data_t(*args)
Bases: `object`
thisowntil:til_tconst*
type library to use when resolving
name:str
is_ordref=false: target type name. we do not own this pointer!
ordinal:int
is_ordref=true: type ordinal number
is_ordref:bool
is reference by ordinal?
resolve:bool
should resolve immediately?
swap(r:typedef_type_data_t)→Noneida_typeinf.MAX_ENUM_SERIAL
Max number of identical constants allowed for one enum type.
classida_typeinf.custom_data_type_info_t
Bases: `object`
thisowndtid:int16
data type id
fid:int16
data format ids
classida_typeinf.value_repr_t
Bases: `object`
thisownbits:uint64ri:refinfo_t
FRB_OFFSET.
strtype:int
FRB_STRLIT.
delta:adiff_t
FRB_STROFF.
type_ordinal:int
FRB_STROFF, FRB_ENUM.
cd:custom_data_type_info_t
FRB_CUSTOM.
ap:array_parameters_t
FRB_TABFORM, AP_SIGNED is ignored, use FRB_SIGNED instead
swap(r:value_repr_t)→Noneclear()→Noneempty()→boolis_enum()→boolis_offset()→boolis_strlit()→boolis_custom()→boolis_stroff()→boolis_typref()→boolis_signed()→boolhas_tabform()→boolhas_lzeroes()→boolget_vtype()→uint64set_vtype(vt:uint64)→Noneset_signed(on:bool)→Noneset_tabform(on:bool)→Noneset_lzeroes(on:bool)→Noneset_ap(_ap:array_parameters_t)→Noneinit_ap(_ap:array_parameters_t)→Nonefrom_opinfo(flags:flags64_t, afl:aflags_t, opinfo:opinfo_t, _ap:array_parameters_t)→boolparse_value_repr(*args)→boolida_typeinf.FRB_MASK
Mask for the value type (* means requires additional info):
ida_typeinf.FRB_UNK
Unknown.
ida_typeinf.FRB_NUMB
Binary number.
ida_typeinf.FRB_NUMO
Octal number.
ida_typeinf.FRB_NUMH
Hexadecimal number.
ida_typeinf.FRB_NUMD
Decimal number.
ida_typeinf.FRB_FLOAT
Floating point number (for interpreting an integer type as a floating value)
ida_typeinf.FRB_CHAR
Char.
ida_typeinf.FRB_SEG
Segment.
ida_typeinf.FRB_ENUM
*Enumeration
ida_typeinf.FRB_OFFSET
*Offset
ida_typeinf.FRB_STRLIT
*String literal (used for arrays)
ida_typeinf.FRB_STROFF
*Struct offset
ida_typeinf.FRB_CUSTOM
*Custom data type
ida_typeinf.FRB_INVSIGN
Invert sign (0x01 is represented as -0xFF)
ida_typeinf.FRB_INVBITS
Invert bits (0x01 is represented as ~0xFE)
ida_typeinf.FRB_SIGNED
Force signed representation.
ida_typeinf.FRB_LZERO
Toggle leading zeros (used for integers)
ida_typeinf.FRB_TABFORM
has additional tabular parameters
classida_typeinf.udm_t(*args)
Bases: `object`
thisownoffset:uint64
member offset in bits
size:uint64
size in bits
name:str
member name
cmt:str
member comment
type:tinfo_t
member type
repr:value_repr_t
radix, refinfo, strpath, custom_id, strtype
effalign:int
effective field alignment (in bytes)
tafld_bits:int
TAH bits.
fda:uchar
field alignment (shift amount)
empty()→boolis_bitfield()→boolis_zero_bitfield()→boolis_unaligned()→boolis_baseclass()→boolis_virtbase()→boolis_vftable()→boolis_method()→boolis_gap()→boolis_regcmt()→boolis_retaddr()→boolis_savregs()→boolis_special_member()→boolis_by_til()→boolset_unaligned(on:bool=True)→Noneset_baseclass(on:bool=True)→Noneset_virtbase(on:bool=True)→Noneset_vftable(on:bool=True)→Noneset_method(on:bool=True)→Noneset_regcmt(on:bool=True)→Noneset_retaddr(on:bool=True)→Noneset_savregs(on:bool=True)→Noneset_by_til(on:bool=True)→Noneclr_unaligned()→Noneclr_baseclass()→Noneclr_virtbase()→Noneclr_vftable()→Noneclr_method()→Nonebegin()→uint64end()→uint64compare_with(r:udm_t, tcflags:int)→boolswap(r:udm_t)→Noneis_anonymous_udm()→boolset_value_repr(r:value_repr_t)→Nonecan_be_dtor()→boolcan_rename()→boolclassida_typeinf.udtmembervec_t
Bases: `udtmembervec_template_t`
thisownclassida_typeinf.udt_type_data_t
Bases: `udtmembervec_t`
thisowntotal_size:int
total structure size in bytes
unpadded_size:int
unpadded structure size in bytes
effalign:int
effective structure alignment (in bytes)
taudt_bits:int
TA… and TAUDT… bits.
version:uchar
version of udt_type_data_t
sda:uchar
declared structure alignment (shift amount+1). 0 - unspecified
pack:uchar
#pragma pack() alignment (shift amount)
is_union:bool
is union or struct?
swap(r:udt_type_data_t)→Noneis_unaligned()→boolis_msstruct()→boolis_cppobj()→boolis_vftable()→boolis_fixed()→boolis_tuple()→boolis_iface()→boolset_vftable(on:bool=True)→Noneset_fixed(on:bool=True)→Noneset_tuple(on:bool=True)→Noneset_iface(on:bool=True)→Noneis_last_baseclass(idx:int)→booladd_member(_name:str, _type:tinfo_t, _offset:uint64=0)→udm_t&
Add a new member to a structure or union. This function just pushes a new member to the back of the structure/union member vector.
Parameters:

-
_name – Member name. Must not be nullptr.

-
_type – Member type. Must not be empty.

-
_offset – Member offset in bits. It is the caller’s responsibility to specify correct offsets.

Returns:
{ Reference to the newly added member }
find_member(*args)→ssize_t
This function has the following signatures:

-
find_member(pattern_udm: udm_t *, strmem_flags: int) -> ssize_t

-
find_member(name: str) -> ssize_t

-
find_member(bit_offset: uint64) -> ssize_t

# 0: find_member(pattern_udm: udm_t *, strmem_flags: int) -> ssize_t

tinfo_t::find_udm
Returns:
the index of the found member or -1

# 1: find_member(name: str) -> ssize_t

# 2: find_member(bit_offset: uint64) -> ssize_t
get_best_fit_member(disp)
Get the member that is most likely referenced by the specified offset.
Parameters:
disp – the byte offset
Returns:
a tuple (int, udm_t), or (-1, None) if member not found
deduplicate_members()→bool
Rename members with the same names. This function finds duplicate member names and renames them by adding a numeric suffix like _2, _3, etc. Also, it renames destructors by substituting ~ by dtr_.
Returns:
true if renamed a member
ida_typeinf.STRUC_SEPARATOR
structname.fieldname
ida_typeinf.VTBL_SUFFIXida_typeinf.VTBL_LAYOUT_SUFFIXida_typeinf.VTBL_MEMNAMEida_typeinf.stroff_as_size(plen:int, tif:tinfo_t, value:asize_t)→bool
Should display a structure offset expression as the structure size?
classida_typeinf.udm_visitor_t
Bases: `object`
thisownvisit_udm(tid:tid_t, tif:tinfo_t, udt:udt_type_data_t, idx:ssize_t)→intParameters:

-
tid – udt tid

-
tif – udt type info (may be nullptr for corrupted idbs)

-
udt – udt type data (may be nullptr for corrupted idbs)

-
idx – the index of udt the member (may be -1 if udm was not found)

ida_typeinf.visit_stroff_udms(sfv:udm_visitor_t, path:tid_tconst*, disp:adiff_t*, appzero:bool)→adiff_t*
Visit structure fields in a stroff expression or in a reference to a struct data variable. This function can be used to enumerate all components of an expression like ‘a.b.c’.
Parameters:

-
sfv – visitor object

-
path – struct path (path[0] contains the initial struct id)

-
disp – offset into structure

-
appzero – should visit field at offset zero?

Returns:
visitor result
classida_typeinf.bitfield_type_data_t(_nbytes:uchar=0, _width:uchar=0, _is_unsigned:bool=False)
Bases: `object`
thisownnbytes:uchar
enclosing type size (1,2,4,8 bytes)
width:uchar
number of bits
is_unsigned:bool
is bitfield unsigned?
compare(r:bitfield_type_data_t)→intswap(r:bitfield_type_data_t)→Noneis_valid_bitfield()→boolida_typeinf.TPOS_LNNUMida_typeinf.TPOS_REGCMTida_typeinf.is_one_bit_mask(mask:int)→bool
Is bitmask one bit?
ida_typeinf.inf_pack_stkargs(*args)→boolida_typeinf.inf_big_arg_align(*args)→boolida_typeinf.inf_huge_arg_align(*args)→boolclassida_typeinf.type_mods_t
Bases: `object`
thisowntype:tinfo_t
current type
name:str
current type name
cmt:str
comment for current type
flags:int
Type modification bits
clear()→Noneset_new_type(t:tinfo_t)→None
The visit_type() function may optionally save the modified type info. Use the following functions for that. The new name and comment will be applied only if the current tinfo element has storage for them.
set_new_name(n:str)→Noneset_new_cmt(c:str, rptcmt:bool)→Nonehas_type()→boolhas_name()→boolhas_cmt()→boolis_rptcmt()→boolhas_info()→boolida_typeinf.TVIS_TYPE
new type info is present
ida_typeinf.TVIS_NAME
new name is present (only for funcargs and udt members)
ida_typeinf.TVIS_CMT
new comment is present (only for udt members)
ida_typeinf.TVIS_RPTCMT
the new comment is repeatable
classida_typeinf.tinfo_visitor_t(s:int=0)
Bases: `object`
thisownstate:int
tinfo visitor states
visit_type(out:type_mods_t, tif:tinfo_t, name:str, cmt:str)→int
Visit a subtype. this function must be implemented in the derived class. it may optionally fill out with the new type info. this can be used to modify types (in this case the ‘out’ argument of apply_to() may not be nullptr) return 0 to continue the traversal. return !=0 to stop the traversal.
prune_now()→None
To refuse to visit children of the current type, use this:
apply_to(tif:tinfo_t, out:type_mods_t=None, name:str=None, cmt:str=None)→int
Call this function to initiate the traversal.
ida_typeinf.TVST_PRUNE
don’t visit children of current type
ida_typeinf.TVST_DEF
visit type definition (meaningful for typerefs)
ida_typeinf.TVST_LEVELclassida_typeinf.regobj_t
Bases: `object`
thisownregidx:int
index into dbg->registers
relocate:int
0-plain num, 1-must relocate
value:bytevec_tsize()→intclassida_typeinf.regobjs_t
Bases: `regobjvec_t`
thisownida_typeinf.unpack_idcobj_from_idb(obj:idc_value_t*, tif:tinfo_t, ea:ida_idaapi.ea_t, off0:bytevec_tconst*, pio_flags:int=0)→error_t
Collection of register objects.

Read a typed idc object from the database
ida_typeinf.PIO_NOATTR_FAIL
missing attributes are not ok
ida_typeinf.PIO_IGNORE_PTRS
do not follow pointers
ida_typeinf.unpack_idcobj_from_bv(obj:idc_value_t*, tif:tinfo_t, bytes:bytevec_tconst&, pio_flags:int=0)→error_t
Read a typed idc object from the byte vector.
ida_typeinf.pack_idcobj_to_idb(obj:idc_value_tconst*, tif:tinfo_t, ea:ida_idaapi.ea_t, pio_flags:int=0)→error_t
Write a typed idc object to the database.
ida_typeinf.pack_idcobj_to_bv(obj:idc_value_tconst*, tif:tinfo_t, bytes:relobj_t, objoff:void*, pio_flags:int=0)→error_t
Write a typed idc object to the byte vector. Byte vector may be non-empty, this function will append data to it
ida_typeinf.apply_tinfo_to_stkarg(insn:insn_tconst&, x:op_tconst&, v:int, tif:tinfo_t, name:str)→bool
Helper function for the processor modules. to be called from processor_t::use_stkarg_type
classida_typeinf.argtinfo_helper_t
Bases: `object`
thisownreserved:intset_op_tinfo(insn:insn_tconst&, x:op_tconst&, tif:tinfo_t, name:str)→bool
Set the operand type as specified.
is_stkarg_load(insn:insn_tconst&, src:int*, dst:int*)→bool
Is the current insn a stkarg load? if yes: * src: index of the source operand in insn_t::ops * dst: index of the destination operand in insn_t::ops insn_t::ops[dst].addr is expected to have the stack offset
has_delay_slot(arg0:ida_idaapi.ea_t)→bool
The call instruction with a delay slot?
use_arg_tinfos(caller:ida_idaapi.ea_t, fti:func_type_data_t, rargs:funcargvec_t)→None
This function is to be called by the processor module in response to ev_use_arg_types.
ida_typeinf.gen_use_arg_tinfos(_this:argtinfo_helper_t, caller:ida_idaapi.ea_t, fti:func_type_data_t, rargs:funcargvec_t)→None
Do not call this function directly, use argtinfo_helper_t.
ida_typeinf.func_has_stkframe_hole(ea:ida_idaapi.ea_t, fti:func_type_data_t)→bool
Looks for a hole at the beginning of the stack arguments. Will make use of the IDB’s func_t function at that place (if present) to help determine the presence of such a hole.
classida_typeinf.lowertype_helper_t(*args, **kwargs)
Bases: `object`
thisownfunc_has_stkframe_hole(candidate:tinfo_t, candidate_data:func_type_data_t)→boolget_func_purged_bytes(candidate:tinfo_t, candidate_data:func_type_data_t)→intclassida_typeinf.ida_lowertype_helper_t(_tif:tinfo_t, _ea:ida_idaapi.ea_t, _pb:int)
Bases: `lowertype_helper_t`
thisownfunc_has_stkframe_hole(candidate:tinfo_t, candidate_data:func_type_data_t)→boolget_func_purged_bytes(candidate:tinfo_t, arg3:func_type_data_t)→intida_typeinf.lower_type(til:til_t, tif:tinfo_t, name:str=None, _helper:lowertype_helper_t=None)→int
Lower type. Inspect the type and lower all function subtypes using lower_func_type(). We call the prototypes usually encountered in source files “high level” They may have implicit arguments, array arguments, big structure retvals, etc We introduce explicit arguments (i.e. ‘this’ pointer) and call the result “low level prototype”. See FTI_HIGH. In order to improve heuristics for recognition of big structure retvals, it is recommended to pass a helper that will be used to make decisions. That helper will be used only for lowering ‘tif’, and not for the children types walked through by recursion.
Returns:
1: removed FTI_HIGH,
Returns:
2: made substantial changes
Returns:
-1: failure
ida_typeinf.replace_ordinal_typerefs(til:til_t, tif:tinfo_t)→int
Replace references to ordinal types by name references. This function ‘unties’ the type from the current local type library and makes it easier to export it.
Parameters:

-
til – type library to use. may be nullptr.

-
tif – type to modify (in/out)

Returns:
number: of replaced subtypes, -1 on failure
ida_typeinf.UTP_ENUMida_typeinf.UTP_STRUCTida_typeinf.begin_type_updating(utp:update_type_t)→None
Mark the beginning of a large update operation on the types. Can be used with add_enum_member(), add_struc_member, etc… Also see end_type_updating()
ida_typeinf.end_type_updating(utp:update_type_t)→None
Mark the end of a large update operation on the types (see begin_type_updating())
ida_typeinf.get_named_type_tid(name:str)→tid_t
Get named local type TID
Parameters:
name – type name
Returns:
TID or BADADDR
ida_typeinf.get_tid_name(tid:tid_t)→str
Get a type name for the specified TID
Parameters:
tid – type TID
Returns:
true if there is type with TID
ida_typeinf.get_tid_ordinal(tid:tid_t)→int
Get type ordinal number for TID
Parameters:
tid – type/enum constant/udt member TID
Returns:
type ordinal number or 0
ida_typeinf.get_udm_by_fullname(udm:udm_t, fullname:str)→ssize_t
Get udt member by full name
Parameters:

-
udm – member, can be NULL

-
fullname – udt member name in format .

Returns:
member index into udt_type_data_t or -1
ida_typeinf.get_idainfo_by_udm(*args)→bool
Calculate IDA info from udt member
Parameters:

-
udm – udt member

-
refinfo_ea – if specified will be used to adjust the refinfo_t data

ida_typeinf.create_enum_type(enum_name:str, ei:enum_type_data_t, enum_width:int, sign:type_sign_t, convert_to_bitmask:bool, enum_cmt:str=None)→tid_t
Create type enum
Parameters:

-
enum_name – type name

-
ei – enum type data

-
enum_width – the width of an enum element allowed values: 0 (unspecified),1,2,4,8,16,32,64

-
sign – enum sign

-
convert_to_bitmask – try convert enum to bitmask enum

-
enum_cmt – enum type comment

Returns:
enum TID
classida_typeinf.valstr_t
Bases: `object`
thisownoneline:str
result if printed on one line in UTF-8 encoding
length:int
length if printed on one line
members:valstrs_t*
strings for members, each member separately
info:valinfo_t*
additional info
props:int
temporary properties, used internally
ida_typeinf.VALSTR_OPEN
printed opening curly brace ‘{’
classida_typeinf.valstrs_t
Bases: `valstrvec_t`
thisownclassida_typeinf.text_sink_t
Bases: `object`
thisownida_typeinf.PDF_INCL_DEPS
Include all type dependencies.
ida_typeinf.PDF_DEF_FWD
Allow forward declarations.
ida_typeinf.PDF_DEF_BASE
Include base types: __int8, __int16, etc..
ida_typeinf.PDF_HEADER_CMT
Prepend output with a descriptive comment.
ida_typeinf.PDF_NO_ANON_NAME
Ignore types with anonymous name.
ida_typeinf.calc_number_of_children(loc:argloc_t, tif:tinfo_t, dont_deref_ptr:bool=False)→int
Calculate max number of lines of a formatted c data, when expanded (PTV_EXPAND).
Parameters:

-
loc – location of the data (ALOC_STATIC or ALOC_CUSTOM)

-
tif – type info

-
dont_deref_ptr – consider ‘ea’ as the ptr value

Returns:
0: data is not expandable
Returns:
-1: error, see qerrno
Returns:
else: the max number of lines
ida_typeinf.get_enum_member_expr(tif:tinfo_t, serial:int, value:uint64)→str
Return a C expression that can be used to represent an enum member. If the value does not correspond to any single enum member, this function tries to find a bitwise combination of enum members that correspond to it. If more than half of value bits do not match any enum members, it fails.
Parameters:

-
tif – enumeration type

-
serial – which enumeration member to use (0 means the first with the given value)

-
value – value to search in the enumeration type

Returns:
success
classida_typeinf.til_symbol_t(n:str=None, t:til_t=None)
Bases: `object`
thisownname:str
symbol name
til:til_tconst*
pointer to til
classida_typeinf.predicate_t
Bases: `object`
thisownshould_display(til:til_t, name:str, type:type_tconst*, fields:p_listconst*)→boolida_typeinf.choose_named_type(out_sym:til_symbol_t, root_til:til_t, title:str, ntf_flags:int, predicate:predicate_t=None)→bool
Choose a type from a type library.
Parameters:

-
out_sym – pointer to be filled with the chosen type

-
root_til – pointer to starting til (the function will inspect the base tils if allowed by flags)

-
title – title of listbox to display

-
ntf_flags – combination of Flags for named types

-
predicate – predicate to select types to display (maybe nullptr)

Returns:
false if nothing is chosen, otherwise true
ida_typeinf.calc_retloc(*args)→bool
This function has the following signatures:

-
calc_retloc(fti: func_type_data_t *) -> bool

-
calc_retloc(retloc: argloc_t *, rettype: const tinfo_t &, cc: callcnv_t) -> bool

# 0: calc_retloc(fti: func_type_data_t *) -> bool

# 1: calc_retloc(retloc: argloc_t *, rettype: const tinfo_t &, cc: callcnv_t) -> bool
classida_typeinf.til_type_ref_t
Bases: `object`
thisowncb:inttif:tinfo_tcursor:tif_cursor_tordinal:intis_writable:boolis_detached:boolis_forward:boolkind:type_tmemidx:ssize_tnmembers:intudm:udm_t
BTF_STRUCT or BTF_UNION: the current member.
total_size:intunpadded_size:intlast_udm_offset:uint64bucket_start:uint64bf_bitoff:intoffset:uint64edm:edm_t
BTF_ENUM: the current enum member.
fa:funcarg_tconst*
BT_FUNC: the current argument, nullptr - ellipsis.
clear()→Noneon_member()→boolis_typedef()→boolis_struct()→boolis_union()→boolis_enum()→boolis_func()→boolis_udt()→boolida_typeinf.choose_local_tinfo(arg1:til_t, arg2:str, arg3:til_tinfo_predicate_t*, arg4:int, arg5:void*)→intida_typeinf.choose_local_tinfo_and_delta(arg1:int32*, arg2:til_t, arg3:str, arg4:til_tinfo_predicate_t*, arg5:int, arg6:void*)→intida_typeinf.register_custom_callcnv(cnv_incref:custom_callcnv_t)→custom_callcnv_t*
Register a calling convention
Returns:
CM_CC_INVALID means failure:

-
bad ccinf.name

-
ccinf.name already exists

-
the calling convention is special (usercall, purging, vararg) and there are too many of them already

ida_typeinf.unregister_custom_callcnv(cnv_decref:custom_callcnv_t)→custom_callcnv_t*
Unregister a calling convention
Returns:
true if successfully unregistered the custom calling convention
ida_typeinf.idc_parse_decl(til:til_t, decl:str, flags:int)→Tuple[str,bytes,bytes]ida_typeinf.calc_type_size(til:til_t, type:bytes)
Returns the size of a type :param til: Type info library. ‘None’ can be passed. :param type: serialized type byte string :returns: The size of the type (None on failure)
ida_typeinf.apply_type(til:til_t, type:bytes, fields:bytes, ea:ida_idaapi.ea_t, flags:int)→bool
Apply the specified type to the address
Parameters:

-
til – Type info library. ‘None’ can be used.

-
type – type string

-
fields – fields string (may be empty or None)

-
ea – the address of the object

-
flags – combination of TINFO_… constants or 0

Returns:
Boolean
ida_typeinf.get_arg_addrs(caller:ida_idaapi.ea_t)
Retrieve addresses of argument initialization instructions
Parameters:
caller – the address of the call instruction
Returns:
list of instruction addresses
ida_typeinf.unpack_object_from_idb(til:til_t, type:bytes, fields:bytes, ea:ida_idaapi.ea_t, pio_flags:int=0)
Unpacks from the database at ‘ea’ to an object. Please refer to unpack_object_from_bv()
ida_typeinf.unpack_object_from_bv(til:til_t, type:unpack_object_from_bv.bytes, fields:unpack_object_from_bv.bytes, bytes, pio_flags:int=0)
Unpacks a buffer into an object. Returns the error_t returned by idaapi.pack_object_to_idb
Parameters:

-
til – Type library. ‘None’ can be passed.

-
type – type string

-
fields – fields string (may be empty or None)

-
bytes – the bytes to unpack

-
pio_flags – flags used while unpacking

Returns:
tuple(1, obj) on success, or tuple(0, err) on failure
ida_typeinf.pack_object_to_idb(obj, til:til_t, type:bytes, fields:bytes, ea:ida_idaapi.ea_t, pio_flags:int=0)
Write a typed object to the database. Raises an exception if wrong parameters were passed or conversion fails Returns the error_t returned by idaapi.pack_object_to_idb
Parameters:

-
til – Type library. ‘None’ can be passed.

-
type – type string

-
fields – fields string (may be empty or None)

-
ea – ea to be used while packing

-
pio_flags – flags used while unpacking

ida_typeinf.pack_object_to_bv(obj, til:til_t, type:bytes, fields:bytes, base_ea:ida_idaapi.ea_t, pio_flags:int=0)
Packs a typed object to a string
Parameters:

-
til – Type library. ‘None’ can be passed.

-
type – type string

-
fields – fields string (may be empty or None)

-
base_ea – base ea used to relocate the pointers in the packed object

-
pio_flags – flags used while unpacking

Returns:
tuple(1, packed_buf) on success, or tuple(0, err_code) on failure
ida_typeinf.PT_FILEida_typeinf.PT_STANDALONEida_typeinf.idc_parse_types(input:str, flags:int)→intida_typeinf.idc_get_type_raw(ea:ida_idaapi.ea_t)→PyObject*ida_typeinf.idc_get_local_type_raw(ordinal)→Tuple[bytes,bytes]ida_typeinf.idc_guess_type(ea:ida_idaapi.ea_t)→strida_typeinf.idc_get_type(ea:ida_idaapi.ea_t)→strida_typeinf.idc_set_local_type(ordinal:int, dcl:str, flags:int)→intida_typeinf.idc_get_local_type(ordinal:int, flags:int)→strida_typeinf.idc_print_type(type:bytes, fields:bytes, name:str, flags:int)→strida_typeinf.idc_get_local_type_name(ordinal:int)→strida_typeinf.get_named_type(til:til_t, name:str, ntf_flags:int)
Get a type data by its name.
Parameters:

-
til – Type library

-
name – the type name

-
ntf_flags – a combination of NTF_* constants

Returns:
tuple(code, type_str, fields_str, cmt, field_cmts, sclass, value) on success, or None on failure
ida_typeinf.get_named_type64(til:til_t, name:str, ntf_flags:int=0)→Tuple[int,bytes,bytes,str,str,int,int]|None
Get a named type from a type library.

Please use til_t.get_named_type instead.
ida_typeinf.print_decls(printer:text_sink_t, til:til_t, ordinals:List[int], flags:int)→int
Print types (and possibly their dependencies) in a format suitable for using in a header file. This is the reverse parse_decls().
Parameters:

-
printer – a handler for printing text

-
til – the type library holding the ordinals

-
ordinals – a list of ordinals corresponding to the types to print

-
flags – a combination of PDF_ constants

Returns:
>0: the number of types exported
Returns:
0: an error occurred
Returns:
<0: the negated number of types exported. There were minor errors and the resulting output might not be compilable.
ida_typeinf.remove_tinfo_pointer(tif:tinfo_t, name:str, til:til_t)→Tuple[bool,str]
Remove pointer of a type. (i.e. convert “char *” into “char”). Optionally remove the “lp” (or similar) prefix of the input name. If the input type is not a pointer, then fail.
Parameters:

-
tif – the type info

-
name – the name of the type to “unpointerify”

-
til – the type library

Returns:
a tuple (success, new-name)
ida_typeinf.get_numbered_type(til:til_t, ordinal:int)→Tuple[bytes,bytes,str,str,int]|None
Get a type from a type library, by its ordinal

Please use til_t.get_numbered_type instead.
ida_typeinf.set_numbered_type(ti:til_t, ordinal:int, ntf_flags:int, name:str, type:type_tconst*, fields:p_listconst*=None, cmt:str=None, fldcmts:p_listconst*=None, sclass:sclass_tconst*=None)→tinfo_code_tida_typeinf.cvarida_typeinf.sc_autoida_typeinf.sc_extida_typeinf.sc_friendida_typeinf.sc_regida_typeinf.sc_statida_typeinf.sc_typeida_typeinf.sc_unkida_typeinf.sc_virtida_typeinf.TERR_SAVEida_typeinf.TERR_WRONGNAMEida_typeinf.BADORD=4294967295ida_typeinf.enum_member_vec_tida_typeinf.enum_member_tida_typeinf.udt_member_t
