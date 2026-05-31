# IDAPython disassembly line API

- 官方来源：https://python.docs.hex-rays.com/ida_lines/index.html

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
- ida_lines
- View page source

# ida_lines

High level functions that deal with the generation of the disassembled text lines.

This file also contains definitions for the syntax highlighting. Finally there are functions that deal with anterior/posterior user-defined lines.

## Attributes

`COLOR_ON`
 |
Escape character (ON). Followed by a color code (color_t).

`COLOR_OFF`
 |
Escape character (OFF). Followed by a color code (color_t).

`COLOR_ESC`
 |
Escape character (Quote next character). This is needed to output '1' and '2' characters.

`COLOR_INV`
 |
Escape character (Inverse foreground and background colors). This escape character has no corresponding COLOR_OFF. Its action continues until the next COLOR_INV or end of line.

`SCOLOR_ON`
 |
Escape character (ON)

`SCOLOR_OFF`
 |
Escape character (OFF)

`SCOLOR_ESC`
 |
Escape character (Quote next character)

`SCOLOR_INV`
 |
Escape character (Inverse colors)

`SCOLOR_DEFAULT`
 |
Default.

`SCOLOR_REGCMT`
 |
Regular comment.

`SCOLOR_RPTCMT`
 |
Repeatable comment (defined not here)

`SCOLOR_AUTOCMT`
 |
Automatic comment.

`SCOLOR_INSN`
 |
Instruction.

`SCOLOR_DATNAME`
 |
Dummy Data Name.

`SCOLOR_DNAME`
 |
Regular Data Name.

`SCOLOR_DEMNAME`
 |
Demangled Name.

`SCOLOR_SYMBOL`
 |
Punctuation.

`SCOLOR_CHAR`
 |
Char constant in instruction.

`SCOLOR_STRING`
 |
String constant in instruction.

`SCOLOR_NUMBER`
 |
Numeric constant in instruction.

`SCOLOR_VOIDOP`
 |
Void operand.

`SCOLOR_CREF`
 |
Code reference.

`SCOLOR_DREF`
 |
Data reference.

`SCOLOR_CREFTAIL`
 |
Code reference to tail byte.

`SCOLOR_DREFTAIL`
 |
Data reference to tail byte.

`SCOLOR_ERROR`
 |
Error or problem.

`SCOLOR_PREFIX`
 |
Line prefix.

`SCOLOR_BINPREF`
 |
Binary line prefix bytes.

`SCOLOR_EXTRA`
 |
Extra line.

`SCOLOR_ALTOP`
 |
Alternative operand.

`SCOLOR_HIDNAME`
 |
Hidden name.

`SCOLOR_LIBNAME`
 |
Library function name.

`SCOLOR_LOCNAME`
 |
Local variable name.

`SCOLOR_CODNAME`
 |
Dummy code name.

`SCOLOR_ASMDIR`
 |
Assembler directive.

`SCOLOR_MACRO`
 |
Macro.

`SCOLOR_DSTR`
 |
String constant in data directive.

`SCOLOR_DCHAR`
 |
Char constant in data directive.

`SCOLOR_DNUM`
 |
Numeric constant in data directive.

`SCOLOR_KEYWORD`
 |
Keywords.

`SCOLOR_REG`
 |
Register name.

`SCOLOR_IMPNAME`
 |
Imported name.

`SCOLOR_SEGNAME`
 |
Segment name.

`SCOLOR_UNKNAME`
 |
Dummy unknown name.

`SCOLOR_CNAME`
 |
Regular code name.

`SCOLOR_UNAME`
 |
Regular unknown name.

`SCOLOR_COLLAPSED`
 |
Collapsed line.

`SCOLOR_ADDR`
 |
Hidden address mark.

`COLOR_SELECTED`
 |
Selected.

`COLOR_LIBFUNC`
 |
Library function.

`COLOR_REGFUNC`
 |
Regular function.

`COLOR_CODE`
 |
Single instruction.

`COLOR_DATA`
 |
Data bytes.

`COLOR_UNKNOWN`
 |
Unexplored byte.

`COLOR_EXTERN`
 |
External name definition segment.

`COLOR_CURITEM`
 |
Current item.

`COLOR_CURLINE`
 |
Current line.

`COLOR_HIDLINE`
 |
Hidden line.

`COLOR_LUMFUNC`
 |
Lumina function.

`COLOR_BG_MAX`
 |
Max color number.

`cvar`
 |

`COLOR_DEFAULT`
 |
Default.

`COLOR_REGCMT`
 |
Regular comment.

`COLOR_RPTCMT`
 |
Repeatable comment (comment defined somewhere else)

`COLOR_AUTOCMT`
 |
Automatic comment.

`COLOR_INSN`
 |
Instruction.

`COLOR_DATNAME`
 |
Dummy Data Name.

`COLOR_DNAME`
 |
Regular Data Name.

`COLOR_DEMNAME`
 |
Demangled Name.

`COLOR_SYMBOL`
 |
Punctuation.

`COLOR_CHAR`
 |
Char constant in instruction.

`COLOR_STRING`
 |
String constant in instruction.

`COLOR_NUMBER`
 |
Numeric constant in instruction.

`COLOR_VOIDOP`
 |
Void operand.

`COLOR_CREF`
 |
Code reference.

`COLOR_DREF`
 |
Data reference.

`COLOR_CREFTAIL`
 |
Code reference to tail byte.

`COLOR_DREFTAIL`
 |
Data reference to tail byte.

`COLOR_ERROR`
 |
Error or problem.

`COLOR_PREFIX`
 |
Line prefix.

`COLOR_BINPREF`
 |
Binary line prefix bytes.

`COLOR_EXTRA`
 |
Extra line.

`COLOR_ALTOP`
 |
Alternative operand.

`COLOR_HIDNAME`
 |
Hidden name.

`COLOR_LIBNAME`
 |
Library function name.

`COLOR_LOCNAME`
 |
Local variable name.

`COLOR_CODNAME`
 |
Dummy code name.

`COLOR_ASMDIR`
 |
Assembler directive.

`COLOR_MACRO`
 |
Macro.

`COLOR_DSTR`
 |
String constant in data directive.

`COLOR_DCHAR`
 |
Char constant in data directive.

`COLOR_DNUM`
 |
Numeric constant in data directive.

`COLOR_KEYWORD`
 |
Keywords.

`COLOR_REG`
 |
Register name.

`COLOR_IMPNAME`
 |
Imported name.

`COLOR_SEGNAME`
 |
Segment name.

`COLOR_UNKNAME`
 |
Dummy unknown name.

`COLOR_CNAME`
 |
Regular code name.

`COLOR_UNAME`
 |
Regular unknown name.

`COLOR_COLLAPSED`
 |
Collapsed line.

`COLOR_FG_MAX`
 |
Max color number.

`COLOR_ADDR`
 |
Hidden address marks. the address is represented as 16-digit hex number: 01234567ABCDEF00. it doesn't have the COLOR_OFF pair.

`COLOR_OPND1`
 |
Instruction operand 1.

`COLOR_OPND2`
 |
Instruction operand 2.

`COLOR_OPND3`
 |
Instruction operand 3.

`COLOR_OPND4`
 |
Instruction operand 4.

`COLOR_OPND5`
 |
Instruction operand 5.

`COLOR_OPND6`
 |
Instruction operand 6.

`COLOR_OPND7`
 |
Instruction operand 7.

`COLOR_OPND8`
 |
Instruction operand 8.

`COLOR_RESERVED1`
 |
This tag is reserved for internal IDA use.

`COLOR_LUMINA`
 |
Lumina-related, only for the navigation band.

`VEL_POST`
 |
append posterior line

`VEL_CMT`
 |
append comment line

`GDISMF_AS_STACK`
 |

`GDISMF_ADDR_TAG`
 |

`GDISMF_REMOVE_TAGS`
 |

`GDISMF_UNHIDE`
 |

`GENDSM_FORCE_CODE`
 |

`GENDSM_MULTI_LINE`
 |

`GENDSM_REMOVE_TAGS`
 |

`GENDSM_UNHIDE`
 |

`COLOR_ADDR_SIZE`
 |
Size of a tagged address (see COLOR_ADDR)

`SCOLOR_FG_MAX`
 |

`cvar`
 |

`SCOLOR_OPND1`
 |

`SCOLOR_OPND2`
 |

`SCOLOR_OPND3`
 |

`SCOLOR_OPND4`
 |

`SCOLOR_OPND5`
 |

`SCOLOR_OPND6`
 |

`SCOLOR_UTF8`
 |

`PALETTE_SIZE`
 |

`E_PREV`
 |

`E_NEXT`
 |

## Classes

`user_defined_prefix_t`
 |

## Functions

`tag_strlen`(→ ssize_t)
 |
Calculate length of a colored string This function computes the length in unicode codepoints of a line

`calc_prefix_color`(→ color_t)
 |
Get prefix color for line at 'ea'

`calc_bg_color`(→ bgcolor_t)
 |
Get background color for line at 'ea'

`add_sourcefile`(→ bool)
 |

`get_sourcefile`(→ str)
 |

`del_sourcefile`(→ bool)
 |

`install_user_defined_prefix`(→ bool)
 |

`add_extra_line`(→ bool)
 |

`add_extra_cmt`(→ bool)
 |

`add_pgm_cmt`(→ bool)
 |

`generate_disasm_line`(→ str)
 |

`get_first_free_extra_cmtidx`(→ int)
 |

`update_extra_cmt`(→ bool)
 |

`del_extra_cmt`(→ bool)
 |

`get_extra_cmt`(→ int)
 |

`delete_extra_cmts`(→ None)
 |

`create_encoding_helper`(→ encoder_t *)
 |

`tag_remove`(→ str)
 |
Remove color escape sequences from a string.

`tag_addr`(→ str)
 |
Insert an address mark into a string.

`tag_skipcode`(→ int)
 |
Skip one color code. This function should be used if you are interested in color codes and want to analyze all of them. Otherwise tag_skipcodes() function is better since it will skip all colors at once. This function will skip the current color code if there is one. If the current symbol is not a color code, it will return the input.

`tag_skipcodes`(→ int)
 |
Move the pointer past all color codes.

`tag_advance`(→ int)
 |
Move pointer to a 'line' to 'cnt' positions right. Take into account escape sequences.

`generate_disassembly`(ea, max_lines, as_stack, notag[, ...])
 |
Generate disassembly lines (many lines) and put them into a buffer

`requires_color_esc`(c)
 |
Is the given char a color escape character?

`COLSTR`(str, tag)
 |
Utility function to create a colored line

## Module Contents

ida_lines.COLOR_ON
Escape character (ON). Followed by a color code (color_t).
ida_lines.COLOR_OFF
Escape character (OFF). Followed by a color code (color_t).
ida_lines.COLOR_ESC
Escape character (Quote next character). This is needed to output ‘1’ and ‘2’ characters.
ida_lines.COLOR_INV
Escape character (Inverse foreground and background colors). This escape character has no corresponding COLOR_OFF. Its action continues until the next COLOR_INV or end of line.
ida_lines.SCOLOR_ON
Escape character (ON)
ida_lines.SCOLOR_OFF
Escape character (OFF)
ida_lines.SCOLOR_ESC
Escape character (Quote next character)
ida_lines.SCOLOR_INV
Escape character (Inverse colors)
ida_lines.SCOLOR_DEFAULT
Default.
ida_lines.SCOLOR_REGCMT
Regular comment.
ida_lines.SCOLOR_RPTCMT
Repeatable comment (defined not here)
ida_lines.SCOLOR_AUTOCMT
Automatic comment.
ida_lines.SCOLOR_INSN
Instruction.
ida_lines.SCOLOR_DATNAME
Dummy Data Name.
ida_lines.SCOLOR_DNAME
Regular Data Name.
ida_lines.SCOLOR_DEMNAME
Demangled Name.
ida_lines.SCOLOR_SYMBOL
Punctuation.
ida_lines.SCOLOR_CHAR
Char constant in instruction.
ida_lines.SCOLOR_STRING
String constant in instruction.
ida_lines.SCOLOR_NUMBER
Numeric constant in instruction.
ida_lines.SCOLOR_VOIDOP
Void operand.
ida_lines.SCOLOR_CREF
Code reference.
ida_lines.SCOLOR_DREF
Data reference.
ida_lines.SCOLOR_CREFTAIL
Code reference to tail byte.
ida_lines.SCOLOR_DREFTAIL
Data reference to tail byte.
ida_lines.SCOLOR_ERROR
Error or problem.
ida_lines.SCOLOR_PREFIX
Line prefix.
ida_lines.SCOLOR_BINPREF
Binary line prefix bytes.
ida_lines.SCOLOR_EXTRA
Extra line.
ida_lines.SCOLOR_ALTOP
Alternative operand.
ida_lines.SCOLOR_HIDNAME
Hidden name.
ida_lines.SCOLOR_LIBNAME
Library function name.
ida_lines.SCOLOR_LOCNAME
Local variable name.
ida_lines.SCOLOR_CODNAME
Dummy code name.
ida_lines.SCOLOR_ASMDIR
Assembler directive.
ida_lines.SCOLOR_MACRO
Macro.
ida_lines.SCOLOR_DSTR
String constant in data directive.
ida_lines.SCOLOR_DCHAR
Char constant in data directive.
ida_lines.SCOLOR_DNUM
Numeric constant in data directive.
ida_lines.SCOLOR_KEYWORD
Keywords.
ida_lines.SCOLOR_REG
Register name.
ida_lines.SCOLOR_IMPNAME
Imported name.
ida_lines.SCOLOR_SEGNAME
Segment name.
ida_lines.SCOLOR_UNKNAME
Dummy unknown name.
ida_lines.SCOLOR_CNAME
Regular code name.
ida_lines.SCOLOR_UNAME
Regular unknown name.
ida_lines.SCOLOR_COLLAPSED
Collapsed line.
ida_lines.SCOLOR_ADDR
Hidden address mark.
ida_lines.COLOR_SELECTED
Selected.
ida_lines.COLOR_LIBFUNC
Library function.
ida_lines.COLOR_REGFUNC
Regular function.
ida_lines.COLOR_CODE
Single instruction.
ida_lines.COLOR_DATA
Data bytes.
ida_lines.COLOR_UNKNOWN
Unexplored byte.
ida_lines.COLOR_EXTERN
External name definition segment.
ida_lines.COLOR_CURITEM
Current item.
ida_lines.COLOR_CURLINE
Current line.
ida_lines.COLOR_HIDLINE
Hidden line.
ida_lines.COLOR_LUMFUNC
Lumina function.
ida_lines.COLOR_BG_MAX
Max color number.
ida_lines.tag_strlen(line:str)→ssize_t
Calculate length of a colored string This function computes the length in unicode codepoints of a line
Returns:
the number of codepoints in the line, or -1 on error
ida_lines.calc_prefix_color(ea:ida_idaapi.ea_t)→color_t
Get prefix color for line at ‘ea’
Returns:
Line prefix colors
ida_lines.calc_bg_color(ea:ida_idaapi.ea_t)→bgcolor_t
Get background color for line at ‘ea’
Returns:
RGB color
ida_lines.add_sourcefile(ea1:ida_idaapi.ea_t, ea2:ida_idaapi.ea_t, filename:str)→boolida_lines.get_sourcefile(ea:ida_idaapi.ea_t, bounds:range_t=None)→strida_lines.del_sourcefile(ea:ida_idaapi.ea_t)→boolida_lines.install_user_defined_prefix(*args)→boolclassida_lines.user_defined_prefix_t(*args)
Bases: `object`
thisownget_user_defined_prefix(ea:ida_idaapi.ea_t, insn:insn_tconst&, lnnum:int, indent:int, line:str)→None
This callback must be overridden by the derived class.
Parameters:

-
ea – the current address

-
insn – the current instruction. if the current item is not an instruction, then insn.itype is zero.

-
lnnum – number of the current line (each address may have several listing lines for it). 0 means the very first line for the current address.

-
indent – see explanations for gen_printf()

-
line – the line to be generated. the line usually contains color tags. this argument can be examined to decide whether to generate the prefix.

ida_lines.cvarida_lines.COLOR_DEFAULT
Default.
ida_lines.COLOR_REGCMT
Regular comment.
ida_lines.COLOR_RPTCMT
Repeatable comment (comment defined somewhere else)
ida_lines.COLOR_AUTOCMT
Automatic comment.
ida_lines.COLOR_INSN
Instruction.
ida_lines.COLOR_DATNAME
Dummy Data Name.
ida_lines.COLOR_DNAME
Regular Data Name.
ida_lines.COLOR_DEMNAME
Demangled Name.
ida_lines.COLOR_SYMBOL
Punctuation.
ida_lines.COLOR_CHAR
Char constant in instruction.
ida_lines.COLOR_STRING
String constant in instruction.
ida_lines.COLOR_NUMBER
Numeric constant in instruction.
ida_lines.COLOR_VOIDOP
Void operand.
ida_lines.COLOR_CREF
Code reference.
ida_lines.COLOR_DREF
Data reference.
ida_lines.COLOR_CREFTAIL
Code reference to tail byte.
ida_lines.COLOR_DREFTAIL
Data reference to tail byte.
ida_lines.COLOR_ERROR
Error or problem.
ida_lines.COLOR_PREFIX
Line prefix.
ida_lines.COLOR_BINPREF
Binary line prefix bytes.
ida_lines.COLOR_EXTRA
Extra line.
ida_lines.COLOR_ALTOP
Alternative operand.
ida_lines.COLOR_HIDNAME
Hidden name.
ida_lines.COLOR_LIBNAME
Library function name.
ida_lines.COLOR_LOCNAME
Local variable name.
ida_lines.COLOR_CODNAME
Dummy code name.
ida_lines.COLOR_ASMDIR
Assembler directive.
ida_lines.COLOR_MACRO
Macro.
ida_lines.COLOR_DSTR
String constant in data directive.
ida_lines.COLOR_DCHAR
Char constant in data directive.
ida_lines.COLOR_DNUM
Numeric constant in data directive.
ida_lines.COLOR_KEYWORD
Keywords.
ida_lines.COLOR_REG
Register name.
ida_lines.COLOR_IMPNAME
Imported name.
ida_lines.COLOR_SEGNAME
Segment name.
ida_lines.COLOR_UNKNAME
Dummy unknown name.
ida_lines.COLOR_CNAME
Regular code name.
ida_lines.COLOR_UNAME
Regular unknown name.
ida_lines.COLOR_COLLAPSED
Collapsed line.
ida_lines.COLOR_FG_MAX
Max color number.
ida_lines.COLOR_ADDR
Hidden address marks. the address is represented as 16-digit hex number: 01234567ABCDEF00. it doesn’t have the COLOR_OFF pair.
ida_lines.COLOR_OPND1
Instruction operand 1.
ida_lines.COLOR_OPND2
Instruction operand 2.
ida_lines.COLOR_OPND3
Instruction operand 3.
ida_lines.COLOR_OPND4
Instruction operand 4.
ida_lines.COLOR_OPND5
Instruction operand 5.
ida_lines.COLOR_OPND6
Instruction operand 6.
ida_lines.COLOR_OPND7
Instruction operand 7.
ida_lines.COLOR_OPND8
Instruction operand 8.
ida_lines.COLOR_RESERVED1
This tag is reserved for internal IDA use.
ida_lines.COLOR_LUMINA
Lumina-related, only for the navigation band.
ida_lines.VEL_POST
append posterior line
ida_lines.VEL_CMT
append comment line
ida_lines.add_extra_line(*args)→boolida_lines.add_extra_cmt(*args)→boolida_lines.add_pgm_cmt(*args)→boolida_lines.GDISMF_AS_STACKida_lines.GDISMF_ADDR_TAGida_lines.GDISMF_REMOVE_TAGSida_lines.GDISMF_UNHIDEida_lines.generate_disasm_line(ea:ida_idaapi.ea_t, flags:int=0)→strida_lines.GENDSM_FORCE_CODEida_lines.GENDSM_MULTI_LINEida_lines.GENDSM_REMOVE_TAGSida_lines.GENDSM_UNHIDEida_lines.get_first_free_extra_cmtidx(ea:ida_idaapi.ea_t, start:int)→intida_lines.update_extra_cmt(ea:ida_idaapi.ea_t, what:int, str:update_extra_cmt.str)→boolida_lines.del_extra_cmt(ea:ida_idaapi.ea_t, what:int)→boolida_lines.get_extra_cmt(ea:ida_idaapi.ea_t, what:int)→intida_lines.delete_extra_cmts(ea:ida_idaapi.ea_t, what:int)→Noneida_lines.create_encoding_helper(*args)→encoder_t*ida_lines.tag_remove(nonnul_instr:str)→str
Remove color escape sequences from a string.
Returns:
length of resulting string, -1 if error
ida_lines.tag_addr(ea:ida_idaapi.ea_t)→str
Insert an address mark into a string.
Parameters:
ea – address to include
ida_lines.tag_skipcode(line:str)→int
Skip one color code. This function should be used if you are interested in color codes and want to analyze all of them. Otherwise tag_skipcodes() function is better since it will skip all colors at once. This function will skip the current color code if there is one. If the current symbol is not a color code, it will return the input.
Returns:
moved pointer
ida_lines.tag_skipcodes(line:str)→int
Move the pointer past all color codes.
Parameters:
line – can’t be nullptr
Returns:
moved pointer, can’t be nullptr
ida_lines.tag_advance(line:str, cnt:int)→int
Move pointer to a ‘line’ to ‘cnt’ positions right. Take into account escape sequences.
Parameters:

-
line – pointer to string

-
cnt – number of positions to move right

Returns:
moved pointer
ida_lines.generate_disassembly(ea, max_lines, as_stack, notag, include_hidden:Boolean=False)
Generate disassembly lines (many lines) and put them into a buffer
Parameters:

-
ea – address to generate disassembly for

-
max_lines – how many lines max to generate

-
as_stack – Display undefined items as 2/4/8 bytes

-
notag – remove color tags

-
include_hidden – automatically unhide hidden objects

Returns:
tuple(most_important_line_number, list(lines)) : Returns a tuple containing the most important line number and a list of generated lines
Returns:
None on failure
ida_lines.COLOR_ADDR_SIZE=16
Size of a tagged address (see COLOR_ADDR)
ida_lines.SCOLOR_FG_MAX='('ida_lines.cvarida_lines.SCOLOR_OPND1ida_lines.SCOLOR_OPND2ida_lines.SCOLOR_OPND3ida_lines.SCOLOR_OPND4ida_lines.SCOLOR_OPND5ida_lines.SCOLOR_OPND6ida_lines.SCOLOR_UTF8ida_lines.PALETTE_SIZEida_lines.requires_color_esc(c)
Is the given char a color escape character?
ida_lines.COLSTR(str, tag)
Utility function to create a colored line :param str: The string :param tag: Color tag constant. One of SCOLOR_XXXX
ida_lines.E_PREVida_lines.E_NEXT
