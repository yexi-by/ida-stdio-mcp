# IDAPython IDC compatibility API

- 官方来源：https://python.docs.hex-rays.com/idc/index.html

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
- idc
- View page source

# idc

IDC compatibility module

This file contains IDA built-in function declarations and internal bit definitions. Each byte of the program has 32-bit flags (low 8 bits keep the byte value). These 32 bits are used in get_full_flags/get_flags functions.

This file is subject to change without any notice. Future versions of IDA may use other definitions.

## Attributes

`WORDMASK`
|

`BADADDR`
|

`BADSEL`
|

`SIZE_MAX`
|

`MS_VAL`
|

`FF_IVL`
|

`MS_CLS`
|

`FF_CODE`
|

`FF_DATA`
|

`FF_TAIL`
|

`FF_UNK`
|

`MS_COMM`
|

`FF_COMM`
|

`FF_REF`
|

`FF_LINE`
|

`FF_NAME`
|

`FF_LABL`
|

`FF_FLOW`
|

`FF_ANYNAME`
|

`MS_0TYPE`
|

`FF_0VOID`
|

`FF_0NUMH`
|

`FF_0NUMD`
|

`FF_0CHAR`
|

`FF_0SEG`
|

`FF_0OFF`
|

`FF_0NUMB`
|

`FF_0NUMO`
|

`FF_0ENUM`
|

`FF_0FOP`
|

`FF_0STRO`
|

`FF_0STK`
|

`MS_1TYPE`
|

`FF_1VOID`
|

`FF_1NUMH`
|

`FF_1NUMD`
|

`FF_1CHAR`
|

`FF_1SEG`
|

`FF_1OFF`
|

`FF_1NUMB`
|

`FF_1NUMO`
|

`FF_1ENUM`
|

`FF_1FOP`
|

`FF_1STRO`
|

`FF_1STK`
|

`DT_TYPE`
|

`FF_BYTE`
|

`FF_WORD`
|

`FF_DWORD`
|

`FF_QWORD`
|

`FF_TBYTE`
|

`FF_STRLIT`
|

`FF_STRUCT`
|

`FF_OWORD`
|

`FF_FLOAT`
|

`FF_DOUBLE`
|

`FF_PACKREAL`
|

`FF_ALIGN`
|

`MS_CODE`
|

`FF_FUNC`
|

`FF_IMMD`
|

`FF_JUMP`
|

`NEF_SEGS`
|

`NEF_RSCS`
|

`NEF_NAME`
|

`NEF_MAN`
|

`NEF_FILL`
|

`NEF_IMPS`
|

`NEF_FIRST`
|

`NEF_CODE`
|

`NEF_RELOAD`
|

`NEF_FLAT`
|

`IDCHK_OK`
|

`IDCHK_ARG`
|

`IDCHK_KEY`
|

`IDCHK_MAX`
|

`add_idc_hotkey`
|

`del_idc_hotkey`
|

`jumpto`
|

`auto_wait`
|

`DBFL_BAK`
|

`qexit`
|

`load_and_run_plugin`
|

`plan_to_apply_idasgn`
|

`create_insn`
|

`SN_CHECK`
|

`SN_NOCHECK`
|

`SN_PUBLIC`
|

`SN_NON_PUBLIC`
|

`SN_WEAK`
|

`SN_NON_WEAK`
|

`SN_AUTO`
|

`SN_NON_AUTO`
|

`SN_NOLIST`
|

`SN_NOWARN`
|

`SN_LOCAL`
|

`set_cmt`
|

`create_data`
|

`create_custom_data`
|

`create_align`
|

`del_items`
|

`DELIT_SIMPLE`
|

`DELIT_EXPAND`
|

`DELIT_DELNAMES`
|

`AP_ALLOWDUPS`
|

`AP_SIGNED`
|

`AP_INDEX`
|

`AP_ARRAY`
|

`AP_IDXBASEMASK`
|

`AP_IDXDEC`
|

`AP_IDXHEX`
|

`AP_IDXOCT`
|

`AP_IDXBIN`
|

`op_bin`
|

`op_oct`
|

`op_dec`
|

`op_hex`
|

`op_chr`
|

`OPND_OUTER`
|

`op_offset`
|

`REF_OFF8`
|

`REF_OFF16`
|

`REF_OFF32`
|

`REF_LOW8`
|

`REF_LOW16`
|

`REF_HIGH8`
|

`REF_HIGH16`
|

`REF_OFF64`
|

`REFINFO_RVA`
|

`REFINFO_PASTEND`
|

`REFINFO_NOBASE`
|

`REFINFO_SUBTRACT`
|

`REFINFO_SIGNEDOP`
|

`op_seg`
|

`op_num`
|

`op_flt`
|

`op_man`
|

`toggle_sign`
|

`op_enum`
|

`op_stkvar`
|

`E_PREV`
|

`E_NEXT`
|

`get_extra_cmt`
|

`update_extra_cmt`
|

`del_extra_cmt`
|

`set_manual_insn`
|

`get_manual_insn`
|

`patch_dbg_byte`
|

`patch_byte`
|

`patch_word`
|

`patch_dword`
|

`patch_qword`
|

`SR_inherit`
|

`SR_user`
|

`SR_auto`
|

`SR_autostart`
|

`auto_mark_range`
|

`auto_unmark`
|

`AU_UNK`
|

`AU_CODE`
|

`AU_PROC`
|

`AU_USED`
|

`AU_LIBF`
|

`AU_FINAL`
|

`OFILE_MAP`
|

`OFILE_EXE`
|

`OFILE_IDC`
|

`OFILE_LST`
|

`OFILE_ASM`
|

`OFILE_DIF`
|

`GENFLG_MAPSEG`
|

`GENFLG_MAPNAME`
|

`GENFLG_MAPDMNG`
|

`GENFLG_MAPLOC`
|

`GENFLG_IDCTYPE`
|

`GENFLG_ASMTYPE`
|

`GENFLG_GENHTML`
|

`GENFLG_ASMINC`
|

`CHART_PRINT_NAMES`
|

`CHART_GEN_GDL`
|

`CHART_WINGRAPH`
|

`CHART_NOLIBFUNCS`
|

`get_root_filename`
|

`get_input_file_path`
|

`set_root_filename`
|

`retrieve_input_file_md5`
|

`get_full_flags`
|

`get_db_byte`
|

`get_wide_byte`
|

`read_dbg_memory`
|

`get_original_byte`
|

`get_wide_word`
|

`get_wide_dword`
|

`get_qword`
|

`get_name_ea`
|

`get_screen_ea`
|

`next_addr`
|

`prev_addr`
|

`next_not_tail`
|

`prev_not_tail`
|

`get_item_head`
|

`get_item_end`
|

`GN_VISIBLE`
|

`GN_COLORED`
|

`GN_DEMANGLED`
|

`GN_STRICT`
|

`GN_SHORT`
|

`GN_LONG`
|

`GN_LOCAL`
|

`GN_ISRET`
|

`GN_NOT_ISRET`
|

`calc_gtn_flags`
|

`GENDSM_FORCE_CODE`
|

`GENDSM_MULTI_LINE`
|

`o_void`
|

`o_reg`
|

`o_mem`
|

`o_phrase`
|

`o_displ`
|

`o_imm`
|

`o_far`
|

`o_near`
|

`o_idpspec0`
|

`o_idpspec1`
|

`o_idpspec2`
|

`o_idpspec3`
|

`o_idpspec4`
|

`o_idpspec5`
|

`o_trreg`
|

`o_dbreg`
|

`o_crreg`
|

`o_fpreg`
|

`o_mmxreg`
|

`o_xmmreg`
|

`o_reglist`
|

`o_creglist`
|

`o_creg`
|

`o_fpreglist`
|

`o_text`
|

`o_cond`
|

`o_spr`
|

`o_twofpr`
|

`o_shmbme`
|

`o_crf`
|

`o_crb`
|

`o_dcr`
|

`GetCommentEx`
|

`get_cmt`
|

`get_forced_operand`
|

`BPU_1B`
|

`BPU_2B`
|

`BPU_4B`
|

`STRWIDTH_1B`
|

`STRWIDTH_2B`
|

`STRWIDTH_4B`
|

`STRWIDTH_MASK`
|

`STRLYT_TERMCHR`
|

`STRLYT_PASCAL1`
|

`STRLYT_PASCAL2`
|

`STRLYT_PASCAL4`
|

`STRLYT_MASK`
|

`STRLYT_SHIFT`
|

`STRTYPE_TERMCHR`
|

`STRTYPE_C`
|

`STRTYPE_C_16`
|

`STRTYPE_C_32`
|

`STRTYPE_PASCAL`
|

`STRTYPE_PASCAL_16`
|

`STRTYPE_LEN2`
|

`STRTYPE_LEN2_16`
|

`STRTYPE_LEN4`
|

`STRTYPE_LEN4_16`
|

`STRTYPE_C16`
|

`find_suspop`
|

`find_code`
|

`find_data`
|

`find_unknown`
|

`find_defined`
|

`find_imm`
|

`find_text`
|

`find_bytes`
|

`INF_VERSION`
|

`INF_PROCNAME`
|

`INF_GENFLAGS`
|

`INF_LFLAGS`
|

`INF_DATABASE_CHANGE_COUNT`
|

`INF_CHANGE_COUNTER`
|

`INF_FILETYPE`
|

`FT_EXE_OLD`
|

`FT_COM_OLD`
|

`FT_BIN`
|

`FT_DRV`
|

`FT_WIN`
|

`FT_HEX`
|

`FT_MEX`
|

`FT_LX`
|

`FT_LE`
|

`FT_NLM`
|

`FT_COFF`
|

`FT_PE`
|

`FT_OMF`
|

`FT_SREC`
|

`FT_ZIP`
|

`FT_OMFLIB`
|

`FT_AR`
|

`FT_LOADER`
|

`FT_ELF`
|

`FT_W32RUN`
|

`FT_AOUT`
|

`FT_PRC`
|

`FT_EXE`
|

`FT_COM`
|

`FT_AIXAR`
|

`FT_MACHO`
|

`INF_OSTYPE`
|

`OSTYPE_MSDOS`
|

`OSTYPE_WIN`
|

`OSTYPE_OS2`
|

`OSTYPE_NETW`
|

`INF_APPTYPE`
|

`APPT_CONSOLE`
|

`APPT_GRAPHIC`
|

`APPT_PROGRAM`
|

`APPT_LIBRARY`
|

`APPT_DRIVER`
|

`APPT_1THREAD`
|

`APPT_MTHREAD`
|

`APPT_16BIT`
|

`APPT_32BIT`
|

`INF_ASMTYPE`
|

`INF_SPECSEGS`
|

`INF_AF`
|

`INF_AF2`
|

`INF_BASEADDR`
|

`INF_START_SS`
|

`INF_START_CS`
|

`INF_START_IP`
|

`INF_START_EA`
|

`INF_START_SP`
|

`INF_MAIN`
|

`INF_MIN_EA`
|

`INF_MAX_EA`
|

`INF_OMIN_EA`
|

`INF_OMAX_EA`
|

`INF_LOWOFF`
|

`INF_LOW_OFF`
|

`INF_HIGHOFF`
|

`INF_HIGH_OFF`
|

`INF_MAXREF`
|

`INF_PRIVRANGE_START_EA`
|

`INF_START_PRIVRANGE`
|

`INF_PRIVRANGE_END_EA`
|

`INF_END_PRIVRANGE`
|

`INF_NETDELTA`
|

`INF_XREFNUM`
|

`INF_TYPE_XREFNUM`
|

`INF_TYPE_XREFS`
|

`INF_REFCMTNUM`
|

`INF_REFCMTS`
|

`INF_XREFFLAG`
|

`INF_XREFS`
|

`INF_MAX_AUTONAME_LEN`
|

`INF_NAMETYPE`
|

`INF_SHORT_DEMNAMES`
|

`INF_SHORT_DN`
|

`INF_LONG_DEMNAMES`
|

`INF_LONG_DN`
|

`INF_DEMNAMES`
|

`INF_LISTNAMES`
|

`INF_INDENT`
|

`INF_CMT_INDENT`
|

`INF_COMMENT`
|

`INF_MARGIN`
|

`INF_LENXREF`
|

`INF_OUTFLAGS`
|

`INF_CMTFLG`
|

`INF_CMTFLAG`
|

`INF_LIMITER`
|

`INF_BORDER`
|

`INF_BIN_PREFIX_SIZE`
|

`INF_BINPREF`
|

`INF_PREFFLAG`
|

`INF_STRLIT_FLAGS`
|

`INF_STRLIT_BREAK`
|

`INF_STRLIT_ZEROES`
|

`INF_STRTYPE`
|

`INF_STRLIT_PREF`
|

`INF_STRLIT_SERNUM`
|

`INF_DATATYPES`
|

`INF_CC_ID`
|

`COMP_MASK`
|

`COMP_UNK`
|

`COMP_MS`
|

`COMP_BC`
|

`COMP_WATCOM`
|

`COMP_GNU`
|

`COMP_VISAGE`
|

`COMP_BP`
|

`INF_CC_CM`
|

`INF_CC_SIZE_I`
|

`INF_CC_SIZE_B`
|

`INF_CC_SIZE_E`
|

`INF_CC_DEFALIGN`
|

`INF_CC_SIZE_S`
|

`INF_CC_SIZE_L`
|

`INF_CC_SIZE_LL`
|

`INF_CC_SIZE_LDBL`
|

`INF_COMPILER`
|

`INF_MODEL`
|

`INF_SIZEOF_INT`
|

`INF_SIZEOF_BOOL`
|

`INF_SIZEOF_ENUM`
|

`INF_SIZEOF_ALGN`
|

`INF_SIZEOF_SHORT`
|

`INF_SIZEOF_LONG`
|

`INF_SIZEOF_LLONG`
|

`INF_SIZEOF_LDBL`
|

`INF_ABIBITS`
|

`INF_APPCALL_OPTIONS`
|

`set_processor_type`
|

`SETPROC_IDB`
|

`SETPROC_LOADER`
|

`SETPROC_LOADER_NON_FATAL`
|

`SETPROC_USER`
|

`set_target_assembler`
|

`ask_seg`
|

`ask_yn`
|

`msg`
|

`warning`
|

`error`
|

`set_ida_state`
|

`IDA_STATUS_READY`
|

`IDA_STATUS_THINKING`
|

`IDA_STATUS_WAITING`
|

`IDA_STATUS_WORK`
|

`refresh_idaview_anyway`
|

`refresh_lists`
|

`set_selector`
|

`del_selector`
|

`ADDSEG_NOSREG`
|

`ADDSEG_OR_DIE`
|

`ADDSEG_NOTRUNC`
|

`ADDSEG_QUIET`
|

`ADDSEG_FILLGAP`
|

`ADDSEG_SPARSE`
|

`del_segm`
|

`SEGMOD_KILL`
|

`SEGMOD_KEEP`
|

`SEGMOD_SILENT`
|

`saAbs`
|

`saRelByte`
|

`saRelWord`
|

`saRelPara`
|

`saRelPage`
|

`saRelDble`
|

`saRel4K`
|

`saGroup`
|

`saRel32Bytes`
|

`saRel64Bytes`
|

`saRelQword`
|

`scPriv`
|

`scPub`
|

`scPub2`
|

`scStack`
|

`scCommon`
|

`scPub3`
|

`SEG_NORM`
|

`SEG_XTRN`
|

`SEG_CODE`
|

`SEG_DATA`
|

`SEG_IMP`
|

`SEG_GRP`
|

`SEG_NULL`
|

`SEG_UNDF`
|

`SEG_BSS`
|

`SEG_ABSSYM`
|

`SEG_COMM`
|

`SEG_IMEM`
|

`SEGATTR_START`
|

`SEGATTR_END`
|

`SEGATTR_ORGBASE`
|

`SEGATTR_ALIGN`
|

`SEGATTR_COMB`
|

`SEGATTR_PERM`
|

`SEGATTR_BITNESS`
|

`SEGATTR_FLAGS`
|

`SEGATTR_SEL`
|

`SEGATTR_ES`
|

`SEGATTR_CS`
|

`SEGATTR_SS`
|

`SEGATTR_DS`
|

`SEGATTR_FS`
|

`SEGATTR_GS`
|

`SEGATTR_TYPE`
|

`SEGATTR_COLOR`
|

`SEGATTR_START`
|

`SFL_COMORG`
|

`SFL_OBOK`
|

`SFL_HIDDEN`
|

`SFL_DEBUG`
|

`SFL_LOADER`
|

`SFL_HIDETYPE`
|

`MSF_SILENT`
|

`MSF_NOFIX`
|

`MSF_LDKEEP`
|

`MSF_FIXONCE`
|

`MOVE_SEGM_OK`
|

`MOVE_SEGM_PARAM`
|

`MOVE_SEGM_ROOM`
|

`MOVE_SEGM_IDP`
|

`MOVE_SEGM_CHUNK`
|

`MOVE_SEGM_LOADER`
|

`MOVE_SEGM_ODD`
|

`MOVE_SEGM_ORPHAN`
|

`MOVE_SEGM_DEBUG`
|

`MOVE_SEGM_SOURCEFILES`
|

`MOVE_SEGM_MAPPING`
|

`MOVE_SEGM_INVAL`
|

`rebase_program`
|

`set_storage_type`
|

`STT_VA`
|

`STT_MM`
|

`fl_CF`
|

`fl_CN`
|

`fl_JF`
|

`fl_JN`
|

`fl_F`
|

`XREF_USER`
|

`add_cref`
|

`del_cref`
|

`get_first_cref_from`
|

`get_next_cref_from`
|

`get_first_cref_to`
|

`get_next_cref_to`
|

`get_first_fcref_from`
|

`get_next_fcref_from`
|

`get_first_fcref_to`
|

`get_next_fcref_to`
|

`dr_O`
|

`dr_W`
|

`dr_R`
|

`dr_T`
|

`dr_I`
|

`add_dref`
|

`del_dref`
|

`get_first_dref_from`
|

`get_next_dref_from`
|

`get_first_dref_to`
|

`get_next_dref_to`
|

`add_func`
|

`del_func`
|

`set_func_end`
|

`FUNCATTR_START`
|

`FUNCATTR_END`
|

`FUNCATTR_FLAGS`
|

`FUNCATTR_FRAME`
|

`FUNCATTR_FRSIZE`
|

`FUNCATTR_FRREGS`
|

`FUNCATTR_ARGSIZE`
|

`FUNCATTR_FPD`
|

`FUNCATTR_COLOR`
|

`FUNCATTR_OWNER`
|

`FUNCATTR_REFQTY`
|

`FUNCATTR_START`
|

`FUNC_NORET`
|

`FUNC_FAR`
|

`FUNC_LIB`
|

`FUNC_STATIC`
|

`FUNC_FRAME`
|

`FUNC_USERFAR`
|

`FUNC_HIDDEN`
|

`FUNC_THUNK`
|

`FUNC_BOTTOMBP`
|

`FUNC_NORET_PENDING`
|

`FUNC_SP_READY`
|

`FUNC_PURGED_OK`
|

`FUNC_TAIL`
|

`FUNC_LUMINA`
|

`FUNC_OUTLINE`
|

`get_fchunk_referer`
|

`add_user_stkpnt`
|

`recalc_spd`
|

`get_entry_qty`
|

`add_entry`
|

`get_entry_ordinal`
|

`get_entry`
|

`get_entry_name`
|

`rename_entry`
|

`get_next_fixup_ea`
|

`get_prev_fixup_ea`
|

`FIXUP_OFF8`
|

`FIXUP_OFF16`
|

`FIXUP_SEG16`
|

`FIXUP_PTR32`
|

`FIXUP_OFF32`
|

`FIXUP_PTR48`
|

`FIXUP_HI8`
|

`FIXUP_HI16`
|

`FIXUP_LOW8`
|

`FIXUP_LOW16`
|

`FIXUP_OFF64`
|

`FIXUP_CUSTOM`
|

`FIXUPF_REL`
|

`FIXUPF_EXTDEF`
|

`FIXUPF_UNUSED`
|

`FIXUPF_CREATED`
|

`del_fixup`
|

`put_bookmark`
|

`get_bookmark`
|

`get_bookmark_desc`
|

`ENFL_REGEX`
|

`AR_LONG`
|
Array of longs

`AR_STR`
|
Array of strings

`add_sourcefile`
|

`get_sourcefile`
|

`del_sourcefile`
|

`set_source_linnum`
|

`get_source_linnum`
|

`del_source_linnum`
|

`SizeOf`
|

`TINFO_GUESSED`
|

`TINFO_DEFINITE`
|

`TINFO_DELAYFUNC`
|

`PT_SIL`
|

`PT_NDC`
|

`PT_TYP`
|

`PT_VAR`
|

`PT_PACKMASK`
|

`PT_HIGH`
|

`PT_LOWER`
|

`PT_REPLACE`
|

`PT_RAWARGS`
|

`PT_SILENT`
|

`PT_PAKDEF`
|

`PT_PAK1`
|

`PT_PAK2`
|

`PT_PAK4`
|

`PT_PAK8`
|

`PT_PAK16`
|

`PT_FILE`
|

`PT_STANDALONE`
|

`PDF_INCL_DEPS`
|

`PDF_DEF_FWD`
|

`PDF_DEF_BASE`
|

`PDF_HEADER_CMT`
|

`PRTYPE_1LINE`
|

`PRTYPE_MULTI`
|

`PRTYPE_TYPE`
|

`PRTYPE_PRAGMA`
|

`PRTYPE_SEMI`
|

`PRTYPE_CPP`
|

`PRTYPE_DEF`
|

`PRTYPE_NOARGS`
|

`PRTYPE_NOARRS`
|

`PRTYPE_NORES`
|

`PRTYPE_RESTORE`
|

`PRTYPE_NOREGEX`
|

`PRTYPE_COLORED`
|

`PRTYPE_METHODS`
|

`PRTYPE_1LINCMT`
|

`add_hidden_range`
|

`del_hidden_range`
|

`load_debugger`
|

`start_process`
|

`exit_process`
|

`suspend_process`
|

`get_processes`
|

`attach_process`
|

`detach_process`
|

`get_thread_qty`
|

`getn_thread`
|

`get_current_thread`
|

`getn_thread_name`
|

`select_thread`
|

`suspend_thread`
|

`resume_thread`
|

`step_into`
|

`step_over`
|

`run_to`
|

`step_until_ret`
|

`wait_for_next_event`
|

`WFNE_ANY`
|

`WFNE_SUSP`
|

`WFNE_SILENT`
|

`WFNE_CONT`
|

`WFNE_NOWAIT`
|

`NOTASK`
|

`DBG_ERROR`
|

`DBG_TIMEOUT`
|

`PROCESS_STARTED`
|

`PROCESS_EXITED`
|

`THREAD_STARTED`
|

`THREAD_EXITED`
|

`BREAKPOINT`
|

`STEP`
|

`EXCEPTION`
|

`LIB_LOADED`
|

`LIB_UNLOADED`
|

`INFORMATION`
|

`PROCESS_ATTACHED`
|

`PROCESS_DETACHED`
|

`PROCESS_SUSPENDED`
|

`refresh_debugger_memory`
|

`take_memory_snapshot`
|

`get_process_state`
|

`DSTATE_SUSP`
|

`DSTATE_NOTASK`
|

`DSTATE_RUN`
|

`DSTATE_RUN_WAIT_ATTACH`
|

`DSTATE_RUN_WAIT_END`
|
Get various information about the current debug event

`set_debugger_options`
|

`DOPT_SEGM_MSGS`
|

`DOPT_START_BPT`
|

`DOPT_THREAD_MSGS`
|

`DOPT_THREAD_BPT`
|

`DOPT_BPT_MSGS`
|

`DOPT_LIB_MSGS`
|

`DOPT_LIB_BPT`
|

`DOPT_INFO_MSGS`
|

`DOPT_INFO_BPT`
|

`DOPT_REAL_MEMORY`
|

`DOPT_REDO_STACK`
|

`DOPT_ENTRY_BPT`
|

`DOPT_EXCDLG`
|

`EXCDLG_NEVER`
|

`EXCDLG_UNKNOWN`
|

`EXCDLG_ALWAYS`
|

`DOPT_LOAD_DINFO`
|

`get_debugger_event_cond`
|

`set_debugger_event_cond`
|

`set_remote_debugger`
|

`define_exception`
|

`EXC_BREAK`
|

`EXC_HANDLE`
|

`get_reg_value`
|

`get_bpt_qty`
|

`BPTATTR_EA`
|

`BPTATTR_SIZE`
|

`BPTATTR_TYPE`
|

`BPT_WRITE`
|

`BPT_RDWR`
|

`BPT_SOFT`
|

`BPT_EXEC`
|

`BPT_DEFAULT`
|

`BPTATTR_COUNT`
|

`BPTATTR_FLAGS`
|

`BPT_BRK`
|

`BPT_TRACE`
|

`BPT_UPDMEM`
|

`BPT_ENABLED`
|

`BPT_LOWCND`
|

`BPT_TRACEON`
|

`BPT_TRACE_INSN`
|

`BPT_TRACE_FUNC`
|

`BPT_TRACE_BBLK`
|

`BPTATTR_COND`
|

`BPTATTR_PID`
|

`BPTATTR_TID`
|

`BPLT_ABS`
|

`BPLT_REL`
|

`BPLT_SYM`
|

`add_bpt`
|

`del_bpt`
|

`enable_bpt`
|

`check_bpt`
|

`BPTCK_NONE`
|

`BPTCK_NO`
|

`BPTCK_YES`
|

`BPTCK_ACT`
|

`TRACE_STEP`
|

`TRACE_INSN`
|

`TRACE_FUNC`
|

`get_step_trace_options`
|

`set_step_trace_options`
|

`ST_OVER_DEBUG_SEG`
|

`ST_OVER_LIB_FUNC`
|

`ST_ALREADY_LOGGED`
|

`ST_SKIP_LOOPS`
|

`load_trace_file`
|

`save_trace_file`
|

`is_valid_trace_file`
|

`diff_trace_file`
|

`get_trace_file_desc`
|

`set_trace_file_desc`
|

`get_tev_qty`
|

`get_tev_ea`
|

`TEV_NONE`
|

`TEV_INSN`
|

`TEV_CALL`
|

`TEV_RET`
|

`TEV_BPT`
|

`TEV_MEM`
|

`TEV_EVENT`
|

`get_tev_type`
|

`get_tev_tid`
|

`get_tev_reg`
|

`get_tev_mem_qty`
|

`get_tev_mem`
|

`get_tev_mem_ea`
|

`get_call_tev_callee`
|

`get_ret_tev_return`
|

`get_bpt_tev_ea`
|

`CIC_ITEM`
|

`CIC_FUNC`
|

`CIC_SEGM`
|

`DEFCOLOR`
|

`ARGV`
|
The command line arguments passed to IDA via the -S switch.

## Exceptions

`DeprecatedIDCError`
|
Exception for deprecated function calls

## Functions

`has_value`(F)
|

`byte_value`(F)
|
Get byte value from flags

`is_loaded`(ea)
|
Is the byte initialized?

`is_code`(F)
|

`is_data`(F)
|

`is_tail`(F)
|

`is_unknown`(F)
|

`is_head`(F)
|

`is_flow`(F)
|

`isExtra`(F)
|

`isRef`(F)
|

`hasName`(F)
|

`hasUserName`(F)
|

`is_defarg0`(F)
|

`is_defarg1`(F)
|

`isDec0`(F)
|

`isDec1`(F)
|

`isHex0`(F)
|

`isHex1`(F)
|

`isOct0`(F)
|

`isOct1`(F)
|

`isBin0`(F)
|

`isBin1`(F)
|

`is_off0`(F)
|

`is_off1`(F)
|

`is_char0`(F)
|

`is_char1`(F)
|

`is_seg0`(F)
|

`is_seg1`(F)
|

`is_enum0`(F)
|

`is_enum1`(F)
|

`is_manual0`(F)
|

`is_manual1`(F)
|

`is_stroff0`(F)
|

`is_stroff1`(F)
|

`is_stkvar0`(F)
|

`is_stkvar1`(F)
|

`is_byte`(F)
|

`is_word`(F)
|

`is_dword`(F)
|

`is_qword`(F)
|

`is_oword`(F)
|

`is_tbyte`(F)
|

`is_float`(F)
|

`is_double`(F)
|

`is_pack_real`(F)
|

`is_strlit`(F)
|

`is_struct`(F)
|

`is_align`(F)
|

`value_is_string`(var)
|

`value_is_long`(var)
|

`value_is_float`(var)
|

`value_is_func`(var)
|

`value_is_pvoid`(var)
|

`value_is_int64`(var)
|

`to_ea`(seg, off)
|
Return value of expression: ((seg<<4) + off)

`form`(format, *args)
|

`substr`(s, x1, x2)
|

`strstr`(s1, s2)
|

`strlen`(s)
|

`xtol`(s)
|

`atoa`(ea)
|
Convert address value to a string

`ltoa`(n, radix)
|

`atol`(s)
|

`rotate_left`(value, count, nbits, offset)
|
Rotate a value to the left (or right)

`rotate_dword`(x, count)
|

`rotate_word`(x, count)
|

`rotate_byte`(x, count)
|

`eval_idc`(expr)
|
Evaluate an IDC expression

`EVAL_FAILURE`(code)
|
Check the result of eval_idc() for evaluation failures

`save_database`(idbname[, flags])
|
Save current database to the specified idb file

`validate_idb_names`([do_repair])
|
check consistency of IDB name records

`call_system`(command)
|
Execute an OS command.

`qsleep`(milliseconds)
|
qsleep the specified number of milliseconds

`delete_all_segments`()
|
Delete all segments, instructions, comments, i.e. everything

`plan_and_wait`(sEA, eEA[, final_pass])
|
Perform full analysis of the range

`set_name`(ea, name[, flags])
|
Rename an address

`make_array`(ea, nitems)
|
Create an array.

`create_strlit`(ea, endea)
|
Create a string.

`create_byte`(ea)
|
Convert the current item to a byte

`create_word`(ea)
|
Convert the current item to a word (2 bytes)

`create_dword`(ea)
|
Convert the current item to a double word (4 bytes)

`create_qword`(ea)
|
Convert the current item to a quadro word (8 bytes)

`create_oword`(ea)
|
Convert the current item to an octa word (16 bytes/128 bits)

`create_yword`(ea)
|
Convert the current item to a ymm word (32 bytes/256 bits)

`create_float`(ea)
|
Convert the current item to a floating point (4 bytes)

`create_double`(ea)
|
Convert the current item to a double floating point (8 bytes)

`create_pack_real`(ea)
|
Convert the current item to a packed real (10 or 12 bytes)

`create_tbyte`(ea)
|
Convert the current item to a tbyte (10 or 12 bytes)

`create_struct`(ea, size, strname)
|
Convert the current item to a structure instance

`define_local_var`(start, end, location, name)
|
Create a local variable

`set_array_params`(ea, flags, litems, align)
|
Set array representation format

`op_plain_offset`(ea, n, base)
|
Convert operand to an offset

`toggle_bnot`(ea, n)
|
Toggle the bitwise not operator for the operand

`op_stroff`(ea, n, strid, delta)
|
Convert operand to an offset in a structure

`op_offset_high16`(ea, n, target)
|
Convert operand to a high offset

`MakeVar`(ea)
|

`split_sreg_range`(ea, reg, value[, tag])
|
Set value of a segment register.

`AutoMark`(ea, qtype)
|
Plan to analyze an address

`gen_file`(filetype, path, ea1, ea2, flags)
|
Generate an output file

`gen_flow_graph`(outfile, title, ea1, ea2, flags)
|
Generate a flow chart GDL file

`gen_simple_call_chart`(outfile, title, flags)
|
Generate a function call graph GDL file

`idadir`()
|
Get IDA directory

`get_idb_path`()
|
Get IDB full path

`get_bytes`(ea, size[, use_dbg])
|
Return the specified number of bytes of the program

`read_dbg_byte`(ea)
|
Get value of program byte using the debugger memory

`read_dbg_word`(ea)
|
Get value of program word using the debugger memory

`read_dbg_dword`(ea)
|
Get value of program double-word using the debugger memory

`read_dbg_qword`(ea)
|
Get value of program quadro-word using the debugger memory

`write_dbg_memory`(ea, data)
|
Write to debugger memory.

`GetFloat`(ea)
|
Get value of a floating point number (4 bytes)

`GetDouble`(ea)
|
Get value of a floating point number (8 bytes)

`get_name_ea_simple`(name)
|
Get linear address of a name

`get_segm_by_sel`(base)
|
Get segment by segment base

`get_curline`()
|
Get the disassembly line at the cursor

`read_selection_start`()
|
Get start address of the selected range

`read_selection_end`()
|
Get end address of the selected range

`get_sreg`(ea, reg)
|
Get value of segment register at the specified address

`next_head`(ea[, maxea])
|
Get next defined item (instruction or data) in the program

`prev_head`(ea[, minea])
|
Get previous defined item (instruction or data) in the program

`get_item_size`(ea)
|
Get size of instruction or data item in bytes

`func_contains`(func_ea, ea)
|
Does the given function contain the given address?

`get_name`(ea[, gtn_flags])
|
Get name at the specified address

`demangle_name`(name, disable_mask)
|
demangle_name a name

`generate_disasm_line`(ea, flags)
|
Get disassembly line

`GetDisasm`(ea)
|
Get disassembly line

`print_insn_mnem`(ea)
|
Get instruction mnemonics

`print_operand`(ea, n)
|
Get operand of an instruction or data

`get_operand_type`(ea, n)
|
Get type of instruction operand

`get_operand_value`(ea, n)
|
Get number used in the operand

`get_strlit_contents`(ea[, length, strtype])
|
Get string contents

`get_str_type`(ea)
|
Get string type

`process_config_line`(directive)
|
Obsolete. Please use ida_idp.process_config_directive().

`get_inf_attr`(attr)
|
Deprecated. Please ida_ida.inf_get_* instead.

`set_inf_attr`(attr, value)
|
Deprecated. Please ida_ida.inf_set_* instead.

`SetPrcsr`(processor)
|

`get_processor_name`()
|
Get name of the current processor

`batch`(batch)
|
Enable/disable batch mode of operation

`process_ui_action`(name[, flags])
|
Invokes an IDA UI action by name

`sel2para`(sel)
|
Get a selector value

`find_selector`(val)
|
Find a selector which has the specified value

`get_first_seg`()
|
Get first segment

`get_next_seg`(ea)
|
Get next segment

`get_segm_start`(ea)
|
Get start address of a segment

`get_segm_end`(ea)
|
Get end address of a segment

`get_segm_name`(ea)
|
Get name of a segment

`add_segm_ex`(startea, endea, base, use32, align, comb, ...)
|
Create a new segment

`AddSeg`(startea, endea, base, use32, align, comb)
|

`set_segment_bounds`(ea, startea, endea, flags)
|
Change segment boundaries

`set_segm_name`(ea, name)
|
Change name of the segment

`set_segm_class`(ea, segclass)
|
Change class of the segment

`set_segm_alignment`(ea, alignment)
|
Change alignment of the segment

`set_segm_combination`(segea, comb)
|
Change combination of the segment

`set_segm_addressing`(ea, bitness)
|
Change segment addressing

`selector_by_name`(segname)
|
Get segment selector by name

`set_default_sreg_value`(ea, reg, value)
|
Set default segment register value for a segment

`set_segm_type`(segea, segtype)
|
Set segment type

`get_segm_attr`(segea, attr)
|
Get segment attribute

`set_segm_attr`(segea, attr, value)
|
Set segment attribute

`move_segm`(ea, to, flags)
|
Move a segment to a new address

`get_xref_type`()
|
Return type of the last xref obtained by

`fopen`(f, mode)
|

`fclose`(handle)
|

`filelength`(handle)
|

`fseek`(handle, offset, origin)
|

`ftell`(handle)
|

`LoadFile`(filepath, pos, ea, size)
|
Load file into IDA database

`loadfile`(filepath, pos, ea, size)
|

`SaveFile`(filepath, pos, ea, size)
|
Save from IDA database to file

`savefile`(filepath, pos, ea, size)
|

`fgetc`(handle)
|

`fputc`(byte, handle)
|

`fprintf`(handle, format, *args)
|

`readshort`(handle, mostfirst)
|

`readlong`(handle, mostfirst)
|

`writeshort`(handle, word, mostfirst)
|

`writelong`(handle, dword, mostfirst)
|

`readstr`(handle)
|

`writestr`(handle, s)
|

`get_next_func`(ea)
|
Find next function

`get_prev_func`(ea)
|
Find previous function

`get_func_attr`(ea, attr)
|
Get a function attribute

`set_func_attr`(ea, attr, value)
|
Set a function attribute

`get_func_flags`(ea)
|
Retrieve function flags

`set_func_flags`(ea, flags)
|
Change function flags

`get_func_name`(ea)
|
Retrieve function name

`get_func_cmt`(ea, repeatable)
|
Retrieve function comment

`set_func_cmt`(ea, cmt, repeatable)
|
Set function comment

`choose_func`(title)
|
Ask the user to select a function

`get_func_off_str`(ea)
|
Convert address to 'funcname+offset' string

`find_func_end`(ea)
|
Determine a new function boundaries

`get_frame_id`(ea)
|
Get ID of function frame structure

`get_frame_lvar_size`(ea)
|
Get size of local variables in function frame

`get_frame_regs_size`(ea)
|
Get size of saved registers in function frame

`get_frame_args_size`(ea)
|
Get size of arguments in function frame which are purged upon return

`get_frame_size`(ea)
|
Get full size of function frame

`set_frame_size`(ea, lvsize, frregs, argsize)
|
Make function frame

`get_spd`(ea)
|
Get current delta for the stack pointer

`get_sp_delta`(ea)
|
Get modification of SP made by the instruction

`get_fchunk_attr`(ea, attr)
|
Get a function chunk attribute

`set_fchunk_attr`(ea, attr, value)
|
Set a function chunk attribute

`get_next_fchunk`(ea)
|
Get next function chunk

`get_prev_fchunk`(ea)
|
Get previous function chunk

`append_func_tail`(funcea, ea1, ea2)
|
Append a function chunk to the function

`remove_fchunk`(funcea, tailea)
|
Remove a function chunk from the function

`set_tail_owner`(tailea, funcea)
|
Change the function chunk owner

`first_func_chunk`(funcea)
|
Get the first function chunk of the specified function

`next_func_chunk`(funcea, tailea)
|
Get the next function chunk of the specified function

`add_auto_stkpnt`(func_ea, ea, delta)
|
Add automatic SP register change point

`del_stkpnt`(func_ea, ea)
|
Delete SP register change point

`get_min_spd_ea`(func_ea)
|
Return the address with the minimal spd (stack pointer delta)

`get_fixup_target_type`(ea)
|
Get fixup target type

`get_fixup_target_flags`(ea)
|
Get fixup target flags

`get_fixup_target_sel`(ea)
|
Get fixup target selector

`get_fixup_target_off`(ea)
|
Get fixup target offset

`get_fixup_target_dis`(ea)
|
Get fixup target displacement

`set_fixup`(ea, fixuptype, fixupflags, targetsel, ...)
|
Set fixup information

`get_struc_id`(name)
|

`get_struc_name`(tid)
|

`get_struc_cmt`(tid)
|

`get_struc_size`(tid)
|

`get_member_qty`(sid)
|
Get number of members of a structure

`get_member_by_idx`(sid, idx)
|
Get member ID by member ordinal number

`is_member_id`(sid)
|
Is a member id?

`get_member_id`(sid, member_offset)
|

`get_member_offset`(sid, member_name)
|
Get offset of a member of a structure by the member name

`get_member_name`(sid, member_offset)
|
Get name of a member of a structure

`get_member_cmt`(sid, member_offset[, repeatable])
|
Get comment of a member

`get_member_size`(sid, member_offset)
|
Get size of a member

`get_member_strid`(sid, member_offset)
|
Get structure id of a member

`is_union`(sid)
|
Is a structure a union?

`add_struc`(index, name, is_union)
|
Define a new structure type

`del_struc`(sid)
|
Delete a structure type

`set_struc_name`(sid, name)
|

`set_struc_cmt`(sid, cmt[, repeatable])
|

`add_struc_member`(sid, name, offset, flag, typeid, nbytes)
|
Add structure member

`del_struc_member`(sid, member_offset)
|
Delete structure member

`set_member_name`(sid, member_offset, name)
|
Change structure member name

`set_member_type`(sid, member_offset, flag, typeid, nitems)
|
Change structure member type

`set_member_cmt`(sid, member_offset, comment, repeatable)
|
Change structure member comment

`expand_struc`(sid, offset, delta[, recalc])
|
Expand or shrink a structure type

`get_enum`(name)
|
Get enum by name

`get_enum_name`(enum_id[, flags])
|
Get name of enum

`get_enum_cmt`(enum_id)
|
Get enum comment

`get_enum_size`(enum_id)
|
Get the number of the members of the enum

`get_enum_width`(enum_id)
|
Get the width of a enum element

`get_enum_flag`(enum_id)
|
Get flags determining the representation of the enum.

`get_enum_member_by_name`(name)
|
Get a reference to an enum member by its name

`get_enum_member_enum`(const_id)
|
Get the parent enum of an enum member

`get_enum_member`(enum_id, value, serial, bmask)
|
Get id of constant

`get_first_bmask`(enum_id)
|
Get first bitmask in the enum

`get_last_bmask`(enum_id)
|
Get last bitmask in the enum

`get_next_bmask`(enum_id, bmask)
|
Get next bitmask in the enum

`get_prev_bmask`(enum_id, bmask)
|
Get prev bitmask in the enum

`get_bmask_name`(enum_id, bmask)
|
Get bitmask name (only for bitfields)

`get_bmask_cmt`(enum_id, bmask, repeatable)
|
Get bitmask comment (only for bitfields)

`set_bmask_name`(enum_id, bmask, name)
|
Set bitmask name (only for bitfields)

`set_bmask_cmt`(enum_id, bmask, cmt, repeatable)
|
Set bitmask comment (only for bitfields)

`get_first_enum_member`(enum_id[, bmask])
|
Get first constant in the enum

`get_last_enum_member`(enum_id[, bmask])
|
Get last constant in the enum

`get_next_enum_member`(enum_id, value[, bmask])
|
Get next constant in the enum

`get_prev_enum_member`(enum_id, value[, bmask])
|
Get prev constant in the enum

`get_enum_member_name`(const_id)
|
Get name of a constant

`get_enum_member_cmt`(const_id[, repeatable])
|
Get comment of a constant

`get_enum_member_value`(const_id)
|
Get value of an enum member

`get_enum_member_bmask`(const_id)
|
Get bitmask of an enum member

`add_enum`(idx, name, flag)
|
Add a new enum type

`del_enum`(enum_id)
|
Delete an enum type

`set_enum_name`(enum_id, name)
|
Set name of enum type

`set_enum_flag`(enum_id, flag)
|
Set enum constant representation flags

`set_enum_width`(enum_id, nbytes)
|
Set the width of enum base type

`is_bf`(enum_id)
|
Is enum a bitmask ?

`set_enum_bf`(enum_id, bf)
|
Set or clear the 'bitmask' attribute of an enum

`set_enum_cmt`(enum_id, cmt, repeatable)
|
Set comment for enum type

`add_enum_member`(enum_id, name, value[, bmask])
|
Add a member of enum - a symbolic constant

`del_enum_member`(enum_id, value, serial[, bmask])
|
Delete a member of enum - a symbolic constant

`set_enum_member_name`(const_id, name)
|
Set name of enum member

`set_enum_member_cmt`(const_id, cmt[, repeatable])
|
Set comment for enum member

`create_array`(name)
|
Create array.

`get_array_id`(name)
|
Get array array_id, by name.

`rename_array`(array_id, newname)
|
Rename array, by its ID.

`delete_array`(array_id)
|
Delete array, by its ID.

`set_array_long`(array_id, idx, value)
|
Sets the long value of an array element.

`set_array_string`(array_id, idx, value)
|
Sets the string value of an array element.

`get_array_element`(tag, array_id, idx)
|
Get value of array element.

`del_array_element`(tag, array_id, idx)
|
Delete an array element.

`get_first_index`(tag, array_id)
|
Get index of the first existing array element.

`get_last_index`(tag, array_id)
|
Get index of last existing array element.

`get_next_index`(tag, array_id, idx)
|
Get index of the next existing array element.

`get_prev_index`(tag, array_id, idx)
|
Get index of the previous existing array element.

`set_hash_long`(hash_id, key, value)
|
Sets the long value of a hash element.

`get_hash_long`(hash_id, key)
|
Gets the long value of a hash element.

`set_hash_string`(hash_id, key, value)
|
Sets the string value of a hash element.

`get_hash_string`(hash_id, key)
|
Gets the string value of a hash element.

`del_hash_string`(hash_id, key)
|
Delete a hash element.

`get_first_hash_key`(hash_id)
|
Get the first key in the hash.

`get_last_hash_key`(hash_id)
|
Get the last key in the hash.

`get_next_hash_key`(hash_id, key)
|
Get the next key in the hash.

`get_prev_hash_key`(hash_id, key)
|
Get the previous key in the hash.

`add_default_til`(name)
|
Load a type library

`import_type`(idx, type_name)
|
Copy information from type library to database

`get_type`(ea)
|
Get type of function/variable

`sizeof`(typestr)
|
Returns the size of the type. It is equivalent to IDC's sizeof().

`get_tinfo`(ea)
|
Get type information of function/variable as 'typeinfo' object

`get_local_tinfo`(ordinal)
|
Get local type information as 'typeinfo' object

`guess_type`(ea)
|
Guess type of function/variable

`apply_type`(ea, py_type[, flags])
|
Apply the specified type to the address

`SetType`(ea, newtype)
|
Set type of function/variable

`parse_decl`(inputtype, flags)
|
Parse type declaration

`parse_decls`(inputtype[, flags])
|
Parse type declarations

`print_decls`(ordinals, flags)
|
Print types in a format suitable for use in a header file

`get_ordinal_limit`()
|
Get number of local types + 1

`set_local_type`(ordinal, input, flags)
|
Parse one type declaration and store it in the specified slot

`GetLocalType`(ordinal, flags)
|
Retrieve a local type declaration

`get_numbered_type_name`(ordinal)
|
Retrieve a local type name

`update_hidden_range`(ea, visible)
|
Set hidden range state

`get_first_module`()
|
Enumerate process modules

`get_next_module`(base)
|
Enumerate process modules

`get_module_name`(base)
|
Get process module name

`get_module_size`(base)
|
Get process module size

`resume_process`()
|

`send_dbg_command`(cmd)
|
Sends a command to the debugger module and returns the output string.

`get_event_id`()
|
Get ID of debug event

`get_event_pid`()
|
Get process ID for debug event

`get_event_tid`()
|
Get type ID for debug event

`get_event_ea`()
|
Get ea for debug event

`is_event_handled`()
|
Is the debug event handled?

`get_event_module_name`()
|
Get module name for debug event

`get_event_module_base`()
|
Get module base for debug event

`get_event_module_size`()
|
Get module size for debug event

`get_event_exit_code`()
|
Get exit code for debug event

`get_event_info`()
|
Get debug event info

`get_event_bpt_hea`()
|
Get hardware address for BREAKPOINT event

`get_event_exc_code`()
|
Get exception code for EXCEPTION event

`get_event_exc_ea`()
|
Get address for EXCEPTION event

`can_exc_continue`()
|
Can it continue after EXCEPTION event?

`get_event_exc_info`()
|
Get info for EXCEPTION event

`set_reg_value`(value, name)
|
Set register value

`get_bpt_ea`(n)
|
Get breakpoint address

`get_bpt_attr`(ea, bptattr)
|
Get the characteristics of a breakpoint

`set_bpt_attr`(address, bptattr, value)
|
modifiable characteristics of a breakpoint

`set_bpt_cond`(ea, cnd[, is_lowcnd])
|
Set breakpoint condition

`enable_tracing`(trace_level, enable)
|
Enable step tracing

`clear_trace`(filename)
|
Clear the current trace buffer

`get_color`(ea, what)
|
Get item color

`set_color`(ea, what, color)
|
Set item color

`force_bl_jump`(ea)
|
Some ARM compilers in Thumb mode use BL (branch-and-link)

`force_bl_call`(ea)
|
Force BL instruction to be a call

`set_flag`(off, bit, value)
|

`here`()
|

`is_mapped`(ea)
|

## Module Contents

idc.WORDMASK=18446744073709551615exceptionidc.DeprecatedIDCError
Bases: `Exception`

Exception for deprecated function calls
idc.BADADDRidc.BADSELidc.SIZE_MAXidc.MS_VALidc.FF_IVLidc.has_value(F)idc.byte_value(F)
Get byte value from flags Get value of byte provided that the byte is initialized. This macro works ok only for 8-bit byte machines.
idc.is_loaded(ea)
Is the byte initialized?
idc.MS_CLSidc.FF_CODEidc.FF_DATAidc.FF_TAILidc.FF_UNKidc.is_code(F)idc.is_data(F)idc.is_tail(F)idc.is_unknown(F)idc.is_head(F)idc.MS_COMMidc.FF_COMMidc.FF_REFidc.FF_LINEidc.FF_NAMEidc.FF_LABLidc.FF_FLOWidc.FF_ANYNAMEidc.is_flow(F)idc.isExtra(F)idc.isRef(F)idc.hasName(F)idc.hasUserName(F)idc.MS_0TYPEidc.FF_0VOIDidc.FF_0NUMHidc.FF_0NUMDidc.FF_0CHARidc.FF_0SEGidc.FF_0OFFidc.FF_0NUMBidc.FF_0NUMOidc.FF_0ENUMidc.FF_0FOPidc.FF_0STROidc.FF_0STKidc.MS_1TYPEidc.FF_1VOIDidc.FF_1NUMHidc.FF_1NUMDidc.FF_1CHARidc.FF_1SEGidc.FF_1OFFidc.FF_1NUMBidc.FF_1NUMOidc.FF_1ENUMidc.FF_1FOPidc.FF_1STROidc.FF_1STKidc.is_defarg0(F)idc.is_defarg1(F)idc.isDec0(F)idc.isDec1(F)idc.isHex0(F)idc.isHex1(F)idc.isOct0(F)idc.isOct1(F)idc.isBin0(F)idc.isBin1(F)idc.is_off0(F)idc.is_off1(F)idc.is_char0(F)idc.is_char1(F)idc.is_seg0(F)idc.is_seg1(F)idc.is_enum0(F)idc.is_enum1(F)idc.is_manual0(F)idc.is_manual1(F)idc.is_stroff0(F)idc.is_stroff1(F)idc.is_stkvar0(F)idc.is_stkvar1(F)idc.DT_TYPEidc.FF_BYTEidc.FF_WORDidc.FF_DWORDidc.FF_QWORDidc.FF_TBYTEidc.FF_STRLITidc.FF_STRUCTidc.FF_OWORDidc.FF_FLOATidc.FF_DOUBLEidc.FF_PACKREALidc.FF_ALIGNidc.is_byte(F)idc.is_word(F)idc.is_dword(F)idc.is_qword(F)idc.is_oword(F)idc.is_tbyte(F)idc.is_float(F)idc.is_double(F)idc.is_pack_real(F)idc.is_strlit(F)idc.is_struct(F)idc.is_align(F)idc.MS_CODEidc.FF_FUNCidc.FF_IMMDidc.FF_JUMPidc.NEF_SEGSidc.NEF_RSCSidc.NEF_NAMEidc.NEF_MANidc.NEF_FILLidc.NEF_IMPSidc.NEF_FIRSTidc.NEF_CODEidc.NEF_RELOADidc.NEF_FLATidc.value_is_string(var)idc.value_is_long(var)idc.value_is_float(var)idc.value_is_func(var)idc.value_is_pvoid(var)idc.value_is_int64(var)idc.to_ea(seg, off)
Return value of expression: ((seg<<4) + off)
idc.form(format, *args)idc.substr(s, x1, x2)idc.strstr(s1, s2)idc.strlen(s)idc.xtol(s)idc.atoa(ea)
Convert address value to a string Return address in the form ‘seg000:1234’ (the same as in line prefixes)
Parameters:
ea – address to format
idc.ltoa(n, radix)idc.atol(s)idc.rotate_left(value, count, nbits, offset)
Rotate a value to the left (or right)
Parameters:

-
value – value to rotate

-
count – number of times to rotate. negative counter means rotate to the right

-
nbits – number of bits to rotate

-
offset – offset of the first bit to rotate

Returns:
the value with the specified field rotated all other bits are not modified
idc.rotate_dword(x, count)idc.rotate_word(x, count)idc.rotate_byte(x, count)idc.IDCHK_OK=0idc.IDCHK_ARG=-1idc.IDCHK_KEY=-2idc.IDCHK_MAX=-3idc.add_idc_hotkeyidc.del_idc_hotkeyidc.jumptoidc.auto_waitidc.eval_idc(expr)
Evaluate an IDC expression
Parameters:
expr – an expression
Returns:
the expression value. If there are problems, the returned value will be “IDC_FAILURE: xxx” where xxx is the error description

NOTE: Python implementation evaluates IDC only, while IDC can call other registered languages
idc.EVAL_FAILURE(code)
Check the result of eval_idc() for evaluation failures
Parameters:
code – result of eval_idc()
Returns:
True if there was an evaluation error
idc.save_database(idbname, flags=0)
Save current database to the specified idb file
Parameters:

-
idbname – name of the idb file. if empty, the current idb file will be used.

-
flags – combination of ida_loader.DBFL_… bits or 0

idc.DBFL_BAKidc.validate_idb_names(do_repair=0)
check consistency of IDB name records :param do_repair: try to repair netnode header it TRUE :returns: number of inconsistent name records
idc.qexitidc.call_system(command)
Execute an OS command.
Parameters:
command – command line to execute
Returns:
error code from OS

NOTE: IDA will wait for the started program to finish. In order to start the command in parallel, use OS methods. For example, you may start another program in parallel using “start” command.
idc.qsleep(milliseconds)
qsleep the specified number of milliseconds This function suspends IDA for the specified amount of time
Parameters:
milliseconds – time to sleep
idc.load_and_run_pluginidc.plan_to_apply_idasgnidc.delete_all_segments()
Delete all segments, instructions, comments, i.e. everything except values of bytes.
idc.create_insnidc.plan_and_wait(sEA, eEA, final_pass=True)
Perform full analysis of the range
Parameters:

-
sEA – starting linear address

-
eEA – ending linear address (excluded)

-
final_pass – make the final pass over the specified range

Returns:
1-ok, 0-Ctrl-Break was pressed.
idc.set_name(ea, name, flags=ida_name.SN_CHECK)
Rename an address
Parameters:

-
ea – linear address

-
name – new name of address. If name == “”, then delete old name

-
flags – combination of SN_… constants

Returns:
1-ok, 0-failure
idc.SN_CHECKidc.SN_NOCHECKidc.SN_PUBLICidc.SN_NON_PUBLICidc.SN_WEAKidc.SN_NON_WEAKidc.SN_AUTOidc.SN_NON_AUTOidc.SN_NOLISTidc.SN_NOWARNidc.SN_LOCALidc.set_cmtidc.make_array(ea, nitems)
Create an array.
Parameters:

-
ea – linear address

-
nitems – size of array in items

NOTE: This function will create an array of the items with the same type as the type of the item at ‘ea’. If the byte at ‘ea’ is undefined, then this function will create an array of bytes.
idc.create_strlit(ea, endea)
Create a string.

This function creates a string (the string type is determined by the value of get_inf_attr(INF_STRTYPE))
Parameters:

-
ea – linear address

-
endea – ending address of the string (excluded) if endea == BADADDR, then length of string will be calculated by the kernel

Returns:
1-ok, 0-failure

NOTE: The type of an existing string is returned by get_str_type()
idc.create_dataidc.create_byte(ea)
Convert the current item to a byte
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_word(ea)
Convert the current item to a word (2 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_dword(ea)
Convert the current item to a double word (4 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_qword(ea)
Convert the current item to a quadro word (8 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_oword(ea)
Convert the current item to an octa word (16 bytes/128 bits)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_yword(ea)
Convert the current item to a ymm word (32 bytes/256 bits)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_float(ea)
Convert the current item to a floating point (4 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_double(ea)
Convert the current item to a double floating point (8 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_pack_real(ea)
Convert the current item to a packed real (10 or 12 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_tbyte(ea)
Convert the current item to a tbyte (10 or 12 bytes)
Parameters:
ea – linear address
Returns:
1-ok, 0-failure
idc.create_struct(ea, size, strname)
Convert the current item to a structure instance
Parameters:

-
ea – linear address

-
size – structure size in bytes. -1 means that the size will be calculated automatically

-
strname – name of a structure type

Returns:
1-ok, 0-failure
idc.create_custom_dataidc.create_alignidc.define_local_var(start, end, location, name)
Create a local variable
Parameters:

-
start – start of address range for the local variable

-
end – end of address range for the local variable

-
location – the variable location in the “[bp+xx]” form where xx is a number. The location can also be specified as a register name.

-
name – name of the local variable

Returns:
1-ok, 0-failure
NOTE: For the stack variables the end address is ignored.
If there is no function at ‘start’ then this function will fail.
idc.del_itemsidc.DELIT_SIMPLEidc.DELIT_EXPANDidc.DELIT_DELNAMESidc.set_array_params(ea, flags, litems, align)
Set array representation format
Parameters:

-
ea – linear address

-
flags – combination of AP_… constants or 0

-
litems – number of items per line. 0 means auto

-
align – element alignment - -1: do not align - 0: automatic alignment - other values: element width

Returns:
1-ok, 0-failure
idc.AP_ALLOWDUPS=1idc.AP_SIGNED=2idc.AP_INDEX=4idc.AP_ARRAY=8idc.AP_IDXBASEMASK=240idc.AP_IDXDEC=0idc.AP_IDXHEX=16idc.AP_IDXOCT=32idc.AP_IDXBIN=48idc.op_binidc.op_octidc.op_decidc.op_hexidc.op_chridc.op_plain_offset(ea, n, base)
Convert operand to an offset (for the explanations of ‘ea’ and ‘n’ please see op_bin())

### Example:

seg000:2000 dw 1234h

and there is a segment at paragraph 0x1000 and there is a data item within the segment at 0x1234:

seg000:1234 MyString db ‘Hello, world!’,0

Then you need to specify a linear address of the segment base to create a proper offset:

op_plain_offset([“seg000”,0x2000],0,0x10000);

and you will have:

seg000:2000 dw offset MyString

Motorola 680x0 processor have a concept of “outer offsets”. If you want to create an outer offset, you need to combine number of the operand with the following bit:

Please note that the outer offsets are meaningful only for Motorola 680x0.
param ea:
linear address
param n:
number of operand - 0 - the first operand - 1 - the second, third and all other operands - -1 - all operands
param base:
base of the offset as a linear address If base == BADADDR then the current operand becomes non-offset

idc.OPND_OUTERidc.op_offsetidc.REF_OFF8idc.REF_OFF16idc.REF_OFF32idc.REF_LOW8idc.REF_LOW16idc.REF_HIGH8idc.REF_HIGH16idc.REF_OFF64idc.REFINFO_RVA=16idc.REFINFO_PASTEND=32idc.REFINFO_NOBASE=128idc.REFINFO_SUBTRACT=256idc.REFINFO_SIGNEDOP=512idc.op_segidc.op_numidc.op_fltidc.op_manidc.toggle_signidc.toggle_bnot(ea, n)
Toggle the bitwise not operator for the operand
Parameters:

-
ea – linear address

-
n – number of operand - 0 - the first operand - 1 - the second, third and all other operands - -1 - all operands

idc.op_enumidc.op_stroff(ea, n, strid, delta)
Convert operand to an offset in a structure
Parameters:

-
ea – linear address

-
n – number of operand - 0 - the first operand - 1 - the second, third and all other operands - -1 - all operands

-
strid – id of a structure type

-
delta – struct offset delta. usually 0. denotes the difference between the structure base and the pointer into the structure.

idc.op_stkvaridc.op_offset_high16(ea, n, target)
Convert operand to a high offset High offset is the upper 16bits of an offset. This type is used by TMS320C6 processors (and probably by other RISC processors too)
Parameters:

-
ea – linear address

-
n – number of operand - 0 - the first operand - 1 - the second, third and all other operands - -1 - all operands

-
target – the full value (all 32bits) of the offset

idc.MakeVar(ea)idc.E_PREVidc.E_NEXTidc.get_extra_cmtidc.update_extra_cmtidc.del_extra_cmtidc.set_manual_insnidc.get_manual_insnidc.patch_dbg_byteidc.patch_byteidc.patch_wordidc.patch_dwordidc.patch_qwordidc.SR_inherit=1idc.SR_user=2idc.SR_auto=3idc.SR_autostart=4idc.split_sreg_range(ea, reg, value, tag=SR_user)
Set value of a segment register.
Parameters:

-
ea – linear address

-
reg – name of a register, like “cs”, “ds”, “es”, etc.

-
value – new value of the segment register.

-
tag – of SR_… constants

NOTE: IDA keeps tracks of all the points where segment register change their
values. This function allows you to specify the correct value of a segment register if IDA is not able to find the correct value.
idc.auto_mark_rangeidc.auto_unmarkidc.AutoMark(ea, qtype)
Plan to analyze an address
idc.AU_UNKidc.AU_CODEidc.AU_PROCidc.AU_USEDidc.AU_LIBFidc.AU_FINALidc.gen_file(filetype, path, ea1, ea2, flags)
Generate an output file
Parameters:

-
filetype – type of output file. One of OFILE_… symbols. See below.

-
path – the output file path (will be overwritten!)

-
ea1 – start address. For some file types this argument is ignored

-
ea2 – end address. For some file types this argument is ignored

-
flags – bit combination of GENFLG_…

Returns:
number of the generated lines. -1 if an error occurred OFILE_EXE: 0-can’t generate exe file, 1-ok
idc.OFILE_MAPidc.OFILE_EXEidc.OFILE_IDCidc.OFILE_LSTidc.OFILE_ASMidc.OFILE_DIFidc.GENFLG_MAPSEGidc.GENFLG_MAPNAMEidc.GENFLG_MAPDMNGidc.GENFLG_MAPLOCidc.GENFLG_IDCTYPEidc.GENFLG_ASMTYPEidc.GENFLG_GENHTMLidc.GENFLG_ASMINCidc.gen_flow_graph(outfile, title, ea1, ea2, flags)
Generate a flow chart GDL file
Parameters:

-
outfile – output file name. GDL extension will be used

-
title – graph title

-
ea1 – beginning of the range to flow chart

-
ea2 – end of the range to flow chart.

-
flags – combination of CHART_… constants

NOTE: If ea2 == BADADDR then ea1 is treated as an address within a function.
That function will be flow charted.
idc.CHART_PRINT_NAMES=4096idc.CHART_GEN_GDL=16384idc.CHART_WINGRAPH=32768idc.CHART_NOLIBFUNCS=1024idc.gen_simple_call_chart(outfile, title, flags)
Generate a function call graph GDL file
Parameters:

-
outfile – output file name. GDL extension will be used

-
title – graph title

-
flags – combination of CHART_GEN_GDL, CHART_WINGRAPH, CHART_NOLIBFUNCS

idc.idadir()
Get IDA directory

This function returns the directory where IDA.EXE resides
idc.get_root_filenameidc.get_input_file_pathidc.set_root_filenameidc.get_idb_path()
Get IDB full path

This function returns full path of the current IDB database
idc.retrieve_input_file_md5idc.get_full_flagsidc.get_db_byteidc.get_bytes(ea, size, use_dbg=False)
Return the specified number of bytes of the program
Parameters:

-
ea – linear address

-
size – size of buffer in normal 8-bit bytes

-
use_dbg – if True, use debugger memory, otherwise just the database

Returns:
None on failure otherwise a string containing the read bytes
idc.get_wide_byteidc.read_dbg_byte(ea)
Get value of program byte using the debugger memory
Parameters:
ea – linear address
Returns:
The value or None on failure.
idc.read_dbg_word(ea)
Get value of program word using the debugger memory
Parameters:
ea – linear address
Returns:
The value or None on failure.
idc.read_dbg_dword(ea)
Get value of program double-word using the debugger memory
Parameters:
ea – linear address
Returns:
The value or None on failure.
idc.read_dbg_qword(ea)
Get value of program quadro-word using the debugger memory
Parameters:
ea – linear address
Returns:
The value or None on failure.
idc.read_dbg_memoryidc.write_dbg_memory(ea, data)
Write to debugger memory.
Parameters:

-
ea – linear address

-
data – string to write

Returns:
number of written bytes (-1 - network/debugger error)

Thread-safe function (may be called only from the main thread and debthread)
idc.get_original_byteidc.get_wide_wordidc.get_wide_dwordidc.get_qwordidc.GetFloat(ea)
Get value of a floating point number (4 bytes) This function assumes number stored using IEEE format and in the same endianness as integers.
Parameters:
ea – linear address
Returns:
float
idc.GetDouble(ea)
Get value of a floating point number (8 bytes) This function assumes number stored using IEEE format and in the same endianness as integers.
Parameters:
ea – linear address
Returns:
double
idc.get_name_ea_simple(name)
Get linear address of a name
Parameters:
name – name of program byte
Returns:
address of the name BADADDR - No such name
idc.get_name_eaidc.get_segm_by_sel(base)
Get segment by segment base
Parameters:
base – segment base paragraph or selector
Returns:
linear address of the start of the segment or BADADDR if no such segment
idc.get_screen_eaidc.get_curline()
Get the disassembly line at the cursor
Returns:
string
idc.read_selection_start()
Get start address of the selected range returns BADADDR - the user has not selected an range
idc.read_selection_end()
Get end address of the selected range
Returns:
BADADDR - the user has not selected an range
idc.get_sreg(ea, reg)
Get value of segment register at the specified address
Parameters:

-
ea – linear address

-
reg – name of segment register

Returns:
the value of the segment register or -1 on error
NOTE: The segment registers in 32bit program usually contain selectors,
so to get paragraph pointed to by the segment register you need to call sel2para() function.
idc.next_addridc.prev_addridc.next_head(ea, maxea=BADADDR)
Get next defined item (instruction or data) in the program
Parameters:

-
ea – linear address to start search from

-
maxea – the search will stop at the address maxea is not included in the search range

Returns:
BADADDR - no (more) defined items
idc.prev_head(ea, minea=0)
Get previous defined item (instruction or data) in the program
Parameters:

-
ea – linear address to start search from

-
minea – the search will stop at the address minea is included in the search range

Returns:
BADADDR - no (more) defined items
idc.next_not_tailidc.prev_not_tailidc.get_item_headidc.get_item_endidc.get_item_size(ea)
Get size of instruction or data item in bytes
Parameters:
ea – linear address
Returns:
1..n
idc.func_contains(func_ea, ea)
Does the given function contain the given address?
Parameters:

-
func_ea – any address belonging to the function

-
ea – linear address

Returns:
success
idc.GN_VISIBLEidc.GN_COLOREDidc.GN_DEMANGLEDidc.GN_STRICTidc.GN_SHORTidc.GN_LONGidc.GN_LOCALidc.GN_ISRETidc.GN_NOT_ISRETidc.calc_gtn_flagsidc.get_name(ea, gtn_flags=0)
Get name at the specified address
Parameters:

-
ea – linear address

-
gtn_flags – how exactly the name should be retrieved. combination of GN_ bits

Returns:
“” - byte has no name
idc.demangle_name(name, disable_mask)
demangle_name a name
Parameters:

-
name – name to demangle

-
disable_mask – a mask that tells how to demangle the name it is a good idea to get this mask using get_inf_attr(INF_SHORT_DN) or get_inf_attr(INF_LONG_DN)

Returns:
a demangled name If the input name cannot be demangled, returns None
idc.generate_disasm_line(ea, flags)
Get disassembly line
Parameters:

-
ea – linear address of instruction

-
flags – combination of the GENDSM_ flags, or 0

Returns:
“” - could not decode instruction at the specified location
NOTE: this function may not return exactly the same mnemonics
as you see on the screen.
idc.GENDSM_FORCE_CODEidc.GENDSM_MULTI_LINEidc.GetDisasm(ea)
Get disassembly line
Parameters:
ea – linear address of instruction
Returns:
“” - could not decode instruction at the specified location
NOTE: this function may not return exactly the same mnemonics
as you see on the screen.
idc.print_insn_mnem(ea)
Get instruction mnemonics
Parameters:
ea – linear address of instruction
Returns:
“” - no instruction at the specified location

NOTE: this function may not return exactly the same mnemonics as you see on the screen.
idc.print_operand(ea, n)
Get operand of an instruction or data
Parameters:

-
ea – linear address of the item

-
n – number of operand: 0 - the first operand 1 - the second operand

Returns:
the current text representation of operand or “”
idc.get_operand_type(ea, n)
Get type of instruction operand
Parameters:

-
ea – linear address of instruction

-
n – number of operand: 0 - the first operand 1 - the second operand

Returns:
any of o_* constants or -1 on error
idc.o_voididc.o_regidc.o_memidc.o_phraseidc.o_displidc.o_immidc.o_faridc.o_nearidc.o_idpspec0idc.o_idpspec1idc.o_idpspec2idc.o_idpspec3idc.o_idpspec4idc.o_idpspec5idc.o_trregidc.o_dbregidc.o_crregidc.o_fpregidc.o_mmxregidc.o_xmmregidc.o_reglistidc.o_creglistidc.o_cregidc.o_fpreglistidc.o_textidc.o_condidc.o_spridc.o_twofpridc.o_shmbmeidc.o_crfidc.o_crbidc.o_dcridc.get_operand_value(ea, n)
Get number used in the operand

This function returns an immediate number used in the operand
Parameters:

-
ea – linear address of instruction

-
n – the operand number

Returns:
value operand is an immediate value => immediate value operand has a displacement => displacement operand is a direct memory ref => memory address operand is a register => register number operand is a register phrase => phrase number otherwise => -1
idc.GetCommentExidc.get_cmtidc.get_forced_operandidc.BPU_1Bidc.BPU_2Bidc.BPU_4Bidc.STRWIDTH_1Bidc.STRWIDTH_2Bidc.STRWIDTH_4Bidc.STRWIDTH_MASKidc.STRLYT_TERMCHRidc.STRLYT_PASCAL1idc.STRLYT_PASCAL2idc.STRLYT_PASCAL4idc.STRLYT_MASKidc.STRLYT_SHIFTidc.STRTYPE_TERMCHRidc.STRTYPE_Cidc.STRTYPE_C_16idc.STRTYPE_C_32idc.STRTYPE_PASCALidc.STRTYPE_PASCAL_16idc.STRTYPE_LEN2idc.STRTYPE_LEN2_16idc.STRTYPE_LEN4idc.STRTYPE_LEN4_16idc.STRTYPE_C16idc.get_strlit_contents(ea, length=-1, strtype=STRTYPE_C)
Get string contents :param ea: linear address :param length: string length. -1 means to calculate the max string length :param strtype: the string type (one of STRTYPE_… constants)
Returns:
string contents or empty string
idc.get_str_type(ea)
Get string type
Parameters:
ea – linear address
Returns:
One of STRTYPE_… constants
idc.find_suspopidc.find_codeidc.find_dataidc.find_unknownidc.find_definedidc.find_immidc.find_textidc.find_bytesidc.process_config_line(directive)
Obsolete. Please use ida_idp.process_config_directive().
idc.INF_VERSION=0idc.INF_PROCNAME=1idc.INF_GENFLAGS=2idc.INF_LFLAGS=3idc.INF_DATABASE_CHANGE_COUNT=4idc.INF_CHANGE_COUNTER=4idc.INF_FILETYPE=5idc.FT_EXE_OLD=0idc.FT_COM_OLD=1idc.FT_BIN=2idc.FT_DRV=3idc.FT_WIN=4idc.FT_HEX=5idc.FT_MEX=6idc.FT_LX=7idc.FT_LE=8idc.FT_NLM=9idc.FT_COFF=10idc.FT_PE=11idc.FT_OMF=12idc.FT_SREC=13idc.FT_ZIP=14idc.FT_OMFLIB=15idc.FT_AR=16idc.FT_LOADER=17idc.FT_ELF=18idc.FT_W32RUN=19idc.FT_AOUT=20idc.FT_PRC=21idc.FT_EXE=22idc.FT_COM=23idc.FT_AIXAR=24idc.FT_MACHO=25idc.INF_OSTYPE=6idc.OSTYPE_MSDOS=1idc.OSTYPE_WIN=2idc.OSTYPE_OS2=4idc.OSTYPE_NETW=8idc.INF_APPTYPE=7idc.APPT_CONSOLE=1idc.APPT_GRAPHIC=2idc.APPT_PROGRAM=4idc.APPT_LIBRARY=8idc.APPT_DRIVER=16idc.APPT_1THREAD=32idc.APPT_MTHREAD=64idc.APPT_16BIT=128idc.APPT_32BIT=256idc.INF_ASMTYPE=8idc.INF_SPECSEGS=9idc.INF_AF=10idc.INF_AF2=11idc.INF_BASEADDR=12idc.INF_START_SS=13idc.INF_START_CS=14idc.INF_START_IP=15idc.INF_START_EA=16idc.INF_START_SP=17idc.INF_MAIN=18idc.INF_MIN_EA=19idc.INF_MAX_EA=20idc.INF_OMIN_EA=21idc.INF_OMAX_EA=22idc.INF_LOWOFF=23idc.INF_LOW_OFF=23idc.INF_HIGHOFF=24idc.INF_HIGH_OFF=24idc.INF_MAXREF=25idc.INF_PRIVRANGE_START_EA=27idc.INF_START_PRIVRANGE=27idc.INF_PRIVRANGE_END_EA=28idc.INF_END_PRIVRANGE=28idc.INF_NETDELTA=29idc.INF_XREFNUM=30idc.INF_TYPE_XREFNUM=31idc.INF_TYPE_XREFS=31idc.INF_REFCMTNUM=32idc.INF_REFCMTS=32idc.INF_XREFFLAG=33idc.INF_XREFS=33idc.INF_MAX_AUTONAME_LEN=34idc.INF_NAMETYPE=35idc.INF_SHORT_DEMNAMES=36idc.INF_SHORT_DN=36idc.INF_LONG_DEMNAMES=37idc.INF_LONG_DN=37idc.INF_DEMNAMES=38idc.INF_LISTNAMES=39idc.INF_INDENT=40idc.INF_CMT_INDENT=41idc.INF_COMMENT=41idc.INF_MARGIN=42idc.INF_LENXREF=43idc.INF_OUTFLAGS=44idc.INF_CMTFLG=45idc.INF_CMTFLAG=45idc.INF_LIMITER=46idc.INF_BORDER=46idc.INF_BIN_PREFIX_SIZE=47idc.INF_BINPREF=47idc.INF_PREFFLAG=48idc.INF_STRLIT_FLAGS=49idc.INF_STRLIT_BREAK=50idc.INF_STRLIT_ZEROES=51idc.INF_STRTYPE=52idc.INF_STRLIT_PREF=53idc.INF_STRLIT_SERNUM=54idc.INF_DATATYPES=55idc.INF_CC_ID=57idc.COMP_MASK=15idc.COMP_UNK=0idc.COMP_MS=1idc.COMP_BC=2idc.COMP_WATCOM=3idc.COMP_GNU=6idc.COMP_VISAGE=7idc.COMP_BP=8idc.INF_CC_CM=58idc.INF_CC_SIZE_I=59idc.INF_CC_SIZE_B=60idc.INF_CC_SIZE_E=61idc.INF_CC_DEFALIGN=62idc.INF_CC_SIZE_S=63idc.INF_CC_SIZE_L=64idc.INF_CC_SIZE_LL=65idc.INF_CC_SIZE_LDBL=66idc.INF_COMPILER=57idc.INF_MODEL=58idc.INF_SIZEOF_INT=59idc.INF_SIZEOF_BOOL=60idc.INF_SIZEOF_ENUM=61idc.INF_SIZEOF_ALGN=62idc.INF_SIZEOF_SHORT=63idc.INF_SIZEOF_LONG=64idc.INF_SIZEOF_LLONG=65idc.INF_SIZEOF_LDBL=66idc.INF_ABIBITS=67idc.INF_APPCALL_OPTIONS=68idc.get_inf_attr(attr)
Deprecated. Please ida_ida.inf_get_* instead.
idc.set_inf_attr(attr, value)
Deprecated. Please ida_ida.inf_set_* instead.
idc.set_processor_typeidc.SETPROC_IDBidc.SETPROC_LOADERidc.SETPROC_LOADER_NON_FATALidc.SETPROC_USERidc.SetPrcsr(processor)idc.get_processor_name()
Get name of the current processor :returns: processor name
idc.set_target_assembleridc.batch(batch)
Enable/disable batch mode of operation
Parameters:
batch – batch mode 0 - ida will display dialog boxes and wait for the user input 1 - ida will not display dialog boxes, warnings, etc.
Returns:
old balue of batch flag
idc.process_ui_action(name, flags=0)
Invokes an IDA UI action by name
Parameters:

-
name – Command name

-
flags – Reserved. Must be zero

Returns:
Boolean
idc.ask_segidc.ask_ynidc.msgidc.warningidc.erroridc.set_ida_stateidc.IDA_STATUS_READY=0idc.IDA_STATUS_THINKING=1idc.IDA_STATUS_WAITING=2idc.IDA_STATUS_WORK=3idc.refresh_idaview_anywayidc.refresh_listsidc.sel2para(sel)
Get a selector value
Parameters:
sel – the selector number
Returns:
selector value if found otherwise the input value (sel)

NOTE: selector values are always in paragraphs
idc.find_selector(val)
Find a selector which has the specified value
Parameters:
val – value to search for
Returns:
the selector number if found, otherwise the input value (val & 0xFFFF)

NOTE: selector values are always in paragraphs
idc.set_selectoridc.del_selectoridc.get_first_seg()
Get first segment
Returns:
address of the start of the first segment BADADDR - no segments are defined
idc.get_next_seg(ea)
Get next segment
Parameters:
ea – linear address
Returns:
start of the next segment BADADDR - no next segment
idc.get_segm_start(ea)
Get start address of a segment
Parameters:
ea – any address in the segment
Returns:
start of segment BADADDR - the specified address doesn’t belong to any segment
idc.get_segm_end(ea)
Get end address of a segment
Parameters:
ea – any address in the segment
Returns:
end of segment (an address past end of the segment) BADADDR - the specified address doesn’t belong to any segment
idc.get_segm_name(ea)
Get name of a segment
Parameters:
ea – any address in the segment
Returns:
“” - no segment at the specified address
idc.add_segm_ex(startea, endea, base, use32, align, comb, flags)
Create a new segment
Parameters:

-
startea – linear address of the start of the segment

-
endea – linear address of the end of the segment this address will not belong to the segment ‘endea’ should be higher than ‘startea’

-
base – base paragraph or selector of the segment. a paragraph is 16byte memory chunk. If a selector value is specified, the selector should be already defined.

-
use32 – 0: 16bit segment, 1: 32bit segment, 2: 64bit segment

-
align – segment alignment. see below for alignment values

-
comb – segment combination. see below for combination values.

-
flags – combination of ADDSEG_… bits

Returns:
0-failed, 1-ok
idc.ADDSEG_NOSREGidc.ADDSEG_OR_DIEidc.ADDSEG_NOTRUNCidc.ADDSEG_QUIETidc.ADDSEG_FILLGAPidc.ADDSEG_SPARSEidc.AddSeg(startea, endea, base, use32, align, comb)idc.del_segmidc.SEGMOD_KILLidc.SEGMOD_KEEPidc.SEGMOD_SILENTidc.set_segment_bounds(ea, startea, endea, flags)
Change segment boundaries
Parameters:

-
ea – any address in the segment

-
startea – new start address of the segment

-
endea – new end address of the segment

-
flags – combination of SEGMOD_… flags

Returns:
boolean success
idc.set_segm_name(ea, name)
Change name of the segment
Parameters:

-
ea – any address in the segment

-
name – new name of the segment

Returns:
success (boolean)
idc.set_segm_class(ea, segclass)
Change class of the segment
Parameters:

-
ea – any address in the segment

-
segclass – new class of the segment

Returns:
success (boolean)
idc.set_segm_alignment(ea, alignment)
Change alignment of the segment
Parameters:

-
ea – any address in the segment

-
alignment – new alignment of the segment (one of the sa… constants)

Returns:
success (boolean)
idc.saAbsidc.saRelByteidc.saRelWordidc.saRelParaidc.saRelPageidc.saRelDbleidc.saRel4Kidc.saGroupidc.saRel32Bytesidc.saRel64Bytesidc.saRelQwordidc.set_segm_combination(segea, comb)
Change combination of the segment
Parameters:

-
segea – any address in the segment

-
comb – new combination of the segment (one of the sc… constants)

Returns:
success (boolean)
idc.scPrividc.scPubidc.scPub2idc.scStackidc.scCommonidc.scPub3idc.set_segm_addressing(ea, bitness)
Change segment addressing
Parameters:

-
ea – any address in the segment

-
bitness – 0: 16bit, 1: 32bit, 2: 64bit

Returns:
success (boolean)
idc.selector_by_name(segname)
Get segment selector by name
Parameters:
segname – name of segment
Returns:
segment selector or BADADDR
idc.set_default_sreg_value(ea, reg, value)
Set default segment register value for a segment
Parameters:

-
ea – any address in the segment if no segment is present at the specified address then all segments will be affected

-
reg – name of segment register

-
value – default value of the segment register. -1-undefined.

idc.set_segm_type(segea, segtype)
Set segment type
Parameters:

-
segea – any address within segment

-
segtype – new segment type:

Returns:
!=0 - ok
idc.SEG_NORMidc.SEG_XTRNidc.SEG_CODEidc.SEG_DATAidc.SEG_IMPidc.SEG_GRPidc.SEG_NULLidc.SEG_UNDFidc.SEG_BSSidc.SEG_ABSSYMidc.SEG_COMMidc.SEG_IMEMidc.get_segm_attr(segea, attr)
Get segment attribute
Parameters:

-
segea – any address within segment

-
attr – one of SEGATTR_… constants

idc.set_segm_attr(segea, attr, value)
Set segment attribute
Parameters:

-
segea – any address within segment

-
attr – one of SEGATTR_… constants

NOTE: Please note that not all segment attributes are modifiable.
Also some of them should be modified using special functions like set_segm_addressing, etc.
idc.SEGATTR_START=0idc.SEGATTR_END=4idc.SEGATTR_ORGBASE=16idc.SEGATTR_ALIGN=20idc.SEGATTR_COMB=21idc.SEGATTR_PERM=22idc.SEGATTR_BITNESS=23idc.SEGATTR_FLAGS=24idc.SEGATTR_SEL=28idc.SEGATTR_ES=32idc.SEGATTR_CS=36idc.SEGATTR_SS=40idc.SEGATTR_DS=44idc.SEGATTR_FS=48idc.SEGATTR_GS=52idc.SEGATTR_TYPE=96idc.SEGATTR_COLOR=100idc.SEGATTR_START=0idc.SFL_COMORG=1idc.SFL_OBOK=2idc.SFL_HIDDEN=4idc.SFL_DEBUG=8idc.SFL_LOADER=16idc.SFL_HIDETYPE=32idc.move_segm(ea, to, flags)
Move a segment to a new address This function moves all information to the new address It fixes up address sensitive information in the kernel The total effect is equal to reloading the segment to the target address
Parameters:

-
ea – any address within the segment to move

-
to – new segment start address

-
flags – combination MFS_… constants

Returns:
MOVE_SEGM_… error code
idc.MSF_SILENT=1idc.MSF_NOFIX=2idc.MSF_LDKEEP=4idc.MSF_FIXONCE=8idc.MOVE_SEGM_OK=0idc.MOVE_SEGM_PARAM=-1idc.MOVE_SEGM_ROOM=-2idc.MOVE_SEGM_IDP=-3idc.MOVE_SEGM_CHUNK=-4idc.MOVE_SEGM_LOADER=-5idc.MOVE_SEGM_ODD=-6idc.MOVE_SEGM_ORPHANidc.MOVE_SEGM_DEBUGidc.MOVE_SEGM_SOURCEFILESidc.MOVE_SEGM_MAPPINGidc.MOVE_SEGM_INVALidc.rebase_programidc.set_storage_typeidc.STT_VA=0idc.STT_MM=1idc.fl_CF=16idc.fl_CN=17idc.fl_JF=18idc.fl_JN=19idc.fl_F=21idc.XREF_USER=32idc.add_crefidc.del_crefidc.get_first_cref_fromidc.get_next_cref_fromidc.get_first_cref_toidc.get_next_cref_toidc.get_first_fcref_fromidc.get_next_fcref_fromidc.get_first_fcref_toidc.get_next_fcref_toidc.dr_Oidc.dr_Widc.dr_Ridc.dr_Tidc.dr_Iidc.add_drefidc.del_drefidc.get_first_dref_fromidc.get_next_dref_fromidc.get_first_dref_toidc.get_next_dref_toidc.get_xref_type()
Return type of the last xref obtained by [RD]first/next[B0] functions.
Returns:
constants fl_* or dr_*
idc.fopen(f, mode)idc.fclose(handle)idc.filelength(handle)idc.fseek(handle, offset, origin)idc.ftell(handle)idc.LoadFile(filepath, pos, ea, size)
Load file into IDA database
Parameters:

-
filepath – path to input file

-
pos – position in the file

-
ea – linear address to load

-
size – number of bytes to load

Returns:
0 - error, 1 - ok
idc.loadfile(filepath, pos, ea, size)idc.SaveFile(filepath, pos, ea, size)
Save from IDA database to file
Parameters:

-
filepath – path to output file

-
pos – position in the file

-
ea – linear address to save from

-
size – number of bytes to save

Returns:
0 - error, 1 - ok
idc.savefile(filepath, pos, ea, size)idc.fgetc(handle)idc.fputc(byte, handle)idc.fprintf(handle, format, *args)idc.readshort(handle, mostfirst)idc.readlong(handle, mostfirst)idc.writeshort(handle, word, mostfirst)idc.writelong(handle, dword, mostfirst)idc.readstr(handle)idc.writestr(handle, s)idc.add_funcidc.del_funcidc.set_func_endidc.get_next_func(ea)
Find next function
Parameters:
ea – any address belonging to the function
Returns:
BADADDR - no more functions otherwise returns the next function start address
idc.get_prev_func(ea)
Find previous function
Parameters:
ea – any address belonging to the function
Returns:
BADADDR - no more functions otherwise returns the previous function start address
idc.get_func_attr(ea, attr)
Get a function attribute
Parameters:

-
ea – any address belonging to the function

-
attr – one of FUNCATTR_… constants

Returns:
BADADDR - error otherwise returns the attribute value
idc.set_func_attr(ea, attr, value)
Set a function attribute
Parameters:

-
ea – any address belonging to the function

-
attr – one of FUNCATTR_… constants

-
value – new value of the attribute

Returns:
1-ok, 0-failed
idc.FUNCATTR_START=0idc.FUNCATTR_END=4idc.FUNCATTR_FLAGS=8idc.FUNCATTR_FRAME=16idc.FUNCATTR_FRSIZE=20idc.FUNCATTR_FRREGS=24idc.FUNCATTR_ARGSIZE=28idc.FUNCATTR_FPD=32idc.FUNCATTR_COLOR=36idc.FUNCATTR_OWNER=16idc.FUNCATTR_REFQTY=20idc.FUNCATTR_START=0idc.get_func_flags(ea)
Retrieve function flags
Parameters:
ea – any address belonging to the function
Returns:
-1 - function doesn’t exist otherwise returns the flags
idc.FUNC_NORETidc.FUNC_FARidc.FUNC_LIBidc.FUNC_STATICidc.FUNC_FRAMEidc.FUNC_USERFARidc.FUNC_HIDDENidc.FUNC_THUNKidc.FUNC_BOTTOMBPidc.FUNC_NORET_PENDINGidc.FUNC_SP_READYidc.FUNC_PURGED_OKidc.FUNC_TAILidc.FUNC_LUMINAidc.FUNC_OUTLINEidc.set_func_flags(ea, flags)
Change function flags
Parameters:

-
ea – any address belonging to the function

-
flags – see get_func_flags() for explanations

Returns:
!=0 - ok
idc.get_func_name(ea)
Retrieve function name
Parameters:
ea – any address belonging to the function
Returns:
null string - function doesn’t exist otherwise returns function name
idc.get_func_cmt(ea, repeatable)
Retrieve function comment
Parameters:

-
ea – any address belonging to the function

-
repeatable – 1: get repeatable comment 0: get regular comment

Returns:
function comment string
idc.set_func_cmt(ea, cmt, repeatable)
Set function comment
Parameters:

-
ea – any address belonging to the function

-
cmt – a function comment line

-
repeatable – 1: get repeatable comment 0: get regular comment

idc.choose_func(title)
Ask the user to select a function

Arguments:
Parameters:
title – title of the dialog box
Returns:
-1 - user refused to select a function otherwise returns the selected function start address
idc.get_func_off_str(ea)
Convert address to ‘funcname+offset’ string
Parameters:
ea – address to convert
Returns:
if the address belongs to a function then return a string formed as ‘name+offset’ where ‘name’ is a function name ‘offset’ is offset within the function else return null string
idc.find_func_end(ea)
Determine a new function boundaries
Parameters:
ea – starting address of a new function
Returns:
if a function already exists, then return its end address. If a function end cannot be determined, the return BADADDR otherwise return the end address of the new function
idc.get_frame_id(ea)
Get ID of function frame structure
Parameters:
ea – any address belonging to the function
Returns:
ID of function frame or None In order to access stack variables you need to use structure member manipulaion functions with the obtained ID.
idc.get_frame_lvar_size(ea)
Get size of local variables in function frame
Parameters:
ea – any address belonging to the function
Returns:
Size of local variables in bytes. If the function doesn’t have a frame, return 0 If the function doesn’t exist, return None
idc.get_frame_regs_size(ea)
Get size of saved registers in function frame
Parameters:
ea – any address belonging to the function
Returns:
Size of saved registers in bytes. If the function doesn’t have a frame, return 0 This value is used as offset for BP (if FUNC_FRAME is set) If the function doesn’t exist, return None
idc.get_frame_args_size(ea)
Get size of arguments in function frame which are purged upon return
Parameters:
ea – any address belonging to the function
Returns:
Size of function arguments in bytes. If the function doesn’t have a frame, return 0 If the function doesn’t exist, return -1
idc.get_frame_size(ea)
Get full size of function frame
Parameters:
ea – any address belonging to the function
Returns:
Size of function frame in bytes. This function takes into account size of local variables + size of saved registers + size of return address + size of function arguments If the function doesn’t have a frame, return size of function return address in the stack. If the function doesn’t exist, return 0
idc.set_frame_size(ea, lvsize, frregs, argsize)
Make function frame
Parameters:

-
ea – any address belonging to the function

-
lvsize – size of function local variables

-
frregs – size of saved registers

-
argsize – size of function arguments

Returns:
ID of function frame or -1 If the function did not have a frame, the frame will be created. Otherwise the frame will be modified
idc.get_spd(ea)
Get current delta for the stack pointer
Parameters:
ea – end address of the instruction i.e.the last address of the instruction+1
Returns:
The difference between the original SP upon entering the function and SP for the specified address
idc.get_sp_delta(ea)
Get modification of SP made by the instruction
Parameters:
ea – end address of the instruction i.e.the last address of the instruction+1
Returns:
Get modification of SP made at the specified location If the specified location doesn’t contain a SP change point, return 0 Otherwise return delta of SP modification
idc.get_fchunk_attr(ea, attr)
Get a function chunk attribute
Parameters:

-
ea – any address in the chunk

-
attr – one of: FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER, FUNCATTR_REFQTY

Returns:
desired attribute or -1
idc.set_fchunk_attr(ea, attr, value)
Set a function chunk attribute
Parameters:

-
ea – any address in the chunk

-
attr – only FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER

-
value – desired value

Returns:
0 if failed, 1 if success
idc.get_fchunk_refereridc.get_next_fchunk(ea)
Get next function chunk
Parameters:
ea – any address
Returns:
the starting address of the next function chunk or BADADDR

NOTE: This function enumerates all chunks of all functions in the database
idc.get_prev_fchunk(ea)
Get previous function chunk
Parameters:
ea – any address
Returns:
the starting address of the function chunk or BADADDR

NOTE: This function enumerates all chunks of all functions in the database
idc.append_func_tail(funcea, ea1, ea2)
Append a function chunk to the function
Parameters:

-
funcea – any address in the function

-
ea1 – start of function tail

-
ea2 – end of function tail

Returns:
0 if failed, 1 if success
NOTE: If a chunk exists at the specified addresses, it must have exactly
the specified boundaries
idc.remove_fchunk(funcea, tailea)
Remove a function chunk from the function
Parameters:

-
funcea – any address in the function

-
tailea – any address in the function chunk to remove

Returns:
0 if failed, 1 if success
idc.set_tail_owner(tailea, funcea)
Change the function chunk owner
Parameters:

-
tailea – any address in the function chunk

-
funcea – the starting address of the new owner

Returns:
False if failed, True if success

NOTE: The new owner must already have the chunk appended before the call
idc.first_func_chunk(funcea)
Get the first function chunk of the specified function
Parameters:
funcea – any address in the function
Returns:
the function entry point or BADADDR

NOTE: This function returns the first (main) chunk of the specified function
idc.next_func_chunk(funcea, tailea)
Get the next function chunk of the specified function
Parameters:

-
funcea – any address in the function

-
tailea – any address in the current chunk

Returns:
the starting address of the next function chunk or BADADDR

NOTE: This function returns the next chunk of the specified function
idc.add_auto_stkpnt(func_ea, ea, delta)
Add automatic SP register change point :param func_ea: function start :param ea: linear address where SP changes

usually this is the end of the instruction which modifies the stack pointer (insn.ea+insn.size)

Parameters:
delta – difference between old and new values of SP
Returns:
1-ok, 0-failed
idc.add_user_stkpntidc.del_stkpnt(func_ea, ea)
Delete SP register change point
Parameters:

-
func_ea – function start

-
ea – linear address

Returns:
1-ok, 0-failed
idc.get_min_spd_ea(func_ea)
Return the address with the minimal spd (stack pointer delta) If there are no SP change points, then return BADADDR.
Parameters:
func_ea – function start
Returns:
BADDADDR - no such function
idc.recalc_spdidc.get_entry_qtyidc.add_entryidc.get_entry_ordinalidc.get_entryidc.get_entry_nameidc.rename_entryidc.get_next_fixup_eaidc.get_prev_fixup_eaidc.get_fixup_target_type(ea)
Get fixup target type
Parameters:
ea – address to get information about
Returns:
0 - no fixup at the specified address otherwise returns fixup type
idc.FIXUP_OFF8=13idc.FIXUP_OFF16=1idc.FIXUP_SEG16=2idc.FIXUP_PTR32=3idc.FIXUP_OFF32=4idc.FIXUP_PTR48=5idc.FIXUP_HI8=6idc.FIXUP_HI16=7idc.FIXUP_LOW8=8idc.FIXUP_LOW16=9idc.FIXUP_OFF64=12idc.FIXUP_CUSTOM=32768idc.get_fixup_target_flags(ea)
Get fixup target flags
Parameters:
ea – address to get information about
Returns:
0 - no fixup at the specified address otherwise returns fixup target flags
idc.FIXUPF_REL=1idc.FIXUPF_EXTDEF=2idc.FIXUPF_UNUSED=4idc.FIXUPF_CREATED=8idc.get_fixup_target_sel(ea)
Get fixup target selector
Parameters:
ea – address to get information about
Returns:
BADSEL - no fixup at the specified address otherwise returns fixup target selector
idc.get_fixup_target_off(ea)
Get fixup target offset
Parameters:
ea – address to get information about
Returns:
BADADDR - no fixup at the specified address otherwise returns fixup target offset
idc.get_fixup_target_dis(ea)
Get fixup target displacement
Parameters:
ea – address to get information about
Returns:
0 - no fixup at the specified address otherwise returns fixup target displacement
idc.set_fixup(ea, fixuptype, fixupflags, targetsel, targetoff, displ)
Set fixup information
Parameters:

-
ea – address to set fixup information about

-
fixuptype – fixup type. see get_fixup_target_type() for possible fixup types.

-
fixupflags – fixup flags. see get_fixup_target_flags() for possible fixup types.

-
targetsel – target selector

-
targetoff – target offset

-
displ – displacement

Returns:
none
idc.del_fixupidc.put_bookmarkidc.get_bookmarkidc.get_bookmark_descidc.get_struc_id(name)idc.get_struc_name(tid)idc.get_struc_cmt(tid)idc.get_struc_size(tid)idc.get_member_qty(sid)
Get number of members of a structure
Parameters:
sid – structure type ID
Returns:
-1 if bad structure type ID is passed otherwise returns number of members.
idc.get_member_by_idx(sid, idx)
Get member ID by member ordinal number
Parameters:

-
sid – structure type ID

-
idx – member ordinal number

Returns:
-1 if bad structure type ID is passed or there is no member with the specified index otherwise returns the member ID.
idc.is_member_id(sid)
Is a member id?
Parameters:
sid – structure type ID
Returns:
True there is structure member with the specified ID False otherwise
idc.get_member_id(sid, member_offset)Parameters:
sid – structure type ID

:param member_offset:. The offset can be any offset in the member. For example, is a member is 4 bytes long and starts at offset 2, then 2,3,4,5 denote the same structure member.
Returns:
-1 if bad structure type ID is passed or there is

no member at the specified offset. otherwise returns the member id.
idc.get_member_offset(sid, member_name)
Get offset of a member of a structure by the member name
Parameters:

-
sid – structure type ID

-
member_name – name of structure member

Returns:
-1 if bad structure type ID is passed or no such member in the structure otherwise returns offset of the specified member.
NOTE: Union members are, in IDA’s internals, located
at subsequent byte offsets: member 0 -> offset 0x0, member 1 -> offset 0x1, etc…
idc.get_member_name(sid, member_offset)
Get name of a member of a structure
Parameters:

-
sid – structure type ID

-
member_offset – member offset. The offset can be any offset in the member. For example, is a member is 4 bytes long and starts at offset 2, then 2,3,4,5 denote the same structure member.

Returns:
None if bad structure type ID is passed or no such member in the structure otherwise returns name of the specified member.
idc.get_member_cmt(sid, member_offset, repeatable=True)
Get comment of a member
Parameters:

-
sid – structure type ID

-
member_offset – member offset. The offset can be any offset in the member. For example, is a member is 4 bytes long and starts at offset 2, then 2,3,4,5 denote the same structure member.

-
repeatable – is not used anymore

Returns:
None if bad structure type ID is passed or no such member in the structure otherwise returns comment of the specified member.
idc.get_member_size(sid, member_offset)
Get size of a member
Parameters:

-
sid – structure type ID

-
member_offset – member offset. The offset can be any offset in the member. For example, is a member is 4 bytes long and starts at offset 2, then 2,3,4,5 denote the same structure member.

Returns:
None if bad structure type ID is passed, or no such member in the structure otherwise returns size of the specified member in bytes.
idc.get_member_strid(sid, member_offset)
Get structure id of a member
Parameters:

-
sid – structure type ID

-
member_offset – member offset. The offset can be any offset in the member. For example, is a member is 4 bytes long and starts at offset 2, then 2,3,4,5 denote the same structure member.

Returns:
-1 if bad structure type ID is passed or no such member in the structure otherwise returns structure id of the member. If the current member is not a structure, returns -1.
idc.is_union(sid)
Is a structure a union?
Parameters:
sid – structure type ID
Returns:
True: yes, this is a union id False: no

NOTE: Unions are a special kind of structures
idc.add_struc(index, name, is_union)
Define a new structure type
Parameters:

-
index – -1

-
name – name of the new structure type.

-
is_union – 0: structure 1: union

Returns:
-1 if can’t define structure type because of bad structure name: the name is ill-formed or is already used in the program. otherwise returns ID of the new structure type
idc.del_struc(sid)
Delete a structure type
Parameters:
sid – structure type ID
Returns:
0 if bad structure type ID is passed 1 otherwise the structure type is deleted. All data and other structure types referencing to the deleted structure type will be displayed as array of bytes.
idc.set_struc_name(sid, name)idc.set_struc_cmt(sid, cmt, repeatable=True)idc.add_struc_member(sid, name, offset, flag, typeid, nbytes, target=-1, tdelta=0, reftype=REF_OFF32)
Add structure member
Parameters:

-
sid – structure type ID

-
name – name of the new member

-
offset – offset of the new member -1 means to add at the end of the structure

-
flag – type of the new member. Should be one of FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA

-
typeid – if is_struct(flag) then typeid specifies the structure id for the member if is_off0(flag) then typeid specifies the offset base. if is_strlit(flag) then typeid specifies the string type (STRTYPE_…). if is_stroff(flag) then typeid specifies the structure id if is_enum(flag) then typeid specifies the enum id if is_custom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16) Otherwise typeid should be -1.

-
nbytes – number of bytes in the new member

-
target – target address of the offset expr. You may specify it as -1, ida will calculate it itself

-
tdelta – offset target delta. usually 0

-
reftype – see REF_… definitions

NOTE: The remaining arguments are allowed only if is_off0(flag) and you want
to specify a complex offset expression
Returns:
0 - ok, otherwise error code (one of typeinf.TERR_*)
idc.del_struc_member(sid, member_offset)
Delete structure member
Parameters:

-
sid – structure type ID

-
member_offset – offset of the member

Returns:
!= 0 - ok.
NOTE: IDA allows ‘holes’ between members of a
structure. It treats these ‘holes’ as unnamed arrays of bytes.
idc.set_member_name(sid, member_offset, name)
Change structure member name
Parameters:

-
sid – structure type ID

-
member_offset – offset of the member

-
name – new name of the member

Returns:
!= 0 - ok.
idc.set_member_type(sid, member_offset, flag, typeid, nitems, target=-1, tdelta=0, reftype=REF_OFF32)
Change structure member type
Parameters:

-
sid – structure type ID

-
member_offset – offset of the member

-
flag – new type of the member. Should be one of FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA

-
typeid – if is_struct(flag) then typeid specifies the structure id for the member if is_off0(flag) then typeid specifies the offset base. if is_strlit(flag) then typeid specifies the string type (STRTYPE_…). if is_stroff(flag) then typeid specifies the structure id if is_enum(flag) then typeid specifies the enum id if is_custom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16) Otherwise typeid should be -1.

-
nitems – number of items in the member

-
target – target address of the offset expr. You may specify it as -1, ida will calculate it itself

-
tdelta – offset target delta. usually 0

-
reftype – see REF_… definitions

NOTE: The remaining arguments are allowed only if is_off0(flag) and you want
to specify a complex offset expression
Returns:
!=0 - ok.
idc.set_member_cmt(sid, member_offset, comment, repeatable)
Change structure member comment
Parameters:

-
sid – structure type ID

-
member_offset – offset of the member

-
comment – new comment of the structure member

-
repeatable – 1: change repeatable comment 0: change regular comment

Returns:
!= 0 - ok
idc.expand_struc(sid, offset, delta, recalc=True)
Expand or shrink a structure type :param id: structure type ID :param offset: offset in the structure :param delta: how many bytes to add or remove :param recalc: is not used anymore :returns: True if ok, False on error
idc.ENFL_REGEX=1idc.get_enum(name)
Get enum by name
Parameters:
name – enum type name
Returns:
enum type TID or BADADDR
idc.get_enum_name(enum_id, flags=0)
Get name of enum
Parameters:

-
enum_id – enum TID

-
flags – use ENFL_REGEX to beautify the name

Returns:
enum name or None
idc.get_enum_cmt(enum_id)
Get enum comment
Parameters:
enum_id – enum TID
Returns:
enum comment
idc.get_enum_size(enum_id)
Get the number of the members of the enum
Parameters:
enum_id – enum TID
Returns:
number of members
idc.get_enum_width(enum_id)
Get the width of a enum element allowed values: 0 (unspecified),1,2,4,8,16,32,64
Parameters:
enum_id – enum TID
Returns:
enum width or -1 in case of error
idc.get_enum_flag(enum_id)
Get flags determining the representation of the enum. (currently they define the numeric base: octal, decimal, hex, bin) and signness.
Parameters:
enum_id – enum TID
Returns:
flag of 0
idc.get_enum_member_by_name(name)
Get a reference to an enum member by its name
Parameters:
name – enum member name
Returns:
enum member TID or BADADDR
idc.get_enum_member_enum(const_id)
Get the parent enum of an enum member
Parameters:
const_id – id of const
Returns:
enum TID or BADADDR
idc.get_enum_member(enum_id, value, serial, bmask)
Get id of constant
Parameters:

-
enum_id – id of enum

-
value – value of constant

-
serial – serial number of the constant in the enumeration. See op_enum() for details.

-
bmask – bitmask of the constant ordinary enums accept only -1 as a bitmask

Returns:
id of constant or -1 if error
idc.get_first_bmask(enum_id)
Get first bitmask in the enum
Parameters:
enum_id – id of enum
Returns:
id of constant or -1 if error
idc.get_last_bmask(enum_id)
Get last bitmask in the enum
Parameters:
enum_id – id of enum
Returns:
id of constant or -1 if error
idc.get_next_bmask(enum_id, bmask)
Get next bitmask in the enum
Parameters:
enum_id – id of enum

:param bmask
Returns:
id of constant or -1 if error
idc.get_prev_bmask(enum_id, bmask)
Get prev bitmask in the enum
Parameters:
enum_id – id of enum

:param bmask
Returns:
id of constant or -1 if error
idc.get_bmask_name(enum_id, bmask)
Get bitmask name (only for bitfields)
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant

Returns:
name of bitmask or None
idc.get_bmask_cmt(enum_id, bmask, repeatable)
Get bitmask comment (only for bitfields)
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant

-
repeatable – type of comment, 0-regular, 1-repeatable

Returns:
comment attached to bitmask or None
idc.set_bmask_name(enum_id, bmask, name)
Set bitmask name (only for bitfields)
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant

-
name – name of bitmask

Returns:
True-ok, False-failed
idc.set_bmask_cmt(enum_id, bmask, cmt, repeatable)
Set bitmask comment (only for bitfields)
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant

-
cmt – comment

repeatable - is not used anymore
Returns:
1-ok, 0-failed
idc.get_first_enum_member(enum_id, bmask=-1)
Get first constant in the enum
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant (ordinary enums accept only -1 as a bitmask)

Returns:
value of constant or -1 if no constants are defined All constants are sorted by their values as unsigned longs.
idc.get_last_enum_member(enum_id, bmask=-1)
Get last constant in the enum
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant (ordinary enums accept only -1 as a bitmask)

Returns:
value of constant or -1 if no constants are defined All constants are sorted by their values as unsigned longs.
idc.get_next_enum_member(enum_id, value, bmask=-1)
Get next constant in the enum
Parameters:

-
enum_id – id of enum

-
bmask – bitmask of the constant ordinary enums accept only -1 as a bitmask

-
value – value of the current constant

Returns:
value of a constant with value higher than the specified value. -1 if no such constants exist. All constants are sorted by their values as unsigned longs.
idc.get_prev_enum_member(enum_id, value, bmask=-1)
Get prev constant in the enum
Parameters:
enum_id – id of enum
:param bmaskbitmask of the constant
ordinary enums accept only -1 as a bitmask
Parameters:
value – value of the current constant
Returns:
value of a constant with value lower than the specified value. -1 if no such constants exist. All constants are sorted by their values as unsigned longs.
idc.get_enum_member_name(const_id)
Get name of a constant
Parameters:
const_id – id of const

Returns: name of constant
idc.get_enum_member_cmt(const_id, repeatable=True)
Get comment of a constant
Parameters:

-
const_id – id of const

-
repeatable – not used anymore

Returns:
comment string
idc.get_enum_member_value(const_id)
Get value of an enum member
Parameters:
const_id – id of const
Returns:
member value or None
idc.get_enum_member_bmask(const_id)
Get bitmask of an enum member
Parameters:
const_id – id of const
Returns:
member value or None
idc.add_enum(idx, name, flag)
Add a new enum type
Parameters:

-
idx – is not used anymore

-
name – name of the enum.

-
flag – flags for representation of numeric constants in the definition of enum.

Returns:
id of new enum or BADADDR
idc.del_enum(enum_id)
Delete an enum type
Parameters:
enum_id – id of enum
Returns:
success
idc.set_enum_name(enum_id, name)
Set name of enum type
Parameters:

-
enum_id – id of enum

-
name – new enum name

Returns:
1-ok, 0-failed
idc.set_enum_flag(enum_id, flag)
Set enum constant representation flags
Parameters:
enum_id – enum TID

:param flag
Returns:
success
idc.set_enum_width(enum_id, nbytes)
Set the width of enum base type
Parameters:

-
enum_id – enum TID

-
nbytes – width of enum base type, allowed values: 0 (unspecified),1,2,4,8,16,32,64

Returns:
success
idc.is_bf(enum_id)
Is enum a bitmask ?
Parameters:
enum_id – enum TID
Returns:
if it is a bitmask enum return True, otherwise False
idc.set_enum_bf(enum_id, bf)
Set or clear the ‘bitmask’ attribute of an enum
Parameters:

-
enum_id – enum TID

-
bf – bitmask enum or not

Returns:
success
idc.set_enum_cmt(enum_id, cmt, repeatable)
Set comment for enum type
Parameters:

-
enum_id – enum TID

-
cmt – comment

-
repeatable – is comment repeatable ?

Returns:
1-ok, 0-failed
idc.add_enum_member(enum_id, name, value, bmask=-1)
Add a member of enum - a symbolic constant
Parameters:

-
enum_id – id of enum

-
name – name of symbolic constant. Must be unique in the program.

-
value – value of symbolic constant.

-
bmask – bitmask of the constant ordinary enums accept only -1 as a bitmask all bits set in value should be set in bmask too

Returns:
0-ok, otherwise error code (one of ENUM_MEMBER_ERROR_*)
idc.del_enum_member(enum_id, value, serial, bmask=-1)
Delete a member of enum - a symbolic constant
Parameters:

-
enum_id – id of enum

-
value – value of symbolic constant.

-
serial – serial number of the constant in the enumeration. See op_enum() for for details.

-
bmask – bitmask of the constant ordinary enums accept only -1 as a bitmask

Returns:
1-ok, 0-failed
idc.set_enum_member_name(const_id, name)
Set name of enum member
Parameters:

-
const_id – enum constant TID

-
name – new member name

Returns:
1-ok, 0-failed
idc.set_enum_member_cmt(const_id, cmt, repeatable=False)
Set comment for enum member
Parameters:

-
const_id – enum constant TID

-
cmt – comment

-
repeatable – is not used anymore

Returns:
1-ok, 0-failed
idc.AR_LONG
Array of longs
idc.AR_STR
Array of strings
idc.create_array(name)
Create array.
Parameters:
name – The array name.
Returns:
-1 in case of failure, a valid array_id otherwise.
idc.get_array_id(name)
Get array array_id, by name.
Parameters:
name – The array name.
Returns:
-1 in case of failure (i.e., no array with that name exists), a valid array_id otherwise.
idc.rename_array(array_id, newname)
Rename array, by its ID.
Parameters:

-
id – The ID of the array to rename.

-
newname – The new name of the array.

Returns:
1 in case of success, 0 otherwise
idc.delete_array(array_id)
Delete array, by its ID.
Parameters:
array_id – The ID of the array to delete.
idc.set_array_long(array_id, idx, value)
Sets the long value of an array element.
Parameters:

-
array_id – The array ID.

-
idx – Index of an element.

-
value – 32bit or 64bit value to store in the array

Returns:
1 in case of success, 0 otherwise
idc.set_array_string(array_id, idx, value)
Sets the string value of an array element.
Parameters:

-
array_id – The array ID.

-
idx – Index of an element.

-
value – String value to store in the array

Returns:
1 in case of success, 0 otherwise
idc.get_array_element(tag, array_id, idx)
Get value of array element.
Parameters:

-
tag – Tag of array, specifies one of two array types: AR_LONG, AR_STR

-
array_id – The array ID.

-
idx – Index of an element.

Returns:
Value of the specified array element. Note that this function may return char or long result. Unexistent array elements give zero as a result.
idc.del_array_element(tag, array_id, idx)
Delete an array element.
Parameters:

-
tag – Tag of array, specifies one of two array types: AR_LONG, AR_STR

-
array_id – The array ID.

-
idx – Index of an element.

Returns:
1 in case of success, 0 otherwise.
idc.get_first_index(tag, array_id)
Get index of the first existing array element.
Parameters:

-
tag – Tag of array, specifies one of two array types: AR_LONG, AR_STR

-
array_id – The array ID.

Returns:
-1 if the array is empty, otherwise index of first array element of given type.
idc.get_last_index(tag, array_id)
Get index of last existing array element.
Parameters:

-
tag – Tag of array, specifies one of two array types: AR_LONG, AR_STR

-
array_id – The array ID.

Returns:
-1 if the array is empty, otherwise index of first array element of given type.
idc.get_next_index(tag, array_id, idx)
Get index of the next existing array element.
Parameters:

-
tag – Tag of array, specifies one of two array types: AR_LONG, AR_STR

-
array_id – The array ID.

-
idx – Index of the current element.

Returns:
-1 if no more elements, otherwise returns index of the next array element of given type.
idc.get_prev_index(tag, array_id, idx)
Get index of the previous existing array element.
Parameters:

-
tag – Tag of array, specifies one of two array types: AR_LONG, AR_STR

-
array_id – The array ID.

-
idx – Index of the current element.

Returns:
-1 if no more elements, otherwise returns index of the previous array element of given type.
idc.set_hash_long(hash_id, key, value)
Sets the long value of a hash element.
Parameters:

-
hash_id – The hash ID.

-
key – Key of an element.

-
value – 32bit or 64bit value to store in the hash

Returns:
1 in case of success, 0 otherwise
idc.get_hash_long(hash_id, key)
Gets the long value of a hash element.
Parameters:

-
hash_id – The hash ID.

-
key – Key of an element.

Returns:
the 32bit or 64bit value of the element, or 0 if no such element.
idc.set_hash_string(hash_id, key, value)
Sets the string value of a hash element.
Parameters:

-
hash_id – The hash ID.

-
key – Key of an element.

-
value – string value to store in the hash

Returns:
1 in case of success, 0 otherwise
idc.get_hash_string(hash_id, key)
Gets the string value of a hash element.
Parameters:

-
hash_id – The hash ID.

-
key – Key of an element.

Returns:
the string value of the element, or None if no such element.
idc.del_hash_string(hash_id, key)
Delete a hash element.
Parameters:

-
hash_id – The hash ID.

-
key – Key of an element

Returns:
1 upon success, 0 otherwise.
idc.get_first_hash_key(hash_id)
Get the first key in the hash.
Parameters:
hash_id – The hash ID.
Returns:
the key, 0 otherwise.
idc.get_last_hash_key(hash_id)
Get the last key in the hash.
Parameters:
hash_id – The hash ID.
Returns:
the key, 0 otherwise.
idc.get_next_hash_key(hash_id, key)
Get the next key in the hash.
Parameters:

-
hash_id – The hash ID.

-
key – The current key.

Returns:
the next key, 0 otherwise
idc.get_prev_hash_key(hash_id, key)
Get the previous key in the hash.
Parameters:

-
hash_id – The hash ID.

-
key – The current key.

Returns:
the previous key, 0 otherwise
idc.add_sourcefileidc.get_sourcefileidc.del_sourcefileidc.set_source_linnumidc.get_source_linnumidc.del_source_linnumidc.add_default_til(name)
Load a type library
Parameters:
name – name of type library.
Returns:
1-ok, 0-failed.
idc.import_type(idx, type_name)
Copy information from type library to database Copy structure, union, or enum definition from the type library to the IDA database.
Parameters:

-
idx – -1, ignored

-
type_name – name of type to copy

Returns:
BADNODE-failed, otherwise the type id (structure id or enum id)
idc.get_type(ea)
Get type of function/variable
Parameters:
ea – the address of the object
Returns:
type string or None if failed
idc.sizeof(typestr)
Returns the size of the type. It is equivalent to IDC’s sizeof(). :param typestr: can be specified as a typeinfo tuple (e.g. the result of get_tinfo()),

serialized type byte string, or a string with C declaration (e.g. “int”)

Returns:
-1 if typestring is not valid or has no size. otherwise size of the type
idc.SizeOfidc.get_tinfo(ea)
Get type information of function/variable as ‘typeinfo’ object
Parameters:
ea – the address of the object
Returns:
None on failure, or (type, fields) tuple.
idc.get_local_tinfo(ordinal)
Get local type information as ‘typeinfo’ object
Parameters:
ordinal – slot number (1…NumberOfLocalTypes)
Returns:
None on failure, or (type, fields) tuple.
idc.guess_type(ea)
Guess type of function/variable
Parameters:
ea – the address of the object, can be the structure member id too
Returns:
type string or None if failed
idc.TINFO_GUESSED=0idc.TINFO_DEFINITE=1idc.TINFO_DELAYFUNC=2idc.apply_type(ea, py_type, flags=TINFO_DEFINITE)
Apply the specified type to the address
Parameters:

-
ea – the address of the object

-
py_type – typeinfo tuple (type, fields) as get_tinfo() returns
or tuple (name, type, fields) as parse_decl() returns or None

if specified as None, then the item associated with ‘ea’ will be deleted.

-
flags – combination of TINFO_… constants or 0

Returns:
Boolean
idc.PT_SILidc.PT_NDCidc.PT_TYPidc.PT_VARidc.PT_PACKMASKidc.PT_HIGHidc.PT_LOWERidc.PT_REPLACEidc.PT_RAWARGSidc.PT_SILENTidc.PT_PAKDEF=0idc.PT_PAK1=16idc.PT_PAK2=32idc.PT_PAK4=48idc.PT_PAK8=64idc.PT_PAK16=80idc.PT_FILE=65536idc.PT_STANDALONEidc.SetType(ea, newtype)
Set type of function/variable
Parameters:

-
ea – the address of the object

-
newtype – the type string in C declaration form. Must contain the closing ‘;’ if specified as an empty string, then the item associated with ‘ea’ will be deleted.

Returns:
1-ok, 0-failed.
idc.parse_decl(inputtype, flags)
Parse type declaration
Parameters:

-
inputtype – file name or C declarations (depending on the flags)

-
flags – combination of PT_… constants or 0

Returns:
None on failure or (name, type, fields) tuple
idc.parse_decls(inputtype, flags=0)
Parse type declarations
Parameters:

-
inputtype – file name or C declarations (depending on the flags)

-
flags – combination of PT_… constants or 0

Returns:
number of parsing errors (0 no errors)
idc.print_decls(ordinals, flags)
Print types in a format suitable for use in a header file
Parameters:

-
ordinals – comma-separated list of type ordinals

-
flags – combination of PDF_… constants or 0

Returns:
string containing the type definitions
idc.PDF_INCL_DEPS=1idc.PDF_DEF_FWD=2idc.PDF_DEF_BASE=4idc.PDF_HEADER_CMT=8idc.get_ordinal_limit()
Get number of local types + 1
Returns:
value >= 1. 1 means that there are no local types.
idc.set_local_type(ordinal, input, flags)
Parse one type declaration and store it in the specified slot
Parameters:

-
ordinal – slot number (1…NumberOfLocalTypes) -1 means allocate new slot or reuse the slot of the existing named type

-
input – C declaration. Empty input empties the slot

-
flags – combination of PT_… constants or 0

Returns:
slot number or 0 if error
idc.GetLocalType(ordinal, flags)
Retrieve a local type declaration :param flags: any of PRTYPE_* constants :returns: local type as a C declaration or “”
idc.PRTYPE_1LINE=0idc.PRTYPE_MULTI=1idc.PRTYPE_TYPE=2idc.PRTYPE_PRAGMA=4idc.PRTYPE_SEMI=8idc.PRTYPE_CPP=16idc.PRTYPE_DEF=32idc.PRTYPE_NOARGS=64idc.PRTYPE_NOARRS=128idc.PRTYPE_NORES=256idc.PRTYPE_RESTORE=512idc.PRTYPE_NOREGEX=1024idc.PRTYPE_COLORED=2048idc.PRTYPE_METHODS=4096idc.PRTYPE_1LINCMT=8192idc.get_numbered_type_name(ordinal)
Retrieve a local type name
Parameters:
ordinal – slot number (1…NumberOfLocalTypes)

returns: local type name or None
idc.add_hidden_rangeidc.update_hidden_range(ea, visible)
Set hidden range state
Parameters:

-
ea – any address belonging to the hidden range

-
visible – new state of the range

Returns:
!= 0 - ok
idc.del_hidden_rangeidc.load_debuggeridc.start_processidc.exit_processidc.suspend_processidc.get_processesidc.attach_processidc.detach_processidc.get_thread_qtyidc.getn_threadidc.get_current_threadidc.getn_thread_nameidc.select_threadidc.suspend_threadidc.resume_threadidc.get_first_module()
Enumerate process modules
Returns:
first module’s base address or None on failure
idc.get_next_module(base)
Enumerate process modules
Parameters:
base – previous module’s base address
Returns:
next module’s base address or None on failure
idc.get_module_name(base)
Get process module name
Parameters:
base – the base address of the module
Returns:
required info or None
idc.get_module_size(base)
Get process module size
Parameters:
base – the base address of the module
Returns:
required info or -1
idc.step_intoidc.step_overidc.run_toidc.step_until_retidc.wait_for_next_eventidc.resume_process()idc.send_dbg_command(cmd)
Sends a command to the debugger module and returns the output string. An exception will be raised if the debugger is not running or the current debugger does not export the ‘send_dbg_command’ IDC command.
idc.WFNE_ANY=1idc.WFNE_SUSP=2idc.WFNE_SILENT=4idc.WFNE_CONT=8idc.WFNE_NOWAIT=16idc.NOTASK=-2idc.DBG_ERROR=-1idc.DBG_TIMEOUT=0idc.PROCESS_STARTED=1idc.PROCESS_EXITED=2idc.THREAD_STARTED=4idc.THREAD_EXITED=8idc.BREAKPOINT=16idc.STEP=32idc.EXCEPTION=64idc.LIB_LOADED=128idc.LIB_UNLOADED=256idc.INFORMATION=512idc.PROCESS_ATTACHED=1024idc.PROCESS_DETACHED=2048idc.PROCESS_SUSPENDED=4096idc.refresh_debugger_memoryidc.take_memory_snapshotidc.get_process_stateidc.DSTATE_SUSP=-1idc.DSTATE_NOTASK=0idc.DSTATE_RUN=1idc.DSTATE_RUN_WAIT_ATTACH=2idc.DSTATE_RUN_WAIT_END=3
Get various information about the current debug event These functions are valid only when the current event exists (the process is in the suspended state)
idc.get_event_id()
Get ID of debug event
Returns:
event ID
idc.get_event_pid()
Get process ID for debug event
Returns:
process ID
idc.get_event_tid()
Get type ID for debug event
Returns:
type ID
idc.get_event_ea()
Get ea for debug event
Returns:
ea
idc.is_event_handled()
Is the debug event handled?
Returns:
boolean
idc.get_event_module_name()
Get module name for debug event
Returns:
module name
idc.get_event_module_base()
Get module base for debug event
Returns:
module base
idc.get_event_module_size()
Get module size for debug event
Returns:
module size
idc.get_event_exit_code()
Get exit code for debug event
Returns:
exit code for PROCESS_EXITED, THREAD_EXITED events
idc.get_event_info()
Get debug event info
Returns:
event info: for THREAD_STARTED (thread name) for LIB_UNLOADED (unloaded library name) for INFORMATION (message to display)
idc.get_event_bpt_hea()
Get hardware address for BREAKPOINT event
Returns:
hardware address
idc.get_event_exc_code()
Get exception code for EXCEPTION event
Returns:
exception code
idc.get_event_exc_ea()
Get address for EXCEPTION event
Returns:
adress of exception
idc.can_exc_continue()
Can it continue after EXCEPTION event?
Returns:
boolean
idc.get_event_exc_info()
Get info for EXCEPTION event
Returns:
info string
idc.set_debugger_optionsidc.DOPT_SEGM_MSGS=1idc.DOPT_START_BPT=2idc.DOPT_THREAD_MSGS=4idc.DOPT_THREAD_BPT=8idc.DOPT_BPT_MSGS=16idc.DOPT_LIB_MSGS=64idc.DOPT_LIB_BPT=128idc.DOPT_INFO_MSGS=256idc.DOPT_INFO_BPT=512idc.DOPT_REAL_MEMORY=1024idc.DOPT_REDO_STACK=2048idc.DOPT_ENTRY_BPT=4096idc.DOPT_EXCDLG=24576idc.EXCDLG_NEVER=0idc.EXCDLG_UNKNOWN=8192idc.EXCDLG_ALWAYS=24576idc.DOPT_LOAD_DINFO=32768idc.get_debugger_event_condidc.set_debugger_event_condidc.set_remote_debuggeridc.define_exceptionidc.EXC_BREAK=1idc.EXC_HANDLE=2idc.get_reg_valueidc.set_reg_value(value, name)
Set register value
Parameters:

-
name – the register name

-
value – new register value

NOTE: The debugger should be running
It is not necessary to use this function to set register values. A register name in the left side of an assignment will do too.
idc.get_bpt_qtyidc.get_bpt_ea(n)
Get breakpoint address
Parameters:
n – number of breakpoint, is in range 0..get_bpt_qty()-1
Returns:
address of the breakpoint or BADADDR
idc.get_bpt_attr(ea, bptattr)
Get the characteristics of a breakpoint
Parameters:

-
ea – any address in the breakpoint range

-
bptattr – the desired attribute code, one of BPTATTR_… constants

Returns:
the desired attribute value or -1
idc.BPTATTR_EA=1idc.BPTATTR_SIZE=2idc.BPTATTR_TYPE=3idc.BPT_WRITE=1idc.BPT_RDWR=3idc.BPT_SOFT=4idc.BPT_EXEC=8idc.BPT_DEFAULT=12idc.BPTATTR_COUNT=4idc.BPTATTR_FLAGS=5idc.BPT_BRK=1idc.BPT_TRACE=2idc.BPT_UPDMEM=4idc.BPT_ENABLED=8idc.BPT_LOWCND=16idc.BPT_TRACEON=32idc.BPT_TRACE_INSN=64idc.BPT_TRACE_FUNC=128idc.BPT_TRACE_BBLK=256idc.BPTATTR_COND=6idc.BPTATTR_PID=7idc.BPTATTR_TID=8idc.BPLT_ABS=0idc.BPLT_REL=1idc.BPLT_SYM=2idc.set_bpt_attr(address, bptattr, value)

modifiable characteristics of a breakpoint

Parameters:

-
address – any address in the breakpoint range

-
bptattr – the attribute code, one of BPTATTR_* constants BPTATTR_CND is not allowed, see set_bpt_cond()

-
value – the attribute value

Returns:
success
idc.set_bpt_cond(ea, cnd, is_lowcnd=0)
Set breakpoint condition
Parameters:

-
ea – any address in the breakpoint range

-
cnd – breakpoint condition

-
is_lowcnd – 0 - regular condition, 1 - low level condition

Returns:
success
idc.add_bptidc.del_bptidc.enable_bptidc.check_bptidc.BPTCK_NONE=-1idc.BPTCK_NO=0idc.BPTCK_YES=1idc.BPTCK_ACT=2idc.enable_tracing(trace_level, enable)
Enable step tracing
Parameters:

-
trace_level – what kind of trace to modify

-
enable – 0: turn off, 1: turn on

Returns:
success
idc.TRACE_STEP=0idc.TRACE_INSN=1idc.TRACE_FUNC=2idc.get_step_trace_optionsidc.set_step_trace_optionsidc.ST_OVER_DEBUG_SEG=1idc.ST_OVER_LIB_FUNC=2idc.ST_ALREADY_LOGGED=4idc.ST_SKIP_LOOPS=8idc.load_trace_fileidc.save_trace_fileidc.is_valid_trace_fileidc.diff_trace_fileidc.clear_trace(filename)
Clear the current trace buffer
idc.get_trace_file_descidc.set_trace_file_descidc.get_tev_qtyidc.get_tev_eaidc.TEV_NONE=0idc.TEV_INSN=1idc.TEV_CALL=2idc.TEV_RET=3idc.TEV_BPT=4idc.TEV_MEM=5idc.TEV_EVENT=6idc.get_tev_typeidc.get_tev_tididc.get_tev_regidc.get_tev_mem_qtyidc.get_tev_memidc.get_tev_mem_eaidc.get_call_tev_calleeidc.get_ret_tev_returnidc.get_bpt_tev_eaidc.get_color(ea, what)
Get item color
Parameters:

-
ea – address of the item

-
what – type of the item (one of CIC_* constants)

Returns:
color code in RGB (hex 0xBBGGRR)
idc.CIC_ITEM=1idc.CIC_FUNC=2idc.CIC_SEGM=3idc.DEFCOLOR=4294967295idc.set_color(ea, what, color)
Set item color
Parameters:

-
ea – address of the item

-
what – type of the item (one of CIC_* constants)

-
color – new color code in RGB (hex 0xBBGGRR)

Returns:
success (True or False)
idc.force_bl_jump(ea)
Some ARM compilers in Thumb mode use BL (branch-and-link) instead of B (branch) for long jumps, since BL has more range. By default, IDA tries to determine if BL is a jump or a call. You can override IDA’s decision using commands in Edit/Other menu (Force BL call/Force BL jump) or the following two functions.

Force BL instruction to be a jump
Parameters:
ea – address of the BL instruction
Returns:
1-ok, 0-failed
idc.force_bl_call(ea)
Force BL instruction to be a call
Parameters:
ea – address of the BL instruction
Returns:
1-ok, 0-failed
idc.set_flag(off, bit, value)idc.here()idc.is_mapped(ea)idc.ARGV=[]
The command line arguments passed to IDA via the -S switch.
