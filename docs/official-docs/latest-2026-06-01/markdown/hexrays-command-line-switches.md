# IDA headless CLI/open options

- 官方来源：https://docs.hex-rays.com/core/user-interface/concepts/command-line-switches.md

# Command line switches

IDA recognizes the following command line switches:

| Switch | Effect |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-a` | disable [auto analysis](/core/disassembler/overview.md#background-analysis). (`-a-` enables it) |
| `-A` | autonomous mode. IDA will not display dialog boxes. Designed to be used together with `-S` switch. |
| `-b####` | loading address, a hexadecimal number, in paragraphs (a paragraph is 16 bytes) |
| `-B` | batch mode. IDA will generate .IDB and .ASM files automatically |
| `-c` | disassemble a new file (delete the old database) |
| `-C####` | set [compiler](/ida-actions/setupcompiler.md) in format name:abi |
| `-ddirective` | A configuration directive which must be processed at the first pass. Example: `-dVPAGESIZE=8192` |
| `-Ddirective` | A configuration directive which must be processed at the second pass. |
| `-f` | disable FPP instructions (IBM PC only) |
| `-h` | help screen -i#### program entry point (hex) |
| `-I#` | set IDA as just-in-time debugger (0 to disable and 1 to enable) |
| `-L####` | name of the log file |
| `-M` | disable mouse (text only) |
| `-O####` | [options](/extensions/plugins/concepts/plugin-options.md) to pass to plugins. This switch is not available in the IDA Home edition. |
| `-o####` | specify the output database (implies `-c`) |
| `-p####` | [processor type](/ida-actions/options.md#processor-type) |
| `-P+` | compress database (create zipped idb) |
| `-P` | pack database (create unzipped idb) |
| `-P-` | do not pack database (not recommended, see the Abort command) |
| `-r###` | immediately run the built-in debugger format of this switch is explained [here](/extensions/plugins/concepts/plugin-options.md) |
| `-R` | load MS Windows exe file resources |
| `-S###` | [Execute a script file](#executing-a-script) when the database is opened |
| `-T###` | interpret the input file as the specified file type. The file type is specified as a prefix of a file type visible in the 'load file' dialog box. To specify archive member, put it after the colon char, for example: `-TZIP:classes.dex` You can specify any nested paths: `-T[:{::}[:]]` IDA does not display the "Load file" dialog in this case. Find additional information [here](/core/user-interface/concepts/command-line-switches/t-switch-loader-selection.md) |
| `-t` | create an empty database. |
| `-W###` | specify MS Windows directory |
| `-x` | do not create segmentation (used in pair with [Dump database](/ida-actions/dumpdatabase.md) command) this switch affects EXE and COM format files only. |
| `-z` | turn on [debugging](#debugging-flags) |
| `-i` | specify the address of an entry point (useful for binary files) |
| `-v` | verbose (enables console messages for the text version) or viewer mode (database is not saved for the GUI version) |
| `-O` | plugin options (e.g. `-Odwarf:off`), see also [-Ohexrays](/core/decompiler/how-tos/running-in-batch-mode.md) |
| `-?` | this screen (works for the text version) |
| `?` | this screen (works for the text version) |
| `-h` | this screen (works for the text version) |
| `-H` | this screen (works for the text version) |
| `--help` | this screen (works for the text version) |

## Debugging flags

The following bitfield can be used with the `-z` directive:

```
00000001 drefs
00000002 offsets
00000004 flirt
00000008 idp module
00000010 ldr module
00000020 plugin module
00000040 ids files
00000080 config file
00000100 check heap
00000200 licensing
00000400 demangler
00000800 queue
00001000 rollback
00002000 already data or code
00004000 type system
00008000 show all notifications
00010000 debugger
00020000 [dbg\_appcall](1572.md)
00040000 source-level debugger
00080000 accessibility
00100000 network
00200000 full stack analysis (simplex method)
00400000 handling of debug info (e.g. pdb, dwarf)
00800000 lumin
```

## Batch mode

It is possible to run IDA in so-called "batch mode", using the following the `-B` switch:

```
ida -B input-file
```

which is equivalent to:

```
ida -c -A -Sanalysis.idc input-file
```

(For more information, please see the analysis.idc file in the IDC subdirectory.)

A couple notes:

* regular plugins are not automatically loaded in batch mode because the `analysis.idc` file quits and the kernel has no chance to load them.
* Although the GUI version of IDA is perfectly of running batch scripts, we recommend using [the "idalib" Python module](/core/idalib/overview.md) for this task as it uses fewer system resources.

## Executing a script

The script file extension (`.idc`, `.py`) is used to determine which interpreter will be used to run the script.

It is possible to pass command line arguments after the script name. For example: `-S"myscript.py argument1 \\"argument 2\\" argument3"`

The passed parameters are stored in the "ARGV" global IDC variable, which means:

* For IDC scripts:
* Use `ARGV.count` to determine the number of arguments.
* The first argument, `ARGV[0]`, contains the script name.
* For Python scripts:
* you can import the `idc` compatibility layer (`import idc`), and then
* access the `idc.ARGV` array

{% hint style="info" %}
The `-S` switch is not available in the IDA Home edition.
{% endhint %}

---

# Agent Instructions: Querying This Documentation

If you need additional information that is not directly available in this page, you can query the documentation dynamically by asking a question.

Perform an HTTP GET request on the current page URL with the `ask` query parameter:

```
GET https://docs.hex-rays.com/core/user-interface/concepts/command-line-switches.md?ask=
```

The question should be specific, self-contained, and written in natural language.
The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
