# Hex-Rays batch decompile

- 官方来源：https://docs.hex-rays.com/9.1/user-guide/decompiler/batch

⌘Ctrlk

IDA 9.1

- Welcome to Hex-Rays docs
- Getting Started
- User Guide

- User Interface
- Disassembler
- Decompiler

- Prerequisites
- Quick primer
- Exception handler
- Introduction to Decompilation vs. Disassembly
- Interactive operation
- Batch operation
- Configuration
- Third party plugins
- Floating point support
- Support for intrinsic functions
- Overlapped variables
- gooMBA
- Failures and troubleshooting
- FAQ
- Limitations
- Tips and tricks

- Debugger
- Creating Signatures
- Types
- Configuration
- Teams
- Lumina
- Plugins
- Helper Tools
- idalib
- Third-Party Licenses
- Floating licenses

- Developer Guide
- Admin Guide
- Release Notes
- Archive
- Bug Bounty

Powered by GitBook

On this page

Copy
On this page

- User Guide
- Decompiler

# Batch operation

The decompiler supports the batch mode operation with the text and GUI versions of IDA. All you need is to specify the -Ohexrays switch in the command line. The format of this switch is:

Copy

```text
-Ohexrays:-option1:-option2...:outfile:func1:func2\...
```

The valid options are:

-

-new decompile only if output file does not exist

-

-nosave do not save the database (idb) file after decompilation

-

-errs send problematic databases to hex-rays.com

-

-lumina use Lumina server

-

[email protected] your email (meaningful if -errs option is used)

The output file name can be prepended with + to append to it. If the specified file extension is invalid, .c will be used.

The functions to decompile can be specified by their addresses or names. The ALL keyword means all non-library non-trivial functions. For example:

Copy

```text
idat -Ohexrays:-errs:[email protected]:outfile:ALL -A input
```

will decompile all nonlibrary non-trivial (having more than one instruction) functions to outfile.c. In the case of an error, the .idb file will be sent to hex-rays.com. The -A switch is necessary to avoid the initial dialog boxes.

Last updated 1 year ago

Was this helpful?

#### Need Help?

- FAQs
- Support

#### Community

- Forum
- Plugins

#### Resources

- Blog
- Download center

© 2025 Copyright Hex-Rays

Was this helpful?
