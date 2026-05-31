# IDA remote debugger

- 官方来源：https://docs.hex-rays.com/user-guide/debugger/remote-debugging

The docs have been restructured for better navigation. Found a broken link or have feedback to share? Let us know
here.

⌘Ctrlk

IDA 9.3

-

Getting started

- IDA Installation
- License Activation
- Basic Usage

-

IDA Core

- User Interface
- Disassembler
- Decompiler
- Debugger

- Overview
- Concepts

- Local debugging
- Remote debugging

- Remote iOS Debugger
- Android debugger
- Dalvik debugger
- Remote GDB Debugger
- PIN debugger
- Replayer debugger
- Bochs debugger

- Instant debugger
- Breakpoints

- How-tos

- Types & Data Structure
- FLIRT
- idalib

-

IDA Extensions

- Teams
- Lumina
- Plugins
- Floating License

-

Developer

- Domain API
- C++ SDK
- IDAPython SDK
- IDC
- Publishing Plugins

- Release Notes

Powered by GitBook

On this page

Copy
On this page

- IDA Core
- Debugger
- Concepts

# Remote debugging

1. Launch a remote IDA debugger server on the remote host. The remote server is started from the command line and accepts command line parameters. You can specify a password if you want to protect your debugger server from strangers. For example, to launch the server under MS Windows, you could enter:

Copy

```text
 win32_remote -Pmy_secret_password
```

2. Specify the remote debugger parameters in the Debugger → Process options. The file paths must be valid on the remote host. Do not forget to specify the same password that you have specified when launching the server. For example, to debug notepad.exe on the remote computer remote.host.com:

Copy

```text
 Application: c:\windows\notepad.exe
 Input file: c:\windows\notepad.exe
 Directory: c:\windows
 Hostname: remote.host.com
 Port: 23946
 Password: my_secret_password
```

3. The rest of debugging is the same as with local debugging.

The Linux debugger server can handle one debugger session at once. If you need to debug several applications simultaneously, launch several servers at different network ports.

The following debugger servers are shipped with IDA

Copy

```text
 File name Target system Debugged programs
 ------------------ ------------------ ----------------------------
 android_server32 ARM Android 32-bit ELF files
 android_server AArch64 Android 64-bit ELF files
 android_x64_server x86 Android 32-bit 32-bit ELF files
 android_x86_server x86 Android 64-bit 64-bit ELF files
 armlinux_server32 ARM Linux 32-bit ELF files
 armlinux_server AArch64 Linux 64-bit ELF files
 linux_server Linux 64-bit 64-bit ELF files
 mac_server Mac OS X/macOS 11 64-bit Mach-O files (x64)
 mac_server_arm ARM macOS 11 64-bit Mach-O files (arm64)
 mac_server_arme ARM macOS 11 64-bit Mach-O files (arm64e)
 win32_remote32.exe MS Windows 32-bit 32-bit PE files
 win64_remote.exe MS Windows 64-bit 64-bit PE files
```

An appropriate server must be started on the remote computer before starting a debug session.

See also

-

Debugger menu

-

Debugger for Linux

-

Debugger for macOS

-

Debugger for Android native code

-

Remote iOS debugger

Last updated 1 month ago

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
