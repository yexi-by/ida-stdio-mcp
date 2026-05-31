# IDA debugger launch

- 官方来源：https://docs.hex-rays.com/core/debugger/concepts/instant-debugger.md

# Instant debugger

The -r command line switch is used to run the built-in debugger without creating a database in advance. The format of this switch is:

```
-rdebname{params}:pass@hostname:port+pid
```

The explanation of the fields:

```
debname Debugger name. Should contain the debugger
module name. Examples: win32, linux. This prefix
can be shortened or even completely
omitted if there is no ambiguity
params Optional parameter for the debugger module
The parameters from the appropriate configuration file
can be specified here, separated by semicolons.
pass Password for the remote debugger server
hostname Host name or address of the remote debugger server.
IPv6 addresses need to be enclosed in [].
port Port number to use to connect to the debugger server
pid PID of the process to attach
```

All fields except the first one are optional. Also, the pid field can be specified as '+'. IDA will display the process list to attach. See examples below for typical command lines:

```
ida -rwin32 file args
Run 'file' with command line 'args' in the local debugger
We have to specify the debugger name to avoid ambiguities.
ida -rwindbg+450
Attach to process 450 on the local machine using the windbg backend
ida -rl:hippy@mycom:4567+
Connect to the remote linux computer 'mycom' at port 4567 using the
password 'hippy' and display the list of processes running on it.
Allow the user to select a process and attach to it.
ida -rl@mycom /bin/ls e*
Run '/bin/ls' command on the 'mycom' computer using the remote
debugger server on Linux. Use an empty password and the
default port number. Pass "e*" as the parameter to /bin/ls.
ida -rl@mycom whobase.idb
Run '/usr/bin/who' command on the 'mycom' computer using the
remote linux debugger server. Use an empty password and the
default port number. IDA will extract the name of the
executable from the whobase.idb file in the local current
directory. If the database does not exist, then this command
will fail.
ida "-rwindbg{MODE=1}@com:port=\\.\pipe\com_1,baud=115200,pipe,reconnect+"
Attach using windbg in kernel mode. The connection string is
"com:port=\\.\pipe\com_1,baud=115200,pipe,reconnect". A mini database
will be created on the fly.
```

When the -r switch is used, IDA works with the databases in the following way:

```
- if a database corresponding to the input file exists and
the -c switch has not been specified, then IDA will use the
database during the debugging session

- otherwise, a temporary database will be created
```

Temporary databases contain only meta-information about the debugged process and not the memory contents. The user can make a [memory snapshot](/ida-actions/takesnapshot.md) any time before the process stops. If IDA detects that a command will cause the process to exit or detach IDA, it will propose to make a snapshot.

The rest of the command line is passed to the launched process.

In the case there is no input file (when attaching to an existing process, for example), then the temporary database is created in the standard temporary directory. For Windows, this directory is usually "Local Setting\Temp" in the user profile directory.

See also [How to launch remote debugging](/core/debugger/concepts/remote-debugging.md)

---

# Agent Instructions: Querying This Documentation

If you need additional information that is not directly available in this page, you can query the documentation dynamically by asking a question.

Perform an HTTP GET request on the current page URL with the `ask` query parameter:

```
GET https://docs.hex-rays.com/core/debugger/concepts/instant-debugger.md?ask=
```

The question should be specific, self-contained, and written in natural language.
The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
