# IDA plugin options

- 官方来源：https://docs.hex-rays.com/extensions/plugins/concepts/plugin-options.md

# Plugin options

The -O command line switch allows the user to pass options to the plugins. A plugin which uses options should call the get\_plugin\_options() function to get them.

Since there may be many plugins written by independent programmers, each options will have a prefix -O in front of the plugin name.

For example, a plugin named "decomp" should expect its parameters to be in the following format:

```
-Odecomp:option1:option2:option3
```

In this case, get\_plugin\_options("decomp") will return the "option1:option2:option3" part of the options string.

If there are several -O options in the command line, they will be concatenated with ':' between them.

List of plugins recognizing '-O' switch

* [Conversion option](/archive/database-conversion-from-idb-to-i64.md)
* [Objective-C](/extensions/plugins/concepts/plugins-shipped-with-ida/objective-c-analysis-plugin.md)
* Lumina
* [License Manager](/ida-actions/licensemanager.md)
* [Pdb](/ida-actions/loadpdbfile.md)
* [Rust](/extensions/plugins/concepts/plugins-shipped-with-ida/rust-plugin.md)
* [Golang](/extensions/plugins/concepts/plugins-shipped-with-ida/golang-plugin.md)
* [Swift](/extensions/plugins/concepts/plugins-shipped-with-ida/swift-plugin.md)
* [Hex-Rays decompiler](/core/decompiler/how-tos/running-in-batch-mode.md)

This switch is not available in the IDA Home edition.

---

# Agent Instructions: Querying This Documentation

If you need additional information that is not directly available in this page, you can query the documentation dynamically by asking a question.

Perform an HTTP GET request on the current page URL with the `ask` query parameter:

```
GET https://docs.hex-rays.com/extensions/plugins/concepts/plugin-options.md?ask=
```

The question should be specific, self-contained, and written in natural language.
The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
