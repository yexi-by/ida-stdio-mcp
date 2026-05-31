# IDA headless runtime

- 官方来源：https://docs.hex-rays.com/core/idalib/overview.md

# Overview

## What's idalib?

IDA as a library (idalib) allows you to use the C++ and IDAPython APIs outside IDA as standalone applications. That way, your app uses IDA's engine directly, letting you work with the IDA APIs from your IDE of choice.

The idalib lets you call IDA as a library and run analysis **headlessly**, or integrate IDA into your own toolchain to drive custom workflows or automate workflows without launching the GUI.

## What can you do with idalib?

The idalib supports a wide range of applications. Some common uses include bulk static analysis, headless decompilation, CI/CD integration, and powering AI agents with IDA as an analysis backend.

**Dive deeper**:

* [Real-world applications of idalib](https://hex-rays.com/blog/4-powerful-applications-of-idalib-headless-ida-in-action)

## License

The idalib is included with IDA Pro 9.0 and newer (idalib is not available in IDA Home). The license you need depends on how you use it:

* **Standard IDA Pro license** — covers typical personal and non-commercial use
* [**IDA OEM license**](https://hex-rays.com/ida-pro-oem) — required if you embed idalib in your own software, use it as a SaaS engine, or run it on a shared server. It's free during development and beta phases.

## What's next?

Check the [Getting Started](/core/idalib/getting-started.md) guide to get you ready with idalib — including simplified installation with HCLI, especially recommended for automated workflows.

---

# Agent Instructions: Querying This Documentation

If you need additional information that is not directly available in this page, you can query the documentation dynamically by asking a question.

Perform an HTTP GET request on the current page URL with the `ask` query parameter:

```
GET https://docs.hex-rays.com/core/idalib/overview.md?ask=
```

The question should be specific, self-contained, and written in natural language.
The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
