---
name: ida-stdio-mcp
description: 使用 ida-stdio-mcp V2 分析 IDA 9.3+ 样本时的固定工作流指南。适用于 native、Unity/.NET、字符串牵引、函数解释和报告导出。
---

# ida-stdio-mcp V2 使用指南

## 固定顺序

默认按这个顺序调用 MCP 工具：

```text
get_workspace_state -> open_target -> triage_binary -> investigate_string / explain_function -> export_report
```

## 操作原则

- 第一步总是调用 `get_workspace_state`，先看当前 session、working IDB、最近目标和推荐下一步。
- 如果没有当前 session，再调用 `open_target`。打开后服务会创建 `.runtime/sessions/<session_id>/working.i64`，后续只操作工作 IDB。
- 开局分析调用 `triage_binary`。默认不要构建全量字符串索引；需要字符串时用 `investigate_string` 定点查。
- 从错误文案、URL、路径、协议字段入手时，用 `investigate_string`，然后对返回的所属函数调用 `explain_function`。
- 分析函数时优先用 `explain_function`，只有明确需要单独伪代码时才直接调用 `decompile_function`。
- 需要复盘或交付结论时调用 `export_report`。
- 需要保存当前分析进度时调用 `save_workspace`；只有用户明确要求导出时才传 `path`。

## 工具面与门控

- 默认 slim 只暴露高层工作流工具，足够完成常规逆向。
- `full` 才使用底层枚举、xref、类型、结构体、导入表等工具。
- `expert` 用于实验性能力。
- 写回、补丁、IDAPython、microcode mutation 必须要求用户确认运行时已启用 `--unsafe`。
- microcode mutation 只能在 `--unsafe --tool-surface expert` 同时满足时使用，并把结论标记为 experimental。

## Native 样本

1. `triage_binary`
2. 选择入口函数、导入分类、关键字符串或高 xref 函数。
3. `explain_function`
4. 必要时 `trace_input_to_check`

## Unity/.NET 样本

1. `triage_binary`，重点看 managed summary、命名空间和托管字符串。
2. 用 `investigate_string` 找入口提示、UI 文案、网络路径或配置键。
3. 用 `explain_function` 读取 C# 或 IL 降级结果。
4. 报告里明确写出 managed 结果质量等级。
