---
name: ida-stdio-mcp
description: 使用 ida-stdio-mcp 分析 IDA Pro 9.3+ 样本时调用。适用于原生逆向、Unity/.NET 分析、字符串牵引、函数解释、IDAPython 专家分析、microcode 线索、调试器流程、报告导出、会话管理与 MCP 排障。
---

# ida-stdio-mcp

## 核心规则

优先使用 `slim` 工作流完成主流程；当前目标需要底层枚举、写回、调试或实验能力时，再进入 `full` 或 `expert` 工具面。

固定入口：

```text
get_workspace_state -> open_target -> triage_binary -> investigate_string / explain_function -> export_report
```

第一次接触任何样本时：

1. 调用 `get_workspace_state`，读取 runtime、当前 session、working IDB、最近目标、推荐下一步。
2. 没有当前 session 时调用 `open_target`。默认 `run_auto_analysis=false`，除非用户明确要求等待全库自动分析。
3. 调用 `triage_binary`。字符串索引保持按需构建，默认先读取索引状态。
4. 根据 triage 结果选择一个具体目标：字符串、入口函数、可疑函数、导入项或检查点。
5. 字符串线索走 `investigate_string`，函数线索走 `explain_function`，输入/鉴权/路径检查走 `trace_input_to_check`。
6. 需要交付结论时调用 `export_report`，需要保存进度时调用 `save_workspace`。

## 会话与真实性

- `open_target` 必须等工具返回后再判断是否打开成功；有效分析结果以工具返回的 `status` 和 `data` 为准。
- `open_target` 会创建 `.runtime/sessions/<session_id>/working.i64`。后续分析、注释、类型、补丁、脚本都作用于 working IDB。
- 多 session 时显式传 `session_id`；启用 `--isolated-contexts` 且 schema 暴露 `context_id` 时必须传 `context_id`。
- 每次工具返回都检查 `status`、`warnings`、`error`、`data`。`degraded` 可以继续，但报告里要说明边界；`unsupported/error` 要按 `error.next_steps` 修正。
- 结果不完整时必须说明原因、可信边界和下一步。

## 工具选择

- **slim**：默认使用 `get_workspace_state`、`open_target`、`triage_binary`、`investigate_string`、`explain_function`、`trace_input_to_check`、`decompile_function`、`export_report`、`save_workspace`、`close_target`。
- **full**：需要枚举函数、字符串、导入、xref、类型、结构体、字节、调用图时使用。先读 [工具面与契约](references/tool-surfaces.md)。
- **expert**：需要 IDAPython、调试器、补丁、microcode 实验时使用。先读 [专家能力](references/expert.md)。

## 常见决策

- 从错误文案、URL、路径、协议字段、UI 文案入手：先用 `investigate_string`。
- 从 `main`、入口点、导入调用、可疑函数名入手：先用 `explain_function`。
- 只需要伪代码：用 `decompile_function`。需要上下文、字符串、调用关系、建议：用 `explain_function`。
- UE、Chrome、游戏客户端、大 PDB 样本：保持 `run_auto_analysis=false` 做轻量打开；用户明确要全库自动分析时再用 `run_auto_analysis=true`，并提醒客户端超时设为 1 到 6 小时。
- 字符串工具首次查询会构建会话级缓存。未命中且 `cache.truncated_by_scan_limit=true` 时，不得断言全库不存在。
- IDAPython 只能在 `--unsafe --tool-surface expert` 下使用。脚本只返回小型摘要，必须把结果赋给 `result`。
- microcode mutation 只能在 `--unsafe --tool-surface expert` 下使用，结论标记为 `experimental`。

## 按需读取

- Native、managed、字符串、函数、报告的完整流程：读 [工作流](references/workflows.md)。
- full/expert 工具面、输出 envelope、字符串缓存契约：读 [工具面与契约](references/tool-surfaces.md)。
- IDAPython、microcode、调试器、写回与补丁：读 [专家能力](references/expert.md)。
- 大样本耗时、卡住、超时、坏结果、客户端等待问题：读 [排障](references/troubleshooting.md)。

MCP prompts 是服务端提供的可选模板；本 skill 是客户端侧操作指南。客户端支持 prompts 时可以读取模板辅助组织任务，工作流检查仍以工具返回结果为准。
