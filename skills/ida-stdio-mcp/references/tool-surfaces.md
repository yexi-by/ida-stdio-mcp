# 工具面与契约

## 目录

- 输出 envelope
- workflow 工具
- all 工具使用时机
- 字符串缓存
- 会话参数
- MCP prompts 与 resources

## 输出 envelope

所有工具返回统一结构：

```text
status, source, warnings, error, data
```

处理规则：

- `ok`：可以使用结果。
- `degraded`：可以继续，但必须记录降级原因。
- `unsupported`：当前环境不支持，换路径分析。
- `error`：读取 `error.code`、`error.message`、`error.next_steps` 后修正调用。

不要只看 `data`，也不要忽略 `warnings`。

## workflow 工具

优先用这些高层工具完成主流程：

| 工具 | 用途 |
| --- | --- |
| `get_workspace_state` | 查看 runtime、当前 session、working IDB、最近目标、推荐下一步 |
| `open_target` | 打开样本并创建 working IDB |
| `triage_binary` | 开局摘要、入口、导入、关键函数、字符串索引状态、managed 摘要 |
| `investigate_string` | 字符串到 xref 到函数的闭环 |
| `explain_function` | 函数画像、伪代码/降级表示、调用关系、字符串、常量 |
| `trace_input_to_check` | 输入、鉴权、路径、协议字段到检查点 |
| `decompile_function` | 单函数高层表示 |
| `export_report` | 结构化报告 |
| `save_workspace` | 保存 working IDB |
| `close_target` | 关闭 session |

## all 工具使用时机

只有 workflow 结果指向具体问题时再使用底层工具：

- 需要枚举候选：`list_functions`、`list_imports`、`list_strings`。
- 需要交叉引用：xref、callgraph、caller/callee 相关工具。
- 需要字节或补丁前验证：`read_bytes`、`find_bytes`、反汇编工具。
- 需要补丁便利流程：`patch_diff`、`patch_history`、`rollback_patch`；直接写入仍使用 `patch_bytes` 或 `patch_assembly`。
- 需要运行时验证：`debug_launch`、`debug_attach`、断点工具、`debug_continue`、`debug_run_to`、`debug_step`、`debug_registers`、`debug_stack`、`debug_read_memory`。
- 需要调用捕获和日志交付：`debug_capture_calls` 与 `debug_export_timeline`。
- 需要定位间接分发器：`scan_dispatchers`，再用 `decompile_function` 或 `explain_function` 深挖候选。
- 需要接入外部字节码、封包或资源扫描结果：`run_external_analyzer`、`import_analysis_artifact`、`list_analysis_artifacts`、`correlate_analysis_artifact`。
- 需要类型恢复：类型、结构体、枚举、栈帧相关工具。
- 需要导入地址语义：`get_import_at`。

不要为了“看看有什么”一次性大量调用底层枚举工具。

## 字符串缓存

`list_strings`、`find_strings`、`search_regex`、`investigate_string` 使用当前 working IDB 的字符串缓存。

返回字段：

- `data`：当前页结果。
- `next_offset`：下一页偏移。
- `statistics`：匹配数、返回数、分页信息。
- `cache`：缓存状态。
- `recommended_next_tools`：下一步建议。

关键约束：

- `limit` / `count` 只限制返回行数，不代表扫描成本。
- 首次字符串查询可能较慢，后续同一 working IDB 会复用缓存。
- `cache.cache_hit=true` 表示复用成功。
- `cache.truncated_by_scan_limit=true` 表示缓存是受控索引；未命中不能解释成全库不存在。
- 无命中时优先回到 imports、entrypoints、interesting_functions，不要盲目关键词循环。

## 会话参数

规则：

- 单 session 时可以省略 `session_id`，服务端使用当前 workflow session。
- 多 session 或需要确保目标时显式传 `session_id`。
- 启用 `--isolated-contexts` 时，schema 暴露 `context_id`，必须传当前上下文。
- 跨 session 操作前先 `get_workspace_state`。

## MCP prompts 与 resources

prompts 是服务端模板：

- `triage-native`
- `triage-managed`
- `string-led-investigation`
- `microcode-investigation`

resources 是可读上下文，如 workspace、capability matrix、functions、strings、imports、callgraph、managed summary、tool docs。

使用原则：

- prompts 用于组织计划，工具结果负责提供证据。
- resources 用于读取稳定上下文，会话检查仍由工作流工具完成。
- 资源读取也要检查 envelope 和错误信息。
