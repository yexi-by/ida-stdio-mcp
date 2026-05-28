# 底层能力

## 目录

- 可用性判断
- IDAPython
- Microcode
- 调试器
- 写回与补丁

## 可用性判断

`all` 工具面展示读、写回、补丁、IDAPython、调试器和 microcode 工具。`workflow` 工具面只展示高层入口，用于减少工具选择噪声。

判断可用性时以 `tools/list`、工具返回 `status`、`warnings`、`error` 和 backend 状态为准。如果工具返回 `unsupported` 或 `error`，按 `error.next_steps` 改走静态分析或补充运行环境。

## IDAPython

优先使用 MCP 现成工具。只有现成工具无法表达查询时才用 `evaluate_python` 或 `execute_python_file`。

脚本规则：

- 显式传 `session_id`，多 agent 隔离时传 `context_id`。
- 导入需要的 IDA 模块，例如 `import idautils`、`import idaapi`、`import ida_bytes`。
- 把结构化摘要赋给 `result`；小结果会直接返回，大结果会写入 artifact。
- 控制 stdout，避免把无关噪声打印进 artifact。
- 需要分页时自己限制数量，返回 `count`、`sample`、`truncated`。

推荐模式：

```python
import idautils

items = []
for index, ea in enumerate(idautils.Functions()):
    if index >= 50:
        break
    items.append(hex(int(ea)))

result = {
    "count_sampled": len(items),
    "sample": items,
    "truncated": True,
}
```

`evaluate_python` 的返回值是受控摘要：`stdout`、`stderr`、`result`、`local_keys`，`include_locals=true` 也只返回可序列化摘要。大 `stdout`、`stderr` 或 `result` 会写入运行时目录，返回 `artifacts`，每个 artifact 包含 `path`、`sha256`、`size` 与 `schema`。需要直接执行文件时使用 `execute_python_file`，入口不附加额外流程。

## Microcode

只读优先：

- `microcode_summary`：读取块和指令摘要。
- `microcode_def_use`：读取 def-use/use-def 线索。

使用规则：

- 需要 Hex-Rays。
- 结果是辅助线索，不是最终证明。
- 报告里标注 microcode 结论来源和不确定性。

mutation：

- 只能用 `microcode_experiment`。
- 结果统一标记为 `experimental`。
- mutation 后需要重新用 `decompile_function` 或 `explain_function` 验证。

## 调试器

调试器工具取决于 IDA 后端和当前样本环境。

使用顺序：

1. 先看工具是否暴露，并读取 backend 状态。
2. `debug_launch` 启动目标，或 `debug_attach` 附加已有 PID；`debug_start` 是启动快捷入口。
3. 设置断点：`debug_add_breakpoints`、`debug_delete_breakpoints`、`debug_toggle_breakpoints`、`debug_list_breakpoints`。
4. 运行控制：`debug_continue`、`debug_run_to`、`debug_step`。
5. 读取运行时状态：`debug_registers`、`debug_stacktrace`、`debug_stack`、`debug_read_memory`。
6. 需要时间线时配置 `debug_capture_calls`，命中后用 `debug_export_timeline` 导出 JSON。
7. 调试结束后 `debug_exit`。

如果返回 `unsupported`，回到静态分析，不要继续发调试命令。

## 写回与补丁

所有写回都作用于 working IDB。`patch_bytes` 与 `patch_assembly` 保持直接写入；需要便利流程时使用：

- `patch_diff`：读取当前字节并预览目标字节差异，不写入。
- `patch_history`：读取当前工作库补丁记录，包含 ID、地址、写入前后字节和变化偏移。
- `rollback_patch`：按补丁 ID 恢复写入前字节，并追加回滚记录。

补丁和类型修改前：

1. 读原始字节、函数、类型或栈帧。
2. 明确修改目的和地址。
3. 执行写回。
4. 重新读取验证。
5. `save_workspace` 保存。

不要在用户没有要求时修改原样本旁边的文件。`save_workspace` 不传 `path` 时只保存 working IDB。

## 外部分析与 dispatcher

`scan_dispatchers` 用通用启发式扫描 hash 常量、switch 元数据、跳转表和间接调用候选。它只负责提出候选，不直接证明语义；命中后用 `decompile_function`、`explain_function` 和调用图继续确认。

外部 VM、字节码、封包或资源扫描通过 JSON artifact 接入：

1. 在配置里声明 analyzer 命令后用 `run_external_analyzer` 执行；命令通过 `{input}`、`{output}`、`{workspace}` 等占位符获得路径。
2. 已有 JSON 用 `import_analysis_artifact` 导入。
3. 用 `list_analysis_artifacts` 查看已导入结果。
4. 用 `correlate_analysis_artifact` 与当前 IDB 的字符串、函数名、地址、hash 常量和路径线索做关联。

外部 artifact 是通用 JSON，不内置特定游戏脚本格式。需要专用 VM disassembler 时，把它作为外部 analyzer 输出结构化 JSON，再由 MCP 做关联。
