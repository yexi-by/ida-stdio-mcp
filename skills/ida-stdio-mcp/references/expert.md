# 专家能力

## 目录

- 门控
- IDAPython
- Microcode
- 调试器
- 写回与补丁

## 门控

专家能力只在用户配置和服务端工具面允许时使用：

| 能力 | 需要 |
| --- | --- |
| IDAPython / 脚本文件 | `--unsafe --tool-surface expert` |
| 注释、重命名、类型写回、补丁 | `--unsafe` |
| 调试器 | `--debugger` |
| microcode mutation | `--unsafe --tool-surface expert` |

如果工具列表里没有对应工具，不要假装可用。先解释需要的运行参数。

## IDAPython

优先使用 MCP 现成工具。只有现成工具无法表达查询时才用 `evaluate_python` 或 `execute_python_file`。

脚本规则：

- 显式传 `session_id`，多 agent 隔离时传 `context_id`。
- 导入需要的 IDA 模块，例如 `import idautils`、`import idaapi`、`import ida_bytes`。
- 把小型结构化摘要赋给 `result`。
- 不要把全量函数、全量字符串、全量 locals 放进 `result`。
- 控制 stdout，避免打印巨大列表。
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

`evaluate_python` 的返回值是受控摘要：`stdout`、`stderr`、`result`、`local_keys`，`include_locals=true` 也只返回安全摘要。

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
- 必须同时满足 `--unsafe --tool-surface expert`。
- 结果统一标记为 `experimental`。
- mutation 后需要重新用 `decompile_function` 或 `explain_function` 验证。

## 调试器

调试器工具取决于 IDA 后端和当前样本环境。

使用顺序：

1. 先看工具是否暴露。
2. `debug_start` 或复用当前输入文件。
3. 设置断点。
4. `debug_continue` / `debug_run_to` / step。
5. 读取寄存器、栈、内存。
6. 调试结束后 `debug_exit`。

如果返回 `unsupported`，回到静态分析，不要继续发调试命令。

## 写回与补丁

所有写回都作用于 working IDB。补丁和类型修改前：

1. 读原始字节、函数、类型或栈帧。
2. 明确修改目的和地址。
3. 执行写回。
4. 重新读取验证。
5. `save_workspace` 保存。

不要在用户没有要求时修改原样本旁边的文件。`save_workspace` 不传 `path` 时只保存 working IDB。
