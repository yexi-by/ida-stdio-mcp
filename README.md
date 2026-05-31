# ida-stdio-mcp

ida-stdio-mcp 是面向 AI Agent 的 IDA Pro 9.3+ stdio MCP 逆向分析服务。服务通过 IDA headless runtime 打开样本、维护隔离工作 IDB，并提供二进制概览、函数解释、字符串牵引、托管程序集反编译、轻量数据流追踪、结构化报告、调试、脚本执行与写回能力。

## 能力概览

- IDA 9.3+ runtime 分层诊断：启动可进入诊断模式，`runtime_health` 区分 `idapro` 包缺失、`idalib.dll` 加载失败、`IDADIR` 错误和版本不足。
- 默认完整工具面：`all` 暴露读、写回、补丁、IDAPython、调试、microcode 等全部已注册能力。
- 工作流工具面：`workflow` 只展示高层逆向入口，用于降低工具选择成本。
- 会话级工作 IDB：每个样本使用 `.runtime/sessions/<session_id>/working.i64`，原始样本保持只读输入角色。
- Native 与 Unity/.NET 双场景：native 优先 Hex-Rays，托管程序集优先 `ilspycmd` C# 反编译。
- MCP prompts：内置 native triage、managed triage、字符串牵引、microcode 调查模板。
- 结构化报告：`export_report` 输出便于 AI 复盘的 JSON 分析包。
- 轻量打开策略：`open_target` 默认完整加载样本和调试符号并创建 working IDB，不等待全库自动分析完成。

## 环境要求

- Windows 或 IDA Pro 9.3+ 支持的系统
- Python 3.11+
- IDA Pro 9.3 / 9.3sp1+
- `uv`
- 可选：Hex-Rays Decompiler
- 可选：`.NET` 与 `ilspycmd`，用于 Unity/.NET C# 反编译

IDA 运行时可通过以下任一方式提供：

- 已激活的 IDA 9.3 Python package / wheel
- `IDADIR` 指向 IDA 9.3+ 安装目录
- 客户端环境中可导入 `idapro`

## 安装

```powershell
git clone https://github.com/yexi-by/ida-stdio-mcp.git
cd ida-stdio-mcp
uv sync
uv run ida-stdio-mcp --help
```

如需托管程序集 C# 反编译，可安装 `ilspycmd`：

```powershell
dotnet tool install --global ilspycmd
```

## MCP 客户端配置

请将 `<UV_PATH>`、`<REPO_PATH>` 和 `<IDA_INSTALL_DIR>` 替换为本机实际路径。`<UV_PATH>` 是 `uv` 可执行文件路径，`<REPO_PATH>` 是本仓库路径，`<IDA_INSTALL_DIR>` 是 IDA 9.3+ 安装目录。

TOML 示例：

```toml
[mcp_servers.ida-stdio-mcp]
command = '<UV_PATH>'
args = [
    "--directory",
    '<REPO_PATH>',
    "run",
    "--no-sync",
    "python",
    "-m",
    "ida_stdio_mcp",
    "--isolated-contexts",
]
startup_timeout_sec = 240
tool_timeout_sec = 21600

[mcp_servers.ida-stdio-mcp.env]
IDADIR = '<IDA_INSTALL_DIR>'
```

JSON 示例：

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "<UV_PATH>",
      "args": [
        "--directory",
        "<REPO_PATH>",
        "run",
        "--no-sync",
        "python",
        "-m",
        "ida_stdio_mcp",
        "--isolated-contexts",
      ],
      "env": {
        "IDADIR": "<IDA_INSTALL_DIR>"
      },
      "startup_timeout_sec": 240,
      "tool_timeout_sec": 21600
    }
  }
}
```

需要减少工具列表时可使用 `workflow` 工具面：

```toml
args = [
    "--directory",
    '<REPO_PATH>',
    "run",
    "--no-sync",
    "python",
    "-m",
    "ida_stdio_mcp",
    "--tool-surface",
    "workflow",
]
tool_timeout_sec = 3600
```

`tool_timeout_sec` 应按分析目标调整。普通样本或轻量工作流可设置为 `3600` 秒；UE、Chrome、游戏客户端、带大型 PDB 的 native 样本在执行全量自动分析时可能持续几十分钟到数小时，建议设置为 `21600` 秒。超时时间只影响 MCP 客户端等待工具返回的窗口，不改变 IDA 的实际分析内容。

## Skill 使用

仓库内提供本地 skill：

```text
skills/ida-stdio-mcp
```

支持本地 skill 的客户端应配置或复制整个 `skills/ida-stdio-mcp` 目录。该目录包含：

- `SKILL.md`：最小入口说明。
- `references/`：按需加载的工作流、工具面、底层能力和排障指南。
- `agents/openai.yaml`：可选 UI 元数据。

TOML 示例：

```toml
[skills.ida-stdio-mcp]
path = '<REPO_PATH>/skills/ida-stdio-mcp'
```

JSON 示例：

```json
{
  "skills": {
    "ida-stdio-mcp": {
      "path": "<REPO_PATH>/skills/ida-stdio-mcp"
    }
  }
}
```

不同客户端的字段名可能不同，核心要求是把 `skills/ida-stdio-mcp` 目录加入客户端的 skill 搜索路径。使用时可显式引用 `$ida-stdio-mcp`，或让客户端按描述在 IDA/MCP/逆向任务中自动触发。

## 工具面

| 工具面 | 适用场景 | 能力范围 |
| --- | --- | --- |
| `all` | 默认完整分析 | 暴露读、写回、补丁、IDAPython、调试、microcode、函数、字符串、导入、xref、类型、结构体、字节、调用图等工具 |
| `workflow` | 自主逆向主流程 | 只展示高层工作区、打开样本、triage、字符串牵引、函数解释、数据流、报告、保存、关闭 |

工具面只影响 `tools/list` 的展示范围。参数 schema、会话归属、输出大小限制、错误 envelope 和 backend unsupported 仍作为可靠性契约保留。调试与 microcode 能力是否真正可用取决于当前 IDA/Hex-Rays 后端状态；本项目不依赖 IDA GUI，能力可用性通过 `runtime_health`、`get_capability_state` 与 `debug_health` 显式探测。

`open_target` 支持 `loader`、`processor` 与 `plugin_options`，分别映射到 IDA headless 打开参数 `-T`、`-p` 与 `-O`；默认值可在 `setting.toml` 的 `[open_target]` 中配置。

调试目标可通过 `debug_launch` 传入 `path`、`args`、`cwd`、`backend`、`use_request` 和 `wait_for_suspend_ms`，也可用 `debug_attach` 附加已有进程；`debug_start` 保留为启动快捷入口。未显式传入 `cwd` 时，服务使用目标程序所在目录作为启动目录。启动或附加前会调用 IDA 的 headless 调试器加载接口，候选来源依次为工具参数 `backend`、`setting.toml` 的 `[debugger].backend_candidates`、环境变量 `IDA_STDIO_MCP_DEBUGGER`、平台默认 `win32` / `linux` / `mac`。寄存器、栈、内存、栈回溯只在调试进程处于 suspended 状态时执行；否则返回明确 `unsupported` 与下一步诊断。运行时验证可组合 `debug_add_breakpoints`、`debug_continue`、`debug_run_to`、`debug_step`、`debug_registers`、`debug_stack`、`debug_read_memory`、`debug_capture_calls` 与 `debug_export_timeline`。

外部脚本、VM 字节码或封包分析通过配置型 analyzer 接入：在 `setting.toml` 的 `external_analyzers` 中配置命令后，用 `run_external_analyzer` 执行并导入 JSON 输出；已有 JSON 可用 `import_analysis_artifact` 导入，随后用 `correlate_analysis_artifact` 与当前 IDB 的字符串、函数、地址、hash 常量和路径线索关联。`scan_dispatchers` 会做通用 hash/switch/table/indirect-call 候选扫描，不绑定特定游戏引擎或脚本格式。

## 推荐工作流

AI Agent 分析样本时建议遵循固定顺序：

```text
get_workspace_state -> open_target -> triage_binary -> investigate_string / explain_function -> export_report
```

常用高层工具：

| 工具 | 用途 |
| --- | --- |
| `get_workspace_state` | 查看 runtime、当前 session、working IDB、最近目标与推荐下一步 |
| `open_target` | 完整加载样本和调试符号，创建隔离 working IDB；默认不等待全库自动分析 |
| `triage_binary` | 生成入口点、关键函数、导入分类、字符串索引状态与托管质量摘要 |
| `investigate_string` | 从错误文案、URL、路径、协议字段或字符串地址追到使用点和所属函数 |
| `explain_function` | 聚合函数画像、伪代码或 C#、调用关系、字符串、常量与可选 microcode 线索 |
| `trace_input_to_check` | 围绕输入、鉴权、路径或协议字段做轻量数据流追踪 |
| `decompile_function` | 直接读取单个函数的高层表示 |
| `export_report` | 导出结构化分析报告 |
| `save_workspace` | 保存当前 working IDB，或显式导出到指定路径 |
| `close_target` | 关闭当前或指定 session |

## 字符串与脚本契约

`list_strings`、`find_strings`、`search_regex` 与 `investigate_string` 会为当前 working IDB 构建并复用会话级字符串缓存。首次字符串查询可能触发 IDA 字符串枚举；后续同一工作库内的字符串搜索直接复用缓存。返回结构统一包含 `data`、`next_offset`、`statistics`、`cache` 与 `recommended_next_tools`。`limit` / `count` 只控制返回行数，`cache.truncated_by_scan_limit=true` 表示当前缓存是受控样本，未命中不能视为全库不存在。

`evaluate_python` 与 `execute_python_file` 作用于当前或指定 session 的 working IDB。脚本结果返回受控大小的 `stdout`、`stderr`、`result`、`local_keys` 与可选 `locals_summary`；服务不会回传完整局部变量表。自定义脚本应把小型结构化摘要赋给 `result`。当 `stdout`、`stderr` 或 `result` 超过返回阈值时，服务会把完整内容写入运行时目录，并在 `artifacts` 中返回 `path`、`sha256`、`size` 与 `schema`。

## Native 分析

1. 使用 `open_target` 打开 ELF、PE、Mach-O 等 native 样本。
2. 使用 `triage_binary` 查看入口点、导入分类、关键函数和字符串索引状态。
3. 对入口函数、校验函数或高 xref 函数调用 `explain_function`。
4. 对错误文案、路径、URL、协议字段调用 `investigate_string`。
5. 需要交付结果时调用 `export_report`。

Hex-Rays 可用时，`decompile_function` 与 `explain_function` 返回 C 伪代码。缺少 Hex-Rays 时，服务返回汇编降级结果。

大型 native 样本默认采用轻量打开：IDA loader、导入表、PDB/调试符号与 working IDB 会正常加载和保存，但 `open_target` 不等待全库自动分析队列清空。需要等待全库自动分析时可显式传入 `run_auto_analysis=true`；UE、Chrome、游戏客户端等大型目标带有大型 PDB 时，全量自动分析可能持续几十分钟到数小时，应把 MCP `tool_timeout_sec` 按目标设置到 `3600` 秒或 `21600` 秒级别。轻量打开后可由 `triage_binary`、`explain_function`、`investigate_string` 对具体目标触发定点分析。

`open_target` 的 `metadata` 字段会返回打开结果报告，包括 `database_loaded`、`working_idb_ready`、`auto_analysis_waited`、`analysis_completeness`、PDB 路径、同目录 PDB 列表、打开耗时、working IDB 大小、入口数量和 segment 预览。AI Agent 应根据这些字段判断当前结果可信边界。

## Unity/.NET 分析

1. 使用 `open_target` 打开 `Assembly-CSharp.dll` 或其他托管程序集。
2. 使用 `triage_binary` 查看 managed summary、类型目录、关键方法和 C# 反编译状态。
3. 使用 `investigate_string` 定位 UI 文案、保存路径、网络端点、配置键或脚本关键字。
4. 对托管方法调用 `decompile_function` 或 `explain_function`，优先返回 `ilspycmd` C# 结果。
5. 在报告中查看 `managed_summary` 与质量等级。

## 工作 IDB 与保存

`open_target` 会为每个 session 创建独立工作库：

```text
.runtime/sessions/<session_id>/working.i64
```

后续分析、注释、类型、补丁和脚本操作作用于 working IDB。`patch_bytes` 与 `patch_assembly` 直接写入；`patch_diff` 用于预览字节差异，`patch_history` 读取当前工作库补丁记录，`rollback_patch` 按补丁 ID 恢复写入前字节。默认 `save_workspace` 保存当前工作库。传入 `path` 时，服务会导出到用户指定位置。

## MCP Prompts

服务实现 `prompts/list` 与 `prompts/get`，内置模板：

- `triage-native`
- `triage-managed`
- `string-led-investigation`
- `microcode-investigation`

这些模板用于让 MCP 客户端了解推荐调用顺序和分析策略。

## MCP Resources

服务提供工作区、能力矩阵、函数、字符串、导入、调用图、托管摘要、工具文档等资源。资源读取使用统一 JSON envelope，便于客户端处理成功、降级、错误和下一步建议。

## 开发

```powershell
uv sync
uv run basedpyright
uv run python -m unittest discover -s tests/unit
```

有 IDA 9.3+ 环境时运行集成测试：

```powershell
$env:IDADIR = '<IDA_INSTALL_DIR>'
uv run python -m unittest discover -s tests/integration
```

## 许可证

本项目使用 MIT License。详见 [LICENSE](LICENSE)。
