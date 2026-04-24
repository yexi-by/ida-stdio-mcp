# ida-stdio-mcp

ida-stdio-mcp 是面向 AI Agent 的 IDA Pro 9.3+ MCP 服务。服务通过 IDA headless runtime 提供二进制分析、函数解释、字符串牵引、托管程序集反编译、数据流追踪、报告导出、调试与受控写回能力。

当前 V2 特性分支：[codex/ida93-ai-state-refactor](https://github.com/yexi-by/ida-stdio-mcp/tree/codex/ida93-ai-state-refactor)

## 特性

- IDA 9.3+ runtime 校验：启动时使用 `idapro.get_library_version()` 检查版本，低于 9.3 直接失败。
- AI 工作流工具面：默认 `slim` 只暴露高层逆向入口，降低工具选择成本。
- 完整专家工具面：`expert` 可暴露 IDAPython、补丁、调试、microcode 实验能力。
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
git checkout codex/ida93-ai-state-refactor
uv sync
uv run ida-stdio-mcp --help
```

如需托管程序集 C# 反编译，可安装 `ilspycmd`：

```powershell
dotnet tool install --global ilspycmd
```

## Codex MCP 配置

以下配置开启最大能力，适合本地可信环境中的 Codex 或高级 Agent。请将 `<UV_PATH>`、`<REPO_PATH>` 和 `<IDA_INSTALL_DIR>` 替换为本机实际路径。

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
    "--unsafe",
    "--debugger",
    "--isolated-contexts",
    "--tool-surface",
    "expert",
]
startup_timeout_sec = 240
tool_timeout_sec = 1800

[mcp_servers.ida-stdio-mcp.env]
IDADIR = '<IDA_INSTALL_DIR>'
```

面向普通 MCP 客户端时建议使用默认 `slim` 工具面：

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
    "slim",
]
```

## 工具面

| 工具面 | 适用场景 | 能力范围 |
| --- | --- | --- |
| `slim` | 默认自主逆向工作流 | 高层工作区、打开样本、triage、字符串牵引、函数解释、数据流、报告、保存、关闭 |
| `full` | 精细分析与结构化查询 | 暴露函数、字符串、导入、xref、类型、结构体、字节、调用图等底层工具 |
| `expert` | 高级本地 Agent 与实验分析 | 在 full 基础上暴露 IDAPython、调试、补丁与 microcode 实验能力 |

危险能力由硬门控控制：

| 参数 | 启用能力 |
| --- | --- |
| `--unsafe` | 写回、补丁、IDAPython、执行脚本、microcode mutation |
| `--debugger` | 断点、单步、继续、寄存器、调试内存读写 |
| `--tool-surface expert` | 实验性 expert 工具 |

microcode mutation 需要同时启用 `--unsafe --tool-surface expert`。

## 推荐工作流

AI Agent 使用 V2 时建议遵循固定顺序：

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

## Native 分析

1. 使用 `open_target` 打开 ELF、PE、Mach-O 等 native 样本。
2. 使用 `triage_binary` 查看入口点、导入分类、关键函数和字符串索引状态。
3. 对入口函数、校验函数或高 xref 函数调用 `explain_function`。
4. 对错误文案、路径、URL、协议字段调用 `investigate_string`。
5. 需要交付结果时调用 `export_report`。

Hex-Rays 可用时，`decompile_function` 与 `explain_function` 返回 C 伪代码。缺少 Hex-Rays 时，服务返回汇编降级结果。

大型 native 样本默认采用轻量打开：IDA loader、导入表、PDB/调试符号与 working IDB 会正常加载和保存，但 `open_target` 不等待全库自动分析队列清空。需要等待全库自动分析时可显式传入 `run_auto_analysis=true`；对 UE、Chrome、游戏客户端等大型目标，推荐保持默认值，并由 `triage_binary`、`explain_function`、`investigate_string` 对具体目标触发定点分析。

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

后续分析、注释、类型、补丁和脚本操作作用于 working IDB。默认 `save_workspace` 保存当前工作库。传入 `path` 时，服务会导出到用户指定位置。

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
