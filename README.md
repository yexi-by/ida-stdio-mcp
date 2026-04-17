# ida-stdio-mcp

IDA Pro 无头模式 MCP 服务器。

灵感来自 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，本项目专注于 IDA Pro 9.2+ 的无头（headless）分析能力，通过 stdio 协议提供 MCP 服务。

## 环境准备

### 必需

- Python 3.11+
- IDA Pro 9.2+（需要 idalib 支持）
- [uv](https://docs.astral.sh/uv/) 包管理器

### 配置 IDA 环境

设置 `IDADIR` 环境变量指向 IDA 安装目录：

```powershell
# Windows
$env:IDADIR = "C:\Program Files\IDA Professional 9.2"

# Linux/macOS
export IDADIR="/opt/ida-9.2"
```

### 安装依赖

```powershell
uv sync
```

## 快速开始

```powershell
# 启动服务
uv run ida-stdio-mcp

# 启动时直接打开样本
uv run ida-stdio-mcp path/to/sample.exe

# 启用危险工具（写操作、Python 执行）
uv run ida-stdio-mcp --unsafe

# 启用调试器工具
uv run ida-stdio-mcp --debugger

# 按 context_id 隔离不同 agent/工作流
uv run ida-stdio-mcp --isolated-contexts
```

## MCP 服务配置

### Claude Desktop (JSON)

编辑 Claude Desktop 配置文件：

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "D:/work/ida-stdio-mcp", "--no-sync", "ida-stdio-mcp"],
      "env": {
        "IDADIR": "C:\\Program Files\\IDA Professional 9.2"
      }
    }
  }
}
```

启动时打开样本：

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "D:/work/ida-stdio-mcp", "--no-sync", "ida-stdio-mcp", "D:/samples/target.exe"],
      "env": {
        "IDADIR": "C:\\Program Files\\IDA Professional 9.2"
      }
    }
  }
}
```

启用危险工具：

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "D:/work/ida-stdio-mcp", "--no-sync", "ida-stdio-mcp", "--unsafe"],
      "env": {
        "IDADIR": "C:\\Program Files\\IDA Professional 9.2"
      }
    }
  }
}
```

### Kilo / 其他 TOML 配置

```toml
[mcpServers.ida-stdio-mcp]
command = "uv"
args = ["run", "--directory", "D:/work/ida-stdio-mcp", "--no-sync", "ida-stdio-mcp"]

[mcpServers.ida-stdio-mcp.env]
IDADIR = "C:\\Program Files\\IDA Professional 9.2"
```

## 配置文件说明

项目使用 `setting.toml` 配置运行参数：

```toml
[logging]
level = "INFO"                    # 日志级别
directory = "logs"                # 日志目录

[server]
protocol_version = "2025-06-18"   # MCP 协议版本
server_name = "ida-stdio-mcp"
server_version = "0.2.0"
default_input_path = ""           # 默认打开的样本路径

[feature_gates]
allow_unsafe = false              # 是否允许危险写操作
allow_debugger = false            # 是否启用调试器工具
isolated_contexts = false         # 是否强制按 context_id 隔离不同 agent/工作流

[limits]
default_page_size = 100           # 默认分页大小
max_page_size = 1000              # 最大分页大小
max_search_hits = 1000            # 最大搜索命中数
max_callgraph_depth = 4           # 调用图最大深度

[directory_analysis]
recursive = true                  # 是否递归扫描目录
max_candidates = 20               # 最大候选文件数
max_deep_analysis = 5             # 最大深度分析数
include_extensions = [".exe", ".dll", ".elf", ".so"]
exclude_patterns = ["*.i64", "*.idb"]
```

## 功能概览

## 上下文隔离（重点）

默认情况下，服务使用共享默认上下文 `stdio:default`。这适合：

- 单 agent
- 单工作流
- 串行切换多个会话

如果你要在**同一个 MCP 进程**里同时服务多个 agent / 多条并发工作流，必须开启：

```powershell
uv run ida-stdio-mcp --isolated-contexts
```

或在 `setting.toml` 中设置：

```toml
[feature_gates]
isolated_contexts = true
```

开启后行为会变成：

- 所有会话按 `context_id` 隔离
- `list_binaries` 只返回当前 `context_id` 可见的会话
- `switch_binary` / `close_binary` / `save_binary` / `deactivate_binary`
  只能操作当前 `context_id` 自己的会话
- 所有会话资源（例如 `ida://functions`、`ida://sessions`）都要求显式传 `context_id`

### 开启隔离后的调用约定

启用 `--isolated-contexts` 后，所有会话相关工具都必须显式传 `context_id`：

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "D:/samples/a.exe",
    "session_id": "sess-a1",
    "context_id": "agent-1"
  }
}
```

```json
{
  "name": "list_binaries",
  "arguments": {
    "context_id": "agent-1"
  }
}
```

```json
{
  "uri": "ida://sessions",
  "context_id": "agent-1"
}
```

如果不传 `context_id`，服务会 **Fail-Fast** 返回错误，而不是退回共享上下文。

### 会话管理

| 工具 | 说明 |
|------|------|
| `health` | 返回运行时健康状态 |
| `warmup` | 预热当前会话（等待自动分析完成） |
| `open_binary` | 打开二进制文件，创建新会话 |
| `close_binary` | 关闭指定会话 |
| `switch_binary` | 切换当前默认会话 |
| `list_binaries` | 列出所有打开的会话 |
| `current_binary` | 返回当前默认会话信息 |
| `save_binary` | 保存 IDB 文件 |
| `deactivate_binary` | 解除默认会话绑定 |
| `analyze_directory` | 批量扫描目录并分析候选二进制 |

### 只读分析

| 工具 | 说明 |
|------|------|
| `survey_binary` | 二进制概览（架构、段、入口点等） |
| `list_functions` | 分页列出函数 |
| `get_function` | 获取函数详情（含 callers/callees） |
| `get_function_profile` | 函数画像（复杂度、调用特征） |
| `analyze_functions` | 批量分析多个函数 |
| `decompile_function` | 反编译函数（native 返回伪代码；managed 优先返回 C# 源码） |
| `disassemble_function` | 反汇编函数 |
| `list_globals` | 列出全局变量 |
| `list_imports` / `query_imports` | 导入表查询 |
| `get_xrefs_to` / `query_xrefs` | 交叉引用查询 |
| `get_xrefs_to_field` | 结构字段交叉引用 |
| `get_callers` / `get_callees` | 调用者/被调用者 |
| `get_basic_blocks` | 函数基本块 |
| `list_strings` / `find_strings` | 字符串列表/搜索 |
| `search_regex` | 正则搜索字符串 |
| `find_bytes` | 字节模式搜索 |
| `find_items` / `query_instructions` | 高级搜索 |
| `read_bytes` / `read_ints` / `read_strings` | 读取内存 |
| `read_global_values` | 读取全局变量值 |
| `get_stack_frame` | 函数栈帧信息 |
| `read_struct` / `search_structs` | 结构体定义 |
| `query_types` / `inspect_type` | 类型查询 |
| `export_functions` | 导出函数（JSON/C头文件/原型） |
| `build_callgraph` | 构建调用图 |
| `analyze_function` | 单函数综合分析 |
| `analyze_component` | 组件级分析（多函数） |
| `trace_data_flow` | 数据流追踪 |
| `convert_integer` | 整数进制转换 |

### 危险工具（需 `--unsafe`）

| 工具 | 说明 |
|------|------|
| `set_comments` / `append_comments` | 设置/追加注释 |
| `rename_symbols` | 重命名符号 |
| `define_function` | 定义函数 |
| `define_code` | 定义代码 |
| `undefine_items` | 取消定义 |
| `patch_assembly` | 汇编补丁 |
| `patch_bytes` | 字节补丁 |
| `write_ints` | 写入整数 |
| `declare_types` | 声明 C 类型 |
| `upsert_enum` | 创建/更新枚举 |
| `set_types` / `apply_types` | 设置类型 |
| `infer_types` | 推断类型 |
| `declare_stack_variables` | 声明栈变量 |
| `delete_stack_variables` | 删除栈变量 |
| `evaluate_python` | 执行 Python 代码 |
| `execute_python_file` | 执行 Python 脚本 |

### 调试器工具（需 `--debugger`）

| 工具 | 说明 |
|------|------|
| `debug_start` / `debug_exit` | 启动/退出调试会话 |
| `debug_continue` | 继续执行 |
| `debug_run_to` | 运行到指定地址 |
| `debug_step_into` / `debug_step_over` | 单步进入/越过 |
| `debug_list_breakpoints` | 列出断点 |
| `debug_add_breakpoints` / `debug_delete_breakpoints` | 添加/删除断点 |
| `debug_toggle_breakpoints` | 启停断点 |
| `debug_registers` | 读取寄存器 |
| `debug_stacktrace` | 读取调用栈 |
| `debug_read_memory` / `debug_write_memory` | 读写调试进程内存 |

### 资源（Resources）

通过 MCP resources 协议访问。以下为核心资源，完整列表可通过 `resources/list` 或读取 `ida://capability-matrix` 获取。

**全局资源（无需活动会话）**
- `ida://capability-matrix` - 全局能力边界文档
- `ida://docs/tools` - 全部工具 schema 与文档
- `ida://docs/tool/{name}` - 单个工具文档
- `ida://session/current` - 当前默认会话（开启隔离后需传 `context_id`）
- `ida://sessions` - 当前上下文可见的会话列表（开启隔离后需传 `context_id`）

**会话资源（需活动会话）**
- `ida://idb/metadata` - IDB 元数据
- `ida://idb/segments` - 段信息
- `ida://idb/entrypoints` - 入口点
- `ida://idb/capabilities` - 当前能力矩阵
- `ida://survey` - 二进制概览
- `ida://types` / `ida://structs` - 类型/结构体列表
- `ida://functions` - 函数列表
- `ida://functions/profiles` - 函数画像摘要
- `ida://globals` / `ida://imports` - 全局变量/导入表
- `ida://imports/categories` - 导入分类视图
- `ida://strings` - 字符串列表
- `ida://callgraph/summary` - 调用图摘要
- `ida://managed/summary` - .NET 托管概览
- `ida://managed/types` - 托管类型目录
- `ida://managed/namespaces` - 托管命名空间

**模板资源**
- `ida://function/{query}` - 函数详情
- `ida://function-profile/{query}` - 函数画像
- `ida://decompile/{query}` - 反编译结果
- `ida://struct/{name}` - 结构体定义
- `ida://type/{name}` - 类型详情
- `ida://basic-blocks/{addr}` - 基本块
- `ida://stack-frame/{addr}` - 栈帧
- `ida://xrefs/from/{addr}` - 交叉引用
- `ida://callgraph/{root}` - 调用图
- `ida://data-flow/{addr}` - 数据流
- `ida://import/{name}` / `ida://export/{name}` - 导入/导出符号
- `ida://managed/method/{query}` - 托管方法

## 命令行参数

| 参数 | 说明 |
|------|------|
| `input_path` | 启动时打开的样本路径 |
| `--config <path>` | 配置文件路径，默认 `setting.toml` |
| `--unsafe` | 启用危险工具（写操作、Python 执行） |
| `--debugger` | 启用调试器工具 |
| `--isolated-contexts` | 按 `context_id` 隔离不同 agent/工作流的默认上下文 |
| `--profile <path>` | 工具白名单配置文件 |

## 测试

```powershell
# 类型检查
uv run basedpyright

# 单元测试
uv run python -m unittest discover -s tests/unit

# 集成测试
uv run python -m unittest discover -s tests/integration

# 真实 headless 测试
uv run ida-stdio-mcp-test tests/fixtures/crackme03.elf
```
