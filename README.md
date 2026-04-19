# ida-stdio-mcp

让 AI 助手直接操控 IDA Pro 进行逆向分析的 MCP 服务器。

本项目灵感来自 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)，专注于 IDA Pro 9.2+ 的命令行模式（headless），让支持 MCP 的 AI 客户端能够：

- 打开并分析二进制文件
- 读取样本摘要、入口点、关键函数与关键字符串
- 反编译函数、查看汇编代码
- 搜索字符串、追踪字符串使用点、查看交叉引用
- 重命名符号、添加注释
- 导出结构化分析结果
- 执行 Python 脚本
- 调试程序

## 特性

- **纯命令行运行** - 无需启动 IDA GUI，适合自动化和 CI/CD
- **MCP 协议** - 兼容支持 MCP 的 AI 客户端
- **多会话支持** - 可同时打开多个二进制文件
- **安全可控** - 写操作和调试功能默认关闭，需显式启用
- **任务化入口** - 提供样本摘要、字符串使用点追踪、完整分析导出等高层工具

## 环境要求

- Python 3.11+
- IDA Pro 9.2+（需包含 idalib）
- [uv](https://docs.astral.sh/uv/) 包管理器

## 安装

### 1. 设置 IDA 环境变量

```powershell
# Windows
$env:IDADIR = "C:\Program Files\IDA Professional 9.2"

# Linux/macOS
export IDADIR="/opt/ida-9.2"
```

### 2. 安装依赖

```powershell
uv sync
```

### 3. 验证安装

```powershell
uv run ida-stdio-mcp --help
```

## 快速开始

```powershell
# 启动服务
uv run ida-stdio-mcp

# 启动时打开样本
uv run ida-stdio-mcp path/to/sample.exe

# 启用写操作和脚本执行
uv run ida-stdio-mcp --unsafe

# 启用调试器
uv run ida-stdio-mcp --debugger
```

## 配置 AI 客户端

当前主流 MCP 客户端通常使用 **JSON 配置** 或 **TOML 配置**。以下示例使用占位符：

- `<repo-root>`：本项目所在的绝对路径
- `<ida-dir>`：IDA 安装目录
- `<sample-path>`：可选，启动时自动打开的样本路径

### JSON 配置格式

**基础配置：**

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "<repo-root>", "--no-sync", "ida-stdio-mcp"],
      "env": {
        "IDADIR": "<ida-dir>"
      }
    }
  }
}
```

**启动时自动加载样本：**

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "<repo-root>", "--no-sync", "ida-stdio-mcp", "<sample-path>"],
      "env": {
        "IDADIR": "<ida-dir>"
      }
    }
  }
}
```

**启用写操作与调试能力：**

```json
{
  "mcpServers": {
    "ida-stdio-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "<repo-root>", "--no-sync", "ida-stdio-mcp", "--unsafe", "--debugger"],
      "env": {
        "IDADIR": "<ida-dir>"
      }
    }
  }
}
```

### TOML 配置格式

**基础配置：**

```toml
[mcpServers.ida-stdio-mcp]
command = "uv"
args = ["run", "--directory", "<repo-root>", "--no-sync", "ida-stdio-mcp"]

[mcpServers.ida-stdio-mcp.env]
IDADIR = "<ida-dir>"
```

**启动时自动加载样本：**

```toml
[mcpServers.ida-stdio-mcp]
command = "uv"
args = ["run", "--directory", "<repo-root>", "--no-sync", "ida-stdio-mcp", "<sample-path>"]

[mcpServers.ida-stdio-mcp.env]
IDADIR = "<ida-dir>"
```

**启用写操作与调试能力：**

```toml
[mcpServers.ida-stdio-mcp]
command = "uv"
args = ["run", "--directory", "<repo-root>", "--no-sync", "ida-stdio-mcp", "--unsafe", "--debugger"]

[mcpServers.ida-stdio-mcp.env]
IDADIR = "<ida-dir>"
```

## 命令行参数

| 参数 | 说明 |
|------|------|
| `<binary_path>` | 启动时自动打开的二进制文件 |
| `--config <path>` | 配置文件路径，默认 `setting.toml` |
| `--unsafe` | 启用写操作、符号重命名、Python 执行等 |
| `--debugger` | 启用调试器功能 |
| `--profile <path>` | 工具白名单配置 |
| `--isolated-contexts` | 多 agent 隔离模式 |

## 工具列表

运行时工具集分为公共读工具、`--unsafe` 写工具和 `--debugger` 调试工具三层。常见逆向工作流可以直接从 `describe_capabilities`、`summarize_binary`、`find_string_usage`、`export_full_analysis` 进入。

### 会话管理

| 工具 | 说明 |
|------|------|
| `open_binary` | 打开二进制文件 |
| `close_binary` | 关闭文件 |
| `list_binaries` | 列出已打开的文件 |
| `switch_binary` | 切换当前活动文件 |
| `save_binary` | 保存 IDB 数据库 |

### 信息查询

| 工具 | 说明 |
|------|------|
| `describe_capabilities` | 返回工具目录、能力矩阵、门控状态与推荐入口 |
| `survey_binary` | 文件概览：架构、段、入口点 |
| `summarize_binary` | 样本摘要：入口点、关键函数、关键字符串、导入分类、推荐下一步 |
| `list_functions` | 列出所有函数 |
| `get_function` | 获取函数详情 |
| `decompile_function` | 反编译函数（native 返回伪代码，.NET 返回 C#） |
| `disassemble_function` | 反汇编函数 |
| `list_imports` | 导入表 |
| `list_globals` | 全局变量 |
| `list_strings` | 字符串列表 |
| `get_xrefs_to` | 交叉引用 |
| `read_struct` | 结构体定义 |

### 搜索功能

| 工具 | 说明 |
|------|------|
| `find_strings` | 搜索字符串 |
| `find_string_usage` | 按字符串或字符串地址追踪使用点，返回字符串、xref/引用点、所属函数 |
| `find_bytes` | 搜索字节序列 |
| `search_regex` | 正则搜索 |

### 写操作（需 `--unsafe`）

| 工具 | 说明 |
|------|------|
| `rename_symbols` | 重命名函数/变量 |
| `set_comments` | 添加注释 |
| `patch_bytes` | 修改字节 |
| `declare_types` | 定义数据类型 |
| `evaluate_python` | 执行 Python 代码 |

### 调试器（需 `--debugger`）

| 工具 | 说明 |
|------|------|
| `debug_start` | 启动调试 |
| `debug_step_into` | 单步进入 |
| `debug_step_over` | 单步跳过 |
| `debug_continue` | 继续执行 |
| `debug_registers` | 查看寄存器 |
| `debug_read_memory` | 读取内存 |

### 导出与批处理

| 工具 | 说明 |
|------|------|
| `export_functions` | 导出函数级分析结果，支持 JSON、原型列表、近似头文件 |
| `export_full_analysis` | 导出当前 IDB 的结构化分析总包，包含 metadata、entrypoints、imports、globals、strings、types、structs、functions |

## 推荐工作流

### 单样本开局

```text
open_binary -> summarize_binary -> list_functions / find_string_usage -> decompile_function / read_struct / query_types
```

### 字符串驱动的定位流程

```text
find_string_usage -> get_function_profile -> decompile_function -> get_xrefs_to
```

### 导出与复盘

```text
export_full_analysis -> export_functions
```

## 配置文件

项目根目录的 `setting.toml`：

```toml
[logging]
level = "INFO"
directory = "logs"

[server]
protocol_version = "2025-06-18"
server_name = "ida-stdio-mcp"
server_version = "0.2.0"

[feature_gates]
allow_unsafe = false
allow_debugger = false
isolated_contexts = false

[runtime_workspace]
directory = ".runtime"
symbol_cache_directory = ".runtime/symbol-cache"

[limits]
default_page_size = 100
max_page_size = 1000
```

## 开发

```powershell
# 类型检查
uv run basedpyright

# 运行测试
uv run python -m unittest discover -s tests/unit
```

## 致谢

本项目受到 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的启发，感谢作者的开拓性工作。

## License

MIT
