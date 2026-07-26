# ida-re-mcp

`ida-re-mcp` 是面向 AI Agent 的 IDA Pro 9.3+ headless MCP 服务。它通过标准
stdio transport 向 Codex、Claude Code、OpenCode 等 MCP Host 提供 Native
静态逆向、Hex-Rays、Unity IL2CPP 原生注解、事务化 IDB 修改，以及 Windows
本机 x64 动态调试能力。

服务不会修改原始样本。分析结果保存在 workspace 的不可变 revision 中；所有 IDB
写入先进入 staging，经过冷验证后才原子发布。

## 快速开始

### 1. 准备环境

需要：

- IDA Pro 9.3+ 及有效许可证；
- Python 3.13；
- [uv](https://docs.astral.sh/uv/)；
- Windows x64（仅动态调试需要）；
- Hex-Rays Decompiler（仅伪代码和 microcode 能力需要）。

克隆项目，并把开发环境放在工作树外：

```powershell
git clone https://github.com/yexi-by/ida-re-mcp.git
$repo = (Resolve-Path .\ida-re-mcp).Path
Set-Location $repo
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\ida-re-mcp\dev-venv"
uv python install 3.13
uv sync --locked --directory $repo
```

### 2. 配置 IDA 与运行目录

编辑项目根目录的 `config.toml`，把 `[runtime]` 中的三个绝对路径改为本机路径：

```toml
schema_version = "1"

[runtime]
data_root = 'C:\Users\you\AppData\Local\ida-re-mcp\data'
log_root = 'C:\Users\you\AppData\Local\ida-re-mcp\logs'
ida_dir = 'C:\Program Files\IDA Professional 9.3'

[policy]
authoring = true
debug_launch = true
debug_attach = false
expert = false

[workers]
analysis_limit = 1
debug_limit = 1
idle_seconds = 300

[storage]
quota_gib = 20
retained_revisions = 3
```

`debug_attach` 允许附加到外部进程，`expert` 会开放可访问文件、网络和子进程的
IDAPython 执行环境；只在明确需要并理解风险时启用。

用同一份配置检查 Python、存储和 IDA worker：

```powershell
uv run --locked --directory $repo ida-re-mcp doctor --config "$repo\config.toml"
```

输出中的 `healthy` 和 `worker.available` 都应为 `true`。

### 3. 接入 MCP Host

下面所有示例都直接从克隆的工作树运行，不依赖预先安装的 wheel。把示例路径替换为
实际项目路径；如果 Host 找不到 `uv`，将 `command` 改为 `uv.exe` 的绝对路径。

Codex 的 `config.toml`：

```toml
[mcp_servers.ida-re-mcp]
command = "uv"
args = ["run", "--locked", "--directory", 'D:\path\to\ida-re-mcp', "ida-re-mcp", "serve", "--config", 'D:\path\to\ida-re-mcp\config.toml']
cwd = 'D:\path\to\ida-re-mcp'
startup_timeout_sec = 240.0
tool_timeout_sec = 3600.0
enabled = true

[mcp_servers.ida-re-mcp.env]
UV_PROJECT_ENVIRONMENT = 'C:\Users\you\AppData\Local\ida-re-mcp\dev-venv'
PYTHONDONTWRITEBYTECODE = "1"
PYTHONUTF8 = "1"
```

Claude Code 项目根目录的 `.mcp.json`：

```json
{
  "mcpServers": {
    "ida-re-mcp": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "run",
        "--locked",
        "--directory",
        "D:\\path\\to\\ida-re-mcp",
        "ida-re-mcp",
        "serve",
        "--config",
        "D:\\path\\to\\ida-re-mcp\\config.toml"
      ],
      "env": {
        "UV_PROJECT_ENVIRONMENT": "C:\\Users\\you\\AppData\\Local\\ida-re-mcp\\dev-venv",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1"
      }
    }
  }
}
```

Claude Code 的 MCP schema 没有 `cwd` 字段，因此不要自行添加。

OpenCode stable 的 `opencode.json`：

```json
{
  "mcp": {
    "ida-re-mcp": {
      "type": "local",
      "command": [
        "uv",
        "run",
        "--locked",
        "--directory",
        "D:\\path\\to\\ida-re-mcp",
        "ida-re-mcp",
        "serve",
        "--config",
        "D:\\path\\to\\ida-re-mcp\\config.toml"
      ],
      "cwd": "D:\\path\\to\\ida-re-mcp",
      "environment": {
        "UV_PROJECT_ENVIRONMENT": "C:\\Users\\you\\AppData\\Local\\ida-re-mcp\\dev-venv",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1"
      },
      "enabled": true,
      "timeout": 3600000
    }
  }
}
```

保存配置并重启 Host 后，确认 `ida-re-mcp` 工具目录可见。

## Agent 的基本调用顺序

1. 调用 `workspace.create` 导入 PE 或 ELF Native 样本，并保存
   `workspace_id` 与 `analysis_operation_id`。
2. 调用 `operation.wait` 等待首次分析完成，保存返回的不可变 `revision`。
3. 所有静态查询都显式传入 `workspace_id` 和 `revision`。
4. 修改 IDB 时先调用 `change.prepare`，再调用 `change.apply`；成功后改用新 revision。
5. 用 `report.build` 或 `workspace.export` 生成 artifact。
6. 动态调试时保存 `debug_session_id`；寄存器、线程、栈和内存读取必须使用当前
   suspended stop 的 `stop_id`。

查询结果中的 `coverage` 和 `provenance` 是结论可信度的一部分。`partial` 表示 IDA
没有完整证据，不应由 Agent 擅自补成确定事实。

IL2CPP 导入只接受项目定义的 canonical NDJSON，不直接消费 Il2CppDumper 或
Il2CppInspector 的原始输出。可运行示例位于
`tests/fixtures/src/il2cpp_bundle_example.ndjson`。

## 能力边界

- 静态分析覆盖 PE32+ 与 ELF64，包括函数、反汇编、交叉引用、字符串、导入导出、
  类型、控制流、调用图和数据流查询。
- 安装 Hex-Rays 时提供伪代码、ctree 与 microcode 查询。
- IDB 修改采用 staging、冷验证和 CAS 发布；失败、取消或 worker 崩溃不会改写已发布
  revision。
- IL2CPP bundle 可事务化写入类型、方法、符号和注释。
- 动态调试限定为 Windows 本机 x64，并依赖真实 IDA debugger 事件。
- `expert.execute` 默认关闭；启用后属于开放世界 IDAPython，不是沙箱。

项目不提供远程调试、普通 .NET/Mono workspace、进程内存写入、恶意样本沙箱、
IL2CPP 转换器或外部分析器执行链。

## 本地验证

常规质量门禁全部在本机运行，不需要 GitHub Actions：

```powershell
./scripts/run_quality.ps1
```

该脚本依次执行锁文件检查、Ruff format/check、basedpyright strict、unit/integration
pytest、fixture 可复现性检查、wheel 隔离安装和 stdio smoke；任一步失败都会立即以
非零码退出。

使用受许可的 IDA 9.3+ 运行真实静态、Hex-Rays 与 debugger 门禁：

```powershell
$env:IDADIR = 'C:\Program Files\IDA Professional 9.3'
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\ida-re-mcp\dev-venv"
$gateRoot = Join-Path $env:TEMP ("ida-re-mcp-gate-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $gateRoot | Out-Null

uv run --locked pytest -q tests/ida -m "ida and not debugger" --basetemp "$gateRoot\static"
uv run --locked pytest -q tests/ida -m "ida and debugger" --basetemp "$gateRoot\debugger"
```

IDA 门禁不会用 skip 伪装成功：缺少许可证、`IDADIR`、Hex-Rays 或真实 debugger
事件时会明确失败。

## 许可证

[MIT](LICENSE)
