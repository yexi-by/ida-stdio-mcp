# ida-re-mcp

`ida-re-mcp` 是面向 AI Agent 的 IDA Pro 9.3+ headless stdio MCP 服务。它以显式
workspace、不可变 revision 和进程隔离 worker 为基础，提供 Native 静态逆向、
Unity IL2CPP 原生注解、事务化 IDB 写回，以及 Windows 本机 x64 动态调试。

当前版本为 `1.0.0.dev0`。服务使用官方 Python MCP SDK 的标准生命周期与 stdio
transport，工具目录在启动时固定，只广告 tools 与不可变 resources。项目不实现自有
协议协商、JSON-RPC parser、Tasks、prompts、sampling、completions 或交互式审批。

## 环境要求

- Python `3.13`；
- `uv`；
- IDA Pro `9.3+` 及对应许可证；
- Windows x64，用于动态调试；
- LLVM/LLD `22.1.8`，仅在重建测试 fixture 时需要。

开发虚拟环境与运行数据必须位于 Git 工作树外：

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\ida-re-mcp\dev-venv"
uv python install 3.13
uv sync --locked
```

IDA 安装目录由 `idapro` 运行环境解析。开发机可按 IDA 安装要求设置 `IDADIR`，然后
执行：

```powershell
ida-re-mcp doctor --config C:\path\to\config.toml
```

## CLI

```powershell
ida-re-mcp serve
ida-re-mcp serve --config C:\path\to\config.toml
ida-re-mcp doctor --config C:\path\to\config.toml
ida-re-mcp gc --dry-run
ida-re-mcp gc --apply
```

配置使用严格 TOML schema，示例见
[config.example.toml](config.example.toml)。workspace、日志、artifact、checkout、
staging、临时文件和虚拟环境都位于工作树外。

`[runtime]` 可在一份服务配置中声明 `data_root`、`log_root` 与 `ida_dir`。环境变量
`IDA_RE_MCP_DATA_ROOT`、`IDA_RE_MCP_LOG_ROOT` 仍可覆盖前两项，但不再要求每个 MCP
host 手工分配不同目录。

每条 stdio 连接拥有随机、独立的 session 目录。operation、change set、cursor 私钥、
checkout、临时文件、IPC、worker 日志、调试会话和 Supervisor owner lease 都只属于
当前连接；workspace、不可变 revision 与 artifact 则在同一个 data root 下受控共享。
因此 Codex、OpenCode 或同一 host 的多个 Agent 可以同时接入：同一 workspace 仍由
跨进程 lease 严格串行，不同 workspace 才能按 worker 上限并行。一个会话的 operation、
change set、cursor 或 debug session 不能在另一个会话中复用。

这里的“会话”严格指一条标准 MCP stdio 连接，也就是一个 server 进程。标准协议不会
携带 Codex/OpenCode 内部的逻辑 Agent 身份；如果某个 host 主动把多个逻辑 Agent
复用到同一条 stdio 连接，它们按协议就属于同一个会话。正常的“一条连接启动一个
server”模式无需额外参数。

`workers.analysis_limit` 与 `workers.debug_limit` 通过共享 data root 下的跨进程 slot
lease 全局执行，不是每个 Agent 各算一遍。空闲 worker、one-shot mutation/refine/
Expert/bootstrap、doctor 与完整 debug session 都占用对应 slot。在正常启动、取消、
超时和有序关闭路径中，只有 IDA worker 真正退出后才释放 slot。Supervisor 被强制结束
时操作系统会回收文件 lease，但已进入 handler 的孤儿 worker 仍可能短暂运行到观察到
IPC 断开；强杀场景不能当作实际进程数的硬上限证明。

支持 `cwd` 的 stdio MCP host 应把服务进程的工作目录明确设为目标项目根目录。Codex
使用 `mcp_servers.<name>.cwd`，OpenCode 本地 MCP 使用 `cwd`。Claude Code 的
`.mcp.json` 没有 `cwd` 字段；项目级文件应放在项目根目录，Claude Code 会向子进程注入
稳定的 `CLAUDE_PROJECT_DIR`，但不会因此保证实际工作目录已经切换。这只表示项目上下文；
会话隔离不依赖工作目录，所以同一项目的并行 Agent 不会再次撞到同一个 owner lease。

### 接入 MCP host

以下配置均假设 `ida-re-mcp` 已安装到 `PATH`，并共用同一份服务配置。多个 host 可以
同时指向同一个 `data_root`：workspace 与不可变 revision 共享，会话态相互隔离。

Codex（`~/.codex/config.toml`）：

```toml
[mcp_servers.ida-re-mcp]
command = "ida-re-mcp"
args = ["serve", "--config", 'C:\Users\you\AppData\Roaming\ida-re-mcp\config.toml']
cwd = 'D:\path\to\your-project'
```

OpenCode stable（`opencode.json`）：

```json
{
  "mcp": {
    "ida-re-mcp": {
      "type": "local",
      "command": ["ida-re-mcp", "serve", "--config", "C:\\Users\\you\\AppData\\Roaming\\ida-re-mcp\\config.toml"],
      "cwd": "D:\\path\\to\\your-project",
      "enabled": true
    }
  }
}
```

OpenCode V2 使用不同的 `mcp.servers` 层级，且没有 stable 的 `enabled` 字段：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "ida-re-mcp": {
        "type": "local",
        "command": ["ida-re-mcp", "serve", "--config", "C:\\Users\\you\\AppData\\Roaming\\ida-re-mcp\\config.toml"],
        "cwd": "D:\\path\\to\\your-project"
      }
    }
  }
}
```

不要把 stable 的 `mcp.<name>`/`enabled` 与 V2 的 `mcp.servers.<name>`/`disabled`
写法混在同一份配置中。

Claude Code（项目根目录 `.mcp.json`）：

```json
{
  "mcpServers": {
    "ida-re-mcp": {
      "command": "ida-re-mcp",
      "args": ["serve", "--config", "C:\\Users\\you\\AppData\\Roaming\\ida-re-mcp\\config.toml"]
    }
  }
}
```

Claude Code 官方 schema 不提供 `cwd`，不要自行添加该字段。子进程可读取 Claude Code
注入的 `CLAUDE_PROJECT_DIR` 获得稳定项目根，但不能据此假定实际工作目录已经切换。

接入前先对 host 使用的同一配置执行：

```powershell
ida-re-mcp doctor --config C:\Users\you\AppData\Roaming\ida-re-mcp\config.toml
```

确认运行目录与 IDA worker 可用后，再由 host 发起 `tools/list`。配置字段依据
[Codex 配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)、
[Claude Code MCP](https://code.claude.com/docs/en/mcp)、
[OpenCode stable MCP](https://opencode.ai/docs/mcp-servers/) 与
[OpenCode V2 MCP](https://v2.opencode.ai/docs/mcp-servers)；stable 与 V2 示例应按所用
版本单独选择。

运行目录不得指向文件系统根目录，也不得位于当前 Git 工作树内或包含工作树。session
owner lease 位于 session 数据树外；`gc` 按数据与日志树的最后活动时间回收遗留目录，
并在同一 lease 内完成删除。活动 session 和未超过 operation 保留期的 session 不会被删。

## Agent 工作流

`workspace.create` 会先把用户提供的文件复制为私有候选副本，再对副本执行严格的
PE/ELF Native 格式预检。调用方必须提供可由 IDA 直接加载的 Native 镜像；shell
脚本、gzexe 和其他压缩包装器稳定返回 `unsupported`。服务不会解包或执行候选文件。

1. 调用 `workspace.create`，保存 `workspace_id` 与 `analysis_operation_id`。
2. 用 `operation.wait` 等待首次分析，取得不可变 revision。
3. 使用显式 `workspace_id` 与 `revision` 调用静态查询。
4. 检查结果中的 `coverage` 与 `provenance`，不要把分析缺口推断为确定事实。
5. 通过 `change.prepare` 与 `change.apply` 执行事务化写回。
6. 用 `report.build` 或 `workspace.export` 生成不可变 artifact，并通过
   `ida-re://...` resource URI 读取。
7. 动态调试时保存 `debug_session_id`，只在当前 suspended `stop_id` 上读取寄存器、
   线程、栈和内存。

`program.search` 的文本域为 `function`、`name`、`string`；显式空
`text_query=""` 表示确定性枚举。`bytes` 域使用独立的 `bytes_query`。

`import_il2cpp_bundle` 只接受本项目定义的 canonical NDJSON。服务不执行分析器或生成器，
调用方需要先把 Il2CppDumper/Il2CppInspector 的输出转换为该格式；逐字段规范与可解析
示例见
[IL2CPP bundle 格式](skills/ida-re-mcp/references/il2cpp-bundle-format.md)。

## 安全与一致性

- 原始样本只读，`workspace.create` 会复制并校验 SHA-256，所有格式识别都发生在私有
  候选副本上。
- AnalysisWorker 与 DebugWorker 使用私有 checkout，关闭时不保存。
- 所有 IDB 写入都在 staging 中完成，经过回读、冷验证和 CAS 后发布为新 revision。
- mutation 失败、取消或 worker 崩溃不得改变旧 revision、HEAD 或样本摘要。
- 调试会执行目标程序；Job Object 负责回收服务启动的进程树，但不是恶意样本沙箱。
- `expert.execute` 默认不注册。启用后仍是可访问文件、网络和子进程的开放世界
  IDAPython。

项目不提供进程内存写入、远程调试、普通 .NET/Mono workspace、通用调用捕获或外部
分析器执行链。

完整边界见 [架构](docs/架构.md)，能力状态见
[能力矩阵](docs/能力矩阵.md)，可复现门禁见
[验证记录](docs/验证记录.md)。
