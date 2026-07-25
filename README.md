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
ida-re-mcp doctor
```

## CLI

```powershell
ida-re-mcp serve
ida-re-mcp serve --config C:\path\to\config.toml
ida-re-mcp doctor
ida-re-mcp gc --dry-run
ida-re-mcp gc --apply
```

配置使用严格 TOML schema，示例见
[config.example.toml](config.example.toml)。workspace、日志、artifact、checkout、
staging、临时文件和虚拟环境都位于工作树外。

同一个 data root 同时只能由一个 Supervisor 占用。多个 MCP host 若需同时启用，必须
使用 `IDA_RE_MCP_DATA_ROOT` 指定互不重叠的绝对路径；可用
`IDA_RE_MCP_LOG_ROOT` 单独指定日志目录。否则第二个进程会在读取或修改运行状态前失败。
两个 override 都不得指向文件系统根目录，也不得位于工作树内或包含工作树。

## Agent 工作流

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

## 安全与一致性

- 原始样本只读，`workspace.create` 会复制并校验 SHA-256。
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
