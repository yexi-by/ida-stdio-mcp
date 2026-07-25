# ida-re-mcp

`ida-re-mcp` 是面向 AI Agent 的 IDA Pro 9.3+ headless stdio MCP 服务。它以显式
workspace、不可变 revision 和进程隔离 worker 为基础，提供 Native 静态逆向、
Unity IL2CPP 原生类型/符号注解、事务化 IDB 写回，以及 Windows 本机 x64 动态调试。

当前版本为 `1.0.0.dev0`，用于开发和验收，不用于生产发布。`1.0.0` 必须同时满足：

- MCP `2026-07-28` 正式规范已经发布并完成差异审计；
- Python MCP SDK `2.0.0` 稳定版已经锁定；
- current-only stdio、wheel 安装、IDA 静态分析与 Windows x64 debugger 的全部硬门禁通过。

开发版本精确锁定 MCP SDK v2 beta 的类型，但不使用会协商多个协议版本的默认 runner。
服务只广告 tools 与不可变 resources；长操作通过显式 operation 句柄管理。

## 环境要求

- Python `3.13`，不支持其他 Python 次版本；
- `uv`；
- IDA Pro `9.3+` 及对应许可证；
- LLVM/LLD `22.1.8`，仅在重建测试 fixture 时需要；
- Windows x64，动态调试验收的唯一目标平台。

Supervisor 与 IDA worker 位于独立进程，只通过本地鉴权 JSON IPC 通信。IDA API 只在
worker 的 owner 线程调用。同一个 data root 同时只允许一个 Supervisor owner；
`serve`、`doctor` 与 `gc` 获取同一 owner lease，不能并行运行。单个 Supervisor 内仍按
worker 上限并行处理不同 workspace，同一 workspace 始终串行。

## 开发环境

虚拟环境和运行数据必须位于 Git 工作树外：

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\ida-re-mcp\dev-venv"
uv python install 3.13
uv sync --locked
```

IDA 安装目录由 `idapro` 的运行环境解析。开发机可按 IDA 安装要求设置 `IDADIR`，然后先
执行诊断：

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
[config.example.toml](config.example.toml)。默认数据、日志、checkout、artifact 和临时
文件都写入当前用户的平台应用数据目录。`workspace.create` 会复制样本并校验 SHA-256，
任何 IDB 写入都只发布为新的 revision。运行 `doctor` 或 `gc` 前必须先停止占用同一
data root 的 `serve`；`gc --dry-run` 只报告候选，`gc --apply` 才回收未保留 revision、
孤立 artifact/change set/staging 与过期 operation，且不会删除 current 或 pinned
revision。

## MCP 工作流

1. 调用 `workspace.create`，再用 `operation.wait` 等待首次分析发布 revision。
2. 使用显式 `workspace_id` 与 `revision` 调用静态查询。
3. `program.search` 的文本域是 `function`、`name`、`string`，显式空
   `text_query=""` 表示确定性枚举；`bytes` 域只使用独立的 `bytes_query`。
4. 检查结果中的 `coverage` 与 `provenance`，不要把分析缺口推断为确定事实。
5. 通过 `change.prepare` 与 `change.apply` 执行事务化写回。
6. `report.build` 生成 Markdown/JSON 报告；`workspace.export` 当前只导出 IDB。
7. 动态调试时保存 `debug_session_id`，并只在当前 suspended `stop_id` 上读取快照。
   `debug.establish`、控制动作与 `debug.finish` 返回完成类型、证据来源和已观察事件
   sequence，调用方应据此关联 `debug.events`。
8. 大结果返回 chunk index artifact；按索引中的 `ida-re://...` URI 逐块读取，每个
   resource chunk 最大 1 MiB。

完整工具边界和验收状态见 [能力矩阵](docs/能力矩阵.md)，进程与 revision 设计见
[架构](docs/架构.md)，可复现门禁见 [验证记录](docs/验证记录.md)。

## 安全边界

动态调试会执行目标程序。Job Object 只负责回收服务启动的进程树，不提供文件、注册表、
网络或系统调用隔离。不要在未隔离的主机上运行不可信样本。

`expert.execute` 默认不注册。操作者启用后，它会在 disposable staging worker 中执行
inline IDAPython，并把写入发布为新 revision；这是开放世界能力，服务不能阻止 Python
访问文件、网络或启动子进程。

截至 2026-07-25，验收环境中的 MCP Inspector `0.21.2` 发送的协议版本不是
`2026-07-28`，严格入口会以 `-32602` 拒绝。项目不会为 Inspector 增加其他协议分支；
能够使用正式 current 协议的 Inspector、正式规范和稳定 Python SDK 都是 `1.0.0`
发布前的外部门禁。
