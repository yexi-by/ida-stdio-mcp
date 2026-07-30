# ida-re-mcp

`ida-re-mcp` 让 Codex 通过 IDA Pro 9.3 分析 PE 和 ELF 文件。它可以读取函数、
反汇编、交叉引用、字符串和伪代码，也可以修改 IDB、生成报告，并在 Windows 上启动
本机 x64 调试。

服务不会修改导入的原文件。样本副本、IDA 分析结果和修改记录保存在项目根目录的
`data/` 中，运行日志保存在 `logs/` 中。两个目录会在首次启动时自动创建。

## 开始使用

你需要：

- 已安装并能正常使用的 IDA Pro 9.3；
- 已安装的 `uv`；
- 有效的 IDA 许可证；
- 如需读取伪代码，还需要 Hex-Rays Decompiler；
- 如需动态调试，需要 Windows x64。

### 1. 修改项目配置

打开项目根目录的 `config.toml`，确认 IDA 安装目录正确：

```toml
[runtime]
data_root = "data"
log_root = "logs"
ida_dir = 'C:\Program Files\IDA Professional 9.3'
```

`data_root` 和 `log_root` 都以 `config.toml` 所在目录为准，不受 Codex 从哪个目录
启动的影响。完整配置中已经写明每个选项的用途，通常只需修改 `ida_dir`。

先运行一次检查：

```powershell
uv run ida-re-mcp doctor --config config.toml
```

`uv` 会为本项目准备所需的 Python 和依赖，不需要手动创建虚拟环境，也不需要设置
环境变量。检查结果中的 `healthy` 和 `worker.available` 都应为 `true`。

### 2. 配置 Codex

在 Codex 的 `config.toml` 中加入以下内容，把 `cwd` 改成本项目的实际目录：

```toml
[mcp_servers.ida-re-mcp]
command = "uv"
args = ["run", "ida-re-mcp", "serve", "--config", "config.toml"]
cwd = 'D:\path\to\ida-re-mcp'
startup_timeout_sec = 240.0
tool_timeout_sec = 3600.0
enabled = true
```

保存后重启 Codex。Codex 会先进入 `cwd`，再运行：

```powershell
uv run ida-re-mcp serve --config config.toml
```

不需要配置 `env`，也不需要使用 `--directory`。

## 第一次分析

1. 调用 `workspace.create` 导入样本。保存返回的分析项目编号 `workspace_id` 和后台任务
   编号 `analysis_operation_id`。
2. 调用 `operation.wait`，等待首次分析完成。保存返回的分析版本 `revision`。
3. 调用静态查询工具时，每次都传入 `workspace_id` 和 `revision`。
4. 修改 IDB 时，先调用 `change.prepare` 检查修改内容，再调用 `change.apply` 保存。
   保存成功后，后续查询改用新返回的 `revision`。
5. 生成报告或导出文件时，调用 `report.build` 或 `workspace.export`。如果工具返回后台
   任务编号，再用 `operation.wait` 等待完成。
6. 动态调试时保存 `debug_session_id`。读取寄存器、线程、调用栈和内存时，必须使用
   当前暂停位置的 `stop_id`。

## 让另一个 Agent 接着分析

`data/` 是本机这份项目的共用分析目录。Agent A 结束任务后，Agent B 不需要重新导入
同一个样本，也不需要重新等待 IDA 分析。

Agent B 开始时按以下顺序读取已经保存的结果：

1. 调用 `workspace.list`，根据样本名称和 SHA-256 找到原来的 `workspace_id`。
2. 调用 `workspace.get` 读取该分析项目，并取得 `current_revision`。
3. 后续静态查询都使用这个 `workspace_id` 和 `current_revision`。
4. 只有找不到对应分析项目，或该项目还没有 `current_revision` 时，才考虑重新导入或
   检查之前的后台任务。

`data/` 中保存的是后续 Agent 可以继续使用的正式分析结果；`logs/` 主要用于查找启动
失败、IDA 运行失败和调试失败的原因。分析结论应通过 MCP 工具读取，不要把日志当作
正式结果。只要后续 Agent 使用同一个项目目录和 `config.toml`，它就能看到之前保存的
分析项目。`data/` 和 `logs/` 不会提交到 Git；另一台机器或另一份项目副本不会自动
拥有这些数据。

## MCP 返回内容

工具结果中的 `structuredContent` 保存完整数据。字段名、地址、编号、哈希值、伪代码
和查询结果都以这里的内容为准。

同时返回的中文文本由程序根据这些字段生成，只说明本次完成了什么以及下一步该调用
什么。它不会替代 `structuredContent`，也可能省略不适合展示的大段内容。

Agent 必须读取 `structuredContent`。如果使用的 MCP 客户端只显示文本而不提供
`structuredContent`，地址、编号或其他细节可能丢失。接入或升级客户端后，应使用真实
客户端调用一次 `workspace.get` 等工具，确认完整字段可以读取，再开始正式分析。

工具失败时，第一段文本直接说明原因和下一步，第二段文本保留
`{code,message,details}` 机器错误对象。旧客户端如果把第一段文本固定当作 JSON
解析，需要改为读取第二段；不要依赖文本段的位置保存成功结果，成功数据一律读取
`structuredContent`。

## 当前项目允许的操作

项目提供的 `config.toml` 保留了重构前已经开启的功能：

- 允许修改 IDB，并把修改保存为新的分析版本；
- 允许由 IDA 启动调试目标；
- 允许附加到已经运行的外部进程；
- 允许执行任意 IDAPython。

`debug_attach` 会让 Agent 附加到其他进程，`expert` 会让 Agent 执行可访问文件、网络
和子进程的 IDAPython。不需要这些功能时，把对应配置改为 `false` 并重启服务。

服务不提供远程调试、普通 .NET/Mono 分析项目、进程内存写入、恶意样本隔离运行环境，
也不会执行外部 IL2CPP 分析器。

## 开发检查

运行项目自带的全部检查：

```powershell
./scripts/run_quality.ps1
```

该脚本会检查代码格式、类型、单元测试、集成测试、测试样本是否可重复生成，以及安装
后的 MCP 是否能正常启动。任一步失败都会返回非零退出码。

## 许可证

[MIT](LICENSE)
