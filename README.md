# ida-re-mcp

IDA Pro 9.3+ 的 headless 逆向工程 MCP 服务。任何支持 MCP 的 AI Agent（Codex、
Claude Code、Kimi CLI 等）都可以通过 stdio 接入，让 Agent 直接驱动 IDA 分析
PE / ELF 文件。

## 功能

- **静态分析**：程序概览与搜索（`program.*`）、函数、反汇编、类型、交叉引用、
  字符串、伪代码、数据流切片
- **IDB 修改**：重命名、注释、改类型等，每次修改生成新的分析版本（revision），
  旧版本仍可读取
- **动态调试**：Windows x64 本机调试，断点、寄存器、线程、调用栈、内存读写
- **产物**：Markdown / JSON 报告、样本与分析结果导出、IL2CPP 元数据
- **协作**：分析结果持久化在本机 `data/`，多个 Agent 可通过 `workspace_id` 接手
  同一份分析，不必重复导入样本

## 要求

- IDA Pro 9.3+ 及有效许可证
- [uv](https://docs.astral.sh/uv/)
- 读取伪代码需要 Hex-Rays Decompiler；动态调试需要 Windows x64

## 快速开始

1. 确认 `config.toml` 中的 `ida_dir` 指向本机 IDA 安装目录，其余选项通常无需修改。
2. 运行检查，确认 `healthy` 和 `worker.available` 都为 `true`：

   ```powershell
   uv run ida-re-mcp doctor --config config.toml
   ```

3. 在你的 Agent 客户端中登记一个 stdio MCP 服务，启动命令为：

   ```powershell
   uv run ida-re-mcp serve --config config.toml
   ```

   以 Codex 为例，在 `config.toml` 中加入：

   ```toml
   [mcp_servers.ida-re-mcp]
   command = "uv"
   args = ["run", "ida-re-mcp", "serve", "--config", "config.toml"]
   cwd = 'D:\path\to\ida-re-mcp'
   startup_timeout_sec = 240.0
   tool_timeout_sec = 3600.0
   ```

   其他客户端同理，工作目录指向本项目即可。这里的
   `startup_timeout_sec` 和 `tool_timeout_sec` 只限制客户端等待 MCP 服务的时间。
   IDA 子进程的单次操作时限由本项目 `config.toml` 的 `[workers]` 控制：
   `operation_timeout_seconds` 用于普通查询、分析细化和 IDB 修改，
   `initial_analysis_timeout_seconds` 单独用于首次导入时的 IDA 自动分析。
   默认分别为 1 小时和 3 小时；修改后需要重启 MCP 服务。

## 工作原理

```
Agent ──stdio/MCP──▶ supervisor ──IPC──▶ IDA headless worker
                          │                     │
                       data/ 持久化 ◀───────────┘
```

- 服务进程（supervisor）只负责协议和调度，真正的分析在独立的 IDA 子进程中执行；
  IDA 崩溃不会影响 MCP 连接，空闲 worker 会自动退出。
- 导入的样本副本、IDB、每次修改生成的 revision 都写入 `data/`，日志写入 `logs/`；
  相对路径以 `config.toml` 所在目录为准。
- 长任务（首次分析、报告生成）返回 `operation` 编号，用 `operation.wait` 等待完成。
- 首次分析失败或取消且尚未产生 revision 时，使用 `workspace.retry` 重新分析已有
  workspace；不要再次导入同一份样本。
- 所有修改走 `change.prepare` → `change.apply` 两段提交，prepare 先校验，
  apply 成功后才产生新 revision。
- 工具结果的完整数据在 `structuredContent` 中，附带的中文文本只是摘要；
  出错时第一段文本说明原因和下一步，第二段是 `{code,message,details}` 错误对象。

默认配置允许修改 IDB、启动调试、附加外部进程和执行任意 IDAPython。不需要这些
功能时，在 `config.toml` 的 `[policy]` 中关闭对应选项并重启服务。

## 开发

```powershell
./scripts/run_quality.ps1
```

运行格式检查、类型检查、全部测试和 MCP 启动检查，任一步失败即返回非零退出码。

## 许可证

[MIT](LICENSE)
