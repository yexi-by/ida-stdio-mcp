# ida-re-mcp

IDA Pro 9.3+ 的 headless 逆向工程 MCP 服务。任何支持 MCP 的 AI Agent（Codex、
Claude Code、Kimi CLI 等）都可以通过它分析 PE / ELF 文件：读取函数、反汇编、
交叉引用、字符串和伪代码，修改 IDB，生成报告，并在 Windows 上启动本机 x64 调试。

样本副本、分析结果和修改记录保存在 `data/`，日志保存在 `logs/`，原文件不会被修改。

## 要求

- IDA Pro 9.3+ 及有效许可证
- [uv](https://docs.astral.sh/uv/)
- 读取伪代码需要 Hex-Rays Decompiler；动态调试需要 Windows x64

## 使用

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

   其他客户端同理，工作目录指向本项目即可。

## 工作方式

- `workspace.create` 导入样本，`operation.wait` 等待首次分析完成；之后的查询
  都传入 `workspace_id` 和 `revision`。
- 接手已有分析时先调用 `workspace.list` 和 `workspace.get` 读取
  `current_revision`，不必重复导入同一样本。
- 修改 IDB 先 `change.prepare` 再 `change.apply`，成功后使用新的 `revision`。
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
