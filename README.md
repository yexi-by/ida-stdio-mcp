# ida-stdio-mcp

一个仅面向 **IDA Pro 9.2+ / idalib / stdio / headless** 的 MCP 服务。

## 设计目标

- 只支持 **headless**
- 只支持 **stdio MCP**
- 只做第一阶段 **只读核心集**
- Native 优先，managed 只做能力探测
- 输出统一使用结构化结果：
  - `status`
  - `source`
  - `warnings`
  - `error`
  - `data`

## 本地运行

```powershell
uv sync
uv run ida-stdio-mcp
```

确保当前进程能读取：

```powershell
$env:IDADIR = "C:\Program Files\IDA Professional 9.2"
```

## Codex 配置示例

```toml
[mcp_servers.ida-stdio-mcp]
command = "uv"
args = [
  "--directory", "D:\\work\\ida-stdio-mcp",
  "run",
  "--no-sync",
  "python",
  "-m",
  "ida_stdio_mcp",
]
env = { IDADIR = "C:\\Program Files\\IDA Professional 9.2" }
```

## 测试

```powershell
uv run python -m unittest discover -s tests/unit
uv run python -m unittest discover -s tests/integration
```

如需真实 headless 集成测试：

```powershell
uv run ida-stdio-mcp-test tests/fixtures/crackme03.elf
```
