# ida-stdio-mcp

一个仅面向 **IDA Pro 9.2+ / idalib / stdio / headless** 的通用 MCP 服务。

## 当前定位

- 只支持 **headless**
- 只支持 **stdio MCP**
- 以 **多会话** 为核心运行模型
- 提供 **resources + tools** 两类能力
- 默认提供完整只读能力
- 可按开关启用：
  - 危险写入/执行能力
  - 调试器能力

## 输出契约

所有工具统一返回：

- `status`
- `source`
- `warnings`
- `error`
- `data`

其中 `status` 只允许：

- `ok`
- `degraded`
- `unsupported`
- `error`

## 本地运行

```powershell
uv sync
uv run ida-stdio-mcp
```

确保当前进程能读取：

```powershell
$env:IDADIR = "C:\Program Files\IDA Professional 9.2"
```

如需直接打开样本：

```powershell
uv run ida-stdio-mcp tests/fixtures/crackme03.elf
```

如需启用危险工具：

```powershell
uv run ida-stdio-mcp --unsafe
```

如需启用调试器工具：

```powershell
uv run ida-stdio-mcp --debugger
```

如需按白名单裁剪工具：

```powershell
uv run ida-stdio-mcp --profile profiles/readonly.txt
```

## 测试与验证

```powershell
uv run basedpyright
uv run python -m unittest discover -s tests/unit
uv run python -m unittest discover -s tests/integration
```

如需真实 headless 集成测试：

```powershell
uv run ida-stdio-mcp-test tests/fixtures/crackme03.elf
```
