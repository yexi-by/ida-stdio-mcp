# ida-re-mcp 项目协作规则

## 产品边界

- 产品与 Python 发行名为 `ida-re-mcp`，导入包为 `ida_re_mcp`，CLI 为 `ida-re-mcp`。
- 服务面向 IDA Pro 9.3+ headless，分析对象是 Native 二进制与 Unity IL2CPP 原生注解。
- 动态调试能力限定为 Windows 本机 x64，并以真实 IDA 调试事件作为完成条件。
- 原始样本只读；所有 IDB 修改都通过 staging、冷验证和原子 revision 发布。

## 协议与进程

- 只实现 MCP `2026-07-28` 的 UTF-8 单行 JSON-RPC stdio 边界。
- stdout 只输出协议消息；诊断写入 stderr 或平台日志目录。
- 工具目录在启动时固定，只广告 tools 和不可变 resources。
- Supervisor 不导入 IDA；IDA API 只在独立 worker 的 owner 线程调用。
- Supervisor 与 worker 只通过当前用户私有、带随机鉴权值的本地 JSON IPC 通信。
- 每个请求显式携带 workspace、revision、operation、debug session 或 stop 等身份。

## 存储与运行目录

- workspace、日志、artifact、checkout、staging、临时文件和开发虚拟环境位于工作树外。
- 同一 workspace 严格串行；不同 workspace 才允许进程级并行。
- 只读分析和调试使用私有 checkout，关闭时不保存。
- mutation 失败、取消或 worker 崩溃不得改变已发布 revision、HEAD 或样本摘要。
- GC 永不删除 current revision 或 pinned export。

## 工程与验证

- 运行时固定为 Python 3.13，项目使用 uv、Ruff、basedpyright strict 与 pytest。
- 新增代码内开发者文档使用规范中文，标识符使用英文 ASCII。
- JSON Schema 使用 2020-12，根对象封闭，输入与输出都由服务端验证。
- 测试覆盖外部可观察行为、失败路径、worker 崩溃和 revision 不变量。
- IDA 与 debugger 门禁必须使用受许可的 IDA 9.3+ headless 环境和真实事件。
- 文档中的“支持”只用于已经通过对应硬门禁的能力。
