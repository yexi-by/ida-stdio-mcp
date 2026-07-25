---
name: ida-re-mcp
description: 使用 ida-re-mcp 调用 IDA Pro 9.3+ headless MCP，完成 Native 样本的 workspace 建立、静态逆向、图与函数内数据流分析、报告导出、事务化 IDB 写回、Unity IL2CPP 原生注解和 Windows 本机 x64 动态调试。适用于 Agent 需要以显式 revision、coverage、provenance、真实 debugger 事件和不可变 artifact 为证据分析二进制的任务。
---

# ida-re-mcp

## 建立上下文

1. 调用 `tools/list`，只使用当前目录实际提供的工具。
2. 确认输入是可由 IDA 直接加载的 PE/ELF Native 镜像，再调用 `workspace.create`，
   保存 `workspace_id`、`sample_sha256` 和
   `analysis_operation_id`。
3. 用 `operation.wait` 等待首次分析；从成功结果中取得 revision。
4. 调用 `workspace.get`，核对样本摘要、架构与 current revision；按 `next_cursor`
   逐页读取 revision 摘要。

`workspace.create` 会复制输入并只在私有候选副本上执行严格格式预检。不要提交 shell
脚本、gzexe 或其他压缩包装器；这些输入稳定返回 `unsupported`。服务不会解包或执行
候选文件，应由用户提供直接 Native 镜像。

不要猜测活动 workspace。每次静态查询都显式传 `workspace_id` 和目标 `revision`。
revision 改变后重新发起分页查询，不复用 cursor。

## 静态分析

1. 用 `program.overview` 取得镜像身份、数量和所需概览视图。
2. 用 `program.search` 在 `function`、`name`、`string` 文本域或 `bytes` 域定位候选。
   文本域显式传 `text_query`；传空字符串表示确定性枚举。字节域单独传
   `bytes_query`，不要把文本查询解释为十六进制。
3. 用 `address.inspect`、`function.inspect`、`graph.query` 和 `type.inspect` 验证具体事实。
4. 仅在需要定义—使用关系时调用 `dataflow.slice`，明确选择 `may` 或 `must`。
5. 检查每个结果的 `coverage.status`、`coverage.reasons` 与 `provenance`。
6. 用 `report.build` 生成 Markdown/JSON 报告；只在需要 IDB 时调用
   `workspace.export`。等待 operation 后读取返回的 `ida-re://...` resource。

视图、地址空间、分页和数据流限制见
[references/static-analysis.md](references/static-analysis.md)。

## 事务化写回

1. 从当前 revision 回读目标的名称、注释、类型或 bytes，作为 precondition。
2. 把相关操作组成一个原子批次并调用 `change.prepare`。
3. 审查返回的 `base_revision`、`digest`、impact 与 conflicts。
4. 只把原样的 `change_set_id`、`digest` 和匹配的 `expected_revision` 交给
   `change.apply`。
5. 应用成功后切换到返回的新 revision，并重新查询受影响事实。

遇到 `revision_conflict` 时读取 workspace HEAD，重新收集 precondition 并 prepare。
不要修改原始样本，也不要绕开 staging revision。IL2CPP 与写回事务规则见
[references/authoring-il2cpp.md](references/authoring-il2cpp.md)。

## Windows x64 动态调试

1. 用 `debug.establish` launch 当前 workspace 样本，保存 `debug_session_id`。
2. 仅用 `debug.events.last_sequence` 作为下一页 `after_sequence`；`observed_latest_sequence`
   只表示 worker 已观察上界，不能代替分页游标。
3. 只在 suspended 状态保存并使用当前 `stop_id`。
4. 用 `debug.breakpoints` 以 image/module + RVA 替换断点集合，并确认状态为 `active`。
5. 用 `debug.control` 执行 `pause`、`continue`、`step_into`、`step_over` 或 `run_to`。
6. 仅在匹配的 suspended stop 上用 `debug.inspect` 读取线程、寄存器、栈、模块、映射
   或有限内存。
7. launch 会话用 `debug.finish(action="terminate")`；只有 attach 会话使用
   `debug.finish(action="detach")`。

状态、事件和地址约束见 [references/debugging.md](references/debugging.md)。

## 错误与结果边界

- operation 进入 `cancel_requested` 不代表已经取消；继续等待终态。
- `capability_unavailable` 或 `unsupported` 表示当前 headless 链路不能完成请求；停止该
  路径并报告 remediation，不转向 GUI。
- `ambiguous_reference` 要求保留候选并改用精确 `entity_id` 或地址。
- `cursor_stale` 要求从第一页重新查询。
- `debug_state_conflict` 要求重新读取事件和当前 stop。
- inline 结果不足时读取 artifact resource；如果返回 chunk index，按索引 URI 逐块
  校验并读取，不要求工具返回无界对象。

## 运行与 Expert 边界

- 服务运行时只接受 Python 3.13；不要用其他 Python 次版本启动 CLI 或 worker。
- 同一个 data root 可由多个 MCP 连接共享；每条连接的 operation、change set、cursor、
  checkout、temp、日志与 debug session 相互隔离，不跨连接复用这些标识。
- 同一 workspace 的 worker lifecycle 仍由跨进程 lease 严格串行；`gc` 会跳过活动
  workspace 和活动 session。
- 不同 workspace 可在 worker 上限内并行，同一 workspace 始终串行。analysis/debug
  worker 上限通过共享 data root 的 slot lease 对所有 stdio 连接全局生效。
- AnalysisWorker 会按 workspace/revision 复用私有 checkout；不要把 worker 热状态当作
  持久证据，只有已发布 revision 和冷验证结果可作为稳定依据。
- `expert.execute` 默认不在工具目录。若操作者启用，它仍是开放世界 IDAPython；即使在
  disposable staging worker 中，服务也不能阻止文件、网络或子进程访问。
