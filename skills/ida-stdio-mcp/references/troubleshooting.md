# 排障

## 目录

- 大样本与超时
- 打开失败
- 工具完成但客户端还在等待
- 字符串结果差
- 分析完整性判断
- 常见修复

## 大样本与超时

UE、Chrome、游戏客户端、大 PDB native 样本可能耗时很长。

规则：

- 默认 `open_target(run_auto_analysis=false)`。这会真实加载 loader、符号和 working IDB，但不等待全库自动分析队列清空。
- 用户明确要求全库自动分析时，传 `run_auto_analysis=true`。
- 全库自动分析可能几十分钟到数小时，客户端 MCP timeout 建议设为 `3600` 到 `21600` 秒。
- 不要建议移走 PDB 来“变快”，除非用户明确要求做对照实验。PDB 是分析信息的一部分。

## 打开失败

检查：

- `status` 是否为 `error`。
- `error.code` 和 `error.next_steps`。
- 路径是否存在，是否是文件。
- 是否有残留 IDA sidecar 文件。
- IDA 运行时是否为 9.3+。

打开成功必须以 `open_target` 返回 `ok` 为准。

## 工具完成但客户端还在等待

常见原因：

- 工具响应过大，客户端还在处理或上传 tool output。
- `evaluate_python` 按契约只返回受控摘要；大 `stdout`、`stderr` 或 `result` 会写入 artifact。
- 客户端侧工具状态未同步，服务端日志可能已经显示完成。

处理：

1. 看 MCP 日志里的 `tool_call_start` / `tool_call_complete`、`request_id`、`duration`。
2. 看客户端 tool output 文件大小。
3. 查看 `artifacts` 中的 `path`、`sha256`、`size` 与 `schema`，必要时读取落盘结果。
4. 字符串工具连续调用时确认 `cache.cache_hit=true`。

## 字符串结果差

先判断：

- `cache.truncated_by_scan_limit` 是否为 true。
- `statistics.matched_strings` 是否为 0。
- 当前样本是否 managed、native、或混合。

无命中时：

- 不要连续换关键词空转。
- 回到 `triage_binary` 的 imports、entrypoints、interesting_functions。
- 对 crypto/Pak/IoStore 场景，查 AES/BCrypt/Crypt/import 调用和相关函数名。

## 分析完整性判断

`open_target.metadata` 里的关键字段：

- `database_loaded`
- `working_idb_ready`
- `auto_analysis_waited`
- `analysis_completeness`
- `analysis_limitations`
- `exact_pdb_path`
- `sibling_pdb_files`
- `database_snapshot`

如果 `auto_analysis_waited=false`，结论应来自后续定点工具，不要写成全库分析完成。

## 常见修复

- `session_required`：先 `open_target` 或 `get_workspace_state`。
- `session_not_found`：确认 `session_id` 属于当前上下文。
- `runtime_not_ready`：先调用 `runtime_health`，按返回的 `reason` 和 `actionable_fix` 检查 `idapro`、`idalib.dll`、`IDADIR`、IDA 版本和安装目录。
- `unsupported`：当前环境缺少 Hex-Rays、调试后端或目标未处于合法状态。调试场景先调用 `debug_health`，查看 `backend.attempts` 与 `process_state_name`；如默认模块加载失败，优先在 `setting.toml` 的 `[debugger].backend_candidates` 配置模块名，临时覆盖可用 `IDA_STDIO_MCP_DEBUGGER`。仍不可用时换静态分析路径。
- `degraded`：继续分析，但在报告中写明降级原因。
