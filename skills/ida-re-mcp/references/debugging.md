# Windows 本机 x64 动态调试

## 状态与事件

状态为 `launching`、`running`、`suspended`、`exited`、`detached`、`lost`、`failed`。

- `debug.establish` 只有观察到 `process_started` 或允许的 `process_attached` 才成功。
- `debug.control` 只有观察到对应 IDA stop/exit 事件，或明确验证
  `get_process_state()==DSTATE_RUN` 后才完成。后者的
  `completion_provenance` 为 `state_observation`，不是 IDA resume event。
- `debug.establish`、`debug.control` 与 `debug.finish` 的结果包含
  `completion_kind`、`completion_provenance` 和 `observed_event_sequence`。保存该
  sequence，并在 `debug.events` 中核对对应事件；不能只依赖返回的状态名称。
- 每次 suspended 都生成新的 `stop_id`；恢复运行后，此前的 stop 不再有效。
- worker 失联时状态为 `lost`，不能推断为 detach 或 exit。
- 每个事件都携带 `provenance`：`ida_event`、`state_observation` 或
  `service_event`，不得把三者混为同一种证据。
- `debug.events.after_sequence` 只使用上一页 `last_sequence`。空页保持请求游标；
  `observed_latest_sequence` 是 worker 上界，`has_more` 表示是否仍有未返回事件。

## 断点与 ASLR

- 主镜像断点使用 `image_id+rva`；已加载模块断点使用事件返回的 `module_id+rva`。
- 模块加载后才解析 runtime VA；pending 不是 active。
- 继续执行前检查返回断点状态。
- `run_to` 同时携带 suspended `stop_id` 与 image target。

## 暂停快照

`debug.inspect` 必须携带当前 `debug_session_id` 和 `stop_id`。可请求：

- `state`；
- `modules`；
- `threads`；
- `registers`；
- `stack`；
- `maps`；
- `memory`，同时提供带相同 `stop_id` 的 runtime address 与不超过 64 KiB 的 size。

调用栈在 stripped、缺少 unwind、自修改或混淆目标上可能不完整。把此限制保留在分析
结论中。

## 生命周期与执行风险

- 默认路径是 launch 当前 workspace 样本。
- attach 只有操作者策略明确允许时才可请求。
- terminate 只适用于服务启动并纳入 Job Object 的目标。
- attach 目标使用 detach。
- Job Object 只负责进程树回收，不隔离文件、注册表、网络或系统调用。
