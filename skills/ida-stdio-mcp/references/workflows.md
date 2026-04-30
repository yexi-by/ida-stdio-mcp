# 工作流

## 目录

- 开局流程
- Native 样本
- Unity/.NET 样本
- 字符串牵引
- 函数解释
- 输入到检查点
- 报告与保存

## 开局流程

1. 调用 `get_workspace_state`。
2. 如果 `current_session` 为空，调用 `open_target`。
3. 调用 `triage_binary`，先看：
   - `summary.opening_moves`
   - `interesting_functions`
   - `interesting_strings`
   - `imports/categories`
   - `string_index`
   - `managed_summary`
   - `recommended_next_tools`
4. 选择一个最小可验证目标继续，不要并发盲扫多个方向。

## Native 样本

推荐顺序：

```text
open_target -> triage_binary -> explain_function(entry/main/suspicious) -> investigate_string -> trace_input_to_check -> export_report
```

要点：

- 优先从入口点、导入分类、可疑函数名、高 xref 函数、关键字符串切入。
- `explain_function` 的结果优先看 `representation`、`backend`、`confidence`、`calls`、`xrefs`、`strings`、`constants`。
- Hex-Rays 不可用时接受汇编降级，不要把降级伪装成 C 伪代码。
- 对导入项使用 `get_import_at` 或导入相关工具时，优先利用 module/name/ordinal 判断外部语义。

## Unity/.NET 样本

推荐顺序：

```text
open_target -> triage_binary -> investigate_string(UI/path/key) -> explain_function(method) -> export_report
```

要点：

- 先看 managed 质量等级、命名空间、类型、托管字符串和 C# 反编译状态。
- 优先使用 `ilspycmd` C# 结果；不可用时接受 IL/反汇编降级。
- 报告里说明 managed 结果质量等级，不要把符号化线索说成完整静态证明。

## 字符串牵引

适用输入：

- 错误文案
- URL、域名、路径
- 配置键、协议字段
- UI 文案
- 可疑字符串地址

步骤：

1. 调用 `investigate_string`，优先传 `pattern`；已有地址时传 `addr`。
2. 看 `matches`、`usages`、`functions`。
3. 对最相关函数调用 `explain_function`。
4. 如果线索指向输入、鉴权、路径或协议检查，继续 `trace_input_to_check`。
5. 若无命中，回到导入、入口、函数名，不要连续换关键词空转。

## 函数解释

`explain_function` 用于综合判断，`decompile_function` 用于只取高层表示。

函数分析时至少确认：

- 函数地址、名称、大小和基本块信息。
- 伪代码或降级表示。
- 调用者、被调函数、外部导入。
- 引用字符串和常量。
- 注释、类型、栈变量或结构体线索。

## 输入到检查点

用 `trace_input_to_check` 处理：

- license/key/password 校验。
- 文件路径、Pak/IoStore、资源加载。
- 网络协议字段。
- UI 输入到逻辑判断。

如果 trace 不完整，列出已确认路径和断点，不要补全不存在的链路。

## 报告与保存

`export_report` 用于交付分析结论。报告应包含：

- 样本、session、working IDB。
- 已使用工具和关键证据。
- 可信结论、降级结果、不确定点。
- 推荐下一步。

`save_workspace` 默认保存 working IDB。只有用户明确要求导出到指定位置时才传 `path`。
