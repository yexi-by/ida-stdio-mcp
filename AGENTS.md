# ida-re-mcp 项目协作规则

## 公开文字

- 默认使用规范中文。
- README、配置注释、MCP 工具说明、成功摘要、错误提示、日志提示和代码内开发者文档都要使用自然、直接、含义明确的语言。
- 不使用中文黑话、管理套话、营销话术、网络行话或生硬直译。除说明禁用词外，不写“赋能、抓手、闭环、拉齐、对齐、沉淀、颗粒度、心智、链路、兜底、落地”。
- 专业名词没有自然、准确的中文说法时，保留英文名称，并用一句普通中文说明用途。
- 工具名、字段名、错误代码、枚举值、地址、编号、哈希值和文件地址属于公开接口，不得为了中文化而改名或改值。
- 错误提示必须说明发生了什么、用户下一步做什么。异常类型、堆栈、本机路径和子进程原始输出只写日志，不直接返回给 MCP 客户端。

## MCP 返回内容

- 成功结果的 `structuredContent` 必须保留经过输出模型校验的完整数据，不能删字段、翻译字段、缩短地址、改写编号或省略哈希值。
- `TextContent` 是由代码根据结果字段生成的中文摘要，只说明结果和下一步，不代替 `structuredContent`，也不交给模型自行概括。
- 新增或修改工具时，必须同时补充确定性摘要和测试。
- 必须使用官方 MCP `ClientSession` 通过真实 stdio 连接测试返回内容。测试要确认 `structuredContent` 完整不变，并确认只看文本时能看到中文结果和下一步。

## 数据、日志与任务接手

- `config.toml` 中的 `runtime.data_root` 默认为项目根目录的 `data/`，`runtime.log_root` 默认为项目根目录的 `logs/`。相对路径一律按 `config.toml` 所在目录解析。
- `data/` 保存样本副本、IDA 分析结果、修改记录和生成文件；`logs/` 保存服务与 IDA 子进程日志。两个目录都不得提交到 Git。
- Agent 接手已有任务时，先调用 `workspace.list` 查找 `workspace_id`，再调用 `workspace.get` 读取 `current_revision`。找到已有分析后，不得重复导入同一样本。
- 静态查询必须显式传入 `workspace_id` 和 `revision`。修改 IDB 时必须先调用 `change.prepare`，再调用 `change.apply`；成功后改用返回的新 `revision`。

## 本地开发

- 使用项目已有的 uv 工具链。开发检查使用 `uv run --locked`，不要修改系统 Python 环境。
- 修改 Python 代码后运行相关 pytest、Ruff 和 basedpyright；涉及 MCP 返回时还要运行真实 stdio 集成测试。
- 完整检查使用 `./scripts/run_quality.ps1`。
