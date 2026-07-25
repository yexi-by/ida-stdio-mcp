# 静态分析

## 概览与搜索

- `program.overview.include` 精确选择 `segments`、`entry_points`、`imports`、`exports`、
  `fixups`、`unwind`、`functions` 或 `strings`。
- `program.search.domains` 只接受不重复的 `function`、`name`、`string`、`bytes`。
- 请求 `function`、`name` 或 `string` 时必须显式提供 `text_query`；空字符串表示按
  IDA 的确定性顺序枚举所选文本域。
- 请求 `bytes` 时必须独立提供非空偶数长度小写十六进制 `bytes_query`。混合文本域与
  `bytes` 时同时提供两个查询字段；不得把 `text_query` 解释为字节模式。
- 名称出现多个候选时保留全部结果，再用 `entity_id` 或严格地址定位。
- 分页默认 50、最大 200。cursor 绑定 workspace、revision 和查询摘要。

## 地址与函数

- image 地址使用 `image_id+rva`，数据库地址使用 `ea`，文件地址使用 `offset`。
- `address.inspect` 用于 bytes、instruction、data、symbol、xrefs 与所属 function。
- `function.inspect.views` 可选择 `summary`、`chunks`、`instructions`、`pseudocode`、
  `ctree_map`、`blocks`、`calls`、`strings`、`stack`、`locals`、`types`。
- 函数范围必须保留非连续 chunks。
- 伪代码与地址是多对多映射；不要把 ctree 文本行视为唯一指令地址。

## 图

- `graph.query.graph` 只接受 `cfg`、`call`、`xref`。
- 图默认最多 200 节点，硬上限 1000。
- `direction` 可选 `outgoing`、`incoming` 或 `both`，`max_depth` 为 0 到 32 的有界
  多跳遍历。
- 节点或边达到硬上限时结果保留已发现事实，并通过 coverage 标记不完整。
- 未解析间接调用由 unresolved edge 或不完整 coverage 表达。
- incoming call graph 无法恢复未知间接调用方时，必须保留
  `indirect_incoming_edges_unresolvable` 限制。

## 函数内数据流

- seed 是函数内地址。
- direction 为 `backward` 或 `forward`；semantics 为 `may` 或 `must`。
- 结果只描述 Hex-Rays microcode 能证明的函数内 def-use。
- `must` 在 CFG 上按全路径 reaching-definition 固定点证明。只有目标 use 的每条进入
  路径都由同一条 microcode 指令定义时，才返回对应 def-use 边；已知分支上的定义不一致
  会得到空关系，不会降级成 `may`。
- forward `must` 复用同一证明，因此表示 use 的唯一 reaching def，不表示该 use 会在
  definition 之后的每条控制流路径上执行。
- unknown call、内存别名和分析上限必须保留为 barrier。屏障经过确定的完整覆盖定义后
  才能被截断；屏障之前的事实不得越过它宣称为证明。
- 达到 `max_steps` 时返回已有的有界结果和 `analysis_limit` barrier，不返回
  capability unavailable。
- 结果不扩展为跨函数或全程序 taint。

## 结论规则

将每项判断绑定到 workspace、revision、实体或地址，并同时保存 coverage 与 provenance。
对 stripped、间接控制流、缺少 unwind 或 decompiler 不可用的区域，明确写出限制。
