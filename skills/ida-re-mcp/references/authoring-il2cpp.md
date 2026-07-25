# 事务化写回与 IL2CPP

## 两阶段事务

`change.prepare` 对完整批次做预检，生成绑定以下内容的不可变计划：

- workspace 与 base revision；
- canonical operations；
- digest；
- 每项操作的 preimage；
- impact 与 conflicts。

`change.apply` 只接受相同的 `change_set_id`、digest 与 `expected_revision`。成功后返回新的
revision；任一步骤失败都不得改变 HEAD、已发布 revision 或样本摘要。

公开写回操作只有 `rename`、`comment`、`set_type`、`patch_bytes` 与
`import_il2cpp_bundle`。`change.prepare` 为每项操作捕获 base revision 的 preimage；
rename/comment 在需要时提供对应 expected 值，patch 必须提供从 base revision 回读的
expected bytes，且 replacement bytes 与其长度一致并非空。撤销使用 inverse change
重新 prepare，并执行同样的校验与发布流程。

## IL2CPP bundle

MIME 固定为 `application/vnd.ida-re.il2cpp-bundle+ndjson`。记录按以下顺序出现：

1. manifest；
2. managed image；
3. type；
4. method；
5. symbol。

manifest 绑定 native binary 与 metadata 的 SHA-256、格式、架构、ABI、指针宽度和端序。
地址只允许 RVA；服务端映射到当前 Native image，并重新计算记录 ID。

类型引用使用封闭 tagged union，不传 C/C++ 声明字符串。managed signature 只用于身份与
展示；只有 bundle 中明确提供的 native signature 才能写入 IDA。共享原生函数体可以
对应多个 managed method identity，不能任意折叠。

image、type、method 与 symbol 使用各自固定前缀的记录 ID，引用不得跨记录种类。struct
和 union 的 alignment 必须是 1 到 4096 的二次幂，size 必须包含尾部 padding；每个
字段必须满足自然对齐、完整落在 size 内且 struct 字段不得重叠。named type 通过
pointer 递归是合法的，直接或经 array 形成的递归值类型会被拒绝。

function symbol 必须绑定相同 RVA 的 method，并精确落在 IDA 已分析函数入口；data
symbol 必须声明数据类型、不得绑定 method，且其完整类型宽度范围不得覆盖函数或已分析
代码。function 与 data 不能在同一 RVA 竞争。

用户确认的名称不自动覆盖。类型冲突必须提供明确 resolution。目标身份不匹配、悬空
引用、非法布局、越段地址或无法验证的函数落点应使事务失败。

bundle 是注解输入；服务不在事务中执行分析器或生成器。

## Expert 边界

`expert.execute` 默认不注册。操作者启用后，只传 inline IDAPython；运行时间默认 30 秒、
最大 120 秒，输出超过 inline 限制时返回 artifact，写入仍通过新 revision 发布。
disposable staging 只保护已发布 IDB 事务边界，不是 Python 沙箱：服务不能阻止代码访问
文件、网络或启动子进程。
