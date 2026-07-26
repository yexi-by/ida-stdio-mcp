# IL2CPP bundle 格式规范

`change.prepare` 的 `import_il2cpp_bundle` 操作只接受本文定义的 canonical NDJSON。
服务不执行分析器或生成器，也不直接解析 Il2CppDumper/Il2CppInspector 的输出；调用方
必须先把外部工具结果转换成本格式。

`src/ida_re_mcp/il2cpp/models.py` 与 `src/ida_re_mcp/il2cpp/bundle.py` 是格式的事实来源。
所有对象均为封闭结构：缺少必填字段、出现额外字段或依赖宽松类型转换都会被拒绝。

## 容器与记录顺序

MIME 固定为 `application/vnd.ida-re.il2cpp-bundle+ndjson`。

| 约束 | 规则 |
|---|---|
| 编码 | UTF-8；禁止 BOM 和 Unicode surrogate |
| 换行 | 只允许 LF，禁止 CR，文件必须以 LF 结束 |
| 每行 | 一条非空 JSON object，且必须已经 canonicalized |
| JSON 数值 | 只允许绝对值不超过 `2^53-1` 的整数；禁止浮点和非有限值 |
| 文件上限 | 64 MiB、1,000,000 条记录 |

Canonicalization 要求 object 键按字典序排列、分隔符固定为 `,` 与 `:`，且没有多余空白。
服务逐行解析并重新编码；重编码字节与输入不同就拒绝。应使用
`ida_re_mcp.il2cpp.canonical_ndjson` 生成文件。

bundle 必须且只能有一个 `manifest`，且位于第一行。后续记录阶段只能单调前进：

```text
manifest → managed_image → type → method → symbol
```

同阶段内不要求按名称或 ID 排序。

## ID、引用与 RVA

除 manifest 外，每条记录都有服务端可重算的语义 ID，格式为 `<prefix>_<sha256>`。

| 记录 | 前缀 | 参与 ID 的字段 |
|---|---|---|
| `managed_image` | `image_` | `kind`, `name`, `assembly_name` |
| `type` | `type_` | `kind`, `image_id`, `namespace`, `name` |
| `method` | `method_` | `kind`, `image_id`, `declaring_type_id`, `name`, `managed_signature` |
| `symbol` | `symbol_` | `kind`, `name`, `rva`, `symbol_kind` |

使用 `ida_re_mcp.il2cpp.compute_record_id` 计算 ID。layout、native signature 或 symbol
binding 不参与 ID，但仍会被完整验证。所有 ID 在 bundle 内必须唯一；`image_id` 只能
指向 image，`declaring_type_id` 与 `type_id` 只能指向 type，`method_id` 只能指向
method。所有引用都必须在同一 bundle 中有定义。

`rva` 只接受 canonical 小写十六进制，正则为
`^0x(?:0|[1-9a-f][0-9a-f]*)$`。它相对 native image base，不是 IDA database EA 或
文件偏移；数值必须小于 manifest 的 `native.image_size`，服务负责映射到当前镜像。

## TypeRef

TypeRef 是封闭 tagged union，不接受 C/C++ 声明字符串。

| `kind` | 字段 | 语义与限制 |
|---|---|---|
| `primitive` | `name` | `void`, `bool`, `i8/u8`, `i16/u16`, `i32/u32`, `i64/u64`, `f32/f64`, `native_int/native_uint` |
| `named` | `type_id` | 引用本 bundle 中的 `type` |
| `pointer` | `to`, `const` | 64 位指针；`const` 修饰 pointee，缺省为 `false` |
| `array` | `element`, `count` | 连续定长数组；`count` 为 1..1,000,000 |

`void` 只允许作为 native 返回类型或 pointer target，不能作为字段、参数或 data symbol
的值类型。named type 经 pointer 递归合法；直接或经 array 形成的递归值类型会被拒绝。
primitive 的宽度和自然对齐按名称确定；`native_int/native_uint` 在本 schema 中均为
8 字节。

## manifest

manifest 把注解绑定到当前 workspace 的 native 二进制和用户选择的 metadata。所有身份
字段都会与服务端可信值比较。

| 字段 | 类型 | 约束 |
|---|---|---|
| `kind` | string | 固定 `manifest` |
| `schema` | string | 固定 `"1"`；字段名不是 `schema_version` |
| `media_type` | string | 固定为本页开头的 MIME |
| `native` | object | native 文件及加载镜像身份 |
| `metadata` | object | metadata 文件身份 |

`native`：

| 字段 | 语义与限制 |
|---|---|
| `sha256` | native 文件的 64 个小写十六进制字符 SHA-256 |
| `size` | native 文件字节数，至少 1 |
| `image_size` | 加载镜像可寻址范围，至少 1；不是文件大小 |
| `architecture` | `x86_64` 或 `aarch64` |
| `abi` | `msvc-x64`, `sysv-x64` 或 `aapcs64` |
| `pointer_width` | 固定 `64` |
| `endianness` | 固定 `little` |

架构与 ABI 必须匹配：`x86_64` 对应 `msvc-x64` 或 `sysv-x64`，`aarch64` 对应
`aapcs64`。`metadata` 只有 `sha256` 和 `size`，分别表示 metadata 文件的摘要与字节数。

## managed_image

| 字段 | 语义与限制 |
|---|---|
| `kind` | 固定 `managed_image` |
| `id` | `image_<sha256>`，按本页 ID 规则重算 |
| `name` | managed image 名，1..512 字符 |
| `assembly_name` | assembly 文件名，1..512 字符 |

## type

| 字段 | 语义与限制 |
|---|---|
| `kind` | 固定 `type` |
| `id` | `type_<sha256>`，按本页 ID 规则重算 |
| `image_id` | 所属 managed image |
| `namespace` | namespace，可为空，最长 1024 字符 |
| `name` | 类型名，1..512 字符 |
| `layout` | `struct`、`union` 或 `enum` layout |

`struct` 与 `union` layout：

| 字段 | 语义与限制 |
|---|---|
| `kind` | `struct` 或 `union` |
| `size` | 完整 ABI 大小，至少 1，必须是 `alignment` 的整数倍 |
| `alignment` | ABI 对齐，1..4096 的二次幂 |
| `fields` | `{name, offset, type}` 数组；字段名必须唯一 |

`offset` 是字段相对 layout 起点的字节偏移。每个字段必须满足 TypeRef 的自然对齐，完整
落在 `size` 内，且自然对齐不能大于 layout 的 `alignment`。struct 字段按 offset
单调排列且不能重叠；union 的所有字段 offset 必须为 0。

`size` 必须包含 ABI 的内部间隙和尾部 padding。例如最后一个 `u32` 位于 offset 8、
layout 对齐为 8 时，包含尾部 padding 的 struct size 是 16。间隙用 offset 与 size
表达，不需要创建伪 padding 字段。

`enum` layout：

| 字段 | 语义与限制 |
|---|---|
| `kind` | 固定 `enum` |
| `underlying` | `i8/u8`, `i16/u16`, `i32/u32` 或 `i64/u64` |
| `members` | `{name, value}` 数组；名称唯一，整数值必须落在 underlying 范围内 |

## method

| 字段 | 语义与限制 |
|---|---|
| `kind` | 固定 `method` |
| `id` | `method_<sha256>`，按本页 ID 规则重算 |
| `image_id` | 所属 managed image |
| `declaring_type_id` | declaring type；必须与 method 属于同一 image |
| `name` | managed method 名，1..512 字符 |
| `rva` | 原生函数入口 RVA |
| `managed_signature` | `{return_type, parameters}`；只用于身份和展示 |
| `native_signature` | 原生 ABI 原型，或显式 `null` |

managed parameter 是 `{name, type}`；`type` 是 1..512 字符的 managed 类型名，参数最多
256 个。managed signature 不会写入 IDA。

native signature：

| 字段 | 语义与限制 |
|---|---|
| `calling_convention` | manifest ABI 对应的 `win64`, `sysv` 或 `aapcs64` |
| `return_type` | TypeRef；允许 `void` |
| `parameters` | `{name, type}` 数组，最多 256 个 |
| `variadic` | 固定 `false` |

只有明确提供 native signature 时才写入 IDA 原型。IL2CPP 的隐藏参数也必须按真实原生
顺序列出，例如示例 `Actor_GetScore` 的 `method` metadata 指针。共享原生函数体可以
对应多个 managed method identity，不能任意折叠。

## symbol

| 字段 | 语义与限制 |
|---|---|
| `kind` | 固定 `symbol` |
| `id` | `symbol_<sha256>`，按本页 ID 规则重算 |
| `name` | 目标符号名，1..512 字符 |
| `rva` | function 入口或 data 起点的 RVA |
| `symbol_kind` | `function` 或 `data` |
| `method_id` | function 必填并绑定相同 RVA 的 method；data 必须为 `null` |
| `type` | data 必填的 TypeRef；function 必须为 `null` |

function RVA 必须精确落在 IDA 已分析函数入口。data 的完整类型宽度必须留在
`native.image_size` 内，且不能覆盖函数或已分析代码。同一个 bundle 内不允许两个
symbol 使用同一 RVA，function 与 data 也不能竞争同一地址。

## 完整真实示例

下列 8 行与
[`tests/fixtures/src/il2cpp_bundle_example.ndjson`](../../../tests/fixtures/src/il2cpp_bundle_example.ndjson)
逐字节相同。它绑定真实的 `il2cpp_pe_x64.dll`（2560 字节、image size `0x5000`）和
`il2cpp_metadata_fingerprint.bin`（206 字节），布局来自
`tests/fixtures/src/il2cpp_shaped.cpp`。`Actor` 的 `ObjectHeader` 被按真实 offset 展开为
`klass`/`monitor`；`MethodMetadata` 的 size 16 包含 `token` 后的 4 字节尾部 padding；
RVA `0x1000` 的 `Actor_GetScore` 包含隐藏的 const metadata 参数。

<!-- il2cpp-bundle-example:start -->
```ndjson
{"kind":"manifest","media_type":"application/vnd.ida-re.il2cpp-bundle+ndjson","metadata":{"sha256":"d2f9bc026488660c94b9d49485ecd1070d92483df1bd08bf946bf300fee45ee4","size":206},"native":{"abi":"msvc-x64","architecture":"x86_64","endianness":"little","image_size":20480,"pointer_width":64,"sha256":"f7d61718ce407ed5ced0049c689aff5ee1a14332037f173d980604b2c0e97021","size":2560},"schema":"1"}
{"assembly_name":"Assembly-CSharp.dll","id":"image_8ce07043994102bd81918ea6c2352015e107e93a8fedf4b77a66e124ac840c1a","kind":"managed_image","name":"Assembly-CSharp"}
{"id":"type_1e39a99be27e4e8548eff98b47871b6e53d96c99d2061e7f519c6f12261ef171","image_id":"image_8ce07043994102bd81918ea6c2352015e107e93a8fedf4b77a66e124ac840c1a","kind":"type","layout":{"alignment":4,"fields":[{"name":"x","offset":0,"type":{"kind":"primitive","name":"f32"}},{"name":"y","offset":4,"type":{"kind":"primitive","name":"f32"}},{"name":"z","offset":8,"type":{"kind":"primitive","name":"f32"}}],"kind":"struct","size":12},"name":"Vec3","namespace":"Game"}
{"id":"type_3ff2564e384ed104387614d2c98d8a9fe9ef9c1a5785b7203e9bc8710bdd3ffa","image_id":"image_8ce07043994102bd81918ea6c2352015e107e93a8fedf4b77a66e124ac840c1a","kind":"type","layout":{"kind":"enum","members":[{"name":"Idle","value":0},{"name":"Running","value":1},{"name":"Disabled","value":2}],"underlying":"i32"},"name":"ActorState","namespace":"Game"}
{"id":"type_79856816f6f01ce250bb170c6d4eb47e2c4319fe76a723c0125565b9f9d18ccd","image_id":"image_8ce07043994102bd81918ea6c2352015e107e93a8fedf4b77a66e124ac840c1a","kind":"type","layout":{"alignment":8,"fields":[{"name":"name","offset":0,"type":{"const":true,"kind":"pointer","to":{"kind":"primitive","name":"i8"}}},{"name":"token","offset":8,"type":{"kind":"primitive","name":"u32"}}],"kind":"struct","size":16},"name":"MethodMetadata","namespace":""}
{"id":"type_ba51838e5731fbc0b180c29ae1849547d9d36e7ff59ef78357b2e7a24e2d2130","image_id":"image_8ce07043994102bd81918ea6c2352015e107e93a8fedf4b77a66e124ac840c1a","kind":"type","layout":{"alignment":8,"fields":[{"name":"klass","offset":0,"type":{"const":false,"kind":"pointer","to":{"kind":"primitive","name":"void"}}},{"name":"monitor","offset":8,"type":{"const":false,"kind":"pointer","to":{"kind":"primitive","name":"void"}}},{"name":"instance_id","offset":16,"type":{"kind":"primitive","name":"i32"}},{"name":"position","offset":20,"type":{"kind":"named","type_id":"type_1e39a99be27e4e8548eff98b47871b6e53d96c99d2061e7f519c6f12261ef171"}}],"kind":"struct","size":32},"name":"Actor","namespace":"Game"}
{"declaring_type_id":"type_ba51838e5731fbc0b180c29ae1849547d9d36e7ff59ef78357b2e7a24e2d2130","id":"method_fe02b14b424c4e31f33ea671f6722ba073d8ff81c84555a1dad4319c72d55a7f","image_id":"image_8ce07043994102bd81918ea6c2352015e107e93a8fedf4b77a66e124ac840c1a","kind":"method","managed_signature":{"parameters":[{"name":"bonus","type":"System.Int32"}],"return_type":"System.Int32"},"name":"GetScore","native_signature":{"calling_convention":"win64","parameters":[{"name":"self","type":{"const":false,"kind":"pointer","to":{"kind":"named","type_id":"type_ba51838e5731fbc0b180c29ae1849547d9d36e7ff59ef78357b2e7a24e2d2130"}}},{"name":"bonus","type":{"kind":"primitive","name":"i32"}},{"name":"method","type":{"const":true,"kind":"pointer","to":{"kind":"named","type_id":"type_79856816f6f01ce250bb170c6d4eb47e2c4319fe76a723c0125565b9f9d18ccd"}}}],"return_type":{"kind":"primitive","name":"i32"},"variadic":false},"rva":"0x1000"}
{"id":"symbol_c1a5f21c8b7bc46ea34fb289fd0b3dea0424e30cbc8c386752f5ef8cc2910978","kind":"symbol","method_id":"method_fe02b14b424c4e31f33ea671f6722ba073d8ff81c84555a1dad4319c72d55a7f","name":"Actor_GetScore","rva":"0x1000","symbol_kind":"function","type":null}
```
<!-- il2cpp-bundle-example:end -->

## 冲突与失败

用户确认的名称不会被自动覆盖，`change.prepare` 会报告 `user_name_preserved` 冲突。
类型冲突必须在 `import_il2cpp_bundle.type_resolutions` 中针对具体 `type_id` 选择
`keep` 或 `replace`，同一 `type_id` 不得重复。

目标身份不匹配、悬空或跨种类引用、非法布局、越界 RVA、ABI 不一致或无法验证的函数
入口都会使整个事务失败，不产生新 revision。事务语义见
[authoring-il2cpp.md](authoring-il2cpp.md)。
