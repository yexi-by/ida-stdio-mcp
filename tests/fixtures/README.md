# 测试 fixture

本目录只包含当前系统的自有、可复现 fixture。

- `native_pe_x64.dll`：PE x64 静态分析，包含真实 unwind 目录。
- `native_elf_x64.so`：ELF x64 静态分析，包含 unwind 与 TLS。
- `native_elf_arm64.so`：ELF AArch64 静态分析，包含 unwind 与 TLS。
- `debug_target_x64.exe`：Windows x64 动态调试，包含真实基址重定位；仅传入
  `--ida-re-hold` 时进入 60 秒可抢占运行窗口，默认仍以已知退出码结束。
- `il2cpp_pe_x64.dll`、`il2cpp_elf_x64.so`：IL2CPP-shaped 原生注解测试。
- `il2cpp_metadata_fingerprint.bin`：由自有 canonical JSON 生成的虚构 metadata
  指纹容器，仅用于身份绑定，不模拟或包含 Unity proprietary metadata。

所有二进制都由 `src/` 中的源码通过 LLVM/LLD 22.1.8 生成，不含第三方样本、
Unity runtime 或游戏数据。`bin/SHA256SUMS` 是当前构建的权威摘要。

`native_static.c` 还把 `fixture_multichunk_entry`、`fixture_multichunk_gap` 与
`fixture_multichunk_tail` 放入按名称排序的独立代码段。真实 IDA E2E 会在 disposable
staging IDB 中执行 `src/annotate_multichunk.py`：脚本按导出名解析三个实际边界，确认
gap 隔开 entry 与 tail，再通过 `ida_funcs.append_func_tail` 建立并保存一个非连续函数。
随后测试冷重开 IDB，并逐项核对 `function.inspect.chunks` 的地址与原始独立函数边界。
该注解只作用于测试 staging，不修改二进制或已发布 revision，也不依赖 GUI 或固定 RVA。

```powershell
./scripts/build_fixtures.ps1
```

构建脚本使用可复现链接选项。验收时必须在两个工作树外的不同输出目录构建，
且两份结果都必须与提交的完整摘要清单相同。
