# Fixture 工具链

当前 fixture 只接受以下生成工具：

- LLVM Clang `22.1.8`
- LLD / LLD-Link `22.1.8`
- PowerShell `7.4+`

唯一生成入口是仓库根目录的 `scripts/build_fixtures.ps1`。脚本固定目标三元组、
优化级别、无运行库链接、无 build-id、确定性 PE 链接和路径前缀映射，并在每次原生
工具调用后检查退出码。

`scripts/check_fixture_reproducibility.ps1` 会在工作树外的两个不同目录执行完整构建，
并要求两份 `SHA256SUMS` 与仓库提交清单完全一致。提交二进制的摘要和 metadata
指纹容器由 `tests/unit/test_fixtures.py` 再次校验。
