# 官方离线资料入口

本目录只作为项目相关官方资料的离线证据库，不作为运行时工作目录。

## 主资料包

- `latest-2026-06-01/`：当前主资料包。
- `latest-2026-06-01/markdown/README.md`：离线阅读入口。

主资料包只覆盖 `ida-stdio-mcp` 当前 Python / IDAPython / headless / MCP 运行链路需要的官方页面，包括 IDA headless、IDAPython 模块、Hex-Rays Python API、debugger、decompiler batch、IDA Domain 相关页面和 MCP `2025-11-25` 规格页。

## 保留规则

- 本目录只保留 AI 可读的 Markdown 文档。
- 不保留历史全站镜像、HTML 原始页、JSON manifest、GUI 教程镜像、C++ SDK 或旧版本 SDK 抓取。
- 后续刷新资料时，先生成 Markdown，再更新 `docs/官方文档资料包.md` 与 `docs/官方知识覆盖清单.md`。
