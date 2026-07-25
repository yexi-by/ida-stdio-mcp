"""确定性工具目录。启动后工具集合不随请求或连接变化。"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ida_re_mcp.domain.base import JsonObject, StrictModel, current_json_schema
from ida_re_mcp.domain.tools import (
    AddressInspectInput,
    AddressInspectOutput,
    AnalysisRefineInput,
    AnalysisRefineOutput,
    ChangeApplyInput,
    ChangeApplyOutput,
    ChangePrepareInput,
    ChangePrepareOutput,
    DataflowSliceInput,
    DataflowSliceOutput,
    DebugBreakpointsInput,
    DebugBreakpointsOutput,
    DebugControlInput,
    DebugControlOutput,
    DebugEstablishInput,
    DebugEstablishOutput,
    DebugEventsInput,
    DebugEventsOutput,
    DebugFinishInput,
    DebugFinishOutput,
    DebugInspectInput,
    DebugInspectOutput,
    ExpertExecuteInput,
    ExpertExecuteOutput,
    FunctionInspectInput,
    FunctionInspectOutput,
    GraphQueryInput,
    GraphQueryOutput,
    OperationCancelInput,
    OperationCancelOutput,
    OperationWaitInput,
    OperationWaitOutput,
    ProgramOverviewInput,
    ProgramOverviewOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
    ReportBuildInput,
    ReportBuildOutput,
    TypeInspectInput,
    TypeInspectOutput,
    WorkspaceCreateInput,
    WorkspaceCreateOutput,
    WorkspaceExportInput,
    WorkspaceExportOutput,
    WorkspaceGetInput,
    WorkspaceGetOutput,
    WorkspaceListInput,
    WorkspaceListOutput,
)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """一个工具的公开契约与行为提示。"""

    name: str
    title: str
    description: str
    input_model: type[StrictModel]
    output_model: type[StrictModel]
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool

    def as_wire_definition(self) -> JsonObject:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": current_json_schema(self.input_model),
            "outputSchema": current_json_schema(self.output_model),
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            },
        }


def _spec(
    name: str,
    title: str,
    description: str,
    input_model: type[StrictModel],
    output_model: type[StrictModel],
    *,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = True,
    open_world: bool = False,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        title=title,
        description=description,
        input_model=input_model,
        output_model=output_model,
        read_only=read_only,
        destructive=destructive,
        idempotent=idempotent,
        open_world=open_world,
    )


_STANDARD_SPECS: Final = (
    _spec(
        "address.inspect",
        "检查地址",
        "在显式 workspace revision 中检查一个已区分地址空间的地址及其事实。",
        AddressInspectInput,
        AddressInspectOutput,
        read_only=True,
    ),
    _spec(
        "analysis.refine",
        "细化分析",
        "在 staging IDB 中执行有界再分析并异步发布新 revision。",
        AnalysisRefineInput,
        AnalysisRefineOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "change.apply",
        "应用变更集",
        "按 expected_revision 与 digest 原子应用已准备的变更集。成功后发布新 revision。",
        ChangeApplyInput,
        ChangeApplyOutput,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    _spec(
        "change.prepare",
        "准备变更集",
        "完整预检一组 IDB 变更并生成绑定 base revision 的不可变变更集和摘要。",
        ChangePrepareInput,
        ChangePrepareOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "dataflow.slice",
        "查询函数内数据流",
        "基于 Hex-Rays microcode 返回函数内有界 MAY/MUST 前向或后向切片及未知屏障。",
        DataflowSliceInput,
        DataflowSliceOutput,
        read_only=True,
    ),
    _spec(
        "debug.breakpoints",
        "替换断点集合",
        "在指定 suspended stop 上用 image/module RVA 语义替换会话断点并返回真实激活状态。",
        DebugBreakpointsInput,
        DebugBreakpointsOutput,
        read_only=False,
        idempotent=True,
        open_world=True,
    ),
    _spec(
        "debug.control",
        "控制调试进程",
        (
            "执行 pause、continue、step_into、step_over 或 run_to; 只有观察到对应 IDA 事件, "
            "或明确验证 DSTATE_RUN 状态后才完成。"
        ),
        DebugControlInput,
        DebugControlOutput,
        read_only=False,
        idempotent=False,
        open_world=True,
    ),
    _spec(
        "debug.establish",
        "建立调试会话",
        "为 workspace revision 启动或按策略附加 Windows x64 目标。观察到真实事件后才成功。",
        DebugEstablishInput,
        DebugEstablishOutput,
        read_only=False,
        idempotent=False,
        open_world=True,
    ),
    _spec(
        "debug.events",
        "等待调试事件",
        (
            "按单调 sequence 游标读取或长轮询调试事实; provenance 明确区分 IDA 事件、"
            "debugger 状态观察和服务事件。"
        ),
        DebugEventsInput,
        DebugEventsOutput,
        read_only=True,
        open_world=True,
    ),
    _spec(
        "debug.finish",
        "结束调试会话",
        "分离目标或仅在策略允许时终止本服务启动的目标并等待真实完成事件。",
        DebugFinishInput,
        DebugFinishOutput,
        read_only=False,
        destructive=True,
        idempotent=False,
        open_world=True,
    ),
    _spec(
        "debug.inspect",
        "检查暂停快照",
        "只在匹配 stop_id 的 suspended 状态读取模块、线程、寄存器、调用栈或有限内存。",
        DebugInspectInput,
        DebugInspectOutput,
        read_only=True,
        open_world=True,
    ),
    _spec(
        "function.inspect",
        "检查函数",
        "按需返回函数 chunks、指令、伪代码、ctree 映射、块、调用、字符串、栈、局部变量与类型视图。",
        FunctionInspectInput,
        FunctionInspectOutput,
        read_only=True,
    ),
    _spec(
        "graph.query",
        "查询关系图",
        "返回有界 CFG、调用图或代码/数据 xref 图并显式报告未解析间接边。",
        GraphQueryInput,
        GraphQueryOutput,
        read_only=True,
    ),
    _spec(
        "operation.cancel",
        "取消长操作",
        "请求取消显式 operation。返回真实状态且不把已接收请求冒充已取消。",
        OperationCancelInput,
        OperationCancelOutput,
        read_only=False,
    ),
    _spec(
        "operation.wait",
        "等待长操作",
        "查询或最多长轮询 30 秒以取得显式 operation 的当前状态。",
        OperationWaitInput,
        OperationWaitOutput,
        read_only=True,
    ),
    _spec(
        "program.overview",
        "程序概览",
        "读取镜像、段、入口、导入导出、fixup、unwind、函数和字符串的 revision 固定概览。",
        ProgramOverviewInput,
        ProgramOverviewOutput,
        read_only=True,
    ),
    _spec(
        "program.search",
        "搜索程序事实",
        (
            "在 function、name、string 文本域与独立 bytes_query 字节域执行有界搜索; "
            "空 text_query 枚举所选文本域。"
        ),
        ProgramSearchInput,
        ProgramSearchOutput,
        read_only=True,
    ),
    _spec(
        "report.build",
        "构建逆向报告",
        "从指定 revision 构建不可变 Markdown 或 JSON 报告 artifact。",
        ReportBuildInput,
        ReportBuildOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "type.inspect",
        "检查类型",
        "按实体、精确名称或地址检查 IDA 类型与字段布局。",
        TypeInspectInput,
        TypeInspectOutput,
        read_only=True,
    ),
    _spec(
        "workspace.create",
        "创建工作区",
        "复制并哈希原始 Native 样本。建立首个冷 IDB revision 并启动 headless 分析。",
        WorkspaceCreateInput,
        WorkspaceCreateOutput,
        read_only=False,
        idempotent=False,
        open_world=True,
    ),
    _spec(
        "workspace.export",
        "导出工作区产物",
        "从不可变 revision 异步导出 IDB, 并返回可逐块读取的不可变 artifact 索引。",
        WorkspaceExportInput,
        WorkspaceExportOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "workspace.get",
        "读取工作区",
        "读取 workspace 当前 revision、样本身份与可用 revision 元数据。",
        WorkspaceGetInput,
        WorkspaceGetOutput,
        read_only=True,
    ),
    _spec(
        "workspace.list",
        "列出工作区",
        "确定性分页列出当前数据目录内的 workspace。",
        WorkspaceListInput,
        WorkspaceListOutput,
        read_only=True,
    ),
)

EXPERT_TOOL_SPEC: Final = _spec(
    "expert.execute",
    "执行专家 IDAPython",
    (
        "在 disposable staging worker 中执行有界 inline IDAPython, 写入只通过新 revision "
        "发布; 开放世界执行不能阻止文件、网络或子进程访问。"
    ),
    ExpertExecuteInput,
    ExpertExecuteOutput,
    read_only=False,
    destructive=True,
    idempotent=False,
    open_world=True,
)


_AUTHORING_NAMES: Final = frozenset(
    {
        "analysis.refine",
        "change.apply",
        "change.prepare",
    }
)
_DEBUG_NAMES: Final = frozenset(
    {
        "debug.breakpoints",
        "debug.control",
        "debug.establish",
        "debug.events",
        "debug.finish",
        "debug.inspect",
    }
)

CORE_TOOL_SPECS: Final = tuple(
    spec
    for spec in _STANDARD_SPECS
    if spec.name not in _AUTHORING_NAMES and spec.name not in _DEBUG_NAMES
)
AUTHORING_TOOL_SPECS: Final = tuple(
    spec for spec in _STANDARD_SPECS if spec.name in _AUTHORING_NAMES
)
DEBUG_TOOL_SPECS: Final = tuple(spec for spec in _STANDARD_SPECS if spec.name in _DEBUG_NAMES)


def build_tool_catalog(
    *,
    enable_authoring: bool = True,
    enable_debug: bool = True,
    enable_expert: bool = False,
) -> tuple[ToolSpec, ...]:
    """构建一次性的、按名称排序且无重复项的目录。"""

    specs = (
        *CORE_TOOL_SPECS,
        *(AUTHORING_TOOL_SPECS if enable_authoring else ()),
        *(DEBUG_TOOL_SPECS if enable_debug else ()),
        *((EXPERT_TOOL_SPEC,) if enable_expert else ()),
    )
    ordered = tuple(sorted(specs, key=lambda item: item.name))
    names = tuple(item.name for item in ordered)
    if len(names) != len(set(names)):
        raise RuntimeError("工具目录包含重复名称")
    return ordered


TOOL_CATALOG: Final = build_tool_catalog()
TOOL_CATALOG_BY_NAME: Final = MappingProxyType({spec.name: spec for spec in TOOL_CATALOG})
