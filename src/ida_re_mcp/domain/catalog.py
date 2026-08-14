"""确定性工具目录。启动后工具集合不随请求或连接变化。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ida_re_mcp.constants import DEFAULT_WORKER_OPERATION_TIMEOUT_SECONDS
from ida_re_mcp.domain.base import StrictModel
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
    WorkspaceRetryInput,
    WorkspaceRetryOutput,
    configured_expert_execute_input,
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
        (
            "查看指定分析项目和版本中某个地址的字节、指令、符号、交叉引用和所属函数。"
            "调用前提供 workspace_id、revision 和 address；需要函数详情时再调用 "
            "function.inspect。"
        ),
        AddressInspectInput,
        AddressInspectOutput,
        read_only=True,
    ),
    _spec(
        "analysis.refine",
        "重新分析指定位置",
        (
            "让 IDA 重新分析指定地址或函数。调用前提供 workspace_id、revision、targets "
            "和 actions；返回 operation_id 后调用 operation.wait，成功后改用新的 revision。"
        ),
        AnalysisRefineInput,
        AnalysisRefineOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "change.apply",
        "保存已经检查的修改",
        (
            "保存 change.prepare 已经检查过的修改。原样传入 workspace_id、"
            "expected_revision、change_set_id 和 digest；成功后，所有后续查询都改用返回的"
            "新 revision。"
        ),
        ChangeApplyInput,
        ChangeApplyOutput,
        read_only=False,
        destructive=True,
        idempotent=False,
    ),
    _spec(
        "change.prepare",
        "检查准备保存的修改",
        (
            "检查重命名、注释、类型和字节修改是否能安全应用，但暂不保存。调用前提供 "
            "workspace_id、base_revision 和 operations；检查 impact 后，把返回的 "
            "change_set_id 与 digest 原样传给 change.apply。"
        ),
        ChangePrepareInput,
        ChangePrepareOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "dataflow.slice",
        "查看函数内的数据流",
        (
            "查看某个值在函数中可能或必然来自哪里、流向哪里。调用前提供 workspace_id、"
            "revision、function、seed、direction 和 semantics；结果中的 barriers 表示"
            "无法继续判断的位置。"
        ),
        DataflowSliceInput,
        DataflowSliceOutput,
        read_only=True,
    ),
    _spec(
        "debug.breakpoints",
        "替换断点集合",
        (
            "用 replace 中的断点完整替换当前调试会话的断点。只能在进程暂停时调用，并提供"
            "当前 stop_id；检查返回的断点状态后，可调用 debug.control 继续执行。"
        ),
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
            "暂停、继续、单步进入、单步越过或运行到指定地址。除 pause 外，调用时使用最近"
            "一次暂停返回的 stop_id；暂停后使用新的 stop_id，运行时调用 debug.events "
            "等待事件。"
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
        (
            "使用指定分析项目和版本启动程序，或在配置允许时附加进程。返回 suspended 时，"
            "后续检查和控制使用返回的 stop_id；返回 running 时调用 debug.events 等待事件。"
        ),
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
            "读取进程启动、暂停、断点、异常和退出等调试事件，也可通过 wait_ms 等待新事件。"
            "再次调用时，把 after_sequence 设为上次返回的 last_sequence，避免重复读取。"
        ),
        DebugEventsInput,
        DebugEventsOutput,
        read_only=True,
        open_world=True,
    ),
    _spec(
        "debug.finish",
        "结束调试会话",
        (
            "与附加的进程分离，或终止由本服务启动的进程。调用前提供 debug_session_id 和 "
            "action；成功后不要再使用这个调试会话。"
        ),
        DebugFinishInput,
        DebugFinishOutput,
        read_only=False,
        destructive=True,
        idempotent=False,
        open_world=True,
    ),
    _spec(
        "debug.inspect",
        "检查暂停时的进程状态",
        (
            "读取暂停时的模块、线程、寄存器、调用栈、内存或内存区域。调用时必须提供当前 "
            "stop_id；进程继续执行后，这次返回的状态和 stop_id 都不能复用。"
        ),
        DebugInspectInput,
        DebugInspectOutput,
        read_only=True,
        open_world=True,
    ),
    _spec(
        "function.inspect",
        "检查函数",
        (
            "读取指定函数的范围、指令、伪代码、基本块、调用、字符串、栈变量和类型。调用前"
            "提供 workspace_id、revision、function 和 views；有 next_cursor 时继续读取"
            "下一页。"
        ),
        FunctionInspectInput,
        FunctionInspectOutput,
        read_only=True,
    ),
    _spec(
        "graph.query",
        "查询关系图",
        (
            "查询控制流图、函数调用图或代码与数据的交叉引用图。调用前提供 workspace_id、"
            "revision、graph 和 roots；结果会明确列出节点、边和无法解析的间接关系数量。"
        ),
        GraphQueryInput,
        GraphQueryOutput,
        read_only=True,
    ),
    _spec(
        "operation.cancel",
        "请求取消后台任务",
        (
            "请求取消 workspace.create、workspace.export、report.build 或 analysis.refine "
            "启动的后台任务。请求被接受不代表任务已经结束；随后调用 operation.wait 查看"
            "最终状态。"
        ),
        OperationCancelInput,
        OperationCancelOutput,
        read_only=False,
    ),
    _spec(
        "operation.wait",
        "等待后台任务",
        (
            "查看 operation_id 对应任务的状态，也可以用 wait_ms 最多等待 30 秒。"
            "任务仍在排队或执行时继续调用；成功后从 result 读取 revision 或生成文件地址。"
        ),
        OperationWaitInput,
        OperationWaitOutput,
        read_only=True,
    ),
    _spec(
        "program.overview",
        "程序概览",
        (
            "查看指定分析版本的文件格式、架构、段、入口点、导入导出、函数和字符串数量。"
            "调用前提供 workspace_id 和 revision；需要具体函数或地址时再调用相应检查工具。"
        ),
        ProgramOverviewInput,
        ProgramOverviewOutput,
        read_only=True,
    ),
    _spec(
        "program.search",
        "搜索程序事实",
        (
            "按函数、名称、字符串或字节搜索指定分析版本。调用前提供 workspace_id、revision "
            "和 domains，并提供 text_query 或 bytes_query；有 next_cursor 时继续读取下一页。"
        ),
        ProgramSearchInput,
        ProgramSearchOutput,
        read_only=True,
    ),
    _spec(
        "report.build",
        "生成分析报告",
        (
            "根据指定分析版本生成 Markdown 或 JSON 报告。调用前提供 workspace_id、revision、"
            "format 和 sections；返回 operation_id 后调用 operation.wait，再用结果中的"
            "文件地址读取报告。"
        ),
        ReportBuildInput,
        ReportBuildOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "type.inspect",
        "检查类型",
        (
            "按实体编号、完整名称或地址查看 IDA 类型及字段位置。调用前提供 workspace_id、"
            "revision 和 type；有 next_cursor 时继续读取下一页。"
        ),
        TypeInspectInput,
        TypeInspectOutput,
        read_only=True,
    ),
    _spec(
        "workspace.create",
        "导入新样本",
        (
            "把本机样本复制到项目 data 目录，计算 SHA-256，并启动首次 IDA 分析。"
            "调用前先用 workspace.list 确认样本没有重复导入；把返回的 "
            "analysis_operation_id 作为 operation_id 调用 operation.wait，成功后取得"
            "首个 revision。"
        ),
        WorkspaceCreateInput,
        WorkspaceCreateOutput,
        read_only=False,
        idempotent=False,
        open_world=True,
    ),
    _spec(
        "workspace.export",
        "导出分析数据库",
        (
            "把指定 workspace_id 和 revision 的 IDA 数据库导出为文件。返回 operation_id "
            "后调用 operation.wait；成功后使用 result.artifact_uri 读取文件。"
        ),
        WorkspaceExportInput,
        WorkspaceExportOutput,
        read_only=False,
        idempotent=False,
    ),
    _spec(
        "workspace.get",
        "查看分析项目",
        (
            "读取一个分析项目的样本信息、current_revision 和已有版本记录。Agent 接手已有"
            "任务时应先调用此工具；有 next_cursor 时继续读取下一页，后续查询使用"
            " current_revision。"
        ),
        WorkspaceGetInput,
        WorkspaceGetOutput,
        read_only=True,
    ),
    _spec(
        "workspace.list",
        "列出已有分析项目",
        (
            "列出 data 目录中已经保存的分析项目。Agent 接手任务时先调用此工具查找 "
            "workspace_id，再调用 workspace.get 读取 current_revision；有 next_cursor 时"
            "继续读取下一页。"
        ),
        WorkspaceListInput,
        WorkspaceListOutput,
        read_only=True,
    ),
    _spec(
        "workspace.retry",
        "重试首次分析",
        (
            "重新启动一个已有项目的首次 IDA 分析。仅当 workspace.list 显示 state 为 "
            "failed 且尚无 revision 时调用；服务会重新校验保存的样本，不要再次导入同一文件。"
            "把返回的 analysis_operation_id 传给 operation.wait，成功后取得首个 revision。"
        ),
        WorkspaceRetryInput,
        WorkspaceRetryOutput,
        read_only=False,
        idempotent=False,
    ),
)


def _expert_tool_spec(operation_timeout_seconds: int) -> ToolSpec:
    return _spec(
        "expert.execute",
        "执行专家 IDAPython",
        (
            "在单独的 IDA 进程中执行 IDAPython，并把数据库修改保存为新 revision。此功能可以"
            "访问文件、网络和子进程，只应运行可信代码；执行后读取 structuredContent 中的输出，"
            "并让后续查询改用新 revision。"
        ),
        configured_expert_execute_input(operation_timeout_seconds),
        ExpertExecuteOutput,
        read_only=False,
        destructive=True,
        idempotent=False,
        open_world=True,
    )


EXPERT_TOOL_SPEC: Final = _expert_tool_spec(DEFAULT_WORKER_OPERATION_TIMEOUT_SECONDS)


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
    operation_timeout_seconds: int = DEFAULT_WORKER_OPERATION_TIMEOUT_SECONDS,
) -> tuple[ToolSpec, ...]:
    """构建一次性的、按名称排序且无重复项的目录。"""

    specs = (
        *CORE_TOOL_SPECS,
        *(AUTHORING_TOOL_SPECS if enable_authoring else ()),
        *(DEBUG_TOOL_SPECS if enable_debug else ()),
        *((_expert_tool_spec(operation_timeout_seconds),) if enable_expert else ()),
    )
    ordered = tuple(sorted(specs, key=lambda item: item.name))
    names = tuple(item.name for item in ordered)
    if len(names) != len(set(names)):
        raise RuntimeError("工具目录包含重复名称")
    return ordered


TOOL_CATALOG: Final = build_tool_catalog()
