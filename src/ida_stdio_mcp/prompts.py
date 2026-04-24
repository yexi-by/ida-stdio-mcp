"""MCP prompts 模板注册表。"""

from __future__ import annotations

from dataclasses import dataclass
from string import Template

from .models import JsonObject, JsonValue
from .result import normalize_json_object


@dataclass(slots=True, frozen=True)
class PromptSpec:
    """单个 MCP prompt 模板。"""

    name: str
    title: str
    description: str
    argument_names: tuple[str, ...]
    template: str


class PromptRegistry:
    """管理 prompts/list 与 prompts/get。"""

    def __init__(self, prompts: tuple[PromptSpec, ...]) -> None:
        self._prompts = {prompt.name: prompt for prompt in prompts}

    def has_prompts(self) -> bool:
        """返回当前是否注册了 prompt。"""
        return bool(self._prompts)

    def list_prompts(self) -> list[JsonObject]:
        """返回 MCP prompts/list 结果。"""
        result: list[JsonObject] = []
        for prompt in self._prompts.values():
            arguments: list[JsonValue] = [
                {
                    "name": name,
                    "description": _argument_description(name),
                    "required": False,
                }
                for name in prompt.argument_names
            ]
            result.append(
                normalize_json_object(
                    {
                        "name": prompt.name,
                        "title": prompt.title,
                        "description": prompt.description,
                        "arguments": arguments,
                    }
                )
            )
        return result

    def get_prompt(self, name: str, arguments: JsonObject | None = None) -> JsonObject:
        """展开指定 prompt。"""
        prompt = self._prompts.get(name)
        if prompt is None:
            raise KeyError(f"未知 prompt：{name}")
        resolved_arguments = arguments or {}
        values = {
            argument_name: str(resolved_arguments.get(argument_name, ""))
            for argument_name in prompt.argument_names
        }
        text = Template(prompt.template).safe_substitute(values).strip()
        return normalize_json_object(
            {
                "description": prompt.description,
                "messages": [
                    {
                        "role": "user",
                        "content": {"type": "text", "text": text},
                    }
                ],
            }
        )


def build_prompt_registry() -> PromptRegistry:
    """构建 V2 默认 prompt 模板。"""
    return PromptRegistry(
        (
            PromptSpec(
                name="triage-native",
                title="Native 样本开局分析",
                description="按 V2 slim 工作流完成原生样本快速 triage。",
                argument_names=("target_path",),
                template="""
请用 ida-stdio-mcp V2 slim 工作流分析原生样本。

固定顺序：
1. 调用 get_workspace_state，确认当前状态。
2. 如果未打开样本，调用 open_target 打开：$target_path；大型 native/UE 样本保持 run_auto_analysis=false。
3. 调用 triage_binary 获取入口点、关键函数、导入分类和字符串索引状态。
4. 选择最可疑的字符串或函数，调用 investigate_string 或 explain_function 深挖。
5. 最后调用 export_report 输出可复盘摘要。
""",
            ),
            PromptSpec(
                name="triage-managed",
                title="托管/.NET 样本开局分析",
                description="按 V2 slim 工作流优先使用托管类型、字符串与 C# 反编译信息。",
                argument_names=("target_path",),
                template="""
请用 ida-stdio-mcp V2 slim 工作流分析托管/.NET 样本。

固定顺序：
1. get_workspace_state。
2. 如果未打开样本，open_target 打开：$target_path；默认不等待全库自动分析。
3. triage_binary，重点查看 managed 质量等级、命名空间、托管字符串和入口方法。
4. 对可疑字符串调用 investigate_string，对关键方法调用 explain_function。
5. export_report，明确标注 managed 结果质量等级和 C# 反编译来源。
""",
            ),
            PromptSpec(
                name="string-led-investigation",
                title="字符串牵引分析",
                description="从错误文案、URL、路径、协议字段等字符串倒推关键逻辑。",
                argument_names=("pattern",),
                template="""
请按字符串牵引方式调查目标：$pattern。

固定顺序：
1. get_workspace_state，确认已有会话。
2. investigate_string，传入 pattern。
3. 对返回的使用点所属函数调用 explain_function。
4. 如果字符串疑似输入检查、鉴权、路径或协议字段，继续调用 trace_input_to_check。
5. export_report 汇总字符串、xref、关键函数和判断依据。
""",
            ),
            PromptSpec(
                name="microcode-investigation",
                title="Microcode 线索分析",
                description="在有 Hex-Rays 的 IDA 9.3+ 环境里读取 microcode summary 与 def-use 线索。",
                argument_names=("query",),
                template="""
请调查函数的 microcode 线索：$query。

要求：
1. 先用 explain_function 读取普通伪代码和调用关系。
2. 在 full/expert 工具面下读取 microcode_summary 或 microcode_def_use。
3. 只在同时启用 --tool-surface expert 与 --unsafe 时才尝试实验性 microcode mutation。
4. export_report 时把 microcode 结论标成线索，不要把实验性结果当成确定事实。
""",
            ),
        )
    )


def _argument_description(name: str) -> str:
    """返回 prompt 参数说明。"""
    descriptions = {
        "target_path": "可选样本路径；已有会话时可以留空。",
        "pattern": "要调查的字符串、URL、路径、错误文案或协议字段。",
        "query": "函数名、符号名或地址。",
    }
    return descriptions.get(name, "可选参数。")
