"""Hex-Rays microcode 线索与实验能力。"""

from __future__ import annotations

from typing import Callable, cast

from ..ida_bootstrap import ensure_ida_environment
from ..models import JsonObject

ensure_ida_environment()

import ida_funcs  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_hexrays  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import ida_idaapi  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。

BADADDR = ida_idaapi.BADADDR
GET_FUNC = cast(Callable[[int], ida_funcs.func_t | None], ida_funcs.get_func)
ToolEnvelope = JsonObject


class MicrocodeCoreMixin:
    """提供 Hex-Rays microcode 摘要、def-use 与局部实验能力。"""

    def hexrays_available(self) -> bool:
        """由核心类提供 Hex-Rays 可用性判断。"""
        raise NotImplementedError

    def hexrays_health(self) -> JsonObject:
        """由核心类提供 Hex-Rays 能力状态。"""
        raise NotImplementedError

    def lookup_function(self, query: str) -> JsonObject:
        """由核心类提供函数查询。"""
        raise NotImplementedError

    def require_function(self, ea: int) -> ida_funcs.func_t:
        """由核心类提供函数对象读取。"""
        raise NotImplementedError

    def _json_object(self, value: object) -> JsonObject:
        """由核心类提供 JSON 对象收窄。"""
        raise NotImplementedError

    def _match_ea(self, match: JsonObject) -> int:
        """由核心类提供匹配地址读取。"""
        raise NotImplementedError

    def _match_name(self, match: JsonObject) -> str:
        """由核心类提供匹配名称读取。"""
        raise NotImplementedError

    @staticmethod
    def _runtime_attr_int(runtime_entry: object, names: tuple[str, ...]) -> int | None:
        """由核心类提供运行时对象整数属性读取。"""
        raise NotImplementedError

    def microcode_summary(self, query: str, *, max_instructions: int = 80) -> ToolEnvelope:
        """返回只读 microcode 摘要。"""
        hexrays_state = self.hexrays_health()
        if hexrays_state.get("status") != "available":
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": [f"当前环境不可用 Hex-Rays，无法生成 microcode：{hexrays_state.get('reason') or '未知原因'}"],
                    "data": {"hexrays": hexrays_state},
                }
            )
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            mba = getattr(cfunc, "mba", None)
            if mba is None:
                return self._json_object(
                    {
                        "status": "unsupported",
                        "warnings": ["Hex-Rays 未返回 mba_t，当前反编译结果无法读取 microcode。"],
                        "data": None,
                    }
                )
            blocks = self._microcode_blocks(mba, max_instructions=max_instructions)
            instruction_count = 0
            for block in blocks:
                raw_count = block.get("instruction_count")
                if isinstance(raw_count, int):
                    instruction_count += raw_count
            return self._json_object(
                {
                    "status": "ok",
                    "warnings": [],
                    "data": {
                        "addr": hex(func.start_ea),
                        "name": self._match_name(match),
                        "experimental": True,
                        "read_only": True,
                        "block_count": len(blocks),
                        "instruction_count": instruction_count,
                        "blocks": blocks,
                    },
                }
            )
        except Exception as exc:
            return self._json_object(
                {
                    "status": "degraded",
                    "warnings": [f"microcode 读取失败，已降级：{exc}"],
                    "data": None,
                }
            )

    def microcode_def_use(self, query: str, *, max_instructions: int = 120) -> ToolEnvelope:
        """返回 microcode def-use 线索。"""
        summary = self.microcode_summary(query, max_instructions=max_instructions)
        if summary.get("status") != "ok":
            return summary
        data = summary.get("data")
        if not isinstance(data, dict):
            return summary
        rows: list[JsonObject] = []
        blocks = data.get("blocks")
        if isinstance(blocks, list):
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                instructions = block.get("instructions")
                if not isinstance(instructions, list):
                    continue
                for instruction in instructions:
                    if not isinstance(instruction, dict):
                        continue
                    defs = instruction.get("defs")
                    uses = instruction.get("uses")
                    if defs or uses:
                        rows.append(
                            self._json_object(
                                {
                                    "block": block.get("serial"),
                                    "addr": instruction.get("addr"),
                                    "opcode": instruction.get("opcode"),
                                    "defs": defs,
                                    "uses": uses,
                                    "text": instruction.get("text"),
                                }
                            )
                        )
        return self._json_object(
            {
                "status": "ok",
                "warnings": ["def-use 来自 Hex-Rays microcode，只作为辅助线索。"],
                "data": {
                    "addr": data.get("addr"),
                    "name": data.get("name"),
                    "experimental": True,
                    "rows": rows,
                },
            }
        )

    def microcode_experiment(self, query: str, *, action: str = "mark_chains_dirty") -> ToolEnvelope:
        """执行实验性 microcode mutation。"""
        if action not in {"mark_chains_dirty"}:
            raise ValueError("microcode_experiment 当前仅支持 mark_chains_dirty")
        hexrays_state = self.hexrays_health()
        if hexrays_state.get("status") != "available":
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": [f"当前环境不可用 Hex-Rays，无法执行 microcode 实验：{hexrays_state.get('reason') or '未知原因'}"],
                    "data": {"hexrays": hexrays_state},
                }
            )
        match = self.lookup_function(query)
        func = self.require_function(self._match_ea(match))
        cfunc = ida_hexrays.decompile(func.start_ea)
        mba = getattr(cfunc, "mba", None)
        if mba is None:
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": ["Hex-Rays 未返回 mba_t，无法执行 microcode 实验。"],
                    "data": None,
                }
            )
        mark_chains_dirty = getattr(mba, "mark_chains_dirty", None)
        if not callable(mark_chains_dirty):
            return self._json_object(
                {
                    "status": "unsupported",
                    "warnings": ["当前 IDA 运行时未暴露 mba_t.mark_chains_dirty。"],
                    "data": None,
                }
            )
        mark_chains_dirty()
        return self._json_object(
            {
                "status": "ok",
                "warnings": ["这是 experimental microcode mutation；请重新用 decompile_function 或 explain_function 验证结果。"],
                "data": {
                    "addr": hex(func.start_ea),
                    "name": self._match_name(match),
                    "experimental": True,
                    "action": action,
                    "mutated": True,
                },
            }
        )

    def _microcode_blocks(self, mba: object, *, max_instructions: int) -> list[JsonObject]:
        """把 mba_t 收窄为块与指令摘要。"""
        qty_value = getattr(mba, "qty", 0)
        qty = int(qty_value) if isinstance(qty_value, int) else 0
        get_mblock = getattr(mba, "get_mblock", None)
        if not callable(get_mblock):
            return []
        blocks: list[JsonObject] = []
        remaining = max(1, max_instructions)
        for index in range(qty):
            block = get_mblock(index)
            if block is None:
                continue
            instructions: list[JsonObject] = []
            current = getattr(block, "head", None)
            while current is not None and remaining > 0:
                instruction_ea = self._runtime_attr_int(current, ("ea",))
                opcode_value = self._runtime_attr_int(current, ("opcode",))
                instructions.append(
                    {
                        "addr": hex(instruction_ea) if instruction_ea is not None and instruction_ea != BADADDR else "",
                        "opcode": self._micro_opcode_name(opcode_value),
                        "defs": self._micro_operand_text(getattr(current, "d", None)),
                        "uses": [
                            item
                            for item in (
                                self._micro_operand_text(getattr(current, "l", None)),
                                self._micro_operand_text(getattr(current, "r", None)),
                            )
                            if item
                        ],
                        "text": self._micro_insn_text(current),
                    }
                )
                remaining -= 1
                current = getattr(current, "next", None)
            serial = self._runtime_attr_int(block, ("serial",))
            start = self._runtime_attr_int(block, ("start",))
            end = self._runtime_attr_int(block, ("end",))
            blocks.append(
                self._json_object(
                    {
                        "serial": serial if serial is not None else index,
                        "start": hex(start) if start is not None and start != BADADDR else "",
                        "end": hex(end) if end is not None and end != BADADDR else "",
                        "instruction_count": len(instructions),
                        "instructions": instructions,
                    }
                )
            )
            if remaining <= 0:
                break
        return blocks

    @staticmethod
    def _micro_opcode_name(opcode: int | None) -> str:
        """把 microcode opcode 转为尽量可读的名字。"""
        if opcode is None:
            return ""
        return str(opcode)

    @staticmethod
    def _micro_operand_text(operand: object | None) -> str:
        """把 microcode 操作数转为短文本。"""
        if operand is None:
            return ""
        text = str(operand).strip()
        if text.startswith("<") and text.endswith(">"):
            return ""
        return text

    @staticmethod
    def _micro_insn_text(instruction: object) -> str:
        """把 microcode 指令转为短文本。"""
        dstr = getattr(instruction, "dstr", None)
        if callable(dstr):
            rendered = dstr()
            return str(rendered).strip()
        return str(instruction).strip()

