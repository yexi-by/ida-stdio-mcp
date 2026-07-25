# pyright: reportAny=false, reportMissingImports=false, reportMissingModuleSource=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""把自有 fixture 的两个代码范围确定性地建模为一个 IDA multi-chunk function。"""

import ida_auto
import ida_funcs
import ida_idaapi
import ida_name
import idautils


def _named_function(name: str) -> tuple[int, int]:
    address = int(ida_name.get_name_ea(ida_idaapi.BADADDR, name))
    if address == int(ida_idaapi.BADADDR):
        raise RuntimeError(f"fixture 缺少导出符号: {name}")
    function = ida_funcs.get_func(address)
    if function is None or int(function.start_ea) != address:
        raise RuntimeError(f"fixture 符号不是独立函数入口: {name}")
    end = int(function.end_ea)
    if end <= address:
        raise RuntimeError(f"fixture 函数范围无效: {name}")
    return address, end


if not ida_auto.auto_wait():
    raise RuntimeError("fixture autoanalysis 未完成")

entry_start, entry_end = _named_function("fixture_multichunk_entry")
gap_start, gap_end = _named_function("fixture_multichunk_gap")
tail_start, tail_end = _named_function("fixture_multichunk_tail")
if not (entry_end <= gap_start < gap_end <= tail_start):
    raise RuntimeError("fixture multi-chunk 三个代码范围没有按 entry/gap/tail 分离")

if not ida_funcs.del_func(tail_start):
    raise RuntimeError("无法移除 fixture tail 的独立函数归属")
entry_function = ida_funcs.get_func(entry_start)
if entry_function is None or int(entry_function.start_ea) != entry_start:
    raise RuntimeError("fixture entry 在重建 tail 前失效")
if not ida_funcs.append_func_tail(entry_function, tail_start, tail_end):
    raise RuntimeError("无法给 fixture entry 添加非连续 tail")

chunks = tuple((int(start), int(end)) for start, end in idautils.Chunks(entry_start))
expected_chunks = ((entry_start, entry_end), (tail_start, tail_end))
if tuple(sorted(chunks)) != tuple(sorted(expected_chunks)):
    raise RuntimeError("IDA 保存前的 multi-chunk 范围与 fixture 边界不一致")

annotation_result = {
    "entry": hex(entry_start),
    "gap": [hex(gap_start), hex(gap_end)],
    "chunks": [[hex(start), hex(end)] for start, end in chunks],
}
