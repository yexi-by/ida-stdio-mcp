"""IDA 运行时引导。

这个模块只有一个职责：在导入任何 `ida_*` 模块之前，先把 `idapro`
加载进当前 Python 进程。否则在普通解释器里直接导入 `ida_auto`、
`ida_bytes` 等模块时，会因为底层 `idalib` 尚未挂载而直接失败。
"""

from __future__ import annotations


def ensure_ida_environment() -> None:
    """确保 `idapro` 已经提前加载。

    这里不返回任何对象，调用方只需要在模块顶部先执行一次即可。
    """

    import idapro  # noqa: F401

