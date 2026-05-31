"""IDA headless 打开样本选项。"""

from __future__ import annotations

from dataclasses import dataclass

from .models import JsonObject


@dataclass(slots=True, frozen=True)
class HeadlessOpenOptions:
    """传给 IDA headless open_database 的结构化选项。"""

    loader: str = ""
    processor: str = ""
    plugin_options: tuple[str, ...] = ()

    def to_ida_args(self) -> str:
        """转换为 IDA 命令行参数字符串。"""
        args: list[str] = []
        if self.loader:
            args.append(f"-T{self.loader}")
        if self.processor:
            args.append(f"-p{self.processor}")
        for option in self.plugin_options:
            if option:
                args.append(f"-O{option}")
        return " ".join(args)

    def to_json(self) -> JsonObject:
        """转换为打开结果 metadata。"""
        return {
            "loader": self.loader,
            "processor": self.processor,
            "plugin_options": [item for item in self.plugin_options],
            "ida_args": self.to_ida_args(),
        }
