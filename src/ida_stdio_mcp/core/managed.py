"""托管/.NET 样本分析能力。"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ..ida_bootstrap import ensure_ida_environment
from ..managed_decompiler import decompile_managed_method, managed_decompiler_available, managed_decompiler_command
from ..models import AnalysisDomain, JsonObject

ensure_ida_environment()

import ida_nalt  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。
import idautils  # pyright: ignore[reportMissingModuleSource]  # IDA 仅提供存根与运行时模块，这里按边界导入。


class ManagedCoreMixin:
    """提供托管样本识别、类型目录、方法身份和外部 C# 反编译能力。"""

    def get_analysis_domain(self) -> AnalysisDomain:
        """由核心类提供分析域判断。"""
        raise NotImplementedError

    def function_signature(self, ea: int) -> str:
        """由核心类提供函数签名读取。"""
        raise NotImplementedError

    def best_name(self, ea: int) -> str:
        """由核心类提供地址命名。"""
        raise NotImplementedError

    def disassembly_lines(self, start_ea: int) -> list[JsonObject]:
        """由核心类提供反汇编行读取。"""
        raise NotImplementedError

    def _json_object(self, value: object) -> JsonObject:
        """由核心类提供 JSON 对象收窄。"""
        raise NotImplementedError

    def _type_row_matches_filter(self, row: JsonObject, lowered: str) -> bool:
        """由核心类提供类型行过滤判断。"""
        raise NotImplementedError

    def managed_csharp_available(self) -> bool:
        """判断当前托管样本是否具备 C# 反编译能力。"""
        return self.get_analysis_domain() == "managed" and managed_decompiler_available()

    def _managed_csharp_decompile(self, start_ea: int) -> JsonObject | None:
        """尝试把托管方法反编译成 C#。"""
        identity = self.managed_method_identity(start_ea)
        if identity is None:
            return None
        full_type_value = identity.get("full_type")
        method_value = identity.get("method")
        if not isinstance(full_type_value, str) or not isinstance(method_value, str):
            return None

        assembly_path = Path(ida_nalt.get_input_file_path() or "")
        if not assembly_path.exists():
            return None

        result = decompile_managed_method(assembly_path, full_type_value, method_value)
        if result is None:
            return None

        warnings: list[str] = []
        if not result.extracted_exact:
            warnings.append("未能精确截取单方法，已返回所属类型的 C# 源码。")
        return self._json_object(
            {
                "text": result.method_source,
                "backend": result.command,
                "source": "ilspycmd",
                "exact": result.extracted_exact,
                "warnings": warnings,
            }
        )

    def managed_summary(self) -> JsonObject:
        """返回托管/.NET 目标的能力与类型摘要。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain != "managed":
            return self._json_object({
                "analysis_domain": analysis_domain,
                "available": False,
                "support_level": "not_managed",
                "external_decompiler": managed_decompiler_command() or "",
                "type_count": 0,
                "namespace_count": 0,
                "top_namespaces": [],
                "sample_types": [],
                "sample_methods": [],
            })
        managed_rows = self.managed_types()
        namespace_histogram: dict[str, int] = defaultdict(int)
        sample_methods: list[JsonObject] = []
        for row in managed_rows:
            namespace = row.get("namespace")
            if isinstance(namespace, str) and namespace:
                namespace_histogram[namespace] += 1
            members = row.get("members")
            if isinstance(members, list):
                for member in members[:3]:
                    if isinstance(member, dict):
                        sample_methods.append(member)
                        if len(sample_methods) >= 10:
                            break
            if len(sample_methods) >= 10:
                break
        top_namespaces: list[JsonObject] = [
            self._json_object({"namespace": namespace, "count": count})
            for namespace, count in sorted(namespace_histogram.items(), key=lambda item: item[1], reverse=True)[:20]
        ]
        support_level = "csharp_external" if self.managed_csharp_available() else "symbolic_il"
        return self._json_object({
            "analysis_domain": analysis_domain,
            "available": True,
            "support_level": support_level,
            "external_decompiler": managed_decompiler_command() or "",
            "type_count": len(managed_rows),
            "namespace_count": len(namespace_histogram),
            "top_namespaces": top_namespaces,
            "sample_types": managed_rows[:20],
            "sample_methods": sample_methods,
        })

    def managed_types(self, filter_text: str = "", *, limit: int = 2000) -> list[JsonObject]:
        """基于符号名推断托管类型目录。

        本函数以 IDA 已识别的函数名和符号名为输入，提取
        `命名空间.类型.方法` 结构，给 headless 模式提供可消费的托管类型视图。
        精确签名以托管反编译器或后续函数解释结果为准。
        """
        lowered = filter_text.lower()
        rows: dict[str, JsonObject] = {}
        for ea in idautils.Functions():
            if len(rows) >= limit:
                break
            identity = self.managed_method_identity(ea)
            if identity is None:
                continue
            full_type_value = identity.get("full_type")
            method_value = identity.get("method")
            type_name_value = identity.get("type_name")
            namespace_value = identity.get("namespace")
            full_name_value = identity.get("full_name")
            if not isinstance(full_type_value, str):
                continue
            if not isinstance(method_value, str):
                continue
            if not isinstance(type_name_value, str):
                continue
            if not isinstance(namespace_value, str):
                continue
            if not isinstance(full_name_value, str):
                continue
            full_type = full_type_value
            method_name = method_value
            type_name = type_name_value
            namespace = namespace_value
            full_name = full_name_value
            if lowered and lowered not in full_type.lower() and lowered not in method_name.lower():
                continue
            row = rows.setdefault(
                full_type,
                {
                    "catalog": "managed_types",
                    "kind": "managed_type",
                    "name": type_name,
                    "namespace": namespace,
                    "declaration_or_signature": full_type,
                    "members": [],
                    "source": "symbolic_names",
                },
            )
            members = row.get("members")
            if not isinstance(members, list):
                continue
            if any(isinstance(member, dict) and member.get("name") == identity["method"] for member in members):
                continue
            members.append(
                {
                    "name": method_name,
                    "kind": "method",
                    "addr": hex(ea),
                    "signature": self.function_signature(ea),
                    "full_name": full_name,
                }
            )
        return list(rows.values())

    def managed_method_identity(self, ea: int) -> JsonObject | None:
        """解析托管方法的“命名空间 / 类型 / 方法”身份。"""
        raw_name = self.best_name(ea)
        parts = self._managed_symbol_parts(raw_name)
        if parts is None:
            return None
        namespace, type_name, full_type, method_name = parts
        return {
            "namespace": namespace,
            "type_name": type_name,
            "full_type": full_type,
            "method": method_name,
            "full_name": f"{full_type}.{method_name}" if full_type else method_name,
        }

    def render_managed_method_view(self, start_ea: int) -> str:
        """渲染托管方法的 headless 视图。"""
        identity = self.managed_method_identity(start_ea)
        signature = self.function_signature(start_ea)
        lines: list[str] = []
        if identity is not None:
            lines.append(f"// Managed method: {identity['full_name']}")
        if signature:
            lines.append(f"// Signature: {signature}")
        lines.append("// Body:")
        lines.extend(f"{item['addr']}: {item['text']}" for item in self.disassembly_lines(start_ea))
        return "\n".join(lines)

    def _managed_support_matrix(self) -> JsonObject:
        """返回托管能力矩阵。"""
        analysis_domain = self.get_analysis_domain()
        if analysis_domain != "managed":
            return self._json_object({
                "available": False,
                "type_catalog": "native_only",
                "decompiler": "native_only",
                "notes": ["当前样本不是托管/.NET 程序"],
            })
        return self._json_object({
            "available": True,
            "type_catalog": "symbolic_managed_types",
            "decompiler": "external_csharp" if self.managed_csharp_available() else "il_symbolic_fallback",
            "notes": [
                "托管类型目录仍以 IDA 已识别符号和方法签名为主。",
                "若系统存在 ilspycmd，则 decompile_function 会直接返回高层 C# 结果。",
            ],
        })

    def _managed_symbol_parts(self, raw_name: str) -> tuple[str, str, str, str] | None:
        """从符号名里拆出托管类型路径。

        常见托管名字形态可能是：
        - `Namespace.Type::Method`
        - `Namespace.Type.Method`
        - `Type::Method`
        """
        normalized = raw_name.strip()
        if not normalized:
            return None
        normalized = normalized.split("(", 1)[0].strip()
        normalized = normalized.replace("/", ".")

        owner = ""
        method_name = ""
        if "::" in normalized:
            owner, method_name = normalized.rsplit("::", 1)
        elif "." in normalized:
            owner, method_name = normalized.rsplit(".", 1)
        if not owner or not method_name:
            return None

        owner = owner.strip(".")
        method_name = method_name.strip(".")
        if not owner or not method_name:
            return None

        if "." in owner:
            namespace, type_name = owner.rsplit(".", 1)
        else:
            namespace = ""
            type_name = owner
        if not type_name:
            return None
        return namespace, type_name, owner, method_name

