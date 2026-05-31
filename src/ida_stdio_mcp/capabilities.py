"""统一能力状态模型。

能力状态用于表达“运行时是否真实可用”，和工具是否注册是两件事。
所有可选后端、外部工具和实验能力都应通过本模型暴露状态。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .models import JsonObject, JsonValue

CapabilityStatus = Literal["available", "unavailable", "unsupported", "misconfigured", "uninitialized"]


@dataclass(slots=True, frozen=True)
class CapabilityState:
    """单项能力的可用性诊断。"""

    name: str
    status: CapabilityStatus
    reason: str
    source: str
    actionable_fix: tuple[str, ...] = ()
    details: JsonObject = field(default_factory=dict)

    @classmethod
    def from_json(cls, value: JsonObject) -> "CapabilityState":
        """从标准 JSON 结构恢复能力状态，便于跨模块复用 health 输出。"""
        status_value = value.get("status")
        status: CapabilityStatus
        if status_value == "available":
            status = "available"
        elif status_value == "unsupported":
            status = "unsupported"
        elif status_value == "misconfigured":
            status = "misconfigured"
        elif status_value == "uninitialized":
            status = "uninitialized"
        else:
            status = "unavailable"
        fixes_value = value.get("actionable_fix")
        fixes = tuple(str(item) for item in fixes_value) if isinstance(fixes_value, list) else ()
        details_value = value.get("details")
        return cls(
            name=str(value.get("name") or "unknown"),
            status=status,
            reason=str(value.get("reason") or ""),
            source=str(value.get("source") or ""),
            actionable_fix=fixes,
            details=details_value if isinstance(details_value, dict) else {},
        )

    def to_json(self) -> JsonObject:
        """转换为工具和资源输出使用的 JSON 对象。"""
        fixes: list[JsonValue] = [item for item in self.actionable_fix]
        return {
            "name": self.name,
            "status": self.status,
            "reason": self.reason,
            "source": self.source,
            "actionable_fix": fixes,
            "details": self.details,
        }


def capability_map(states: tuple[CapabilityState, ...]) -> JsonObject:
    """把能力状态元组转换成按名称索引的 JSON 对象。"""
    return {state.name: state.to_json() for state in states}


def dependent_capability(
    *,
    name: str,
    dependency: CapabilityState,
    reason: str,
    source: str,
) -> CapabilityState:
    """构造依赖某项基础能力的状态。"""
    if dependency.status == "available":
        return CapabilityState(
            name=name,
            status="uninitialized",
            reason=reason,
            source=source,
            actionable_fix=("先打开样本或调用对应 health 工具完成实时探测。",),
            details={"dependency": dependency.name, "dependency_status": dependency.status},
        )
    return CapabilityState(
        name=name,
        status=dependency.status,
        reason=f"依赖能力 {dependency.name} 不可用：{dependency.reason}",
        source=source,
        actionable_fix=dependency.actionable_fix,
        details={"dependency": dependency.to_json()},
    )
