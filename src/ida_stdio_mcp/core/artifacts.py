"""外部分析 artifact 与 IDA 上下文关联能力。"""

from __future__ import annotations

import re
from typing import cast

from ..analysis_artifacts import extract_artifact_entities, get_analysis_artifact
from ..models import JsonObject, JsonValue


class ArtifactCoreMixin:
    """提供通用 dispatcher 扫描和外部 artifact 关联能力。"""

    def _json_object(self, value: object) -> JsonObject:
        """由核心类提供 JSON 对象收窄。"""
        raise NotImplementedError

    def list_functions(self, *, filter_text: str = "", offset: int = 0, limit: int = 100) -> list[JsonObject]:
        """由核心类提供函数分页。"""
        raise NotImplementedError

    def disassembly_lines(self, start_ea: int) -> list[JsonObject]:
        """由核心类提供函数反汇编行。"""
        raise NotImplementedError

    def function_constants(self, start_ea: int) -> list[int]:
        """由核心类提供函数常量列表。"""
        raise NotImplementedError

    def get_function_profile(self, query: str, *, include_asm: bool = True) -> JsonObject:
        """由核心类提供函数画像。"""
        raise NotImplementedError

    def best_name(self, ea: int) -> str:
        """由核心类提供地址命名。"""
        raise NotImplementedError

    def parse_address(self, value: str) -> int:
        """由核心类提供地址解析。"""
        raise NotImplementedError

    def find_strings(self, pattern: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """由核心类提供字符串查询。"""
        raise NotImplementedError

    def scan_dispatchers(self, *, max_functions: int = 300, max_candidates: int = 100) -> JsonObject:
        """扫描通用间接分发器候选。"""
        functions = self.list_functions(limit=max(1, max_functions))
        candidates: list[JsonObject] = []
        for function in functions:
            addr_value = function.get("addr")
            name_value = function.get("name")
            if not isinstance(addr_value, str):
                continue
            try:
                function_ea = self.parse_address(addr_value)
                lines = self.disassembly_lines(function_ea)
                constants = self.function_constants(function_ea)
            except Exception:
                continue

            indirect_sites: list[JsonObject] = []
            table_sites: list[JsonObject] = []
            hash_sites: list[JsonObject] = []
            switch_sites: list[JsonObject] = []
            for line in lines:
                line_addr = line.get("addr")
                line_text_value = line.get("text")
                if not isinstance(line_addr, str) or not isinstance(line_text_value, str):
                    continue
                lowered = line_text_value.lower()
                if self._line_looks_indirect_dispatch(lowered):
                    indirect_sites.append({"addr": line_addr, "text": line_text_value})
                if self._line_looks_table_dispatch(lowered):
                    table_sites.append({"addr": line_addr, "text": line_text_value})
                if self._line_looks_hash_mix(lowered):
                    hash_sites.append({"addr": line_addr, "text": line_text_value})
                if "switch" in lowered or "case" in lowered or "jumptable" in lowered:
                    switch_sites.append({"addr": line_addr, "text": line_text_value})

            hash_constants = self._dispatcher_hash_constants(constants)
            score = (
                len(indirect_sites) * 3
                + len(table_sites) * 2
                + len(switch_sites) * 3
                + len(hash_sites)
                + min(len(hash_constants), 8)
            )
            if score <= 0:
                continue
            patterns: list[JsonValue] = []
            if indirect_sites:
                patterns.append("indirect_call_or_jump")
            if table_sites:
                patterns.append("jump_table_or_pointer_table")
            if switch_sites:
                patterns.append("switch_metadata")
            if hash_sites or hash_constants:
                patterns.append("hash_mixing_or_hash_constants")
            row = cast(
                JsonObject,
                {
                    "addr": addr_value,
                    "name": str(name_value or self.best_name(function_ea)),
                    "score": score,
                    "patterns": patterns,
                    "indirect_sites": indirect_sites[:12],
                    "table_sites": table_sites[:12],
                    "switch_sites": switch_sites[:12],
                    "hash_sites": hash_sites[:12],
                    "hash_constants": hash_constants[:24],
                    "recommended_next_tools": ["decompile_function", "explain_function", "build_callgraph"],
                },
            )
            candidates.append(row)

        def score_value(item: JsonObject) -> int:
            """读取候选评分。"""
            value = item.get("score")
            return value if isinstance(value, int) and not isinstance(value, bool) else 0

        candidates.sort(key=score_value, reverse=True)
        return self._json_object(
            {
                "scanned_functions": len(functions),
                "candidate_count": len(candidates),
                "items": candidates[: max(1, max_candidates)],
                "heuristics": [
                    "indirect call/jump operands",
                    "jump-table or pointer-table references",
                    "switch metadata in disassembly comments",
                    "hash-mixing instructions and immediate constants",
                ],
                "recommended_next_tools": ["decompile_function", "explain_function", "correlate_analysis_artifact"],
            }
        )

    @staticmethod
    def _line_looks_indirect_dispatch(lowered: str) -> bool:
        """判断反汇编行是否像间接跳转或调用。"""
        if not ("call" in lowered or "jmp" in lowered or "br " in lowered):
            return False
        return "[" in lowered or "ptr" in lowered or "reg" in lowered or re.search(r"\b[er]?[abcd]x\b", lowered) is not None

    @staticmethod
    def _line_looks_table_dispatch(lowered: str) -> bool:
        """判断反汇编行是否像表驱动分发。"""
        return any(token in lowered for token in ("jpt_", "jumptable", "off_", "dq offset", "dd offset", "table", "switch"))

    @staticmethod
    def _line_looks_hash_mix(lowered: str) -> bool:
        """判断反汇编行是否像 hash 混合逻辑。"""
        return any(token in lowered for token in ("crc", "hash", "imul", "xor", "rol", "ror", "shl", "shr"))

    @staticmethod
    def _dispatcher_hash_constants(constants: list[int]) -> list[JsonObject]:
        """筛选可能参与 hash 映射的立即数。"""
        results: list[JsonObject] = []
        seen: set[int] = set()
        for value in constants:
            if value in seen:
                continue
            seen.add(value)
            if 0x1000 <= value <= 0xFFFFFFFFFFFFFFFF:
                results.append({"value": hex(value), "decimal": value, "width": 64 if value > 0xFFFFFFFF else 32})
        return results

    def correlate_analysis_artifact(self, *, artifact_id: str = "", path: str = "", max_items: int = 100) -> JsonObject:
        """把外部分析 artifact 与当前 IDB 的字符串、函数、地址和 hash 常量关联。"""
        record, payload = get_analysis_artifact(artifact_id=artifact_id, path=path)
        entities = extract_artifact_entities(payload, max_items=max(1, max_items))
        addresses = self._entity_list(entities, "addresses")
        hashes = self._entity_list(entities, "hashes")
        texts = self._entity_list(entities, "texts")
        paths = self._entity_list(entities, "paths")
        address_matches = self._correlate_addresses(addresses[:max_items])
        hash_matches = self._correlate_hashes(hashes[:max_items], max_functions=500)
        string_matches = self._correlate_strings((texts + paths)[:max_items])
        function_name_matches = self._correlate_function_names(texts[:max_items])
        return self._json_object(
            {
                "artifact": record.to_json(),
                "entities": entities,
                "matches": {
                    "addresses": address_matches,
                    "hashes": hash_matches,
                    "strings": string_matches,
                    "function_names": function_name_matches,
                },
                "summary": {
                    "address_matches": len(address_matches),
                    "hash_matches": len(hash_matches),
                    "string_matches": len(string_matches),
                    "function_name_matches": len(function_name_matches),
                },
                "recommended_next_tools": ["explain_function", "decompile_function", "scan_dispatchers"],
            }
        )

    @staticmethod
    def _entity_list(entities: JsonObject, key: str) -> list[JsonObject]:
        """从实体对象中读取对象数组。"""
        value = entities.get(key)
        if not isinstance(value, list):
            return []
        return [cast(JsonObject, item) for item in value if isinstance(item, dict)]

    def _correlate_addresses(self, entities: list[JsonObject]) -> list[JsonObject]:
        """关联 artifact 中的地址候选。"""
        results: list[JsonObject] = []
        for entity in entities:
            value = entity.get("value")
            if not isinstance(value, str):
                continue
            try:
                ea = self.parse_address(value)
                profile = self.get_function_profile(hex(ea), include_asm=False)
                results.append({"entity": entity, "addr": hex(ea), "function": profile})
            except Exception:
                continue
        return results

    def _correlate_hashes(self, entities: list[JsonObject], *, max_functions: int) -> list[JsonObject]:
        """把 hash 候选与函数常量做通用匹配。"""
        wanted: dict[int, JsonObject] = {}
        for entity in entities:
            value = entity.get("value")
            if not isinstance(value, str):
                continue
            try:
                wanted[int(value, 0)] = entity
            except ValueError:
                continue
        if not wanted:
            return []
        results: list[JsonObject] = []
        for function in self.list_functions(limit=max_functions):
            addr = function.get("addr")
            if not isinstance(addr, str):
                continue
            try:
                function_ea = self.parse_address(addr)
                constants = set(self.function_constants(function_ea))
            except Exception:
                continue
            for wanted_value, entity in wanted.items():
                if wanted_value in constants:
                    results.append({"entity": entity, "hash": hex(wanted_value), "function": function})
        return results

    def _correlate_strings(self, entities: list[JsonObject]) -> list[JsonObject]:
        """把文本和路径实体与 IDA 字符串缓存关联。"""
        results: list[JsonObject] = []
        seen: set[str] = set()
        for entity in entities:
            value = entity.get("value")
            if not isinstance(value, str):
                continue
            text = value.strip()
            if len(text) < 3 or text in seen:
                continue
            seen.add(text)
            try:
                matches = self.find_strings(text, limit=5)
            except Exception:
                continue
            data = matches.get("data")
            if isinstance(data, list) and data:
                results.append({"entity": entity, "matches": data[:5]})
        return results

    def _correlate_function_names(self, entities: list[JsonObject]) -> list[JsonObject]:
        """把文本实体与函数名做模糊关联。"""
        results: list[JsonObject] = []
        seen: set[str] = set()
        for entity in entities:
            value = entity.get("value")
            if not isinstance(value, str):
                continue
            text = value.strip()
            if len(text) < 3 or text in seen:
                continue
            if not re.fullmatch(r"[A-Za-z_.$?][A-Za-z0-9_.$?@:<>~-]{2,128}", text):
                continue
            seen.add(text)
            matches = self.list_functions(filter_text=text, limit=5)
            if matches:
                results.append(cast(JsonObject, {"entity": entity, "matches": matches}))
        return results
