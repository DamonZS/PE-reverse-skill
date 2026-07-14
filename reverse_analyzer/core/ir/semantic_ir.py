from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from reverse_analyzer.core.capabilities.models import JsonMixin


@dataclass
class SemanticIR(JsonMixin):
    status: str = "unavailable"
    schema_version: int = 1
    entities: List[Dict[str, Any]] = field(default_factory=list)
    relations: List[Dict[str, Any]] = field(default_factory=list)
    capabilities: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    sample: Dict[str, Any] = field(default_factory=dict)
    modules: List[Dict[str, Any]] = field(default_factory=list)
    runtime: List[Dict[str, Any]] = field(default_factory=list)
    engine: Dict[str, Any] = field(default_factory=dict)
    android: Dict[str, Any] = field(default_factory=dict)
    ios: Dict[str, Any] = field(default_factory=dict)
    protocol: Dict[str, Any] = field(default_factory=dict)
    gui: Dict[str, Any] = field(default_factory=dict)
    source: Dict[str, Any] = field(default_factory=dict)
    notes: List[Dict[str, Any]] = field(default_factory=list)

    def merge_fragment(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def write_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
