from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from reverse_analyzer.core.capabilities.models import JsonMixin


@dataclass
class EvidenceNode(JsonMixin):
    node_id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceEdge(JsonMixin):
    source: str
    target: str
    edge_type: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceGraph(JsonMixin):
    nodes: List[EvidenceNode] = field(default_factory=list)
    edges: List[EvidenceEdge] = field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, label: str, **properties: Any) -> None:
        self.nodes.append(EvidenceNode(node_id=node_id, node_type=node_type, label=label, properties=properties))

    def add_edge(self, source: str, target: str, edge_type: str, **properties: Any) -> None:
        self.edges.append(EvidenceEdge(source=source, target=target, edge_type=edge_type, properties=properties))

    def write_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
