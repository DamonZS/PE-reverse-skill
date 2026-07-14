from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from reverse_analyzer.core.capabilities.models import JsonMixin


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _edge_id(source: str, target: str, edge_type: str, properties: Dict[str, Any]) -> str:
    identity = {
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "properties": properties,
    }
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"edge:sha256:{digest}"


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
    edge_id: str = ""

    def __post_init__(self) -> None:
        if not self.edge_id:
            self.edge_id = _edge_id(self.source, self.target, self.edge_type, self.properties)


@dataclass
class EvidenceGraph(JsonMixin):
    nodes: List[EvidenceNode] = field(default_factory=list)
    edges: List[EvidenceEdge] = field(default_factory=list)

    def add_node(self, node_id: str, node_type: str, label: str, **properties: Any) -> None:
        if not node_id or not node_type:
            raise ValueError("evidence nodes require non-empty node_id and node_type")

        existing = next((node for node in self.nodes if node.node_id == node_id), None)
        if existing is not None:
            if existing.node_type != node_type:
                raise ValueError(
                    f"evidence node {node_id!r} already exists as {existing.node_type!r}"
                )
            if not existing.label and label:
                existing.label = label
            for key, value in properties.items():
                if key not in existing.properties or existing.properties[key] in (None, "", [], {}):
                    existing.properties[key] = value
            return

        self.nodes.append(
            EvidenceNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                properties=properties,
            )
        )

    def add_edge(self, source: str, target: str, edge_type: str, **properties: Any) -> None:
        node_ids = {node.node_id for node in self.nodes}
        missing = [node_id for node_id in (source, target) if node_id not in node_ids]
        if missing:
            raise ValueError(
                "evidence edge endpoints must exist before the edge is added: "
                + ", ".join(repr(node_id) for node_id in missing)
            )
        if not edge_type:
            raise ValueError("evidence edges require a non-empty edge_type")

        edge = EvidenceEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            properties=properties,
        )
        if any(existing.edge_id == edge.edge_id for existing in self.edges):
            return
        self.edges.append(edge)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                node.to_dict()
                for node in sorted(
                    self.nodes,
                    key=lambda item: (item.node_type != "sample", item.node_id),
                )
            ],
            "edges": [edge.to_dict() for edge in sorted(self.edges, key=lambda item: item.edge_id)],
        }

    def write_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                self.to_dict(),
                handle,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            handle.write("\n")
