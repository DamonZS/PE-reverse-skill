"""Evidence-backed property graph for reconstructed source trees.

The graph is deliberately serializable and deterministic: it is an artifact consumed by
model prompts and build diagnostics, not an in-memory source-code index.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable


SOURCE_SUFFIXES = {".py", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".java", ".kt", ".cs"}
RESOURCE_SUFFIXES = {".json", ".xml", ".yaml", ".yml", ".ini", ".properties", ".html", ".css"}
IGNORED_PARTS = {".git", "__pycache__", "node_modules", "build", "dist", ".venv", ".build", ".reconstruction-build", "docs"}


def _stable_id(kind: str, *parts: str) -> str:
    value = "\x1f".join((kind, *parts))
    return f"{kind.lower()}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:20]}"


def _evidence(path: str, parser: str, line: int | None = None, confidence: str = "high") -> dict[str, Any]:
    result: dict[str, Any] = {"path": path, "parser": parser, "confidence": confidence}
    if line is not None:
        result["line"] = line
    return result


class ReconstructionGraph:
    """Build and query a stable JSON property graph rooted at a composite project."""

    schema_version = "reconstruction-graph/v1"

    def __init__(self, project_root: str | Path):
        self.root = Path(project_root).resolve()
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, dict[str, Any]] = {}
        self._symbols: dict[str, list[str]] = {}

    def build(self) -> dict[str, Any]:
        self._nodes.clear()
        self._edges.clear()
        self._symbols.clear()
        files = sorted(
            path for path in self.root.rglob("*")
            if path.is_file() and not any(part in IGNORED_PARTS for part in path.relative_to(self.root).parts)
        )
        modules: dict[str, str] = {}
        for path in files:
            rel = path.relative_to(self.root).as_posix()
            module_id, module_name, module_path = self._module_for(rel)
            if module_id not in modules:
                modules[module_id] = self._node("Module", module_name, module_path, module_id=module_id)
            kind = "Resource" if path.suffix.lower() in RESOURCE_SUFFIXES else "File"
            file_id = self._node(kind, path.name, rel, module_id=module_id, language=self._language(path))
            self._nodes[file_id]["size"] = path.stat().st_size
            if path.suffix.lower() in SOURCE_SUFFIXES | RESOURCE_SUFFIXES or path.name.lower() == "cmakelists.txt":
                self._nodes[file_id]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            self._edge("contains", modules[module_id], file_id, _evidence(rel, "filesystem"))
            if path.name.lower() == "capability-plan.json":
                self._parse_capability_plan(path, rel, module_id, modules[module_id], file_id)
            elif path.name.lower() == "cmakelists.txt":
                self._parse_cmake(path, rel, module_id, file_id)
            elif path.suffix.lower() == ".py":
                self._parse_python(path, rel, module_id, file_id)
            elif path.suffix.lower() in SOURCE_SUFFIXES:
                self._parse_structured_text(path, rel, module_id, file_id)
            elif path.suffix.lower() in {".json", ".xml"}:
                self._parse_resource(path, rel, module_id, file_id)
        self._resolve_symbolic_calls()
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        nodes = sorted(self._nodes.values(), key=lambda item: item["id"])
        edges = sorted(self._edges.values(), key=lambda item: item["id"])
        fingerprint = hashlib.sha256(
            json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": self.schema_version,
            "project_root": ".",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "fingerprint": fingerprint,
            "nodes": nodes,
            "edges": edges,
        }

    def write_artifact(self, destination: str | Path) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return destination

    def module_context(self, module_id: str, *, max_nodes: int = 80, max_edges: int = 160) -> dict[str, Any]:
        """Return deterministic, bounded local context, with one-hop cross-module evidence."""
        if max_nodes < 1 or max_edges < 0:
            raise ValueError("context bounds must be non-negative and include at least one node")
        primary = {node_id for node_id, node in self._nodes.items() if node.get("module_id") == module_id}
        if not primary:
            raise KeyError(f"unknown module_id: {module_id}")
        candidate_edges = [
            edge for edge in self._edges.values()
            if edge["source"] in primary or edge["target"] in primary
        ]
        candidate_edges.sort(key=lambda edge: (edge["source"] not in primary, edge["type"], edge["id"]))
        selected_edges = candidate_edges[:max_edges]
        connected = primary | {edge[key] for edge in selected_edges for key in ("source", "target")}
        ordered_ids = sorted(connected, key=lambda node_id: (node_id not in primary, node_id))[:max_nodes]
        selected = set(ordered_ids)
        selected_edges = [edge for edge in selected_edges if edge["source"] in selected and edge["target"] in selected]
        return {
            "schema_version": self.schema_version,
            "module_id": module_id,
            "truncated": len(connected) > max_nodes or len(candidate_edges) > max_edges,
            "nodes": [self._nodes[node_id] for node_id in ordered_ids],
            "edges": selected_edges,
            "limits": {"max_nodes": max_nodes, "max_edges": max_edges},
        }

    def _module_for(self, rel: str) -> tuple[str, str, str]:
        parts = rel.split("/")
        if len(parts) >= 2 and parts[0] == "targets":
            path, name = "/".join(parts[:2]), parts[1]
        else:
            path, name = ".", "root"
        return name, name, path

    def _node(self, kind: str, name: str, path: str, *, module_id: str, **properties: Any) -> str:
        node_id = _stable_id(kind, module_id, path, name)
        self._nodes.setdefault(node_id, {
            "id": node_id, "type": kind, "name": name, "path": path, "module_id": module_id,
            **{key: value for key, value in properties.items() if value is not None and value != ""},
        })
        if kind in {"Function", "Class"}:
            self._symbols.setdefault(name, []).append(node_id)
        return node_id

    def _edge(self, kind: str, source: str, target: str, evidence: dict[str, Any], **properties: Any) -> str:
        edge_id = _stable_id("edge", kind, source, target, json.dumps(evidence, sort_keys=True))
        self._edges.setdefault(edge_id, {
            "id": edge_id, "type": kind, "source": source, "target": target,
            "evidence": evidence, **properties,
        })
        return edge_id

    @staticmethod
    def _language(path: Path) -> str | None:
        return {".py": "python", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
                ".hpp": "cpp", ".java": "java", ".kt": "kotlin", ".cs": "csharp"}.get(path.suffix.lower())

    @staticmethod
    def _read(path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def _parse_python(self, path: Path, rel: str, module_id: str, file_id: str) -> None:
        try:
            tree = ast.parse(self._read(path), filename=rel)
        except SyntaxError:
            return
        definitions: dict[ast.AST, str] = {}
        for item in ast.walk(tree):
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node = self._node("Function", item.name, rel, module_id=module_id, line=item.lineno)
                definitions[item] = node
                self._edge("contains", file_id, node, _evidence(rel, "python-ast", item.lineno))
            elif isinstance(item, ast.ClassDef):
                node = self._node("Class", item.name, rel, module_id=module_id, line=item.lineno)
                definitions[item] = node
                self._edge("contains", file_id, node, _evidence(rel, "python-ast", item.lineno))
                for base in item.bases:
                    name = self._ast_name(base)
                    if name:
                        target = self._external_module(name, module_id)
                        self._edge("inherits", node, target, _evidence(rel, "python-ast", item.lineno))
            elif isinstance(item, (ast.Import, ast.ImportFrom)):
                names = [alias.name for alias in item.names]
                if isinstance(item, ast.ImportFrom) and item.module:
                    names = [item.module]
                for name in names:
                    self._edge("imports", file_id, self._external_module(name, module_id), _evidence(rel, "python-ast", item.lineno))
        for owner in [tree, *definitions]:
            source = definitions.get(owner, file_id)
            for call in (node for node in ast.walk(owner) if isinstance(node, ast.Call)):
                name = self._ast_name(call.func)
                if name:
                    self._record_call(source, name.split(".")[-1], rel, "python-ast", call.lineno)

    @staticmethod
    def _ast_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = ReconstructionGraph._ast_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return None

    def _parse_structured_text(self, path: Path, rel: str, module_id: str, file_id: str) -> None:
        text = self._read(path)
        parser = f"conservative-{self._language(path) or 'text'}-regex"
        classes: dict[str, str] = {}
        for match in re.finditer(r"\b(?:class|interface|struct)\s+(\w+)(?:\s*:\s*(?:public\s+)?(\w+)|\s+extends\s+(\w+))?", text):
            line = text.count("\n", 0, match.start()) + 1
            node = self._node("Class", match.group(1), rel, module_id=module_id, line=line)
            classes[match.group(1)] = node
            self._edge("contains", file_id, node, _evidence(rel, parser, line, "medium"))
            base = match.group(2) or match.group(3)
            if base:
                self._edge("inherits", node, self._external_module(base, module_id), _evidence(rel, parser, line, "medium"))
        function_pattern = re.compile(r"(?m)^\s*(?:[\w:<>,\[\]*&?]+\s+)+(\w+)\s*\([^;{}]*\)\s*(?:\{|=>)")
        for match in function_pattern.finditer(text):
            name = match.group(1)
            if name in {"if", "for", "while", "switch", "catch"}:
                continue
            line = text.count("\n", 0, match.start()) + 1
            node = self._node("Function", name, rel, module_id=module_id, line=line)
            self._edge("contains", file_id, node, _evidence(rel, parser, line, "medium"))
        for match in re.finditer(r"(?m)^\s*(?:#include\s*[<\"]([^>\"]+)|(?:import|using)\s+([\w.]+))", text):
            name = match.group(1) or match.group(2)
            line = text.count("\n", 0, match.start()) + 1
            self._edge("imports", file_id, self._external_module(name, module_id), _evidence(rel, parser, line, "medium"))
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", text):
            if match.group(1) not in {"if", "for", "while", "switch", "sizeof", "return"}:
                self._record_call(file_id, match.group(1), rel, parser, text.count("\n", 0, match.start()) + 1)
        for match in re.finditer(r"DllImport\s*\(\s*[\"']([^\"']+)", text):
            self._edge("PInvoke", file_id, self._external_module(match.group(1), module_id),
                       _evidence(rel, parser, text.count("\n", 0, match.start()) + 1, "high"))
        for match in re.finditer(r"\b(?:JNIEXPORT|external\s+fun|native\s+\w+)\b", text):
            self._edge("JNI", file_id, self._external_module("jni-runtime", module_id),
                       _evidence(rel, parser, text.count("\n", 0, match.start()) + 1, "medium"))
        for match in re.finditer(r"\b(?:NamedPipe|CreateNamedPipe|socket|AF_INET|grpc|Binder|Messenger)\b", text):
            self._edge("IPC", file_id, self._external_module(match.group(0), module_id),
                       _evidence(rel, parser, text.count("\n", 0, match.start()) + 1, "medium"))

    def _parse_cmake(self, path: Path, rel: str, module_id: str, file_id: str) -> None:
        text = self._read(path)
        for match in re.finditer(r"(?is)\badd_(executable|library)\s*\(\s*([^\s\)]+)(.*?)\)", text):
            name = match.group(2)
            line = text.count("\n", 0, match.start()) + 1
            target = self._node("BuildTarget", name, rel, module_id=module_id, target_kind=match.group(1).lower())
            self._edge("contains", file_id, target, _evidence(rel, "cmake-command-parser", line))
            module = next(node["id"] for node in self._nodes.values() if node["type"] == "Module" and node["module_id"] == module_id)
            self._edge("builds", module, target, _evidence(rel, "cmake-command-parser", line))

    def _parse_resource(self, path: Path, rel: str, module_id: str, file_id: str) -> None:
        try:
            if path.suffix.lower() == ".json":
                parsed: Any = json.loads(self._read(path))
                values = self._string_values(parsed)
                parser = "json"
            else:
                root = ET.parse(path).getroot()
                values = [value for element in root.iter() for value in [element.text, *element.attrib.values()] if value]
                parser = "xml.etree"
        except (json.JSONDecodeError, ET.ParseError, OSError):
            return
        for value in sorted(set(values)):
            if any(value.lower().endswith(suffix) for suffix in RESOURCE_SUFFIXES | SOURCE_SUFFIXES):
                target = self._node("Resource", Path(value).name, value, module_id=module_id)
                self._edge("resource_reference", file_id, target, _evidence(rel, parser))

    def _parse_capability_plan(self, path: Path, rel: str, module_id: str, module_node: str, file_id: str) -> None:
        try:
            payload = json.loads(self._read(path))
        except (json.JSONDecodeError, OSError):
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("stages"), list):
            return
        target = str(payload.get("target") or "unknown-target")
        target_evidence = payload.get("target_evidence") if isinstance(payload.get("target_evidence"), dict) else {}
        target_node = self._node(
            "BinaryTarget",
            Path(target).name,
            target,
            module_id=module_id,
            size=target_evidence.get("size"),
            sha256=target_evidence.get("sha256"),
        )
        self._edge("analyzes", file_id, target_node, _evidence(rel, "capability-plan"))
        for index, raw_stage in enumerate(payload["stages"]):
            if not isinstance(raw_stage, dict) or not raw_stage.get("capability"):
                continue
            capability = str(raw_stage["capability"])
            stage_node = self._node(
                "ToolStage",
                capability,
                f"{rel}#stage-{index}",
                module_id=module_id,
                provider=raw_stage.get("provider"),
                status=raw_stage.get("status"),
                return_code=raw_stage.get("return_code"),
            )
            self._edge("analyzed_by", module_node, stage_node, _evidence(rel, "capability-plan"))
            self._edge("consumes", stage_node, target_node, _evidence(rel, "capability-plan"))
            artifacts = raw_stage.get("artifact_evidence")
            if not isinstance(artifacts, list):
                continue
            for raw_artifact in artifacts:
                if not isinstance(raw_artifact, dict) or not raw_artifact.get("path"):
                    continue
                artifact_path = str(raw_artifact["path"])
                artifact_node = self._node(
                    "EvidenceArtifact",
                    Path(artifact_path).name,
                    artifact_path,
                    module_id=module_id,
                    artifact_type=raw_artifact.get("type"),
                    size=raw_artifact.get("size"),
                    file_count=raw_artifact.get("file_count"),
                    sha256=raw_artifact.get("sha256"),
                )
                self._edge("produced", stage_node, artifact_node, _evidence(rel, "capability-plan"))

    @classmethod
    def _string_values(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [item for child in value.values() for item in cls._string_values(child)]
        if isinstance(value, list):
            return [item for child in value for item in cls._string_values(child)]
        return []

    def _external_module(self, name: str, module_id: str) -> str:
        del module_id
        return self._node("Module", name, f"external:{name}", module_id="external", external=True)

    def _record_call(self, source: str, name: str, rel: str, parser: str, line: int) -> None:
        self._edge("calls", source, self._external_module(name, self._nodes[source]["module_id"]),
                   _evidence(rel, parser, line, "medium"), unresolved_symbol=name)

    def _resolve_symbolic_calls(self) -> None:
        symbolic = [edge for edge in self._edges.values() if edge.get("unresolved_symbol")]
        for edge in symbolic:
            targets = self._symbols.get(edge["unresolved_symbol"], [])
            if len(targets) == 1:
                del self._edges[edge["id"]]
                self._edge("calls", edge["source"], targets[0], edge["evidence"])


def build_reconstruction_graph(project_root: str | Path) -> ReconstructionGraph:
    graph = ReconstructionGraph(project_root)
    graph.build()
    return graph
