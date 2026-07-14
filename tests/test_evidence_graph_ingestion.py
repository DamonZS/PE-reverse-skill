import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.integration import build_evidence_graph
from reverse_analyzer.core.ir import EvidenceGraph
from reverse_analyzer.evidence import build_manifest, write_manifest


def _nodes(graph: EvidenceGraph, node_type: str):
    return [node for node in graph.nodes if node.node_type == node_type]


def _edges(graph: EvidenceGraph, edge_type: str):
    return [edge for edge in graph.edges if edge.edge_type == edge_type]


class EvidenceGraphIngestionTests(unittest.TestCase):
    def test_graph_deduplicates_rejects_dangling_edges_and_writes_stable_json(self) -> None:
        first = EvidenceGraph()
        first.add_node("sample:1", "sample", "sample.exe", sha256="abc")
        first.add_node("artifact:1", "artifact", "trace.json", role="trace")
        first.add_node(
            "artifact:1",
            "artifact",
            "trace.json",
            role="trace",
            sha256="def",
        )
        first.add_edge(
            "sample:1",
            "artifact:1",
            "generated_artifact",
            tool="probe",
            confidence=0.9,
        )
        first.add_edge(
            "sample:1",
            "artifact:1",
            "generated_artifact",
            tool="probe",
            confidence=0.9,
        )

        second = EvidenceGraph()
        second.add_node(
            "artifact:1",
            "artifact",
            "trace.json",
            sha256="def",
            role="trace",
        )
        second.add_node("sample:1", "sample", "sample.exe", sha256="abc")
        second.add_edge(
            "sample:1",
            "artifact:1",
            "generated_artifact",
            confidence=0.9,
            tool="probe",
        )

        self.assertEqual(len(first.nodes), 2)
        self.assertEqual(len(first.edges), 1)
        self.assertEqual(first.edges[0].edge_id, second.edges[0].edge_id)
        self.assertRegex(first.edges[0].edge_id, r"^edge:sha256:[0-9a-f]{64}$")
        with self.assertRaisesRegex(ValueError, "endpoints must exist"):
            first.add_edge("sample:1", "missing:1", "references")

        with tempfile.TemporaryDirectory() as tmp:
            first_path = Path(tmp) / "first.json"
            second_path = Path(tmp) / "second.json"
            first.write_json(first_path)
            second.write_json(second_path)
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            payload = json.loads(first_path.read_text(encoding="utf-8"))

        self.assertEqual(payload["nodes"][0]["node_type"], "sample")
        self.assertEqual(payload["nodes"][0]["label"], "sample.exe")

    def test_ingests_manifest_semantic_ir_and_capability_audit_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            artifact = root / "trace.json"
            sample.write_bytes(b"MZ production sample")
            artifact.write_text('{"events": 2}\n', encoding="utf-8")
            manifest = write_manifest(
                build_manifest(
                    root,
                    [
                        {
                            "path": artifact,
                            "kind": "runtime_trace",
                            "role": "evidence",
                            "tool": "runtime_probe",
                        }
                    ],
                    sample=sample,
                ),
                root / "evidence-manifest.json",
            )
            semantic_ir = {
                "status": "ok",
                "schema_version": 1,
                "entities": [
                    {
                        "id": "entity:function:entry",
                        "kind": "function",
                        "name": "entry",
                        "confidence": 0.95,
                        "sources": [{"path": "trace.json", "kind": "runtime_trace"}],
                    },
                    {
                        "id": "entity:api:create-file",
                        "kind": "api",
                        "name": "CreateFileW",
                    },
                    {
                        "id": "entity:state:ready",
                        "kind": "state",
                        "name": "ready",
                    },
                ],
                "relations": [
                    {
                        "id": "relation:calls",
                        "type": "calls",
                        "source": "entity:function:entry",
                        "target": "entity:api:create-file",
                        "sources": ["trace.json"],
                    },
                    {
                        "id": "relation:controls",
                        "kind": "controls",
                        "source": "entity:state:ready",
                        "target": "entity:function:entry",
                        "sources": [{"path": "trace.json"}],
                    },
                ],
                "artifacts": [{"path": str(artifact), "kind": "runtime_trace"}],
            }
            report = {
                "sample_name": sample.name,
                "evidence_integrity": {
                    "status": "ok",
                    "manifest_path": "evidence-manifest.json",
                    "manifest_id": manifest["manifest_id"],
                },
                "engine_analysis": {"status": "ok", "engine": "native"},
                "capability_audit": {
                    "records": [
                        {
                            "session_id": "audit-completed",
                            "capability": "memory_runtime",
                            "provider": "windows_memory_runtime",
                            "action": "trace",
                            "status": "succeeded",
                            "provenance": {"tool": "runtime_probe", "version": "1.0"},
                            "evidence_manifest_entries": [
                                {"path": str(artifact), "kind": "runtime_trace"}
                            ],
                            "dashboard_trace": [
                                {"kind": "request", "state": "completed"}
                            ],
                        },
                        {
                            "session_id": "audit-gated",
                            "capability": "protocol_runtime",
                            "provider": "protocol_runtime",
                            "action": "capture",
                            "status": "dependency_gated",
                            "provenance": {"dependency": "npcap"},
                            "dashboard_trace": {
                                "steps": [
                                    {"kind": "validate", "state": "unavailable"},
                                    {"kind": "execute", "state": "not_run"},
                                ]
                            },
                        },
                    ]
                },
            }

            first = build_evidence_graph(
                copy.deepcopy(report),
                sample_path=str(sample),
                semantic_ir=copy.deepcopy(semantic_ir),
                base_dir=root,
            )
            second = build_evidence_graph(
                copy.deepcopy(report),
                sample_path=str(sample),
                semantic_ir=copy.deepcopy(semantic_ir),
                base_dir=root,
            )

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(len({node.node_id for node in first.nodes}), len(first.nodes))
        self.assertEqual(len({edge.edge_id for edge in first.edges}), len(first.edges))
        node_ids = {node.node_id for node in first.nodes}
        self.assertTrue(
            all(edge.source in node_ids and edge.target in node_ids for edge in first.edges)
        )

        artifact_nodes = [
            node
            for node in _nodes(first, "artifact")
            if node.properties.get("path") == "trace.json"
        ]
        self.assertEqual(len(artifact_nodes), 1)
        self.assertEqual(artifact_nodes[0].properties["verification_status"], "verified")
        declared_digest = manifest["artifacts"][0]["sha256"]
        self.assertTrue(
            any(node.properties.get("digest") == declared_digest for node in _nodes(first, "artifact_hash"))
        )
        self.assertEqual(len(_nodes(first, "semantic_entity")), 3)
        self.assertEqual(len(_nodes(first, "semantic_relation")), 2)
        self.assertEqual(len(_edges(first, "calls")), 1)
        self.assertEqual(len(_edges(first, "controls")), 1)
        self.assertEqual(len(_nodes(first, "capability_audit")), 2)
        self.assertEqual(len(_nodes(first, "audit_provenance")), 2)
        self.assertEqual(len(_nodes(first, "dashboard_trace")), 3)
        self.assertTrue(_edges(first, "references_evidence"))
        verification = _nodes(first, "evidence_verification")
        self.assertEqual(len(verification), 1)
        self.assertTrue(verification[0].properties["valid"])
        self.assertEqual(verification[0].properties["verification_source"], "live")

    def test_models_live_hash_and_manifest_identity_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"trusted")
            manifest_path = root / "evidence-manifest.json"
            payload = write_manifest(
                build_manifest(root, [{"path": artifact, "tool": "extractor"}]),
                manifest_path,
            )
            declared_hash = payload["artifacts"][0]["sha256"]
            payload["manifest_id"] = "sha256:" + "0" * 64
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            artifact.write_bytes(b"altered")
            observed_hash = hashlib.sha256(b"altered").hexdigest()

            graph = build_evidence_graph(
                {
                    "sample_name": "sample.exe",
                    "evidence_integrity": {
                        "status": "ok",
                        "manifest_path": manifest_path.name,
                    },
                },
                base_dir=root,
                semantic_ir={"status": "unavailable"},
            )

        failures = _nodes(graph, "integrity_failure")
        self.assertEqual(
            {node.properties.get("kind") for node in failures},
            {"hash", "manifest_id"},
        )
        self.assertEqual(len(failures), 2)
        artifact_node = next(
            node
            for node in _nodes(graph, "artifact")
            if node.properties.get("path") == "artifact.bin"
        )
        self.assertEqual(artifact_node.properties["verification_status"], "failed")
        digests = {node.properties.get("digest") for node in _nodes(graph, "artifact_hash")}
        self.assertIn(declared_hash, digests)
        self.assertIn(observed_hash, digests)
        self.assertTrue(_edges(graph, "affects_artifact"))
        self.assertTrue(_edges(graph, "expected_hash"))
        self.assertTrue(_edges(graph, "observed_hash"))
        verification = _nodes(graph, "evidence_verification")[0]
        self.assertEqual(verification.properties["status"], "failed")
        self.assertFalse(verification.properties["valid"])

    def test_non_production_and_unavailable_sections_never_claim_real_analysis(self) -> None:
        inline_manifest = {
            "schema": "reverse_analyzer.evidence_manifest/v1",
            "manifest_id": "sha256:inline",
            "hash_algorithm": "sha256",
            "artifacts": [
                {
                    "path": "not-produced.json",
                    "kind": "schema",
                    "status": "unavailable",
                }
            ],
            "derivations": [],
        }
        report = {
            "sample_name": "truth.exe",
            "evidence_integrity": {
                "status": "failed",
                "manifest": {
                    "manifest": inline_manifest,
                    "verification": {"status": "failed", "valid": False},
                },
            },
            "memory_analysis": {"status": "unavailable"},
            "patch_analysis": {"status": "mock", "provider": "mock"},
            "engine_analysis": {"status": "dependency_gated"},
            "android_analysis": {"status": "schema"},
            "gui_analysis": {"status": "ok", "framework": "wpf"},
        }

        graph = build_evidence_graph(
            report,
            semantic_ir={"status": "unavailable", "schema_version": 1},
        )
        section_edges = {
            edge.properties.get("section"): edge.edge_type
            for edge in graph.edges
            if edge.properties.get("section")
        }
        self.assertEqual(section_edges["memory_analysis"], "analysis_unavailable")
        self.assertEqual(section_edges["patch_analysis"], "has_mock_analysis")
        self.assertEqual(section_edges["engine_analysis"], "analysis_dependency_gated")
        self.assertEqual(
            section_edges["android_analysis"],
            "has_non_production_analysis",
        )
        self.assertEqual(section_edges["gui_analysis"], "has_analysis")
        self.assertTrue(_edges(graph, "semantic_ir_unavailable"))
        self.assertFalse(
            any(
                edge.edge_type == "has_analysis"
                and edge.properties.get("section")
                in {
                    "memory_analysis",
                    "patch_analysis",
                    "engine_analysis",
                    "android_analysis",
                }
                for edge in graph.edges
            )
        )
        failures = _nodes(graph, "integrity_failure")
        self.assertTrue(
            any(node.properties.get("kind") == "verification_failed" for node in failures)
        )
        artifact = next(
            node
            for node in _nodes(graph, "artifact")
            if node.properties.get("path") == "not-produced.json"
        )
        self.assertEqual(artifact.properties["verification_status"], "skipped")


if __name__ == "__main__":
    unittest.main()
