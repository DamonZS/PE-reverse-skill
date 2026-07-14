from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.dashboard import build_dashboard
from reverse_analyzer.dashboard_platform_core import build_analysis_views


class DashboardViewTests(unittest.TestCase):
    def test_analysis_domain_availability_uses_canonical_status_semantics(self) -> None:
        cases = (
            ({"status": "unsupported"}, "unavailable", False),
            ({"status": "error"}, "failed", False),
            ({"status": "degraded"}, "partial", True),
            ({"status": "success"}, "ok", True),
            ({"status": "pending"}, "unavailable", False),
            ({"framework": "wpf"}, "ok", True),
            ({"status": "provider-specific"}, "unavailable", False),
            (
                {"status": "provider-specific", "evidence": ["runtime tree captured"]},
                "partial",
                True,
            ),
        )

        for payload, expected_status, expected_available in cases:
            with self.subTest(payload=payload):
                views = build_analysis_views(
                    [
                        {
                            "source_path": "output/report.json",
                            "payload": {"gui_analysis": payload},
                        }
                    ]
                )
                view = views["gui"]

                self.assertEqual(view["status"], expected_status)
                self.assertIs(view["available"], expected_available)

    def test_report_domains_capability_audit_and_artifacts_are_rendered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            artifact_paths = (
                "output/semantic_ir.json",
                "output/evidence_graph.json",
                "output/engine/metadata.json",
                "output/android/manifest.json",
                "output/protocol/flows.json",
                "output/source/analysis.json",
                "output/memory/before.bin",
                "output/memory/after.bin",
                "output/memory/rollback.json",
                "output/memory/provenance.json",
                "output/memory/events.json",
                "output/evidence-manifest.json",
            )
            for relative_path in artifact_paths:
                path = workspace / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"artifact")

            report = {
                "timestamp": "2026-07-13T10:00:00Z",
                "platform_core": {
                    "status": "ok",
                    "semantic_ir": {
                        "path": "output/semantic_ir.json",
                        "module_count": 4,
                        "entity_count": 22,
                        "runtime_count": 1,
                    },
                    "evidence_graph": {
                        "path": "output/evidence_graph.json",
                        "node_count": 31,
                        "edge_count": 45,
                    },
                    "capability_registry": {
                        "capability_count": 5,
                        "capabilities": {"memory_runtime": ["native"]},
                    },
                },
                "capability_audit": {
                    "records": [
                        {
                            "session_id": "runtime-1",
                            "capability": "memory_runtime",
                            "provider": "native",
                            "action": "write",
                            "status": "ok",
                            "target_identity": {"pid": 4242, "display_name": "fixture.exe"},
                            "precondition_hash": "sha256:before",
                            "before_snapshot": {"path": "output/memory/before.bin"},
                            "after_snapshot": {"path": "output/memory/after.bin"},
                            "rollback_supported": True,
                            "rollback_plan": {"path": "output/memory/rollback.json"},
                            "provenance": {"path": "output/memory/provenance.json"},
                            "evidence_manifest_entries": [
                                {"path": "output/evidence-manifest.json"}
                            ],
                            "report_section": "memory_analysis",
                            "events": [{"path": "output/memory/events.json"}],
                            "dashboard_trace": {
                                "steps": ["plan", "validate", "execute", "collect_artifacts"]
                            },
                        }
                    ]
                },
                "engine_analysis": {
                    "status": "ok",
                    "platform": "windows-pe",
                    "engine": "unity-il2cpp",
                    "confidence": 0.96,
                    "assets": [{"name": "global-metadata.dat"}],
                    "symbols": [{"name": "PlayerController"}],
                    "artifacts": [{"path": "output/engine/metadata.json"}],
                },
                "android_analysis": {
                    "status": "ok",
                    "package_type": "apk",
                    "framework": {"name": "flutter", "confidence": 0.91},
                    "manifest": {"package": "example.fixture"},
                    "dex_summary": {"class_count": 120},
                    "native_libs": ["libapp.so"],
                    "artifacts": [{"path": "output/android/manifest.json"}],
                },
                "protocol_analysis": {
                    "status": "ok",
                    "confidence": 0.88,
                    "protocols": ["http", "protobuf"],
                    "flows": [{"id": "flow-1"}],
                    "field_stats": [{"name": "field_1"}],
                    "inference": {"format": "protobuf", "confidence": 0.88},
                    "artifacts": [{"path": "output/protocol/flows.json"}],
                },
                "source_reconstruction": {
                    "status": "ok",
                    "language": "csharp",
                    "output_stack": "unity-csharp",
                    "confidence": 0.82,
                    "function_count": 18,
                    "module_count": 3,
                    "verification_status": "passed",
                    "verification_score": 0.79,
                    "artifacts": [{"path": "output/source/analysis.json"}],
                },
            }
            self._write_json(workspace / "output" / "report.json", report)

            data = build_dashboard(workspace)

            self.assertEqual(data["analysis_views"]["engine"]["engine"], "unity-il2cpp")
            self.assertEqual(data["analysis_views"]["android"]["status"], "ok")
            self.assertEqual(data["analysis_views"]["protocol"]["confidence"], 0.88)
            self.assertEqual(data["analysis_views"]["source"]["verification_score"], 0.79)

            audit = data["capability_audit"]
            self.assertEqual(audit["record_count"], 1)
            self.assertEqual(audit["trace_count"], 4)
            self.assertEqual(audit["summary"]["precondition_hash_count"], 1)
            self.assertEqual(audit["summary"]["before_snapshot_count"], 1)
            self.assertEqual(audit["summary"]["after_snapshot_count"], 1)
            self.assertEqual(audit["summary"]["provenance_count"], 1)
            self.assertEqual(audit["summary"]["event_count"], 1)
            record = audit["records"][0]
            for field in (
                "session_id",
                "target_identity",
                "precondition_hash",
                "before_snapshot",
                "after_snapshot",
                "rollback_plan",
                "provenance",
                "evidence_manifest_entries",
                "report_section",
                "events",
                "dashboard_trace",
            ):
                self.assertIn(field, record)

            navigation = data["artifact_navigation"]
            items = {item["path"]: item for item in navigation["items"]}
            for relative_path in artifact_paths:
                self.assertIn(relative_path, items)
                self.assertTrue(items[relative_path]["exists"])
                self.assertIn("href", items[relative_path])
            self.assertEqual(
                data["platform_core"]["artifacts"],
                {
                    "semantic_ir": "output/semantic_ir.json",
                    "evidence_graph": "output/evidence_graph.json",
                },
            )

            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")
            for title in (
                "Analysis Domains",
                "Capability Audit",
                "KnowledgeBase Recommendations",
                "Session Compare & Trend",
                "Artifact Navigation",
            ):
                self.assertIn(title, html)
            self.assertIn('"engine": "unity-il2cpp"', html)
            self.assertIn('"precondition_hash": "sha256:before"', html)

    def test_session_history_is_deduplicated_compared_and_trended(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write_json(
                workspace / "sessions" / "latest.json",
                {
                    "session_id": "session-latest",
                    "status": "completed",
                    "timestamp": "2026-07-13T12:00:00Z",
                    "target": "latest.exe",
                    "finding_count": 12,
                    "recommended_dynamic_profile": {"profile": "behavior"},
                },
            )
            self._write_json(
                workspace / ".reverse_analyzer" / "knowledge" / "sessions.json",
                [
                    {
                        "session_id": "session-latest",
                        "status": "completed",
                        "timestamp": "2026-07-13T12:00:00Z",
                        "finding_count": 12,
                        "artifact_count": 9,
                        "recommended_dynamic_profile": {"profile": "behavior"},
                        "recommended_engine_strategy": {"key": "unity:metadata"},
                    },
                    {
                        "session_id": "session-previous",
                        "status": "failed",
                        "timestamp": "2026-07-12T12:00:00Z",
                        "target": "previous.exe",
                        "finding_count": 5,
                        "artifact_count": 4,
                        "recommended_dynamic_profile": {"profile": "quick"},
                        "recommended_engine_strategy": {"key": "engine:strings"},
                    },
                ],
            )

            data = build_dashboard(workspace)

            analytics = data["session_analytics"]
            self.assertEqual(analytics["record_count"], 2)
            latest = analytics["records"][0]
            self.assertEqual(latest["session_id"], "session-latest")
            self.assertEqual(latest["_sources"], ["knowledge", "session"])

            comparison = data["session_compare"]
            self.assertTrue(comparison["available"])
            self.assertEqual(comparison["latest"]["session_id"], "session-latest")
            self.assertEqual(comparison["previous"]["session_id"], "session-previous")
            self.assertEqual(comparison["deltas"]["findings"], 7.0)
            self.assertEqual(comparison["deltas"]["artifacts"], 5.0)
            self.assertEqual(
                comparison["recommendation_changes"],
                [
                    {
                        "namespace": "dynamic",
                        "previous": "quick",
                        "latest": "behavior",
                    },
                    {
                        "namespace": "engine",
                        "previous": "engine:strings",
                        "latest": "unity:metadata",
                    },
                ],
            )
            trend = data["session_trend"]
            self.assertEqual(trend["point_count"], 2)
            self.assertEqual(trend["status_counts"], {"completed": 1, "failed": 1})
            self.assertEqual(trend["completion_rate"], 0.5)
            self.assertEqual(
                [point["session_id"] for point in trend["points"]],
                ["session-previous", "session-latest"],
            )

    def test_artifact_navigation_blocks_workspace_escape_and_urls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            valid_artifact = workspace / "output" / "inside.json"
            self._write_json(valid_artifact, {"status": "ok"})
            outside_artifact = workspace.parent / "outside-dashboard-artifact.json"
            self._write_json(outside_artifact, {"status": "outside"})
            try:
                self._write_json(
                    workspace / "output" / "report.json",
                    {
                        "artifacts": [
                            "output/inside.json",
                            "../../outside-dashboard-artifact.json",
                            str(outside_artifact.resolve()),
                            "https://example.invalid/external.json",
                        ]
                    },
                )

                navigation = build_dashboard(workspace)["artifact_navigation"]

                self.assertEqual(navigation["blocked_count"], 3)
                paths = {item["path"] for item in navigation["items"]}
                self.assertIn("output/inside.json", paths)
                self.assertNotIn("../../outside-dashboard-artifact.json", paths)
                self.assertTrue(all("example.invalid" not in item.get("href", "") for item in navigation["items"]))
                self.assertTrue(all(Path(item["path"]).parts[0] != ".." for item in navigation["items"]))
            finally:
                outside_artifact.unlink(missing_ok=True)

    def test_non_finite_report_and_knowledge_metrics_are_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write_json(
                workspace / "output" / "report.json",
                {
                    "engine_analysis": {
                        "status": "partial",
                        "confidence": math.nan,
                        "assets": math.inf,
                    },
                    "platform_core": {
                        "status": "partial",
                        "semantic_ir": {"module_count": math.inf},
                    },
                },
            )
            self._write_json(
                workspace
                / ".reverse_analyzer"
                / "knowledge"
                / "engine_strategies.json",
                {
                    "strategies": {
                        "corrupt": {
                            "runs": "NaN",
                            "success_rate": "Infinity",
                            "avg_confidence": math.nan,
                        },
                        "valid": {
                            "runs": 2,
                            "success_rate": 0.75,
                            "avg_confidence": 0.8,
                        },
                    }
                },
            )

            data = build_dashboard(workspace)

            self.assertIsNone(data["analysis_views"]["engine"]["confidence"])
            self.assertEqual(data["platform_core"]["cards"][1]["value"], 0)
            recommendation = data["recommendations"]["engine_strategy"]
            self.assertEqual(recommendation["key"], "valid")
            serialized = (workspace / "dashboard" / "data.json").read_text(encoding="utf-8")
            self.assertNotIn("NaN", serialized)
            self.assertNotIn("Infinity", serialized)

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
