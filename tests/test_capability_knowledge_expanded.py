from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.core.capabilities import (
    KNOWLEDGE_MANAGED_CAPABILITIES,
    record_capability_lifecycle_outcome,
)
from reverse_analyzer.knowledge import KnowledgeBase
from reverse_analyzer.providers import build_default_registry


class ExpandedCapabilityKnowledgeTests(unittest.TestCase):
    def test_legacy_flat_action_bucket_migrates_without_losing_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = {
                "version": 0,
                "capabilities": {
                    "engine_runtime": {
                        "providers": {
                            "legacy-engine": {
                                "actions": {
                                    "analyze": {
                                        "target_kind": "sample",
                                        "runs": "3",
                                        "success": "2",
                                        "failure": "1",
                                        "avg_duration_ms": 10,
                                        "artifact_completeness_rate": 0.75,
                                        "rollback_completeness_rate": 0.5,
                                        "audit_completeness_rate": 0.5,
                                        "quality_metrics": {"coverage": 0.6},
                                        "samples": [
                                            {
                                                "timestamp": "2026-01-01T00:00:00+00:00",
                                                "status": "ok",
                                                "target": {
                                                    "kind": "sample",
                                                    "path": r"C:\private\legacy-engine.bin",
                                                },
                                            }
                                        ],
                                    }
                                }
                            }
                        }
                    }
                },
            }
            (root / "capability_outcomes.json").write_text(
                json.dumps(legacy),
                encoding="utf-8",
            )
            knowledge = KnowledgeBase(root)

            record = knowledge.record_capability_outcome(
                "engine_runtime",
                "legacy-engine",
                "analyze",
                status="ok",
                target={"kind": "sample", "path": r"C:\private\new-engine.bin"},
                duration_ms=20,
                artifact_completeness=1.0,
                rollback_completeness=1.0,
                audit_completeness=1.0,
                quality_metrics={"coverage": 0.8},
            )

            self.assertEqual(record["runs"], 4)
            self.assertEqual(record["successes"], 3)
            self.assertEqual(record["failures"], 1)
            self.assertEqual(record["unavailable"], 0)
            self.assertEqual(record["success"], 3)
            self.assertEqual(record["failure"], 1)
            self.assertEqual(record["avg_duration_ms"], 12.5)
            self.assertEqual(record["artifact_completeness"], 0.8125)
            self.assertEqual(record["rollback_completeness"], 0.625)
            self.assertEqual(record["audit_completeness"], 0.625)
            self.assertEqual(record["quality_metrics"], {"coverage": 0.65})
            self.assertEqual(record["quality_metric_counts"], {"coverage": 4})
            self.assertEqual(len(record["recent_samples"]), 2)
            self.assertEqual(record["recent_samples"], record["samples"])

            persisted_text = (root / "capability_outcomes.json").read_text("utf-8")
            self.assertNotIn("legacy-engine.bin", persisted_text)
            self.assertNotIn("new-engine.bin", persisted_text)
            persisted = json.loads(persisted_text)
            self.assertEqual(persisted["version"], 1)
            action = persisted["capabilities"]["engine_runtime"]["providers"][
                "legacy-engine"
            ]["actions"]["analyze"]
            self.assertEqual(set(action["target_kinds"]), {"sample"})

    def test_every_registry_capability_and_unknown_plugins_are_recorded(self) -> None:
        registry = build_default_registry()
        registry_capabilities = set(registry.list_capabilities())
        self.assertLessEqual(registry_capabilities, set(KNOWLEDGE_MANAGED_CAPABILITIES))
        requested_capabilities = registry_capabilities | {
            "android_native_patch",
            "future_vendor_runtime",
        }

        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            for capability in sorted(requested_capabilities):
                provider = (
                    registry.list_providers(capability)[0]
                    if capability in registry_capabilities
                    else "plugin-provider"
                )
                with self.subTest(capability=capability):
                    record = record_capability_lifecycle_outcome(
                        knowledge,
                        {
                            "capability": capability,
                            "provider": provider,
                            "action": "probe",
                            "status": "unavailable",
                            "target": {"kind": "sample", "sha256": "a" * 64},
                        },
                        artifact_completeness=1.0,
                        rollback_completeness=1.0,
                        audit_completeness=0.5,
                        quality_metrics={"coverage": 0.25},
                    )
                    self.assertIsNotNone(record)
                    self.assertEqual(record["capability"], capability)
                    self.assertEqual(record["unavailable"], 1)

            stored = knowledge.load_capability_outcomes()["capabilities"]
            self.assertEqual(set(stored), requested_capabilities)

    def test_lifecycle_extracts_quality_and_complete_audit_for_unknown_capability(self) -> None:
        capability = "future_graphics_backend"
        provider = "vendor-plugin"
        action = "capture"
        target = {
            "kind": "process",
            "pid": 912345,
            "path": r"C:\private\future-target.exe",
        }
        report_section = {
            "capability": capability,
            "provider": provider,
            "action": action,
            "status": "succeeded",
            "quality_metrics": {"coverage": 0.92, "confidence": 87},
        }
        result = {
            "capability": capability,
            "provider": provider,
            "session_id": "future-session",
            "action": action,
            "status": "succeeded",
            "target": target,
            "before_snapshot": {"state": "before"},
            "after_snapshot": {"state": "after"},
            "rollback_plan": {"supported": False},
            "artifacts": [{"path": "capture.json"}],
            "evidence_manifest_entries": [{"path": "capture.json"}],
            "report_section": report_section,
            "dashboard_trace": [{"kind": "capture"}],
            "provenance": {"backend": provider},
        }
        audit = {
            "session_id": "future-session",
            "capability": capability,
            "provider": provider,
            "target_identity": target,
            "action": action,
            "status": "succeeded",
            "precondition_hash": "precondition-hash",
            "before_snapshot": {"state": "before"},
            "after_snapshot": {"state": "after"},
            "rollback_plan": {"supported": False},
            "provenance": {"backend": provider},
            "evidence_manifest_entries": [{"path": "capture.json"}],
            "report_section": report_section,
            "dashboard_trace": [{"kind": "capture"}],
            "events": [
                {"kind": "plan", "ts": "2026-01-01T00:00:00Z", "message": "planned"},
                {
                    "kind": "validate",
                    "ts": "2026-01-01T00:00:01Z",
                    "message": "validated",
                },
                {
                    "kind": "execute",
                    "ts": "2026-01-01T00:00:02Z",
                    "message": "executed",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)
            record = record_capability_lifecycle_outcome(
                knowledge,
                result,
                artifact_bundle={
                    "artifacts": [{"path": "capture.json"}],
                    "manifest_entries": [{"path": "capture.json"}],
                },
                audit_record=audit,
                duration_ms=12.0,
            )

            self.assertIsNotNone(record)
            self.assertEqual(record["successes"], 1)
            self.assertEqual(record["audit_completeness"], 1.0)
            self.assertEqual(record["audit_complete_runs"], 1)
            self.assertEqual(
                record["quality_metrics"],
                {"confidence": 0.87, "coverage": 0.92},
            )
            self.assertEqual(record["artifact_completeness"], 1.0)
            self.assertEqual(record["rollback_completeness"], 1.0)
            self.assertEqual(len(record["recent_samples"]), 1)
            self.assertEqual(record["recent_samples"][0]["audit_completeness"], 1.0)

            persisted_text = (root / "capability_outcomes.json").read_text("utf-8")
            self.assertNotIn("912345", persisted_text)
            self.assertNotIn("future-target.exe", persisted_text)

    def test_multiple_providers_have_stable_aggregate_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)

            def record_many(
                provider: str,
                statuses: list[str],
                *,
                artifact: float,
                rollback: float,
                audit: float,
                quality: float,
                split_target_kinds: bool = False,
            ) -> None:
                for index, status in enumerate(statuses):
                    kind = "archive" if split_target_kinds and index % 2 else "sample"
                    knowledge.record_capability_outcome(
                        "android_native_patch",
                        provider,
                        "apply",
                        status=status,
                        target={"kind": kind, "sha256": str(index).zfill(64)},
                        duration_ms=10 + index,
                        artifact_completeness=artifact,
                        rollback_completeness=rollback,
                        audit_completeness=audit,
                        quality_metrics={"verification": quality},
                    )

            record_many(
                "verified",
                ["ok"] * 4,
                artifact=1.0,
                rollback=1.0,
                audit=1.0,
                quality=0.95,
                split_target_kinds=True,
            )
            record_many(
                "unstable",
                ["ok"] * 5 + ["failed"] * 3,
                artifact=0.8,
                rollback=0.6,
                audit=0.5,
                quality=0.4,
            )
            record_many(
                "one-shot",
                ["ok"],
                artifact=1.0,
                rollback=1.0,
                audit=1.0,
                quality=1.0,
            )
            record_many(
                "dependency-gated",
                ["unavailable"] * 5,
                artifact=1.0,
                rollback=1.0,
                audit=1.0,
                quality=1.0,
            )

            ranking = knowledge.rank_capability_providers(
                "android_native_patch",
                action="apply",
            )
            self.assertEqual(
                [item["provider"] for item in ranking],
                ["verified", "unstable", "one-shot", "dependency-gated"],
            )
            self.assertEqual(ranking[0]["runs"], 4)
            self.assertIsNone(ranking[0]["target_kind"])
            self.assertEqual(ranking[0]["target_kinds"], ["archive", "sample"])
            self.assertTrue(
                all(
                    ranking[index]["score"] > ranking[index + 1]["score"]
                    for index in range(len(ranking) - 1)
                )
            )
            self.assertEqual(
                knowledge.recommend_capability_provider(
                    "android_native_patch",
                    action="apply",
                )["provider"],
                "verified",
            )
            self.assertEqual(
                KnowledgeBase(root).rank_capability_providers(
                    "android_native_patch",
                    action="apply",
                ),
                ranking,
            )


if __name__ == "__main__":
    unittest.main()
