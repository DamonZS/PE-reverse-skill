from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    record_capability_lifecycle_outcome,
)
from reverse_analyzer.knowledge import KnowledgeBase
from reverse_analyzer.knowledge.capability_outcomes import CAPABILITY_SAMPLE_LIMIT
from reverse_analyzer.providers.mock import MockCapabilityProvider


class CapabilityKnowledgeTests(unittest.TestCase):
    def test_record_preserves_legacy_kb_and_persists_only_hashed_target_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = {
                "version": 1,
                "samples": {"legacy-sample": {"features": {"packer": "none"}}},
                "custom_legacy_field": {"keep": True},
            }
            (root / "knowledge_base.json").write_text(
                json.dumps(legacy),
                encoding="utf-8",
            )
            knowledge = KnowledgeBase(root)

            record = knowledge.record_capability_outcome(
                " memory_runtime ",
                " native-process ",
                " read_memory ",
                status="OK",
                target={
                    "kind": "process",
                    "pid": 781239,
                    "display_name": "private-target-name.exe",
                    "path": r"C:\private\target.exe",
                    "metadata": {"token": "private-target-token"},
                },
                duration_ms=12.5,
                artifact_completeness=1.0,
                rollback_completeness=0.5,
            )

            self.assertEqual(json.loads((root / "knowledge_base.json").read_text("utf-8")), legacy)
            self.assertEqual(record["capability"], "memory_runtime")
            self.assertEqual(record["provider"], "native-process")
            self.assertEqual(record["action"], "read_memory")
            self.assertEqual(record["target_kind"], "process")
            self.assertEqual(record["runs"], 1)
            self.assertEqual(record["successes"], 1)
            self.assertEqual(record["success_rate"], 1.0)
            self.assertEqual(record["avg_duration_ms"], 12.5)
            self.assertEqual(record["artifact_completeness"], 1.0)
            self.assertEqual(record["rollback_completeness"], 0.5)

            target = record["samples"][0]["target"]
            self.assertEqual(set(target), {"kind", "identity_hash"})
            self.assertEqual(target["kind"], "process")
            self.assertRegex(target["identity_hash"], r"^[0-9a-f]{64}$")

            persisted_text = (root / "capability_outcomes.json").read_text("utf-8")
            for sensitive in (
                "781239",
                "private-target-name.exe",
                r"C:\private\target.exe",
                "private-target-token",
            ):
                self.assertNotIn(sensitive, persisted_text)
            persisted = json.loads(persisted_text)
            self.assertEqual(persisted["version"], 1)
            self.assertIn("memory_runtime", persisted["capabilities"])
            self.assertEqual(list(root.glob(".capability_outcomes.json.*.tmp")), [])

    def test_recommendation_uses_success_completeness_and_target_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            target = TargetIdentity(kind="process", pid=44001, display_name="hidden.exe")
            for _ in range(3):
                knowledge.record_capability_outcome(
                    "injector",
                    "fragile",
                    "load_library",
                    status="failed",
                    target=target,
                    duration_ms=100,
                    artifact_completeness=0.25,
                    rollback_completeness=0.0,
                )
            for _ in range(2):
                knowledge.record_capability_outcome(
                    "injector",
                    "verified",
                    "load_library",
                    status="ok",
                    target=target,
                    duration_ms=20,
                    artifact_completeness=1.0,
                    rollback_completeness=1.0,
                )
            knowledge.record_capability_outcome(
                "injector",
                "file-only",
                "load_library",
                status="ok",
                target=TargetIdentity(kind="sample", path=r"C:\private\payload.dll"),
                artifact_completeness=1.0,
                rollback_completeness=1.0,
            )

            recommendation = knowledge.recommend_capability_provider(
                "injector",
                action="load_library",
                target_kind="process",
            )

            self.assertEqual(recommendation["provider"], "verified")
            self.assertEqual(recommendation["action"], "load_library")
            self.assertEqual(recommendation["target_kind"], "process")
            self.assertEqual(recommendation["runs"], 2)
            self.assertEqual(recommendation["success_rate"], 1.0)
            self.assertEqual(recommendation["artifact_completeness"], 1.0)
            self.assertEqual(recommendation["rollback_completeness"], 1.0)

    def test_recent_samples_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            for index in range(CAPABILITY_SAMPLE_LIMIT + 7):
                record = knowledge.record_capability_outcome(
                    "hook_runtime",
                    "local-hook",
                    "api_hook",
                    status="ok",
                    target=TargetIdentity(kind="process", pid=50000 + index),
                    duration_ms=index,
                    artifact_completeness=True,
                    rollback_completeness=True,
                )

            self.assertEqual(record["runs"], CAPABILITY_SAMPLE_LIMIT + 7)
            self.assertEqual(len(record["samples"]), CAPABILITY_SAMPLE_LIMIT)
            self.assertEqual(record["success_rate"], 1.0)
            self.assertEqual(record["artifact_complete_runs"], CAPABILITY_SAMPLE_LIMIT + 7)
            self.assertEqual(record["rollback_complete_runs"], CAPABILITY_SAMPLE_LIMIT + 7)

    def test_legacy_outcome_bucket_is_normalized_without_revealing_old_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_store = {
                "version": 0,
                "capabilities": {
                    "memory_runtime": {
                        "providers": {
                            "legacy": {
                                "actions": {
                                    "read": {
                                        "target_kinds": {
                                            "process": {
                                                "runs": "1",
                                                "successes": "1",
                                                "total_artifact_completeness": 99,
                                                "total_rollback_completeness": 99,
                                                "samples": [
                                                    {
                                                        "status": "ok",
                                                        "target": {
                                                            "kind": "process",
                                                            "pid": 812349,
                                                            "path": r"C:\legacy-private\target.exe",
                                                        },
                                                    }
                                                ],
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
            (root / "capability_outcomes.json").write_text(
                json.dumps(legacy_store),
                encoding="utf-8",
            )
            knowledge = KnowledgeBase(root)

            record = knowledge.record_capability_outcome(
                "memory_runtime",
                "legacy",
                "read",
                status="failed",
                target=TargetIdentity(kind="process", pid=812350),
            )

            self.assertEqual(record["runs"], 2)
            self.assertEqual(record["artifact_completeness"], 0.5)
            self.assertEqual(record["rollback_completeness"], 0.5)
            self.assertEqual(set(record["samples"][0]["target"]), {"kind", "identity_hash"})
            persisted_text = (root / "capability_outcomes.json").read_text("utf-8")
            self.assertNotIn("812349", persisted_text)
            self.assertNotIn("target.exe", persisted_text)

    def test_mock_provider_lifecycle_is_recorded_for_all_managed_capabilities(self) -> None:
        cases = {
            "memory_runtime": TargetIdentity(
                kind="process",
                pid=963147,
                display_name="sensitive-memory-target.exe",
            ),
            "injector": TargetIdentity(kind="process", pid=963147),
            "hook_runtime": TargetIdentity(kind="process", pid=963147),
            "patch_executor": TargetIdentity(
                kind="sample",
                path=r"C:\sensitive\patch-target.exe",
                sha256="a" * 64,
            ),
            "android_rebuild": TargetIdentity(
                kind="sample",
                path=r"C:\sensitive\application.apk",
                sha256="b" * 64,
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)
            for capability, target in cases.items():
                with self.subTest(capability=capability):
                    provider = MockCapabilityProvider(capability)
                    request = CapabilityRequest(
                        capability=capability,
                        action="inspect",
                        target=target,
                        session_id=f"{capability}-knowledge-test",
                    )
                    plan = provider.plan(request)
                    validation = provider.validate(plan)
                    result = provider.execute(plan)
                    bundle = provider.collect_artifacts(result, temporary)
                    rollback = provider.rollback(result)

                    self.assertTrue(validation.ok)
                    record = record_capability_lifecycle_outcome(
                        knowledge,
                        result,
                        artifact_bundle=bundle,
                        rollback_result=rollback,
                        duration_ms=7.25,
                    )

                    self.assertIsNotNone(record)
                    self.assertEqual(record["capability"], capability)
                    self.assertEqual(record["provider"], "mock")
                    self.assertEqual(record["action"], "inspect")
                    self.assertEqual(record["last_status"], "mocked")
                    self.assertEqual(record["unavailable"], 1)
                    self.assertEqual(record["success_rate"], 0.0)
                    self.assertEqual(record["artifact_completeness"], 1.0)
                    self.assertEqual(record["rollback_completeness"], 1.0)
                    self.assertEqual(record["avg_duration_ms"], 7.25)

            persisted_text = (root / "capability_outcomes.json").read_text("utf-8")
            self.assertNotIn("963147", persisted_text)
            self.assertNotIn("sensitive-memory-target.exe", persisted_text)
            self.assertNotIn("patch-target.exe", persisted_text)
            self.assertNotIn("application.apk", persisted_text)
            self.assertEqual(
                set(knowledge.load_capability_outcomes()["capabilities"]),
                set(cases),
            )


if __name__ == "__main__":
    unittest.main()
