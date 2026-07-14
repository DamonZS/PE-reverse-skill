from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.knowledge import KnowledgeBase


class PatchKnowledgeTests(unittest.TestCase):
    def test_patch_strategy_statistics_accumulate_attempted_rates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            kb.record_patch_strategy_result(
                "inline_patch",
                target_format="pe",
                status="ok",
                verification_status="passed",
                apply_status="ok",
                rollback_status="success",
                operation_count=3,
                risk_counts={"high": 2, "warning": 1},
                sample_id="sample-a",
                backend="local_verified_patch",
            )
            kb.record_patch_strategy_result(
                "inline_patch",
                target_format="pe",
                status="failed",
                verification_status="failed",
                apply_status="failed",
                rollback_status="failed",
                operation_count=1,
                risk_counts={"high": 1, "medium": 2},
                sample_id="sample-b",
                backend="local_verified_patch",
            )
            record = kb.record_patch_strategy_result(
                "inline_patch",
                target_format="pe",
                status="unavailable",
                operation_count=0,
                risk_counts={"warning": 2},
                sample_id="sample-c",
            )

            self.assertEqual(record["runs"], 3)
            self.assertEqual(record["successes"], 1)
            self.assertEqual(record["failures"], 1)
            self.assertEqual(record["unavailable"], 1)
            self.assertEqual(record["verifications_passed"], 1)
            self.assertEqual(record["applies_succeeded"], 1)
            self.assertEqual(record["rollbacks_succeeded"], 1)
            self.assertEqual(record["total_operation_count"], 4)
            self.assertEqual(
                record["risk_counts"],
                {"high": 3, "warning": 3, "medium": 2},
            )
            self.assertEqual(record["samples"], ["sample-a", "sample-b", "sample-c"])
            self.assertAlmostEqual(record["success_rate"], 1 / 3, delta=0.001)
            self.assertAlmostEqual(record["verify_rate"], 1 / 2, delta=0.001)
            self.assertAlmostEqual(record["apply_rate"], 1 / 2, delta=0.001)
            self.assertAlmostEqual(record["rollback_rate"], 1 / 2, delta=0.001)
            self.assertAlmostEqual(record["avg_operation_count"], 4 / 3, delta=0.001)

    def test_recommend_patch_strategy_selects_best_for_target_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            for _ in range(3):
                kb.record_patch_strategy_result(
                    "inline_patch",
                    target_format="pe",
                    status="failed",
                    verification_status="failed",
                    operation_count=1,
                    risk_counts={"high": 3},
                )
            for index in range(3):
                kb.record_patch_strategy_result(
                    "code_cave_patch",
                    target_format="pe",
                    status="ok",
                    verification_status="passed",
                    apply_status="ok",
                    operation_count=2,
                    sample_id=f"pe-{index}",
                )
            for index in range(5):
                kb.record_patch_strategy_result(
                    "resource_replace",
                    target_format="apk",
                    status="ok",
                    verification_status="passed",
                    apply_status="ok",
                    operation_count=1,
                    sample_id=f"apk-{index}",
                )

            recommendation = kb.recommend_patch_strategy(target_format=" PE ")

            self.assertEqual(recommendation["target_format"], "pe")
            self.assertEqual(recommendation["strategy"], "code_cave_patch")
            self.assertEqual(recommendation["runs"], 3)
            self.assertGreater(recommendation["score"], 0.0)

    def test_patch_strategy_save_and_load_survive_reinstantiation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "version": 1,
                "strategies": {
                    "pe:inline_patch": {
                        "target_format": "pe",
                        "strategy": "inline_patch",
                        "runs": 2,
                        "successes": 1,
                        "failures": 1,
                    }
                },
                "last_updated": "2026-07-13T00:00:00Z",
            }
            KnowledgeBase(tmp).save_patch_strategies(payload)

            reloaded = KnowledgeBase(tmp).load_patch_strategies()

            self.assertEqual(reloaded, payload)
            self.assertTrue((Path(tmp) / "patch_strategies.json").is_file())

    def test_patch_inputs_and_recent_samples_are_normalized_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            for index in range(27):
                kb.record_patch_strategy_result(
                    " inline_patch ",
                    target_format=" PE ",
                    status="OK",
                    operation_count=1,
                    sample_id=f"sample-{index:02d}",
                )
            record = kb.record_patch_strategy_result(
                " inline_patch ",
                target_format=" PE ",
                status="OK",
                operation_count=1,
                sample_id="sample-10",
            )
            stored = kb.load_patch_strategies()

            self.assertEqual(set(stored["strategies"]), {"pe:inline_patch"})
            self.assertEqual(record["target_format"], "pe")
            self.assertEqual(record["strategy"], "inline_patch")
            self.assertEqual(record["runs"], 28)
            self.assertEqual(record["successes"], 28)
            self.assertEqual(len(record["samples"]), 25)
            self.assertEqual(
                set(record["samples"]),
                {f"sample-{index:02d}" for index in range(2, 27)},
            )
            self.assertEqual(record["samples"].count("sample-10"), 1)

    def test_patch_strategy_recommendation_has_predictable_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            recommendation = KnowledgeBase(tmp).recommend_patch_strategy(
                target_format=" ELF ",
                default="section_extend_patch",
            )

            self.assertEqual(recommendation["target_format"], "elf")
            self.assertEqual(recommendation["strategy"], "section_extend_patch")
            self.assertEqual(recommendation["score"], 0.0)


if __name__ == "__main__":
    unittest.main()
