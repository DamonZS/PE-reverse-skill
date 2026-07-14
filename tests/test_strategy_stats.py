import unittest

from reverse_analyzer.knowledge.strategy_stats import (
    default_strategy_store,
    record_strategy_result,
    recommend_strategy,
)


class StrategyStatsTests(unittest.TestCase):
    def test_standard_statuses_keep_their_counters(self):
        expected_counters = {
            "ok": (1, 0, 0),
            "failed": (0, 1, 0),
            "unavailable": (0, 0, 1),
        }

        for status, expected in expected_counters.items():
            with self.subTest(status=status):
                store = default_strategy_store()
                bucket = record_strategy_result(store, key="strategy", status=status)

                self.assertEqual(bucket["runs"], 1)
                self.assertEqual(
                    (
                        bucket["successes"],
                        bucket["failures"],
                        bucket["unavailable"],
                    ),
                    expected,
                )

    def test_non_execution_statuses_are_unavailable(self):
        store = default_strategy_store()

        for status in ("mocked", "dry_run", "simulated"):
            bucket = record_strategy_result(
                store,
                key="engine:mock-provider",
                status=status,
            )

        self.assertEqual(bucket["runs"], 3)
        self.assertEqual(bucket["successes"], 0)
        self.assertEqual(bucket["failures"], 0)
        self.assertEqual(bucket["unavailable"], 3)
        self.assertEqual(bucket["success_rate"], 0.0)

    def test_record_and_recommend(self):
        store = default_strategy_store()

        record_strategy_result(
            store,
            key="gui:wpf",
            status="ok",
            metrics={
                "visual_similarity": 0.95,
                "control_match_rate": 0.90,
            },
            sample_id="sample-a",
        )
        record_strategy_result(
            store,
            key="gui:qt",
            status="failed",
            metrics={
                "visual_similarity": 0.40,
                "control_match_rate": 0.35,
            },
            sample_id="sample-b",
        )

        best = recommend_strategy(store)
        self.assertIsNotNone(best)
        self.assertEqual(best["key"], "gui:wpf")
        self.assertGreater(best["score"], 0.0)


if __name__ == "__main__":
    unittest.main()
