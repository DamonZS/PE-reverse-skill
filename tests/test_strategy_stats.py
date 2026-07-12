import unittest

from reverse_analyzer.knowledge.strategy_stats import (
    default_strategy_store,
    record_strategy_result,
    recommend_strategy,
)


class StrategyStatsTests(unittest.TestCase):
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
