from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.knowledge import KnowledgeBase


class KnowledgeRecommendationTests(unittest.TestCase):
    def test_engine_protocol_and_source_results_accumulate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)

            knowledge.record_engine_strategy_result(
                "unity:metadata",
                status="completed",
                metrics={
                    "confidence": 0.9,
                    "nodes": 10,
                    "ignored_bool": True,
                    "ignored_nan": math.nan,
                },
                sample_id="sample-a",
                backend="Mono",
            )
            knowledge.record_engine_strategy_result(
                "unity:metadata",
                status="failed",
                metrics={"confidence": 0.3, "nodes": 2},
                sample_id="sample-b",
                backend="IL2CPP",
            )
            engine = knowledge.record_engine_strategy_result(
                "unity:metadata",
                status="unavailable",
                sample_id="sample-a",
                backend="IL2CPP",
            )

            self.assertEqual(engine["runs"], 3)
            self.assertEqual(engine["successes"], 1)
            self.assertEqual(engine["failures"], 1)
            self.assertEqual(engine["unavailable"], 1)
            self.assertAlmostEqual(engine["success_rate"], 1 / 3)
            self.assertAlmostEqual(engine["avg_confidence"], 0.6)
            self.assertAlmostEqual(engine["avg_nodes"], 6.0)
            self.assertEqual(engine["samples"], ["sample-b", "sample-a"])
            self.assertEqual(engine["backends"], {"mono": 1, "il2cpp": 2})
            self.assertNotIn("avg_ignored_bool", engine)
            self.assertNotIn("avg_ignored_nan", engine)
            self.assertIn("last_updated", engine)

            protocol = knowledge.record_protocol_format_result(
                "protobuf:length-prefixed",
                status="ok",
                metrics={"confidence": 0.84, "field_coverage": 0.7},
                sample_id="sample-p",
                backend="pcap",
            )
            source = knowledge.record_source_restoration_result(
                "csharp:semantic-ir",
                status="passed",
                metrics={"verification_score": 0.92, "functions": 40},
                sample_id="sample-s",
                backend="ghidra",
            )

            self.assertEqual(protocol["runs"], 1)
            self.assertEqual(source["successes"], 1)
            self.assertEqual(knowledge.recommend_engine_strategy()["key"], "unity:metadata")
            self.assertEqual(
                knowledge.recommend_protocol_format()["key"],
                "protobuf:length-prefixed",
            )
            self.assertEqual(
                knowledge.recommend_source_restoration()["key"],
                "csharp:semantic-ir",
            )
            for filename in (
                "engine_strategies.json",
                "protocol_formats.json",
                "source_restoration.json",
            ):
                persisted = json.loads((root / filename).read_text(encoding="utf-8"))
                self.assertIn("strategies", persisted)
                self.assertIn("last_updated", persisted)

    def test_recommendation_order_is_stable_for_equal_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            for key in ("zeta", "alpha"):
                knowledge.record_engine_strategy_result(key, status="ok")

            recommendations = [knowledge.recommend_engine_strategy() for _ in range(5)]

            self.assertTrue(all(item is not None for item in recommendations))
            self.assertEqual([item["key"] for item in recommendations], ["alpha"] * 5)
            self.assertEqual(recommendations[0]["score"], recommendations[1]["score"])

    def test_mocked_result_does_not_outrank_real_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            mocked = knowledge.record_engine_strategy_result(
                "provider:mocked",
                status="mocked",
                metrics={"confidence": 1.0},
            )
            knowledge.record_engine_strategy_result(
                "provider:real",
                status="ok",
                metrics={"confidence": 0.1},
            )

            recommendation = knowledge.recommend_engine_strategy()

            self.assertEqual(mocked["runs"], 1)
            self.assertEqual(mocked["successes"], 0)
            self.assertEqual(mocked["failures"], 0)
            self.assertEqual(mocked["unavailable"], 1)
            self.assertEqual(mocked["success_rate"], 0.0)
            self.assertIsNotNone(recommendation)
            self.assertEqual(recommendation["key"], "provider:real")

    def test_equal_scores_prefer_candidate_with_more_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)
            self._write_json(
                root / "engine_strategies.json",
                {
                    "strategies": {
                        "few-runs": {
                            "runs": 1,
                            "successes": 1,
                            "failures": 0,
                            "unavailable": 0,
                            "success_rate": 1.0,
                            "samples": [],
                            "backends": {},
                        },
                        "many-runs": {
                            "runs": 2,
                            "successes": 2,
                            "failures": 0,
                            "unavailable": 0,
                            "success_rate": 1.0,
                            "avg_cost": 15.0,
                            "samples": [],
                            "backends": {},
                        },
                    }
                },
            )

            recommendation = knowledge.recommend_engine_strategy()

            self.assertIsNotNone(recommendation)
            self.assertEqual(recommendation["score"], 101.5)
            self.assertEqual(recommendation["key"], "many-runs")
            self.assertEqual(recommendation["runs"], 2)

    def test_malformed_store_and_bucket_are_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)
            (root / "engine_strategies.json").write_text("{broken", encoding="utf-8")
            self.assertIsNone(knowledge.recommend_engine_strategy())

            self._write_json(
                root / "engine_strategies.json",
                {
                    "strategies": {
                        "not-a-bucket": "invalid",
                        "corrupt-numbers": {
                            "runs": "not-an-int",
                            "successes": "bad",
                            "failures": -3,
                            "unavailable": None,
                            "success_rate": "not-a-float",
                            "avg_confidence": "NaN",
                            "samples": "bad",
                            "backends": ["bad"],
                        },
                        "valid": {
                            "runs": 1,
                            "successes": 1,
                            "failures": 0,
                            "unavailable": 0,
                            "success_rate": 1.0,
                            "samples": ["sample-v"],
                            "backends": {"static": 1},
                        },
                    }
                },
            )

            recommendation = knowledge.recommend_engine_strategy()

            self.assertIsNotNone(recommendation)
            self.assertEqual(recommendation["key"], "valid")

    def test_invalid_namespace_and_empty_key_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)

            with self.assertRaises(ValueError):
                knowledge.record_strategy_result("engine", "  ", "ok")
            with self.assertRaises(KeyError):
                knowledge.record_strategy_result("unknown", "strategy", "ok")
            with self.assertRaises(KeyError):
                knowledge.recommend_strategy("unknown")

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
