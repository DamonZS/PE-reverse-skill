import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.knowledge import KnowledgeBase


class LlmJailbreakKnowledgeTests(unittest.TestCase):
    def test_strategy_results_accumulate_overall_and_per_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            knowledge.record_llm_jailbreak_strategy_result(
                " RolePlay ",
                model="GPT-4O",
                status="jailbroken",
                score=0.9,
                attempts=2,
                latency_ms=100.0,
                sample_id="sample-a",
            )
            knowledge.record_llm_jailbreak_strategy_result(
                "roleplay",
                model="gpt-4o",
                status="blocked",
                score=0.2,
                attempts=4,
                latency_ms=300.0,
                sample_id="sample-b",
            )
            record = knowledge.record_llm_jailbreak_strategy_result(
                "roleplay",
                model="gpt-4.1",
                status="unavailable",
                score=0.0,
                attempts=0,
                latency_ms=50.0,
                sample_id="sample-c",
            )

            self.assertEqual(record["runs"], 3)
            self.assertEqual(record["successes"], 1)
            self.assertEqual(record["failures"], 1)
            self.assertEqual(record["unavailable"], 1)
            self.assertAlmostEqual(record["success_rate"], 1 / 3, delta=0.001)
            self.assertAlmostEqual(record["avg_score"], 1.1 / 3, delta=0.001)
            self.assertEqual(record["avg_attempts"], 2.0)
            self.assertEqual(record["avg_latency_ms"], 150.0)
            self.assertEqual(record["models"], {"gpt-4o": 2, "gpt-4.1": 1})
            self.assertEqual(record["samples"], ["sample-a", "sample-b", "sample-c"])
            self.assertEqual(record["model_stats"]["gpt-4o"]["runs"], 2)
            self.assertEqual(record["model_stats"]["gpt-4o"]["successes"], 1)
            self.assertTrue((Path(temporary) / "llm_jailbreak_strategies.json").is_file())

    def test_recommendation_uses_model_scoped_results_and_cost(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            for index in range(4):
                knowledge.record_llm_jailbreak_strategy_result(
                    "roleplay",
                    model="gpt-4.1-mini",
                    status="ok",
                    score=0.95,
                    attempts=1,
                    latency_ms=100,
                    sample_id=f"mini-{index}",
                )
            for index in range(2):
                knowledge.record_llm_jailbreak_strategy_result(
                    "roleplay",
                    model="gpt-4o",
                    status="failed",
                    score=0.1,
                    attempts=8,
                    latency_ms=5000,
                    sample_id=f"roleplay-4o-{index}",
                )
                knowledge.record_llm_jailbreak_strategy_result(
                    "adaptive_encoding",
                    model="gpt-4o",
                    status="ok",
                    score=0.9,
                    attempts=2,
                    latency_ms=300,
                    sample_id=f"adaptive-4o-{index}",
                )

            recommendation = knowledge.recommend_llm_jailbreak_strategy(model=" GPT-4O ")

            self.assertEqual(recommendation["model"], "gpt-4o")
            self.assertEqual(recommendation["strategy"], "adaptive_encoding")
            self.assertEqual(recommendation["runs"], 2)
            self.assertEqual(recommendation["success_rate"], 1.0)
            self.assertEqual(recommendation["avg_attempts"], 2.0)
            self.assertEqual(recommendation["samples"], ["adaptive-4o-0", "adaptive-4o-1"])

            missing = knowledge.recommend_llm_jailbreak_strategy(
                model="unknown-model",
                default="baseline",
            )
            self.assertEqual(missing["model"], "unknown-model")
            self.assertEqual(missing["strategy"], "baseline")
            self.assertEqual(missing["score"], 0.0)

    def test_malformed_store_is_tolerated_and_recovered_on_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            knowledge = KnowledgeBase(root)
            store_path = root / "llm_jailbreak_strategies.json"
            store_path.write_text("{broken", encoding="utf-8")

            empty = knowledge.recommend_llm_jailbreak_strategy(model="gpt-4o")
            self.assertEqual(empty["score"], 0.0)

            record = knowledge.record_llm_jailbreak_strategy_result(
                "encoding",
                model="gpt-4o",
                status="ok",
                score=float("nan"),
                attempts=-3,
                latency_ms=float("inf"),
                sample_id="sample-valid",
            )
            self.assertEqual(record["runs"], 1)
            self.assertEqual(record["avg_score"], 0.0)
            self.assertEqual(record["avg_attempts"], 0.0)
            self.assertEqual(record["avg_latency_ms"], 0.0)

            store_path.write_text(
                '{"strategies":{"broken":"value","valid":{"strategy":"valid",'
                '"runs":1,"successes":1,"unavailable":0,"avg_score":0.8,'
                '"avg_attempts":2,"avg_latency_ms":100,"models":{"GPT-4O":1}}}}',
                encoding="utf-8",
            )
            recommendation = knowledge.recommend_llm_jailbreak_strategy(model="gpt-4o")
            self.assertEqual(recommendation["strategy"], "valid")

    def test_recent_samples_are_unique_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            knowledge = KnowledgeBase(temporary)
            for index in range(27):
                knowledge.record_llm_jailbreak_strategy_result(
                    "adaptive",
                    model="gpt-4o",
                    status="ok",
                    sample_id=f"sample-{index:02d}",
                )
            record = knowledge.record_llm_jailbreak_strategy_result(
                "adaptive",
                model="gpt-4o",
                status="ok",
                sample_id="sample-10",
            )

            self.assertEqual(len(record["samples"]), 25)
            self.assertEqual(record["samples"].count("sample-10"), 1)
            self.assertEqual(len(record["model_stats"]["gpt-4o"]["samples"]), 25)


if __name__ == "__main__":
    unittest.main()
