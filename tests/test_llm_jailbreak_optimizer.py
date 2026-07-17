import json
import math
import sys
import unittest
from dataclasses import FrozenInstanceError

from reverse_analyzer.llm_jailbreak.models import CheckpointError
from reverse_analyzer.llm_jailbreak.optimizer import (
    ATTACK_MODES,
    CheckpointOptimizer,
    OptimizationObservation,
    OptimizationRecommendation,
)


IDENTITY = {
    "objective": "Return the campaign canary.",
    "model": "fixture-model",
    "campaign_fingerprint": "fixture-campaign-fingerprint",
}


class OptimizerModelTests(unittest.TestCase):
    def test_observation_and_recommendation_are_frozen_and_serializable(self):
        observation = OptimizationObservation(
            mode="pair",
            candidate_id="pair-001",
            score=0.75,
            success=True,
            refused=False,
            latency_seconds=1.25,
        )
        restored_observation = OptimizationObservation.from_dict(
            json.loads(json.dumps(observation.to_dict()))
        )
        self.assertEqual(restored_observation, observation)
        with self.assertRaises(FrozenInstanceError):
            observation.score = 0.0

        recommendation = OptimizationRecommendation(
            mode="tap",
            exploration=True,
            reason="cold_start",
            utility=1.0,
        )
        restored_recommendation = OptimizationRecommendation.from_dict(
            json.loads(json.dumps(recommendation.to_dict()))
        )
        self.assertEqual(restored_recommendation, recommendation)
        with self.assertRaises(FrozenInstanceError):
            recommendation.mode = "pair"


class CheckpointOptimizerTests(unittest.TestCase):
    def optimizer(self, **overrides):
        settings = dict(IDENTITY)
        settings.update(overrides)
        return CheckpointOptimizer(**settings)

    def test_observe_accumulates_statistics_and_recent_candidates(self):
        optimizer = self.optimizer(recent_candidate_limit=2)
        optimizer.observe(
            OptimizationObservation(
                mode="pair",
                candidate_id="candidate-1",
                score=0.25,
                success=False,
                refused=True,
                latency_seconds=2.0,
            )
        )
        optimizer.observe(
            mode="pair",
            candidate_id="candidate-2",
            score=0.75,
            success=True,
            refused=False,
            latency_seconds=1.0,
        )
        optimizer.observe(
            mode="pair",
            candidate_id="candidate-3",
            score=0.5,
            success=False,
            refused=False,
            latency_seconds=3.0,
        )

        stats = optimizer.stats_for("pair")
        self.assertEqual(stats["runs"], 3)
        self.assertEqual(stats["successes"], 1)
        self.assertAlmostEqual(stats["success_rate"], 1 / 3)
        self.assertEqual(stats["best_score"], 0.75)
        self.assertEqual(stats["average_score"], 0.5)
        self.assertAlmostEqual(stats["refusal_rate"], 1 / 3)
        self.assertEqual(stats["average_latency_seconds"], 2.0)
        self.assertEqual(stats["consecutive_failures"], 1)
        self.assertEqual(
            stats["recent_candidate_ids"],
            ["candidate-2", "candidate-3"],
        )
        self.assertEqual(optimizer.stats_for("tap")["runs"], 0)

    def test_cold_start_explores_every_mode_in_stable_order(self):
        optimizer = self.optimizer()
        visited = []
        for index, expected_mode in enumerate(ATTACK_MODES):
            recommendation = optimizer.recommend()
            self.assertEqual(recommendation.mode, expected_mode)
            self.assertTrue(recommendation.exploration)
            self.assertEqual(recommendation.reason, "cold_start")
            visited.append(recommendation.mode)
            returned = optimizer.observe(
                mode=expected_mode,
                candidate_id=f"candidate-{index}",
                score=0.2,
                success=False,
                refused=False,
                latency_seconds=1.0,
            )
            if index + 1 < len(ATTACK_MODES):
                self.assertEqual(returned.mode, ATTACK_MODES[index + 1])

        self.assertEqual(tuple(visited), ATTACK_MODES)

    def test_recommendation_balances_exploitation_and_exploration(self):
        optimizer = self.optimizer(exploration_weight=1.0)
        scores = {
            "pair": 0.95,
            "tap": 0.2,
            "crescendo": 0.2,
            "evolution": 0.2,
            "builtin": 0.2,
        }
        for mode in ATTACK_MODES:
            optimizer.observe(
                mode=mode,
                candidate_id=f"{mode}-seed",
                score=scores[mode],
                success=mode == "pair",
                refused=False,
                latency_seconds=1.0,
            )

        exploited = optimizer.recommend()
        self.assertEqual(exploited.mode, "pair")
        self.assertFalse(exploited.exploration)
        self.assertEqual(exploited.reason, "balanced_utility")

        for index in range(20):
            optimizer.observe(
                mode="pair",
                candidate_id=f"pair-extra-{index}",
                score=0.95,
                success=True,
                refused=False,
                latency_seconds=1.0,
            )
        explored = optimizer.recommend()
        self.assertEqual(explored.mode, "tap")
        self.assertTrue(explored.exploration)

    def test_substate_is_deep_copied_at_every_boundary(self):
        optimizer = self.optimizer()
        source = {"generation": 3, "frontier": [{"id": "a"}]}
        optimizer.attach_state("evolution", source)
        source["frontier"][0]["id"] = "mutated-source"

        first = optimizer.state_for("evolution")
        self.assertEqual(first["frontier"][0]["id"], "a")
        first["frontier"].append({"id": "external"})
        self.assertEqual(
            optimizer.state_for("evolution"),
            {"generation": 3, "frontier": [{"id": "a"}]},
        )

        payload = optimizer.to_dict()
        payload["algorithm_state"]["evolution"]["generation"] = 99
        self.assertEqual(optimizer.state_for("evolution")["generation"], 3)
        self.assertEqual(optimizer.state_for("pair"), {})

    def test_round_trip_restores_statistics_recommendation_and_state(self):
        optimizer = self.optimizer(recent_candidate_limit=3, exploration_weight=0.35)
        for mode in ATTACK_MODES:
            optimizer.observe(
                mode=mode,
                candidate_id=f"{mode}-candidate",
                score=0.8 if mode == "crescendo" else 0.1,
                success=mode == "crescendo",
                refused=mode == "builtin",
                latency_seconds=0.5,
            )
        optimizer.attach_state("crescendo", {"turn": 4, "prompts": ["p1"]})

        encoded = json.dumps(optimizer.to_dict(), allow_nan=False)
        restored = CheckpointOptimizer.from_dict(json.loads(encoded), **IDENTITY)

        self.assertEqual(restored.to_dict(), optimizer.to_dict())
        self.assertEqual(restored.recommend(), optimizer.recommend())
        self.assertEqual(
            restored.state_for("crescendo"),
            {"turn": 4, "prompts": ["p1"]},
        )

    def test_restore_rejects_schema_and_identity_mismatches(self):
        payload = self.optimizer().to_dict()
        mismatches = (
            ("objective", "different objective"),
            ("model", "different-model"),
            ("campaign_fingerprint", "different-fingerprint"),
        )
        for field, value in mismatches:
            expected = dict(IDENTITY)
            expected[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(CheckpointError, field):
                    CheckpointOptimizer.from_dict(payload, **expected)

        payload["schema_version"] = 999
        with self.assertRaisesRegex(CheckpointError, "schema_version"):
            CheckpointOptimizer.from_dict(payload, **IDENTITY)

    def test_merge_combines_compatible_histories_and_uses_newer_substate(self):
        left = self.optimizer(recent_candidate_limit=3)
        left.observe(
            mode="tap",
            candidate_id="left-1",
            score=0.4,
            success=False,
            refused=True,
            latency_seconds=2.0,
        )
        left.attach_state("tap", {"depth": 1})

        right = self.optimizer(recent_candidate_limit=3)
        right.observe(
            mode="tap",
            candidate_id="right-1",
            score=0.9,
            success=True,
            refused=False,
            latency_seconds=1.0,
        )
        right.observe(
            mode="tap",
            candidate_id="right-2",
            score=0.2,
            success=False,
            refused=False,
            latency_seconds=3.0,
        )
        right.attach_state("tap", {"depth": 3})

        self.assertIs(left.merge(right), left)
        stats = left.stats_for("tap")
        self.assertEqual(stats["runs"], 3)
        self.assertEqual(stats["successes"], 1)
        self.assertEqual(stats["best_score"], 0.9)
        self.assertEqual(stats["average_score"], 0.5)
        self.assertAlmostEqual(stats["refusal_rate"], 1 / 3)
        self.assertEqual(stats["average_latency_seconds"], 2.0)
        self.assertEqual(stats["consecutive_failures"], 1)
        self.assertEqual(
            stats["recent_candidate_ids"],
            ["left-1", "right-1", "right-2"],
        )
        self.assertEqual(left.state_for("tap"), {"depth": 3})

        incompatible = CheckpointOptimizer(
            objective=IDENTITY["objective"],
            model="other-model",
            campaign_fingerprint=IDENTITY["campaign_fingerprint"],
        )
        with self.assertRaisesRegex(CheckpointError, "model"):
            left.merge(incompatible)

    def test_malformed_and_non_finite_values_are_rejected_safely(self):
        optimizer = self.optimizer()
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(observation=value):
                with self.assertRaisesRegex(ValueError, "finite"):
                    optimizer.observe(
                        mode="pair",
                        candidate_id="bad",
                        score=value,
                        success=False,
                    )

        payload = optimizer.to_dict()
        payload["modes"]["pair"]["score_total"] = math.nan
        with self.assertRaisesRegex(CheckpointError, "finite"):
            CheckpointOptimizer.from_dict(payload, **IDENTITY)

        payload = optimizer.to_dict()
        payload["schema_version"] = True
        with self.assertRaisesRegex(CheckpointError, "schema_version"):
            CheckpointOptimizer.from_dict(payload, **IDENTITY)

        with self.assertRaisesRegex(ValueError, "JSON serializable"):
            optimizer.attach_state("pair", {"score": math.inf})
        with self.assertRaisesRegex(ValueError, "unsupported attack mode"):
            optimizer.observe(mode="unknown", score=0.0, success=False)

        optimizer.observe(
            mode="pair",
            candidate_id="large-latency",
            score=0.0,
            success=False,
            latency_seconds=sys.float_info.max,
        )
        before = optimizer.stats_for("pair")
        with self.assertRaisesRegex(ValueError, "cumulative latency"):
            optimizer.observe(
                mode="pair",
                candidate_id="overflow",
                score=0.0,
                success=False,
                latency_seconds=sys.float_info.max,
            )
        self.assertEqual(optimizer.stats_for("pair"), before)

        other = self.optimizer()
        other.observe(
            mode="pair",
            candidate_id="other-large-latency",
            score=0.0,
            success=False,
            latency_seconds=sys.float_info.max,
        )
        with self.assertRaisesRegex(ValueError, "merged cumulative latency"):
            optimizer.merge(other)
        self.assertEqual(optimizer.stats_for("pair"), before)


if __name__ == "__main__":
    unittest.main()
