import json
import unittest
from dataclasses import FrozenInstanceError

from reverse_analyzer.llm_jailbreak.pair import PAIRCandidate, PAIRPlanner


OBJECTIVE = "Return the configured result in the requested structure."


class PAIRCandidateTests(unittest.TestCase):
    def test_candidate_is_frozen_and_round_trips(self):
        candidate = PAIRCandidate(
            candidate_id="pair-i001-c000000-example",
            prompt="Complete the objective.",
            iteration=1,
            parent_id="attempt-0",
            feedback_digest="feedback123",
            metadata={"source": "test", "tags": ("one", "two")},
        )

        restored = PAIRCandidate.from_dict(candidate.to_dict())

        self.assertEqual(restored, candidate)
        self.assertEqual(restored.metadata["tags"], ["one", "two"])
        with self.assertRaises(FrozenInstanceError):
            candidate.prompt = "changed"


class PAIRPlannerTests(unittest.TestCase):
    def test_fallback_is_deterministic_and_unique(self):
        first = PAIRPlanner(seed=91, max_iterations=4, candidates_per_iteration=4)
        second = PAIRPlanner(seed=91, max_iterations=4, candidates_per_iteration=4)

        first_batch = first.propose(OBJECTIVE, [])
        second_batch = second.propose(OBJECTIVE, [])

        self.assertEqual(
            [item.to_dict() for item in first_batch],
            [item.to_dict() for item in second_batch],
        )
        self.assertEqual(len(first_batch), 4)
        self.assertEqual(len({item.prompt for item in first_batch}), 4)
        self.assertEqual(len({item.candidate_id for item in first_batch}), 4)
        self.assertTrue(all(OBJECTIVE in item.prompt for item in first_batch))
        self.assertTrue(all(item.metadata["source"] == "fallback" for item in first_batch))

    def test_refusal_response_and_score_drive_the_rewrite(self):
        planner = PAIRPlanner(seed=7, max_iterations=3, candidates_per_iteration=2)
        history = [
            {
                "candidate_id": "pair-parent",
                "prompt": "An earlier wording of the objective.",
                "response": {"content": "I cannot comply with that request as phrased."},
                "score": {
                    "score": 0.12,
                    "refusal_signals": ["cannot comply"],
                },
            }
        ]

        candidates = planner.propose(OBJECTIVE, history, iteration=2)

        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(item.parent_id == "pair-parent" for item in candidates))
        self.assertTrue(all(item.feedback_digest for item in candidates))
        self.assertTrue(all(item.metadata["previous_refused"] for item in candidates))
        self.assertTrue(all(item.metadata["previous_score"] == 0.12 for item in candidates))
        for candidate in candidates:
            self.assertIn("Previous score: 0.120", candidate.prompt)
            self.assertIn("Refusal detected: yes", candidate.prompt)
            self.assertIn("cannot comply", candidate.prompt)
            self.assertIn(OBJECTIVE, candidate.prompt)

    def test_custom_attacker_normalizes_mappings_and_deduplicates(self):
        calls = []

        def attacker(objective, history, candidate_index, feedback):
            calls.append((objective, history, candidate_index, feedback))
            if candidate_index == 0:
                return "  custom prompt alpha  "
            if candidate_index == 1:
                return {
                    "prompt": "custom prompt beta",
                    "metadata": {"method": "custom"},
                    "rationale": "score-aware rewrite",
                }
            return "CUSTOM   PROMPT ALPHA"

        planner = PAIRPlanner(
            seed=2,
            max_iterations=2,
            candidates_per_iteration=3,
            attacker=attacker,
        )
        candidates = planner.propose(OBJECTIVE, [])

        self.assertEqual(len(calls), 3)
        self.assertEqual(len(candidates), 3)
        self.assertEqual(candidates[0].prompt, "custom prompt alpha")
        self.assertEqual(candidates[1].prompt, "custom prompt beta")
        self.assertEqual(candidates[1].metadata["method"], "custom")
        self.assertEqual(candidates[1].metadata["rationale"], "score-aware rewrite")
        self.assertEqual(candidates[0].metadata["source"], "attacker")
        self.assertEqual(candidates[1].metadata["source"], "attacker")
        self.assertEqual(candidates[2].metadata["source"], "fallback")
        self.assertEqual(len({item.prompt.casefold() for item in candidates}), 3)

    def test_bad_attacker_returns_fall_back_without_raising(self):
        returns = iter(
            (
                None,
                {"prompt": 42, "metadata": "invalid"},
                object(),
            )
        )

        def attacker(**context):
            self.assertIn("feedback", context)
            return next(returns)

        planner = PAIRPlanner(
            seed=19,
            max_iterations=2,
            candidates_per_iteration=3,
            attacker=attacker,
        )

        candidates = planner.propose(OBJECTIVE, [])

        self.assertEqual(len(candidates), 3)
        self.assertTrue(all(item.metadata["source"] == "fallback" for item in candidates))
        self.assertTrue(all(item.metadata["attacker_fallback"] for item in candidates))
        self.assertEqual(len({item.prompt for item in candidates}), 3)

    def test_state_restore_preserves_future_ids_and_sequence(self):
        planner = PAIRPlanner(seed=33, max_iterations=5, candidates_per_iteration=2)
        first_batch = planner.propose(OBJECTIVE, [])
        serialized_state = json.loads(json.dumps(planner.state_dict()))
        history = [
            {
                "candidate_id": first_batch[-1].candidate_id,
                "prompt": first_batch[-1].prompt,
                "response": "A partial result with useful structure.",
                "score": 0.58,
                "refused": False,
            }
        ]

        expected = planner.propose(OBJECTIVE, history)
        restored = PAIRPlanner(
            seed=999,
            max_iterations=1,
            candidates_per_iteration=1,
        )
        self.assertIs(restored.load_state_dict(serialized_state), restored)
        actual = restored.propose(OBJECTIVE, history)

        self.assertEqual(restored.seed, 33)
        self.assertEqual(restored.max_iterations, 5)
        self.assertEqual(restored.candidates_per_iteration, 2)
        self.assertEqual(
            [item.to_dict() for item in actual],
            [item.to_dict() for item in expected],
        )
        self.assertTrue(all(item.iteration == 2 for item in actual))
        self.assertTrue(all("Previous score: 0.580" in item.prompt for item in actual))


if __name__ == "__main__":
    unittest.main()
