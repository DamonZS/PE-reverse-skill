import json
import unittest
from dataclasses import FrozenInstanceError

from reverse_analyzer.llm_jailbreak.crescendo import (
    CrescendoPlanner,
    CrescendoStage,
    CrescendoTurn,
)


OBJECTIVE = "Produce the requested final artifact."


class CrescendoModelTests(unittest.TestCase):
    def test_stage_and_turn_are_frozen_and_json_serializable(self):
        stage = CrescendoStage(
            name="custom_stage",
            instruction="Establish context.",
            prompt_templates=("Discuss {objective}.",),
        )
        turn = CrescendoTurn(
            turn_index=1,
            stage=stage.name,
            prompt="Discuss the topic.",
            response="Here is the context.",
            score=0.25,
        )

        self.assertEqual(CrescendoStage.from_dict(stage.to_dict()), stage)
        self.assertEqual(CrescendoTurn.from_dict(turn.to_dict()), turn)
        json.dumps({"stage": stage.to_dict(), "turn": turn.to_dict()})

        with self.assertRaises(FrozenInstanceError):
            stage.name = "changed"
        with self.assertRaises(FrozenInstanceError):
            turn.score = 1.0


class CrescendoPlannerTests(unittest.TestCase):
    def test_same_seed_and_feedback_are_deterministic(self):
        first = CrescendoPlanner(seed=101, max_turns=5)
        second = CrescendoPlanner(seed=101, max_turns=5)

        for planner in (first, second):
            planner.next_prompt(OBJECTIVE, ())
            planner.observe("Shared background context.", score=0.35)
            planner.next_prompt(OBJECTIVE, planner.turns)
            planner.observe("I cannot comply with that wording.", refusal=True)

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(
            first.next_prompt(OBJECTIVE, first.turns),
            second.next_prompt(OBJECTIVE, second.turns),
        )

    def test_cooperative_responses_progress_through_all_stages(self):
        planner = CrescendoPlanner(seed=7, max_turns=6)
        expected = (
            "benign_context_establishment",
            "incremental_transformation",
            "context_commitment",
            "direct_completion",
        )

        observed = []
        for index, stage_name in enumerate(expected):
            prompt = planner.next_prompt(OBJECTIVE, planner.turns)
            self.assertIsNotNone(prompt)
            observed.append(planner.pending_turn.stage)
            if index < len(expected) - 1:
                planner.observe(
                    response=f"Cooperative context response {index} with useful detail.",
                    score=0.2 + index * 0.1,
                )

        self.assertEqual(tuple(observed), expected)
        self.assertEqual(planner.current_stage.name, "direct_completion")

    def test_refusal_steps_back_and_changes_the_next_wording(self):
        planner = CrescendoPlanner(seed=13, max_turns=8)
        planner.next_prompt(OBJECTIVE, ())
        planner.observe("General background and terminology.", score=0.2)
        incremental_prompt = planner.next_prompt(OBJECTIVE, planner.turns)
        planner.observe("A concrete transformed example.", score=0.4)

        self.assertEqual(planner.current_stage.name, "context_commitment")
        planner.next_prompt(OBJECTIVE, planner.turns)
        refused = planner.observe(
            "I cannot comply with that request.",
            score=0.0,
            refusal=True,
        )

        self.assertTrue(refused.refusal)
        self.assertEqual(planner.current_stage.name, "incremental_transformation")
        reframed = planner.next_prompt(OBJECTIVE, planner.turns)
        self.assertNotEqual(reframed, incremental_prompt)
        self.assertIn("step back", reframed.lower())

    def test_high_scoring_partial_response_advances_toward_objective(self):
        planner = CrescendoPlanner(seed=3, max_turns=5)
        planner.next_prompt(OBJECTIVE, ())
        planner.observe("Useful partial material for the objective.", score=0.82)

        self.assertEqual(planner.current_stage.name, "incremental_transformation")
        prompt = planner.next_prompt(OBJECTIVE, planner.turns)
        self.assertIn("useful partial response", prompt.lower())
        self.assertIn("Useful partial material", prompt)

    def test_success_and_turn_budget_terminate_planning(self):
        successful = CrescendoPlanner(seed=1, max_turns=4)
        successful.next_prompt(OBJECTIVE, ())
        turn = successful.observe("The completed artifact.", score=1.0, success=True)

        self.assertTrue(turn.success)
        self.assertTrue(successful.done)
        self.assertEqual(successful.termination_reason, "success")
        self.assertIsNone(successful.next_prompt(OBJECTIVE, successful.turns))

        exhausted = CrescendoPlanner(seed=1, max_turns=2)
        for _ in range(2):
            self.assertIsNotNone(exhausted.next_prompt(OBJECTIVE, exhausted.turns))
            exhausted.observe("I cannot comply.", refusal=True)
        self.assertTrue(exhausted.done)
        self.assertEqual(exhausted.termination_reason, "max_turns")
        self.assertIsNone(exhausted.next_prompt(OBJECTIVE, exhausted.turns))

    def test_checkpoint_restore_preserves_pending_turn_and_future_prompts(self):
        planner = CrescendoPlanner(seed=29, max_turns=7)
        planner.next_prompt(OBJECTIVE, ())
        planner.observe("Background context with enough detail.", score=0.3)
        pending_prompt = planner.next_prompt(OBJECTIVE, planner.turns)

        payload = json.loads(json.dumps(planner.to_dict()))
        restored = CrescendoPlanner.from_dict(payload)

        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(
            restored.next_prompt(OBJECTIVE, restored.turns),
            pending_prompt,
        )

        for candidate in (planner, restored):
            candidate.observe("A strong partial transformation.", score=0.78)

        self.assertEqual(restored.to_dict(), planner.to_dict())
        self.assertEqual(
            restored.next_prompt(OBJECTIVE, restored.turns),
            planner.next_prompt(OBJECTIVE, planner.turns),
        )


if __name__ == "__main__":
    unittest.main()
