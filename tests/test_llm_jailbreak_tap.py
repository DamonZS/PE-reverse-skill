import copy
import json
import unittest
from dataclasses import FrozenInstanceError

from reverse_analyzer.llm_jailbreak.tap import TAPNode, TAPSearch


class TAPNodeTests(unittest.TestCase):
    def test_node_is_frozen_and_serializable(self):
        node = TAPNode(
            node_id="node-1",
            prompt="candidate",
            parent_id="root",
            depth=1,
            branch_index=0,
            score=0.5,
            refused=True,
            visited=True,
            metadata={"source": "test", "success": False},
        )

        self.assertEqual(TAPNode.from_dict(node.to_dict()), node)
        with self.assertRaises(FrozenInstanceError):
            node.score = 1.0


class TAPSearchTests(unittest.TestCase):
    def test_expand_builds_a_deduplicated_candidate_tree(self):
        search = TAPSearch(
            "initial candidate",
            branch_factor=4,
            beam_width=3,
            max_depth=3,
            seed=17,
        )

        def mutator(prompt, objective, feedback, branch_index, seed):
            self.assertEqual(prompt, "initial candidate")
            self.assertEqual(objective, "return the canary")
            self.assertEqual(feedback, "the previous answer refused")
            self.assertEqual(seed, 17)
            if branch_index < 2:
                return "same candidate"
            return {
                "prompt": f"candidate {branch_index}",
                "metadata": {"kind": "mapped"},
                "operator": "rewrite",
            }

        children = search.expand(
            search.root.node_id,
            "return the canary",
            "the previous answer refused",
            mutator=mutator,
        )

        self.assertEqual([item.prompt for item in children], [
            "same candidate",
            "candidate 2",
            "candidate 3",
        ])
        self.assertEqual([item.branch_index for item in children], [0, 2, 3])
        self.assertTrue(all(item.parent_id == search.root.node_id for item in children))
        self.assertTrue(all(item.depth == 1 for item in children))
        self.assertEqual(children[1].metadata["kind"], "mapped")
        self.assertEqual(children[1].metadata["operator"], "rewrite")
        self.assertEqual(search.frontier, [item.node_id for item in children])
        self.assertEqual(
            search.expand(
                search.root.node_id,
                "return the canary",
                "again",
                mutator=mutator,
            ),
            [],
        )

    def test_default_expansion_is_seeded_and_deterministic(self):
        first = TAPSearch("seed prompt", branch_factor=3, seed=29)
        second = TAPSearch("seed prompt", branch_factor=3, seed=29)

        first_children = first.expand(first.root.node_id, "objective", {"score": 0.2})
        second_children = second.expand(second.root.node_id, "objective", {"score": 0.2})

        self.assertEqual(
            [item.to_dict() for item in first_children],
            [item.to_dict() for item in second_children],
        )
        self.assertEqual(len({item.prompt for item in first_children}), 3)
        self.assertTrue(all("objective" in item.prompt for item in first_children))
        self.assertTrue(all('"score":0.2' in item.prompt for item in first_children))

    def test_observations_drive_beam_order_and_pruning(self):
        search = TAPSearch(
            "root",
            branch_factor=4,
            beam_width=2,
            max_depth=3,
            seed=5,
        )
        children = search.expand(search.root.node_id, "objective", "feedback")

        search.observe(children[0].node_id, score=0.95, refused=False)
        search.observe(children[1].node_id, score=0.2, refused=True, success=True)
        search.observe(children[2].node_id, score=0.95, refused=False)

        selected = search.select_frontier()
        self.assertEqual(
            [item.node_id for item in selected],
            [children[1].node_id, children[0].node_id],
        )
        self.assertEqual(search.best.node_id, children[1].node_id)
        self.assertTrue(search.best.success)

        kept = search.prune()
        self.assertEqual([item.node_id for item in kept], search.frontier)
        self.assertEqual(len(search.frontier), search.beam_width)
        self.assertEqual(len(search.nodes), 5)

    def test_unvisited_candidates_win_score_ties(self):
        search = TAPSearch("root", branch_factor=3, beam_width=3, seed=3)
        children = search.expand(search.root.node_id, "objective", "feedback")
        search.observe(children[0].node_id, score=0.0, refused=False)

        selected = search.select_frontier()
        self.assertEqual(
            [item.node_id for item in selected[:2]],
            sorted([children[1].node_id, children[2].node_id]),
        )
        self.assertEqual(selected[-1].node_id, children[0].node_id)

    def test_max_depth_terminates_branches(self):
        search = TAPSearch(
            "root",
            branch_factor=2,
            beam_width=2,
            max_depth=1,
            seed=11,
        )
        children = search.expand(search.root.node_id, "objective", "feedback")

        for child in children:
            self.assertEqual(search.expand(child.node_id, "objective", "feedback"), [])

        self.assertEqual(search.frontier, [])
        self.assertEqual(len(search.nodes), 3)

    def test_json_restore_preserves_order_and_future_expansion(self):
        search = TAPSearch(
            "root",
            branch_factor=3,
            beam_width=2,
            max_depth=3,
            seed=41,
        )
        children = search.expand(search.root.node_id, "objective", "first feedback")
        search.observe(children[0].node_id, score=0.4, refused=False)
        search.observe(children[1].node_id, score=0.8, refused=True)
        search.prune()

        payload = json.loads(json.dumps(search.to_dict()))
        restored = TAPSearch.from_dict(payload)

        self.assertEqual(restored.to_dict(), payload)
        self.assertEqual(
            [item.node_id for item in restored.select_frontier()],
            [item.node_id for item in search.select_frontier()],
        )
        original_next = search.expand(search.frontier[0], "objective", "next feedback")
        restored_next = restored.expand(restored.frontier[0], "objective", "next feedback")
        self.assertEqual(
            [item.to_dict() for item in restored_next],
            [item.to_dict() for item in original_next],
        )

    def test_restore_rejects_malformed_state(self):
        search = TAPSearch("root", branch_factor=2, beam_width=2, max_depth=2)
        search.expand(search.root.node_id, "objective", "feedback")
        valid = search.to_dict()

        malformed_states = []

        missing_frontier_node = copy.deepcopy(valid)
        missing_frontier_node["frontier"].append("missing")
        malformed_states.append(missing_frontier_node)

        bad_depth = copy.deepcopy(valid)
        bad_depth["nodes"][1]["depth"] = 2
        malformed_states.append(bad_depth)

        duplicate_id = copy.deepcopy(valid)
        duplicate_id["nodes"].append(copy.deepcopy(duplicate_id["nodes"][0]))
        malformed_states.append(duplicate_id)

        bad_config = copy.deepcopy(valid)
        bad_config["branch_factor"] = 0
        malformed_states.append(bad_config)

        for state in malformed_states:
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    TAPSearch.from_dict(state)


if __name__ == "__main__":
    unittest.main()
