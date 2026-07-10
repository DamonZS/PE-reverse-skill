import copy
import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.gui_state import build_gui_state_machine


class GuiStateMachineTests(unittest.TestCase):
    def test_derives_a_single_initial_state_from_gui_evidence(self) -> None:
        runtime_tree = {
            "status": "ok",
            "windows": [
                {
                    "title": "Main window",
                    "controls": [{"id": "save"}, {"id": "cancel"}],
                }
            ],
        }
        visual = {
            "status": "ok",
            "screenshots": ["main.png"],
            "widgets": [{"type": "button"}, {"type": "button"}],
        }
        evidence_graph = {
            "status": "ok",
            "nodes": [{"id": "save"}, {"id": "cancel"}],
        }

        result = build_gui_state_machine(
            runtime_tree=runtime_tree,
            visual=visual,
            evidence_graph=evidence_graph,
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["transitions"], [])
        self.assertEqual(len(result["states"]), 1)
        state = result["states"][0]
        self.assertTrue(state["id"].startswith("state_"))
        self.assertEqual(state["title"], "Main window")
        self.assertEqual(state["control_count"], 2)
        self.assertEqual(state["screenshots"], ["main.png"])
        self.assertTrue(state["evidence"])
        self.assertGreater(state["confidence"], 0.0)

    def test_normalizes_a_click_and_creates_a_transition(self) -> None:
        result = build_gui_state_machine(
            interaction_trace=[
                {
                    "action": {"type": "Click", "text": "Save"},
                    "control_id": "save_button",
                    "before": {
                        "title": "Editor",
                        "runtime_tree": {
                            "windows": [{"controls": [{"id": "save_button"}]}],
                        },
                        "screenshot": "editor.png",
                    },
                    "after": {
                        "title": "Saved",
                        "runtime_tree": {
                            "windows": [{"controls": [{"id": "save_button"}, {"id": "status"}]}],
                        },
                        "screenshot": "saved.png",
                    },
                }
            ]
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["states"]), 2)
        self.assertEqual(len(result["actions"]), 1)
        action = result["actions"][0]
        self.assertEqual(action["type"], "click")
        self.assertEqual(action["control_id"], "save_button")
        self.assertEqual(action["text"], "Save")
        self.assertEqual(len(result["transitions"]), 1)
        transition = result["transitions"][0]
        self.assertNotEqual(transition["from"], transition["to"])
        self.assertEqual(transition["source"], transition["from"])
        self.assertEqual(transition["target"], transition["to"])
        self.assertEqual(transition["action"], action)
        self.assertEqual(transition["action_id"], action["id"])

    def test_deduplicates_repeated_transitions(self) -> None:
        before = {"title": "Editor", "screenshot": "editor.png"}
        after = {"title": "Saved", "screenshot": "saved.png"}
        result = build_gui_state_machine(
            interaction_trace=[
                {"action": "click", "control_id": "save", "before": before, "after": after},
                {"control_id": "save", "after": dict(after), "before": dict(before), "action": "click"},
            ]
        )

        self.assertEqual(len(result["states"]), 2)
        self.assertEqual(len(result["actions"]), 1)
        self.assertEqual(len(result["transitions"]), 1)
        self.assertEqual(result["summary"]["transition_count"], 1)

    def test_accepts_trace_object_with_steps(self) -> None:
        result = build_gui_state_machine(
            interaction_trace={
                "steps": [
                    {
                        "event": "keypress",
                        "control_id": "search",
                        "from_state": "search-empty",
                        "to_state": "search-results",
                        "text": "needle",
                    }
                ]
            }
        )

        self.assertEqual(result["summary"]["input"]["interaction_trace"]["format"], "object")
        self.assertEqual(result["summary"]["input"]["interaction_trace"]["step_key"], "steps")
        self.assertEqual(result["summary"]["trace_step_count"], 1)
        self.assertEqual(result["actions"][0]["type"], "keypress")
        self.assertEqual(len(result["states"]), 2)
        self.assertEqual(len(result["transitions"]), 1)

    def test_interactions_alias_preserves_explicit_state_ids_and_trace(self) -> None:
        trace = {
            "version": 1,
            "initial_state": "editing",
            "interactions": [
                {
                    "event": "Click",
                    "control": {"id": "saveButton"},
                    "action": {"id": "SaveButton_Click"},
                    "from_state": "editing",
                    "to_state": "saved",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = build_gui_state_machine(interaction_trace=trace, out_dir=tmp)
            transition = result["transitions"][0]
            trace_json = json.loads((Path(tmp) / "gui" / "interaction_trace.json").read_text(encoding="utf-8"))

        self.assertEqual({state["id"] for state in result["states"]}, {"editing", "saved"})
        self.assertEqual(result["summary"]["initial_state_id"], "editing")
        self.assertEqual(result["actions"][0]["type"], "click")
        self.assertEqual(result["actions"][0]["control_id"], "saveButton")
        self.assertEqual(transition["source"], "editing")
        self.assertEqual(transition["target"], "saved")
        self.assertEqual(trace_json["interactions"], trace["interactions"])
        self.assertEqual(trace_json["normalized"]["transitions"][0]["source"], "editing")

    def test_trace_step_limit_bounds_processing_and_persisted_trace(self) -> None:
        trace = {
            "steps": [
                {
                    "event": "Click",
                    "control": {"id": f"button-{index}"},
                    "from_state": "editing",
                    "to_state": "editing",
                }
                for index in range(1001)
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = build_gui_state_machine(interaction_trace=trace, out_dir=tmp)
            trace_json = json.loads((Path(tmp) / "gui" / "interaction_trace.json").read_text(encoding="utf-8"))

        trace_summary = result["summary"]["input"]["interaction_trace"]
        self.assertTrue(trace_summary["truncated"])
        self.assertEqual(trace_summary["raw_step_count"], 1001)
        self.assertEqual(result["summary"]["trace_step_count"], 1000)
        self.assertEqual(len(trace_json["steps"]), 1000)
        self.assertTrue(trace_json["normalized"]["summary"]["trace_truncated"])

    def test_interactions_alias_is_bounded_in_persisted_trace(self) -> None:
        trace = {
            "interactions": [
                {
                    "event": "Click",
                    "control": {"id": f"button-{index}"},
                    "from_state": "editing",
                    "to_state": "editing",
                }
                for index in range(1001)
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = build_gui_state_machine(interaction_trace=trace, out_dir=tmp)
            trace_json = json.loads((Path(tmp) / "gui" / "interaction_trace.json").read_text(encoding="utf-8"))

        self.assertTrue(result["summary"]["input"]["interaction_trace"]["truncated"])
        self.assertEqual(len(trace_json["interactions"]), 1000)
        self.assertTrue(trace_json["normalized"]["summary"]["trace_truncated"])

    def test_no_input_is_gracefully_unavailable(self) -> None:
        result = build_gui_state_machine()

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["states"], [])
        self.assertEqual(result["actions"], [])
        self.assertEqual(result["transitions"], [])
        self.assertEqual(result["summary"]["input"]["interaction_trace"]["format"], "none")

    def test_writes_artifacts_is_deterministic_and_does_not_mutate_inputs(self) -> None:
        runtime_tree = {
            "windows": [
                {
                    "controls": [{"id": "open"}],
                    "title": "Main",
                }
            ],
            "status": "ok",
        }
        reordered_runtime_tree = {
            "status": "ok",
            "windows": [
                {
                    "title": "Main",
                    "controls": [{"id": "open"}],
                }
            ],
        }
        visual = {"screenshots": ["main.png"], "widgets": [{"id": "open"}]}
        before = copy.deepcopy(runtime_tree)

        first = build_gui_state_machine(runtime_tree=runtime_tree, visual=visual)
        second = build_gui_state_machine(runtime_tree=reordered_runtime_tree, visual=copy.deepcopy(visual))

        self.assertEqual(first, second)
        self.assertEqual(runtime_tree, before)

        with tempfile.TemporaryDirectory() as tmp:
            result = build_gui_state_machine(
                runtime_tree=runtime_tree,
                visual=visual,
                out_dir=tmp,
            )
            gui_dir = Path(tmp) / "gui"
            state_path = gui_dir / "state_machine.json"
            trace_path = gui_dir / "interaction_trace.json"

            self.assertTrue(state_path.is_file())
            self.assertTrue(trace_path.is_file())
            self.assertEqual(len(result["artifacts"]), 2)
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), result)
            trace = json.loads(trace_path.read_text(encoding="utf-8"))
            self.assertEqual(trace["normalized"]["summary"]["trace_step_count"], 0)
            self.assertEqual(trace["normalized"]["transitions"], [])


if __name__ == "__main__":
    unittest.main()
