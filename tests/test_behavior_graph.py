"""Contract tests for the unified behavior evidence graph."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

try:
    from reverse_analyzer.tools.behavior_graph import build_behavior_evidence_graph
except ModuleNotFoundError as exc:
    if exc.name != "reverse_analyzer.tools.behavior_graph":
        raise
    build_behavior_evidence_graph = None


class BehaviorEvidenceGraphTests(unittest.TestCase):
    def _build(self, **kwargs: Any) -> dict[str, Any]:
        self.assertIsNotNone(
            build_behavior_evidence_graph,
            "behavior graph builder must be available from reverse_analyzer.tools.behavior_graph",
        )
        assert build_behavior_evidence_graph is not None
        return build_behavior_evidence_graph(**kwargs)

    def test_links_all_supported_evidence_sources(self) -> None:
        sources = {
            "fingerprint": {"status": "ok", "platform": "windows-pe"},
            "decompiler": {
                "status": "ok",
                "functions": [
                    {"name": "Save_Click", "address": "0x401000", "confidence": 0.96},
                ],
            },
            "dynamic_analysis": {
                "status": "ok",
                "api_counts": {"CreateFileW": 3},
                "sample_events": [
                    {
                        "id": "event-1",
                        "api": "CreateFileW",
                        "timestamp": 1.25,
                        "pid": 42,
                        "confidence": 0.88,
                    }
                ],
            },
            "gui_analysis": {
                "status": "ok",
                "evidence_graph": {
                    "nodes": [
                        {
                            "id": "save-button",
                            "type": "Button",
                            "text": "Save",
                            "event_handlers": {"Click": "Save_Click"},
                            "confidence": 0.91,
                        }
                    ]
                },
            },
            "resources": {
                "status": "ok",
                "entries": [{"path": "ui/MainWindow.xaml", "kind": "layout"}],
                "extracted_files": [{"path": "assets/icon.ico", "kind": "icon"}],
            },
            "state_machine": {
                "status": "ok",
                "states": [
                    {"id": "idle", "name": "Idle"},
                    {"id": "saved", "name": "Saved"},
                ],
                "actions": [{"id": "save", "name": "Save"}],
                "transitions": [{"from": "Idle", "action": "Save", "to": "Saved"}],
            },
        }
        original = copy.deepcopy(sources)

        graph = self._build(**sources)

        self.assertEqual(graph["status"], "ok")
        self.assertEqual(graph["version"], 1)
        self.assertEqual(sources, original)
        self.assertEqual(graph["summary"]["linked_handler_count"], 1)
        self.assertEqual(graph["summary"]["dynamic_event_count"], 1)
        self.assertEqual(graph["summary"]["state_count"], 2)
        self.assertEqual(graph["summary"]["transition_count"], 1)
        self.assertEqual(graph["summary"]["type_counts"]["resource"], 2)

        nodes_by_id = {node["id"]: node for node in graph["nodes"]}
        node_types = {node["type"] for node in graph["nodes"]}
        self.assertTrue(
            {
                "function",
                "api",
                "dynamic_event",
                "ui_control",
                "ui_handler",
                "resource",
                "ui_state",
                "ui_action",
            }.issubset(node_types)
        )
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "ui_handler"
                and nodes_by_id[edge["target"]]["type"] == "function"
                for edge in graph["edges"]
            )
        )
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "dynamic_event"
                and nodes_by_id[edge["target"]]["type"] == "api"
                for edge in graph["edges"]
            )
        )
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "ui_control"
                and nodes_by_id[edge["target"]]["type"] == "ui_handler"
                for edge in graph["edges"]
            )
        )
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "ui_state"
                and nodes_by_id[edge["target"]]["type"] == "ui_action"
                for edge in graph["edges"]
            )
        )
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "ui_action"
                and nodes_by_id[edge["target"]]["type"] == "ui_state"
                for edge in graph["edges"]
            )
        )

        for node in graph["nodes"]:
            self.assertIsInstance(node["source"], str)
            self.assertTrue(node["evidence"])
            self.assertIsInstance(node["confidence"], float)
        for edge in graph["edges"]:
            self.assertIn(edge["source"], nodes_by_id)
            self.assertIn(edge["target"], nodes_by_id)
            self.assertTrue(edge["evidence"])
            self.assertIsInstance(edge["confidence"], float)

    def test_keeps_same_named_distinct_objects_separate(self) -> None:
        graph = self._build(
            decompiler={
                "functions": [
                    {"name": "Duplicate", "address": "0x401000"},
                    {"name": "Duplicate", "address": "0x402000"},
                ]
            },
            gui_analysis={
                "evidence_graph": {
                    "nodes": [
                        {
                            "id": "saveButton",
                            "type": "Button",
                            "text": "Save",
                            "source_path": "first/MainWindow.xaml",
                        },
                        {
                            "id": "saveButton",
                            "type": "Button",
                            "text": "Save",
                            "source_path": "second/MainWindow.xaml",
                        },
                    ]
                }
            },
        )

        functions = [node for node in graph["nodes"] if node["type"] == "function"]
        controls = [node for node in graph["nodes"] if node["type"] == "ui_control"]
        self.assertEqual(len(functions), 2)
        self.assertEqual(len(controls), 2)
        self.assertEqual({node["name"] for node in functions}, {"Duplicate"})
        self.assertEqual({node["name"] for node in controls}, {"saveButton"})
        self.assertEqual(len({node["id"] for node in functions}), 2)
        self.assertEqual(len({node["id"] for node in controls}), 2)

    def test_handles_empty_and_unavailable_sources_gracefully(self) -> None:
        graph = self._build(
            fingerprint={"status": "unavailable"},
            decompiler={"status": "unavailable", "functions": None},
            dynamic_analysis={"status": "unavailable", "api_counts": None, "sample_events": None},
            gui_analysis={"status": "unavailable", "evidence_graph": {"nodes": None}},
            resources={"status": "unavailable", "entries": None, "extracted_files": None},
            state_machine={"status": "unavailable", "states": None, "transitions": None},
        )

        self.assertEqual(graph["status"], "unavailable")
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["summary"]["node_count"], 0)
        self.assertEqual(graph["summary"]["edge_count"], 0)
        self.assertEqual(graph["summary"]["dynamic_event_count"], 0)
        self.assertEqual(graph["summary"]["state_count"], 0)
        self.assertEqual(graph["summary"]["transition_count"], 0)

        empty = self._build()
        self.assertEqual(empty["status"], "ok")
        self.assertEqual(empty["nodes"], [])
        self.assertEqual(empty["edges"], [])

    def test_models_cli_control_action_state_transition(self) -> None:
        graph = self._build(
            gui_analysis={
                "evidence_graph": {
                    "nodes": [{"id": "saveButton", "type": "Button", "text": "Save"}]
                }
            },
            state_machine={
                "states": [{"id": "editing"}, {"id": "saved"}],
                "actions": [{"id": "SaveButton_Click"}],
                "transitions": [
                    {
                        "source": "editing",
                        "target": "saved",
                        "control_id": "saveButton",
                        "action": "SaveButton_Click",
                    }
                ],
            },
        )

        nodes_by_id = {node["id"]: node for node in graph["nodes"]}
        controls = [node for node in graph["nodes"] if node["type"] == "ui_control"]
        states = [node for node in graph["nodes"] if node["type"] == "ui_state"]
        actions = [node for node in graph["nodes"] if node["type"] == "ui_action"]
        self.assertEqual({node["name"] for node in controls}, {"saveButton"})
        self.assertEqual({node["name"] for node in states}, {"editing", "saved"})
        self.assertEqual({node["name"] for node in actions}, {"SaveButton_Click"})
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "ui_action"
                and nodes_by_id[edge["source"]]["name"] == "SaveButton_Click"
                and nodes_by_id[edge["target"]]["type"] == "ui_state"
                and nodes_by_id[edge["target"]]["name"] == "saved"
                for edge in graph["edges"]
            )
        )
        self.assertTrue(
            all(edge["source"] in nodes_by_id and edge["target"] in nodes_by_id for edge in graph["edges"])
        )

    def test_accepts_transition_records_from_actions_when_transitions_are_absent(self) -> None:
        graph = self._build(
            gui_analysis={"evidence_graph": {"nodes": [{"id": "saveButton", "type": "Button"}]}},
            state_machine={
                "states": [{"id": "editing"}, {"id": "saved"}],
                "actions": [
                    {
                        "source": "editing",
                        "target": "saved",
                        "control_id": "saveButton",
                        "action": "SaveButton_Click",
                    }
                ],
            },
        )

        nodes_by_id = {node["id"]: node for node in graph["nodes"]}
        self.assertEqual(graph["summary"]["transition_count"], 1)
        self.assertTrue(
            any(
                nodes_by_id[edge["source"]]["type"] == "ui_action"
                and nodes_by_id[edge["target"]]["type"] == "ui_state"
                and nodes_by_id[edge["target"]]["name"] == "saved"
                for edge in graph["edges"]
            )
        )

    def test_writes_deterministic_json_safe_artifact(self) -> None:
        sources = {
            "decompiler": {"functions": [{"name": "Run", "address": "0x401000"}]},
            "dynamic_analysis": {
                "api_counts": {"Sleep": 1},
                "sample_events": [{"api": "Sleep", "arguments": {"milliseconds": 10}}],
            },
        }
        before = copy.deepcopy(sources)

        first = self._build(**sources)
        second = self._build(**sources)
        self.assertEqual(first, second)
        self.assertEqual(sources, before)
        json.dumps(first, ensure_ascii=False, sort_keys=True)

        with tempfile.TemporaryDirectory() as tmp:
            written = self._build(**sources, out_dir=tmp)
            artifact = Path(tmp) / "analysis_graph.json"
            self.assertTrue(artifact.is_file())
            self.assertEqual(written["artifacts"][0]["path"], str(artifact))
            self.assertEqual(written["artifacts"][0]["name"], "analysis_graph.json")
            on_disk = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(on_disk["nodes"], written["nodes"])
            self.assertEqual(on_disk["edges"], written["edges"])
            self.assertEqual(on_disk["summary"], written["summary"])


if __name__ == "__main__":
    unittest.main()
