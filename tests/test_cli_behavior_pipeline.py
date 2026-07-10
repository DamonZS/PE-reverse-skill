import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]

WPF_XAML = """<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Behavior Evidence Fixture">
  <Grid>
    <TextBox x:Name="nameBox" />
    <Button x:Name="saveButton" Content="Save" Click="SaveButton_Click" />
  </Grid>
</Window>"""


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _records(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return list(value.values())
    return list(value) if isinstance(value, list) else []


def _node_type(node: Any) -> str:
    if not isinstance(node, Mapping):
        return ""
    return str(node.get("type") or node.get("kind") or node.get("node_type") or "")


def _node_id(node: Any) -> str:
    if not isinstance(node, Mapping):
        return ""
    return str(node.get("id") or node.get("key") or node.get("name") or "")


def _edge_endpoint(edge: Any, direction: str) -> str:
    if not isinstance(edge, Mapping):
        return ""
    keys = ("source", "from", "from_id", "from_state") if direction == "source" else (
        "target",
        "to",
        "to_id",
        "to_state",
    )
    for key in keys:
        value = edge.get(key)
        if isinstance(value, Mapping):
            value = value.get("id") or value.get("key") or value.get("name")
        if value is not None:
            return str(value)
    return ""


def _behavior_graph(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    nested = payload.get("behavior_graph")
    return nested if isinstance(nested, Mapping) else payload


class CliBehaviorPipelineTests(unittest.TestCase):
    def test_gui_interaction_trace_produces_behavior_graph_and_state_machine_artifacts(self) -> None:
        """The static WPF path must work without runtime GUI, OCR, or Frida tooling."""
        interaction_trace = {
            "version": 1,
            "initial_state": "editing",
            "steps": [
                {
                    "sequence": 1,
                    "event": "Click",
                    "control": {"id": "saveButton", "type": "Button", "text": "Save"},
                    "action": {"id": "SaveButton_Click", "type": "handler"},
                    "from_state": "editing",
                    "to_state": "saved",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "behavior-fixture.exe"
            trace_path = root / "interaction-trace.json"
            out_dir = root / "analysis"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("Views/MainWindow.xaml", WPF_XAML)
            trace_path.write_text(json.dumps(interaction_trace), encoding="utf-8")

            result = run_cli(
                "analyze",
                str(sample),
                "--out",
                str(out_dir),
                "--max-iterations",
                "1",
                "--gui-interaction-trace",
                str(trace_path),
            )

            self.assertEqual(result.returncode, 0, result.stderr)

            analysis_graph_path = out_dir / "analysis_graph.json"
            state_machine_path = out_dir / "gui" / "state_machine.json"
            persisted_trace_path = out_dir / "gui" / "interaction_trace.json"
            for artifact in (analysis_graph_path, state_machine_path, persisted_trace_path):
                self.assertTrue(artifact.is_file(), f"missing expected artifact: {artifact}")

            report = _read_json(out_dir / "report.json")
            self.assertIn("behavior_graph", report)
            self.assertIn("gui_analysis", report)
            self.assertIn("state_machine", report["gui_analysis"])

            graph = _behavior_graph(_read_json(analysis_graph_path))
            report_graph = _behavior_graph(report["behavior_graph"])
            graph_nodes = _records(graph.get("nodes"))
            graph_edges = _records(graph.get("edges"))
            self.assertTrue(graph_nodes, graph)
            self.assertTrue(graph_edges, graph)
            self.assertTrue(
                {"ui_control", "ui_state", "ui_action"}.issubset({_node_type(node) for node in graph_nodes}),
                graph,
            )
            node_ids = {_node_id(node) for node in graph_nodes if _node_id(node)}
            self.assertTrue(
                any(
                    _edge_endpoint(edge, "source") in node_ids
                    and _edge_endpoint(edge, "target") in node_ids
                    for edge in graph_edges
                ),
                graph_edges,
            )
            self.assertEqual(report_graph.get("nodes"), graph.get("nodes"))
            self.assertEqual(report_graph.get("edges"), graph.get("edges"))

            state_machine = _read_json(state_machine_path)
            report_state_machine = report["gui_analysis"]["state_machine"]
            states = _records(state_machine.get("states"))
            transitions = _records(state_machine.get("transitions"))
            state_ids = {_node_id(state) if isinstance(state, Mapping) else str(state) for state in states}
            self.assertTrue({"editing", "saved"}.issubset(state_ids), state_machine)
            self.assertTrue(
                any(
                    _edge_endpoint(transition, "source") == "editing"
                    and _edge_endpoint(transition, "target") == "saved"
                    for transition in transitions
                ),
                state_machine,
            )
            self.assertEqual(report_state_machine.get("states"), state_machine.get("states"))
            self.assertEqual(report_state_machine.get("transitions"), state_machine.get("transitions"))

            persisted_trace = _read_json(persisted_trace_path)
            self.assertEqual(persisted_trace["initial_state"], "editing")
            self.assertEqual(persisted_trace["steps"][0]["control"]["id"], "saveButton")
            self.assertEqual(persisted_trace["steps"][0]["to_state"], "saved")

if __name__ == "__main__":
    unittest.main()
