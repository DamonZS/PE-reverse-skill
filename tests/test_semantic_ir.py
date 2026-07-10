import copy
import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.semantic_ir import build_semantic_ir


class SemanticIrTests(unittest.TestCase):
    def test_graph_input_fuses_supported_entities_relations_and_capabilities(self):
        behavior_graph = {
            "status": "ok",
            "nodes": [
                {
                    "id": "fn-entry",
                    "type": "function",
                    "name": "entry",
                    "confidence": 0.9,
                    "source": "decompiler.functions",
                    "attributes": {"address": "00401000"},
                },
                {
                    "id": "api-winhttp",
                    "type": "api",
                    "name": "WinHttpOpen",
                    "confidence": 0.8,
                    "evidence": [{"source": "dynamic_analysis.api_counts"}],
                    "attributes": {"library": "WINHTTP.dll"},
                },
                {
                    "id": "event-connect",
                    "type": "dynamic_event",
                    "name": "connect",
                    "confidence": 0.75,
                    "source": "dynamic_analysis.events",
                    "attributes": {"api": "connect"},
                },
                {"id": "control-connect", "type": "ui_control", "name": "ConnectButton"},
                {"id": "handler-connect", "type": "ui_handler", "name": "Connect_Click"},
                {"id": "state-idle", "type": "ui_state", "name": "Idle"},
                {"id": "action-connect", "type": "ui_action", "name": "Connect"},
                {"id": "resource-main", "type": "resource", "name": "MainWindow.xaml"},
            ],
            "edges": [
                {
                    "id": "edge-call",
                    "type": "calls",
                    "source": "fn-entry",
                    "target": "api-winhttp",
                    "confidence": 0.8,
                    "evidence": [{"source": "decompiler.call_graph"}],
                },
                {
                    "id": "edge-event-api",
                    "type": "dynamic_event_to_api",
                    "source": "event-connect",
                    "target": "api-winhttp",
                    "confidence": 0.75,
                },
                {
                    "id": "edge-control-handler",
                    "type": "ui_control_to_handler",
                    "source": "control-connect",
                    "target": "handler-connect",
                },
            ],
        }

        result = build_semantic_ir(behavior_graph=behavior_graph)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["summary"]["function_count"], 1)
        self.assertEqual(result["summary"]["api_count"], 1)
        self.assertEqual(result["summary"]["dynamic_event_count"], 1)
        self.assertEqual(result["summary"]["ui_control_count"], 1)
        self.assertEqual(result["summary"]["ui_state_count"], 1)

        entities_by_name = {item["name"]: item for item in result["entities"]}
        self.assertEqual(entities_by_name["entry"]["kind"], "function")
        self.assertIn("decompiler.functions", entities_by_name["entry"]["sources"])
        self.assertEqual(entities_by_name["WinHttpOpen"]["kind"], "api")

        entity_ids = {item["id"] for item in result["entities"]}
        self.assertTrue(all(item["source"] in entity_ids for item in result["relations"]))
        self.assertTrue(all(item["target"] in entity_ids for item in result["relations"]))
        self.assertTrue(any(item["type"] == "calls" for item in result["relations"]))

        network_capabilities = [item for item in result["capabilities"] if item["category"] == "network"]
        self.assertTrue(network_capabilities)
        self.assertIn(entities_by_name["WinHttpOpen"]["id"], network_capabilities[0]["entity_ids"])
        json.dumps(result, ensure_ascii=False, sort_keys=True)

    def test_fallback_is_deterministic_preserves_inputs_and_writes_artifact(self):
        decompiler = {
            "status": "ok",
            "functions": [
                {"name": "helper", "address": "00402000"},
                {"name": "entry", "address": "00401000", "calls": [{"name": "helper"}]},
            ],
            "imports": [
                {
                    "dll": "KERNEL32.dll",
                    "functions": [{"name": "CreateFileW", "attributes": {"marker": "keep"}}],
                },
            ],
            "call_graph": {"edges": [{"source": "entry", "target": "helper"}]},
        }
        dynamic_analysis = {
            "status": "ok",
            "api_counts": {"CreateFileW": 2},
            "events": [{"api": "CreateFileW", "operation": "CreateFileW", "count": 2}],
        }
        gui_analysis = {
            "status": "ok",
            "evidence_graph": {
                "nodes": [
                    {
                        "id": "ConnectButton",
                        "name": "ConnectButton",
                        "event_handlers": {"Click": "Connect_Click"},
                    }
                ]
            },
            "state_machine": {
                "states": [{"name": "Idle"}, {"name": "Connected"}],
                "actions": [{"name": "Connect"}],
                "transitions": [{"from": "Idle", "action": "Connect", "to": "Connected"}],
            },
        }
        source_snapshot = copy.deepcopy((decompiler, dynamic_analysis, gui_analysis))

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "analysis"
            first = build_semantic_ir(
                decompiler=decompiler,
                dynamic_analysis=dynamic_analysis,
                gui_analysis=gui_analysis,
                out_dir=out_dir,
            )
            reordered = copy.deepcopy((decompiler, dynamic_analysis, gui_analysis))
            reordered[0]["functions"].reverse()
            reordered[2]["state_machine"]["states"].reverse()
            second = build_semantic_ir(
                decompiler=reordered[0],
                dynamic_analysis=reordered[1],
                gui_analysis=reordered[2],
                out_dir=out_dir,
            )

            artifact = out_dir / "semantic_ir.json"
            self.assertEqual(first, second)
            self.assertEqual((decompiler, dynamic_analysis, gui_analysis), source_snapshot)
            self.assertTrue(artifact.is_file())
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8")), first)
            self.assertEqual(first["artifacts"][0]["name"], "semantic_ir.json")
            self.assertIn("CreateFileW", {item["name"] for item in first["entities"]})
            self.assertTrue(any(item["category"] == "file" for item in first["capabilities"]))

        malformed = build_semantic_ir(
            behavior_graph={"nodes": "not-a-list", "edges": 42},
            decompiler={"functions": {"entry": {"address": "00401000"}}, "imports": "bad"},
            dynamic_analysis={"events": {"CreateFileW": 1}},
        )
        self.assertIsInstance(malformed["entities"], list)
        self.assertIsInstance(malformed["relations"], list)
        json.dumps(malformed, ensure_ascii=False, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
