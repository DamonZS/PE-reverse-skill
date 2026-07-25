from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.knowledge.reconstruction_graph import build_reconstruction_graph


class ReconstructionGraphTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        project = root / "project"
        app = project / "targets/app"
        app.mkdir(parents=True)
        (app / "CMakeLists.txt").write_text("add_executable(app native.c)\n", encoding="utf-8")
        (app / "logic.py").write_text(
            "import json\nclass Child(Base):\n    def run(self):\n        return helper() + cross_service()\ndef helper():\n    return 1\n",
            encoding="utf-8",
        )
        (app / "native.c").write_text(
            '#include "native.h"\nJNIEXPORT int bridge(void) { return helper(); }\n'
            'int ipc(void) { return socket(0, 0, 0); }\n', encoding="utf-8",
        )
        (app / "interop.cs").write_text(
            'using System.Runtime.InteropServices;\nclass Native { [DllImport("demo.dll")] static extern int demo(); }\n',
            encoding="utf-8",
        )
        (app / "config.json").write_text(json.dumps({"view": "ui/layout.xml"}), encoding="utf-8")
        (app / "capability-plan.json").write_text(json.dumps({
            "target": "bin/app.exe",
            "target_evidence": {"size": 128, "sha256": "a" * 64},
            "stages": [{
                "capability": "pe-static-decompile-gui-reconstruction",
                "provider": "ToolExecutor:analyze",
                "status": "completed",
                "return_code": 0,
                "artifact_evidence": [{"path": "report.json", "type": "file", "size": 42, "sha256": "b" * 64}],
            }],
        }), encoding="utf-8")
        (app / "ui").mkdir()
        (app / "ui/layout.xml").write_text("<view />", encoding="utf-8")
        shared = project / "targets/shared"
        shared.mkdir(parents=True)
        (shared / "cross.py").write_text("def cross_service():\n    return 2\n", encoding="utf-8")
        return project

    def test_builds_stable_evidence_backed_cross_language_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._fixture(Path(temporary))
            first = build_reconstruction_graph(project)
            second = build_reconstruction_graph(project)
            payload = first.to_dict()
            self.assertEqual(payload, second.to_dict())
            self.assertTrue({"Module", "File", "Function", "Class", "Resource", "BuildTarget", "ToolStage", "EvidenceArtifact"}.issubset(
                {node["type"] for node in payload["nodes"]}
            ))
            edge_types = {edge["type"] for edge in payload["edges"]}
            self.assertTrue({"contains", "imports", "calls", "inherits", "resource_reference", "builds", "JNI", "PInvoke", "IPC", "analyzed_by", "produced"}.issubset(edge_types))
            artifact = next(node for node in payload["nodes"] if node["type"] == "EvidenceArtifact")
            self.assertEqual(artifact["sha256"], "b" * 64)
            self.assertTrue(all(edge["evidence"].get("parser") and edge["evidence"].get("path") for edge in payload["edges"]))
            app_context = first.module_context("app")
            cross_nodes = [node for node in app_context["nodes"] if node["name"] == "cross_service"]
            self.assertEqual(len(cross_nodes), 1)
            self.assertEqual(cross_nodes[0]["module_id"], "shared")
            self.assertEqual(len(payload["fingerprint"]), 64)

    def test_writes_artifact_and_returns_bounded_module_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            graph = build_reconstruction_graph(self._fixture(root))
            artifact = graph.write_artifact(root / "artifacts/reconstruction-graph.json")
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8"))["schema_version"], "reconstruction-graph/v1")
            context = graph.module_context("app", max_nodes=7, max_edges=8)
            self.assertLessEqual(len(context["nodes"]), 7)
            self.assertLessEqual(len(context["edges"]), 8)
            self.assertTrue(context["truncated"])
            self.assertEqual(context["module_id"], "app")
            with self.assertRaises(KeyError):
                graph.module_context("missing")


if __name__ == "__main__":
    unittest.main()
