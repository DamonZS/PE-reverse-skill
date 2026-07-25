from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import base64
import os
from unittest import mock

from reverse_analyzer.config import AnalyzerConfig
from reverse_analyzer.knowledge import KnowledgeBase
from reverse_analyzer.web_api import (
    _delete_knowledge,
    _read_artifact,
    _save_upload,
    _upsert_knowledge,
    build_environment_payload,
    build_workspace_payload,
    create_experiment_plan,
    serve_web_console,
)


class WebApiTests(unittest.TestCase):
    def _config(self, root: Path) -> AnalyzerConfig:
        return AnalyzerConfig(
            workspace=root,
            knowledge_dir=root / ".reverse_analyzer" / "knowledge",
            sessions_dir=root / ".reverse_analyzer" / "sessions",
            reports_dir=root / "reports",
            dashboard_port=8088,
        )

    def test_workspace_payload_reads_real_stores(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._config(root)
            docs = root / "docs"
            docs.mkdir()
            (docs / "skill_parity_matrix.md").write_text(
                "| capability | status | modules | gap | owner | risk | deps | phase | acceptance |\n"
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
                "| pe_static | done | a.py | none | core | low | none | 1 | test |\n"
                "| source | partial | b.py | runtime | core | medium | ghidra | 2 | test |\n",
                encoding="utf-8",
            )
            KnowledgeBase(config.knowledge_dir).add_document(
                "evidence-backed source note",
                title="source note",
                document_type="guide",
            )

            payload = build_workspace_payload(config)

            self.assertEqual(payload["mode"], "connected")
            self.assertEqual(payload["summary"]["capability_total"], 2)
            self.assertEqual(payload["summary"]["capability_done"], 1)
            self.assertEqual(payload["summary"]["knowledge_total"], 1)
            self.assertEqual(payload["experiments"], [])

    def test_create_experiment_plan_never_executes_target(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._config(root)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ")

            result = create_experiment_plan(
                config,
                {"target": "sample.bin", "mode": "pe-reconstruction"},
            )

            self.assertFalse(result["executed"])
            self.assertEqual(result["experiment"]["status"], "queued")
            self.assertTrue(result["experiment"]["options"]["reconstruct"])
            records = list((root / "experiments").glob("*.json"))
            self.assertEqual(len(records), 1)
            stored = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(stored["status"], "queued")

    def test_create_experiment_rejects_path_outside_workspace(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "sample.bin"
            external.write_bytes(b"MZ")
            with self.assertRaisesRegex(ValueError, "inside the configured workspace"):
                create_experiment_plan(
                    self._config(root),
                    {"target": str(external), "mode": "evidence-first"},
                )

    def test_upload_decodes_content_inside_workspace(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            result = _save_upload(
                self._config(root),
                {"filename": "../evil.exe", "content_base64": base64.b64encode(b"MZ").decode("ascii")},
            )

            uploaded = root / result["path"]
            self.assertTrue(uploaded.is_file())
            self.assertEqual(uploaded.read_bytes(), b"MZ")
            self.assertIn("evil.exe", result["filename"])

    def test_read_artifact_rejects_outside_workspace(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "artifact.json"
            external.write_text("{}", encoding="utf-8")

            with self.assertRaises(ValueError):
                _read_artifact(self._config(root), str(external))

    def test_knowledge_upsert_and_delete(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._config(root)

            record = _upsert_knowledge(
                config,
                {"title": "还原经验", "content": "先固定证据再生成源码", "type": "guide", "tags": ["source"]},
            )

            self.assertEqual(record["title"], "还原经验")
            self.assertTrue(_delete_knowledge(config, record["id"]))
            self.assertFalse(_delete_knowledge(config, record["id"]))

    def test_environment_payload_exposes_toolchain_and_acceptance_without_live_run(self) -> None:
        payload = build_environment_payload(execute_probes=False)

        self.assertFalse(payload["execute_probes"])
        self.assertIn("summary", payload)
        self.assertIn("workflows", payload)
        self.assertIn("acceptance_fixtures", payload)
        self.assertTrue(payload["acceptance_fixtures"])
        self.assertIn("live_verified", payload["acceptance_fixtures"][0])

    def test_python_web_backend_is_retired(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            frontend = root / "dist"
            frontend.mkdir()
            (frontend / "index.html").write_text("<html>ok</html>", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Go control plane"):
                serve_web_console(
                    workspace=root,
                    frontend_dir=frontend,
                    host="127.0.0.1",
                    port=0,
                )


if __name__ == "__main__":
    unittest.main()
