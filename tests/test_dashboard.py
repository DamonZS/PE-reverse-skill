from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import urlopen

from reverse_analyzer.dashboard import _load_records, build_dashboard, serve_dashboard


class DashboardTests(unittest.TestCase):
    def test_empty_workspace_writes_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            data = build_dashboard(workspace)

            self.assertEqual(data["summary"]["experiment_total"], 0)
            self.assertEqual(data["summary"]["session_total"], 0)
            self.assertEqual(data["recommendations"]["dynamic_profile"]["profile"], "quick")
            self.assertTrue((workspace / "dashboard" / "index.html").is_file())
            self.assertTrue((workspace / "dashboard" / "data.json").is_file())

    def test_aggregates_records_and_writes_matching_data_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write(workspace / "experiments" / "older.json", {"name": "older", "status": "queued", "updated_at": "2026-01-01T00:00:00Z"})
            self._write(workspace / "experiments" / "newer.json", {"name": "newer", "status": "completed", "updated_at": "2026-02-01T00:00:00Z"})
            (workspace / "experiments" / "bad.json").write_text("{invalid", encoding="utf-8")
            self._write(workspace / "sessions" / "run.json", {"session_id": "run-1", "status": "completed", "timestamp": "2026-03-01T00:00:00Z"})
            self._write(workspace / ".reverse_analyzer" / "knowledge" / "dynamic_profiles.json", {"profiles": {"deep": {"runs": 3, "success_rate": 1, "avg_events": 10}}})
            self._write(workspace / ".reverse_analyzer" / "knowledge" / "gui_strategies.json", {"strategies": {"wpf:faithful": {"runs": 2, "success_rate": 1, "avg_visual_similarity": .9}}})

            data = build_dashboard(workspace)
            saved = json.loads((workspace / "dashboard" / "data.json").read_text(encoding="utf-8"))

            self.assertEqual(data["summary"], {"experiment_total": 2, "status_counts": {"queued": 1, "completed": 1}, "session_total": 1, "completed_total": 1})
            self.assertEqual(data["experiments"][0]["name"], "newer")
            self.assertEqual(data["recommendations"]["dynamic_profile"]["profile"], "deep")
            self.assertEqual(data["recommendations"]["gui_strategy"]["strategy"], "faithful")
            self.assertEqual(data["diagnostics"]["malformed_json"], 1)
            self.assertEqual(saved, data)

    def test_custom_knowledge_directory_overrides_workspace_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            default_knowledge = workspace / ".reverse_analyzer" / "knowledge"
            custom_knowledge = workspace / "custom-knowledge"
            self._write(default_knowledge / "dynamic_profiles.json", {"profiles": {"default": {"runs": 1, "success_rate": 1}}})
            self._write(default_knowledge / "gui_strategies.json", {"strategies": {"wpf:default": {"runs": 1, "success_rate": 1}}})
            self._write(custom_knowledge / "dynamic_profiles.json", {"profiles": {"custom": {"runs": 2, "success_rate": 1, "avg_events": 4}}})
            self._write(custom_knowledge / "gui_strategies.json", {"strategies": {"winforms:custom": {"runs": 2, "success_rate": 1, "avg_visual_similarity": .9}}})

            data = build_dashboard(workspace, knowledge_dir=custom_knowledge)

            self.assertEqual(data["recommendations"]["dynamic_profile"]["profile"], "custom")
            self.assertEqual(data["recommendations"]["gui_strategy"]["strategy"], "custom")
            self.assertEqual(data["recommendations"]["gui_strategy"]["framework"], "winforms")

    def test_html_escapes_malicious_sample_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write(workspace / "experiments" / "sample.json", {"name": "</script><script>window.injected=true</script>", "status": "queued"})

            build_dashboard(workspace)
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")

            self.assertNotIn("</script><script>window.injected=true", html)
            self.assertIn("\\u003c/script\\u003e", html)
            self.assertIn("textContent", html)

    def test_non_utf8_json_is_reported_and_does_not_block_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            invalid_path = workspace / "experiments" / "non-utf8.json"
            invalid_path.parent.mkdir(parents=True, exist_ok=True)
            invalid_path.write_bytes(b"\xff\xfe{\x00}\x00")

            data = build_dashboard(workspace)

            self.assertEqual(data["summary"]["experiment_total"], 0)
            self.assertEqual(data["diagnostics"]["malformed_json"], 1)
            self.assertTrue((workspace / "dashboard" / "index.html").is_file())
            self.assertTrue((workspace / "dashboard" / "data.json").is_file())

    def test_aggregates_local_runner_sessions_and_deduplicates_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            top_level_sessions = workspace / "sessions"
            local_sessions = workspace / "experiments" / "run-42" / "analysis" / "sessions"
            self._write(top_level_sessions / "top.json", {"session_id": "top", "timestamp": "2026-01-01T00:00:00Z"})
            self._write(local_sessions / "local.json", {"session_id": "local", "timestamp": "2026-02-01T00:00:00Z"})
            (local_sessions / "bad.json").write_text("{invalid", encoding="utf-8")

            data = build_dashboard(workspace)
            diagnostics = {
                "files_scanned": 0,
                "files_loaded": 0,
                "malformed_json": 0,
                "invalid_records": 0,
                "skipped_files": [],
            }
            duplicate_load = _load_records((top_level_sessions, top_level_sessions), diagnostics)

            self.assertEqual(data["summary"]["session_total"], 2)
            self.assertEqual(data["sessions"][0]["session_id"], "local")
            self.assertEqual(data["diagnostics"]["malformed_json"], 1)
            self.assertEqual([item["session_id"] for item in duplicate_load], ["top"])
            self.assertEqual(diagnostics["files_scanned"], 1)

    def test_dashboard_surfaces_source_reconstruction_projects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "experiments" / "run-42" / "analysis" / "reconstructed_fixture"
            self._write(project / "analysis" / "summary.json", {"function_count": 3, "import_count": 2})
            self._write(
                project / "analysis" / "reconstruction_plan.json",
                {"tasks": [{"name": "dynamic_correlation"}, {"name": "network"}]},
            )
            self._write(project / "analysis" / "dynamic_evidence.json", [{"api": "connect"}])
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (project / "src" / "network.c").write_text("void reconstruct_network(void) {}\n", encoding="utf-8")
            (project / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n", encoding="utf-8")
            (project / "README.md").write_text("# Reconstruction\n", encoding="utf-8")

            data = build_dashboard(workspace)
            saved = json.loads((workspace / "dashboard" / "data.json").read_text(encoding="utf-8"))
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")

            source = data["source_reconstruction"]
            self.assertEqual(source["summary"]["project_total"], 1)
            self.assertEqual(source["summary"]["source_file_total"], 2)
            self.assertEqual(source["projects"][0]["name"], "reconstructed_fixture")
            self.assertEqual(source["projects"][0]["function_count"], 3)
            self.assertEqual(source["projects"][0]["dynamic_evidence_count"], 1)
            self.assertIn("src/main.c", [item["path"] for item in source["projects"][0]["source_files"]])
            self.assertEqual(saved["source_reconstruction"], source)
            self.assertIn("Source Reconstruction", html)

    def test_dashboard_server_can_be_created_and_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "index.html").write_text("dashboard", encoding="utf-8")
            server = serve_dashboard(directory)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = server.server_address[:2]
                with urlopen(f"http://{host}:{port}/index.html", timeout=2) as response:
                    self.assertEqual(response.read(), b"dashboard")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
