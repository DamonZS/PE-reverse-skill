from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import urlopen

from reverse_analyzer.dashboard import _load_records, build_dashboard, serve_dashboard
from reverse_analyzer.evidence import build_manifest, write_manifest


class DashboardTests(unittest.TestCase):
    def test_empty_workspace_writes_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            data = build_dashboard(workspace)

            self.assertEqual(data["summary"]["experiment_total"], 0)
            self.assertEqual(data["summary"]["session_total"], 0)
            self.assertEqual(data["binary_patches"], {"count": 0, "dry_run_count": 0, "applied_count": 0, "recent": []})
            self.assertEqual(
                data["evidence_manifests"],
                {"count": 0, "valid_count": 0, "failed_count": 0, "covered_file_count": 0, "verified_file_count": 0, "recent": []},
            )
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

    def test_binary_patch_audit_aggregates_manifest_and_rollback_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            artifacts = workspace / "sessions" / "run-42" / "output" / "sample.exe.patch-artifacts"
            source_hash = "a" * 64
            patched_hash = "b" * 64
            manifest = {
                "status": "ok",
                "schema_version": 1,
                "source_path": "C:/samples/source.exe",
                "patched_path": "C:/output/patched.exe",
                "source_sha256": source_hash,
                "patched_sha256": patched_hash,
                "operations": [{"id": "first"}, {"id": "second"}],
                "timestamp": "2026-03-01T12:00:00Z",
                "dry_run": False,
            }
            self._write(artifacts / "patch_manifest.json", manifest)
            self._write(
                artifacts / "rollback.json",
                {
                    "schema_version": 1,
                    "source_path": "C:/samples/source.exe",
                    "source_sha256": source_hash,
                    "patched_sha256": patched_hash,
                    "operations": [{"id": "first"}],
                },
            )

            data = build_dashboard(workspace)
            audit = data["binary_patches"]

            self.assertEqual(audit["count"], 1)
            self.assertEqual(audit["applied_count"], 1)
            self.assertEqual(audit["dry_run_count"], 0)
            self.assertEqual(audit["recent"][0]["source_path"], manifest["source_path"])
            self.assertEqual(audit["recent"][0]["patched_path"], manifest["patched_path"])
            self.assertEqual(audit["recent"][0]["patched_sha256"], manifest["patched_sha256"])
            self.assertEqual(audit["recent"][0]["operation_count"], 2)
            self.assertIn("Binary Patch Audit", (workspace / "dashboard" / "index.html").read_text(encoding="utf-8"))

    def test_malformed_binary_patch_manifest_is_reported_without_blocking_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            manifest = workspace / "output" / "broken.patch-artifacts" / "patch_manifest.json"
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text("{invalid", encoding="utf-8")

            data = build_dashboard(workspace)

            self.assertEqual(data["binary_patches"]["count"], 0)
            self.assertEqual(data["diagnostics"]["malformed_json"], 1)
            self.assertTrue((workspace / "dashboard" / "data.json").is_file())

    def test_binary_patch_audit_includes_independent_rollback_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source_hash = "a" * 64
            patched_hash = "b" * 64
            restored_hash = "c" * 64
            self._write(
                workspace / "output" / "sample.patch-artifacts" / "patch_manifest.json",
                {"status": "ok", "schema_version": 1, "source_path": "C:/samples/source.exe", "patched_path": "C:/output/patched.exe", "source_sha256": source_hash, "patched_sha256": patched_hash, "operations": [{"id": "patch"}], "dry_run": False},
            )
            rollback = {"status": "ok", "schema_version": 1, "patched_path": "C:/output/patched.exe", "restored_path": "C:/output/restored.exe", "patched_sha256": patched_hash, "restored_sha256": restored_hash, "operations": [{"id": "restore"}], "dry_run": False}
            self._write(workspace / "output" / "sample.rollback-artifacts" / "rollback_manifest.json", rollback)

            audit = build_dashboard(workspace)["binary_patches"]
            patch = next(item for item in audit["recent"] if item["audit_type"] == "patch")
            restored = next(item for item in audit["recent"] if item["audit_type"] == "rollback")

            self.assertEqual(audit["count"], 2)
            self.assertEqual(audit["applied_count"], 2)
            self.assertEqual(patch["patched_path"], "C:/output/patched.exe")
            self.assertEqual(patch["patched_sha256"], patched_hash)
            self.assertEqual(restored["source_path"], rollback["patched_path"])
            self.assertEqual(restored["patched_path"], rollback["restored_path"])
            self.assertEqual(restored["source_sha256"], rollback["patched_sha256"])
            self.assertEqual(restored["patched_sha256"], rollback["restored_sha256"])
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")
            self.assertIn("item.audit_type || 'patch'", html)
            self.assertIn('"audit_type": "rollback"', html)

    def test_binary_patch_audit_ignores_filename_only_or_incomplete_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write(
                workspace / "unrelated" / "patch_manifest.json",
                {
                    "schema_version": 1,
                    "status": "ok",
                    "source_path": "C:/samples/source.exe",
                    "patched_path": "C:/output/patched.exe",
                    "source_sha256": "a" * 64,
                    "patched_sha256": "b" * 64,
                    "operations": [],
                    "dry_run": False,
                },
            )
            self._write(
                workspace / "output" / "incomplete.patch-artifacts" / "patch_manifest.json",
                {"schema_version": 1, "status": "ok", "operations": [], "dry_run": False},
            )

            data = build_dashboard(workspace)

            self.assertEqual(data["binary_patches"]["count"], 0)
            self.assertEqual(data["diagnostics"]["invalid_records"], 2)
            self.assertEqual(len(data["diagnostics"]["skipped_files"]), 2)

    def test_binary_patch_audit_accepts_custom_artifact_directory_with_matching_rollback_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            artifacts = workspace / "output" / "manual-audit"
            source_hash = "a" * 64
            patched_hash = "b" * 64
            manifest = {
                "schema_version": 1,
                "status": "ok",
                "source_path": "C:/samples/source.exe",
                "patched_path": "C:/output/patched.exe",
                "source_sha256": source_hash,
                "patched_sha256": patched_hash,
                "operations": [{"id": "patch"}],
                "dry_run": False,
            }
            self._write(artifacts / "patch_manifest.json", manifest)
            self._write(
                artifacts / "rollback.json",
                {
                    "schema_version": 1,
                    "source_path": manifest["source_path"],
                    "source_sha256": source_hash,
                    "patched_sha256": patched_hash,
                    "operations": [{"id": "restore"}],
                },
            )

            audit = build_dashboard(workspace)["binary_patches"]

            self.assertEqual(audit["count"], 1)
            self.assertEqual(audit["recent"][0]["patched_sha256"], patched_hash)

    def test_evidence_manifest_audit_verifies_hashes_before_dashboard_display(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            output = workspace / "analysis-output"
            artifact = output / "static.json"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(b"original-evidence")
            manifest = build_manifest(
                output,
                [{"path": str(artifact), "kind": "static_analysis", "tool": "pe_deep_scan"}],
            )
            write_manifest(manifest, output / "evidence-manifest.json")

            verified = build_dashboard(workspace)["evidence_manifests"]

            self.assertEqual(verified["count"], 1)
            self.assertEqual(verified["valid_count"], 1)
            self.assertEqual(verified["failed_count"], 0)
            self.assertEqual(verified["verified_file_count"], 1)
            self.assertEqual(verified["recent"][0]["status"], "ok")
            self.assertTrue(verified["recent"][0]["schema_valid"])
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")
            self.assertIn("Evidence Integrity", html)
            self.assertIn("evidence-manifests", html)

            # Preserve the length to exercise the hash-verification path rather
            # than only the earlier size check.
            artifact.write_bytes(b"tampered-evidence")
            failed = build_dashboard(workspace)["evidence_manifests"]
            self.assertEqual(failed["valid_count"], 0)
            self.assertEqual(failed["failed_count"], 1)
            self.assertEqual(failed["recent"][0]["status"], "failed")
            self.assertIn("hash", failed["recent"][0]["issue_kinds"])

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



    def test_dashboard_surfaces_platform_core_capability_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            self._write(
                workspace / "output" / "report.json",
                {
                    "platform_core": {
                        "status": "ok",
                        "semantic_ir": {"path": "output/semantic_ir.json", "module_count": 1, "runtime_count": 0},
                        "evidence_graph": {"path": "output/evidence_graph.json", "node_count": 3, "edge_count": 2},
                        "capability_registry": {
                            "capability_count": 5,
                            "capabilities": {"memory_runtime": ["mock"], "injector": ["mock"]},
                        },
                        "capability_audit": {
                            "record_count": 1,
                            "records": [
                                {
                                    "capability": "memory_runtime",
                                    "provider": "mock",
                                    "action": "scan",
                                    "status": "mocked",
                                    "target_identity": {"kind": "process", "display_name": "demo.exe"},
                                }
                            ],
                            "summary": {
                                "status_counts": {"mocked": 1},
                                "rollback_supported_count": 1,
                                "manifest_reference_count": 1,
                                "dashboard_trace_count": 1,
                            },
                        },
                    }
                },
            )

            data = build_dashboard(workspace)
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")
            platform_core = data["platform_core"]

            self.assertEqual(platform_core["status"], "ok")
            self.assertEqual(platform_core["capability_audit"]["record_count"], 1)
            self.assertEqual(platform_core["capability_audit"]["summary"]["status_counts"]["mocked"], 1)
            self.assertIn("Capability audit records", html)
            self.assertIn('"capability": "memory_runtime"', html)
            self.assertIn('"action": "scan"', html)

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
