from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import urlopen

from reverse_analyzer.acceptance import merge_acceptance_records
from reverse_analyzer.dashboard import _load_records, build_dashboard, serve_dashboard
from reverse_analyzer.evidence import build_manifest, write_manifest


class DashboardTests(unittest.TestCase):
    def test_empty_workspace_writes_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            data = build_dashboard(workspace)

            self.assertEqual(data["summary"]["experiment_total"], 0)
            self.assertEqual(data["summary"]["session_total"], 0)
            self.assertEqual(
                data["acceptance_history"],
                {
                    "available": False,
                    "summary": {
                        "total": 0,
                        "live_verified": 0,
                        "failed": 0,
                        "dependency_blocked": 0,
                    },
                    "records": [],
                },
            )
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

    def test_dashboard_uses_latest_valid_environment_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            older = workspace / "reports" / "older" / "environment-validation.json"
            newer = workspace / "reports" / "newer" / "environment-validation.json"
            self._write(older, self._environment_report("older"))
            self._write(newer, self._environment_report("newer"))
            os.utime(older, (1_700_000_000, 1_700_000_000))
            os.utime(newer, (1_700_000_100, 1_700_000_100))

            data = build_dashboard(workspace)
            environment = data["environment_validation"]
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")

            self.assertTrue(environment["available"])
            self.assertEqual(
                environment["source_path"],
                "reports/newer/environment-validation.json",
            )
            self.assertEqual(environment["marker"], "newer")
            self.assertEqual(
                environment["checks"]["frida_python"]["status"], "discovered"
            )
            self.assertEqual(
                environment["checks"]["frida_cli"]["status"], "verified"
            )
            self.assertEqual(
                environment["workflows"]["frida_desktop"]["status"],
                "dependency_gated",
            )
            artifact = next(
                item
                for item in data["artifact_navigation"]["items"]
                if item["kind"] == "environment_validation"
            )
            self.assertEqual(artifact["domain"], "environment")
            self.assertEqual(artifact["path"], environment["source_path"])
            self.assertIn("Environment Validation", html)
            self.assertIn("Discovery", html)
            self.assertIn("Probe verification", html)
            self.assertIn("dependency-gated", html)
            self.assertIn("Acceptance fixtures", html)
            self.assertIn("p1-memory-runtime-live", html)
            self.assertEqual(
                environment["summary"]["acceptance_fixture_dependency_gated"],
                1,
            )

    def test_dashboard_remains_compatible_with_environment_schema_v1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            report = self._environment_report("legacy")
            report["schema_version"] = 1
            report.pop("acceptance_fixtures")
            summary = report["summary"]
            assert isinstance(summary, dict)
            for key in list(summary):
                if key.startswith("acceptance_fixture_"):
                    summary.pop(key)
            self._write(workspace / "environment-validation.json", report)

            environment = build_dashboard(workspace)["environment_validation"]

            self.assertTrue(environment["available"])
            self.assertEqual(environment["schema_version"], 1)

    def test_dashboard_accepts_live_verified_merged_environment_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            report = self._environment_report("merged-live")
            fixtures = report["acceptance_fixtures"]
            summary = report["summary"]
            assert isinstance(fixtures, list)
            assert isinstance(fixtures[0], dict)
            assert isinstance(summary, dict)
            fixtures[0]["status"] = "ready_to_run"
            fixtures[0]["configured_gates"] = ["RUN_MEMORY_RUNTIME_INTEGRATION"]
            fixtures[0]["missing_gates"] = []
            summary["acceptance_fixture_ready_to_run"] = 1
            summary["acceptance_fixture_dependency_gated"] = 0
            merged = merge_acceptance_records(
                report,
                [
                    {
                        "fixture_id": "p1-memory-runtime-live",
                        "outcome": "passed",
                        "finished_at": "2026-07-14T00:01:00+00:00",
                        "record_path": "acceptance/records/p1-memory-runtime-live.json",
                        "live_verified": True,
                        "integrity": {"status": "ok", "live_verified": True},
                    }
                ],
            )
            self._write(workspace / "environment-validation.json", merged)

            data = build_dashboard(workspace)
            environment = data["environment_validation"]
            fixture = environment["acceptance_fixtures"][0]

            self.assertTrue(environment["available"])
            self.assertEqual(fixture["status"], "live_verified")
            self.assertTrue(fixture["live_verified"])
            self.assertEqual(
                environment["summary"]["acceptance_fixture_live_verified"], 1
            )
            self.assertEqual(
                fixture["latest_acceptance_record"],
                "acceptance/records/p1-memory-runtime-live.json",
            )
            self.assertEqual(
                data["diagnostics"]["environment_validation"]["invalid_reports"],
                0,
            )

    def test_dashboard_surfaces_acceptance_history_and_artifact_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            session_record = (
                workspace
                / "sessions"
                / "run-p4"
                / "output"
                / "acceptance"
                / "records"
                / "graphics.json"
            )
            frame = workspace / "sessions" / "run-p4" / "output" / "frame.json"
            self._write(frame, {"frame_id": 7})
            self._write(
                session_record,
                {
                    "fixture_id": "p4-graphics-live",
                    "phase": "P4",
                    "capability": "graphics_present_runtime",
                    "outcome": "passed",
                    "live_verified": True,
                    "started_at": "2026-07-14T10:00:00Z",
                    "finished_at": "2026-07-14T10:01:00Z",
                    "record_path": "sessions/run-p4/output/acceptance/records/graphics.json",
                    "observed_artifacts": [
                        {
                            "path": "sessions/run-p4/output/frame.json",
                            "label": "Frame evidence",
                            "kind": "frame_evidence",
                        }
                    ],
                },
            )
            self._write(
                workspace / "output" / "acceptance" / "records" / "memory.json",
                {
                    "fixture_id": "p1-memory-blocked",
                    "phase": "P1",
                    "capability": "memory_runtime",
                    "outcome": "dependency-blocked",
                    "live_verified": False,
                    "started_at": "2026-07-14T09:00:00Z",
                    "finished_at": "2026-07-14T09:00:01Z",
                },
            )
            self._write(
                workspace / "acceptance" / "records" / "source.json",
                {
                    "fixture_id": "p3-source-failed",
                    "phase": "P3",
                    "capability": "source_reconstruction",
                    "outcome": "failed",
                    "live_verified": False,
                    "started_at": "2026-07-14T08:00:00Z",
                    "finished_at": "2026-07-14T08:00:02Z",
                    "observed_artifacts": ["missing-output.json"],
                },
            )

            data = build_dashboard(workspace)
            history = data["acceptance_history"]
            html = (workspace / "dashboard" / "index.html").read_text(encoding="utf-8")

            self.assertTrue(history["available"])
            self.assertEqual(
                history["summary"],
                {
                    "total": 3,
                    "live_verified": 0,
                    "failed": 1,
                    "dependency_blocked": 1,
                },
            )
            self.assertEqual(history["records"][0]["fixture_id"], "p4-graphics-live")
            self.assertTrue(history["records"][0]["declared_live_verified"])
            self.assertFalse(history["records"][0]["live_verified"])
            self.assertEqual(history["records"][0]["integrity"]["status"], "failed")
            frame_link = next(
                item
                for item in history["records"][0]["artifact_links"]
                if item["kind"] == "frame_evidence"
            )
            self.assertTrue(frame_link["exists"])
            self.assertIn("frame.json", frame_link["href"])
            acceptance_group = next(
                group
                for group in data["artifact_navigation"]["groups"]
                if group["domain"] == "acceptance"
            )
            self.assertGreaterEqual(acceptance_group["available_count"], 4)
            self.assertIn("Acceptance history", html)
            self.assertIn("Dependency blocked", html)
            self.assertIn("p4-graphics-live", html)
            self.assertIn("Frame evidence", html)

    def test_acceptance_history_skips_malformed_and_invalid_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            records = workspace / "output" / "acceptance" / "records"
            records.mkdir(parents=True)
            (records / "malformed.json").write_text("{invalid", encoding="utf-8")
            self._write(
                records / "invalid.json",
                {
                    "fixture_id": "missing-required-fields",
                    "phase": "P4",
                    "capability": "graphics_present_runtime",
                },
            )

            data = build_dashboard(workspace)
            state = data["diagnostics"]["acceptance_history"]

            self.assertFalse(data["acceptance_history"]["available"])
            self.assertEqual(data["acceptance_history"]["summary"]["total"], 0)
            self.assertEqual(state["malformed_records"], 1)
            self.assertEqual(state["invalid_records"], 1)
            self.assertEqual(data["diagnostics"]["malformed_json"], 1)
            self.assertTrue((workspace / "dashboard" / "index.html").is_file())

    def test_environment_report_rejects_fixture_summary_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            valid = workspace / "reports" / "valid" / "environment-validation.json"
            invalid = workspace / "reports" / "invalid" / "environment-validation.json"
            self._write(valid, self._environment_report("valid"))
            invalid_report = self._environment_report("invalid")
            summary = invalid_report["summary"]
            assert isinstance(summary, dict)
            summary["acceptance_fixture_dependency_gated"] = 0
            self._write(invalid, invalid_report)
            os.utime(valid, (1_700_000_200, 1_700_000_200))
            os.utime(invalid, (1_700_000_300, 1_700_000_300))

            data = build_dashboard(workspace)

            self.assertEqual(data["environment_validation"]["marker"], "valid")
            self.assertEqual(
                data["diagnostics"]["environment_validation"]["invalid_reports"],
                1,
            )

    def test_environment_report_falls_back_from_newer_invalid_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            valid = workspace / "reports" / "valid" / "environment-validation.json"
            malformed = workspace / "reports" / "malformed" / "environment-validation.json"
            invalid = workspace / "reports" / "invalid" / "environment-validation.json"
            oversized = workspace / "reports" / "oversized" / "environment-validation.json"
            self._write(valid, self._environment_report("valid"))
            malformed.parent.mkdir(parents=True, exist_ok=True)
            malformed.write_text("{not-json", encoding="utf-8")
            self._write(invalid, {"schema_version": 1, "checks": []})
            oversized.parent.mkdir(parents=True, exist_ok=True)
            oversized.write_bytes(b" " * (2 * 1024 * 1024 + 1))
            for offset, path in enumerate((valid, malformed, invalid, oversized)):
                timestamp = 1_700_001_000 + offset
                os.utime(path, (timestamp, timestamp))

            data = build_dashboard(workspace)
            environment = data["environment_validation"]
            environment_diagnostics = data["diagnostics"]["environment_validation"]

            self.assertEqual(environment["marker"], "valid")
            self.assertEqual(
                environment["source_path"],
                "reports/valid/environment-validation.json",
            )
            self.assertEqual(environment_diagnostics["malformed_reports"], 1)
            self.assertEqual(environment_diagnostics["invalid_reports"], 1)
            self.assertEqual(environment_diagnostics["oversize_reports"], 1)

    def test_environment_report_rejects_verified_check_without_successful_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            valid = workspace / "reports" / "valid" / "environment-validation.json"
            invalid = workspace / "reports" / "invalid" / "environment-validation.json"
            self._write(valid, self._environment_report("valid"))
            invalid_report = self._environment_report("invalid")
            checks = invalid_report["checks"]
            assert isinstance(checks, dict)
            frida_cli = checks["frida_cli"]
            assert isinstance(frida_cli, dict)
            frida_cli["probe"] = None
            self._write(invalid, invalid_report)
            os.utime(valid, (1_700_001_100, 1_700_001_100))
            os.utime(invalid, (1_700_001_200, 1_700_001_200))

            data = build_dashboard(workspace)

            self.assertEqual(data["environment_validation"]["marker"], "valid")
            self.assertEqual(
                data["diagnostics"]["environment_validation"]["invalid_reports"],
                1,
            )

    def test_environment_report_rejects_summary_that_disagrees_with_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            valid = workspace / "reports" / "valid" / "environment-validation.json"
            invalid = workspace / "reports" / "invalid" / "environment-validation.json"
            self._write(valid, self._environment_report("valid"))
            invalid_report = self._environment_report("invalid")
            summary = invalid_report["summary"]
            assert isinstance(summary, dict)
            summary["verified"] = 1
            summary["dependency_gated"] = 0
            self._write(invalid, invalid_report)
            os.utime(valid, (1_700_001_300, 1_700_001_300))
            os.utime(invalid, (1_700_001_400, 1_700_001_400))

            data = build_dashboard(workspace)

            self.assertEqual(data["environment_validation"]["marker"], "valid")
            self.assertEqual(
                data["diagnostics"]["environment_validation"]["invalid_reports"],
                1,
            )

    def test_environment_report_rejects_verified_workflow_with_unverified_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            valid = workspace / "reports" / "valid" / "environment-validation.json"
            invalid = workspace / "reports" / "invalid" / "environment-validation.json"
            self._write(valid, self._environment_report("valid"))
            invalid_report = self._environment_report("invalid")
            workflows = invalid_report["workflows"]
            summary = invalid_report["summary"]
            assert isinstance(workflows, dict)
            assert isinstance(summary, dict)
            workflow = workflows["frida_desktop"]
            assert isinstance(workflow, dict)
            workflow["status"] = "verified"
            workflow["verified"] = True
            summary["verified"] = 1
            summary["dependency_gated"] = 0
            self._write(invalid, invalid_report)
            os.utime(valid, (1_700_001_500, 1_700_001_500))
            os.utime(invalid, (1_700_001_600, 1_700_001_600))

            data = build_dashboard(workspace)

            self.assertEqual(data["environment_validation"]["marker"], "valid")
            self.assertEqual(
                data["diagnostics"]["environment_validation"]["invalid_reports"],
                1,
            )

    def test_environment_report_symlink_cannot_escape_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            valid = workspace / "reports" / "valid" / "environment-validation.json"
            outside = root / "outside" / "environment-validation.json"
            link = workspace / "reports" / "outside-link" / "environment-validation.json"
            self._write(valid, self._environment_report("inside"))
            self._write(outside, self._environment_report("outside"))
            link.parent.mkdir(parents=True, exist_ok=True)
            try:
                link.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"file symlinks are unavailable: {exc}")
            os.utime(valid, (1_700_002_000, 1_700_002_000))
            os.utime(outside, (1_700_002_100, 1_700_002_100))

            data = build_dashboard(workspace)

            self.assertEqual(data["environment_validation"]["marker"], "inside")
            self.assertGreaterEqual(
                data["diagnostics"]["environment_validation"]["unsafe_paths"], 1
            )

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
            self._write(
                project / "analysis" / "equivalence_assessment.json",
                {
                    "schema_version": 1,
                    "status": "mismatch",
                    "score": 0.875,
                    "observed_evidence_matched": False,
                    "claim_scope": "observed_evidence_only",
                    "complete_behavior_equivalence_proven": False,
                    "mismatch_count": 1,
                    "dimensions": {
                        "static_structure_coverage": {
                            "status": "matched",
                            "score": 1.0,
                        },
                        "runtime_differential_traces": {
                            "status": "mismatch",
                            "score": 0.75,
                        },
                    },
                    "mismatches": [
                        {
                            "dimension": "runtime_differential_traces",
                            "observation_id": "runtime:1",
                        }
                    ],
                },
            )
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
            self.assertEqual(
                source["projects"][0]["equivalence_assessment_status"], "mismatch"
            )
            self.assertEqual(
                source["projects"][0]["equivalence_assessment_score"], 0.875
            )
            self.assertEqual(
                source["projects"][0]["equivalence_dimension_statuses"],
                {
                    "static_structure_coverage": "matched",
                    "runtime_differential_traces": "mismatch",
                },
            )
            self.assertEqual(source["projects"][0]["equivalence_mismatch_count"], 1)
            self.assertFalse(
                source["projects"][0]["complete_behavior_equivalence_proven"]
            )
            self.assertIn("src/main.c", [item["path"] for item in source["projects"][0]["source_files"]])
            self.assertEqual(saved["source_reconstruction"], source)
            self.assertIn("Source Reconstruction", html)
            self.assertIn("Observed evidence", html)
            self.assertIn("Complete behavior proof: not claimed", html)
            self.assertIn("Dimensions", html)
            self.assertIn("Mismatches", html)



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

    @staticmethod
    def _environment_report(marker: str) -> dict[str, object]:
        return {
            "schema_version": 2,
            "generated_at": "2026-07-14T00:00:00+00:00",
            "host": {
                "system": "Windows",
                "release": "fixture",
                "machine": "AMD64",
                "python": "3.12",
            },
            "execute_probes": True,
            "checks": {
                "frida_python": {
                    "kind": "python_module",
                    "module": "frida",
                    "discovered": True,
                    "status": "discovered",
                    "probe": None,
                },
                "frida_cli": {
                    "kind": "executable",
                    "path": "C:/fixture/frida.exe",
                    "discovered": True,
                    "status": "verified",
                    "probe": {"status": "ok"},
                },
            },
            "workflows": {
                "frida_desktop": {
                    "name": "frida_desktop",
                    "status": "dependency_gated",
                    "ready": True,
                    "verified": False,
                    "required": ["frida_python"],
                    "any_of": ["frida_cli"],
                    "note": marker,
                }
            },
            "summary": {
                "total": 1,
                "verified": 0,
                "dependency_gated": 1,
                "partial": 0,
                "failed": 0,
                "unavailable": 0,
                "unsupported_host": 0,
                "acceptance_fixture_total": 1,
                "acceptance_fixture_repository_ready": 0,
                "acceptance_fixture_ready_to_run": 0,
                "acceptance_fixture_dependency_gated": 1,
                "acceptance_fixture_unsupported_host": 0,
            },
            "acceptance_fixtures": [
                {
                    "id": "p1-memory-runtime-live",
                    "phase": "P1",
                    "capability": "memory_runtime",
                    "evidence_level": "live-target",
                    "host": "windows",
                    "gate_env": ["RUN_MEMORY_RUNTIME_INTEGRATION"],
                    "command": "$env:RUN_MEMORY_RUNTIME_INTEGRATION='1'; python -m unittest tests.test_memory_structured",
                    "expected_artifacts": ["memory/session.json"],
                    "status": "dependency_gated",
                    "host_supported": True,
                    "workflow_states": {},
                    "configured_gates": [],
                    "missing_gates": ["RUN_MEMORY_RUNTIME_INTEGRATION"],
                    "live_verified": False,
                    "acceptance_boundary": "Readiness does not prove a completed live target run.",
                }
            ],
            "marker": marker,
        }


if __name__ == "__main__":
    unittest.main()
