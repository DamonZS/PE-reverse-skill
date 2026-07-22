from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reverse_analyzer.acceptance import (
    AcceptanceError,
    load_acceptance_records,
    merge_acceptance_records,
    run_acceptance_fixture,
    verify_acceptance_record,
)
from reverse_analyzer.environment_validation import validate_external_environment
from tests.e2e.test_gui_vlm_live import _normalized_canary, _visual_text


def _write_live_memory_artifacts(
    run_dir: Path,
    *,
    synthetic: bool = False,
    pid: int = 1234,
) -> None:
    memory = run_dir / "memory"
    memory.mkdir(parents=True, exist_ok=True)
    (memory / "session.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "provider": "production",
                "evidence_class": "synthetic" if synthetic else "live_host_proof",
            }
        ),
        encoding="utf-8",
    )
    (memory / "rollback_plan.json").write_text(
        json.dumps({"status": "ok", "rollback_verified": True}),
        encoding="utf-8",
    )
    (memory / "cleanup.json").write_text(
        json.dumps({"status": "ok", "cleanup_verified": True}),
        encoding="utf-8",
    )
    (memory / "target-identity.json").write_text(
        json.dumps({"pid": pid, "path": "controlled-memory-fixture.exe"}),
        encoding="utf-8",
    )
    (memory / "execution-proof.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "provider": "production",
                "evidence_class": "synthetic" if synthetic else "live_host_proof",
                "executed_tests": 2,
                "skipped_tests": 0,
                "live_operations": 3,
            }
        ),
        encoding="utf-8",
    )


class AcceptanceRecordTests(unittest.TestCase):
    def test_vlm_canary_matching_normalizes_case_and_whitespace(self) -> None:
        output = {
            "text_regions": [{"text": "Status: VLM   Canary 42"}],
            "widgets": [{"text": "Save"}, {"type": "button"}],
        }

        observed = [_normalized_canary(item) for item in _visual_text(output)]

        self.assertIn("vlm canary 42", observed[0])
        self.assertEqual(len(observed), 2)

    def test_graphics_combined_fixture_contract_retains_hash_backed_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
                artifact_dir = run_dir / "graphics-combined"
                artifact_dir.mkdir(parents=True)
                artifacts = {
                    "target-identity.json": {
                        "kind": "process",
                        "pid": 4321,
                        "display_name": "controlled-graphics-host-4321",
                        "metadata": {"hwnd": 9001},
                    },
                    "present-observation.json": {
                        "status": "ok",
                        "provider": "windows_presentmon",
                        "target_pid": 4321,
                        "event_count": 3,
                        "last_event": {"pid": 4321},
                        "matrix_frame_id": "frame-3",
                    },
                    "matrix-capture.json": {
                        "status": "ok",
                        "source": "native_host_bridge",
                        "pid": 4321,
                        "hwnd": 9001,
                        "frame_id": "frame-3",
                        "matrix": [1, 0, 0, 0] * 4,
                    },
                    "projection.json": {
                        "status": "ok",
                        "matrix_frame_id": "frame-3",
                        "visible_point_count": 1,
                    },
                    "overlay-audit.json": {
                        "status": "ok",
                        "provider": "windows_gdi_overlay",
                        "frame_count": 1,
                    },
                    "cleanup.json": {
                        "status": "completed",
                        "verified": True,
                        "rollback_verified": True,
                        "cleanup_verified": True,
                    },
                    "execution-proof.json": {
                        "status": "ok",
                        "provider": "native-graphics-bridge-plus-windows-gdi",
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 4,
                    },
                }
                for name, payload in artifacts.items():
                    (artifact_dir / name).write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="graphics live ok", stderr="")

            environment = {
                "RUN_GRAPHICS_COMBINED_LIVE": "1",
                "REVERSE_ANALYZER_GRAPHICS_BRIDGE": "graphics-bridge.exe",
                "REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID": "4321",
                "REVERSE_ANALYZER_GRAPHICS_FIXTURE_HWND": "9001",
            }
            ready_report = {
                "status": "ok",
                "acceptance_fixtures": [
                    {
                        "id": "p7-graphics-combined-live",
                        "status": "ready_to_run",
                        "configured_gates": sorted(environment),
                        "missing_gates": [],
                        "workflow_states": {},
                    }
                ],
            }
            with mock.patch(
                "reverse_analyzer.acceptance.validate_external_environment",
                return_value=ready_report,
            ):
                record = run_acceptance_fixture(
                    "p7-graphics-combined-live",
                    temporary,
                    execute=True,
                    environ=environment,
                    system="Windows",
                    runner=runner,
                )

            self.assertEqual(record["outcome"], "passed")
            self.assertTrue(record["live_verified"])
            self.assertEqual(record["missing_artifacts"], [])
            self.assertTrue(record["rollback_result"]["verified"])
            self.assertTrue(record["cleanup_result"]["verified"])
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "ok")
            self.assertTrue(verification["live_verified"])

            # Integrity verification must also reject a cross-component frame
            # mismatch even when an attacker recomputes the retained file hash.
            matrix_path = (
                Path(record["run_directory"])
                / "graphics-combined"
                / "matrix-capture.json"
            )
            matrix_payload = json.loads(matrix_path.read_text(encoding="utf-8"))
            matrix_payload["frame_id"] = "frame-tampered"
            matrix_path.write_text(json.dumps(matrix_payload), encoding="utf-8")
            for entry in record["observed_artifacts"]:
                if entry["path"].endswith("matrix-capture.json"):
                    encoded = matrix_path.read_bytes()
                    entry["size"] = len(encoded)
                    entry["sha256"] = hashlib.sha256(encoded).hexdigest()
            Path(record["record_path"]).write_text(
                json.dumps(record), encoding="utf-8"
            )
            tampered = verify_acceptance_record(record["record_path"])
            self.assertEqual(tampered["status"], "failed")
            self.assertTrue(
                any("frame IDs do not match" in error for error in tampered["errors"])
            )

    def test_vlm_fixture_contract_retains_hash_backed_live_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
                artifact_dir = run_dir / "gui-vlm"
                artifact_dir.mkdir(parents=True)
                artifacts = {
                    "target-identity.json": {
                        "kind": "remote-openai-compatible-vlm",
                        "endpoint_sha256": "a" * 64,
                        "model": "fixture-vision",
                        "sha256": "b" * 64,
                        "image_sha256": "b" * 64,
                        "canary_sha256": "c" * 64,
                    },
                    "invocation.json": {"status": "ok", "duration_ms": 12},
                    "output.json": {
                        "status": "ok",
                        "text_regions": [{"text": "Save"}],
                        "widgets": [{"type": "button", "text": "Save"}],
                    },
                    "transport-audit.json": {
                        "status": "ok",
                        "transport": "openai-compatible-http",
                        "authorization_persisted": False,
                        "canary_verified": True,
                    },
                    "canary-verification.json": {
                        "status": "ok",
                        "verified": True,
                        "canary_sha256": "c" * 64,
                        "matched_items": 1,
                    },
                    "execution-proof.json": {
                        "status": "ok",
                        "provider": "openai-compatible-vlm",
                        "evidence_class": "live_target_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 1,
                        "canary_verified": True,
                    },
                }
                for name, payload in artifacts.items():
                    (artifact_dir / name).write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="vlm live ok", stderr="")

            environment = {
                "REVERSE_ANALYZER_RUN_VLM_LIVE": "1",
                "REVERSE_ANALYZER_VLM_BASE_URL": "https://vlm.example.invalid/v1",
                "REVERSE_ANALYZER_VLM_MODEL": "fixture-vision",
                "REVERSE_ANALYZER_VLM_API_KEY": "fixture-secret",
                "REVERSE_ANALYZER_VLM_IMAGE": "fixture.png",
                "REVERSE_ANALYZER_VLM_CANARY": "VLM-CANARY-42",
            }
            record = run_acceptance_fixture(
                "p7-vlm-openai-live",
                temporary,
                execute=True,
                environ=environment,
                system="Windows",
                runner=runner,
            )

            self.assertEqual(record["outcome"], "passed")
            self.assertTrue(record["live_verified"])
            self.assertEqual(record["missing_artifacts"], [])
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "ok")
            self.assertTrue(verification["live_verified"])

    def test_windows_uia_fixture_contract_retains_hash_backed_live_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
                artifact_dir = run_dir / "gui-uia"
                artifact_dir.mkdir(parents=True)
                artifacts = {
                    "target-identity.json": {
                        "kind": "live-child-process",
                        "pid": 4321,
                        "path": "python.exe",
                        "window_handle": 9001,
                    },
                    "runtime-tree-audit.json": {
                        "status": "ok",
                        "provider": {"name": "windows_uia", "api": "UIAutomationClient"},
                        "session_id": run_dir.name,
                        "window_count": 1,
                        "node_count": 2,
                        "evidence_class": "live_host_proof",
                    },
                    "fixture-cleanup.json": {
                        "status": "stopped",
                        "terminated": True,
                    },
                    "execution-proof.json": {
                        "status": "ok",
                        "provider": "windows-uia-comtypes",
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 2,
                    },
                }
                for name, payload in artifacts.items():
                    (artifact_dir / name).write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="uia live ok", stderr="")

            record = run_acceptance_fixture(
                "p7-windows-uia-live",
                temporary,
                execute=True,
                environ={"REVERSE_ANALYZER_RUN_WINDOWS_UIA_LIVE": "1"},
                system="Windows",
                runner=runner,
            )

            self.assertEqual(record["outcome"], "passed")
            self.assertTrue(record["live_verified"])
            self.assertEqual(record["missing_artifacts"], [])
            self.assertEqual(record["execution_proof"]["live_operations"], 2)
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "ok")
            self.assertTrue(verification["live_verified"])

    def test_registered_live_fixture_can_produce_hash_backed_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                self.assertIsInstance(command, list)
                self.assertNotIn("shell", kwargs)
                run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
                _write_live_memory_artifacts(run_dir)
                return subprocess.CompletedProcess(command, 0, stdout="live ok", stderr="")

            record = run_acceptance_fixture(
                "p1-memory-runtime-live",
                temporary,
                execute=True,
                target_identity={"pid": 1234, "path": "controlled-memory-fixture.exe"},
                environ={},
                system="Windows",
                runner=runner,
            )

            self.assertEqual(record["outcome"], "passed")
            self.assertTrue(record["live_verified"])
            self.assertEqual(record["missing_artifacts"], [])
            self.assertTrue(all(item["sha256"] for item in record["observed_artifacts"]))
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "ok")
            self.assertTrue(verification["live_verified"])

    def test_synthetic_provenance_cannot_be_live_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                _write_live_memory_artifacts(
                    Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"]),
                    synthetic=True,
                )
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            record = run_acceptance_fixture(
                "p1-memory-runtime-live",
                temporary,
                execute=True,
                target_identity={"pid": 1234},
                environ={},
                system="Windows",
                runner=runner,
            )

        self.assertFalse(record["live_verified"])
        self.assertFalse(record["verification_constraints"]["provenance_non_synthetic"])
        self.assertTrue(record["rejected_provenance"])

    def test_explicit_false_simulation_marker_is_not_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
                _write_live_memory_artifacts(run_dir)
                session = run_dir / "memory" / "session.json"
                payload = json.loads(session.read_text(encoding="utf-8"))
                payload["provenance"] = {"backend": {"simulated": False}}
                session.write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="live ok", stderr="")

            record = run_acceptance_fixture(
                "p1-memory-runtime-live",
                temporary,
                execute=True,
                environ={},
                system="Windows",
                runner=runner,
            )

        self.assertTrue(record["verification_constraints"]["provenance_non_synthetic"])
        self.assertTrue(record["live_verified"])

    def test_missing_artifacts_and_failed_command_never_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                del kwargs
                return subprocess.CompletedProcess(command, 9, stdout="", stderr="failed")

            record = run_acceptance_fixture(
                "p1-memory-runtime-live",
                temporary,
                execute=True,
                target_identity={"pid": 12},
                environ={},
                system="Windows",
                runner=runner,
            )

        self.assertEqual(record["outcome"], "failed")
        self.assertFalse(record["live_verified"])
        self.assertTrue(record["missing_artifacts"])

    def test_zero_exit_with_skipped_execution_proof_never_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
                _write_live_memory_artifacts(run_dir)
                proof = run_dir / "memory" / "execution-proof.json"
                proof.write_text(
                    json.dumps(
                        {
                            "status": "ok",
                            "executed_tests": 0,
                            "skipped_tests": 2,
                            "live_operations": 0,
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, stdout="OK (skipped=2)", stderr="")

            record = run_acceptance_fixture(
                "p1-memory-runtime-live",
                temporary,
                execute=True,
                environ={},
                system="Windows",
                runner=runner,
            )

        self.assertEqual(record["outcome"], "passed")
        self.assertFalse(record["live_verified"])
        self.assertFalse(record["verification_constraints"]["execution_proof_valid"])
        self.assertIn("execution proof contains skipped tests", record["execution_proof_errors"])
        self.assertTrue(
            any("below the fixture requirement" in item for item in record["execution_proof_errors"])
        )

    def test_unknown_fixture_and_non_explicit_execution_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(AcceptanceError):
                run_acceptance_fixture("not-registered", temporary, execute=True)
            with self.assertRaises(AcceptanceError):
                run_acceptance_fixture("p0-environment-contract", temporary, execute=False)

    def test_registry_path_escape_is_rejected(self) -> None:
        malicious = {
            "id": "malicious",
            "phase": "P0",
            "capability": "test",
            "evidence_level": "repository",
            "host": "any",
            "argv": ["{python}", "-c", "print('bounded')"],
            "expected_artifacts": ["../escaped.json"],
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.acceptance_fixture_definitions",
            return_value=(malicious,),
        ):
            with self.assertRaises(AcceptanceError):
                run_acceptance_fixture("malicious", temporary, execute=True)

    def test_tamper_is_detected_and_environment_report_uses_only_valid_live_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                _write_live_memory_artifacts(
                    Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"]),
                    pid=55,
                )
                return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

            record = run_acceptance_fixture(
                "p1-memory-runtime-live",
                temporary,
                execute=True,
                target_identity={"pid": 55},
                environ={},
                system="Windows",
                runner=runner,
            )
            records = load_acceptance_records(temporary)
            report = validate_external_environment(environ={}, system="Windows")
            merged = merge_acceptance_records(report, records)
            fixture = next(item for item in merged["acceptance_fixtures"] if item["id"] == "p1-memory-runtime-live")
            self.assertTrue(fixture["live_verified"])
            self.assertEqual(fixture["status"], "live_verified")

            (Path(record["run_directory"]) / "memory" / "session.json").write_text("tampered", encoding="utf-8")
            records = load_acceptance_records(temporary)
            merged = merge_acceptance_records(report, records)
            fixture = next(item for item in merged["acceptance_fixtures"] if item["id"] == "p1-memory-runtime-live")
            self.assertFalse(fixture["live_verified"])
            self.assertEqual(records[0]["integrity"]["status"], "failed")
            self.assertTrue(records[0]["declared_live_verified"])
            self.assertFalse(records[0]["live_verified"])
            self.assertTrue(merged["acceptance_records"][0]["declared_live_verified"])
            self.assertFalse(merged["acceptance_records"][0]["live_verified"])


if __name__ == "__main__":
    unittest.main()
