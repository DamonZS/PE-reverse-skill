from __future__ import annotations

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
