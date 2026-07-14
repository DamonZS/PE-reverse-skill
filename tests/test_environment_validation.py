from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.cli import main
from reverse_analyzer.environment_validation import validate_external_environment


class EnvironmentValidationTests(unittest.TestCase):
    def test_discovery_does_not_claim_e2e_verification(self) -> None:
        report = validate_external_environment(
            overrides={"frida_python": True},
            execute_probes=False,
            environ={},
            system="Windows",
        )

        self.assertEqual(report["checks"]["frida_python"]["status"], "discovered")
        self.assertEqual(report["workflows"]["frida_desktop"]["verified"], False)
        self.assertEqual(report["workflows"]["ios_toolchain"]["status"], "unsupported_host")

    def test_json_bridge_probe_can_verify_graphics_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bridge = Path(temp_dir) / "graphics-bridge.exe"
            bridge.write_bytes(b"fixture")

            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                del kwargs
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=json.dumps({"protocol_version": 1, "status": "ok"}),
                    stderr="",
                )

            report = validate_external_environment(
                overrides={
                    "graphics_bridge": str(bridge),
                    "frida_python": False,
                    "comtypes": False,
                    "opencv": False,
                },
                execute_probes=True,
                runner=runner,
                environ={},
                system="Windows",
            )

        check = report["checks"]["graphics_bridge"]
        self.assertEqual(check["status"], "verified")
        self.assertEqual(report["workflows"]["graphics_present_hook"]["status"], "verified")

    def test_invalid_bridge_protocol_is_failed_not_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bridge = Path(temp_dir) / "imgui-bridge.exe"
            bridge.write_bytes(b"fixture")

            def runner(command, **kwargs):  # type: ignore[no-untyped-def]
                del kwargs
                return subprocess.CompletedProcess(command, 0, stdout="not-json", stderr="")

            report = validate_external_environment(
                overrides={
                    "imgui_bridge": str(bridge),
                    "frida_python": False,
                    "comtypes": False,
                    "opencv": False,
                },
                execute_probes=True,
                runner=runner,
                environ={},
                system="Windows",
            )

        self.assertEqual(report["checks"]["imgui_bridge"]["status"], "failed")
        self.assertEqual(report["workflows"]["imgui_in_process"]["verified"], False)

    def test_cli_writes_machine_readable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["environment", "validate", "--out", temp_dir, "--json"])

            artifact = Path(temp_dir) / "environment-validation.json"
            self.assertEqual(code, 0)
            self.assertTrue(artifact.exists())
            payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertIn("workflows", payload)
            self.assertIn("acceptance_fixtures", payload)
            self.assertIn("summary", payload)
            self.assertIn("artifact_path", json.loads(stdout.getvalue()))

    def test_p0_p4_acceptance_fixtures_separate_readiness_from_live_proof(self) -> None:
        report = validate_external_environment(
            overrides={
                "graphics_bridge": False,
                "imgui_bridge": False,
                "presentmon": False,
                "frida_python": False,
                "comtypes": False,
                "opencv": False,
            },
            execute_probes=False,
            environ={"RUN_MEMORY_RUNTIME_INTEGRATION": "1"},
            system="Windows",
        )
        fixtures = {item["id"]: item for item in report["acceptance_fixtures"]}

        self.assertEqual(fixtures["p0-environment-contract"]["status"], "repository_ready")
        self.assertEqual(fixtures["p1-memory-runtime-live"]["status"], "ready_to_run")
        self.assertFalse(fixtures["p1-memory-runtime-live"]["live_verified"])
        self.assertEqual(fixtures["p4-presentmon-live"]["status"], "dependency_gated")
        self.assertIn(
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID",
            fixtures["p4-presentmon-live"]["missing_gates"],
        )
        self.assertEqual(report["summary"]["acceptance_fixture_total"], len(fixtures))

    def test_fixture_contract_has_command_artifacts_and_acceptance_boundary(self) -> None:
        report = validate_external_environment(
            overrides={"frida_python": False, "comtypes": False, "opencv": False},
            execute_probes=False,
            environ={},
            system="Linux",
        )

        for fixture in report["acceptance_fixtures"]:
            with self.subTest(fixture=fixture["id"]):
                self.assertIn(fixture["phase"], {"P0", "P1", "P2", "P3", "P4"})
                self.assertTrue(fixture["capability"])
                self.assertTrue(fixture["command"])
                self.assertTrue(fixture["expected_artifacts"])
                self.assertFalse(fixture["live_verified"])
                self.assertIn("does not become live_verified", fixture["acceptance_boundary"])


if __name__ == "__main__":
    unittest.main()
