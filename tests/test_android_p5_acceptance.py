from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reverse_analyzer.acceptance import run_acceptance_fixture, verify_acceptance_record
from tests.e2e.test_android_native_patch_live import _adb_fixture_preflight


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _ready_report(fixture_id: str) -> dict[str, object]:
    return {
        "schema_version": 2,
        "acceptance_fixtures": [
            {
                "id": fixture_id,
                "status": "ready_to_run",
                "configured_gates": ["fixture"],
                "missing_gates": [],
                "workflow_states": {"fixture": "verified"},
            }
        ],
        "workflows": {},
        "summary": {},
    }


class AndroidP5AcceptanceContractTests(unittest.TestCase):
    def test_native_patch_preflight_rejects_existing_package_before_mutation(self) -> None:
        commands: list[list[str]] = []
        responses = iter(
            [
                {"ok": True, "stdout": "device\n"},
                {"ok": True, "stdout": "emulator-5554\n"},
                {"ok": True, "stdout": "package:/data/app/fixture.apk\n"},
            ]
        )

        def runner(command, **_kwargs):  # type: ignore[no-untyped-def]
            commands.append(command)
            return next(responses)

        with self.assertRaisesRegex(RuntimeError, "already installed"):
            _adb_fixture_preflight(
                ["adb", "-s", "emulator-5554"],
                "com.fixture.app",
                runner=runner,
            )

        self.assertEqual(len(commands), 3)
        self.assertNotIn("install", " ".join(" ".join(item) for item in commands))

    def test_native_patch_preflight_records_observed_device_and_clean_baseline(self) -> None:
        responses = iter(
            [
                {"ok": True, "stdout": "device\n"},
                {"ok": True, "stdout": "device-serial-1\n"},
                {"ok": True, "stdout": ""},
            ]
        )

        serial, evidence = _adb_fixture_preflight(
            ["adb"],
            "com.fixture.app",
            runner=lambda *_args, **_kwargs: next(responses),
        )

        self.assertEqual(serial, "device-serial-1")
        self.assertEqual(
            [item["step"] for item in evidence],
            ["device_state", "device_serial", "package_absent_precondition"],
        )

    def test_native_patch_preflight_rejects_failed_package_baseline_query(self) -> None:
        responses = iter(
            [
                {"ok": True, "stdout": "device\n"},
                {"ok": True, "stdout": "device-serial-1\n"},
                {"ok": False, "stdout": "", "stderr": "transport error"},
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "baseline query failed"):
            _adb_fixture_preflight(
                ["adb"],
                "com.fixture.app",
                runner=lambda *_args, **_kwargs: next(responses),
            )

    def test_frida_fixture_requires_cleanup_and_non_skipped_live_proof(self) -> None:
        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
            session = run_dir / "android_instrumentation" / "fixture-session"
            for name, payload in {
                "audit.json": {"status": "ok", "provider": "frida-android"},
                "events.json": {"status": "ok", "events": [{"event": "ready"}]},
                "rollback.json": {"status": "ok", "cleanup": {"ok": True}},
            }.items():
                _write_json(session / name, payload)
            evidence = run_dir / "android-frida"
            _write_json(
                evidence / "target-identity.json",
                {
                    "kind": "android_package",
                    "package_name": "com.fixture.app",
                    "device_selector": "usb",
                    "device_id": "fixture-device-1",
                    "device_name": "Fixture Android",
                    "device_type": "usb",
                },
            )
            _write_json(evidence / "cleanup.json", {"status": "ok", "verified": True, "unloaded": True, "detached": True})
            _write_json(evidence / "execution-proof.json", {
                "status": "ok", "provider": "frida-android", "evidence_class": "live_target_proof",
                "executed_tests": 1, "skipped_tests": 0, "live_operations": 3,
            })
            return subprocess.CompletedProcess(command, 0, stdout="frida ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-frida-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-frida-live", temporary, execute=True,
                environ={"ANDROID_FRIDA_LIVE_PACKAGE": "com.fixture.app"}, runner=runner,
            )
            self.assertTrue(record["live_verified"], record)
            self.assertEqual(verify_acceptance_record(record["record_path"])["status"], "ok")

            # A live claim must contain exactly the constraints recomputed
            # from the registered fixture; extra user-supplied true values do
            # not substitute for the acceptance predicate.
            record_path = Path(record["record_path"])
            persisted = json.loads(record_path.read_text(encoding="utf-8"))
            persisted["verification_constraints"]["forged_constraint"] = True
            record_path.write_text(json.dumps(persisted), encoding="utf-8")
            verification = verify_acceptance_record(record_path)
            self.assertEqual(verification["status"], "failed")
            self.assertIn("recomputed acceptance state", " ".join(verification["errors"]))

    def test_frida_fixture_rejects_selector_only_identity(self) -> None:
        """A configured selector must not stand in for observed Frida device identity."""

        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
            evidence = run_dir / "android-frida"
            _write_json(
                evidence / "target-identity.json",
                {"kind": "android_package", "package_name": "com.fixture.app", "device_selector": "usb"},
            )
            _write_json(evidence / "cleanup.json", {"status": "ok", "verified": True, "unloaded": True, "detached": True})
            _write_json(
                evidence / "execution-proof.json",
                {
                    "status": "ok",
                    "provider": "frida-android",
                    "evidence_class": "live_target_proof",
                    "executed_tests": 1,
                    "skipped_tests": 0,
                    "live_operations": 1,
                },
            )
            session = run_dir / "android_instrumentation" / "fixture-session"
            for name in ("audit.json", "events.json", "rollback.json"):
                _write_json(session / name, {"status": "ok"})
            return subprocess.CompletedProcess(command, 0, stdout="frida ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-frida-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-frida-live",
                temporary,
                execute=True,
                environ={"ANDROID_FRIDA_LIVE_PACKAGE": "com.fixture.app"},
                runner=runner,
            )
            self.assertFalse(record["live_verified"])
            persisted = json.loads(Path(record["record_path"]).read_text(encoding="utf-8"))
            persisted["live_verified"] = True
            Path(record["record_path"]).write_text(json.dumps(persisted), encoding="utf-8")
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "failed")

    def test_native_patch_fixture_requires_signed_deployment_launch_and_rollback(self) -> None:
        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            root = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"]) / "android-native-patch"
            for name in ("native-patch-plan.json", "native-patch-verify.json"):
                _write_json(root / "provider" / name, {"status": "ok", "verified": True})
            (root / "retained").mkdir(parents=True)
            (root / "retained" / "patched-signed.apk").write_bytes(b"signed-patched-fixture")
            _write_json(root / "provider" / "rollback.json", {"status": "ok", "verified": True})
            _write_json(root / "target-identity.json", {"kind": "apk_fixture", "package_name": "com.fixture.app", "sample_sha256": "a" * 64})
            _write_json(root / "deployment.json", {"status": "ok", "install_verified": True, "launch_verified": True})
            _write_json(root / "rollback.json", {"status": "ok", "verified": True, "restored": True, "device_cleanup_verified": True})
            _write_json(root / "execution-proof.json", {
                "status": "ok", "provider": "local_android_native_patch+adb", "evidence_class": "live_target_proof",
                "executed_tests": 1, "skipped_tests": 0, "live_operations": 8,
                "signature_verified": True, "install_verified": True, "launch_verified": True, "rollback_verified": True,
            })
            return subprocess.CompletedProcess(command, 0, stdout="native patch ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-native-patch-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-native-patch-live", temporary, execute=True,
                environ={
                    "ANDROID_NATIVE_PATCH_LIVE_APK": "fixture.apk",
                    "ANDROID_NATIVE_PATCH_LIVE_SPEC": "fixture.json",
                    "ANDROID_NATIVE_PATCH_LIVE_PACKAGE": "com.fixture.app",
                    "ANDROID_NATIVE_PATCH_LIVE_KEYSTORE": "fixture.keystore",
                    "ANDROID_NATIVE_PATCH_LIVE_KS_PASS": "secret",
                }, runner=runner,
            )
            self.assertTrue(record["live_verified"], record)
            self.assertEqual(verify_acceptance_record(record["record_path"])["status"], "ok")

    def test_jadx_fixture_promotes_only_with_retained_live_proof(self) -> None:
        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
            (run_dir / "android" / "jadx" / "fixture" / "Main.java").parent.mkdir(
                parents=True
            )
            (run_dir / "android" / "jadx" / "fixture" / "Main.java").write_text(
                "package fixture; class Main {}\n", encoding="utf-8"
            )
            _write_json(
                run_dir / "android" / "java_decompilation.json",
                {
                    "status": "passed",
                    "provider": "jadx",
                    "dependency": {
                        "state": "available",
                        "probe": {"status": "passed", "version": "jadx 1.0"},
                    },
                    "output": {"source_file_count": 1},
                    "target": {"unchanged": True},
                },
            )
            evidence = run_dir / "android-jadx"
            _write_json(
                evidence / "target-identity.json",
                {"kind": "apk_fixture", "sample_sha256": "a" * 64},
            )
            _write_json(
                evidence / "input-integrity.json",
                {"status": "ok", "verified": True, "unchanged": True},
            )
            _write_json(
                evidence / "toolchain.json",
                {"status": "ok", "provider": "jadx", "source_file_count": 1},
            )
            _write_json(
                evidence / "execution-proof.json",
                {
                    "status": "ok",
                    "provider": "jadx-subprocess",
                    "evidence_class": "live_host_proof",
                    "executed_tests": 1,
                    "skipped_tests": 0,
                    "live_operations": 1,
                },
            )
            return subprocess.CompletedProcess(command, 0, stdout="jadx ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-jadx-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-jadx-live",
                temporary,
                execute=True,
                environ={"ANDROID_JADX_LIVE_APK": "fixture.apk"},
                runner=runner,
            )

            self.assertTrue(record["live_verified"], record)
            self.assertEqual(record["missing_artifacts"], [])
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "ok")
            self.assertTrue(verification["live_verified"])

    def test_rebuild_fixture_requires_signed_artifact_and_verified_rollback(self) -> None:
        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
            evidence = run_dir / "android-rebuild"
            retained = evidence / "retained" / "fixture-signed.apk"
            retained.parent.mkdir(parents=True)
            retained.write_bytes(b"PK\x03\x04signed-apk-fixture")
            _write_json(
                evidence / "provider" / "rebuild_verify.json",
                {
                    "status": "ok",
                    "provider": "android-rebuild",
                    "signing": {"status": "ok", "verified": True},
                },
            )
            _write_json(
                evidence / "provider" / "rebuild_audit.json",
                {"status": "ok", "provider": "android-rebuild"},
            )
            _write_json(
                evidence / "retained-artifact.json",
                {"status": "ok", "signature_verified": True, "sha256": "b" * 64},
            )
            _write_json(
                evidence / "target-identity.json",
                {"kind": "apk_fixture", "sample_sha256": "a" * 64},
            )
            _write_json(
                evidence / "rollback.json",
                {"status": "ok", "verified": True, "restored": True},
            )
            _write_json(
                evidence / "execution-proof.json",
                {
                    "status": "ok",
                    "provider": "android-rebuild",
                    "evidence_class": "live_host_proof",
                    "executed_tests": 1,
                    "skipped_tests": 0,
                    "live_operations": 3,
                    "signature_verified": True,
                    "rollback_verified": True,
                },
            )
            return subprocess.CompletedProcess(command, 0, stdout="rebuild ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-rebuild-sign-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-rebuild-sign-live",
                temporary,
                execute=True,
                environ={
                    "ANDROID_REBUILD_LIVE_APK": "fixture.apk",
                    "ANDROID_REBUILD_LIVE_KEYSTORE": "fixture.keystore",
                    "ANDROID_REBUILD_LIVE_KS_PASS": "fixture-secret",
                },
                runner=runner,
            )

            self.assertTrue(record["live_verified"], record)
            self.assertTrue(record["rollback_result"]["verified"])
            self.assertTrue(record["cleanup_result"]["verified"])
            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "ok")
            self.assertTrue(verification["live_verified"])

    def test_live_record_reverification_rejects_tampered_rollback_proof(self) -> None:
        """A valid hash list must not turn a failed Android rollback into proof."""

        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            run_dir = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"])
            evidence = run_dir / "android-rebuild"
            retained = evidence / "retained" / "fixture-signed.apk"
            retained.parent.mkdir(parents=True)
            retained.write_bytes(b"signed-patched-fixture")
            _write_json(evidence / "provider" / "rebuild_verify.json", {"status": "ok", "verified": True})
            _write_json(evidence / "provider" / "rebuild_audit.json", {"status": "ok"})
            _write_json(evidence / "retained-artifact.json", {"status": "ok", "signature_verified": True})
            _write_json(evidence / "target-identity.json", {"kind": "apk_fixture", "sample_sha256": "a" * 64})
            _write_json(evidence / "rollback.json", {"status": "ok", "verified": True, "restored": True})
            _write_json(evidence / "execution-proof.json", {
                "status": "ok", "provider": "android-rebuild", "evidence_class": "live_host_proof",
                "executed_tests": 1, "skipped_tests": 0, "live_operations": 2,
            })
            return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-rebuild-sign-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-rebuild-sign-live", temporary, execute=True,
                environ={"ANDROID_REBUILD_LIVE_APK": "fixture.apk"}, runner=runner,
            )
            self.assertTrue(record["live_verified"], record)
            rollback = Path(record["run_directory"]) / "android-rebuild" / "rollback.json"
            # A generic successful status and self-asserted verification do
            # not prove that the original APK was restored.
            rollback.write_text(
                json.dumps({"status": "ok", "verified": True, "restored": False}),
                encoding="utf-8",
            )
            for entry in record["observed_artifacts"]:
                if entry["path"] == "android-rebuild/rollback.json":
                    entry["size"] = rollback.stat().st_size
                    entry["sha256"] = hashlib.sha256(rollback.read_bytes()).hexdigest()
            Path(record["record_path"]).write_text(json.dumps(record), encoding="utf-8")

            verification = verify_acceptance_record(record["record_path"])
            self.assertEqual(verification["status"], "failed")
            self.assertIn("rollback proof is missing or unverified", verification["errors"])

    def test_native_patch_fixture_rejects_missing_device_cleanup_proof(self) -> None:
        def runner(command, **kwargs):  # type: ignore[no-untyped-def]
            root = Path(kwargs["env"]["REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR"]) / "android-native-patch"
            for name in ("native-patch-plan.json", "native-patch-verify.json"):
                _write_json(root / "provider" / name, {"status": "ok", "verified": True})
            (root / "retained").mkdir(parents=True)
            (root / "retained" / "patched-signed.apk").write_bytes(b"signed-patched-fixture")
            _write_json(root / "provider" / "rollback.json", {"status": "ok", "verified": True})
            _write_json(root / "target-identity.json", {"kind": "apk_fixture", "package_name": "com.fixture.app", "sample_sha256": "a" * 64})
            _write_json(root / "deployment.json", {"status": "ok", "install_verified": True, "launch_verified": True})
            _write_json(
                root / "rollback.json",
                {"status": "ok", "verified": True, "restored": True, "device_cleanup_verified": False},
            )
            _write_json(root / "execution-proof.json", {
                "status": "ok", "provider": "local_android_native_patch+adb", "evidence_class": "live_target_proof",
                "executed_tests": 1, "skipped_tests": 0, "live_operations": 8,
            })
            return subprocess.CompletedProcess(command, 0, stdout="native patch ok", stderr="")

        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "reverse_analyzer.acceptance.validate_external_environment",
            return_value=_ready_report("p5-android-native-patch-live"),
        ):
            record = run_acceptance_fixture(
                "p5-android-native-patch-live",
                temporary,
                execute=True,
                environ={
                    "ANDROID_NATIVE_PATCH_LIVE_APK": "fixture.apk",
                    "ANDROID_NATIVE_PATCH_LIVE_SPEC": "fixture.json",
                    "ANDROID_NATIVE_PATCH_LIVE_PACKAGE": "com.fixture.app",
                    "ANDROID_NATIVE_PATCH_LIVE_KEYSTORE": "fixture.keystore",
                    "ANDROID_NATIVE_PATCH_LIVE_KS_PASS": "secret",
                },
                runner=runner,
            )

            self.assertFalse(record["live_verified"])
            self.assertFalse(record["rollback_result"]["verified"])


if __name__ == "__main__":
    unittest.main()
