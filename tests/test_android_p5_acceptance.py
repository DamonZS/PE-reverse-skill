from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reverse_analyzer.acceptance import run_acceptance_fixture, verify_acceptance_record


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
            _write_json(evidence / "target-identity.json", {"kind": "android_package", "package_name": "com.fixture.app"})
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
                    "dependency": {"state": "available"},
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


if __name__ == "__main__":
    unittest.main()
