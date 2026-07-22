"""Opt-in retained acceptance for a signed native APK patch on a test device."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.android_native_patch import AndroidNativePatchProvider


_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_PATCH_KEYS = {
    "abi",
    "library_path",
    "virtual_address",
    "relative_virtual_address",
    "rva",
    "file_offset",
    "expected",
    "replacement",
    "instruction_mode",
    "operation_id",
    "intent",
    "limits",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(command: list[str], *, timeout: float = 180.0) -> dict[str, object]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return {
        "command": [
            Path(command[0]).name,
            *(
                Path(value).name
                if Path(value).is_absolute()
                else ("<secret>" if value.startswith("--ks-pass=") else value)
                for value in command[1:]
            ),
        ],
        "returncode": completed.returncode,
        "stdout": completed.stdout[-8192:],
        "stderr": completed.stderr[-8192:],
        "ok": completed.returncode == 0,
    }


def _adb_fixture_preflight(
    adb_prefix: list[str],
    package: str,
    *,
    runner=_run,
) -> tuple[str, list[dict[str, object]]]:
    device_state = runner([*adb_prefix, "get-state"], timeout=60)
    if not (device_state["ok"] and str(device_state["stdout"]).strip() == "device"):
        raise RuntimeError("ADB target is not online")
    observed_serial = runner([*adb_prefix, "get-serialno"], timeout=60)
    observed_serial_value = str(observed_serial["stdout"]).strip()
    if not (observed_serial["ok"] and observed_serial_value not in {"", "unknown"}):
        raise RuntimeError("ADB target did not report a stable serial")
    installed_before = runner(
        [*adb_prefix, "shell", "pm", "path", package], timeout=60
    )
    if not installed_before["ok"]:
        raise RuntimeError("ADB package baseline query failed")
    if str(installed_before["stdout"]).strip():
        raise RuntimeError(
            "fixture package is already installed; use a clean test-device baseline"
        )
    return observed_serial_value, [
        {"step": "device_state", **device_state},
        {"step": "device_serial", **observed_serial},
        {"step": "package_absent_precondition", **installed_before},
    ]


@unittest.skipUnless(
    os.environ.get("RUN_ANDROID_NATIVE_PATCH_LIVE") == "1",
    "set RUN_ANDROID_NATIVE_PATCH_LIVE=1 to run native patch acceptance",
)
class AndroidNativePatchLiveTests(unittest.TestCase):
    def test_patch_sign_deploy_launch_and_rollback(self) -> None:
        source = Path(os.environ.get("ANDROID_NATIVE_PATCH_LIVE_APK", "")).expanduser().resolve()
        spec_path = Path(os.environ.get("ANDROID_NATIVE_PATCH_LIVE_SPEC", "")).expanduser().resolve()
        keystore = Path(os.environ.get("ANDROID_NATIVE_PATCH_LIVE_KEYSTORE", "")).expanduser().resolve()
        package = os.environ.get("ANDROID_NATIVE_PATCH_LIVE_PACKAGE", "").strip()
        password = os.environ.get("ANDROID_NATIVE_PATCH_LIVE_KS_PASS", "")
        if not source.is_file() or not spec_path.is_file() or not keystore.is_file() or not password:
            self.skipTest("APK, patch spec, keystore and keystore password must be configured")
        self.assertRegex(package, _PACKAGE_RE)

        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        self.assertIsInstance(spec, dict)
        unknown = sorted(set(spec) - _PATCH_KEYS)
        self.assertEqual(unknown, [], f"unsupported patch spec keys: {unknown}")
        self.assertIn("expected", spec)
        self.assertIn("replacement", spec)

        apksigner = os.environ.get("ANDROID_NATIVE_PATCH_LIVE_APKSIGNER", "") or os.environ.get("APKSIGNER_PATH", "") or shutil.which("apksigner")
        adb = os.environ.get("ANDROID_NATIVE_PATCH_LIVE_ADB", "") or os.environ.get("ADB_PATH", "") or shutil.which("adb")
        if not apksigner or not adb:
            self.skipTest("apksigner and adb must be available")
        serial = os.environ.get("ANDROID_NATIVE_PATCH_LIVE_DEVICE", "").strip()
        adb_prefix = [str(adb), "-s", serial] if serial else [str(adb)]

        try:
            observed_serial_value, preflight = _adb_fixture_preflight(
                adb_prefix, package
            )
        except RuntimeError as exc:
            self.fail(str(exc))

        acceptance_root = os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR", "")
        temporary = tempfile.TemporaryDirectory() if not acceptance_root else None
        root = Path(acceptance_root or temporary.name).expanduser().resolve()
        evidence = root / "android-native-patch"
        patched = evidence / "retained" / "patched-signed.apk"
        source_hash = _sha256(source)
        provider = AndroidNativePatchProvider()
        deployment: list[dict[str, object]] = preflight
        device_mutated = False
        try:
            params = {
                **spec,
                "sign": True,
                "signing": {
                    "keystore": str(keystore),
                    "key_alias": os.environ.get("ANDROID_NATIVE_PATCH_LIVE_KEY_ALIAS", ""),
                    "ks_pass": password,
                    "key_pass": os.environ.get("ANDROID_NATIVE_PATCH_LIVE_KEY_PASS", ""),
                },
                "apksigner": str(apksigner),
                "out_path": str(patched),
                "artifact_dir": str(evidence / "provider"),
                "rollback_out_path": str(evidence / "retained" / "restored.apk"),
                "rollback_artifact_dir": str(evidence / "rollback-provider"),
            }
            request = CapabilityRequest(
                capability="android_native_patch",
                action="apply",
                target=TargetIdentity(kind="apk_fixture", path=str(source), sha256=source_hash),
                params=params,
                session_id="android-native-patch-live",
                provenance={"fixture": "p5-android-native-patch-live"},
            )
            plan = provider.plan(request)
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = provider.execute(plan)
            self.assertEqual(result.status, "ok", result.to_dict())
            self.assertTrue(patched.is_file())

            signature = _run([str(apksigner), "verify", "--verbose", "--print-certs", str(patched)])
            deployment.append({"step": "verify_patched_signature", **signature})
            self.assertTrue(signature["ok"], signature)

            device_mutated = True
            install = _run([*adb_prefix, "install", "-r", str(patched)])
            deployment.append({"step": "install_patched", **install})
            self.assertTrue(install["ok"], install)
            activity = os.environ.get("ANDROID_NATIVE_PATCH_LIVE_ACTIVITY", "").strip()
            launch_command = (
                [*adb_prefix, "shell", "am", "start", "-W", "-n", f"{package}/{activity}"]
                if activity
                else [*adb_prefix, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"]
            )
            launch = _run(launch_command)
            deployment.append({"step": "launch_patched", **launch})
            self.assertTrue(launch["ok"], launch)
            process = _run([*adb_prefix, "shell", "pidof", package])
            deployment.append({"step": "verify_patched_process", **process})
            self.assertTrue(process["ok"] and process["stdout"].strip(), process)

            uninstall = _run([*adb_prefix, "uninstall", package])
            deployment.append({"step": "uninstall_patched", **uninstall})
            self.assertTrue(uninstall["ok"], uninstall)

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok, rollback.to_dict())
            restored = Path(str(rollback.details["restored_path"]))
            self.assertTrue(restored.is_file())
            self.assertEqual(_sha256(restored), source_hash)

            restore_install = _run([*adb_prefix, "install", "-r", str(restored)])
            deployment.append({"step": "install_restored", **restore_install})
            self.assertTrue(restore_install["ok"], restore_install)
            restore_launch = _run(launch_command)
            deployment.append({"step": "launch_restored", **restore_launch})
            self.assertTrue(restore_launch["ok"], restore_launch)
            restored_process = _run([*adb_prefix, "shell", "pidof", package])
            deployment.append({"step": "verify_restored_process", **restored_process})
            self.assertTrue(
                restored_process["ok"] and restored_process["stdout"].strip(),
                restored_process,
            )
            final_uninstall = _run([*adb_prefix, "uninstall", package])
            deployment.append({"step": "uninstall_restored", **final_uninstall})
            self.assertTrue(final_uninstall["ok"], final_uninstall)

            self.assertEqual(_sha256(source), source_hash)
            provider.collect_artifacts(result, str(evidence))
            _write_json(
                evidence / "target-identity.json",
                {
                    "kind": "apk_fixture",
                    "package_name": package,
                    "sample_sha256": source_hash,
                    "device_serial": observed_serial_value,
                    "requested_device": serial or "default",
                    "package_absent_before": True,
                },
            )
            _write_json(evidence / "deployment.json", {"status": "ok", "operations": deployment})
            _write_json(
                evidence / "rollback.json",
                {
                    "status": "ok",
                    "verified": True,
                    "restored": True,
                    "restored_sha256": _sha256(restored),
                    "source_unchanged": True,
                    "device_cleanup_verified": bool(final_uninstall["ok"]),
                },
            )
            _write_json(
                evidence / "execution-proof.json",
                {
                    "schema_version": 1,
                    "status": "ok",
                    "provider": "local_android_native_patch+adb",
                    "evidence_class": "live_target_proof",
                    "executed_tests": 1,
                    "skipped_tests": 0,
                    "live_operations": len(deployment) + 2,
                    "signature_verified": True,
                    "install_verified": True,
                    "launch_verified": True,
                    "rollback_verified": True,
                },
            )
            retained_text = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in evidence.rglob("*.json")
            )
            for secret in (
                password,
                os.environ.get("ANDROID_NATIVE_PATCH_LIVE_KEY_PASS", ""),
            ):
                if secret:
                    self.assertNotIn(secret, retained_text)
        finally:
            if adb and package and device_mutated:
                _run([*adb_prefix, "uninstall", package], timeout=60)
            if temporary is not None:
                temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
