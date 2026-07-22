"""Opt-in Android P5 acceptance tests.

These tests require a real local JADX binary or a real Frida Android device.
They intentionally skip by default and never turn an unavailable dependency
into a passing result.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.android_instrumentation import AndroidInstrumentationProvider
from reverse_analyzer.tools.android import android_analyze


def _assert_redacted(test: unittest.TestCase, root: Path, *, forbidden: tuple[str, ...] = ()) -> None:
    payload = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file()
    )
    test.assertNotIn(str(root), payload)
    test.assertNotIn("Authorization", payload)
    test.assertNotIn("Bearer ", payload)
    for value in forbidden:
        if value:
            test.assertNotIn(value, payload)


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class AndroidP5JadxLiveTests(unittest.TestCase):
    def test_real_jadx_e2e(self) -> None:
        if os.getenv("RUN_ANDROID_JADX_LIVE") != "1":
            self.skipTest("set RUN_ANDROID_JADX_LIVE=1 to run real JADX acceptance")
        apk_value = os.getenv("ANDROID_JADX_LIVE_APK", "")
        apk = Path(apk_value).expanduser().resolve()
        if not apk.is_file():
            self.skipTest("ANDROID_JADX_LIVE_APK must point to a local APK fixture")
        acceptance_value = os.getenv("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR", "")
        out_value = acceptance_value or os.getenv("ANDROID_JADX_LIVE_OUT", "")
        temp = tempfile.TemporaryDirectory() if not out_value else None
        try:
            out = Path(out_value).expanduser().resolve() if out_value else Path(temp.name)
            out.mkdir(parents=True, exist_ok=True)
            before = hashlib.sha256(apk.read_bytes()).hexdigest()
            result = android_analyze(
                apk,
                out,
                config={
                    "java_decompilation": {
                        "enabled": True,
                        "executable": (
                            os.getenv("ANDROID_JADX_LIVE_JADX", "")
                            or os.getenv("JADX_PATH", "")
                            or None
                        ),
                        "timeout_seconds": float(os.getenv("ANDROID_JADX_LIVE_TIMEOUT", "600")),
                    }
                },
            )
            section = result["java_decompilation"]
            self.assertEqual(section["status"], "passed", section)
            self.assertEqual(section["dependency"]["state"], "available")
            self.assertEqual(section["dependency"]["probe"]["status"], "passed")
            self.assertTrue(section["dependency"]["probe"]["version"])
            self.assertGreater(section["output"]["source_file_count"], 0)
            self.assertTrue(section["target"]["unchanged"])
            self.assertEqual(hashlib.sha256(apk.read_bytes()).hexdigest(), before)
            for item in section["output"]["files"]:
                self.assertEqual(len(item["sha256"]), 64)
            if acceptance_value:
                evidence = out / "android-jadx"
                identity = {
                    "kind": "apk_fixture",
                    "sample_sha256": before,
                    "file_name": apk.name,
                    "size": apk.stat().st_size,
                }
                _write_json(evidence / "target-identity.json", identity)
                _write_json(
                    evidence / "input-integrity.json",
                    {
                        "status": "ok",
                        "verified": True,
                        "sha256_before": before,
                        "sha256_after": hashlib.sha256(apk.read_bytes()).hexdigest(),
                        "unchanged": True,
                    },
                )
                command = list(section.get("command") or [])
                _write_json(
                    evidence / "toolchain.json",
                    {
                        "status": "ok",
                        "provider": "jadx",
                        "dependency_state": section["dependency"]["state"],
                        "probe": section["dependency"]["probe"],
                        "executable": Path(command[0]).name if command else "jadx",
                        "returncode": section.get("returncode"),
                        "source_file_count": section["output"]["source_file_count"],
                    },
                )
                _write_json(
                    evidence / "execution-proof.json",
                    {
                        "schema_version": 1,
                        "status": "ok",
                        "provider": "jadx-subprocess",
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 1,
                        "sample_sha256": before,
                        "source_file_count": section["output"]["source_file_count"],
                    },
                )
            _assert_redacted(self, out)
        finally:
            if temp is not None:
                temp.cleanup()


class AndroidP5InstrumentationLiveTests(unittest.TestCase):
    def test_real_frida_device_e2e_and_cleanup(self) -> None:
        if os.getenv("RUN_ANDROID_FRIDA_LIVE") != "1":
            self.skipTest("set RUN_ANDROID_FRIDA_LIVE=1 to run real Frida acceptance")
        package = os.getenv("ANDROID_FRIDA_LIVE_PACKAGE", "")
        if not package:
            self.skipTest("ANDROID_FRIDA_LIVE_PACKAGE must identify a test package")
        device = os.getenv("ANDROID_FRIDA_LIVE_DEVICE", "usb")
        acceptance_value = os.getenv("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR", "")
        out_value = acceptance_value or os.getenv("ANDROID_FRIDA_LIVE_OUT", "")
        temp = tempfile.TemporaryDirectory() if not out_value else None
        try:
            out = Path(out_value).expanduser().resolve() if out_value else Path(temp.name)
            out.mkdir(parents=True, exist_ok=True)
            params = {
                "mode": os.getenv("ANDROID_FRIDA_LIVE_MODE", "spawn"),
                "device": device,
                "timeout_ms": int(os.getenv("ANDROID_FRIDA_LIVE_TIMEOUT_MS", "1000")),
                "max_messages": int(os.getenv("ANDROID_FRIDA_LIVE_MAX_MESSAGES", "16")),
                "hooks": [
                    {
                        "kind": "java",
                        "class": os.getenv("ANDROID_FRIDA_LIVE_CLASS", "android.app.Activity"),
                        "method": os.getenv("ANDROID_FRIDA_LIVE_METHOD", "onResume"),
                        "overload": [],
                        "label": "p5-live-canary",
                    }
                ],
            }
            target = TargetIdentity(kind="android_package", display_name=package)
            request = CapabilityRequest(
                capability="android_instrumentation",
                action=params["mode"],
                target=target,
                params=params,
                session_id="android-p5-live",
                provenance={"source": "opt-in-real-device-e2e"},
            )
            provider = AndroidInstrumentationProvider()
            plan = provider.plan(request)
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = provider.execute(plan)
            self.assertEqual(result.status, "ok", result.to_dict())
            cleanup = result.after_snapshot["cleanup"]
            device_identity = result.after_snapshot.get("device") or {}
            self.assertIsInstance(device_identity, dict)
            self.assertTrue(device_identity.get("id"), "Frida did not report a device ID")
            self.assertTrue(cleanup["ok"], cleanup)
            self.assertTrue(cleanup["unloaded"])
            self.assertTrue(cleanup["detached"])
            if params["mode"] == "spawn":
                self.assertTrue(cleanup["resume_completed"])
            bundle = provider.collect_artifacts(result, out)
            self.assertGreaterEqual(len(bundle.artifacts), 3)
            for artifact in bundle.artifacts:
                path = out / artifact.path
                self.assertTrue(path.is_file())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), artifact.metadata["sha256"])
                json.loads(path.read_text(encoding="utf-8"))
            if acceptance_value:
                evidence = out / "android-frida"
                _write_json(
                    evidence / "target-identity.json",
                    {
                        "kind": "android_package",
                        "package_name": package,
                        "device_selector": device,
                        "device_id": device_identity.get("id"),
                        "device_name": device_identity.get("name"),
                        "device_type": device_identity.get("type"),
                        "mode": params["mode"],
                    },
                )
                _write_json(
                    evidence / "cleanup.json",
                    {
                        "status": "ok" if cleanup["ok"] else "failed",
                        "verified": bool(cleanup["ok"]),
                        "resume_completed": bool(cleanup["resume_completed"]),
                        "unloaded": bool(cleanup["unloaded"]),
                        "detached": bool(cleanup["detached"]),
                    },
                )
                _write_json(
                    evidence / "execution-proof.json",
                    {
                        "schema_version": 1,
                        "status": "ok",
                        "provider": "frida-android",
                        "evidence_class": "live_target_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 4 if params["mode"] == "spawn" else 3,
                        "cleanup_verified": bool(cleanup["ok"]),
                    },
                )
            _assert_redacted(self, out)
        finally:
            if temp is not None:
                temp.cleanup()


if __name__ == "__main__":
    unittest.main()
