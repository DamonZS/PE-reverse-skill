from __future__ import annotations

import json
import hashlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.android_rebuild import AndroidRebuildProvider


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@unittest.skipUnless(
    os.environ.get("RUN_ANDROID_REBUILD_LIVE") == "1",
    "set RUN_ANDROID_REBUILD_LIVE=1 to run the local Android toolchain E2E",
)
class AndroidRebuildLiveTests(unittest.TestCase):
    def test_rebuild_sign_verify_and_rollback(self) -> None:
        source_value = os.environ.get("ANDROID_REBUILD_LIVE_APK", "")
        keystore_value = os.environ.get("ANDROID_REBUILD_LIVE_KEYSTORE", "")
        ks_pass = os.environ.get("ANDROID_REBUILD_LIVE_KS_PASS", "")
        source = Path(source_value).expanduser().resolve()
        keystore = Path(keystore_value).expanduser().resolve()
        if not source.is_file() or not keystore.is_file() or not ks_pass:
            self.skipTest(
                "ANDROID_REBUILD_LIVE_APK, ANDROID_REBUILD_LIVE_KEYSTORE and "
                "ANDROID_REBUILD_LIVE_KS_PASS must identify local fixture inputs"
            )

        acceptance_value = os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR", "")
        temporary = tempfile.TemporaryDirectory() if not acceptance_value else None
        try:
            root = Path(acceptance_value or temporary.name).expanduser().resolve()
            evidence = root / "android-rebuild" if acceptance_value else root
            output = evidence / "fixture-signed.apk"
            artifacts = evidence / "provider"
            source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            request = CapabilityRequest(
                capability="android_rebuild",
                action="rebuild",
                target=TargetIdentity(kind="apk_fixture", path=str(source)),
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(output),
                    "artifact_dir": str(artifacts),
                    "keystore": str(keystore),
                    "key_alias": os.environ.get("ANDROID_REBUILD_LIVE_KEY_ALIAS", ""),
                    "ks_pass": ks_pass,
                    "key_pass": os.environ.get("ANDROID_REBUILD_LIVE_KEY_PASS", ""),
                    "apktool_path": (
                        os.environ.get("ANDROID_REBUILD_LIVE_APKTOOL", "")
                        or os.environ.get("APKTOOL_PATH", "")
                        or "apktool"
                    ),
                    "apksigner_path": (
                        os.environ.get("ANDROID_REBUILD_LIVE_APKSIGNER", "")
                        or os.environ.get("APKSIGNER_PATH", "")
                        or "apksigner"
                    ),
                },
                session_id="android-rebuild-live",
                provenance={"fixture": "local-android-toolchain"},
            )
            provider = AndroidRebuildProvider(timeout=300)
            plan = provider.plan(request)
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)

            result = provider.execute(plan)
            self.assertEqual(result.status, "ok", result.to_dict())
            self.assertTrue(output.is_file())
            signing = result.report_section["signing"]
            self.assertEqual(signing["status"], "ok")
            self.assertTrue(signing["verified"])
            self.assertTrue(signing.get("verification_stdout"))

            audit_text = Path(plan.parameters["audit_path"]).read_text("utf-8")
            verify_payload = json.loads(
                Path(plan.parameters["verify_path"]).read_text("utf-8")
            )
            self.assertNotIn(ks_pass, audit_text)
            self.assertTrue(
                all(item.get("status") == "ok" for item in verify_payload["checks"])
            )
            self.assertTrue(
                any(
                    item.get("step") == "apksigner_verify" and item.get("ok")
                    for item in verify_payload["commands"]
                )
            )

            retained = evidence / "retained" / "fixture-signed.apk"
            retained.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(output, retained)
            retained_sha256 = hashlib.sha256(retained.read_bytes()).hexdigest()
            self.assertEqual(retained_sha256, result.report_section["output_sha256"])

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok, rollback.to_dict())
            self.assertFalse(output.exists())
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_sha256)

            if acceptance_value:
                _write_json(
                    evidence / "target-identity.json",
                    {
                        "kind": "apk_fixture",
                        "sample_sha256": source_sha256,
                        "file_name": source.name,
                        "size": source.stat().st_size,
                    },
                )
                _write_json(
                    evidence / "retained-artifact.json",
                    {
                        "status": "ok",
                        "path": "android-rebuild/retained/fixture-signed.apk",
                        "sha256": retained_sha256,
                        "size": retained.stat().st_size,
                        "signature_verified": True,
                    },
                )
                rollback_payload = {
                    "status": "ok",
                    "verified": True,
                    "restored": rollback.restored,
                    "output_removed": not output.exists(),
                    "source_unchanged": True,
                }
                _write_json(evidence / "rollback.json", rollback_payload)
                commands = verify_payload.get("commands") or []
                _write_json(
                    evidence / "execution-proof.json",
                    {
                        "schema_version": 1,
                        "status": "ok",
                        "provider": result.provider,
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": len(commands),
                        "command_steps": [item.get("step") for item in commands],
                        "signature_verified": True,
                        "rollback_verified": rollback.ok,
                        "sample_sha256": source_sha256,
                        "output_sha256": retained_sha256,
                    },
                )
                text_payload = "\n".join(
                    path.read_text(encoding="utf-8", errors="replace")
                    for path in evidence.rglob("*")
                    if path.is_file() and path.suffix.lower() in {".json", ".log", ".txt"}
                )
                self.assertNotIn(ks_pass, text_payload)
                key_pass = os.environ.get("ANDROID_REBUILD_LIVE_KEY_PASS", "")
                if key_pass:
                    self.assertNotIn(key_pass, text_payload)
        finally:
            if temporary is not None:
                temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
