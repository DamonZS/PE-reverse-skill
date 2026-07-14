from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
import zlib

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.android_rebuild import (
    AndroidRebuildProvider,
    LocalAndroidRebuildBackend,
)
from reverse_analyzer.tools.android import android_analyze


ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AndroidPipelineTests(unittest.TestCase):
    def test_static_unpack_verify_rebuild_and_rollback_audit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.apk"
            analysis_dir = root / "analysis"
            unpack_dir = root / "unpacked"
            rebuilt = root / "rebuilt.apk"
            _write_pipeline_apk(source)
            source_hash = _sha256(source)

            analysis = android_analyze(source, analysis_dir)

            self.assertEqual(analysis["status"], "ok", analysis["warnings"])
            self.assertEqual(analysis["manifest"]["package"], "com.example.pipeline")
            self.assertEqual(analysis["resources"]["layout_count"], 1)
            self.assertEqual(analysis["dex_summary"]["valid_count"], 1)
            self.assertEqual(analysis["native_libs"]["abis"], ["arm64-v8a"])
            self.assertEqual(analysis["framework"]["name"], "android_xml")
            self.assertEqual(len(analysis["artifacts"]), 7)
            self.assertTrue(all(Path(item["path"]).is_file() for item in analysis["artifacts"]))

            provider = AndroidRebuildProvider()
            unpack_plan = provider.plan(
                _request(
                    source,
                    source_hash,
                    "unpack",
                    "pipeline-unpack",
                    {
                        "unpack_dir": str(unpack_dir),
                        "artifact_dir": str(root / "audit" / "unpack"),
                    },
                )
            )
            verify_plan = provider.plan(
                _request(
                    source,
                    source_hash,
                    "verify",
                    "pipeline-verify",
                    {"artifact_dir": str(root / "audit" / "verify")},
                )
            )
            rebuild_plan = provider.plan(
                _request(
                    source,
                    source_hash,
                    "rebuild",
                    "pipeline-rebuild",
                    {
                        "out_path": str(rebuilt),
                        "artifact_dir": str(root / "audit" / "rebuild"),
                    },
                )
            )

            unpack_result = provider.execute(unpack_plan)
            verify_result = provider.execute(verify_plan)
            rebuild_result = provider.execute(rebuild_plan)

            for plan, result in (
                (unpack_plan, unpack_result),
                (verify_plan, verify_result),
                (rebuild_plan, rebuild_result),
            ):
                with self.subTest(action=plan.action):
                    self.assertEqual(result.status, "ok")
                    _assert_audit_contract(self, provider, plan, result)

            self.assertTrue((unpack_dir / "AndroidManifest.xml").is_file())
            self.assertEqual(rebuilt.read_bytes(), source.read_bytes())
            self.assertEqual(_sha256(source), source_hash)

            verify_rollback = provider.rollback(verify_result)
            rebuild_rollback = provider.rollback(rebuild_result)
            unpack_rollback = provider.rollback(unpack_result)

            self.assertTrue(verify_rollback.ok)
            self.assertFalse(verify_rollback.restored)
            self.assertTrue(rebuild_rollback.restored)
            self.assertTrue(unpack_rollback.restored)
            self.assertFalse(rebuilt.exists())
            self.assertFalse(unpack_dir.exists())
            self.assertEqual(_sha256(source), source_hash)
            _assert_manifest_hashes(self, provider.backend, rebuild_result)
            _assert_manifest_hashes(self, provider.backend, unpack_result)


def _request(
    source: Path,
    source_hash: str,
    action: str,
    session_id: str,
    params: dict[str, str],
) -> CapabilityRequest:
    return CapabilityRequest(
        capability="android_rebuild",
        action=action,
        target=TargetIdentity(
            kind="apk",
            path=str(source),
            sha256=source_hash,
            display_name=source.name,
        ),
        params=params,
        session_id=session_id,
        provenance={"pipeline_test": True},
    )


def _assert_audit_contract(
    case: unittest.TestCase,
    provider: AndroidRebuildProvider,
    plan: object,
    result: object,
) -> None:
    validation = provider.validate(plan)
    record = CapabilityAuditBuilder().build_record(
        plan=plan,
        result=result,
        validation=validation,
    )
    contract = validate_capability_audit_record(record)
    case.assertTrue(contract.ok, contract.errors)
    case.assertEqual(result.session_id, plan.session_id)
    case.assertEqual(result.target.path, plan.target.path)
    case.assertEqual(result.provenance["precondition_hash"], plan.precondition_hash)
    case.assertTrue(result.before_snapshot)
    case.assertIn("side_effects", result.after_snapshot)
    case.assertIn("supported", result.rollback_plan)
    case.assertTrue(result.provenance)
    case.assertTrue(result.evidence_manifest_entries)
    case.assertEqual(result.report_section["status"], result.status)
    case.assertTrue(result.dashboard_trace)
    case.assertEqual(result.dashboard_trace[0]["status"], result.status)

    audit_path = Path(plan.parameters["audit_path"])
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    case.assertEqual(audit["session_id"], plan.session_id)
    case.assertEqual(audit["plan"]["target"]["path"], plan.target.path)
    case.assertEqual(audit["plan"]["precondition_hash"], plan.precondition_hash)
    case.assertTrue(audit["before_snapshot"])
    case.assertIn("side_effects", audit["after_snapshot"])
    case.assertIn("supported", audit["rollback_plan"])
    case.assertTrue(audit["provenance"])

    bundle = provider.collect_artifacts(result, str(audit_path.parent))
    case.assertEqual(len(bundle.artifacts), len(result.artifacts))
    case.assertEqual(len(bundle.manifest_entries), len(result.evidence_manifest_entries))
    _assert_manifest_hashes(case, provider.backend, result)


def _assert_manifest_hashes(
    case: unittest.TestCase,
    backend: LocalAndroidRebuildBackend,
    result: object,
) -> None:
    artifact_paths = {artifact.path for artifact in result.artifacts}
    entry_paths = {str(entry["path"]) for entry in result.evidence_manifest_entries}
    case.assertEqual(entry_paths, artifact_paths)
    for entry in result.evidence_manifest_entries:
        snapshot = backend.snapshot(entry["path"])
        case.assertTrue(snapshot["exists"], entry)
        case.assertEqual(entry.get("sha256"), snapshot.get("sha256"), entry)


def _write_pipeline_apk(path: Path) -> None:
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.pipeline">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />
  <application android:label="Pipeline">
    <activity android:name=".MainActivity" android:exported="true" />
  </application>
</manifest>
""".encode("utf-8")
    layout = (
        f'<LinearLayout xmlns:android="{ANDROID_NS}" '
        'android:orientation="vertical"><TextView android:text="Pipeline" />'
        "</LinearLayout>"
    ).encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", _empty_valid_dex())
        archive.writestr("resources.arsc", b"arsc")
        archive.writestr("res/layout/activity_main.xml", layout)
        archive.writestr("res/drawable/icon.png", b"\x89PNG\r\n\x1a\n")
        archive.writestr("lib/arm64-v8a/libpipeline.so", _minimal_elf64())


def _empty_valid_dex() -> bytes:
    dex = bytearray(112)
    dex[:8] = b"dex\n035\x00"
    dex[12:32] = b"\x11" * 20
    struct.pack_into("<I", dex, 32, len(dex))
    struct.pack_into("<I", dex, 36, 112)
    struct.pack_into("<I", dex, 40, 0x12345678)
    struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]) & 0xFFFFFFFF)
    return bytes(dex)


def _minimal_elf64() -> bytes:
    elf = bytearray(64)
    elf[:4] = b"\x7fELF"
    elf[4] = 2
    elf[5] = 1
    elf[6] = 1
    struct.pack_into("<H", elf, 16, 3)
    struct.pack_into("<H", elf, 18, 183)
    struct.pack_into("<I", elf, 20, 1)
    struct.pack_into("<H", elf, 52, 64)
    struct.pack_into("<H", elf, 58, 64)
    return bytes(elf)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
