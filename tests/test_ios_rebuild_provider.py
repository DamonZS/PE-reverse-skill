from __future__ import annotations

import hashlib
import json
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Sequence

from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.ios_rebuild import (
    IosRebuildProvider,
    LocalIosRebuildBackend,
)


APP_ROOT = "Payload/Sample.app"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_ipa(path: Path, *, unsafe_member: str | None = None) -> Path:
    info = plistlib.dumps(
        {
            "CFBundleExecutable": "Sample",
            "CFBundleIdentifier": "com.example.rebuild",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{APP_ROOT}/Info.plist", info)
        archive.writestr(f"{APP_ROOT}/Sample", b"\xcf\xfa\xed\xfe" + b"\0" * 64)
        archive.writestr(f"{APP_ROOT}/asset.txt", b"fixture")
        if unsafe_member:
            archive.writestr(unsafe_member, b"escape")
    return path


class MissingToolsRunner:
    production = True

    def which(self, command: str) -> None:
        del command
        return None

    def run(self, command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
        raise AssertionError(f"unavailable command must not run: {command}, {kwargs}")


class ClaimedProductionRunner:
    """Signing command recorder that must never qualify as production."""

    production = True

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def which(self, command: str) -> str:
        return f"/usr/bin/{command}"

    def run(self, command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
        del kwargs
        self.calls.append([str(item) for item in command])
        return {"returncode": 0, "stdout": "fixture", "stderr": ""}


class IosRebuildProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ipa = _write_ipa(self.root / "sample.ipa")
        self.source_hash = _sha256(self.ipa)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(
        self,
        action: str,
        *,
        params: dict[str, Any] | None = None,
        path: Path | None = None,
        sha256: str | None = None,
    ) -> CapabilityRequest:
        target = path or self.ipa
        return CapabilityRequest(
            capability="ios_rebuild",
            action=action,
            target=TargetIdentity(
                kind="sample",
                path=str(target),
                sha256=self.source_hash if sha256 is None else sha256,
            ),
            params=params or {},
            session_id=f"ios-{action}",
            provenance={"test_case": self.id()},
        )

    def test_supports_only_declared_actions(self) -> None:
        provider = IosRebuildProvider()
        for action in ("unpack", "resign", "verify"):
            self.assertTrue(provider.supports(self.request(action)))
        for action in ("rebuild", "sign", "install", ""):
            self.assertFalse(provider.supports(self.request(action)))
        self.assertEqual(provider.supported_actions, ("unpack", "resign", "verify"))

    def test_unpack_is_transactional_audited_and_rollback_restores_output(self) -> None:
        output = self.root / "unpacked"
        output.mkdir()
        (output / "previous.txt").write_text("previous", encoding="utf-8")
        previous_tree_hash = LocalIosRebuildBackend().snapshot(output)["sha256"]
        provider = IosRebuildProvider()
        plan = provider.plan(
            self.request(
                "unpack",
                params={
                    "unpack_dir": str(output),
                    "artifact_dir": str(self.root / "artifacts"),
                },
            )
        )

        validation = provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertTrue((output / "Payload" / "Sample.app" / "Info.plist").is_file())
        self.assertFalse((output / "previous.txt").exists())
        self.assertEqual(_sha256(self.ipa), self.source_hash)
        self.assertTrue(result.after_snapshot["destination"]["static_valid"])
        self.assertTrue(result.rollback_plan["supported"])
        self.assertEqual(result.rollback_plan["mode"], "restore_directory")
        self.assertGreaterEqual(len(result.evidence_manifest_entries), 3)

        audit_path = Path(plan.parameters["audit_path"])
        audit = json.loads(audit_path.read_text(encoding="utf-8"))
        contract = validate_capability_audit_record(audit)
        self.assertTrue(contract.ok, contract.errors)
        bundle = provider.collect_artifacts(result, str(self.root / "collected"))
        self.assertEqual(len(bundle.artifacts), len(result.artifacts))
        self.assertEqual(len(bundle.manifest_entries), len(result.evidence_manifest_entries))
        self.assertTrue(all(item.metadata["verified"] for item in bundle.artifacts))
        self.assertTrue(all(entry["verified"] for entry in bundle.manifest_entries))

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue((output / "previous.txt").is_file())
        self.assertEqual(
            LocalIosRebuildBackend().snapshot(output)["sha256"],
            previous_tree_hash,
        )
        self.assertEqual(_sha256(self.ipa), self.source_hash)

        repeated = provider.rollback(result)
        self.assertTrue(repeated.ok, repeated.details)
        self.assertTrue(repeated.restored)
        self.assertEqual(repeated.details["status"], "already_completed")

    def test_static_verify_is_read_only_and_emits_evidence(self) -> None:
        provider = IosRebuildProvider(platform_name="win32")
        plan = provider.plan(
            self.request(
                "verify",
                params={
                    "verify_signature": False,
                    "artifact_dir": str(self.root / "verify-artifacts"),
                },
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.report_section["verification"]["mode"], "static")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertFalse(result.rollback_plan["supported"])
        self.assertEqual(_sha256(self.ipa), self.source_hash)
        self.assertTrue(Path(plan.parameters["verify_path"]).is_file())
        self.assertTrue(Path(plan.parameters["audit_path"]).is_file())
        self.assertEqual(result.provenance["execution_assurance"], "offline_verified")
        self.assertTrue(result.provenance["production_evidence"])

    def test_resign_is_dependency_gated_without_macos_toolchain(self) -> None:
        output = self.root / "resigned.ipa"
        provider = IosRebuildProvider(
            runner=MissingToolsRunner(),
            platform_name="win32",
        )
        plan = provider.plan(
            self.request(
                "resign",
                params={
                    "identity": "Developer ID Application: Fixture",
                    "out_path": str(output),
                    "artifact_dir": str(self.root / "resign-artifacts"),
                },
            )
        )

        validation = provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        unavailable = {
            check["tool"]
            for check in validation.checks
            if check.get("required") and check.get("status") == "unavailable"
        }
        self.assertEqual(unavailable, {"xcrun", "codesign", "security"})

        result = provider.execute(plan)

        self.assertEqual(result.status, "unavailable")
        self.assertFalse(output.exists())
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(_sha256(self.ipa), self.source_hash)
        self.assertIn("requires macOS", result.report_section["error"])
        self.assertEqual(result.provenance["execution_assurance"], "dependency_gated")
        self.assertFalse(result.provenance["production_evidence"])

    def test_claimed_production_signing_runner_is_orchestration_only(self) -> None:
        runner = ClaimedProductionRunner()
        output = self.root / "simulated-resigned.ipa"
        provider = IosRebuildProvider(runner=runner, platform_name="darwin")
        plan = provider.plan(
            self.request(
                "resign",
                params={
                    "identity": "Fixture Identity",
                    "out_path": str(output),
                    "artifact_dir": str(self.root / "simulated-artifacts"),
                },
            )
        )

        validation = provider.validate(plan)
        boundary = next(
            check for check in validation.checks if check["name"] == "capability_boundary"
        )
        self.assertEqual(boundary["execution_assurance"], "orchestration_only")

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertTrue(output.is_file())
        self.assertTrue(runner.calls)
        self.assertEqual(result.provenance["execution_assurance"], "orchestration_only")
        self.assertFalse(result.provenance["production_parity"])
        self.assertFalse(result.provenance["production_evidence"])

    def test_validation_rejects_tampered_plan_contract(self) -> None:
        provider = IosRebuildProvider(platform_name="win32")
        plan = provider.plan(self.request("verify", params={"verify_signature": False}))
        plan.capability = "other"
        plan.parameters["action"] = "resign"

        validation = provider.validate(plan)

        self.assertFalse(validation.ok)
        self.assertIn("capability", " ".join(validation.errors))
        self.assertIn("action", " ".join(validation.errors))

    def test_unsafe_archive_member_is_rejected_without_filesystem_escape(self) -> None:
        unsafe = _write_ipa(self.root / "unsafe.ipa", unsafe_member="../escaped.txt")
        output = self.root / "unsafe-unpacked"
        provider = IosRebuildProvider()
        plan = provider.plan(
            self.request(
                "unpack",
                path=unsafe,
                sha256=_sha256(unsafe),
                params={
                    "unpack_dir": str(output),
                    "artifact_dir": str(self.root / "unsafe-artifacts"),
                },
            )
        )

        validation = provider.validate(plan)
        self.assertFalse(validation.ok)
        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertFalse(output.exists())
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertEqual(_sha256(unsafe), plan.precondition_hash)

    def test_repack_is_deterministic_for_same_unpacked_tree(self) -> None:
        backend = LocalIosRebuildBackend()
        unpacked = self.root / "tree"
        backend.extract_ipa(self.ipa, unpacked)
        first = self.root / "first.ipa"
        second = self.root / "second.ipa"

        backend.repack_ipa(unpacked, first)
        backend.repack_ipa(unpacked, second)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertTrue(backend.inspect_ipa(first)["static_valid"])


if __name__ == "__main__":
    unittest.main()
