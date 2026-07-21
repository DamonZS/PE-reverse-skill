from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence
from unittest import mock

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import android_rebuild as android_rebuild_module
from reverse_analyzer.providers.android_rebuild import (
    AndroidRebuildMockProvider,
    AndroidRebuildProvider,
    LocalAndroidRebuildBackend,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_apk(
    path: Path,
    *,
    manifest: bool = True,
    entries: dict[str, bytes] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        if manifest:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
        archive.writestr("classes.dex", b"dex\n035\0")
        for name, payload in (entries or {}).items():
            archive.writestr(name, payload)
    return path


class MissingToolsRunner:
    def which(self, command: str) -> None:
        del command
        return None

    def run(self, command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
        raise AssertionError(f"unavailable command must not execute: {command}, {kwargs}")


class FakeAndroidRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def which(self, command: str) -> str:
        return command

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        del cwd, timeout
        args = [str(item) for item in command]
        self.calls.append(args)
        tool = Path(args[0]).name.lower()
        if "apktool" in tool and args[1] == "d":
            source = Path(args[args.index("-f") + 1])
            destination = Path(args[args.index("-o") + 1])
            with zipfile.ZipFile(source) as archive:
                archive.extractall(destination)
        elif "apktool" in tool and args[1] == "b":
            output = Path(args[args.index("-o") + 1])
            _write_apk(output, entries={"res/raw/rebuilt.txt": b"rebuilt"})
        elif "apksigner" in tool and args[1] == "sign":
            output = Path(args[args.index("--out") + 1])
            shutil.copyfile(Path(args[-1]), output)
        return {"returncode": 0, "stdout": "verified", "stderr": ""}


class NoneResultRunner:
    def which(self, command: str) -> str:
        return command

    def run(self, command: Sequence[str], **kwargs: Any) -> None:
        del command, kwargs
        return None


class NoOutputRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def which(self, command: str) -> str:
        return command

    def run(self, command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
        del kwargs
        self.calls.append([str(item) for item in command])
        return {"returncode": 0, "stdout": "ok", "stderr": ""}


class OpaqueRunner:
    def run(self, command: Sequence[str], **kwargs: Any) -> dict[str, Any]:
        raise AssertionError(f"runner without an availability probe must not execute: {command}, {kwargs}")


class CountingBackend(LocalAndroidRebuildBackend):
    def __init__(self) -> None:
        self.copy_count = 0
        self.inspect_count = 0

    def copy_file(self, source: str | Path, destination: str | Path) -> None:
        self.copy_count += 1
        super().copy_file(source, destination)

    def inspect_apk(self, path: str | Path) -> dict[str, Any]:
        self.inspect_count += 1
        return super().inspect_apk(path)


class FailingAuditBackend(LocalAndroidRebuildBackend):
    def __init__(self, failed_name: str) -> None:
        self.failed_name = failed_name

    def write_json(self, path: str | Path, payload: Mapping[str, Any]) -> None:
        if Path(path).name == self.failed_name:
            raise OSError("injected audit write failure")
        super().write_json(path, payload)


class FailingJsonBackend(LocalAndroidRebuildBackend):
    def write_json(self, path: str | Path, payload: Mapping[str, Any]) -> None:
        del path, payload
        raise OSError("all JSON writes are blocked")


class AndroidRebuildProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.apk = _write_apk(
            self.root / "sample.apk",
            entries={"assets/config.json": b"{}"},
        )
        self.source_hash = _sha256(self.apk)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(
        self,
        action: str,
        *,
        params: dict[str, Any] | None = None,
        path: Path | None = None,
        sha256: str | None = None,
        session_id: str | None = None,
    ) -> CapabilityRequest:
        target_path = path or self.apk
        return CapabilityRequest(
            capability="android_rebuild",
            action=action,
            target=TargetIdentity(
                kind="sample",
                path=str(target_path),
                sha256=self.source_hash if sha256 is None else sha256,
            ),
            params=params or {},
            session_id=session_id or f"test-{action}",
            provenance={"test_case": self.id()},
        )

    def test_supports_only_unpack_rebuild_and_verify(self) -> None:
        provider = AndroidRebuildProvider()
        for action in ("unpack", "rebuild", "verify"):
            self.assertTrue(provider.supports(self.request(action)))
        for action in ("analyze", "build", "repack", "zip_copy", ""):
            self.assertFalse(provider.supports(self.request(action)))
        wrong_capability = self.request("verify")
        wrong_capability.capability = "static_analysis"
        self.assertFalse(provider.supports(wrong_capability))
        self.assertEqual(provider.supported_actions, ("unpack", "rebuild", "verify"))
        self.assertIn("unpack_dir", provider.parameter_contract["unpack"])
        self.assertIn("out_path", provider.parameter_contract["rebuild"])
        self.assertIn("verify_signature", provider.parameter_contract["verify"])

    def test_zip_copy_rebuild_verifies_artifacts_and_rolls_back(self) -> None:
        output = self.root / "rebuilt.apk"
        provider = AndroidRebuildProvider()
        plan = provider.plan(
            self.request("rebuild", params={"strategy": "zip_copy", "out_path": str(output)})
        )

        validation = provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(output.read_bytes(), self.apk.read_bytes())
        self.assertEqual(result.before_snapshot["source_sha256"], self.source_hash)
        self.assertEqual(result.after_snapshot["source_sha256"], self.source_hash)
        self.assertEqual(result.after_snapshot["output_sha256"], self.source_hash)
        self.assertTrue(result.after_snapshot["zip_integrity"])
        self.assertTrue(result.after_snapshot["manifest_present"])
        roles = {artifact.metadata.get("role") for artifact in result.artifacts}
        self.assertEqual(roles, {"rebuilt-apk", "rebuild-verification", "rebuild-audit"})
        verify_payload = json.loads(Path(plan.parameters["verify_path"]).read_text("utf-8"))
        self.assertEqual(verify_payload["status"], "ok")
        self.assertEqual(verify_payload["source"]["sha256"], self.source_hash)
        self.assertEqual(verify_payload["output"]["sha256"], self.source_hash)
        self.assertTrue(result.provenance["source_sha256"])
        bundle = provider.collect_artifacts(result, str(self.root / "collected"))
        self.assertEqual(len(bundle.artifacts), 3)
        self.assertEqual(len(bundle.manifest_entries), 3)

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)
        self.assertFalse(output.exists())
        self.assertEqual(_sha256(self.apk), self.source_hash)
        self.assertEqual(len(provider.collect_artifacts(result, str(self.root)).artifacts), 2)
        for entry in result.evidence_manifest_entries:
            artifact_path = Path(entry["path"])
            self.assertEqual(entry["sha256"], _sha256(artifact_path))

    def test_capability_boundaries_distinguish_builtin_external_and_unavailable(self) -> None:
        builtin = AndroidRebuildProvider()
        builtin_plan = builtin.plan(
            self.request(
                "rebuild",
                params={"out_path": str(self.root / "builtin.apk")},
                session_id="boundary-builtin",
            )
        )
        builtin_boundary = builtin_plan.parameters["capability_boundary"]
        self.assertEqual(builtin_boundary["provider_kind"], "builtin")
        self.assertEqual(builtin_boundary["operation_kind"], "byte_preserving_copy")
        self.assertEqual(builtin_boundary["dependency_state"], "not_required")
        self.assertEqual(builtin_boundary["required_tools"], [])
        self.assertFalse(builtin_boundary["content_recompiled"])
        self.assertTrue(builtin_boundary["byte_preserving"])
        self.assertEqual(
            builtin_plan.provenance["capability_boundary"], builtin_boundary
        )

        external = AndroidRebuildProvider(runner=MissingToolsRunner())
        external_plan = external.plan(
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(self.root / "external.apk"),
                },
                session_id="boundary-external",
            )
        )
        planned_boundary = external_plan.parameters["capability_boundary"]
        self.assertEqual(planned_boundary["provider_kind"], "external_toolchain")
        self.assertEqual(planned_boundary["operation_kind"], "apktool_build_sign_verify")
        self.assertEqual(planned_boundary["dependency_state"], "required")
        self.assertEqual(planned_boundary["required_tools"], ["apktool", "apksigner"])
        validation = external.validate(external_plan)
        validation_boundary = next(
            check for check in validation.checks if check["name"] == "capability_boundary"
        )
        self.assertEqual(validation_boundary["dependency_state"], "unavailable")

        result = external.execute(external_plan)
        self.assertEqual(result.status, "unavailable")
        for payload in (
            result.provenance,
            result.report_section,
            result.dashboard_trace[0],
        ):
            self.assertEqual(
                payload["capability_boundary"]["dependency_state"], "unavailable"
            )

    def test_rebuild_rollback_restores_existing_output(self) -> None:
        output = self.root / "existing.apk"
        original_output = b"prior-output"
        output.write_bytes(original_output)
        provider = AndroidRebuildProvider()
        plan = provider.plan(self.request("rebuild", params={"out_path": str(output)}))
        result = provider.execute(plan)
        self.assertEqual(result.status, "ok")
        self.assertNotEqual(output.read_bytes(), original_output)

        rollback = provider.rollback(result)
        self.assertTrue(rollback.restored)
        self.assertEqual(output.read_bytes(), original_output)

    def test_validation_rejects_invalid_apks_hash_and_source_overwrite(self) -> None:
        provider = AndroidRebuildProvider()
        non_zip = self.root / "not-zip.apk"
        non_zip.write_bytes(b"not a zip")
        missing_manifest = _write_apk(self.root / "missing.apk", manifest=False)
        cases = [
            (
                self.request(
                    "rebuild",
                    path=non_zip,
                    sha256=_sha256(non_zip),
                    params={"out_path": str(self.root / "nonzip-out.apk")},
                ),
                "complete, safe ZIP",
            ),
            (
                self.request(
                    "rebuild",
                    path=missing_manifest,
                    sha256=_sha256(missing_manifest),
                    params={"out_path": str(self.root / "missing-out.apk")},
                ),
                "AndroidManifest.xml",
            ),
            (
                self.request(
                    "verify",
                    sha256="0" * 64,
                    params={"artifact_dir": str(self.root / "hash-artifacts")},
                ),
                "declared target SHA-256",
            ),
            (
                self.request("rebuild", params={"out_path": str(self.apk)}),
                "must not overwrite",
            ),
        ]
        for request, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                validation = provider.validate(provider.plan(request))
                self.assertFalse(validation.ok)
                self.assertTrue(
                    any(expected_error in error for error in validation.errors),
                    validation.errors,
                )

    def test_unpack_zip_copy_is_safe_audited_and_reversible(self) -> None:
        unpack_dir = self.root / "unpacked"
        provider = AndroidRebuildProvider()
        plan = provider.plan(
            self.request("unpack", params={"unpack_dir": str(unpack_dir)})
        )
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual((unpack_dir / "AndroidManifest.xml").read_bytes(), b"binary-manifest")
        self.assertEqual((unpack_dir / "assets" / "config.json").read_bytes(), b"{}")
        self.assertEqual(_sha256(self.apk), self.source_hash)
        self.assertEqual(result.rollback_plan["mode"], "delete_unpack")
        self.assertEqual(result.artifacts[0].kind, "android-unpacked-directory")
        audit = json.loads(Path(plan.parameters["audit_path"]).read_text("utf-8"))
        self.assertEqual(audit["action"], "unpack")
        self.assertEqual(audit["provenance"]["action"], "unpack")

        rollback = provider.rollback(result)
        self.assertTrue(rollback.restored)
        self.assertFalse(unpack_dir.exists())

    def test_unpack_rollback_restores_existing_directory(self) -> None:
        unpack_dir = self.root / "existing-unpack"
        unpack_dir.mkdir()
        (unpack_dir / "prior.txt").write_text("prior", encoding="ascii")
        provider = AndroidRebuildProvider()
        plan = provider.plan(
            self.request("unpack", params={"unpack_dir": str(unpack_dir)})
        )
        result = provider.execute(plan)
        self.assertEqual(result.status, "ok")
        self.assertFalse((unpack_dir / "prior.txt").exists())

        rollback = provider.rollback(result)
        self.assertTrue(rollback.restored)
        self.assertEqual((unpack_dir / "prior.txt").read_text("ascii"), "prior")
        self.assertFalse((unpack_dir / "AndroidManifest.xml").exists())

    def test_unpack_rejects_unsafe_zip_entries(self) -> None:
        unsafe = _write_apk(
            self.root / "unsafe.apk",
            entries={"../escaped.txt": b"escape"},
        )
        provider = AndroidRebuildProvider()
        plan = provider.plan(
            self.request(
                "unpack",
                path=unsafe,
                sha256=_sha256(unsafe),
                params={"unpack_dir": str(self.root / "unsafe-unpack")},
            )
        )
        validation = provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertFalse(provider.execute(plan).after_snapshot["side_effects"])
        self.assertFalse((self.root / "escaped.txt").exists())

    def test_zip_limits_reject_oversized_and_high_ratio_members_without_output(self) -> None:
        oversized = _write_apk(
            self.root / "oversized.apk",
            entries={"assets/large.bin": b"x" * 512},
        )
        compressed = self.root / "high-ratio.apk"
        with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"binary-manifest")
            archive.writestr("assets/repeated.bin", b"A" * (4 * 1024 * 1024))

        cases = (
            (oversized, self.root / "oversized-output.apk", 256),
            (compressed, self.root / "ratio-output.apk", None),
        )
        for source, output, member_limit in cases:
            with self.subTest(source=source.name):
                provider = AndroidRebuildProvider()
                request = self.request(
                    "rebuild",
                    path=source,
                    sha256=_sha256(source),
                    params={"out_path": str(output)},
                    session_id=f"limit-{source.stem}",
                )
                patcher = (
                    mock.patch.object(
                        android_rebuild_module,
                        "_MAX_APK_MEMBER_BYTES",
                        member_limit,
                    )
                    if member_limit is not None
                    else mock.patch.object(
                        android_rebuild_module,
                        "_MAX_APK_COMPRESSION_RATIO",
                        100,
                    )
                )
                with patcher:
                    plan = provider.plan(request)
                    inspection = provider.backend.inspect_apk(source)
                    validation = provider.validate(plan)
                    result = provider.execute(plan)

                self.assertFalse(inspection["zip_integrity"])
                self.assertTrue(inspection["unsafe_entry_details"])
                self.assertFalse(validation.ok)
                self.assertEqual(result.status, "failed")
                self.assertFalse(result.after_snapshot["side_effects"])
                self.assertFalse(output.exists())

    def test_verify_checks_apk_without_creating_an_apk_output(self) -> None:
        artifact_dir = self.root / "verify-artifacts"
        provider = AndroidRebuildProvider()
        plan = provider.plan(
            self.request("verify", params={"artifact_dir": str(artifact_dir)})
        )
        self.assertNotIn("out_path", plan.parameters)
        self.assertNotIn("unpack_dir", plan.parameters)
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(_sha256(self.apk), self.source_hash)
        self.assertEqual({artifact.kind for artifact in result.artifacts}, {
            "android-verify-verify",
            "android-verify-audit",
        })
        self.assertFalse(any(path.suffix == ".apk" for path in artifact_dir.rglob("*")))
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "not_required")
        boundary = result.report_section["capability_boundary"]
        self.assertEqual(boundary["provider_kind"], "builtin")
        self.assertEqual(boundary["operation_kind"], "bounded_zip_static_verify")
        self.assertEqual(boundary["signature_verification"], "presence_only")

    def test_missing_external_tools_return_unavailable_without_running(self) -> None:
        provider = AndroidRebuildProvider(runner=MissingToolsRunner())
        requests = [
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(self.root / "tool-rebuilt.apk"),
                },
                session_id="missing-rebuild",
            ),
            self.request(
                "unpack",
                params={
                    "strategy": "apktool_rebuild",
                    "unpack_dir": str(self.root / "tool-unpacked"),
                },
                session_id="missing-unpack",
            ),
            self.request(
                "verify",
                params={
                    "verify_signature": True,
                    "artifact_dir": str(self.root / "tool-verify"),
                },
                session_id="missing-verify",
            ),
        ]
        for request in requests:
            with self.subTest(action=request.action):
                plan = provider.plan(request)
                validation = provider.validate(plan)
                self.assertTrue(
                    any(check["status"] == "unavailable" for check in validation.checks)
                )
                result = provider.execute(plan)
                self.assertEqual(result.status, "unavailable")
                self.assertFalse(result.after_snapshot["side_effects"])

    def test_injected_runner_handles_apktool_rebuild_unpack_and_verify(self) -> None:
        runner = FakeAndroidRunner()
        provider = AndroidRebuildProvider(runner=runner)
        keystore = self.root / "test.keystore"
        keystore.write_bytes(b"fake-keystore")
        rebuild = provider.execute(
            provider.plan(
                self.request(
                    "rebuild",
                    params={
                        "strategy": "apktool_rebuild",
                        "out_path": str(self.root / "fake-rebuilt.apk"),
                        "keystore": str(keystore),
                        "ks_pass": "secret",
                    },
                    session_id="fake-rebuild",
                )
            )
        )
        unpack = provider.execute(
            provider.plan(
                self.request(
                    "unpack",
                    params={
                        "strategy": "apktool_rebuild",
                        "unpack_dir": str(self.root / "fake-unpacked"),
                    },
                    session_id="fake-unpack",
                )
            )
        )
        verify = provider.execute(
            provider.plan(
                self.request(
                    "verify",
                    params={
                        "verify_signature": True,
                        "artifact_dir": str(self.root / "fake-verify"),
                    },
                    session_id="fake-verify",
                )
            )
        )

        self.assertEqual((rebuild.status, unpack.status, verify.status), ("ok", "ok", "ok"))
        steps = [call[1] for call in runner.calls]
        self.assertEqual(steps.count("d"), 2)
        self.assertIn("b", steps)
        self.assertIn("sign", steps)
        self.assertEqual(steps.count("verify"), 2)
        sign_call = next(call for call in runner.calls if call[1] == "sign")
        self.assertIn("pass:secret", sign_call)
        self.assertNotIn("secret", rebuild.provenance)

        verify_record = json.loads(
            Path(self.root / "fake-verify" / "verify_verify.json").read_text("utf-8")
        )
        self.assertEqual(len(verify_record["commands"]), 1)
        self.assertEqual(verify_record["commands"][0]["step"], "apksigner_verify")
        self.assertEqual(
            rebuild.provenance["capability_boundary"]["dependency_state"],
            "available",
        )
        self.assertEqual(
            verify_record["capability_boundary"]["operation_kind"],
            "apksigner_signature_verify",
        )

    def test_runner_without_explicit_result_does_not_report_signature_success(self) -> None:
        provider = AndroidRebuildProvider(runner=NoneResultRunner())
        plan = provider.plan(
            self.request(
                "verify",
                params={
                    "verify_signature": True,
                    "artifact_dir": str(self.root / "none-result"),
                },
                session_id="none-result",
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(result.report_section["signing"]["status"], "failed")
        verify_payload = json.loads(Path(plan.parameters["verify_path"]).read_text("utf-8"))
        self.assertFalse(verify_payload["commands"][0]["ok"])

    def test_successful_command_without_rebuild_output_is_failed(self) -> None:
        output = self.root / "missing-output.apk"
        runner = NoOutputRunner()
        provider = AndroidRebuildProvider(runner=runner)
        plan = provider.plan(
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(output),
                    "apksigner_args": ["--ks-pass=pass:test"],
                },
                session_id="missing-output",
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertFalse(output.exists())
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertTrue(any(call[1] == "b" for call in runner.calls))
        self.assertIn("without producing an unsigned APK", result.report_section["error"])

    def test_runner_without_availability_probe_is_unavailable(self) -> None:
        provider = AndroidRebuildProvider(runner=OpaqueRunner())
        plan = provider.plan(
            self.request(
                "unpack",
                params={
                    "strategy": "apktool_rebuild",
                    "unpack_dir": str(self.root / "opaque-unpack"),
                },
                session_id="opaque-runner",
            )
        )

        validation = provider.validate(plan)
        tool_check = next(
            check for check in validation.checks if check["name"] == "apktool_available"
        )
        self.assertEqual(tool_check["status"], "unavailable")
        result = provider.execute(plan)
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.after_snapshot["side_effects"])

    def test_inline_apksigner_password_arguments_are_redacted_from_audit(self) -> None:
        runner = FakeAndroidRunner()
        provider = AndroidRebuildProvider(runner=runner)
        output = self.root / "redacted.apk"
        plan = provider.plan(
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(output),
                    "apksigner_args": [
                        "--ks-pass=pass:inline-secret",
                        "--key-pass=pass:key-secret",
                    ],
                },
                session_id="redaction",
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        sign_call = next(call for call in runner.calls if call[1] == "sign")
        self.assertIn("--ks-pass=pass:inline-secret", sign_call)
        audit_text = Path(plan.parameters["audit_path"]).read_text("utf-8")
        verify_text = Path(plan.parameters["verify_path"]).read_text("utf-8")
        serialized_result = json.dumps(result.to_dict())
        for value in (audit_text, verify_text, serialized_result):
            self.assertNotIn("inline-secret", value)
            self.assertNotIn("key-secret", value)
        self.assertIn("--ks-pass=<redacted>", verify_text)
        self.assertIn("--key-pass=<redacted>", verify_text)

    def test_apksigner_managed_arguments_are_rejected_before_execution(self) -> None:
        runner = FakeAndroidRunner()
        provider = AndroidRebuildProvider(runner=runner)
        output = self.root / "managed-args.apk"
        plan = provider.plan(
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(output),
                    "apksigner_args": ["--out", str(self.root / "other.apk")],
                },
                session_id="managed-args",
            )
        )

        validation = provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertTrue(any("managed by the provider" in error for error in validation.errors))
        result = provider.execute(plan)
        self.assertEqual(result.status, "failed")
        self.assertFalse(output.exists())
        self.assertEqual(runner.calls, [])

    def test_apksigner_control_characters_are_rejected(self) -> None:
        provider = AndroidRebuildProvider(runner=FakeAndroidRunner())
        plan = provider.plan(
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(self.root / "control.apk"),
                    "apksigner_args": ["--lineage\ncorrupt"],
                },
                session_id="control-args",
            )
        )
        validation = provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertTrue(any("control characters" in error for error in validation.errors))

    def test_apksigner_arguments_require_an_array_or_single_flag(self) -> None:
        provider = AndroidRebuildProvider(runner=FakeAndroidRunner())
        plan = provider.plan(
            self.request(
                "rebuild",
                params={
                    "strategy": "apktool_rebuild",
                    "out_path": str(self.root / "invalid-args.apk"),
                    "apksigner_args": {"unexpected": "mapping"},
                },
                session_id="invalid-args",
            )
        )
        validation = provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertTrue(any("must be an array" in error for error in validation.errors))

    def test_successful_output_with_audit_write_failure_is_partial_and_rollbackable(self) -> None:
        output = self.root / "partial-rebuilt.apk"
        provider = AndroidRebuildProvider(
            backend=FailingAuditBackend("rebuild_audit.json")
        )
        plan = provider.plan(
            self.request("rebuild", params={"out_path": str(output)})
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.report_section["operation_status"], "ok")
        self.assertTrue(result.after_snapshot["side_effects"])
        self.assertTrue(result.rollback_plan["supported"])
        self.assertFalse(result.provenance["audit_complete"])
        self.assertTrue(result.report_section["artifact_errors"])
        self.assertTrue(output.is_file())

        rollback = provider.rollback(result)

        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)
        self.assertFalse(output.exists())
        self.assertEqual(_sha256(self.apk), self.source_hash)
        for entry in result.evidence_manifest_entries:
            artifact_path = Path(entry["path"])
            self.assertEqual(entry["sha256"], _sha256(artifact_path))

    def test_failed_json_writes_retain_source_evidence_and_valid_audit_contract(self) -> None:
        provider = AndroidRebuildProvider(backend=FailingJsonBackend())
        plan = provider.plan(
            self.request(
                "verify",
                params={"artifact_dir": str(self.root / "blocked-json")},
                session_id="blocked-json",
            )
        )
        validation = provider.validate(plan)

        result = provider.execute(plan)

        self.assertEqual(result.status, "partial")
        self.assertEqual(result.artifacts, [])
        self.assertEqual(len(result.evidence_manifest_entries), 1)
        source_entry = result.evidence_manifest_entries[0]
        self.assertEqual(Path(source_entry["path"]), self.apk.resolve())
        self.assertEqual(source_entry["sha256"], self.source_hash)
        self.assertTrue(source_entry["read_only"])
        self.assertEqual(source_entry["role"], "input-evidence")
        bundle = provider.collect_artifacts(result, str(self.root / "collected-blocked"))
        self.assertEqual(bundle.artifacts, [])
        self.assertEqual(bundle.manifest_entries, result.evidence_manifest_entries)

        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            result=result,
            validation=validation,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_rollback_refuses_modified_output_and_keeps_materialized_artifact(self) -> None:
        output = self.root / "modified-after-rebuild.apk"
        provider = AndroidRebuildProvider()
        result = provider.execute(
            provider.plan(
                self.request(
                    "rebuild",
                    params={"out_path": str(output)},
                    session_id="modified-rollback",
                )
            )
        )
        self.assertEqual(result.status, "ok")
        output.write_bytes(b"changed after execution")

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertTrue(output.is_file())
        self.assertIn(
            "android-rebuilt-apk", {artifact.kind for artifact in result.artifacts}
        )
        output_entry = next(
            entry
            for entry in result.evidence_manifest_entries
            if Path(entry["path"]) == output.resolve()
        )
        self.assertEqual(output_entry["sha256"], _sha256(output))

    def test_decoded_project_target_auto_selects_apktool_and_preserves_tree(self) -> None:
        project = self.root / "decoded-project"
        project.mkdir()
        (project / "AndroidManifest.xml").write_text("<manifest package='example.test'/>", encoding="utf-8")
        (project / "apktool.yml").write_text("version: 2.9.0\n", encoding="utf-8")
        project_hash = LocalAndroidRebuildBackend().snapshot(project)["sha256"]
        output = self.root / "project-rebuilt.apk"
        keystore = self.root / "project.keystore"
        keystore.write_bytes(b"fake-keystore")
        runner = FakeAndroidRunner()
        provider = AndroidRebuildProvider(runner=runner)

        plan = provider.plan(
            self.request(
                "rebuild",
                path=project,
                sha256=project_hash,
                params={
                    "out_path": str(output),
                    "keystore": str(keystore),
                    "ks_pass": "secret",
                },
                session_id="decoded-project",
            )
        )

        self.assertEqual(plan.parameters["strategy"], "apktool_rebuild")
        self.assertEqual(plan.parameters["source_kind"], "apktool_project")
        self.assertEqual(Path(plan.parameters["project_dir"]), project.resolve())
        validation = provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertTrue(output.is_file())
        self.assertEqual(LocalAndroidRebuildBackend().snapshot(project)["sha256"], project_hash)
        apktool_actions = [call[1] for call in runner.calls if "apktool" in Path(call[0]).name.lower()]
        self.assertEqual(apktool_actions, ["b"])
        self.assertEqual(result.provenance["source_kind"], "apktool_project")

        invalid = provider.plan(
            self.request(
                "rebuild",
                path=project,
                sha256=project_hash,
                params={"strategy": "zip_copy", "out_path": str(self.root / "invalid.apk")},
                session_id="decoded-project-invalid",
            )
        )
        self.assertFalse(provider.validate(invalid).ok)

    def test_backend_can_be_injected(self) -> None:
        backend = CountingBackend()
        output = self.root / "backend.apk"
        provider = AndroidRebuildProvider(backend=backend)
        result = provider.execute(
            provider.plan(self.request("rebuild", params={"out_path": str(output)}))
        )
        self.assertEqual(result.status, "ok")
        self.assertGreaterEqual(backend.copy_count, 1)
        self.assertGreater(backend.inspect_count, 1)

    def test_mock_provider_is_preserved(self) -> None:
        mock = AndroidRebuildMockProvider()
        plan = mock.plan(self.request("rebuild"))
        self.assertEqual(mock.capability_name, "android_rebuild")
        self.assertEqual(mock.execute(plan).status, "mocked")


if __name__ == "__main__":
    unittest.main()
