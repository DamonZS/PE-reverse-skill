import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zipfile

from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import AndroidNativePatchProvider, build_default_registry
from reverse_analyzer.tools.executor import ToolResult


ARM_BASE = 0x1000
ARM_CODE_OFFSET = 0x100
ARM_CODE = bytes.fromhex("00 f0 20 e3 00 f0 20 e3")
PATCHED_ARM_INSTRUCTION = bytes.fromhex("01 00 a0 e3")
TARGET_MEMBER = "lib/armeabi-v7a/libfixture.so"


def _minimal_arm_elf32() -> bytes:
    section_table = 0x220
    data = bytearray(0x2A0)
    data[:16] = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        data,
        16,
        3,
        40,
        1,
        ARM_BASE + ARM_CODE_OFFSET,
        52,
        section_table,
        0x05000000,
        52,
        32,
        1,
        40,
        3,
        0,
    )
    struct.pack_into(
        "<IIIIIIII",
        data,
        52,
        1,
        0,
        ARM_BASE,
        ARM_BASE,
        0x200,
        0x200,
        0x5,
        0x1000,
    )
    data[ARM_CODE_OFFSET : ARM_CODE_OFFSET + len(ARM_CODE)] = ARM_CODE
    struct.pack_into(
        "<IIIIIIIIII",
        data,
        section_table + 40,
        0,
        1,
        0x6,
        ARM_BASE + ARM_CODE_OFFSET,
        ARM_CODE_OFFSET,
        0x40,
        0,
        0,
        4,
        0,
    )
    struct.pack_into(
        "<IIIIIIIIII",
        data,
        section_table + 80,
        0,
        9,
        0,
        0,
        0x180,
        0,
        0,
        1,
        4,
        8,
    )
    jni_names = b"JNI_OnLoad\x00Java_com_example_Native_ping\x00"
    data[0x1A0 : 0x1A0 + len(jni_names)] = jni_names
    return bytes(data)


def _write_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr(TARGET_MEMBER, _minimal_arm_elf32())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AndroidNativePatchCapabilityTests(unittest.TestCase):
    def _request(
        self,
        source: Path,
        *,
        action: str,
        root: Path,
        expected: bytes = ARM_CODE[:4],
        session_id: str = "android-native-patch-test",
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="android_native_patch",
            action=action,
            target=TargetIdentity(
                kind="apk",
                path=str(source),
                sha256=_sha256(source),
                display_name=source.name,
            ),
            params={
                "abi": "armeabi-v7a",
                "library_path": "libfixture.so",
                "file_offset": ARM_CODE_OFFSET,
                "expected": expected,
                "replacement": PATCHED_ARM_INSTRUCTION,
                "instruction_mode": "arm",
                "out_path": str(root / "patched.apk"),
                "artifact_dir": str(root / "patch-artifacts"),
                "rollback_out_path": str(root / "restored.apk"),
                "rollback_artifact_dir": str(root / "rollback-artifacts"),
            },
            session_id=session_id,
            provenance={"source": "test_android_native_patch_capability"},
        )

    def test_default_registry_resolves_android_native_patch_provider(self) -> None:
        registry = build_default_registry()

        self.assertIn("android_native_patch", registry.list_capabilities())
        self.assertEqual(
            registry.list_providers("android_native_patch"),
            ["local_android_native_patch"],
        )
        self.assertIsInstance(
            registry.resolve("android_native_patch"),
            AndroidNativePatchProvider,
        )

    def test_plan_dry_run_checks_real_patch_without_materializing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            original = source.read_bytes()
            provider = AndroidNativePatchProvider()
            request = self._request(source, action="dry-run", root=root)

            plan = provider.plan(request)

            self.assertEqual(plan.action, "plan")
            self.assertEqual(plan.precondition_hash, _sha256(source))
            self.assertEqual(plan.parameters["expected"], ARM_CODE[:4])
            self.assertFalse(plan.rollback_plan["supported"])
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = provider.execute(plan)

            self.assertEqual(result.status, "planned")
            self.assertTrue(result.report_section["dry_run"])
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse((root / "patched.apk").exists())
            self.assertFalse((root / "patch-artifacts").exists())
            self.assertFalse((root / "restored.apk").exists())
            self.assertFalse((root / "rollback-artifacts").exists())

    def test_apply_and_lifecycle_rollback_keep_source_and_patched_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            original = source.read_bytes()
            provider = AndroidNativePatchProvider()
            plan = provider.plan(self._request(source, action="apply", root=root))

            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = provider.execute(plan)

            patched = root / "patched.apk"
            rollback_manifest = root / "patch-artifacts" / "rollback.json"
            self.assertEqual(result.status, "ok", result.report_section.get("error"))
            self.assertTrue(result.report_section["applied"])
            self.assertEqual(result.rollback_plan["status"], "ready")
            self.assertEqual(source.read_bytes(), original)
            self.assertTrue(patched.is_file())
            self.assertTrue(rollback_manifest.is_file())
            with zipfile.ZipFile(patched, "r") as archive:
                patched_elf = archive.read(TARGET_MEMBER)
            self.assertEqual(
                patched_elf[ARM_CODE_OFFSET : ARM_CODE_OFFSET + 4],
                PATCHED_ARM_INSTRUCTION,
            )
            for artifact in result.artifacts:
                if artifact.metadata.get("materialized"):
                    snapshot = artifact.metadata["snapshot"]
                    self.assertEqual(snapshot["sha256"], _sha256(Path(artifact.path)))
                    self.assertEqual(snapshot["size"], Path(artifact.path).stat().st_size)
            bundle = provider.collect_artifacts(result, str(root / "collected"))
            self.assertEqual(len(bundle.artifacts), len(bundle.manifest_entries))

            patched_bytes = patched.read_bytes()
            rollback = provider.rollback(result)

            restored = root / "restored.apk"
            self.assertTrue(rollback.ok, rollback.details)
            self.assertTrue(rollback.restored)
            self.assertEqual(Path(rollback.details["restored_path"]), restored.resolve())
            self.assertEqual(restored.read_bytes(), original)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(patched.read_bytes(), patched_bytes)
            self.assertEqual(result.rollback_plan["status"], "completed")
            provider.collect_artifacts(result, str(root / "after-rollback"))

    def test_changed_source_and_wrong_expected_bytes_fail_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            provider = AndroidNativePatchProvider()
            plan = provider.plan(self._request(source, action="apply", root=root))
            source.write_bytes(source.read_bytes() + b"changed")

            validation = provider.validate(plan)

            self.assertFalse(validation.ok)
            self.assertIn("precondition hash", " ".join(validation.errors))
            with self.assertRaisesRegex(RuntimeError, "target changed"):
                provider.execute(plan)
            self.assertFalse((root / "patched.apk").exists())
            self.assertFalse((root / "patch-artifacts").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            provider = AndroidNativePatchProvider()
            bad_plan = provider.plan(
                self._request(
                    source,
                    action="apply",
                    root=root,
                    expected=b"\xff\xff\xff\xff",
                    session_id="wrong-preimage",
                )
            )

            validation = provider.validate(bad_plan)

            self.assertFalse(validation.ok)
            self.assertIn("preimage", " ".join(validation.errors).lower())
            self.assertFalse((root / "patched.apk").exists())
            self.assertFalse((root / "patch-artifacts").exists())

    def test_execute_rejects_source_replaced_after_successful_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            provider = AndroidNativePatchProvider()
            plan = provider.plan(self._request(source, action="apply", root=root))

            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            replacement = source.read_bytes() + b"replaced-after-validation"
            source.write_bytes(replacement)

            with self.assertRaisesRegex(RuntimeError, "target changed"):
                provider.execute(plan)

            self.assertEqual(source.read_bytes(), replacement)
            self.assertFalse((root / "patched.apk").exists())
            self.assertFalse((root / "patch-artifacts").exists())

    def test_failed_execution_cleans_provider_owned_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            original = source.read_bytes()
            replacement = original + b"changed-during-execution"
            provider = AndroidNativePatchProvider()
            plan = provider.plan(self._request(source, action="apply", root=root))

            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)

            def dirty_success(
                execution_plan: object,
                *,
                target_path: str | Path | None = None,
                parameters: object = None,
            ) -> ToolResult:
                del execution_plan
                self.assertIsNotNone(target_path)
                trusted_source = Path(str(target_path)).resolve()
                self.assertNotEqual(trusted_source, source.resolve())
                self.assertEqual(trusted_source.read_bytes(), original)
                self.assertIsInstance(parameters, dict)

                source.write_bytes(replacement)
                patched = root / "patched.apk"
                patched.write_bytes(trusted_source.read_bytes())
                artifact_dir = root / "patch-artifacts"
                artifact_dir.mkdir()
                plan_path = artifact_dir / "native-patch-plan.json"
                verify_path = artifact_dir / "native-patch-verify.json"
                rollback_path = artifact_dir / "rollback.json"
                for path in (plan_path, verify_path, rollback_path):
                    path.write_text("{}\n", encoding="utf-8")

                def artifact(path: Path, kind: str) -> dict[str, object]:
                    return {
                        "name": path.name,
                        "path": str(path.resolve()),
                        "kind": kind,
                        "size": path.stat().st_size,
                        "sha256": _sha256(path),
                    }

                return ToolResult(
                    tool="android_native_patch_apk",
                    status="ok",
                    data={
                        "status": "ok",
                        "valid": True,
                        "source_apk_path": str(trusted_source),
                        "patched_apk_path": str(patched.resolve()),
                        "source_sha256": plan.precondition_hash,
                        "patched_sha256": _sha256(patched),
                        "original_apk_unchanged": True,
                        "elf": {
                            "evidence": {
                                "address_mapping": {"preimage_verified": True}
                            }
                        },
                        "plan_path": str(plan_path.resolve()),
                        "verify_path": str(verify_path.resolve()),
                        "rollback_path": str(rollback_path.resolve()),
                        "artifacts": [
                            artifact(patched, "unsigned-patched-apk"),
                            artifact(plan_path, "android-native-patch-plan"),
                            artifact(verify_path, "android-native-patch-verify"),
                            artifact(rollback_path, "android-native-apk-rollback"),
                        ],
                    },
                )

            with patch(
                "reverse_analyzer.providers.android_native_patch._execute_action",
                side_effect=dirty_success,
            ):
                result = provider.execute(plan)

            self.assertEqual(result.status, "failed")
            self.assertFalse(result.report_section["applied"])
            self.assertIn("source APK changed", result.report_section["error"])
            self.assertEqual(source.read_bytes(), replacement)
            self.assertFalse((root / "patched.apk").exists())
            self.assertFalse((root / "patch-artifacts").exists())
            self.assertFalse(
                any(item.metadata.get("materialized") for item in result.artifacts)
            )


if __name__ == "__main__":
    unittest.main()
