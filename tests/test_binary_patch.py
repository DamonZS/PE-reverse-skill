import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.tools.patch import (
    binary_patch_apply,
    binary_patch_apply_plan,
    binary_patch_rollback,
    binary_patch_rollback_plan,
    validate_patch_plan,
)


class BinaryPatchTests(unittest.TestCase):
    @staticmethod
    def _pe_fixture_with_virtual_only_tail() -> bytes:
        """Build a PE-like fixture whose section has bytes past raw_size."""

        data = bytearray(0x240)
        data[:2] = b"MZ"
        pe_offset = 0x80
        struct.pack_into("<I", data, 0x3C, pe_offset)
        data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
        struct.pack_into("<H", data, pe_offset + 6, 1)  # NumberOfSections
        struct.pack_into("<H", data, pe_offset + 20, 0xE0)  # SizeOfOptionalHeader
        section = pe_offset + 24 + 0xE0
        data[section : section + 8] = b".text\x00\x00\x00"
        struct.pack_into("<I", data, section + 8, 0x20)  # VirtualSize
        struct.pack_into("<I", data, section + 12, 0x1000)  # VirtualAddress
        struct.pack_into("<I", data, section + 16, 0x10)  # SizeOfRawData
        struct.pack_into("<I", data, section + 20, 0x200)  # PointerToRawData
        data[0x200:0x220] = bytes(range(0x20))
        return bytes(data)

    def test_checked_replace_writes_new_file_and_rollback_restores_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            output = root / "patched.bin"
            artifacts = root / "audit"
            original = b"MZ\x90\x90HELLO\x00"
            source.write_bytes(original)
            plan = {
                "target_sha256": hashlib.sha256(original).hexdigest(),
                "operations": [
                    {
                        "id": "swap-nops",
                        "kind": "replace_offset",
                        "offset": "0x2",
                        "expected": "9090",
                        "replacement": "cccc",
                    }
                ],
            }

            result = binary_patch_apply_plan(source, plan=plan, out_path=output, apply=True, artifact_dir=artifacts)

            self.assertEqual(result.status, "ok")
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(output.read_bytes(), b"MZ\xCC\xCCHELLO\x00")
            self.assertTrue((artifacts / "patch_manifest.json").is_file())
            rollback_path = artifacts / "rollback.json"
            self.assertTrue(rollback_path.is_file())

            restored = binary_patch_rollback(output, rollback=rollback_path, out_dir=root / "rollback", overwrite=True)

            self.assertEqual(restored.status, "ok")
            restored_path = Path(restored.data["restored_path"])
            self.assertEqual(restored_path.read_bytes(), original)

    def test_aob_replace_and_overlay_embedding_are_verified_and_reversible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            payload = root / "payload.dat"
            output = root / "patched.bin"
            original = b"prefix\xAA\xBB\xCCsuffix"
            source.write_bytes(original)
            payload.write_bytes(b"embedded-data")
            plan = {
                "operations": [
                    {
                        "id": "aob",
                        "kind": "replace_aob",
                        "pattern": "AA BB ??",
                        "replacement": "11 22 33",
                        "expected_match_count": 1,
                    },
                    {"id": "embed", "kind": "embed_overlay", "payload_file": "payload.dat", "marker": "test-payload"},
                ]
            }
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            result = binary_patch_apply_plan(source, plan=plan_path, out_path=output, apply=True)

            self.assertEqual(result.status, "ok")
            self.assertIn(b"\x11\x22\x33", output.read_bytes())
            self.assertIn(b"RAPATCH\x00", output.read_bytes())
            rollback = Path(result.data["rollback_path"])
            restored = binary_patch_rollback(output, rollback=rollback, out_dir=root / "restore", overwrite=True)
            self.assertEqual(restored.status, "ok")
            self.assertEqual(Path(restored.data["restored_path"]).read_bytes(), original)

    def test_dry_run_and_mismatched_preimage_do_not_write_a_patched_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            output = root / "patched.bin"
            source.write_bytes(b"abcdef")
            plan = {
                "operations": [
                    {"kind": "replace_offset", "offset": 1, "expected": "62", "replacement": "42"}
                ]
            }

            planned = binary_patch_apply_plan(source, plan=plan, out_path=output, apply=False)

            self.assertEqual(planned.status, "planned")
            self.assertFalse(output.exists())
            self.assertEqual(planned.data["patched_sha256"], hashlib.sha256(b"aBcdef").hexdigest())

            failed = binary_patch_apply_plan(
                source,
                plan={"operations": [{"kind": "replace_offset", "offset": 1, "expected": "ff", "replacement": "42"}]},
                out_path=output,
                apply=True,
            )
            self.assertEqual(failed.status, "failed")
            self.assertFalse(output.exists())

    def test_validate_patch_plan_checks_hash_payload_and_never_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            payload = root / "payload.dat"
            source.write_bytes(b"MZ\x90\x90")
            payload.write_bytes(b"metadata")
            plan_path = root / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "target_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "operations": [
                            {"kind": "replace_offset", "offset": "0x2", "expected": "9090", "replacement": "cccc"},
                            {"kind": "embed_overlay", "payload_file": payload.name},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            validated = validate_patch_plan(source, plan=plan_path)

            self.assertEqual(validated.status, "ok")
            self.assertTrue(validated.data["valid"])
            self.assertEqual(source.read_bytes(), b"MZ\x90\x90")
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["fixture.bin", "payload.dat", "plan.json"])

            invalid = validate_patch_plan(source, plan={"schema_version": 2, "operations": []})
            self.assertEqual(invalid.status, "failed")
            self.assertFalse(invalid.data["valid"])

    def test_public_apply_matches_plan_adapter_validation_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            source.write_bytes(b"abcdef")
            valid_operation = {
                "kind": "replace_offset",
                "offset": 1,
                "expected": "62",
                "replacement": "42",
            }
            invalid_plans = [
                {"schema_version": 2, "operations": [valid_operation]},
                {"target_sha256": "0" * 64, "operations": [valid_operation]},
                {"operations": [{"kind": "not-supported"}]},
                {
                    "operations": [
                        {"kind": "replace_offset", "offset": 1, "expected": "ff", "replacement": "42"}
                    ]
                },
            ]

            for plan in invalid_plans:
                with self.subTest(plan=plan):
                    public_result = binary_patch_apply(source, plan=plan, out_dir=root / "public", dry_run=True)
                    adapter_result = binary_patch_apply_plan(
                        source,
                        plan=plan,
                        out_path=root / "patched.bin",
                        apply=False,
                    )

                    self.assertEqual(public_result.status, "failed")
                    self.assertEqual(adapter_result.status, "failed")
                    self.assertEqual(public_result.error, adapter_result.error)
                    self.assertFalse((root / "public").exists())
                    self.assertFalse((root / "patched.bin").exists())

    def test_rollback_verifies_restored_hash_before_writing_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            patched = root / "patched.bin"
            artifacts = root / "artifacts"
            source.write_bytes(b"abcdef")
            applied = binary_patch_apply_plan(
                source,
                plan={"operations": [{"kind": "replace_offset", "offset": 1, "expected": "62", "replacement": "42"}]},
                out_path=patched,
                apply=True,
                artifact_dir=artifacts,
            )
            self.assertEqual(applied.status, "ok")

            rollback_path = artifacts / "rollback.json"
            rollback_payload = json.loads(rollback_path.read_text(encoding="utf-8"))
            rollback_payload["source_sha256"] = "0" * 64
            rollback_path.write_text(json.dumps(rollback_payload), encoding="utf-8")

            restored = binary_patch_rollback(patched, rollback=rollback_path, out_dir=root / "restore")
            self.assertEqual(restored.status, "failed")
            self.assertIn("rollback result hash does not match source_sha256", restored.error)
            self.assertFalse((root / "restore").exists())

            planned_restore = root / "planned-restored.bin"
            adapter = binary_patch_rollback_plan(
                patched,
                rollback=rollback_path,
                out_path=planned_restore,
                apply=True,
            )
            self.assertEqual(adapter.status, "failed")
            self.assertIn("rollback result hash does not match source_sha256", adapter.error)
            self.assertFalse(planned_restore.exists())

    def test_replace_rva_rejects_virtual_tail_and_raw_range_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.exe"
            source.write_bytes(self._pe_fixture_with_virtual_only_tail())
            cases = [
                (
                    "virtual-tail",
                    {"kind": "replace_rva", "rva": 0x1010, "expected": "10", "replacement": "FF"},
                    "virtual-only tail",
                ),
                (
                    "raw-overflow",
                    {"kind": "replace_rva", "rva": 0x100F, "expected": "0F 10", "replacement": "FF EE"},
                    "exceeds the section raw_size",
                ),
            ]

            for name, operation, error_text in cases:
                with self.subTest(name=name):
                    output = root / f"{name}.exe"
                    result = binary_patch_apply_plan(
                        source,
                        plan={"operations": [operation]},
                        out_path=output,
                        apply=True,
                    )

                    self.assertEqual(result.status, "failed")
                    self.assertIn(error_text, result.error)
                    self.assertFalse(output.exists())

    def test_overlay_payload_size_is_checked_before_reading_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            payload = (root / "payload.dat").resolve()
            source.write_bytes(b"fixture")
            payload.write_bytes(b"12345")
            original_read_bytes = Path.read_bytes

            def guarded_read_bytes(path: Path) -> bytes:
                if path.resolve() == payload:
                    raise AssertionError("oversized payload must not be read")
                return original_read_bytes(path)

            with (
                patch("reverse_analyzer.tools.patch._MAX_EMBED_PAYLOAD_BYTES", 4),
                patch.object(Path, "read_bytes", new=guarded_read_bytes),
            ):
                result = validate_patch_plan(
                    source,
                    plan={"operations": [{"kind": "embed_overlay", "payload_file": str(payload)}]},
                )

            self.assertEqual(result.status, "failed")
            self.assertIn("payload exceeds 4 byte limit", result.error)


if __name__ == "__main__":
    unittest.main()
