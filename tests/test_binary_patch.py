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
from reverse_analyzer.tools.executor import ToolResult


class BinaryPatchTests(unittest.TestCase):
    @staticmethod
    def _plan(original: bytes, operations: list[dict], **extra) -> dict:
        return {
            "schema_version": 1,
            "target_sha256": hashlib.sha256(original).hexdigest(),
            "operations": operations,
            **extra,
        }

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

    def test_offset_and_aob_manifests_keep_exact_file_offsets_and_rvas_through_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.exe"
            patched = root / "patched.exe"
            restored = root / "restored.exe"
            artifacts = root / "artifacts"
            original = self._pe_fixture_with_virtual_only_tail()
            source.write_bytes(original)
            plan = self._plan(
                original,
                [
                    {
                        "id": "offset-op",
                        "kind": "replace_offset",
                        "offset": 0x200,
                        "expected": "0001",
                        "replacement": "A0A1",
                    },
                    {
                        "id": "aob-op",
                        "kind": "replace_aob",
                        "pattern": "02 03 04 05",
                        "expected": "02030405",
                        "replacement": "A2A30405",
                        "expected_match_count": 1,
                    },
                ],
            )

            applied = binary_patch_apply_plan(
                source,
                plan=plan,
                out_path=patched,
                apply=True,
                artifact_dir=artifacts,
            )

            self.assertEqual(applied.status, "ok", applied.error)
            operations = applied.data["operations"]
            self.assertEqual(
                [
                    (
                        item["file_offset"],
                        item["file_offset_value"],
                        item["rva"],
                        item["rva_value"],
                    )
                    for item in operations
                ],
                [
                    ("0x200", 0x200, "0x1000", 0x1000),
                    ("0x202", 0x202, "0x1002", 0x1002),
                ],
            )

            rolled_back = binary_patch_rollback_plan(
                patched,
                rollback=artifacts / "rollback.json",
                out_path=restored,
                apply=True,
                artifact_dir=root / "rollback-artifacts",
            )

            self.assertEqual(rolled_back.status, "ok", rolled_back.error)
            self.assertEqual(restored.read_bytes(), original)
            self.assertEqual(rolled_back.data["restored_sha256"], hashlib.sha256(original).hexdigest())
            restored_by_id = {item["id"]: item for item in rolled_back.data["operations"]}
            self.assertEqual(restored_by_id["offset-op"]["file_offset_value"], 0x200)
            self.assertEqual(restored_by_id["offset-op"]["rva_value"], 0x1000)
            self.assertEqual(restored_by_id["aob-op"]["file_offset_value"], 0x202)
            self.assertEqual(restored_by_id["aob-op"]["rva_value"], 0x1002)

    def test_aob_replace_and_overlay_embedding_are_verified_and_reversible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            payload = root / "payload.dat"
            output = root / "patched.bin"
            original = b"prefix\xAA\xBB\xCCsuffix"
            source.write_bytes(original)
            payload.write_bytes(b"embedded-data")
            plan = self._plan(
                original,
                [
                    {
                        "id": "aob",
                        "kind": "replace_aob",
                        "pattern": "AA BB ??",
                        "replacement": "11 22 33",
                        "expected_match_count": 1,
                    },
                    {"id": "embed", "kind": "embed_overlay", "payload_file": "payload.dat", "marker": "test-payload"},
                ],
            )
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
            plan = self._plan(
                source.read_bytes(),
                [
                    {"kind": "replace_offset", "offset": 1, "expected": "62", "replacement": "42"}
                ],
            )

            planned = binary_patch_apply_plan(source, plan=plan, out_path=output, apply=False)

            self.assertEqual(planned.status, "planned")
            self.assertFalse(output.exists())
            self.assertEqual(planned.data["patched_sha256"], hashlib.sha256(b"aBcdef").hexdigest())

            failed = binary_patch_apply_plan(
                source,
                plan=self._plan(
                    source.read_bytes(),
                    [{"kind": "replace_offset", "offset": 1, "expected": "ff", "replacement": "42"}],
                ),
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
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            invalid_plans = [
                {"schema_version": 2, "target_sha256": source_hash, "operations": [valid_operation]},
                {"target_sha256": "0" * 64, "operations": [valid_operation]},
                {"target_sha256": source_hash, "operations": [{"kind": "not-supported"}]},
                {
                    "target_sha256": source_hash,
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
                plan=self._plan(
                    source.read_bytes(),
                    [{"kind": "replace_offset", "offset": 1, "expected": "62", "replacement": "42"}],
                ),
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
                        plan=self._plan(source.read_bytes(), [operation]),
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
                    plan=self._plan(
                        source.read_bytes(),
                        [{"kind": "embed_overlay", "payload_file": str(payload)}],
                    ),
                )

            self.assertEqual(result.status, "failed")
            self.assertIn("payload exceeds 4 byte limit", result.error)

    def test_missing_target_hash_is_rejected_without_writing(self) -> None:
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

            results = [
                validate_patch_plan(source, plan=plan),
                binary_patch_apply(source, plan=plan, out_dir=root / "legacy", dry_run=True),
                binary_patch_apply_plan(source, plan=plan, out_path=output, apply=True),
            ]

            for result in results:
                with self.subTest(tool=result.tool):
                    self.assertEqual(result.status, "failed")
                    self.assertIn("target_sha256 is required", result.error)
            self.assertEqual(source.read_bytes(), b"abcdef")
            self.assertFalse(output.exists())
            self.assertFalse((root / "legacy").exists())

    def test_pe_validation_unavailable_never_writes_or_reports_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            output = root / "patched.bin"
            artifacts = root / "artifacts"
            original = b"MZ\x90\x90payload"
            source.write_bytes(original)
            plan = self._plan(
                original,
                [
                    {
                        "kind": "replace_offset",
                        "offset": 2,
                        "expected": "9090",
                        "replacement": "CCCC",
                    }
                ],
                planner={"name": "pe_aware_patch_planner"},
            )
            unavailable = ToolResult(
                tool="pe_patch_validate",
                status="unavailable",
                error="capstone unavailable",
                data={"status": "unavailable", "valid": False, "artifacts": []},
            )

            with patch(
                "reverse_analyzer.patch.planner.validate_pe_patch_plan",
                return_value=unavailable,
            ):
                validated = validate_patch_plan(source, plan=plan)
                applied = binary_patch_apply_plan(
                    source,
                    plan=plan,
                    out_path=output,
                    apply=True,
                    artifact_dir=artifacts,
                )

            self.assertEqual(validated.status, "unavailable")
            self.assertFalse(validated.data["valid"])
            self.assertEqual(applied.status, "unavailable")
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(output.exists())
            self.assertFalse(artifacts.exists())

    def test_apply_rejects_sample_plan_output_and_artifact_path_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = b"abcdef"
            operation = {"kind": "replace_offset", "offset": 1, "expected": "62", "replacement": "42"}

            for sample_name in ("patch_manifest.json", "rollback.json"):
                with self.subTest(sample_name=sample_name):
                    source = root / sample_name
                    source.write_bytes(original)
                    output = root / f"{sample_name}.patched"
                    result = binary_patch_apply_plan(
                        source,
                        plan=self._plan(original, [operation]),
                        out_path=output,
                        apply=True,
                        artifact_dir=root,
                    )
                    self.assertEqual(result.status, "failed")
                    self.assertIn("path collision", result.error)
                    self.assertEqual(source.read_bytes(), original)
                    self.assertFalse(output.exists())
                    source.unlink()

            source = root / "fixture.bin"
            source.write_bytes(original)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(self._plan(original, [operation])), encoding="utf-8")
            plan_before = plan_path.read_bytes()
            plan_collision = binary_patch_apply_plan(
                source,
                plan=plan_path,
                out_path=plan_path,
                apply=True,
                artifact_dir=root / "plan-artifacts",
            )
            self.assertEqual(plan_collision.status, "failed")
            self.assertIn("path collision", plan_collision.error)
            self.assertEqual(plan_path.read_bytes(), plan_before)

            manifest_collision = binary_patch_apply_plan(
                source,
                plan=self._plan(original, [operation]),
                out_path=root / "audit" / "patch_manifest.json",
                apply=True,
                artifact_dir=root / "audit",
            )
            self.assertEqual(manifest_collision.status, "failed")
            self.assertIn("path collision", manifest_collision.error)
            self.assertEqual(source.read_bytes(), original)

    def test_bundle_publish_failure_restores_preexisting_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.bin"
            out_dir = root / "out"
            original = b"abcdef"
            source.write_bytes(original)
            destinations = [
                out_dir / "patched" / "fixture.patched.bin",
                out_dir / "patch_manifest.json",
                out_dir / "rollback.json",
            ]
            prior = [b"old-binary", b"old-manifest", b"old-rollback"]
            for path, payload in zip(destinations, prior):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)

            real_replace = __import__("os").replace
            call_count = 0

            def fail_second_commit(source_path, destination_path):
                nonlocal call_count
                call_count += 1
                if call_count == 5:
                    raise OSError("simulated bundle commit failure")
                return real_replace(source_path, destination_path)

            with patch("reverse_analyzer.tools.patch.os.replace", side_effect=fail_second_commit):
                result = binary_patch_apply(
                    source,
                    plan=self._plan(
                        original,
                        [{"kind": "replace_offset", "offset": 1, "expected": "62", "replacement": "42"}],
                    ),
                    out_dir=out_dir,
                    overwrite=True,
                )

            self.assertEqual(result.status, "failed")
            self.assertIn("simulated bundle commit failure", result.error)
            self.assertEqual([path.read_bytes() for path in destinations], prior)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
