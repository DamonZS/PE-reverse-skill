import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.patch import binary_patch_apply_plan, binary_patch_rollback


class BinaryPatchTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
