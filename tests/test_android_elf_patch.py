import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from reverse_analyzer.patch.android_elf import (
    AndroidElfPatchError,
    parse_android_elf,
    plan_android_elf_patch,
    verify_android_elf_patch,
)
from reverse_analyzer.tools import binary_patch_apply_plan


ARM_BASE = 0x1000
ARM_CODE_OFFSET = 0x100
ARM_CODE_VA = ARM_BASE + ARM_CODE_OFFSET
ARM_CODE = bytes.fromhex("00 f0 20 e3 00 f0 20 e3 00 f0 20 e3 00 f0 20 e3")
AARCH64_BASE = 0x400000
AARCH64_CODE_OFFSET = 0x100
AARCH64_CODE_VA = AARCH64_BASE + AARCH64_CODE_OFFSET
AARCH64_CODE = bytes.fromhex("1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5")


def _sha256(value: bytes | Path) -> str:
    data = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(data).hexdigest()


def _minimal_arm_elf32(
    *,
    segment_flags: int = 0x5,
    load_file_size: int = 0x200,
    load_memory_size: int | None = None,
    relocation_va: int | None = None,
    entrypoint: int = ARM_CODE_VA,
    data_encoding: int = 1,
    machine: int = 40,
) -> bytes:
    """Build a structurally valid ELF32 ET_DYN with a file-backed PT_LOAD."""

    section_table = 0x220
    data = bytearray(0x2A0)
    data[:16] = b"\x7fELF" + bytes([1, data_encoding, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        data,
        16,
        3,  # ET_DYN
        machine,
        1,
        entrypoint,
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
    memory_size = load_file_size if load_memory_size is None else load_memory_size
    struct.pack_into(
        "<IIIIIIII",
        data,
        52,
        1,  # PT_LOAD
        0,
        ARM_BASE,
        ARM_BASE,
        load_file_size,
        memory_size,
        segment_flags,
        0x1000,
    )
    data[ARM_CODE_OFFSET : ARM_CODE_OFFSET + len(ARM_CODE)] = ARM_CODE

    # section[0] is the mandatory null section.
    struct.pack_into(
        "<IIIIIIIIII",
        data,
        section_table + 40,
        0,
        1,  # SHT_PROGBITS
        0x6,  # SHF_ALLOC | SHF_EXECINSTR
        ARM_CODE_VA,
        ARM_CODE_OFFSET,
        0x40,
        0,
        0,
        4,
        0,
    )
    relocation_size = 8 if relocation_va is not None else 0
    struct.pack_into(
        "<IIIIIIIIII",
        data,
        section_table + 80,
        0,
        9,  # SHT_REL
        0,
        0,
        0x180,
        relocation_size,
        0,
        1,  # target section index
        4,
        8,
    )
    if relocation_va is not None:
        struct.pack_into("<II", data, 0x180, relocation_va, (1 << 8) | 2)  # R_ARM_ABS32
    return bytes(data)


def _minimal_aarch64_elf64(
    *,
    segment_flags: int = 0x5,
    relocation_va: int | None = None,
) -> bytes:
    """Build a structurally valid ELF64 ET_DYN with an optional SHT_RELA."""

    section_table = 0x240
    data = bytearray(0x310)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,
        183,  # EM_AARCH64
        1,
        AARCH64_CODE_VA,
        64,
        section_table,
        0,
        64,
        56,
        1,
        64,
        3,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        segment_flags,
        0,
        AARCH64_BASE,
        AARCH64_BASE,
        0x200,
        0x200,
        0x1000,
    )
    data[AARCH64_CODE_OFFSET : AARCH64_CODE_OFFSET + len(AARCH64_CODE)] = AARCH64_CODE
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_table + 64,
        0,
        1,
        0x6,
        AARCH64_CODE_VA,
        AARCH64_CODE_OFFSET,
        0x40,
        0,
        0,
        4,
        0,
    )
    relocation_size = 24 if relocation_va is not None else 0
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_table + 128,
        0,
        4,  # SHT_RELA
        0,
        0,
        0x180,
        relocation_size,
        0,
        1,
        8,
        24,
    )
    if relocation_va is not None:
        struct.pack_into("<QQq", data, 0x180, relocation_va, (1 << 32) | 257, 0)
    return bytes(data)


def _payload(result: Any) -> dict[str, Any]:
    if isinstance(result, Mapping):
        return dict(result)
    if hasattr(result, "to_dict"):
        value = result.to_dict()
        if isinstance(value, Mapping):
            return dict(value)
    return {
        "status": getattr(result, "status", None),
        "error": getattr(result, "error", None),
        "data": getattr(result, "data", None),
    }


def _status(result: Any) -> str:
    payload = _payload(result)
    data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
    return str(payload.get("status") or data.get("status") or "")


def _check(payload: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return next(item for item in payload["checks"] if item["name"] == name)


class AndroidElfPatchPlannerTests(unittest.TestCase):
    def _write(self, root: Path, payload: bytes, name: str = "libfixture.so") -> Path:
        target = root / name
        target.write_bytes(payload)
        return target

    def test_parses_real_elf32_and_strictly_maps_file_backed_pt_load_ranges(self) -> None:
        image = parse_android_elf(
            _minimal_arm_elf32(load_file_size=0x180, load_memory_size=0x200)
        )
        self.assertEqual(image.bits, 32)
        self.assertEqual(image.architecture, "arm")
        self.assertEqual(image.supported_instruction_modes, ("arm", "thumb"))
        self.assertEqual(
            image.virtual_address_to_file_offset(
                ARM_CODE_VA | 1,
                2,
                instruction_mode="thumb",
            ),
            ARM_CODE_OFFSET,
        )
        self.assertEqual(image.file_offset_to_virtual_address(ARM_CODE_OFFSET, 4), ARM_CODE_VA)
        with self.assertRaisesRegex(AndroidElfPatchError, "not wholly file-backed"):
            image.virtual_address_to_file_offset(ARM_BASE + 0x190, 4)
        with self.assertRaisesRegex(AndroidElfPatchError, "crosses a PT_LOAD"):
            image.file_offset_to_virtual_address(0x17E, 4)

    def test_thumb_low_bit_is_semantic_and_plan_records_canonical_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_arm_elf32(entrypoint=ARM_CODE_VA | 1))
            out_dir = root / "plan"

            result = plan_android_elf_patch(
                sample,
                out_dir=out_dir,
                virtual_address=ARM_CODE_VA | 1,
                replacement="01 20",
            )

            self.assertEqual(_status(result), "ok", _payload(result))
            plan = json.loads((out_dir / "plan.json").read_text(encoding="utf-8"))
            operation = plan["operations"][0]
            self.assertEqual(operation["architecture"], "arm")
            self.assertEqual(operation["instruction_mode"], "thumb")
            self.assertEqual(operation["selector_virtual_address"], ARM_CODE_VA | 1)
            self.assertEqual(operation["virtual_address"], ARM_CODE_VA)
            self.assertEqual(operation["offset"], ARM_CODE_OFFSET)
            self.assertTrue(operation["thumb_address_bit"])
            self.assertEqual(operation["instruction_alignment"], 2)
            self.assertEqual(operation["preimage"], ARM_CODE[:2].hex())
            self.assertEqual(plan["target_identity"]["sha256"], _sha256(sample))
            for artifact in ("plan.json", "verify.json", "risk_report.json", "rollback_plan.json"):
                self.assertTrue((out_dir / artifact).is_file(), artifact)
            verified = verify_android_elf_patch(sample, plan=out_dir / "plan.json")
            self.assertEqual(_status(verified), "ok", _payload(verified))

    def test_arm_and_thumb_alignment_rules_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_arm_elf32())
            misaligned_arm = plan_android_elf_patch(
                sample,
                out_dir=root / "misaligned-arm",
                virtual_address=ARM_CODE_VA + 2,
                replacement="00 f0 20 e3",
                instruction_mode="arm",
            )
            short_arm = plan_android_elf_patch(
                sample,
                out_dir=root / "short-arm",
                virtual_address=ARM_CODE_VA,
                replacement="00 bf",
                instruction_mode="arm",
            )
            odd_arm = plan_android_elf_patch(
                sample,
                out_dir=root / "odd-arm",
                virtual_address=ARM_CODE_VA | 1,
                replacement="00 f0 20 e3",
                instruction_mode="arm",
            )

            for result in (misaligned_arm, short_arm, odd_arm):
                self.assertEqual(_status(result), "failed", _payload(result))
            self.assertIn("not 4-byte aligned", str(misaligned_arm.error))
            self.assertIn("not a multiple of 4", str(short_arm.error))
            self.assertIn("Thumb state", str(odd_arm.error))

    def test_elf64_aarch64_architecture_and_alignment_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_aarch64_elf64())
            image = parse_android_elf(sample)
            self.assertEqual((image.bits, image.architecture), (64, "aarch64"))
            self.assertEqual(image.va_to_offset(AARCH64_CODE_VA, 4), AARCH64_CODE_OFFSET)

            result = plan_android_elf_patch(
                sample,
                out_dir=root / "valid",
                virtual_address=AARCH64_CODE_VA,
                replacement="c0 03 5f d6",  # RET
            )
            self.assertEqual(_status(result), "ok", _payload(result))
            plan = json.loads((root / "valid" / "plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["operations"][0]["instruction_mode"], "aarch64")

            wrong_mode = plan_android_elf_patch(
                sample,
                out_dir=root / "wrong-mode",
                virtual_address=AARCH64_CODE_VA,
                replacement="c0 03 5f d6",
                instruction_mode="thumb",
            )
            misaligned = plan_android_elf_patch(
                sample,
                out_dir=root / "misaligned",
                virtual_address=AARCH64_CODE_VA + 2,
                replacement="c0 03 5f d6",
            )
            self.assertEqual(_status(wrong_mode), "failed")
            self.assertEqual(_status(misaligned), "failed")

    def test_file_bounds_virtual_tail_and_cross_segment_ranges_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(
                root,
                _minimal_arm_elf32(load_file_size=0x180, load_memory_size=0x200),
            )
            cross = plan_android_elf_patch(
                sample,
                out_dir=root / "cross",
                file_offset=0x17E,
                replacement="00 f0 20 e3",
                instruction_mode="arm",
            )
            virtual_tail = plan_android_elf_patch(
                sample,
                out_dir=root / "tail",
                virtual_address=ARM_BASE + 0x190,
                replacement="00 f0 20 e3",
                instruction_mode="arm",
            )
            outside = plan_android_elf_patch(
                sample,
                out_dir=root / "outside",
                file_offset=len(sample.read_bytes()) - 2,
                replacement="00 f0 20 e3",
                instruction_mode="arm",
            )
            for result in (cross, virtual_tail, outside):
                self.assertEqual(_status(result), "failed", _payload(result))
            self.assertFalse((root / "cross" / "plan.json").exists())

    def test_verify_rechecks_current_hash_and_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_arm_elf32())
            plan_dir = root / "plan"
            planned = plan_android_elf_patch(
                sample,
                out_dir=plan_dir,
                virtual_address=ARM_CODE_VA,
                replacement="1e ff 2f e1",  # BX LR
                instruction_mode="arm",
            )
            self.assertEqual(_status(planned), "ok", _payload(planned))

            changed = bytearray(sample.read_bytes())
            changed[ARM_CODE_OFFSET] ^= 0xFF
            sample.write_bytes(changed)
            verify_dir = root / "reverify"
            verified = verify_android_elf_patch(
                sample,
                plan=plan_dir / "plan.json",
                out_dir=verify_dir,
            )

            self.assertEqual(_status(verified), "failed", _payload(verified))
            verification = json.loads((verify_dir / "verify.json").read_text(encoding="utf-8"))
            self.assertEqual(_check(verification, "target_hash")["status"], "failed")
            self.assertEqual(_check(verification, "operation_ranges")["status"], "failed")
            self.assertTrue(
                any("preimage" in message for message in verification["errors"]),
                verification["errors"],
            )
            rollback = json.loads((verify_dir / "rollback_plan.json").read_text(encoding="utf-8"))
            self.assertFalse(rollback["reversible"])

    def test_relocation_target_overlap_is_a_deterministic_critical_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relocation_va = ARM_CODE_VA + 8
            sample = self._write(
                root,
                _minimal_arm_elf32(relocation_va=relocation_va),
            )
            plan_dir = root / "plan"
            planned = plan_android_elf_patch(
                sample,
                out_dir=plan_dir,
                virtual_address=relocation_va,
                replacement="1e ff 2f e1",
                instruction_mode="arm",
            )
            self.assertEqual(_status(planned), "ok", _payload(planned))
            first_risk = json.loads((plan_dir / "risk_report.json").read_text(encoding="utf-8"))
            self.assertEqual(first_risk["overall_risk"], "critical")
            relocation_findings = [
                item
                for item in first_risk["findings"]
                if item["id"].startswith("relocation_target_intersection")
            ]
            self.assertEqual(len(relocation_findings), 1)
            self.assertEqual(relocation_findings[0]["evidence"]["virtual_address"], relocation_va)

            second_dir = root / "verify-again"
            verified = verify_android_elf_patch(
                sample,
                plan=plan_dir / "plan.json",
                out_dir=second_dir,
            )
            self.assertEqual(_status(verified), "ok", _payload(verified))
            second_risk = json.loads((second_dir / "risk_report.json").read_text(encoding="utf-8"))
            self.assertEqual(first_risk, second_risk)

    def test_segment_permission_risks_cover_non_writable_and_non_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_arm_elf32(segment_flags=0x4))
            planned = plan_android_elf_patch(
                sample,
                out_dir=root / "plan",
                virtual_address=ARM_CODE_VA,
                replacement="1e ff 2f e1",
                instruction_mode="arm",
            )
            self.assertEqual(_status(planned), "ok", _payload(planned))
            risk = json.loads((root / "plan" / "risk_report.json").read_text(encoding="utf-8"))
            ids = {item["id"].split(":", 1)[0] for item in risk["findings"]}
            self.assertIn("segment_not_writable", ids)
            self.assertIn("segment_not_executable", ids)

    def test_plan_is_consumable_by_generic_executor_and_rollback_bytes_restore_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_aarch64_elf64())
            source = sample.read_bytes()
            plan_dir = root / "plan"
            planned = plan_android_elf_patch(
                sample,
                out_dir=plan_dir,
                file_offset=AARCH64_CODE_OFFSET,
                replacement="c0 03 5f d6",
                instruction_mode="aarch64",
            )
            self.assertEqual(_status(planned), "ok", _payload(planned))
            plan = json.loads((plan_dir / "plan.json").read_text(encoding="utf-8"))
            output = root / "patched.so"
            applied = binary_patch_apply_plan(
                sample,
                plan=plan,
                out_path=output,
                apply=True,
                artifact_dir=root / "apply-artifacts",
            )
            self.assertEqual(applied.status, "ok", applied.error)
            self.assertEqual(sample.read_bytes(), source)
            self.assertNotEqual(output.read_bytes(), source)

            rollback = json.loads((plan_dir / "rollback_plan.json").read_text(encoding="utf-8"))
            self.assertTrue(rollback["reversible"])
            self.assertEqual(rollback["source_sha256"], _sha256(source))
            self.assertEqual(rollback["patched_sha256"], _sha256(output))
            restored = bytearray(output.read_bytes())
            for operation in reversed(rollback["operations"]):
                offset = operation["file_offset"]
                expected = bytes.fromhex(operation["expected"])
                replacement = bytes.fromhex(operation["replacement"])
                self.assertEqual(restored[offset : offset + len(expected)], expected)
                restored[offset : offset + len(expected)] = replacement
            self.assertEqual(bytes(restored), source)

    def test_verify_rejects_tampered_va_mapping_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write(root, _minimal_arm_elf32())
            plan_dir = root / "plan"
            self.assertEqual(
                _status(
                    plan_android_elf_patch(
                        sample,
                        out_dir=plan_dir,
                        virtual_address=ARM_CODE_VA,
                        replacement="1e ff 2f e1",
                        instruction_mode="arm",
                    )
                ),
                "ok",
            )
            plan = json.loads((plan_dir / "plan.json").read_text(encoding="utf-8"))
            plan["operations"][0]["virtual_address"] += 4
            plan["rollback_plan"]["operations"][0]["replacement"] = "00000000"
            verified = verify_android_elf_patch(
                sample,
                plan=plan,
                out_dir=root / "verify",
            )
            self.assertEqual(_status(verified), "failed", _payload(verified))
            self.assertIn("PT_LOAD file-offset mapping", str(verified.error))

    def test_rejects_big_endian_and_non_arm_elf_identity(self) -> None:
        with self.assertRaisesRegex(AndroidElfPatchError, "little-endian"):
            parse_android_elf(_minimal_arm_elf32(data_encoding=2))
        with self.assertRaisesRegex(AndroidElfPatchError, "unsupported ELF machine"):
            parse_android_elf(_minimal_arm_elf32(machine=3))


if __name__ == "__main__":
    unittest.main()
