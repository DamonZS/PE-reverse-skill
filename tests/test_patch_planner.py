import builtins
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch

import pefile

from reverse_analyzer.patch import plan_pe_patch, verify_pe_patch
from reverse_analyzer.tools import binary_patch_apply_plan


ROOT = Path(__file__).resolve().parents[1]
TEXT_OFFSET = 0x200
TEXT_RVA = 0x1000
TEXT_CODE = bytes.fromhex("55 8B EC 83 EC 08 33 C0 5D C3")
RDATA_OFFSET = 0x400
RDATA_RVA = 0x2000
IAT_OFFSET = 0x460
IAT_RVA = 0x2060
RESOURCE_DIRECTORY_OFFSET = 0x480
RESOURCE_DIRECTORY_RVA = 0x2080
RESOURCE_DATA_OFFSET = 0x4E0
RESOURCE_DATA_RVA = 0x20E0
RESOURCE_BYTES = b"RESOURCE"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _minimal_pe32(
    *,
    authenticode: bool = False,
    overlay: bytes = b"",
    section_gap: bool = False,
) -> bytes:
    """Build a small, pefile-parseable PE32 with .text and .rdata sections."""

    pe_offset = 0x80
    optional_offset = pe_offset + 24
    section_table = optional_offset + 0xE0
    data = bytearray(0x600)

    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        data,
        pe_offset + 4,
        0x014C,  # IMAGE_FILE_MACHINE_I386
        2,
        0,
        0,
        0,
        0xE0,
        0x0102,  # executable, 32-bit
    )

    struct.pack_into("<H", data, optional_offset, 0x10B)
    data[optional_offset + 2] = 14
    struct.pack_into("<I", data, optional_offset + 4, 0x200)  # SizeOfCode
    struct.pack_into("<I", data, optional_offset + 8, 0x200)  # initialized data
    struct.pack_into("<I", data, optional_offset + 16, TEXT_RVA)
    struct.pack_into("<I", data, optional_offset + 20, TEXT_RVA)
    struct.pack_into("<I", data, optional_offset + 24, 0x2000)
    struct.pack_into("<I", data, optional_offset + 28, 0x400000)
    struct.pack_into("<I", data, optional_offset + 32, 0x1000)
    struct.pack_into("<I", data, optional_offset + 36, 0x200)
    struct.pack_into("<H", data, optional_offset + 40, 4)
    struct.pack_into("<H", data, optional_offset + 48, 4)
    struct.pack_into("<I", data, optional_offset + 56, 0x3000)
    struct.pack_into("<I", data, optional_offset + 60, 0x200)
    struct.pack_into("<H", data, optional_offset + 68, 3)  # console subsystem
    struct.pack_into("<I", data, optional_offset + 72, 0x100000)
    struct.pack_into("<I", data, optional_offset + 76, 0x1000)
    struct.pack_into("<I", data, optional_offset + 80, 0x100000)
    struct.pack_into("<I", data, optional_offset + 84, 0x1000)
    struct.pack_into("<I", data, optional_offset + 92, 16)
    resource_directory = optional_offset + 96 + (2 * 8)
    struct.pack_into("<II", data, resource_directory, RESOURCE_DIRECTORY_RVA, 0x68)
    iat_directory = optional_offset + 96 + (12 * 8)
    struct.pack_into("<II", data, iat_directory, IAT_RVA, 8)

    text_section = section_table
    data[text_section : text_section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, text_section + 8, len(TEXT_CODE))
    struct.pack_into("<I", data, text_section + 12, TEXT_RVA)
    struct.pack_into("<I", data, text_section + 16, 0x200)
    struct.pack_into("<I", data, text_section + 20, TEXT_OFFSET)
    struct.pack_into("<I", data, text_section + 36, 0x60000020)

    rdata_section = section_table + 40
    data[rdata_section : rdata_section + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", data, rdata_section + 8, 0x40)
    struct.pack_into("<I", data, rdata_section + 12, RDATA_RVA)
    struct.pack_into("<I", data, rdata_section + 16, 0x200)
    struct.pack_into("<I", data, rdata_section + 20, RDATA_OFFSET)
    struct.pack_into("<I", data, rdata_section + 36, 0x40000040)

    data[TEXT_OFFSET : TEXT_OFFSET + 0x200] = b"\x90" * 0x200
    data[TEXT_OFFSET : TEXT_OFFSET + len(TEXT_CODE)] = TEXT_CODE
    data[RDATA_OFFSET : RDATA_OFFSET + 0x10] = b"PATCH-RISK-DATA\x00"
    struct.pack_into("<II", data, IAT_OFFSET, 0x20F0, 0)

    # RT_RCDATA(10) -> resource id 1 -> language 1033 -> one data entry.
    struct.pack_into("<IIHHHH", data, RESOURCE_DIRECTORY_OFFSET, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, RESOURCE_DIRECTORY_OFFSET + 16, 10, 0x80000018)
    struct.pack_into("<IIHHHH", data, RESOURCE_DIRECTORY_OFFSET + 0x18, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, RESOURCE_DIRECTORY_OFFSET + 0x28, 1, 0x80000030)
    struct.pack_into("<IIHHHH", data, RESOURCE_DIRECTORY_OFFSET + 0x30, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", data, RESOURCE_DIRECTORY_OFFSET + 0x40, 1033, 0x48)
    struct.pack_into(
        "<IIII",
        data,
        RESOURCE_DIRECTORY_OFFSET + 0x48,
        RESOURCE_DATA_RVA,
        len(RESOURCE_BYTES),
        0,
        0,
    )
    data[RESOURCE_DATA_OFFSET : RESOURCE_DATA_OFFSET + len(RESOURCE_BYTES)] = RESOURCE_BYTES

    if section_gap:
        data.extend(b"\x00" * 0x200)
        data[0x600:0x800] = data[0x400:0x600]
        data[0x400:0x600] = b"\x00" * 0x200
        struct.pack_into("<I", data, rdata_section + 20, 0x600)

    if authenticode:
        security_directory = optional_offset + 96 + (4 * 8)
        struct.pack_into("<II", data, security_directory, len(data), 8)
        data.extend(struct.pack("<IHH", 8, 0x0200, 0x0002))
    data.extend(overlay)
    return bytes(data)


def _result_payload(result: Any) -> dict[str, Any]:
    if isinstance(result, Mapping):
        return dict(result)
    if hasattr(result, "to_dict"):
        payload = result.to_dict()
        if isinstance(payload, Mapping):
            return dict(payload)
    payload: dict[str, Any] = {}
    for name in ("status", "error", "data", "metadata"):
        if hasattr(result, name):
            payload[name] = getattr(result, name)
    return payload


def _result_status(result: Any) -> str:
    payload = _result_payload(result)
    return str(payload.get("status") or payload.get("data", {}).get("status") or "")


def _hex(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    return "".join(str(value or "").replace("0x", "").split()).casefold()


def _risk_text(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).casefold()


class PePatchPlannerTests(unittest.TestCase):
    def _write_fixture(
        self,
        root: Path,
        *,
        authenticode: bool = False,
        overlay: bytes = b"",
        section_gap: bool = False,
    ) -> Path:
        sample = root / "fixture.exe"
        sample.write_bytes(
            _minimal_pe32(
                authenticode=authenticode,
                overlay=overlay,
                section_gap=section_gap,
            )
        )
        pe = pefile.PE(str(sample), fast_load=False)
        self.assertEqual(pe.FILE_HEADER.Machine, 0x014C)
        self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x10B)
        self.assertEqual(pe.get_offset_from_rva(TEXT_RVA), TEXT_OFFSET)
        self.assertEqual([section.Name.rstrip(b"\x00") for section in pe.sections], [b".text", b".rdata"])
        pe.close()
        return sample

    def _plan_and_verify(
        self,
        sample: Path,
        out_dir: Path,
        *,
        intent: Mapping[str, Any],
        strategy: str = "auto",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        planned = plan_pe_patch(sample, intent=dict(intent), out_dir=out_dir, strategy=strategy)
        self.assertIn(_result_status(planned), {"ok", "planned"}, _result_payload(planned))
        plan_path = out_dir / "plan.json"
        verified = verify_pe_patch(sample, plan=plan_path, out_dir=out_dir)
        self.assertEqual(_result_status(verified), "ok", _result_payload(verified))
        return (
            json.loads(plan_path.read_text(encoding="utf-8")),
            _result_payload(verified),
        )

    def _exercise_advanced_strategy(
        self,
        root: Path,
        *,
        strategy: str,
        intent: Mapping[str, Any],
        overlay: bytes = b"",
        section_gap: bool = False,
    ) -> tuple[dict[str, Any], bytes, bytes]:
        case_root = root / strategy
        case_root.mkdir()
        sample = self._write_fixture(case_root, overlay=overlay, section_gap=section_gap)
        original = sample.read_bytes()
        plan_dir = case_root / "plan"

        plan, _ = self._plan_and_verify(
            sample,
            plan_dir,
            intent=intent,
            strategy=strategy,
        )
        self.assertEqual(plan["strategy"], strategy)
        self.assertTrue(plan.get("strategy_details"), plan)
        self.assertTrue(
            all(operation["kind"] in {"replace_offset", "replace_rva", "replace_aob"} for operation in plan["operations"]),
            plan["operations"],
        )
        rollback = json.loads((plan_dir / "rollback_plan.json").read_text(encoding="utf-8"))
        self.assertTrue(rollback["reversible"], rollback)
        self.assertEqual(len(rollback["operations"]), len(plan["operations"]))

        output = case_root / "patched.exe"
        applied = binary_patch_apply_plan(
            sample,
            plan=plan,
            out_path=output,
            apply=True,
            artifact_dir=case_root / "apply-artifacts",
        )
        self.assertEqual(applied.status, "ok", applied.error)
        self.assertTrue(output.is_file())
        self.assertEqual(sample.read_bytes(), original)
        self.assertNotEqual(output.read_bytes(), original)
        return plan, original, output.read_bytes()

    def test_offset_rva_and_aob_intents_capture_preimage_and_write_four_artifacts(self) -> None:
        cases = [
            (
                "offset",
                {"offset": TEXT_OFFSET, "replacement": "90"},
                "55",
            ),
            (
                "rva",
                {"rva": TEXT_RVA + 1, "replacement": "90 90"},
                "8bec",
            ),
            (
                "aob",
                {"aob": "33 C0 5D C3", "replacement": "31 C0 5D C3"},
                "33c05dc3",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            original_hash = _sha256(sample)

            for name, intent, expected_preimage in cases:
                with self.subTest(intent=name):
                    out_dir = root / name
                    plan, _ = self._plan_and_verify(sample, out_dir, intent=intent)
                    operation = plan["operations"][0]
                    captured_preimage = (
                        operation.get("expected")
                        or operation.get("preimage")
                        or operation.get("resolved_preimage")
                        or operation.get("pattern")
                    )
                    self.assertEqual(_hex(captured_preimage), expected_preimage)
                    self.assertEqual(plan["target_sha256"], original_hash)
                    for artifact in (
                        "plan.json",
                        "verify.json",
                        "risk_report.json",
                        "rollback_plan.json",
                    ):
                        self.assertTrue((out_dir / artifact).is_file(), artifact)
                    self.assertEqual(_sha256(sample), original_hash)

    def test_code_cave_strategy_plans_verifies_and_applies_checked_cave_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan, _, patched = self._exercise_advanced_strategy(
                Path(tmp),
                strategy="code_cave_patch",
                intent={"section": ".text", "replacement": "CC CC"},
            )

            self.assertEqual(plan["operations"][0]["role"], "code_cave_payload")
            self.assertEqual(patched[TEXT_OFFSET + len(TEXT_CODE) : TEXT_OFFSET + len(TEXT_CODE) + 2], b"\xCC\xCC")

    def test_section_extend_strategy_grows_aligned_raw_size_into_existing_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan, _, patched = self._exercise_advanced_strategy(
                Path(tmp),
                strategy="section_extend_patch",
                intent={"section": ".text", "replacement": b"\xCC" * 0x202},
                section_gap=True,
            )

            self.assertEqual(plan["strategy_details"]["mode"], "existing_inter_section_gap")
            parsed = pefile.PE(data=patched, fast_load=False)
            self.assertEqual(parsed.sections[0].Misc_VirtualSize, len(TEXT_CODE) + 0x202)
            self.assertEqual(parsed.sections[0].SizeOfRawData, 0x400)
            self.assertEqual(parsed.sections[1].PointerToRawData, 0x600)
            parsed.close()

    def test_resource_replace_strategy_targets_parsed_resource_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan, _, patched = self._exercise_advanced_strategy(
                Path(tmp),
                strategy="resource_replace",
                intent={
                    "resource_type": 10,
                    "resource_name": 1,
                    "resource_lang": 1033,
                    "replacement": b"NEW".hex(),
                },
            )

            self.assertEqual(
                {operation["role"] for operation in plan["operations"]},
                {"resource_data", "resource_size"},
            )
            self.assertEqual(patched[RESOURCE_DATA_OFFSET : RESOURCE_DATA_OFFSET + 8], b"NEW\x00\x00\x00\x00\x00")
            parsed = pefile.PE(data=patched, fast_load=False)
            leaf = parsed.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].directory.entries[0]
            self.assertEqual(leaf.data.struct.Size, 3)
            parsed.close()

    def test_iat_thunk_strategy_replaces_one_pointer_sized_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan, _, patched = self._exercise_advanced_strategy(
                Path(tmp),
                strategy="iat_thunk_patch",
                intent={"rva": IAT_RVA, "replacement": "34 12 40 00"},
            )

            self.assertEqual(plan["strategy_details"]["pointer_size"], 4)
            self.assertEqual(patched[IAT_OFFSET : IAT_OFFSET + 4], bytes.fromhex("34 12 40 00"))

    def test_entrypoint_redirect_strategy_updates_header_and_target_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target_rva = TEXT_RVA + 0x20
            plan, _, patched = self._exercise_advanced_strategy(
                Path(tmp),
                strategy="entrypoint_redirect",
                intent={"target_rva": target_rva, "replacement": "CC"},
            )

            self.assertEqual(
                {operation["role"] for operation in plan["operations"]},
                {"entrypoint_target_payload", "address_of_entrypoint"},
            )
            parsed = pefile.PE(data=patched, fast_load=False)
            self.assertEqual(parsed.OPTIONAL_HEADER.AddressOfEntryPoint, target_rva)
            parsed.close()

    def test_entrypoint_redirect_without_payload_reports_new_basic_block_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            out_dir = root / "patch"
            target_rva = TEXT_RVA + 0x20

            plan, _ = self._plan_and_verify(
                sample,
                out_dir,
                intent={"target_rva": target_rva},
                strategy="entrypoint_redirect",
            )

            self.assertEqual(
                [operation["role"] for operation in plan["operations"]],
                ["address_of_entrypoint"],
            )
            verification = json.loads((out_dir / "verify.json").read_text(encoding="utf-8"))
            basic_cfg = next(item for item in verification["checks"] if item["name"] == "basic_cfg")
            redirect = basic_cfg["entrypoint_redirect"]
            self.assertEqual(basic_cfg["status"], "passed")
            self.assertEqual(redirect["new_entrypoint_rva"], target_rva)
            self.assertEqual(redirect["new_entrypoint_file_offset"], TEXT_OFFSET + 0x20)
            self.assertTrue(redirect["instruction_boundary"])
            self.assertTrue(redirect["basic_block_entry"])
            self.assertEqual(redirect["entry_sources"], ["address_of_entrypoint"])
            self.assertEqual(redirect["payload_size"], 0)

    def test_overlay_preserve_strategy_keeps_overlay_byte_exact(self) -> None:
        overlay = b"OVERLAY-MUST-STAY-BYTE-EXACT"
        with tempfile.TemporaryDirectory() as tmp:
            plan, original, patched = self._exercise_advanced_strategy(
                Path(tmp),
                strategy="overlay_preserve_patch",
                intent={"offset": RDATA_OFFSET, "replacement": "51"},
                overlay=overlay,
            )

            self.assertEqual(plan["strategy_details"]["overlay_sha256"], hashlib.sha256(overlay).hexdigest())
            self.assertEqual(original[-len(overlay) :], overlay)
            self.assertEqual(patched[-len(overlay) :], overlay)

    def test_acceptance_runner_retains_all_seven_production_strategy_artifacts(self) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            return

        acceptance_root = Path(configured).expanduser().resolve()
        patch_root = acceptance_root / "patch"
        strategy_root = patch_root / "strategies"
        strategy_root.mkdir(parents=True, exist_ok=True)
        cases = (
            (
                "inline_patch",
                {"offset": TEXT_OFFSET, "replacement": "90"},
                {},
            ),
            (
                "code_cave_patch",
                {"section": ".text", "replacement": "CC CC"},
                {},
            ),
            (
                "section_extend_patch",
                {"section": ".text", "replacement": b"\xCC" * 0x202},
                {"section_gap": True},
            ),
            (
                "resource_replace",
                {
                    "resource_type": 10,
                    "resource_name": 1,
                    "resource_lang": 1033,
                    "replacement": b"NEW".hex(),
                },
                {},
            ),
            (
                "iat_thunk_patch",
                {"rva": IAT_RVA, "replacement": "34 12 40 00"},
                {},
            ),
            (
                "entrypoint_redirect",
                {"target_rva": TEXT_RVA + 0x20, "replacement": "CC"},
                {},
            ),
            (
                "overlay_preserve_patch",
                {"offset": RDATA_OFFSET, "replacement": "51"},
                {"overlay": b"P2-ACCEPTANCE-OVERLAY"},
            ),
        )
        outcomes: list[dict[str, Any]] = []
        for strategy, intent, fixture_options in cases:
            case_root = strategy_root / strategy
            case_root.mkdir(parents=True, exist_ok=False)
            sample = self._write_fixture(case_root, **fixture_options)
            source_hash = _sha256(sample)
            artifacts = case_root / "artifacts"
            plan, verification = self._plan_and_verify(
                sample,
                artifacts,
                intent=intent,
                strategy=strategy,
            )
            patched = case_root / "patched.exe"
            applied = binary_patch_apply_plan(
                sample,
                plan=plan,
                out_path=patched,
                apply=True,
                artifact_dir=case_root / "apply-artifacts",
            )
            self.assertEqual(applied.status, "ok", applied.error)
            self.assertEqual(_sha256(sample), source_hash)
            self.assertNotEqual(_sha256(patched), source_hash)
            outcomes.append(
                {
                    "strategy": strategy,
                    "planner": plan.get("planner"),
                    "plan_status": "planned",
                    "verification_status": _result_status(verification),
                    "apply_status": applied.status,
                    "source_sha256": source_hash,
                    "patched_sha256": _sha256(patched),
                    "artifacts": [
                        str((artifacts / name).relative_to(acceptance_root).as_posix())
                        for name in ("plan.json", "verify.json", "risk_report.json", "rollback_plan.json")
                    ],
                }
            )

        canonical = strategy_root / "inline_patch" / "artifacts"
        for name in ("plan.json", "verify.json", "rollback_plan.json"):
            shutil.copy2(canonical / name, patch_root / name)
        (patch_root / "acceptance-summary.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "passed",
                    "evidence_level": "repository-production-backend",
                    "producer": "reverse_analyzer.patch.plan_pe_patch",
                    "executor": "reverse_analyzer.tools.binary_patch_apply_plan",
                    "strategy_count": len(outcomes),
                    "strategies": outcomes,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_advanced_strategies_fail_with_actionable_missing_or_ambiguous_intent(self) -> None:
        cases = [
            ("code_cave_patch", {"section": ".text"}, "replacement"),
            ("section_extend_patch", {"replacement": "CC CC"}, "unique section"),
            (
                "resource_replace",
                {"resource_type": 999, "replacement": "41"},
                "matched 0 resources",
            ),
            ("iat_thunk_patch", {"replacement": "34 12 40 00"}, "provide dll/symbol"),
            ("entrypoint_redirect", {"replacement": "CC"}, "requires new_entrypoint_rva"),
            (
                "overlay_preserve_patch",
                {"offset": RDATA_OFFSET, "replacement": "51"},
                "requires an existing pe overlay",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            for strategy, intent, expected in cases:
                with self.subTest(strategy=strategy):
                    out_dir = root / strategy
                    result = plan_pe_patch(
                        sample,
                        out_dir=out_dir,
                        strategy=strategy,
                        intent=intent,
                    )
                    self.assertEqual(_result_status(result), "failed", _result_payload(result))
                    self.assertIn(expected, _risk_text(_result_payload(result)))
                    self.assertFalse(out_dir.exists())

    def test_missing_intent_returns_needs_intent_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            out_dir = root / "patch"
            original_hash = _sha256(sample)

            result = plan_pe_patch(sample, out_dir=out_dir)

            self.assertEqual(_result_status(result), "needs_intent", _result_payload(result))
            self.assertFalse(out_dir.exists(), list(out_dir.rglob("*")) if out_dir.exists() else [])
            self.assertEqual(_sha256(sample), original_hash)

    def test_planning_artifacts_never_overwrite_a_same_named_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "plan.json"
            original = _minimal_pe32()
            sample.write_bytes(original)

            result = plan_pe_patch(
                sample,
                out_dir=root,
                offset=TEXT_OFFSET,
                replacement="90",
            )

            self.assertEqual(_result_status(result), "failed", _result_payload(result))
            self.assertIn("path collision", str(_result_payload(result).get("error") or "").casefold())
            self.assertEqual(sample.read_bytes(), original)
            self.assertFalse((root / "verify.json").exists())
            self.assertFalse((root / "risk_report.json").exists())
            self.assertFalse((root / "rollback_plan.json").exists())

    def test_verify_requires_target_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            out_dir = root / "patch"
            plan = {
                "schema_version": 1,
                "operations": [
                    {
                        "id": "missing-hash",
                        "kind": "replace_offset",
                        "offset": TEXT_OFFSET,
                        "expected": "55",
                        "replacement": "90",
                    }
                ],
            }

            result = verify_pe_patch(sample, plan=plan, out_dir=out_dir)

            self.assertEqual(_result_status(result), "failed", _result_payload(result))
            self.assertIn("target_sha256", _risk_text(_result_payload(result)))
            verification = json.loads((out_dir / "verify.json").read_text(encoding="utf-8"))
            self.assertFalse(verification["valid"])

    def test_executable_patch_fails_closed_when_capstone_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            plan = {
                "schema_version": 1,
                "target_sha256": _sha256(sample),
                "operations": [
                    {
                        "id": "needs-disassembly",
                        "kind": "replace_offset",
                        "offset": TEXT_OFFSET,
                        "expected": "55",
                        "replacement": "90",
                    }
                ],
            }
            real_import = builtins.__import__

            def import_without_capstone(name, *args, **kwargs):
                if name == "capstone":
                    raise ImportError("capstone intentionally unavailable")
                return real_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=import_without_capstone):
                result = verify_pe_patch(sample, plan=plan, out_dir=root / "patch")

            self.assertEqual(_result_status(result), "failed", _result_payload(result))
            self.assertIn("capstone", _risk_text(_result_payload(result)))

    def test_executable_patch_fails_closed_for_unsupported_pe_machine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            data = bytearray(sample.read_bytes())
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            struct.pack_into("<H", data, pe_offset + 4, 0xAA64)
            sample.write_bytes(data)
            plan = {
                "schema_version": 1,
                "target_sha256": _sha256(sample),
                "operations": [
                    {
                        "id": "unsupported-machine",
                        "kind": "replace_offset",
                        "offset": TEXT_OFFSET,
                        "expected": "55",
                        "replacement": "90",
                    }
                ],
            }

            result = verify_pe_patch(sample, plan=plan, out_dir=root / "patch")

            self.assertEqual(_result_status(result), "failed", _result_payload(result))
            text = _risk_text(_result_payload(result))
            self.assertIn("unsupported", text)
            self.assertIn("0xaa64", text)

    def test_sequential_aob_resolution_matches_patch_engine_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            data = bytearray(sample.read_bytes())
            data[0x420:0x424] = bytes.fromhex("AA BB AA BB")
            sample.write_bytes(data)
            plan = {
                "schema_version": 1,
                "target_sha256": _sha256(sample),
                "operations": [
                    {
                        "id": "remove-first-match",
                        "kind": "replace_aob",
                        "pattern": "AA BB",
                        "replacement": "CC DD",
                        "expected_match_count": 2,
                        "occurrence": 0,
                    },
                    {
                        "id": "replace-remaining-match",
                        "kind": "replace_aob",
                        "pattern": "AA BB",
                        "replacement": "EE FF",
                        "expected_match_count": 1,
                        "occurrence": 0,
                    },
                ],
            }
            artifact_dir = root / "patch"

            verified = verify_pe_patch(sample, plan=plan, out_dir=artifact_dir)
            self.assertEqual(_result_status(verified), "ok", _result_payload(verified))
            rollback = json.loads((artifact_dir / "rollback_plan.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [item["file_offset"] for item in rollback["operations"]],
                [0x420, 0x422],
            )

            output = root / "patched.exe"
            applied = binary_patch_apply_plan(
                sample,
                plan=plan,
                out_path=output,
                apply=True,
                artifact_dir=root / "apply-artifacts",
            )
            self.assertEqual(applied.status, "ok", applied.error)
            self.assertEqual(output.read_bytes()[0x420:0x424], bytes.fromhex("CC DD EE FF"))

    def test_verify_rejects_patch_that_splits_an_executable_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            out_dir = root / "patch"
            split_instruction_plan = {
                "schema_version": 1,
                "target_sha256": _sha256(sample),
                "operations": [
                    {
                        "id": "split-sub-esp",
                        "kind": "replace_offset",
                        "offset": TEXT_OFFSET + 4,
                        "expected": "EC",
                        "replacement": "90",
                    }
                ],
            }

            result = verify_pe_patch(sample, plan=split_instruction_plan, out_dir=out_dir)

            self.assertEqual(_result_status(result), "failed", _result_payload(result))
            verify_payload = json.loads((out_dir / "verify.json").read_text(encoding="utf-8"))
            self.assertIn(verify_payload.get("status"), {"failed", "rejected"})
            text = _risk_text(verify_payload)
            self.assertTrue(
                "instruction" in text or "boundary" in text or "disassembly" in text,
                verify_payload,
            )
            self.assertEqual(sample.read_bytes()[TEXT_OFFSET : TEXT_OFFSET + len(TEXT_CODE)], TEXT_CODE)

    def test_verify_rejects_overlapping_operations_with_ambiguous_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            out_dir = root / "patch"
            overlapping_plan = {
                "schema_version": 1,
                "target_sha256": _sha256(sample),
                "operations": [
                    {
                        "id": "first",
                        "kind": "replace_offset",
                        "offset": 0x400,
                        "expected": "5041",
                        "replacement": "9090",
                    },
                    {
                        "id": "second",
                        "kind": "replace_offset",
                        "offset": 0x401,
                        "expected": "90",
                        "replacement": "cc",
                    },
                ],
            }

            result = verify_pe_patch(sample, plan=overlapping_plan, out_dir=out_dir)

            self.assertEqual(_result_status(result), "failed", _result_payload(result))
            verification = json.loads((out_dir / "verify.json").read_text(encoding="utf-8"))
            self.assertIn("overlap", _risk_text(verification))
            rollback = json.loads((out_dir / "rollback_plan.json").read_text(encoding="utf-8"))
            self.assertFalse(rollback["reversible"])

    def test_basic_cfg_reports_patch_range_rva_boundaries_and_entry_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            out_dir = root / "patch"

            self._plan_and_verify(
                sample,
                out_dir,
                intent={"offset": TEXT_OFFSET, "replacement": "90"},
            )

            verification = json.loads((out_dir / "verify.json").read_text(encoding="utf-8"))
            basic_cfg = next(item for item in verification["checks"] if item["name"] == "basic_cfg")
            operation = basic_cfg["operations"][0]
            patch_range = operation["patch_range"]
            self.assertEqual(patch_range["file_offset_start"], TEXT_OFFSET)
            self.assertEqual(patch_range["file_offset_end"], TEXT_OFFSET + 1)
            self.assertEqual(patch_range["rva_start"], TEXT_RVA)
            self.assertEqual(patch_range["rva_end"], TEXT_RVA + 1)
            self.assertTrue(patch_range["start_instruction_boundary"])
            self.assertTrue(patch_range["end_instruction_boundary"])
            entry = next(
                item
                for item in operation["basic_block_entries"]
                if item["file_offset"] == TEXT_OFFSET
            )
            self.assertEqual(entry["rva"], TEXT_RVA)
            self.assertEqual(
                entry["sources"],
                ["address_of_entrypoint", "section_start"],
            )
            self.assertEqual(
                operation["patch_entry_sources"],
                ["address_of_entrypoint", "section_start"],
            )

    def test_resource_strategy_rejects_directory_metadata_disguised_as_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            valid_dir = root / "valid"
            plan, _ = self._plan_and_verify(
                sample,
                valid_dir,
                intent={
                    "resource_type": 10,
                    "resource_name": 1,
                    "resource_lang": 1033,
                    "replacement": b"NEW".hex(),
                },
                strategy="resource_replace",
            )
            data = sample.read_bytes()
            resource_operation = next(
                item for item in plan["operations"] if item["role"] == "resource_data"
            )
            resource_operation.pop("rva", None)
            resource_operation["kind"] = "replace_offset"
            resource_operation["offset"] = RESOURCE_DIRECTORY_OFFSET
            resource_operation["expected"] = data[
                RESOURCE_DIRECTORY_OFFSET : RESOURCE_DIRECTORY_OFFSET + len(RESOURCE_BYTES)
            ].hex()
            resource_operation["replacement"] = resource_operation["expected"]
            plan["strategy_details"]["resource_offset"] = RESOURCE_DIRECTORY_OFFSET
            plan["strategy_details"]["resource_rva"] = RESOURCE_DIRECTORY_RVA

            rejected = verify_pe_patch(sample, plan=plan, out_dir=root / "spoofed")

            self.assertEqual(_result_status(rejected), "failed", _result_payload(rejected))
            self.assertIn("parsed resource data leaf", _risk_text(_result_payload(rejected)))

    def test_signed_pe_with_overlay_reports_patch_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(
                root,
                authenticode=True,
                overlay=b"OVERLAY-EVIDENCE",
            )
            out_dir = root / "patch"

            self._plan_and_verify(
                sample,
                out_dir,
                intent={"offset": TEXT_OFFSET, "replacement": "90"},
            )

            risk = json.loads((out_dir / "risk_report.json").read_text(encoding="utf-8"))
            text = _risk_text(risk)
            self.assertTrue(
                any(token in text for token in ("authenticode", "signature", "security directory", "overlay")),
                risk,
            )

    def test_authenticode_findings_distinguish_digest_exclusions_and_certificate_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root, authenticode=True, overlay=b"OVERLAY")
            data = sample.read_bytes()
            parsed = pefile.PE(str(sample), fast_load=False)
            checksum_offset = parsed.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
            security_entry_offset = parsed.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset()
            certificate_offset = parsed.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
            parsed.close()
            offsets = [TEXT_OFFSET, checksum_offset, security_entry_offset, certificate_offset]
            plan = {
                "schema_version": 1,
                "target_sha256": _sha256(sample),
                "operations": [
                    {
                        "id": f"authenticode-{index}",
                        "kind": "replace_offset",
                        "offset": offset,
                        "expected": data[offset : offset + 1].hex(),
                        "replacement": ("90" if offset == TEXT_OFFSET else data[offset : offset + 1].hex()),
                    }
                    for index, offset in enumerate(offsets)
                ],
            }

            verified = verify_pe_patch(sample, plan=plan, out_dir=root / "patch")

            self.assertEqual(_result_status(verified), "ok", _result_payload(verified))
            risk = json.loads((root / "patch" / "risk_report.json").read_text(encoding="utf-8"))
            finding_ids = [item["id"] for item in risk["findings"]]
            self.assertEqual(finding_ids.count("authenticode_certificate_table_present"), 1)
            for finding_id in (
                "authenticode_checksum_excluded_range",
                "authenticode_security_directory_entry_intersection",
                "authenticode_certificate_table_intersection",
                "authenticode_digest_invalidation",
            ):
                self.assertIn(finding_id, finding_ids)

    def test_cli_plan_apply_and_rollback_preserve_original(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = self._write_fixture(root)
            patch_dir = root / "patch"
            patched = root / "patched.exe"
            restored = root / "restored.exe"
            original = sample.read_bytes()
            original_hash = _sha256(sample)

            commands = [
                [
                    "patch",
                    "plan",
                    str(sample),
                    "--out",
                    str(patch_dir),
                    "--offset",
                    hex(TEXT_OFFSET),
                    "--replacement",
                    "90",
                ],
                [
                    "patch",
                    "verify",
                    str(sample),
                    "--plan",
                    str(patch_dir / "plan.json"),
                    "--out",
                    str(patch_dir),
                ],
                [
                    "patch",
                    "apply",
                    str(sample),
                    "--plan",
                    str(patch_dir / "plan.json"),
                    "--out",
                    str(patched),
                ],
                [
                    "patch",
                    "rollback",
                    str(patched),
                    "--plan",
                    str(patch_dir / "rollback_plan.json"),
                    "--out",
                    str(restored),
                ],
            ]

            for command in commands:
                with self.subTest(command=command[1]):
                    completed = subprocess.run(
                        [sys.executable, "-m", "reverse_analyzer", *command],
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=60,
                    )
                    self.assertEqual(
                        completed.returncode,
                        0,
                        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                    )

            self.assertEqual(_sha256(sample), original_hash)
            self.assertEqual(sample.read_bytes(), original)
            self.assertNotEqual(patched.read_bytes(), original)
            self.assertEqual(patched.read_bytes()[TEXT_OFFSET], 0x90)
            self.assertEqual(restored.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
