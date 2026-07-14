from __future__ import annotations

import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import pefile

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities.audit_contract import (
    validate_capability_audit_record,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.anti_tamper_lab import (
    AntiTamperLabError,
    AntiTamperLabProvider,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _section_header(
    image: bytearray,
    offset: int,
    *,
    name: bytes,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> None:
    image[offset : offset + 8] = name.ljust(8, b"\x00")
    struct.pack_into(
        "<IIIIIIHHI",
        image,
        offset + 8,
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _build_pe_fixture() -> bytes:
    """Build a real PE32 with imports and protection-oriented section data."""

    image = bytearray(0x800)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)

    pe_offset = 0x80
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        pe_offset + 4,
        0x14C,
        3,
        0,
        0,
        0,
        0xE0,
        0x010F,
    )

    optional = pe_offset + 24
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 4, 0x200)
    struct.pack_into("<I", image, optional + 8, 0x400)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<I", image, optional + 24, 0x2000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<I", image, optional + 32, 0x1000)
    struct.pack_into("<I", image, optional + 36, 0x200)
    struct.pack_into("<H", image, optional + 40, 6)
    struct.pack_into("<H", image, optional + 48, 6)
    struct.pack_into("<I", image, optional + 56, 0x4000)
    struct.pack_into("<I", image, optional + 60, 0x200)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<H", image, optional + 70, 0x8140)
    struct.pack_into("<I", image, optional + 72, 0x100000)
    struct.pack_into("<I", image, optional + 76, 0x1000)
    struct.pack_into("<I", image, optional + 80, 0x100000)
    struct.pack_into("<I", image, optional + 84, 0x1000)
    struct.pack_into("<I", image, optional + 92, 16)
    struct.pack_into("<II", image, optional + 104, 0x3000, 0xC0)

    sections = optional + 0xE0
    _section_header(
        image,
        sections,
        name=b".text",
        virtual_size=0x100,
        virtual_address=0x1000,
        raw_size=0x200,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    _section_header(
        image,
        sections + 40,
        name=b".vmp0",
        virtual_size=0x180,
        virtual_address=0x2000,
        raw_size=0x200,
        raw_offset=0x400,
        characteristics=0xE0000040,
    )
    _section_header(
        image,
        sections + 80,
        name=b".idata",
        virtual_size=0x180,
        virtual_address=0x3000,
        raw_size=0x200,
        raw_offset=0x600,
        characteristics=0xC0000040,
    )

    strings = (
        b"integrity checksum failed\x00"
        b"CreateToolhelp32Snapshot Process32First Module32Next\x00"
        b"\\\\.\\LabDriver.sys OpenServiceW StartServiceW\x00"
        b"VMware VirtualBox hypervisor cpuid\x00"
    )
    image[0x400 : 0x400 + len(strings)] = strings
    utf16 = "NtGlobalFlag BeingDebugged".encode("utf-16le") + b"\x00\x00"
    image[0x500 : 0x500 + len(utf16)] = utf16

    struct.pack_into("<IIIII", image, 0x600, 0x3040, 0, 0, 0x3060, 0x3050)
    struct.pack_into("<III", image, 0x640, 0x3070, 0x3090, 0)
    struct.pack_into("<III", image, 0x650, 0x3070, 0x3090, 0)
    image[0x660 : 0x660 + len(b"KERNEL32.dll\x00")] = b"KERNEL32.dll\x00"
    image[0x670 : 0x670 + 2] = b"\x00\x00"
    image[0x672 : 0x672 + len(b"IsDebuggerPresent\x00")] = b"IsDebuggerPresent\x00"
    image[0x690 : 0x690 + 2] = b"\x00\x00"
    image[0x692 : 0x692 + len(b"QueryPerformanceCounter\x00")] = (
        b"QueryPerformanceCounter\x00"
    )
    return bytes(image)


class AntiTamperLabProviderTests(unittest.TestCase):
    def _request(
        self,
        sample: Path,
        *,
        action: str = "analyze",
        params: dict | None = None,
        session_id: str = "anti-tamper-fixture",
        sha256: str | None = None,
    ) -> CapabilityRequest:
        data = sample.read_bytes()
        return CapabilityRequest(
            capability="anti_tamper_lab",
            action=action,
            target=TargetIdentity(
                kind="sample",
                path=str(sample),
                sha256=sha256 if sha256 is not None else _sha256(data),
                display_name=sample.name,
            ),
            params=dict(params or {}),
            session_id=session_id,
            provenance={"source": "test_anti_tamper_lab_provider", "authorized": True},
        )

    def test_real_pe_lifecycle_evidence_artifacts_and_read_only_rollback(self) -> None:
        data = _build_pe_fixture()
        pe = pefile.PE(data=data, fast_load=False)
        self.assertEqual(pe.DIRECTORY_ENTRY_IMPORT[0].dll, b"KERNEL32.dll")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = root / "guarded.exe"
            sample.write_bytes(data)
            out = root / "artifacts"
            provider = AntiTamperLabProvider(
                allowed_input_roots=[root],
                allowed_output_roots=[root],
            )
            request = self._request(sample)

            self.assertTrue(provider.supports(request))
            plan = provider.plan(request)
            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.report_section["mode"], "detection_analysis")
            self.assertEqual(
                result.report_section["anti_detection_and_evasion"], "not_done"
            )
            self.assertFalse(result.after_snapshot["sample_executed"])
            self.assertFalse(result.after_snapshot["side_effects"])
            self.assertTrue(result.provenance["production_provider"])
            self.assertFalse(result.provenance["mocked"])

            analysis = result.report_section["analysis"]
            self.assertEqual(analysis["sample"]["format"], "pe32")
            imported = {
                item["symbol"]
                for item in analysis["sample"]["imports"]
                if item.get("symbol")
            }
            self.assertIn("IsDebuggerPresent", imported)
            self.assertIn("QueryPerformanceCounter", imported)
            self.assertEqual(
                set(analysis["category_summary"]),
                {
                    "anti_debug",
                    "timing",
                    "integrity_checksum",
                    "driver_service",
                    "process_module_enumeration",
                    "vm_environment",
                },
            )
            self.assertTrue(
                any(item.get("section") == ".vmp0" for item in analysis["evidence"])
            )
            self.assertTrue(
                any(item.get("encoding") == "utf-16le" for item in analysis["evidence"])
            )
            self.assertGreaterEqual(len(result.report_section["experiment_matrix"]), 2)
            self.assertGreaterEqual(len(result.report_section["validation_steps"]), 4)

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok, rollback.details)
            self.assertFalse(rollback.restored)
            self.assertEqual(rollback.details["status"], "not_required_read_only")
            self.assertFalse(result.rollback_plan["supported"])
            self.assertFalse(result.rollback_plan["required"])

            bundle = provider.collect_artifacts(result, str(out))
            self.assertEqual(len(bundle.artifacts), 7)
            self.assertEqual(len(bundle.manifest_entries), 7)
            for artifact in bundle.artifacts:
                destination = (out / artifact.path).resolve()
                self.assertTrue(destination.is_file(), artifact.path)
                self.assertIn(out.resolve(), destination.parents)
                entry = next(
                    item for item in bundle.manifest_entries if item["path"] == artifact.path
                )
                encoded = destination.read_bytes()
                self.assertEqual(_sha256(encoded), entry["sha256"])
                self.assertEqual(len(encoded), entry["size"])

            manifest_artifact = next(
                item for item in bundle.artifacts if item.kind == "anti-tamper-manifest"
            )
            manifest = json.loads((out / manifest_artifact.path).read_text("utf-8"))
            self.assertEqual(manifest["mode"], "detection_analysis")
            self.assertTrue(manifest["entries"])

            session_artifact = next(
                item for item in bundle.artifacts if item.kind == "anti-tamper-audit"
            )
            persisted_session = json.loads(
                (out / session_artifact.path).read_text("utf-8")
            )
            persisted_contract = validate_capability_audit_record(persisted_session)
            self.assertTrue(persisted_contract.ok, persisted_contract.errors)

            audit = CapabilityAuditBuilder().build_record(
                plan=plan,
                validation=validation,
                result=result,
            )
            contract = validate_capability_audit_record(audit)
            self.assertTrue(contract.ok, contract.errors)

    def test_malformed_pe_degrades_to_bounded_raw_binary_analysis(self) -> None:
        data = (
            b"MZ"
            + b"\x00" * 126
            + b"IsDebuggerPresent\x00checksum mismatch\x00VMware hypervisor\x00"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = root / "malformed.exe"
            sample.write_bytes(data)
            provider = AntiTamperLabProvider(allowed_input_roots=[root])

            plan = provider.plan(self._request(sample, session_id="malformed-pe"))
            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(result.status, "ok")
            sample_analysis = result.report_section["analysis"]["sample"]
            self.assertEqual(sample_analysis["format"], "binary")
            self.assertEqual(sample_analysis["pe_parse_status"], "not_pe")
            self.assertEqual(sample_analysis["sections"][0]["name"], "raw")
            self.assertEqual(
                sample_analysis["sections"][0]["entropy_sample_size"], len(data)
            )
            self.assertTrue(sample_analysis["parse_warnings"])
            self.assertTrue(
                {"anti_debug", "integrity_checksum", "vm_environment"}.issubset(
                    result.report_section["analysis"]["category_summary"]
                )
            )

    def test_offline_before_after_attribution_and_experiment_plan(self) -> None:
        before = {
            "imports": {"kernel32.dll": ["GetTickCount"]},
            "detectors": [{"name": "sample_guard", "detected": False}],
            "modules": ["kernel32.dll"],
        }
        after = {
            "imports": {
                "kernel32.dll": [
                    "GetTickCount",
                    "IsDebuggerPresent",
                    "CreateToolhelp32Snapshot",
                ]
            },
            "strings": [
                "VMware",
                "checksum mismatch",
                "OpenServiceW driver.sys",
                "offline note: PEB unlink was observed but is not requested",
            ],
            "detectors": [{"name": "sample_guard", "detected": True}],
            "modules": ["kernel32.dll", "inspection.dll"],
        }
        request = CapabilityRequest(
            capability="anti_tamper_lab",
            action="compare_observations",
            target=TargetIdentity(
                kind="offline_observations",
                display_name="controlled-lab-run",
                sha256=_sha256(b"controlled-lab-run"),
            ),
            params={
                "before": before,
                "after": after,
                "experiment_variables": [
                    {
                        "name": "declared analysis host profile",
                        "category": "vm_environment",
                        "baseline": "documented profile A",
                        "variant": "documented profile B",
                        "expected_telemetry": [
                            "detector_verdict",
                            "environment_snapshot",
                        ],
                        "purpose": "validate the environment-probe attribution",
                    }
                ],
            },
            session_id="offline-comparison",
            provenance={"source": "analyst-supplied-offline-observations"},
        )
        provider = AntiTamperLabProvider()

        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertEqual(plan.action, "compare")
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok")
        attribution = result.report_section["difference_attribution"]
        self.assertEqual(attribution["detection_transition"], "not_detected_to_detected")
        self.assertTrue(attribution["added_evidence"])
        self.assertTrue(
            any(item["classification"] == "introduced" for item in attribution["categories"])
        )
        self.assertEqual(result.before_snapshot["observation_role"], "before")
        self.assertEqual(result.after_snapshot["observation_role"], "after")
        self.assertFalse(result.after_snapshot["sample_executed"])
        for row in result.report_section["experiment_matrix"]:
            self.assertFalse(row["provider_executes"])
            self.assertEqual(row["execution_scope"], "external_isolated_lab_only")
        declared = next(
            row
            for row in result.report_section["experiment_matrix"]
            if row["controlled_variable"] == "declared analysis host profile"
        )
        self.assertEqual(declared["source"], "analyst_declared_safe_variable")
        self.assertEqual(declared["baseline_condition"], "documented profile A")
        self.assertEqual(declared["variant_condition"], "documented profile B")

    def test_plan_execute_and_artifact_bytes_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = root / "deterministic.exe"
            sample.write_bytes(_build_pe_fixture())
            request = self._request(sample, session_id="deterministic-session")
            first_provider = AntiTamperLabProvider(allowed_input_roots=[root])
            second_provider = AntiTamperLabProvider(allowed_input_roots=[root])

            first_plan = first_provider.plan(request)
            second_plan = second_provider.plan(copy.deepcopy(request))
            self.assertEqual(first_plan.to_dict(), second_plan.to_dict())
            first = first_provider.execute(first_plan)
            second = second_provider.execute(second_plan)
            self.assertEqual(first.to_dict(), second.to_dict())

            first_out = root / "first"
            second_out = root / "second"
            first_bundle = first_provider.collect_artifacts(first, str(first_out))
            second_bundle = second_provider.collect_artifacts(second, str(second_out))
            self.assertEqual(
                first_bundle.manifest_entries,
                second_bundle.manifest_entries,
            )
            for artifact in first_bundle.artifacts:
                self.assertEqual(
                    (first_out / artifact.path).read_bytes(),
                    (second_out / artifact.path).read_bytes(),
                )

    def test_hash_drift_wrong_identity_and_tampered_plan_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample = root / "drift.exe"
            original = _build_pe_fixture()
            sample.write_bytes(original)
            provider = AntiTamperLabProvider(allowed_input_roots=[root])

            wrong = provider.plan(self._request(sample, sha256="0" * 64))
            wrong_validation = provider.validate(wrong)
            self.assertFalse(wrong_validation.ok)
            self.assertIn("target sha256 does not match sample", " ".join(wrong_validation.errors))

            plan = provider.plan(self._request(sample, session_id="drift"))
            sample.write_bytes(original + b"changed")
            validation = provider.validate(plan)
            result = provider.execute(plan)
            self.assertFalse(validation.ok)
            self.assertIn("sample changed after planning", " ".join(validation.errors))
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.after_snapshot["side_effects"])

            sample.write_bytes(original)
            tampered = provider.plan(self._request(sample, session_id="tampered"))
            tampered.parameters["max_strings"] += 1
            tampered_validation = provider.validate(tampered)
            self.assertFalse(tampered_validation.ok)
            self.assertIn("precondition hash", " ".join(tampered_validation.errors))

    def test_input_limits_path_roots_and_forbidden_actions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            allowed = root / "allowed"
            outside = root / "outside"
            allowed.mkdir()
            outside.mkdir()
            oversized = allowed / "oversized.bin"
            oversized.write_bytes(b"MZ" + b"A" * 512)
            outside_sample = outside / "outside.bin"
            outside_sample.write_bytes(b"IsDebuggerPresent")
            provider = AntiTamperLabProvider(
                allowed_input_roots=[allowed],
                allowed_output_roots=[allowed],
                max_sample_bytes=128,
                max_observation_bytes=256,
            )

            oversized_plan = provider.plan(self._request(oversized))
            self.assertFalse(provider.validate(oversized_plan).ok)
            self.assertEqual(provider.execute(oversized_plan).status, "failed")

            outside_plan = provider.plan(self._request(outside_sample))
            self.assertFalse(provider.validate(outside_plan).ok)
            self.assertIn("configured input roots", " ".join(provider.validate(outside_plan).errors))

            observation_request = CapabilityRequest(
                capability="anti_tamper_lab",
                action="analyze",
                target=TargetIdentity(kind="offline", display_name="too-large"),
                params={"observations": {"strings": ["V" * 400]}},
                session_id="observation-limit",
            )
            observation_plan = provider.plan(observation_request)
            self.assertFalse(provider.validate(observation_plan).ok)

            forbidden_request = CapabilityRequest(
                capability="anti_tamper_lab",
                action="peb_unlink",
                target=TargetIdentity(kind="offline", display_name="forbidden"),
                params={"hide_modules": True},
                session_id="../../must-not-escape",
            )
            self.assertFalse(provider.supports(forbidden_request))
            forbidden_plan = provider.plan(forbidden_request)
            self.assertFalse(provider.validate(forbidden_plan).ok)
            self.assertEqual(provider.execute(forbidden_plan).status, "failed")

            invalid_variable_request = CapabilityRequest(
                capability="anti_tamper_lab",
                action="experiment_matrix",
                target=TargetIdentity(kind="offline", display_name="invalid-variable"),
                params={
                    "observations": {},
                    "experiment_variables": [
                        {
                            "name": "unsafe executor",
                            "baseline": "control",
                            "variant": "variant",
                            "executor": "kernel_hook",
                        }
                    ],
                },
                session_id="invalid-variable",
            )
            invalid_variable_plan = provider.plan(invalid_variable_request)
            invalid_variable_validation = provider.validate(invalid_variable_plan)
            self.assertFalse(invalid_variable_validation.ok)
            self.assertIn(
                "unsupported fields",
                " ".join(invalid_variable_validation.errors),
            )

    def test_artifact_root_and_result_integrity_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            allowed_out = root / "allowed-output"
            allowed_out.mkdir()
            sample = root / "sample.exe"
            sample.write_bytes(_build_pe_fixture())
            provider = AntiTamperLabProvider(
                allowed_input_roots=[root],
                allowed_output_roots=[allowed_out],
            )
            result = provider.execute(provider.plan(self._request(sample)))
            self.assertEqual(result.status, "ok")

            with self.assertRaises(AntiTamperLabError):
                provider.collect_artifacts(result, str(root / "outside-output"))

            forged = copy.deepcopy(result)
            forged.after_snapshot["side_effects"] = True
            with self.assertRaises(AntiTamperLabError):
                provider.collect_artifacts(forged, str(allowed_out))
            rollback = provider.rollback(forged)
            self.assertFalse(rollback.ok)
            self.assertEqual(rollback.details["status"], "result_integrity_failed")


if __name__ == "__main__":
    unittest.main()
