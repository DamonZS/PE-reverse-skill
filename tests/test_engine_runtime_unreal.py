import json
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from tests._engine_acceptance import (
    live_engine_fixture_enabled,
    run_live_engine_acceptance,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.engine_runtime import (
    EngineRuntimeProvider,
    UnavailableEngineRuntimeBackend,
)


_BASE_ADDRESS = 0x180000000
_IMAGE_SIZE = 0x8000


def _write_bytes(image: bytearray, rva: int, value: bytes) -> None:
    image[rva : rva + len(value)] = value


def _unreal_pe_image(
    *,
    base_address: int = _BASE_ADDRESS,
    include_global_exports: bool = True,
    pe_size_of_image: int = _IMAGE_SIZE,
) -> tuple[bytes, dict[str, int]]:
    """Build a loaded PE32+ image with bounded Unreal runtime fixtures."""

    image = bytearray(_IMAGE_SIZE)
    image[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", image, 0x3C, pe_offset)
    section_count = 4
    optional_size = 0xF0
    struct.pack_into(
        "<4sHHIIIHH",
        image,
        pe_offset,
        b"PE\x00\x00",
        0x8664,
        section_count,
        0x66AABBCC,
        0,
        0,
        optional_size,
        0x2022,
    )
    optional_offset = pe_offset + 24
    struct.pack_into("<H", image, optional_offset, 0x20B)
    struct.pack_into("<I", image, optional_offset + 16, 0x1000)
    struct.pack_into("<I", image, optional_offset + 56, pe_size_of_image)
    struct.pack_into("<I", image, optional_offset + 64, 0x1234ABCD)
    struct.pack_into("<I", image, optional_offset + 108, 16)

    sections = (
        (b".text", 0x1000, 0x1000, 0x60000020),
        (b".rdata", 0x2000, 0x2000, 0x40000040),
        (b".data", 0x4000, 0x2000, 0xC0000040),
        (b".hidden", 0x6000, 0x1000, 0x80000040),
    )
    section_offset = optional_offset + optional_size
    for index, (name, rva, size, characteristics) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            section_offset + index * 40,
            name.ljust(8, b"\x00"),
            size,
            rva,
            size,
            rva,
            0,
            0,
            0,
            0,
            characteristics,
        )

    exports = [
        ("ProcessEvent", 0x1100),
        ("StaticFindObject", 0x1180),
    ]
    if include_global_exports:
        exports.extend(
            (
                ("GNames", 0x4100),
                ("GUObjectArray", 0x4300),
                ("GWorld", 0x4500),
            )
        )

    export_rva = 0x2100
    export_size = 0x600
    dll_name_rva = 0x2160
    functions_rva = 0x2200
    names_rva = 0x2240
    ordinals_rva = 0x2280
    struct.pack_into("<II", image, optional_offset + 112, export_rva, export_size)
    struct.pack_into(
        "<IIHHIIIIIII",
        image,
        export_rva,
        0,
        0x66AABBCC,
        1,
        0,
        dll_name_rva,
        1,
        len(exports),
        len(exports),
        functions_rva,
        names_rva,
        ordinals_rva,
    )
    _write_bytes(image, dll_name_rva, b"UnrealEditor-CoreUObject.dll\x00")

    rvas: dict[str, int] = {}
    next_name_rva = 0x2300
    for index, (name, function_rva) in enumerate(exports):
        struct.pack_into("<I", image, functions_rva + index * 4, function_rva)
        struct.pack_into("<I", image, names_rva + index * 4, next_name_rva)
        struct.pack_into("<H", image, ordinals_rva + index * 2, index)
        encoded = name.encode("ascii") + b"\x00"
        _write_bytes(image, next_name_rva, encoded)
        rvas[name] = function_rva
        next_name_rva += len(encoded) + 8

    # FNamePool starts four bytes before a 128-byte scan boundary.
    markers = {
        "FNamePool": (0x207C, b"FNamePool"),
        "UObject": (0x2800, b"UObject"),
        "UClass": (0x2820, b"UClass"),
        "UFunction:utf16": (0x2860, "UFunction".encode("utf-16-le")),
        "/Script/UMG": (0x28A0, b"/Script/UMG"),
        "UUserWidget": (0x28D0, b"UUserWidget"),
        "GUObjectArray:string": (0x2900, b"GUObjectArray"),
    }
    for name, (rva, encoded) in markers.items():
        _write_bytes(image, rva, encoded + b"\x00\x00")
        rvas[name] = rva

    # A recognized marker in a range-valid but unreadable section must be ignored.
    hidden_rva = 0x6100
    _write_bytes(image, hidden_rva, b"WidgetBlueprintGeneratedClass\x00")
    rvas["hidden:WidgetBlueprintGeneratedClass"] = hidden_rva

    if include_global_exports:
        fname_block = base_address + 0x4700
        struct.pack_into("<IIQ", image, 0x4108, 0, 0x40, fname_block)
        _write_bytes(image, 0x4700, b"\x08\x00None\x00")

        chunks = base_address + 0x4800
        first_chunk = base_address + 0x4900
        first_item = base_address + 0x4A00
        struct.pack_into("<QQIIII", image, 0x4300, chunks, 0, 0x10000, 2, 1, 1)
        struct.pack_into("<Q", image, 0x4800, first_chunk)
        struct.pack_into("<Q", image, 0x4900, first_item)

        world = base_address + 0x4B00
        struct.pack_into("<Q", image, 0x4500, world)
        struct.pack_into("<QQ", image, 0x4B00, base_address + 0x1000, base_address + 0x4000)
        rvas.update(
            {
                "FNamePool:resolved": 0x4100,
                "FUObjectArray:resolved": 0x4300,
                "UWorld:candidate": 0x4B00,
            }
        )

    return bytes(image), rvas


class SyntheticUnrealBackend:
    name = "synthetic_unreal_runtime"
    available = True
    unavailable_reason = None

    def __init__(
        self,
        image: bytes,
        *,
        base_address: int = _BASE_ADDRESS,
        pid: int = 7331,
        fail_addresses: set[int] | None = None,
    ) -> None:
        self.pid = pid
        self.calls: list[tuple[Any, ...]] = []
        self.fail_addresses = set(fail_addresses or ())
        self.modules: list[dict[str, Any]] = [
            {
                "name": "UnrealEditor-CoreUObject.dll",
                "path": "C:/fixtures/Unreal/UnrealEditor-CoreUObject.dll",
                "base_address": base_address,
                "size": len(image),
                "data": image,
            }
        ]

    @property
    def read_calls(self) -> list[tuple[Any, ...]]:
        return [call for call in self.calls if call[0] == "read_process_memory"]

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        accessible = pid == self.pid
        return {
            "pid": pid,
            "exists": accessible,
            "accessible": accessible,
            "status": "ok" if accessible else "unavailable",
            "image_path": "C:/fixtures/Unreal/FixtureGame.exe" if accessible else None,
            "side_effects": False,
        }

    def enumerate_modules(self, pid: int) -> list[Mapping[str, Any]]:
        if pid != self.pid:
            raise RuntimeError(f"unexpected pid: {pid}")
        self.calls.append(("enumerate_modules", pid))
        return [
            {key: value for key, value in module.items() if key != "data"}
            for module in self.modules
        ]

    def read_process_memory(self, pid: int, address: int, size: int) -> bytes:
        if pid != self.pid:
            raise RuntimeError(f"unexpected pid: {pid}")
        self.calls.append(("read_process_memory", pid, address, size))
        if address in self.fail_addresses:
            raise OSError(f"synthetic unreadable address: {hex(address)}")
        for module in self.modules:
            base = int(module["base_address"])
            data = bytes(module["data"])
            if base <= address and address + size <= base + len(data):
                offset = address - base
                return data[offset : offset + size]
        return b""


class EngineRuntimeUnrealTests(unittest.TestCase):
    def _request(self, pid: int, **params: Any) -> CapabilityRequest:
        values = {
            "scan_all_modules": True,
            "include_exports": True,
            "include_utf16": True,
        }
        values.update(params)
        return CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=TargetIdentity(
                kind="process",
                pid=pid,
                display_name="synthetic-unreal-process",
            ),
            params=values,
            session_id="engine-runtime-unreal-test",
            provenance={"request_source": "unit-test"},
        )

    def _provider(
        self,
        backend: SyntheticUnrealBackend,
        *,
        total: int = 24 * 1024,
        module: int = 24 * 1024,
        single: int = 128,
    ) -> EngineRuntimeProvider:
        return EngineRuntimeProvider(
            backend,
            platform_name="win32",
            max_total_read_bytes=total,
            max_module_read_bytes=module,
            max_single_read_bytes=single,
            max_modules=4,
            max_evidence=256,
            max_export_names=32,
        )

    def test_full_lifecycle_emits_verified_unreal_analysis_and_artifact(self) -> None:
        image, rvas = _unreal_pe_image()
        backend = SyntheticUnrealBackend(image)
        provider = self._provider(backend)
        plan = provider.plan(self._request(backend.pid))
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok")
        self.assertTrue(any(step["name"] == "collect_runtime_evidence" for step in plan.steps))
        report = result.report_section
        operation = report["operation"]
        analysis = report["engine_analysis"]
        self.assertEqual(operation["engine_analysis"], analysis)
        self.assertEqual(analysis["status"], "ok")
        self.assertEqual(analysis["loaded_module_detection"]["status"], "detected")
        self.assertEqual(analysis["loaded_module_detection"]["module_count"], 1)
        proof = analysis["pe_identity_proofs"][0]
        self.assertTrue(proof["verified"])
        self.assertEqual(proof["pe_header"]["kind"], "PE32+")
        self.assertEqual(proof["pe_header"]["architecture"], "amd64")
        self.assertTrue(proof["image_range"]["verified"])
        self.assertEqual(proof["image_range"]["pe_size_of_image"], len(image))

        self.assertGreater(analysis["normalized_clues"]["uobject"], [])
        self.assertGreater(analysis["normalized_clues"]["uclass"], [])
        self.assertGreater(analysis["normalized_clues"]["ufunction"], [])
        self.assertGreater(analysis["normalized_clues"]["umg"], [])
        globals_by_role = {
            item["role"]: item for item in analysis["runtime_globals"]["validated"]
        }
        self.assertEqual(set(globals_by_role), {"gnames", "gobjects", "gworld"})
        self.assertEqual(
            analysis["address_resolution"]["name_pool"]["addresses"],
            [_BASE_ADDRESS + rvas["FNamePool:resolved"]],
        )
        self.assertEqual(
            analysis["address_resolution"]["object_array"]["addresses"],
            [_BASE_ADDRESS + rvas["FUObjectArray:resolved"]],
        )
        self.assertEqual(
            analysis["address_resolution"]["world_object"]["status"],
            "dependency-gated",
        )
        self.assertEqual(
            analysis["address_resolution"]["world_object"]["candidate_values"],
            [_BASE_ADDRESS + rvas["UWorld:candidate"]],
        )
        self.assertEqual(analysis["dependency_status"]["status"], "dependency-gated")
        self.assertIn("ReadProcessMemory", analysis["provenance"]["sources"])
        self.assertIn(
            "bounded readable-section reflection/name scan",
            analysis["completion_boundary"]["done"],
        )
        self.assertIn(
            "FUObjectItem/UObject traversal",
            analysis["completion_boundary"]["dependency_gated"],
        )
        semantic = analysis["semantic_ir_fragment"]
        self.assertEqual(semantic["engine"], "unreal")
        self.assertGreater(semantic["summary"]["entity_count"], 0)
        self.assertEqual(report["semantic_ir_fragment"], operation["semantic_ir_fragment"])

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle = provider.collect_artifacts(result, temp_dir)
            self.assertEqual(len(bundle.artifacts), 1)
            artifact_path = Path(temp_dir) / bundle.artifacts[0].path
            payload = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["report"]["engine_analysis"]["status"], "ok")
            self.assertEqual(payload["rollback"]["rollback_status"], "not_required")

    def test_scan_crosses_chunk_boundary_and_skips_unreadable_section(self) -> None:
        image, rvas = _unreal_pe_image()
        backend = SyntheticUnrealBackend(image)
        result = self._provider(backend).execute(
            self._provider(backend).plan(self._request(backend.pid))
        )
        analysis = result.report_section["engine_analysis"]
        clues = [
            clue
            for values in analysis["normalized_clues"].values()
            if isinstance(values, list)
            for clue in values
        ]
        fname = next(
            clue
            for clue in clues
            if clue.get("marker") == "FNamePool"
            and clue.get("address") == _BASE_ADDRESS + rvas["FNamePool"]
        )
        self.assertEqual(fname["encoding"], "ascii")
        self.assertEqual(fname["section_proof"]["name"], ".rdata")
        hidden_address = _BASE_ADDRESS + rvas["hidden:WidgetBlueprintGeneratedClass"]
        self.assertNotIn(hidden_address, {clue.get("address") for clue in clues})
        scan_calls = [
            call
            for call in backend.read_calls
            if call[2] in {
                _BASE_ADDRESS + 0x2000,
                _BASE_ADDRESS + 0x2080,
            }
        ]
        self.assertEqual([call[3] for call in scan_calls], [128, 128])

    def test_string_hits_do_not_claim_object_or_name_pool_addresses(self) -> None:
        image, _ = _unreal_pe_image(include_global_exports=False)
        backend = SyntheticUnrealBackend(image)
        provider = self._provider(backend)
        result = provider.execute(provider.plan(self._request(backend.pid)))
        analysis = result.report_section["engine_analysis"]

        self.assertEqual(analysis["status"], "partial")
        self.assertFalse(analysis["runtime_globals"].get("validated", []))
        self.assertEqual(
            analysis["address_resolution"]["name_pool"]["status"],
            "dependency-gated",
        )
        self.assertEqual(
            analysis["address_resolution"]["object_array"]["status"],
            "dependency-gated",
        )
        for key in ("uobject_instances", "uclass_instances", "ufunction_instances", "umg_instances"):
            self.assertEqual(analysis["address_resolution"][key]["status"], "unresolved")

        clues = [
            clue
            for values in analysis["normalized_clues"].values()
            if isinstance(values, list)
            for clue in values
        ]
        self.assertTrue(clues)
        for clue in clues:
            self.assertEqual(clue["address_kind"], "string_storage")
            self.assertEqual(clue["object_address"]["status"], "unresolved")
            self.assertEqual(clue["address"], clue["string_storage"]["address"])
        fname_clue = next(item for item in clues if item.get("marker") == "FNamePool")
        self.assertEqual(fname_clue["name_pool_address"]["status"], "dependency-gated")

    def test_unreal_collection_obeys_all_read_ceilings(self) -> None:
        image, _ = _unreal_pe_image()
        backend = SyntheticUnrealBackend(image)
        provider = self._provider(backend, total=1024, module=768, single=64)
        request = self._request(
            backend.pid,
            max_total_read_bytes=999999,
            max_module_read_bytes=999999,
            max_single_read_bytes=999999,
        )
        plan = provider.plan(request)
        self.assertEqual(plan.parameters["max_total_read_bytes"], 1024)
        self.assertEqual(plan.parameters["max_module_read_bytes"], 768)
        self.assertEqual(plan.parameters["max_single_read_bytes"], 64)
        result = provider.execute(plan)
        usage = result.report_section["read_usage"]

        self.assertLessEqual(usage["requested_bytes"], 1024)
        self.assertLessEqual(usage["max_observed_request"], 64)
        self.assertTrue(usage["truncated"])
        self.assertTrue(
            all(value <= 768 for value in usage["module_requested_bytes"].values())
        )
        self.assertTrue(backend.read_calls)
        self.assertTrue(all(call[3] <= 64 for call in backend.read_calls))
        analysis = result.report_section["engine_analysis"]
        self.assertEqual(analysis["status"], "partial")
        self.assertEqual(analysis["read_budget"]["limits"]["max_total_read_bytes"], 1024)
        self.assertTrue(analysis["read_budget"]["truncated"])

    def test_size_of_image_mismatch_is_reported_as_partial_pe_proof(self) -> None:
        image, _ = _unreal_pe_image(pe_size_of_image=_IMAGE_SIZE - 0x1000)
        backend = SyntheticUnrealBackend(image)
        provider = self._provider(backend)
        result = provider.execute(provider.plan(self._request(backend.pid)))
        analysis = result.report_section["engine_analysis"]
        proof = analysis["pe_identity_proofs"][0]

        self.assertEqual(result.status, "partial")
        self.assertEqual(analysis["status"], "partial")
        self.assertFalse(proof["verified"])
        self.assertFalse(proof["image_range"]["size_matches"])
        self.assertEqual(proof["status"], "partial")

    def test_module_range_drift_blocks_before_any_memory_read(self) -> None:
        image, _ = _unreal_pe_image()
        backend = SyntheticUnrealBackend(image)
        provider = self._provider(backend)
        plan = provider.plan(self._request(backend.pid))
        backend.modules[0]["size"] += 0x1000
        validation = provider.validate(plan)
        reads_before = len(backend.read_calls)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.report_section["operation"]["status"], "blocked")
        self.assertEqual(result.report_section["engine_analysis"]["status"], "blocked")
        self.assertEqual(len(backend.read_calls), reads_before)

    def test_section_read_failure_is_partial_and_preserves_error_provenance(self) -> None:
        image, _ = _unreal_pe_image()
        failed_address = _BASE_ADDRESS + 0x2000
        backend = SyntheticUnrealBackend(image, fail_addresses={failed_address})
        provider = self._provider(backend)
        result = provider.execute(provider.plan(self._request(backend.pid)))
        analysis = result.report_section["engine_analysis"]
        component = analysis["runtime_components"][0]

        self.assertEqual(result.status, "partial")
        self.assertEqual(analysis["status"], "partial")
        self.assertEqual(component["reflection_scan"]["status"], "partial")
        self.assertFalse(component["reflection_scan"]["coverage_complete"])
        self.assertTrue(component["read_budget"]["truncated"])
        self.assertTrue(component["errors"])
        self.assertEqual(component["errors"][0]["address"], failed_address)
        self.assertEqual(
            component["dependency_status"]["readable_section_name_scan"],
            "partial",
        )

    def test_unavailable_backend_emits_structured_unreal_boundary_without_reads(self) -> None:
        reason = "synthetic Windows runtime backend unavailable"
        provider = EngineRuntimeProvider(
            UnavailableEngineRuntimeBackend(reason),
            platform_name="linux",
        )
        request = self._request(9001)
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)
        analysis = result.report_section["engine_analysis"]

        self.assertTrue(validation.ok)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(analysis["status"], "unavailable")
        self.assertEqual(analysis["dependency_status"]["status"], "unavailable")
        self.assertEqual(analysis["loaded_module_detection"]["module_count"], 0)
        self.assertEqual(result.report_section["read_usage"]["requested_bytes"], 0)
        self.assertEqual(analysis["address_resolution"]["uobject_instances"]["status"], "unresolved")


@unittest.skipUnless(
    live_engine_fixture_enabled("REVERSE_ANALYZER_UNREAL_FIXTURE"),
    "requires a production Windows Unreal fixture and acceptance directory",
)
class EngineRuntimeUnrealLiveAcceptanceTests(unittest.TestCase):
    def test_production_backend_materializes_live_acceptance_artifacts(self) -> None:
        run_live_engine_acceptance(
            self,
            fixture_env="REVERSE_ANALYZER_UNREAL_FIXTURE",
            expected_engine="unreal",
        )


if __name__ == "__main__":
    unittest.main()
