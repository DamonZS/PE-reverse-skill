import json
import struct
import unittest
from typing import Any, Mapping

from tests._engine_acceptance import (
    live_engine_fixture_enabled,
    run_live_engine_acceptance,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.engine_runtime import EngineRuntimeProvider


_BASE_ADDRESS = 0x180000000
_IMAGE_SIZE = 0x7000


def _write_lea(
    image: bytearray,
    instruction_rva: int,
    opcode: bytes,
    target_rva: int,
) -> None:
    displacement = target_rva - (instruction_rva + 7)
    image[instruction_rva : instruction_rva + 7] = opcode + struct.pack(
        "<i", displacement
    )


def _write_count_pointer_pair(
    image: bytearray,
    structure_rva: int,
    index: int,
    count: int,
    pointer_rva: int,
) -> None:
    pointer = _BASE_ADDRESS + pointer_rva if pointer_rva else 0
    struct.pack_into("<I4xQ", image, structure_rva + index * 16, count, pointer)


def _write_registration_site(
    image: bytearray,
    site_rva: int,
    code_registration_rva: int,
    metadata_registration_rva: int,
    codegen_options_rva: int,
) -> None:
    _write_lea(image, site_rva, b"\x48\x8d\x0d", code_registration_rva)
    _write_lea(
        image,
        site_rva + 8,
        b"\x48\x8d\x15",
        metadata_registration_rva,
    )
    _write_lea(image, site_rva + 16, b"\x4c\x8d\x05", codegen_options_rva)


def _il2cpp_pe_image() -> tuple[bytes, dict[str, int]]:
    image = bytearray(_IMAGE_SIZE)
    image[:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", image, 0x3C, pe_offset)
    struct.pack_into(
        "<4sHHIIIHH",
        image,
        pe_offset,
        b"PE\x00\x00",
        0x8664,
        3,
        0x66CCBBAA,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional_offset = pe_offset + 24
    struct.pack_into("<H", image, optional_offset, 0x20B)
    struct.pack_into("<I", image, optional_offset + 16, 0x1000)
    struct.pack_into("<Q", image, optional_offset + 24, _BASE_ADDRESS)
    struct.pack_into("<I", image, optional_offset + 32, 0x1000)
    struct.pack_into("<I", image, optional_offset + 36, 0x200)
    struct.pack_into("<I", image, optional_offset + 56, len(image))
    struct.pack_into("<I", image, optional_offset + 60, 0x400)
    struct.pack_into("<I", image, optional_offset + 64, 0x1234ABCD)
    struct.pack_into("<I", image, optional_offset + 108, 16)

    sections = (
        (b".text", 0x1000, 0x1000, 0x60000020),
        (b".rdata", 0x2000, 0x4000, 0x40000040),
        (b".data", 0x6000, 0x1000, 0xC0000040),
    )
    section_offset = optional_offset + 0xF0
    for index, (name, rva, size, characteristics) in enumerate(sections):
        cursor = section_offset + index * 40
        image[cursor : cursor + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", image, cursor + 8, size, rva, size, 0)
        struct.pack_into("<I", image, cursor + 36, characteristics)

    rvas = {
        "registration_site": 0x1100,
        "method_1": 0x1400,
        "method_2": 0x1420,
        "code_registration": 0x3000,
        "metadata_registration": 0x3200,
        "codegen_options": 0x3400,
        "codegen_module_table": 0x3500,
        "codegen_module": 0x3600,
        "codegen_module_name": 0x3700,
        "method_pointer_table": 0x3800,
        "generic_method_table": 0x3900,
        "types_table": 0x3A00,
    }
    _write_registration_site(
        image,
        rvas["registration_site"],
        rvas["code_registration"],
        rvas["metadata_registration"],
        rvas["codegen_options"],
    )
    image[rvas["method_1"] : rvas["method_1"] + 4] = b"\x55\x48\x89\xe5"
    image[rvas["method_2"] : rvas["method_2"] + 4] = b"\x55\x48\x89\xe5"

    # v27.1+: the eighth count/pointer pair is codeGenModules.
    _write_count_pointer_pair(
        image,
        rvas["code_registration"],
        7,
        1,
        rvas["codegen_module_table"],
    )
    struct.pack_into(
        "<Q",
        image,
        rvas["codegen_module_table"],
        _BASE_ADDRESS + rvas["codegen_module"],
    )
    struct.pack_into(
        "<QI4xQ",
        image,
        rvas["codegen_module"],
        _BASE_ADDRESS + rvas["codegen_module_name"],
        2,
        _BASE_ADDRESS + rvas["method_pointer_table"],
    )
    module_name = b"Assembly-CSharp.dll\x00"
    start = rvas["codegen_module_name"]
    image[start : start + len(module_name)] = module_name
    struct.pack_into(
        "<QQ",
        image,
        rvas["method_pointer_table"],
        _BASE_ADDRESS + rvas["method_1"],
        _BASE_ADDRESS + rvas["method_2"],
    )

    # Two independently range-validated metadata tables make the candidate
    # structurally meaningful without claiming external metadata-file names.
    _write_count_pointer_pair(
        image,
        rvas["metadata_registration"],
        2,
        1,
        rvas["generic_method_table"],
    )
    _write_count_pointer_pair(
        image,
        rvas["metadata_registration"],
        3,
        2,
        rvas["types_table"],
    )
    return bytes(image), rvas


class Il2CppRuntimeBackend:
    name = "deterministic_il2cpp_runtime"
    available = True
    unavailable_reason = None

    def __init__(
        self,
        image: bytes,
        *,
        pid: int = 8123,
        short_reads: Mapping[int, int] | None = None,
    ) -> None:
        self.pid = pid
        self.short_reads = dict(short_reads or {})
        self.calls: list[tuple[Any, ...]] = []
        self.modules: list[dict[str, Any]] = [
            {
                "name": "GameAssembly.dll",
                "path": r"C:\Fixtures\Il2CppGame\GameAssembly.dll",
                "base_address": _BASE_ADDRESS,
                "size": len(image),
                "data": image,
            }
        ]

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        accessible = pid == self.pid
        return {
            "pid": pid,
            "exists": accessible,
            "accessible": accessible,
            "status": "ok" if accessible else "unavailable",
            "image_path": r"C:\Fixtures\Il2CppGame\Game.exe" if accessible else None,
            "side_effects": False,
        }

    def enumerate_modules(self, pid: int) -> list[Mapping[str, Any]]:
        self._require_pid(pid)
        self.calls.append(("enumerate_modules", pid))
        return [
            {key: value for key, value in module.items() if key != "data"}
            for module in self.modules
        ]

    def read_process_memory(self, pid: int, address: int, size: int) -> bytes:
        self._require_pid(pid)
        self.calls.append(("read_process_memory", pid, address, size))
        module = self.modules[0]
        base = int(module["base_address"])
        data = bytes(module["data"])
        if base <= address and address + size <= base + len(data):
            offset = address - base
            result = data[offset : offset + size]
            if address in self.short_reads:
                return result[: self.short_reads[address]]
            return result
        return b""

    def _require_pid(self, pid: int) -> None:
        if pid != self.pid:
            raise RuntimeError(f"unexpected pid: {pid}")


class EngineRuntimeIl2CppTests(unittest.TestCase):
    def _execute(self, backend: Il2CppRuntimeBackend) -> tuple[Any, dict[str, Any]]:
        provider = EngineRuntimeProvider(
            backend,
            platform_name="win32",
            max_total_read_bytes=256 * 1024,
            max_module_read_bytes=256 * 1024,
            max_single_read_bytes=4096,
            max_modules=4,
            max_evidence=256,
            max_export_names=32,
        )
        request = CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=TargetIdentity(kind="process", pid=backend.pid),
            params={
                "scan_all_modules": True,
                "include_exports": False,
                "include_utf16": False,
            },
            session_id="engine-runtime-il2cpp-test",
            provenance={"request_source": "unit-test"},
        )
        result = provider.execute(provider.plan(request))
        return result, result.report_section["operation"]

    @staticmethod
    def _component(operation: Mapping[str, Any]) -> dict[str, Any]:
        extraction = operation["analyzed_modules"][0]["runtime_extraction"]
        return next(
            item
            for item in extraction["components"]
            if item.get("engine") == "unity_il2cpp"
        )

    def test_maps_method_definition_tokens_to_validated_runtime_pointers(self) -> None:
        image, rvas = _il2cpp_pe_image()
        result, operation = self._execute(Il2CppRuntimeBackend(image))
        component = self._component(operation)

        self.assertEqual(result.status, "ok")
        self.assertEqual(component["validated_candidate_count"], 1)
        codegen = component["selected"]["code_registration"]["codegen_modules"][0]
        self.assertEqual(codegen["name"], "Assembly-CSharp.dll")
        self.assertEqual(
            codegen["method_token_mappings"],
            [
                {
                    "token": "0x06000001",
                    "pointer_index": 0,
                    "address": _BASE_ADDRESS + rvas["method_1"],
                    "address_hex": hex(_BASE_ADDRESS + rvas["method_1"]),
                    "rva": rvas["method_1"],
                    "rva_hex": hex(rvas["method_1"]),
                    "section": ".text",
                },
                {
                    "token": "0x06000002",
                    "pointer_index": 1,
                    "address": _BASE_ADDRESS + rvas["method_2"],
                    "address_hex": hex(_BASE_ADDRESS + rvas["method_2"]),
                    "rva": rvas["method_2"],
                    "rva_hex": hex(rvas["method_2"]),
                    "section": ".text",
                },
            ],
        )

    def test_preserves_method_token_rid_when_pointer_table_contains_a_hole(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        struct.pack_into("<Q", image, rvas["method_pointer_table"], 0)

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        component = self._component(operation)
        codegen = component["selected"]["code_registration"]["codegen_modules"][0]

        self.assertEqual(codegen["method_token_mapping_count"], 1)
        self.assertEqual(
            codegen["method_token_mappings"],
            [
                {
                    "token": "0x06000002",
                    "pointer_index": 1,
                    "address": _BASE_ADDRESS + rvas["method_2"],
                    "address_hex": hex(_BASE_ADDRESS + rvas["method_2"]),
                    "rva": rvas["method_2"],
                    "rva_hex": hex(rvas["method_2"]),
                    "section": ".text",
                }
            ],
        )

    def test_preserves_method_token_rid_for_hole_after_eighth_entry(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        method_pointers = [
            *([_BASE_ADDRESS + rvas["method_1"]] * 8),
            0,
            _BASE_ADDRESS + rvas["method_2"],
        ]
        struct.pack_into(
            "<I", image, rvas["codegen_module"] + 8, len(method_pointers)
        )
        struct.pack_into(
            f"<{len(method_pointers)}Q",
            image,
            rvas["method_pointer_table"],
            *method_pointers,
        )

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        component = self._component(operation)
        codegen = component["selected"]["code_registration"]["codegen_modules"][0]
        mappings = codegen["method_token_mappings"]

        self.assertEqual(component["validated_candidate_count"], 1)
        self.assertEqual(codegen["method_token_mapping_count"], 9)
        self.assertEqual(
            [mapping["pointer_index"] for mapping in mappings],
            [*range(8), 9],
        )
        self.assertEqual(mappings[-1]["token"], "0x0600000a")
        self.assertEqual(mappings[-1]["address"], _BASE_ADDRESS + rvas["method_2"])

    def test_selects_only_valid_registration_pair(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        _write_registration_site(image, 0x1200, 0x3C00, 0x3D00, 0x3E00)

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        component = self._component(operation)

        self.assertEqual(component["candidate_count"], 2)
        self.assertEqual(component["validated_candidate_count"], 1)
        self.assertEqual(
            component["selected"]["registration_site"]["code_registration_rva"],
            rvas["code_registration"],
        )
        self.assertEqual(
            sorted(candidate["status"] for candidate in component["candidates"]),
            ["rejected", "validated"],
        )

    def test_keeps_distinct_valid_registration_pairs_ambiguous(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        second_code = 0x3C00
        second_metadata = 0x3D00
        image[second_code : second_code + 9 * 16] = image[
            rvas["code_registration"] : rvas["code_registration"] + 9 * 16
        ]
        image[second_metadata : second_metadata + 8 * 16] = image[
            rvas["metadata_registration"] : rvas["metadata_registration"] + 8 * 16
        ]
        _write_registration_site(
            image,
            0x1200,
            second_code,
            second_metadata,
            0x3E00,
        )

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        component = self._component(operation)

        self.assertEqual(component["status"], "partial")
        self.assertEqual(component["candidate_count"], 2)
        self.assertEqual(component["validated_candidate_count"], 2)
        self.assertNotIn("selected", component)
        self.assertEqual(component.get("symbols", []), [])
        self.assertEqual(
            component["semantic_ir_fragment"].get("entities", []),
            [],
        )
        self.assertTrue(
            any(
                "multiple distinct validated registration pairs are ambiguous"
                in str(error.get("message"))
                for error in component["errors"]
            )
        )

    def test_rejects_illegal_metadata_count_and_pointer_span(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        mutations = {
            "count": (8_000_001, rvas["generic_method_table"]),
            "pointer_span": (2, 0x6FF0),
        }
        for case, (count, pointer_rva) in mutations.items():
            with self.subTest(case=case):
                image = bytearray(raw)
                _write_count_pointer_pair(
                    image,
                    rvas["metadata_registration"],
                    2,
                    count,
                    pointer_rva,
                )

                _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
                component = self._component(operation)
                candidate = component["candidates"][0]
                messages = [str(error.get("message")) for error in candidate["errors"]]

                self.assertEqual(component["validated_candidate_count"], 0)
                self.assertEqual(candidate["status"], "rejected")
                self.assertNotIn("selected", component)
                self.assertTrue(
                    any(
                        "generic_method_table" in message
                        and ("bounded range" in message or "pointer/span" in message)
                        for message in messages
                    )
                )

    def test_rejects_truncated_registration_structures_with_provenance(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        cases = {
            "code": (0x6FC0, rvas["metadata_registration"], "il2cpp_code_registration"),
            "metadata": (rvas["code_registration"], 0x6FC0, "il2cpp_metadata_registration"),
        }
        for case, (code_rva, metadata_rva, operation_name) in cases.items():
            with self.subTest(case=case):
                image = bytearray(raw)
                _write_registration_site(
                    image,
                    rvas["registration_site"],
                    code_rva,
                    metadata_rva,
                    rvas["codegen_options"],
                )

                _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
                component = self._component(operation)
                errors = component["candidates"][0]["errors"]

                self.assertEqual(component["validated_candidate_count"], 0)
                self.assertTrue(
                    any(
                        error.get("operation") == operation_name
                        and "truncated" in str(error.get("message"))
                        for error in errors
                    )
                )

    def test_truncated_method_pointer_table_never_produces_token_mappings(self) -> None:
        image, rvas = _il2cpp_pe_image()
        backend = Il2CppRuntimeBackend(
            image,
            short_reads={_BASE_ADDRESS + rvas["method_pointer_table"]: 8},
        )

        _, operation = self._execute(backend)
        component = self._component(operation)
        candidate = component["candidates"][0]

        self.assertEqual(candidate["status"], "rejected")
        self.assertNotIn("selected", component)
        self.assertFalse(
            any(
                module.get("method_token_mappings")
                for module in (candidate.get("code_registration") or {}).get(
                    "codegen_modules", []
                )
            )
        )
        self.assertTrue(
            any(
                "method table is truncated" in str(error.get("message"))
                for error in candidate["errors"]
            )
        )

    def test_non_executable_method_pointer_rejects_candidate_without_mapping(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        struct.pack_into(
            "<Q",
            image,
            rvas["method_pointer_table"],
            _BASE_ADDRESS + rvas["codegen_module_name"],
        )

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        component = self._component(operation)
        candidate = component["candidates"][0]

        self.assertEqual(candidate["status"], "rejected")
        self.assertNotIn("selected", component)
        self.assertTrue(
            any(
                "non-executable sampled method pointer" in str(error.get("message"))
                for error in candidate["errors"]
            )
        )

    def test_non_executable_method_pointer_after_eighth_rejects_candidate(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        method_pointers = [
            *([_BASE_ADDRESS + rvas["method_1"]] * 8),
            _BASE_ADDRESS + rvas["codegen_module_name"],
        ]
        struct.pack_into(
            "<I", image, rvas["codegen_module"] + 8, len(method_pointers)
        )
        struct.pack_into(
            f"<{len(method_pointers)}Q",
            image,
            rvas["method_pointer_table"],
            *method_pointers,
        )

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        component = self._component(operation)
        candidate = component["candidates"][0]

        self.assertEqual(component["validated_candidate_count"], 0)
        self.assertEqual(candidate["status"], "rejected")
        self.assertNotIn("selected", component)
        self.assertTrue(
            any(
                "non-executable" in str(error.get("message"))
                and "method pointer" in str(error.get("message"))
                for error in candidate["errors"]
            )
        )

    def test_semantic_ir_links_registration_modules_and_method_tokens(self) -> None:
        image, _ = _il2cpp_pe_image()
        _, operation = self._execute(Il2CppRuntimeBackend(image))
        component = self._component(operation)
        semantic = component["semantic_ir_fragment"]
        entities = semantic["entities"]

        by_role: dict[str, list[dict[str, Any]]] = {}
        for entity in entities:
            by_role.setdefault(entity["attributes"]["role"], []).append(entity)
        self.assertEqual(len(by_role["code_registration"]), 1)
        self.assertEqual(len(by_role["metadata_registration"]), 1)
        self.assertEqual(len(by_role["codegen_module"]), 1)
        self.assertEqual(
            [entity["name"] for entity in by_role["il2cpp_method"]],
            [
                "Assembly-CSharp.dll!0x06000001",
                "Assembly-CSharp.dll!0x06000002",
            ],
        )
        self.assertEqual(
            [entity["attributes"]["token"] for entity in by_role["il2cpp_method"]],
            ["0x06000001", "0x06000002"],
        )
        self.assertTrue(
            all(
                entity["attributes"]["codegen_module"] == "Assembly-CSharp.dll"
                and entity["attributes"]["address_kind"] == "runtime_va"
                for entity in by_role["il2cpp_method"]
            )
        )
        module_id = by_role["codegen_module"][0]["id"]
        method_ids = {entity["id"] for entity in by_role["il2cpp_method"]}
        self.assertEqual(
            {
                relation["target"]
                for relation in semantic["relations"]
                if relation["type"] == "maps_method"
                and relation["source"] == module_id
            },
            method_ids,
        )
        self.assertEqual(
            operation["semantic_ir_fragment"]["entities"], semantic["entities"]
        )
        self.assertEqual(
            operation["semantic_ir_fragment"]["relations"], semantic["relations"]
        )

    def test_semantic_ir_keeps_distinct_tokens_that_share_a_native_pointer(self) -> None:
        raw, rvas = _il2cpp_pe_image()
        image = bytearray(raw)
        struct.pack_into(
            "<Q",
            image,
            rvas["method_pointer_table"] + 8,
            _BASE_ADDRESS + rvas["method_1"],
        )

        _, operation = self._execute(Il2CppRuntimeBackend(bytes(image)))
        entities = self._component(operation)["semantic_ir_fragment"]["entities"]
        methods = [
            entity
            for entity in entities
            if entity["attributes"]["role"] == "il2cpp_method"
        ]

        self.assertEqual(len(methods), 2)
        self.assertEqual(len({entity["id"] for entity in methods}), 2)
        self.assertEqual(
            {entity["attributes"]["address"] for entity in methods},
            {_BASE_ADDRESS + rvas["method_1"]},
        )
        self.assertEqual(
            {entity["attributes"]["token"] for entity in methods},
            {"0x06000001", "0x06000002"},
        )

    def test_two_independent_backend_runs_are_byte_deterministic(self) -> None:
        image, _ = _il2cpp_pe_image()
        first_result, first_operation = self._execute(Il2CppRuntimeBackend(image))
        second_result, second_operation = self._execute(Il2CppRuntimeBackend(image))

        self.assertEqual(first_result.status, second_result.status)
        self.assertEqual(
            json.dumps(first_operation, sort_keys=True, separators=(",", ":")),
            json.dumps(second_operation, sort_keys=True, separators=(",", ":")),
        )


@unittest.skipUnless(
    live_engine_fixture_enabled("REVERSE_ANALYZER_UNITY_IL2CPP_FIXTURE"),
    "requires a production Windows Unity IL2CPP fixture and acceptance directory",
)
class EngineRuntimeIl2CppLiveAcceptanceTests(unittest.TestCase):
    def test_production_backend_materializes_live_acceptance_artifacts(self) -> None:
        run_live_engine_acceptance(
            self,
            fixture_env="REVERSE_ANALYZER_UNITY_IL2CPP_FIXTURE",
            expected_engine="unity_il2cpp",
        )


if __name__ == "__main__":
    unittest.main()
