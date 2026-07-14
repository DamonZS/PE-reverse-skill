import json
import struct
import unittest
from typing import Any, Mapping, Sequence

from tests._engine_acceptance import (
    live_engine_fixture_enabled,
    run_live_engine_acceptance,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.engine_runtime import EngineRuntimeProvider


def _align(value: int, alignment: int = 4) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _string_heap(values: Sequence[str]) -> tuple[bytes, dict[str, int]]:
    data = bytearray(b"\x00")
    offsets = {"": 0}
    for value in values:
        if value in offsets:
            continue
        offsets[value] = len(data)
        data.extend(value.encode("utf-8") + b"\x00")
    return bytes(data), offsets


def _mono_metadata_root(assembly_name: str = "Assembly-CSharp") -> bytes:
    strings, index = _string_heap(
        [
            f"{assembly_name}.dll",
            assembly_name,
            "<Module>",
            "MonoBehaviour",
            "UnityEngine",
            "PlayerController",
            "Game",
            "Update",
            "Start",
        ]
    )
    rows: dict[int, bytes] = {
        0: struct.pack("<HHHHH", 0, index[f"{assembly_name}.dll"], 0, 0, 0),
        1: struct.pack("<HHH", 0, index["MonoBehaviour"], index["UnityEngine"]),
        2: b"".join(
            [
                struct.pack("<IHHHHH", 0, index["<Module>"], 0, 0, 1, 1),
                struct.pack(
                    "<IHHHHH",
                    1,
                    index["PlayerController"],
                    index["Game"],
                    (1 << 2) | 1,
                    1,
                    1,
                ),
            ]
        ),
        6: b"".join(
            [
                struct.pack("<IHHHHH", 0x1100, 0, 6, index["Update"], 1, 1),
                struct.pack("<IHHHHH", 0x1120, 0, 6, index["Start"], 1, 1),
            ]
        ),
        32: struct.pack(
            "<IHHHHIHHH",
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            index[assembly_name],
            0,
        ),
    }
    row_sizes = {0: 10, 1: 6, 2: 14, 6: 14, 32: 22}
    row_counts = {
        table: len(payload) // row_sizes[table] for table, payload in rows.items()
    }
    valid_mask = sum(1 << table for table in rows)
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0)
    tables += b"".join(
        struct.pack("<I", row_counts[table]) for table in sorted(rows)
    )
    tables += b"".join(rows[table] for table in sorted(rows))
    blob = b"\x00\x01\x00"

    version = b"v4.0.30319\x00"
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    root = root.ljust(_align(len(root)), b"\x00") + struct.pack("<HH", 0, 3)
    stream_names = (b"#~", b"#Strings", b"#Blob")
    record_sizes = tuple(_align(8 + len(name) + 1) for name in stream_names)
    tables_offset = _align(len(root) + sum(record_sizes))
    strings_offset = _align(tables_offset + len(tables))
    blob_offset = _align(strings_offset + len(strings))

    def stream_record(offset: int, size: int, name: bytes) -> bytes:
        record = struct.pack("<II", offset, size) + name + b"\x00"
        return record.ljust(_align(len(record)), b"\x00")

    root += stream_record(tables_offset, len(tables), b"#~")
    root += stream_record(strings_offset, len(strings), b"#Strings")
    root += stream_record(blob_offset, len(blob), b"#Blob")
    root = root.ljust(tables_offset, b"\x00") + tables
    root = root.ljust(strings_offset, b"\x00") + strings
    return root.ljust(blob_offset, b"\x00") + blob


def _loaded_pe_image(
    module_name: str,
    *,
    exports: Sequence[tuple[str, int]] = (),
    metadata: bytes | None = None,
) -> tuple[bytes, dict[str, int]]:
    image = bytearray(0x6000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    struct.pack_into(
        "<4sHHIIIHH",
        image,
        0x80,
        b"PE\x00\x00",
        0x8664,
        2,
        0x65A0BEEF,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional_offset = 0x98
    struct.pack_into("<H", image, optional_offset, 0x20B)
    struct.pack_into("<I", image, optional_offset + 16, 0x1000)
    struct.pack_into("<Q", image, optional_offset + 24, 0x180000000)
    struct.pack_into("<I", image, optional_offset + 32, 0x1000)
    struct.pack_into("<I", image, optional_offset + 36, 0x200)
    struct.pack_into("<I", image, optional_offset + 56, len(image))
    struct.pack_into("<I", image, optional_offset + 60, 0x400)
    struct.pack_into("<I", image, optional_offset + 64, 0x11223344)
    struct.pack_into("<I", image, optional_offset + 108, 16)

    section_offset = optional_offset + 0xF0
    sections = (
        (b".text", 0x1000, 0x1000, 0x60000020),
        (b".rdata", 0x2000, 0x4000, 0x40000040),
    )
    for section_index, (name, rva, size, characteristics) in enumerate(sections):
        cursor = section_offset + section_index * 40
        image[cursor : cursor + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", image, cursor + 8, size, rva, size, 0)
        struct.pack_into("<I", image, cursor + 36, characteristics)

    export_rvas: dict[str, int] = {}
    if exports:
        export_rva = 0x2400
        export_size = 0x400
        dll_name_rva = 0x2480
        functions_rva = 0x24C0
        names_rva = 0x2500
        ordinals_rva = 0x2540
        name_cursor = 0x2580
        struct.pack_into(
            "<IIHHIIIIIII",
            image,
            export_rva,
            0,
            0x65A0BEEF,
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
        struct.pack_into("<II", image, optional_offset + 112, export_rva, export_size)
        dll_name = module_name.encode("ascii") + b"\x00"
        image[dll_name_rva : dll_name_rva + len(dll_name)] = dll_name
        for export_index, (name, function_rva) in enumerate(exports):
            encoded = name.encode("ascii") + b"\x00"
            struct.pack_into(
                "<I", image, functions_rva + export_index * 4, function_rva
            )
            struct.pack_into("<I", image, names_rva + export_index * 4, name_cursor)
            struct.pack_into("<H", image, ordinals_rva + export_index * 2, export_index)
            image[name_cursor : name_cursor + len(encoded)] = encoded
            export_rvas.setdefault(name, function_rva)
            name_cursor += len(encoded) + 4
            if 0x1000 <= function_rva < 0x2000:
                image[function_rva : function_rva + 4] = b"\x55\x48\x89\xe5"

    if metadata is not None:
        cli_rva = 0x2800
        metadata_rva = 0x3000
        struct.pack_into(
            "<II", image, optional_offset + 112 + 14 * 8, cli_rva, 72
        )
        struct.pack_into(
            "<IHHIIII",
            image,
            cli_rva,
            72,
            2,
            5,
            metadata_rva,
            len(metadata),
            1,
            0,
        )
        image[metadata_rva : metadata_rva + len(metadata)] = metadata
        image[0x1100:0x1104] = b"\x55\x48\x89\xe5"
        image[0x1120:0x1124] = b"\x55\x48\x89\xe5"
    return bytes(image), export_rvas


class MonoRuntimeBackend:
    name = "mono_runtime_fixture"
    available = True
    unavailable_reason = None

    def __init__(
        self,
        *,
        exports: Sequence[tuple[str, int]] | None = None,
        metadata: bytes | None = None,
        include_unity_player: bool = True,
        managed_path: str = r"C:\Fixtures\Unity\Managed\Assembly-CSharp.dll",
    ) -> None:
        self.pid = 7331
        self.calls: list[tuple[Any, ...]] = []
        selected_exports = exports or (
            ("mono_get_root_domain", 0x1180),
            ("mono_get_root_domain", 0x1180),
            ("mono_runtime_invoke", 0x11A0),
        )
        mono_image, self.mono_export_rvas = _loaded_pe_image(
            "mono-2.0-bdwgc.dll", exports=selected_exports
        )
        managed_image, _ = _loaded_pe_image(
            "Assembly-CSharp.dll",
            metadata=_mono_metadata_root() if metadata is None else metadata,
        )
        unity_image, _ = _loaded_pe_image("UnityPlayer.dll")
        self.modules: list[dict[str, Any]] = [
            {
                "name": "mono-2.0-bdwgc.dll",
                "path": r"C:\Fixtures\Unity\MonoBleedingEdge\EmbedRuntime\mono-2.0-bdwgc.dll",
                "base_address": 0x180000000,
                "size": len(mono_image),
                "data": mono_image,
            },
        ]
        if include_unity_player:
            self.modules.append(
                {
                    "name": "UnityPlayer.dll",
                    "path": r"C:\Fixtures\Unity\UnityPlayer.dll",
                    "base_address": 0x181000000,
                    "size": len(unity_image),
                    "data": unity_image,
                }
            )
        self.modules.append(
            {
                "name": "Assembly-CSharp.dll",
                "path": managed_path,
                "base_address": 0x182000000,
                "size": len(managed_image),
                "data": managed_image,
            }
        )

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        accessible = pid == self.pid
        return {
            "pid": pid,
            "exists": accessible,
            "accessible": accessible,
            "status": "ok" if accessible else "unavailable",
            "image_path": r"C:\Fixtures\Unity\Game.exe" if accessible else None,
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
        for module in self.modules:
            base = int(module["base_address"])
            data = bytes(module["data"])
            if base <= address and address + size <= base + len(data):
                offset = address - base
                return data[offset : offset + size]
        return b""

    def module(self, name: str) -> dict[str, Any]:
        return next(item for item in self.modules if item["name"] == name)

    def _require_pid(self, pid: int) -> None:
        if pid != self.pid:
            raise RuntimeError(f"unexpected pid: {pid}")


class EngineRuntimeMonoTests(unittest.TestCase):
    def _provider(
        self,
        backend: MonoRuntimeBackend,
        *,
        total: int = 256 * 1024,
        per_module: int = 64 * 1024,
        single: int = 4096,
    ) -> EngineRuntimeProvider:
        return EngineRuntimeProvider(
            backend,
            platform_name="win32",
            max_total_read_bytes=total,
            max_module_read_bytes=per_module,
            max_single_read_bytes=single,
            max_modules=8,
            max_evidence=256,
            max_export_names=64,
        )

    def _request(self, backend: MonoRuntimeBackend) -> CapabilityRequest:
        return CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=TargetIdentity(kind="process", pid=backend.pid),
            params={
                "scan_all_modules": True,
                "include_exports": True,
                "include_utf16": False,
            },
            session_id="engine-runtime-mono-test",
            provenance={"request_source": "unit-test"},
        )

    def _execute(
        self,
        backend: MonoRuntimeBackend,
        provider: EngineRuntimeProvider | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        selected_provider = provider or self._provider(backend)
        result = selected_provider.execute(
            selected_provider.plan(self._request(backend))
        )
        return result, result.report_section["operation"]

    def _mono_component(
        self, operation: Mapping[str, Any], module_name: str
    ) -> dict[str, Any]:
        analyzed = next(
            item
            for item in operation["analyzed_modules"]
            if item["module"]["name"] == module_name
        )
        return next(
            item
            for item in analyzed["runtime_extraction"]["components"]
            if item.get("engine") == "unity_mono"
        )

    def test_extracts_validated_exports_clr_tables_and_semantic_ir(self) -> None:
        backend = MonoRuntimeBackend()
        result, operation = self._execute(backend)

        self.assertEqual(result.status, "ok")
        self.assertIn("unity_mono", operation["detected_engines"])
        self.assertFalse(operation["remote_api_calls"])
        self.assertEqual(operation["runtime_object_addresses"]["status"], "unresolved")

        mono_component = self._mono_component(operation, "mono-2.0-bdwgc.dll")
        root_domain = next(
            item for item in mono_component["symbols"] if item["role"] == "root_domain"
        )
        mono_base = backend.module("mono-2.0-bdwgc.dll")["base_address"]
        self.assertEqual(root_domain["rva"], 0x1180)
        self.assertEqual(root_domain["address"], mono_base + 0x1180)
        self.assertTrue(root_domain["runtime_va_proof"]["verified"])
        self.assertEqual(root_domain["attributes"]["address_kind"], "embedding_function_va")
        self.assertEqual(root_domain["attributes"]["runtime_object_address"], "unresolved")
        validated_export = next(
            item
            for item in mono_component["embedding_exports"]
            if item["name"] == "mono_get_root_domain"
        )
        self.assertEqual(validated_export["status"], "validated")
        self.assertEqual(validated_export["address_kind"], "embedding_function_va")
        self.assertEqual(validated_export["section"], ".text")
        self.assertTrue(validated_export["section_proof"]["executable"])

        managed = self._mono_component(operation, "Assembly-CSharp.dll")
        record = managed["managed_assembly"]
        self.assertEqual(record["status"], "ok")
        self.assertTrue(record["validated"])
        self.assertEqual(record["file_header"]["pe_status"], "ok")
        self.assertEqual(record["assembly_name"], "Assembly-CSharp")
        self.assertEqual(
            {item["name"] for item in record["metadata"]["streams"]},
            {"#~", "#Strings", "#Blob"},
        )
        self.assertTrue(
            all(
                item["runtime_va_proof"]["verified"]
                for item in record["metadata"]["streams"]
            )
        )
        roles = {item["role"] for item in managed["symbols"]}
        self.assertTrue({"managed_assembly", "managed_type", "managed_method"} <= roles)
        player_type = next(
            item
            for item in managed["symbols"]
            if item["role"] == "managed_type" and item["name"] == "Game.PlayerController"
        )
        update = next(
            item
            for item in managed["symbols"]
            if item["role"] == "managed_method" and item["name"] == "Update"
        )
        managed_base = backend.module("Assembly-CSharp.dll")["base_address"]
        self.assertEqual(player_type["token"], "0x02000002")
        self.assertEqual(update["token"], "0x06000001")
        self.assertEqual(update["address"], managed_base + 0x1100)
        self.assertTrue(update["runtime_va_proof"]["verified"])
        self.assertEqual(update["attributes"]["address_kind"], "managed_method_body_va")
        self.assertEqual(update["attributes"]["runtime_object_address"], "unresolved")
        self.assertIn(
            "not a live MonoMethod object address",
            update["attributes"]["runtime_object_address_reason"],
        )

        entities = operation["semantic_ir_fragment"]["entities"]
        relations = operation["semantic_ir_fragment"]["relations"]
        self.assertIn("assembly", {item["kind"] for item in entities})
        self.assertIn("class", {item["kind"] for item in entities})
        self.assertIn("function", {item["kind"] for item in entities})
        self.assertIn("contains_type", {item["type"] for item in relations})
        self.assertIn("declares_method", {item["type"] for item in relations})
        managed_symbol_count = sum(
            item["role"] in {"managed_assembly", "managed_type", "managed_method"}
            for item in managed["symbols"]
        )
        self.assertEqual(
            managed["semantic_ir_fragment"]["runtime_object_addresses"]["count"],
            managed_symbol_count,
        )
        unity = self._mono_component(operation, "UnityPlayer.dll")
        self.assertEqual(unity["evidence"][0]["kind"], "unity_player_module")

    def test_rejects_non_executable_and_forwarded_embedding_exports(self) -> None:
        backend = MonoRuntimeBackend(
            exports=(
                ("mono_get_root_domain", 0x2A00),
                ("mono_runtime_invoke", 0x2600),
            ),
            include_unity_player=False,
        )
        result, operation = self._execute(backend)
        component = self._mono_component(operation, "mono-2.0-bdwgc.dll")

        self.assertEqual(result.status, "partial")
        self.assertEqual(component["status"], "partial")
        self.assertFalse(component["remote_api_calls"])
        self.assertEqual(component["runtime_object_addresses"]["status"], "unresolved")
        self.assertEqual(
            {item["status"] for item in component["embedding_exports"]}, {"rejected"}
        )
        errors = " ".join(
            message
            for item in component["embedding_exports"]
            for message in item.get("errors") or []
        )
        self.assertIn("not in an executable", errors)
        self.assertIn("forwarded exports", errors)
        self.assertFalse(
            {"root_domain", "runtime_invoke"}
            & {item["role"] for item in component.get("symbols") or []}
        )

    def test_bad_metadata_never_recovers_filename_only_symbols(self) -> None:
        metadata = bytearray(_mono_metadata_root())
        metadata[:4] = b"NOPE"
        backend = MonoRuntimeBackend(
            metadata=bytes(metadata), include_unity_player=False
        )
        result, operation = self._execute(backend)
        managed = self._mono_component(operation, "Assembly-CSharp.dll")

        self.assertEqual(result.status, "partial")
        self.assertEqual(managed["status"], "partial")
        self.assertFalse(managed["managed_assembly"]["validated"])
        self.assertIsNone(managed["managed_assembly"].get("assembly_name"))
        self.assertFalse(
            {"managed_assembly", "managed_type", "managed_method"}
            & {item["role"] for item in managed.get("symbols") or []}
        )
        self.assertTrue(managed["errors"])
        self.assertFalse(operation["remote_api_calls"])

    def test_budget_truncation_bounds_every_read_and_emits_no_partial_symbols(self) -> None:
        backend = MonoRuntimeBackend(include_unity_player=False)
        provider = self._provider(backend, total=1200, per_module=600, single=64)
        result, operation = self._execute(backend, provider)
        usage = operation["read_usage"]

        self.assertEqual(result.status, "partial")
        self.assertTrue(usage["truncated"])
        self.assertLessEqual(usage["requested_bytes"], 1200)
        self.assertLessEqual(usage["max_observed_request"], 64)
        self.assertTrue(
            all(value <= 600 for value in usage["module_requested_bytes"].values())
        )
        reads = [call for call in backend.calls if call[0] == "read_process_memory"]
        self.assertTrue(reads)
        self.assertTrue(all(call[3] <= 64 for call in reads))
        managed = self._mono_component(operation, "Assembly-CSharp.dll")
        self.assertEqual(managed["managed_assembly"]["status"], "partial")
        self.assertFalse(
            {"managed_assembly", "managed_type", "managed_method"}
            & {item["role"] for item in managed.get("symbols") or []}
        )

    def test_duplicate_export_evidence_is_deduplicated_and_output_is_deterministic(self) -> None:
        first_backend = MonoRuntimeBackend()
        _, first = self._execute(first_backend)
        second_backend = MonoRuntimeBackend()
        _, second = self._execute(second_backend)

        root_evidence = [
            item
            for item in first["evidence"]
            if item.get("kind") == "mono_embedding_export"
            and item.get("marker") == "mono_get_root_domain"
        ]
        generic_root_evidence = [
            item
            for item in first["evidence"]
            if item.get("kind") == "symbol"
            and item.get("marker") == "mono_get_root_domain"
        ]
        self.assertEqual(len(root_evidence), 1)
        self.assertEqual(len(generic_root_evidence), 1)
        first_component = self._mono_component(first, "mono-2.0-bdwgc.dll")
        self.assertEqual(
            sum(
                item["name"] == "mono_get_root_domain"
                for item in first_component["embedding_exports"]
            ),
            1,
        )

        keys = (
            "runtime_extractions",
            "symbols",
            "semantic_ir_fragment",
            "evidence",
            "dependency_status",
        )
        first_payload = json.dumps(
            {key: first[key] for key in keys}, sort_keys=True, separators=(",", ":")
        )
        second_payload = json.dumps(
            {key: second[key] for key in keys}, sort_keys=True, separators=(",", ":")
        )
        self.assertEqual(first_payload, second_payload)

    def test_relative_managed_path_is_rejected_before_remote_reads(self) -> None:
        backend = MonoRuntimeBackend(
            include_unity_player=False,
            managed_path=r"Managed\Assembly-CSharp.dll",
        )
        result, operation = self._execute(backend)
        managed_analysis = next(
            item
            for item in operation["analyzed_modules"]
            if item["module"]["name"] == "Assembly-CSharp.dll"
        )
        managed = self._mono_component(operation, "Assembly-CSharp.dll")
        module = backend.module("Assembly-CSharp.dll")
        start = int(module["base_address"])
        end = start + int(module["size"])
        managed_reads = [
            call
            for call in backend.calls
            if call[0] == "read_process_memory" and start <= call[2] < end
        ]

        self.assertEqual(result.status, "partial")
        self.assertEqual(managed_analysis["pe"]["status"], "skipped")
        self.assertEqual(managed["status"], "partial")
        self.assertFalse(managed["path_identity"]["valid"])
        self.assertEqual(managed_reads, [])
        self.assertFalse(
            {"managed_assembly", "managed_type", "managed_method"}
            & {item["role"] for item in managed.get("symbols") or []}
        )


@unittest.skipUnless(
    live_engine_fixture_enabled("REVERSE_ANALYZER_UNITY_MONO_FIXTURE"),
    "requires a production Windows Unity Mono fixture and acceptance directory",
)
class EngineRuntimeMonoLiveAcceptanceTests(unittest.TestCase):
    def test_production_backend_materializes_live_acceptance_artifacts(self) -> None:
        run_live_engine_acceptance(
            self,
            fixture_env="REVERSE_ANALYZER_UNITY_MONO_FIXTURE",
            expected_engine="unity_mono",
        )


if __name__ == "__main__":
    unittest.main()
