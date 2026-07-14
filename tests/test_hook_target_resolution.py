from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.providers.hook_targets import (
    common_hook_targets,
    inspect_hook_module,
    resolve_common_hook_target,
    write_hook_target_resolution,
)
from reverse_analyzer.providers.native_hook import NativeHookProvider
from tests.test_dll_proxy_generator import SECTION_OFFSET, _minimal_export_dll
from tests.test_native_hook_provider import FakeWin32Backend, _request


def _fixture(
    *,
    bits: int = 64,
    export: str = "Alpha",
    second_export: str = "Forwarded",
    executable: bool = True,
) -> bytes:
    data = bytearray(_minimal_export_dll(bits=bits, first_export_name=export))
    encoded_second = second_export.encode("ascii")
    if not 1 <= len(encoded_second) <= 9:
        raise ValueError("second_export must contain 1-9 ASCII bytes")
    data[SECTION_OFFSET + 0x78 : SECTION_OFFSET + 0x82] = encoded_second.ljust(10, b"\x00")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    characteristics = 0x60000040 if executable else 0x40000040
    struct.pack_into("<I", data, section_table + 36, characteristics)
    return bytes(data)


def _iat_fixture(*, duplicate_descriptor: bool = False) -> bytes:
    data = bytearray(_fixture())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic != 0x20B:
        raise ValueError("IAT fixture expects PE32+")
    import_directory = optional + 112 + 8
    descriptor_count = 2 if duplicate_descriptor else 1
    struct.pack_into("<II", data, import_directory, 0x1400, (descriptor_count + 1) * 20)

    descriptor = (0x1450, 0, 0, 0x1490, 0x1470)
    struct.pack_into("<IIIII", data, SECTION_OFFSET + 0x400, *descriptor)
    if duplicate_descriptor:
        struct.pack_into("<IIIII", data, SECTION_OFFSET + 0x414, *descriptor)
    struct.pack_into("<QQQ", data, SECTION_OFFSET + 0x450, 0x14A0, (1 << 63) | 7, 0)
    struct.pack_into("<QQQ", data, SECTION_OFFSET + 0x470, 0x14A0, (1 << 63) | 7, 0)
    data[SECTION_OFFSET + 0x490 : SECTION_OFFSET + 0x49D] = b"KERNEL32.dll\x00"
    struct.pack_into("<H", data, SECTION_OFFSET + 0x4A0, 3)
    data[SECTION_OFFSET + 0x4A2 : SECTION_OFFSET + 0x4A8] = b"Sleep\x00"
    return bytes(data)


class HookTargetResolutionTests(unittest.TestCase):
    def test_catalogue_export_alias_resolves_with_executable_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "ws2_32.dll"
            module.write_bytes(_fixture(export="send", second_export="zzzzzzzz"))

            resolution = resolve_common_hook_target(
                {
                    "target": "winsock_send",
                    "module_path": str(module),
                    "module_base": "0x70000000",
                }
            )

            self.assertTrue(resolution.ok, resolution.to_dict())
            self.assertEqual(resolution.address, 0x70001300)
            self.assertEqual(resolution.rva, 0x1300)
            self.assertEqual(resolution.symbol, "send")
            self.assertEqual(resolution.executable_range["status"], "ok")
            self.assertTrue(resolution.executable_range["executable"])
            self.assertEqual(resolution.source["kind"], "pe_export")
            self.assertEqual(resolution.source["sha256"], inspect_hook_module(module).sha256)

    def test_module_rva_requires_an_executable_section(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "game.exe"
            executable.write_bytes(_fixture())
            rejected = Path(temporary) / "data.dll"
            rejected.write_bytes(_fixture(executable=False))

            accepted = resolve_common_hook_target(
                {
                    "method": "module_rva",
                    "module_path": executable,
                    "module_base": 0x140000000,
                    "rva": 0x1300,
                    "symbol": "GameTick",
                }
            )
            denied = resolve_common_hook_target(
                {
                    "method": "module_rva",
                    "module_path": rejected,
                    "module_base": 0x180000000,
                    "rva": 0x1300,
                }
            )

            self.assertTrue(accepted.ok, accepted.to_dict())
            self.assertEqual(accepted.address, 0x140001300)
            self.assertEqual(denied.status, "failed")
            self.assertIn("non-executable", denied.errors[0])

    def test_iat_slot_resolves_named_and_ordinal_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "game.exe"
            module.write_bytes(_iat_fixture())
            named = resolve_common_hook_target(
                {
                    "method": "iat_slot",
                    "module_path": module,
                    "module_base": 0x140000000,
                    "dll": "kernel32",
                    "symbol": "Sleep",
                }
            )
            ordinal = resolve_common_hook_target(
                {
                    "method": "import_thunk",
                    "module_path": module,
                    "module_base": 0x140000000,
                    "import_module": "KERNEL32.dll",
                    "ordinal": 7,
                }
            )

            self.assertTrue(named.ok, named.to_dict())
            self.assertEqual(named.method, "iat_slot")
            self.assertEqual(named.address, 0x140001470)
            self.assertEqual(named.slot_address, named.address)
            self.assertEqual(named.rva, 0x1470)
            self.assertEqual(named.source["file_offset"], SECTION_OFFSET + 0x470)
            self.assertEqual(named.source["imported_module"], "KERNEL32.dll")
            self.assertEqual(named.source["pointer_size"], 8)
            self.assertEqual(named.executable_range["status"], "not_observed")
            self.assertFalse(named.production_ready)
            self.assertEqual(named.evidence_tier, "offline")

            self.assertTrue(ordinal.ok, ordinal.to_dict())
            self.assertEqual(ordinal.slot_address, 0x140001478)
            self.assertEqual(ordinal.symbol, "#7")
            self.assertEqual(ordinal.source["import_ordinal"], 7)

    def test_iat_slot_rejects_ambiguous_and_missing_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "game.exe"
            module.write_bytes(_iat_fixture(duplicate_descriptor=True))
            ambiguous = resolve_common_hook_target(
                {
                    "method": "iat",
                    "module_path": module,
                    "module_base": 0x140000000,
                    "dll": "kernel32.dll",
                    "symbol": "Sleep",
                }
            )
            missing = resolve_common_hook_target(
                {
                    "method": "iat_slot",
                    "module_path": module,
                    "module_base": 0x140000000,
                    "dll": "user32.dll",
                    "symbol": "MessageBoxW",
                }
            )

            self.assertEqual(ambiguous.status, "ambiguous")
            self.assertEqual(ambiguous.ambiguity["candidate_count"], 2)
            self.assertEqual(missing.status, "failed")
            self.assertIn("resolved to 0 IAT slots", missing.errors[0])

    def test_pattern_resolution_accepts_one_match_and_rejects_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "game.dll"
            data = bytearray(_fixture())
            data[SECTION_OFFSET + 0x300 : SECTION_OFFSET + 0x304] = b"\x48\x8b\x51\xc3"
            module.write_bytes(data)

            unique = resolve_common_hook_target(
                {
                    "method": "pattern",
                    "module_path": module,
                    "module_base": 0x180000000,
                    "pattern": "48 8B ?? C3",
                    "symbol": "CameraUpdate",
                }
            )
            self.assertTrue(unique.ok, unique.to_dict())
            self.assertEqual(unique.address, 0x180001300)
            self.assertEqual(unique.source["pattern"], "48 8B ?? C3")

            data[SECTION_OFFSET + 0x310 : SECTION_OFFSET + 0x314] = b"\x48\x8b\x61\xc3"
            module.write_bytes(data)
            ambiguous = resolve_common_hook_target(
                {
                    "method": "pattern",
                    "module_path": module,
                    "module_base": 0x180000000,
                    "pattern": "48 8B ?? C3",
                }
            )
            self.assertEqual(ambiguous.status, "ambiguous")
            self.assertEqual(ambiguous.ambiguity["candidate_count"], 2)
            self.assertEqual(len(ambiguous.ambiguity["candidates"]), 2)

    def test_vtable_alias_proves_method_and_calculates_slot_address(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "dxgi.dll"
            module.write_bytes(_fixture())
            entries = [0] * 9
            entries[8] = 0x180001300

            resolution = resolve_common_hook_target(
                {
                    "target": "dxgi_present",
                    "vtable_address": 0x50000000,
                    "architecture": "x64",
                    "entries": entries,
                },
                modules=[{"name": "dxgi.dll", "path": module, "base": 0x180000000}],
            )

            self.assertTrue(resolution.ok, resolution.to_dict())
            self.assertEqual(resolution.address, 0x180001300)
            self.assertEqual(resolution.slot_address, 0x50000040)
            self.assertEqual(resolution.source["vtable_index"], 8)
            self.assertEqual(resolution.source["interface"], "IDXGISwapChain")
            self.assertEqual(resolution.module, "dxgi.dll")

    def test_vtable_address_without_module_evidence_is_not_accepted(self) -> None:
        resolution = resolve_common_hook_target(
            {
                "target": "d3d9_end_scene",
                "vtable_address": 0x50000000,
                "method_address": 0x70001000,
            }
        )
        self.assertFalse(resolution.ok)
        self.assertEqual(resolution.executable_range["candidate_count"], 0)
        self.assertIn("0 supplied module ranges", resolution.errors[0])

    def test_forwarded_export_is_followed_through_supplied_module_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "forwarder.dll"
            source.write_bytes(_fixture(export="Alpha"))
            kernel32 = Path(temporary) / "kernel32.dll"
            kernel32.write_bytes(_fixture(export="Sleep", second_export="zzzzzzzz"))

            resolution = resolve_common_hook_target(
                {
                    "method": "module_export",
                    "module_path": source,
                    "module_base": 0x180000000,
                    "export": "Forwarded",
                },
                modules=[
                    {"name": "kernel32.dll", "path": kernel32, "base": 0x7FFF00000000}
                ],
            )

            self.assertTrue(resolution.ok, resolution.to_dict())
            self.assertEqual(resolution.address, 0x7FFF00001300)
            self.assertEqual(resolution.symbol, "Sleep")
            self.assertEqual(resolution.source["forwarder_chain"][0]["forwarder"], "KERNEL32.Sleep")

    def test_resolution_artifact_and_catalogue_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "vulkan-1.dll"
            module.write_bytes(_fixture(export="Alpha"))
            resolution = resolve_common_hook_target(
                {
                    "method": "module_rva",
                    "module_path": module,
                    "module_base": 0x180000000,
                    "rva": 0x1300,
                }
            )
            artifact = write_hook_target_resolution(resolution, temporary)
            payload = json.loads(artifact.read_text(encoding="utf-8"))

            self.assertEqual(artifact, Path(temporary).resolve() / "hook-targets" / "resolution.json")
            self.assertEqual(payload["address"], 0x180001300)
            self.assertIn("vulkan_present", common_hook_targets())
            first = common_hook_targets()
            first["vulkan_present"]["export"] = "changed"
            self.assertEqual(common_hook_targets()["vulkan_present"]["export"], "vkQueuePresentKHR")

    def test_native_vtable_plan_consumes_resolution_and_materializes_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "dxgi.dll"
            module.write_bytes(_fixture())
            method = 0x180001300
            slot = 0x50000040
            replacement = 0x180001380
            entries = [0] * 9
            entries[8] = method
            backend = FakeWin32Backend()
            backend.map(slot, method.to_bytes(8, "little"))
            provider = NativeHookProvider(backend, platform_name="win32")

            plan = provider.plan(
                _request(
                    "vtable_pointer",
                    {
                        "authorized": True,
                        "replacement_pointer": replacement,
                        "target_resolution": {
                            "specification": {
                                "target": "dxgi_present",
                                "vtable_address": 0x50000000,
                                "architecture": "x64",
                                "entries": entries,
                            },
                            "modules": [
                                {
                                    "name": "dxgi.dll",
                                    "path": module,
                                    "base": 0x180000000,
                                }
                            ],
                        },
                    },
                )
            )

            self.assertEqual(plan.parameters["slot_address"], slot)
            self.assertEqual(plan.parameters["expected_original_pointer"], method)
            self.assertEqual(plan.parameters["architecture"], "x64")
            self.assertEqual(plan.parameters["target_resolution"]["status"], "ok")
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.to_dict())

            result = provider.execute(plan)
            self.assertEqual(result.status, "ok")
            bundle = provider.collect_artifacts(result, temporary)
            resolution_artifact = next(
                item
                for item in bundle.artifacts
                if item.kind == "native-hook-target-resolution"
            )
            payload = json.loads(
                (Path(temporary) / resolution_artifact.path).read_text(encoding="utf-8")
            )
            self.assertEqual(payload["address"], method)
            self.assertEqual(payload["slot_address"], slot)
            self.assertEqual(payload["executable_range"]["status"], "ok")
            self.assertTrue(provider.rollback(result).restored)

    def test_native_hook_resolution_conflicts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "dxgi.dll"
            module.write_bytes(_fixture())
            method = 0x180001300
            entries = [0] * 9
            entries[8] = method
            backend = FakeWin32Backend()
            backend.map(0x50000040, method.to_bytes(8, "little"))
            provider = NativeHookProvider(backend, platform_name="win32")
            plan = provider.plan(
                _request(
                    "vtable_pointer",
                    {
                        "authorized": True,
                        "slot_address": 0x50000048,
                        "replacement_pointer": 0x180001380,
                        "target_resolution": {
                            "target": "dxgi_present",
                            "vtable_address": 0x50000000,
                            "architecture": "x64",
                            "entries": entries,
                            "modules": [
                                {"name": "dxgi.dll", "path": module, "base": 0x180000000}
                            ],
                        },
                    },
                )
            )

            self.assertTrue(
                any("conflicts" in item for item in plan.parameters["parameter_errors"])
            )
            result = provider.execute(plan)
            self.assertEqual(result.status, "failed")
            self.assertFalse(any(call[0] == "write" for call in backend.calls))

    def test_native_hook_validation_rejects_changed_module_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "dxgi.dll"
            module.write_bytes(_fixture())
            method = 0x180001300
            slot = 0x50000040
            entries = [0] * 9
            entries[8] = method
            backend = FakeWin32Backend()
            backend.map(slot, method.to_bytes(8, "little"))
            provider = NativeHookProvider(backend, platform_name="win32")
            plan = provider.plan(
                _request(
                    "vtable_pointer",
                    {
                        "authorized": True,
                        "replacement_pointer": 0x180001380,
                        "target_resolution": {
                            "target": "dxgi_present",
                            "vtable_address": 0x50000000,
                            "architecture": "x64",
                            "entries": entries,
                            "modules": [
                                {"name": "dxgi.dll", "path": module, "base": 0x180000000}
                            ],
                        },
                    },
                )
            )
            changed = bytearray(module.read_bytes())
            changed[-1] ^= 0x5A
            module.write_bytes(changed)

            validation = provider.validate(plan)
            self.assertFalse(validation.ok)
            self.assertTrue(
                any("changed after planning" in item for item in validation.errors),
                validation.to_dict(),
            )
            result = provider.execute(plan)
            self.assertEqual(result.status, "failed")
            self.assertFalse(any(call[0] == "write" for call in backend.calls))

    def test_inline_and_hardware_plans_bind_the_resolved_executable_address(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "game.dll"
            module.write_bytes(_fixture())
            target = 0x140001300
            original = b"\x55\x48\x89\xE5" + b"\x90" * 10
            backend = FakeWin32Backend()
            backend.map(target, original)
            provider = NativeHookProvider(backend, platform_name="win32")
            resolution = {
                "method": "module_rva",
                "module_path": module,
                "module_base": 0x140000000,
                "rva": 0x1300,
            }

            inline = provider.plan(
                _request(
                    "inline_trampoline",
                    {
                        "authorized": True,
                        "replacement_pointer": 0x180002000,
                        "expected_original_bytes": original.hex(),
                        "target_resolution": resolution,
                    },
                    session_id="resolved-inline",
                )
            )
            hardware = provider.plan(
                _request(
                    "hardware_breakpoint",
                    {
                        "authorized": True,
                        "thread_id": 77,
                        "access": "execute",
                        "size": 1,
                        "target_resolution": resolution,
                    },
                    session_id="resolved-hardware",
                )
            )

            self.assertEqual(inline.parameters["target_address"], target)
            self.assertEqual(inline.parameters["architecture"], "x64")
            self.assertEqual(hardware.parameters["address"], target)
            self.assertEqual(hardware.parameters["target_resolution"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
