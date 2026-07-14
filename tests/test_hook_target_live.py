from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.patch.dll_proxy import parse_pe_exports
from reverse_analyzer.providers.hook_target_resolver import HookTargetResolverProvider
from reverse_analyzer.providers.hook_targets import (
    enumerate_current_process_modules,
    live_hook_target_capability,
    plan_live_common_hook_target,
    resolve_common_hook_target,
    resolve_live_common_hook_target,
)
from tests.test_dll_proxy_generator import _minimal_export_dll


WINDOWS = sys.platform == "win32"


class HookTargetProductionTruthTests(unittest.TestCase):
    def test_offline_fixture_never_becomes_production_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module = Path(temporary) / "fixture.dll"
            image = bytearray(
                _minimal_export_dll(bits=64, first_export_name="Alpha")
            )
            pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
            optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
            section_table = pe_offset + 24 + optional_size
            struct.pack_into("<I", image, section_table + 36, 0x60000040)
            module.write_bytes(image)

            resolution = resolve_common_hook_target(
                {
                    "method": "module_export",
                    "module": "fixture.dll",
                    "export": "Alpha",
                    "module_path": module,
                    "module_base": 0x70000000,
                }
            )

        self.assertTrue(resolution.ok, resolution.to_dict())
        self.assertFalse(resolution.production_ready)
        self.assertEqual(resolution.evidence_tier, "offline")
        self.assertFalse(resolution.to_dict()["production_ready"])

    def test_non_windows_live_resolution_is_explicitly_unavailable(self) -> None:
        if WINDOWS:
            self.skipTest("non-Windows availability contract")

        capability = live_hook_target_capability()
        resolution = resolve_live_common_hook_target("winsock_send")
        plan = plan_live_common_hook_target("d3d11_present")

        self.assertEqual(capability["status"], "unavailable")
        self.assertEqual(resolution.status, "unavailable")
        self.assertFalse(resolution.production_ready)
        self.assertEqual(plan.status, "unavailable")
        self.assertFalse(plan.production_ready)


@unittest.skipUnless(WINDOWS, "requires benign current-process Windows APIs")
class WindowsLiveHookTargetTests(unittest.TestCase):
    def test_acceptance_runner_retains_live_production_artifacts(self) -> None:
        configured = str(
            os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or ""
        ).strip()
        if not configured:
            return

        session_id = str(
            os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID")
            or "p1-hook-target-resolution"
        )
        executable = Path(sys.executable).resolve()
        provider = HookTargetResolverProvider()
        request = CapabilityRequest(
            capability="hook_target_resolver",
            action="resolve_live",
            target=TargetIdentity(
                kind="process",
                pid=os.getpid(),
                path=str(executable),
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
                display_name=executable.name,
            ),
            params={
                "specification": {
                    "method": "module_export",
                    "module": "kernel32.dll",
                    "export": "GetCurrentProcessId",
                },
                "load_if_missing": False,
            },
            session_id=session_id,
            provenance={
                "source": "p1-acceptance",
                "evidence_class": "live_host_proof",
                "synthetic": False,
            },
        )

        plan = provider.plan(request)
        validation = provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        result = provider.execute(plan)
        self.assertEqual(result.status, "ok", result.report_section)
        resolution = result.after_snapshot["resolution"]
        self.assertTrue(resolution["production_ready"], resolution)
        self.assertEqual(resolution["evidence_tier"], "live-production")
        self.assertFalse(resolution["provenance"]["injected_backend"])
        self.assertFalse(resolution["provenance"]["synthetic"])

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)
        root = Path(configured).expanduser().resolve()
        bundle = provider.collect_artifacts(result, str(root))
        self.assertEqual(len(bundle.artifacts), 3)
        self.assertTrue(
            (root / "hook-targets" / session_id / "resolution.json").is_file()
        )
        self.assertTrue((root / "hook-targets" / session_id / "audit.json").is_file())
        evidence = root / "hook-targets"
        (evidence / "target-identity.json").write_text(
            json.dumps(request.target.to_dict(), indent=2) + "\n",
            encoding="utf-8",
        )
        (evidence / "rollback.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "verified": True,
                    "restored": bool(rollback.restored),
                    "target_mutated": False,
                    "strategy": "read_only_noop",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (evidence / "execution-proof.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "provider": result.provider,
                    "evidence_class": "live_host_proof",
                    "executed_tests": 1,
                    "skipped_tests": 0,
                    "live_operations": 1,
                    "actions": ["resolve_live"],
                    "synthetic": False,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_current_process_module_enumeration_is_real_and_unambiguous(self) -> None:
        capability = live_hook_target_capability()
        modules = enumerate_current_process_modules()
        kernel32 = [item for item in modules if item.name.casefold() == "kernel32.dll"]

        self.assertEqual(capability["status"], "available")
        self.assertTrue(capability["production_ready"])
        self.assertFalse(capability["injected_backend"])
        self.assertGreater(len(modules), 3)
        self.assertEqual(len(kernel32), 1)
        self.assertTrue(kernel32[0].path.is_file())
        self.assertGreater(kernel32[0].base, 0)
        self.assertGreater(kernel32[0].size_of_image, 0)
        self.assertEqual(len({item.base for item in modules}), len(modules))

    def test_winsock_and_opengl_exports_have_live_production_proof(self) -> None:
        cases = (
            ("winsock_send", "send"),
            ("winsock_recv", "recv"),
            ("opengl_swap_buffers", "wglSwapBuffers"),
            ("gdi_swap_buffers", "SwapBuffers"),
        )
        for target, export_name in cases:
            with self.subTest(target=target):
                resolution = resolve_live_common_hook_target(
                    target,
                    load_if_missing=True,
                )
                payload = resolution.to_dict()

                self.assertTrue(resolution.ok, payload)
                self.assertTrue(resolution.production_ready, payload)
                self.assertEqual(resolution.evidence_tier, "live-production")
                self.assertEqual(resolution.symbol, export_name)
                self.assertIsNotNone(resolution.address)
                self.assertEqual(resolution.executable_range["status"], "ok")
                self.assertTrue(resolution.executable_range["executable"])
                memory = resolution.executable_range["virtual_memory"]
                self.assertEqual(memory["status"], "ok")
                self.assertTrue(memory["committed"])
                self.assertTrue(memory["image"])
                self.assertTrue(memory["executable"])

                identity = resolution.source["resolved_module_identity"]
                self.assertEqual(identity["status"], "ok")
                self.assertEqual(len(identity["file_sha256"]), 64)
                self.assertTrue(identity["architecture_matches_process"])
                self.assertTrue(identity["memory_header_matches_file"])
                self.assertTrue(identity["memory_header_base_matches_loader"])
                self.assertTrue(identity["loader_size_matches_pe"])
                self.assertTrue(identity["executable_ranges"])

                aslr = resolution.source["aslr_address_proof"]
                self.assertEqual(aslr["status"], "ok")
                self.assertTrue(aslr["matches"])
                self.assertEqual(
                    aslr["loaded_base"] + aslr["rva"],
                    resolution.address,
                )
                self.assertFalse(resolution.ambiguity["ambiguous"])
                self.assertEqual(resolution.ambiguity["candidate_count"], 1)
                self.assertFalse(resolution.provenance["injected_backend"])
                self.assertFalse(resolution.provenance["synthetic"])

                library = ctypes.WinDLL(
                    resolution.source["source_module_identity"]["path"]
                )
                loader_address = ctypes.cast(
                    getattr(library, export_name),
                    ctypes.c_void_p,
                ).value
                self.assertEqual(loader_address, resolution.address)

    def test_forwarded_system_export_tracks_loader_endpoint(self) -> None:
        modules = enumerate_current_process_modules()
        kernel32 = next(
            item for item in modules if item.name.casefold() == "kernel32.dll"
        )
        loaded_names = {
            item.name.casefold().removesuffix(".dll") for item in modules
        }
        exports = parse_pe_exports(kernel32.path).exports
        physical_forwarders = []
        for export in exports:
            if export.name is None or not export.forwarder:
                continue
            module_token = export.forwarder.rpartition(".")[0].casefold()
            if module_token.removesuffix(".dll") in loaded_names:
                physical_forwarders.append(export)

        selected = None
        for export in physical_forwarders:
            candidate = resolve_live_common_hook_target(
                {
                    "method": "module_export",
                    "module": kernel32.name,
                    "module_path": kernel32.path,
                    "module_base": kernel32.base,
                    "export": export.name,
                }
            )
            if candidate.ok and len(candidate.source.get("forwarder_chain", [])) >= 2:
                selected = candidate
                break
        if selected is None:
            self.skipTest("this Windows build exposes no resolvable physical forwarder")

        self.assertTrue(selected.production_ready, selected.to_dict())
        self.assertIsNotNone(selected.source["requested_export"]["forwarder"])
        chain = selected.source["forwarder_chain"]
        self.assertGreaterEqual(len(chain), 2)
        self.assertEqual(chain[0]["module"].casefold(), "kernel32.dll")
        self.assertEqual(chain[-1]["status"], "ok")
        self.assertIsNone(chain[-1]["forwarder"])
        self.assertEqual(selected.module.casefold(), chain[-1]["module"].casefold())
        self.assertEqual(selected.symbol, chain[-1]["export"])
        self.assertEqual(selected.executable_range["status"], "ok")
        self.assertEqual(
            selected.source["loader_resolution"]["resolved_address"],
            selected.address,
        )

    def test_repeated_live_resolution_is_stable_after_benign_auto_load(self) -> None:
        spec = {
            "method": "module_export",
            "module": "d3d11.dll",
            "export": "D3D11CreateDevice",
            "load_if_missing": True,
        }
        initially_loaded = any(
            item.name.casefold() == "d3d11.dll"
            for item in enumerate_current_process_modules()
        )
        if initially_loaded:
            self.skipTest("d3d11.dll was already loaded by the test process")

        first = resolve_live_common_hook_target(spec)
        second = resolve_live_common_hook_target(spec)

        self.assertTrue(first.ok, first.to_dict())
        self.assertTrue(first.production_ready, first.to_dict())
        self.assertTrue(first.provenance["loaded_by_resolver"])
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_common_resolver_live_dispatch_cannot_use_fixture_modules(self) -> None:
        resolution = resolve_common_hook_target(
            {
                "target": "winsock_send",
                "live": True,
                "load_if_missing": True,
                "modules": [
                    {
                        "name": "ws2_32.dll",
                        "path": "C:/synthetic/ws2_32.dll",
                        "base": 0x70000000,
                    }
                ],
            }
        )

        self.assertTrue(resolution.ok, resolution.to_dict())
        self.assertTrue(resolution.production_ready)
        self.assertNotEqual(resolution.address, 0x70000000)
        self.assertFalse(resolution.provenance["injected_backend"])
        self.assertEqual(
            resolution.source["loader_resolution"]["module_handle"],
            resolution.source["source_module_identity"]["loaded_base"],
        )

    def test_dxgi_d3d11_present_is_dependency_gated_without_swap_chain(self) -> None:
        for target in ("dxgi_present", "d3d11_present"):
            with self.subTest(target=target):
                plan = plan_live_common_hook_target(target)
                via_resolver = resolve_live_common_hook_target(target)

                self.assertEqual(plan.status, "dependency_gated")
                self.assertEqual(via_resolver.status, "dependency_gated")
                self.assertFalse(plan.ok)
                self.assertFalse(plan.production_ready)
                self.assertFalse(plan.evidence_plan["creation_performed"])
                self.assertEqual(
                    plan.evidence_plan["creation_policy"],
                    "caller_owned_object_only",
                )
                self.assertEqual(plan.source["vtable_index"], 8)
                self.assertEqual(plan.source["interface"], "IDXGISwapChain")
                self.assertIn(
                    "object_address or vtable_address",
                    plan.evidence_plan["required_inputs"],
                )
                dependency_names = {
                    item["module"]
                    for item in plan.evidence_plan["dependency_status"]
                }
                self.assertIn("dxgi.dll", dependency_names)
                if target == "d3d11_present":
                    self.assertIn("d3d11.dll", dependency_names)


if __name__ == "__main__":
    unittest.main()
