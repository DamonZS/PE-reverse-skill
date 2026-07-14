import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch

from reverse_analyzer.core.capabilities.models import (
    CapabilityRequest,
    TargetIdentity,
)
from reverse_analyzer.providers.engine_runtime import (
    EngineRuntimeProvider,
    UnavailableEngineRuntimeBackend,
    WindowsEngineRuntimeBackend,
)
from tests._engine_acceptance import (
    _acceptance_root,
    live_engine_fixture_enabled,
)


def _pe_image(
    module_name: str,
    exports: list[str],
    *,
    ascii_markers: tuple[str, ...] = (),
    utf16_markers: tuple[str, ...] = (),
) -> tuple[bytes, dict[str, int]]:
    image = bytearray(0x4000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    struct.pack_into(
        "<4sHHIIIHH",
        image,
        0x80,
        b"PE\x00\x00",
        0x8664,
        1,
        0x65A0BEEF,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional_offset = 0x98
    struct.pack_into("<H", image, optional_offset, 0x20B)
    struct.pack_into("<I", image, optional_offset + 16, 0x1000)
    struct.pack_into("<I", image, optional_offset + 56, len(image))
    struct.pack_into("<I", image, optional_offset + 64, 0x11223344)
    struct.pack_into("<I", image, optional_offset + 108, 16)

    export_rva = 0x400
    export_size = 0x300
    dll_name_rva = 0x480
    functions_rva = 0x500
    names_rva = 0x540
    ordinals_rva = 0x580
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
    struct.pack_into(
        "<II", image, optional_offset + 112, export_rva, export_size
    )
    dll_name = module_name.encode("ascii") + b"\x00"
    image[dll_name_rva : dll_name_rva + len(dll_name)] = dll_name

    rvas: dict[str, int] = {}
    next_name_rva = 0x700
    for index, export in enumerate(exports):
        function_rva = 0x1000 + index * 0x20
        encoded = export.encode("ascii") + b"\x00"
        struct.pack_into("<I", image, functions_rva + index * 4, function_rva)
        struct.pack_into("<I", image, names_rva + index * 4, next_name_rva)
        struct.pack_into("<H", image, ordinals_rva + index * 2, index)
        image[next_name_rva : next_name_rva + len(encoded)] = encoded
        rvas[export] = function_rva
        next_name_rva += len(encoded) + 8

    marker_rva = 0x1800
    for marker in ascii_markers:
        encoded = marker.encode("ascii") + b"\x00"
        image[marker_rva : marker_rva + len(encoded)] = encoded
        rvas[f"ascii:{marker}"] = marker_rva
        marker_rva += len(encoded) + 16
    marker_rva = 0x2000
    for marker in utf16_markers:
        encoded = marker.encode("utf-16-le") + b"\x00\x00"
        image[marker_rva : marker_rva + len(encoded)] = encoded
        rvas[f"utf16:{marker}"] = marker_rva
        marker_rva += len(encoded) + 16
    return bytes(image), rvas


class FakeEngineRuntimeBackend:
    """Deterministic unit-test backend; it is not a production E2E fixture."""

    name = "fake_engine_runtime"
    available = True
    unavailable_reason = None

    def __init__(self, *, pid: int = 4242) -> None:
        self.pid = pid
        self.calls: list[tuple[Any, ...]] = []
        unity_image, self.unity_rvas = _pe_image(
            "GameAssembly.dll",
            ["il2cpp_init", "il2cpp_domain_get"],
            ascii_markers=("global-metadata.dat",),
            utf16_markers=("UnityEngine.CoreModule",),
        )
        unreal_image, self.unreal_rvas = _pe_image(
            "UnrealEditor-Core.dll",
            ["ProcessEvent", "StaticFindObject"],
            ascii_markers=("FNamePool", "/Script/Engine"),
            utf16_markers=("GUObjectArray",),
        )
        self.modules: list[dict[str, Any]] = [
            {
                "name": "GameAssembly.dll",
                "path": "C:/fixtures/Unity/GameAssembly.dll",
                "base_address": 0x180000000,
                "size": len(unity_image),
                "data": unity_image,
            },
            {
                "name": "UnrealEditor-Core.dll",
                "path": "C:/fixtures/Unreal/UnrealEditor-Core.dll",
                "base_address": 0x7FF700000000,
                "size": len(unreal_image),
                "data": unreal_image,
            },
        ]

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        accessible = pid == self.pid
        return {
            "pid": pid,
            "exists": accessible,
            "accessible": accessible,
            "status": "ok" if accessible else "unavailable",
            "image_path": "C:/fixtures/Game.exe" if accessible else None,
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

    def _require_pid(self, pid: int) -> None:
        if pid != self.pid:
            raise RuntimeError(f"unexpected pid: {pid}")


class EngineRuntimeProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeEngineRuntimeBackend()
        self.provider = EngineRuntimeProvider(
            self.backend,
            platform_name="win32",
            max_total_read_bytes=64 * 1024,
            max_module_read_bytes=32 * 1024,
            max_single_read_bytes=4096,
            max_modules=8,
            max_evidence=64,
            max_export_names=32,
        )

    def _request(self, **params: Any) -> CapabilityRequest:
        defaults = {
            "scan_all_modules": True,
            "include_exports": True,
            "include_utf16": True,
        }
        defaults.update(params)
        return CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=TargetIdentity(
                kind="process",
                pid=self.backend.pid,
                display_name="fixture-process",
            ),
            params=defaults,
            session_id="engine-runtime-test",
            provenance={"request_source": "unit-test"},
        )

    def test_fake_backend_contract_extracts_engine_evidence_and_addresses(self) -> None:
        plan = self.provider.plan(self._request())
        validation = self.provider.validate(plan)
        result = self.provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok")
        operation = result.report_section["operation"]
        identities = operation["module_identities"]
        self.assertEqual([item["name"] for item in identities], [
            "GameAssembly.dll",
            "UnrealEditor-Core.dll",
        ])
        self.assertTrue(all(item["identity_sha256"] for item in identities))
        self.assertEqual(operation["detected_engines"], [
            "unity_il2cpp",
            "unreal",
        ])

        evidence = operation["evidence"]
        symbols = {item.get("symbol"): item for item in evidence if item["kind"] == "symbol"}
        self.assertEqual(symbols["il2cpp_init"]["rva"], self.backend.unity_rvas["il2cpp_init"])
        self.assertEqual(
            symbols["il2cpp_init"]["address"],
            self.backend.modules[0]["base_address"] + self.backend.unity_rvas["il2cpp_init"],
        )
        self.assertEqual(symbols["ProcessEvent"]["rva_hex"], "0x1000")
        strings = {
            (item["marker"], item["details"]["encoding"]): item
            for item in evidence
            if item["kind"] == "candidate_string"
        }
        metadata = strings[("global-metadata.dat", "ascii")]
        self.assertEqual(metadata["rva"], self.backend.unity_rvas["ascii:global-metadata.dat"])
        self.assertEqual(metadata["address_hex"], hex(metadata["address"]))
        self.assertIn(("GUObjectArray", "utf-16-le"), strings)
        self.assertTrue(all("rva" in item and "address" in item for item in evidence))

    def test_provider_ceilings_bound_every_fake_backend_read(self) -> None:
        provider = EngineRuntimeProvider(
            self.backend,
            platform_name="win32",
            max_total_read_bytes=768,
            max_module_read_bytes=512,
            max_single_read_bytes=64,
            max_modules=2,
            max_evidence=8,
            max_export_names=4,
        )
        request = self._request(
            max_total_read_bytes=999999,
            max_module_read_bytes=999999,
            max_single_read_bytes=999999,
            max_modules=999,
            max_evidence=999,
            max_export_names=999,
        )
        plan = provider.plan(request)
        self.assertEqual(plan.parameters["max_total_read_bytes"], 768)
        self.assertEqual(plan.parameters["max_module_read_bytes"], 512)
        self.assertEqual(plan.parameters["max_single_read_bytes"], 64)
        self.assertTrue(plan.parameters["limit_clamps"])

        result = provider.execute(plan)
        self.assertEqual(result.status, "ok")
        usage = result.report_section["operation"]["read_usage"]
        self.assertLessEqual(usage["requested_bytes"], 768)
        self.assertLessEqual(usage["max_observed_request"], 64)
        self.assertTrue(usage["truncated"])
        self.assertTrue(
            all(value <= 512 for value in usage["module_requested_bytes"].values())
        )
        read_calls = [call for call in self.backend.calls if call[0] == "read_process_memory"]
        self.assertTrue(read_calls)
        self.assertTrue(all(call[3] <= 64 for call in read_calls))

    def test_precondition_drift_blocks_execution_before_memory_reads(self) -> None:
        plan = self.provider.plan(self._request())
        self.backend.modules[0]["base_address"] += 0x10000
        validation = self.provider.validate(plan)
        reads_before = sum(
            call[0] == "read_process_memory" for call in self.backend.calls
        )
        result = self.provider.execute(plan)
        reads_after = sum(
            call[0] == "read_process_memory" for call in self.backend.calls
        )

        self.assertFalse(validation.ok)
        precondition = next(
            check for check in validation.checks if check["name"] == "precondition_hash"
        )
        self.assertEqual(precondition["status"], "failed")
        self.assertEqual(result.status, "failed")
        self.assertEqual(reads_before, reads_after)
        self.assertEqual(result.report_section["operation"]["status"], "blocked")

    def test_unavailable_backend_is_structured_and_side_effect_free(self) -> None:
        reason = "Win32 APIs intentionally unavailable in this test"
        provider = EngineRuntimeProvider(
            UnavailableEngineRuntimeBackend(reason),
            platform_name="linux",
        )
        request = CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=TargetIdentity(kind="process", pid=3333),
            session_id="engine-runtime-unavailable",
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok)
        self.assertTrue(validation.warnings)
        self.assertEqual(result.status, "unavailable")
        self.assertIn(reason, result.report_section["operation"]["reason"])
        self.assertEqual(
            result.report_section["operation"]["read_usage"]["requested_bytes"], 0
        )
        self.assertTrue(result.report_section["read_only"])
        self.assertFalse(result.report_section["side_effects"])

    def test_audit_artifact_manifest_trace_and_read_only_rollback(self) -> None:
        plan = self.provider.plan(self._request())
        result = self.provider.execute(plan)
        rollback = self.provider.rollback(result)

        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "not_required")
        self.assertEqual(result.rollback_plan["rollback_status"], "not_required")
        self.assertEqual(result.before_snapshot["precondition_hash"], plan.precondition_hash)
        self.assertEqual(result.provenance["precondition_hash"], plan.precondition_hash)
        self.assertIn("plan", result.provenance)
        self.assertIn("validation", result.provenance)
        self.assertEqual(result.dashboard_trace[0]["kind"], "engine_runtime_execution")
        self.assertEqual(result.dashboard_trace[-1]["kind"], "engine_runtime_rollback")

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle = self.provider.collect_artifacts(result, temp_dir)
            self.assertEqual(len(bundle.artifacts), 1)
            self.assertEqual(len(bundle.manifest_entries), 1)
            artifact = bundle.artifacts[0]
            destination = Path(temp_dir) / artifact.path
            payload = json.loads(destination.read_text(encoding="utf-8"))
            encoded = destination.read_bytes()
            digest = hashlib.sha256(encoded).hexdigest()

            self.assertEqual(artifact.metadata["sha256"], digest)
            self.assertEqual(bundle.manifest_entries[0]["sha256"], digest)
            self.assertEqual(bundle.manifest_entries[0]["role"], "engine-runtime-evidence")
            self.assertEqual(payload["before"]["precondition_hash"], plan.precondition_hash)
            self.assertEqual(payload["rollback"]["rollback_status"], "not_required")
            self.assertEqual(payload["report"]["operation"]["status"], "ok")
            self.assertEqual(payload["dashboard_trace"][-1]["status"], "not_required")

    def test_collect_artifacts_rejects_path_escape(self) -> None:
        result = self.provider.execute(self.provider.plan(self._request()))
        result.artifacts[0].path = "../outside.json"
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "inside|escapes"):
                self.provider.collect_artifacts(result, temp_dir)

    def test_fake_backend_never_materializes_live_acceptance_proof(self) -> None:
        self.assertIs(type(self.provider.backend), FakeEngineRuntimeBackend)
        result = self.provider.execute(self.provider.plan(self._request()))
        with tempfile.TemporaryDirectory() as temp_dir:
            self.provider.collect_artifacts(result, temp_dir)
            self.assertFalse(
                (Path(temp_dir) / "engine" / "execution-proof.json").exists()
            )


class EngineRuntimeAcceptanceGateTests(unittest.TestCase):
    def test_live_gate_requires_explicit_acceptance_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            environment = {
                "RUN_ENGINE_RUNTIME_WINDOWS_SMOKE": "1",
                "REVERSE_ANALYZER_UNITY_MONO_FIXTURE": str(
                    Path(temp_dir) / "fixture.exe"
                ),
            }
            with patch.object(sys, "platform", "win32"), patch.dict(
                os.environ, environment, clear=True
            ):
                self.assertFalse(
                    live_engine_fixture_enabled(
                        "REVERSE_ANALYZER_UNITY_MONO_FIXTURE"
                    )
                )
                os.environ["REVERSE_ANALYZER_ACCEPTANCE_DIR"] = temp_dir
                self.assertTrue(
                    live_engine_fixture_enabled(
                        "REVERSE_ANALYZER_UNITY_MONO_FIXTURE"
                    )
                )

    def test_acceptance_root_binds_registered_fixture_and_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            authorized = Path(temp_dir).resolve()
            run_root = (
                authorized
                / "acceptance"
                / "runs"
                / "p3-unity-mono-live"
                / "session-1"
            )
            run_root.mkdir(parents=True)
            environment = {
                "REVERSE_ANALYZER_ACCEPTANCE_DIR": str(authorized),
                "REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR": str(run_root),
                "REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID": "session-1",
            }
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(_acceptance_root("p3-unity-mono-live"), run_root)
                with self.assertRaisesRegex(AssertionError, "fixture id"):
                    _acceptance_root("p3-unity-il2cpp-live")


@unittest.skipUnless(
    sys.platform == "win32"
    and os.environ.get("RUN_ENGINE_RUNTIME_WINDOWS_SMOKE") == "1",
    "requires Windows and RUN_ENGINE_RUNTIME_WINDOWS_SMOKE=1",
)
class EngineRuntimeWindowsSmokeTests(unittest.TestCase):
    def test_opt_in_real_child_process_module_enumeration_and_bounded_read(self) -> None:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import time; print('ready', flush=True); time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            self.assertEqual(child.stdout.readline().strip(), "ready")
            backend = WindowsEngineRuntimeBackend(max_single_read_bytes=4096)
            self.assertTrue(backend.available, backend.unavailable_reason)
            provider = EngineRuntimeProvider(
                backend,
                platform_name="win32",
                max_total_read_bytes=64 * 1024,
                max_module_read_bytes=64 * 1024,
                max_single_read_bytes=4096,
                max_modules=1,
                max_evidence=16,
                max_export_names=16,
            )
            request = CapabilityRequest(
                capability="engine_runtime",
                action="analyze",
                target=TargetIdentity(kind="process", pid=child.pid),
                params={"max_modules": 1},
                session_id="engine-runtime-windows-smoke",
            )
            plan = provider.plan(request)
            result = provider.execute(plan)

            self.assertEqual(result.status, "ok")
            operation = result.report_section["operation"]
            self.assertGreater(operation["module_count"], 0)
            self.assertGreater(operation["selected_module_count"], 0)
            usage = operation["read_usage"]
            self.assertGreater(usage["returned_bytes"], 0)
            self.assertLessEqual(usage["requested_bytes"], 64 * 1024)
            self.assertLessEqual(usage["max_observed_request"], 4096)
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()
            if child.stderr is not None:
                child.stderr.close()


if __name__ == "__main__":
    unittest.main()
