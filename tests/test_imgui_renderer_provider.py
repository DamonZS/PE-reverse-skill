from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

import reverse_analyzer.providers.imgui_renderer as imgui_renderer_module
from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.imgui_renderer import (
    EXPECTED_PLUGIN_EXPORTS,
    IMGUI_HOST_LIFECYCLE,
    REQUIRED_IMGUI_FILES,
    ImGuiHostOrchestrator,
    ImGuiPathBoundaryError,
    ImGuiRendererProvider,
    RendererPluginValidationError,
    inspect_renderer_plugin_bytes,
)
from reverse_analyzer.providers.graphics_runtime import LocalJsonBridgeAdapter
from tests._graphics_acceptance import (
    acceptance_context,
    assert_non_synthetic,
    load_json,
    required_pid,
    target_identity as acceptance_target_identity,
    write_bundle,
)


_UNSET = object()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _create_imgui_checkout(root: Path, *, missing: set[str] | None = None) -> Path:
    missing = missing or set()
    markers = {
        "LICENSE.txt": b"MIT License\n",
        "imgui.h": b"#define IMGUI_VERSION \"fixture\"\n",
        "imgui.cpp": b"// Dear ImGui\n",
        "backends/imgui_impl_win32.cpp": b"// ImGui_ImplWin32_Init\n",
        "backends/imgui_impl_dx11.cpp": b"// ImGui_ImplDX11_Init\n",
    }
    for relative in REQUIRED_IMGUI_FILES:
        if relative in missing:
            continue
        destination = root / Path(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(markers.get(relative, f"// {relative}\n".encode("ascii")))
    return root


def _present_resolution(
    *,
    architecture: str = "x64",
    module_path: Path | None = None,
) -> dict[str, Any]:
    pointer_size = 4 if architecture == "x86" else 8
    method_address = 0x10001000 if architecture == "x86" else 0x180001000
    vtable_address = 0x50000000
    source: dict[str, Any] = {
        "kind": "vtable_snapshot",
        "architecture": architecture,
        "pointer_size": pointer_size,
        "vtable_address": vtable_address,
        "vtable_index": 8,
        "interface": "IDXGISwapChain",
    }
    if module_path is not None:
        source.update(
            {
                "module_path": str(module_path.resolve()),
                "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
                "module_base": 0x180000000 if architecture == "x64" else 0x10000000,
            }
        )
    return {
        "schema_version": 1,
        "status": "ok",
        "method": "vtable_slot",
        "target": "dxgi_present",
        "api": "direct3d",
        "module": "dxgi.dll",
        "symbol": "Present",
        "address": method_address,
        "slot_address": vtable_address + 8 * pointer_size,
        "source": source,
        "executable_range": {
            "status": "ok",
            "executable": True,
            "range_start": method_address,
            "range_end": method_address + 0x1000,
            "address": method_address,
            "size": 1,
        },
        "confidence": 0.98,
        "ambiguity": {"candidate_count": 1, "ambiguous": False},
        "errors": [],
        "warnings": [],
    }


def _minimal_dll_pe(architecture: str) -> bytes:
    if architecture == "x86":
        machine, magic, optional_size = 0x014C, 0x10B, 0xE0
    else:
        machine, magic, optional_size = 0x8664, 0x20B, 0xF0
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        machine,
        1,
        0,
        0,
        0,
        optional_size,
        0x2102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, magic)
    struct.pack_into("<I", data, optional + 60, 0x200)
    directory_count_offset = 92 if architecture == "x86" else 108
    struct.pack_into("<I", data, optional + directory_count_offset, 0)
    section = optional + optional_size
    data[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    return bytes(data)


class _SuccessfulTestDouble:
    name = "successful-test-double"
    test_double = True

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def build(
        self,
        project_dir: Path,
        *,
        build_dir: Path,
        architecture: str,
        imgui_root: Path,
        timeout_seconds: int,
    ) -> Mapping[str, Any]:
        self.calls.append(
            {
                "project_files": sorted(
                    path.relative_to(project_dir).as_posix()
                    for path in project_dir.rglob("*")
                    if path.is_file()
                ),
                "build_dir": str(build_dir),
                "architecture": architecture,
                "imgui_root": str(imgui_root),
                "timeout_seconds": timeout_seconds,
            }
        )
        return {"status": "ok", "claimed_plugin_sha256": "0" * 64}


class _UnmarkedRunner:
    name = "unmarked-runner"
    test_double = False

    def __init__(self) -> None:
        self.calls = 0

    def build(self, *_: Any, **__: Any) -> Mapping[str, Any]:
        self.calls += 1
        return {"status": "ok"}


class _FailingTestDouble(_SuccessfulTestDouble):
    name = "failing-test-double"

    def build(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
        super().build(*args, **kwargs)
        return {"status": "failed", "error": "fixture build failure"}


class ImGuiRendererProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.checkout = _create_imgui_checkout(self.root / "imgui")
        self.dxgi = self.root / "dxgi.dll"
        self.dxgi.write_bytes(b"audited dxgi module fixture")
        self.missing_cmake = self.root / "missing-tools" / "cmake.exe"
        self.missing_cxx = self.root / "missing-tools" / "g++.exe"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _provider(self, runner: Any = None) -> ImGuiRendererProvider:
        return ImGuiRendererProvider(
            build_runner=runner,
            cmake_path=self.missing_cmake,
            cxx_compiler=self.missing_cxx,
            platform_name="win32",
        )

    def _request(
        self,
        *,
        action: str = "generate",
        architecture: str = "x64",
        imgui_root: Any = _UNSET,
        resolution: Any = _UNSET,
        target: TargetIdentity | None = None,
        session_id: str = "imgui/test-session",
        extra: Mapping[str, Any] | None = None,
    ) -> CapabilityRequest:
        params: dict[str, Any] = {
            "architecture": architecture,
            "backend": "d3d11",
            "install_wndproc": True,
            "input_capture": True,
        }
        if imgui_root is _UNSET:
            params["imgui_root"] = str(self.checkout)
        elif imgui_root is not None:
            params["imgui_root"] = str(imgui_root)
        if resolution is _UNSET:
            params["hook_target_resolution"] = _present_resolution(
                architecture=architecture,
                module_path=self.dxgi,
            )
        elif resolution is not None:
            params["hook_target_resolution"] = resolution
        params.update(dict(extra or {}))
        return CapabilityRequest(
            capability="imgui_renderer_runtime",
            action=action,
            target=target
            or TargetIdentity(
                kind="process",
                pid=4242,
                display_name="fixture.exe",
                metadata={"architecture": architecture},
            ),
            params=params,
            session_id=session_id,
            provenance={"source": "test_imgui_renderer_provider"},
        )

    @staticmethod
    def _checks(validation: Any) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in validation.checks}

    @staticmethod
    def _artifact_bytes(
        collection_root: Path,
        bundle: Any,
        kind: str,
    ) -> bytes:
        artifact = next(item for item in bundle.artifacts if item.kind == kind)
        return (collection_root / artifact.path).read_bytes()

    def test_generated_project_encodes_complete_d3d11_lifecycle_and_audit_links(self) -> None:
        provider = self._provider()
        request = self._request()

        self.assertTrue(provider.supports(request))
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.to_dict())
        self.assertEqual(result.status, "ok", result.report_section)
        resolution_hash = _canonical_sha256(request.params["hook_target_resolution"])
        self.assertEqual(plan.parameters["hook_target_resolution_hash"], resolution_hash)
        self.assertEqual(plan.provenance["hook_target_resolution_hash"], resolution_hash)
        self.assertEqual(plan.before_snapshot["plugin_sha256"], None)
        self.assertFalse(plan.before_snapshot["hook_write_performed"])
        self.assertFalse(plan.before_snapshot["injection_performed"])
        self.assertEqual(plan.rollback_plan["hook_rollback_owner"], "host_hook_provider")
        self.assertRegex(plan.precondition_hash or "", r"^[0-9a-f]{64}$")

        collection_root = self.root / "generated"
        bundle = provider.collect_artifacts(result, str(collection_root))
        source = self._artifact_bytes(
            collection_root, bundle, "imgui-renderer-source"
        ).decode("ascii")
        header = self._artifact_bytes(
            collection_root, bundle, "imgui-renderer-c-abi"
        ).decode("ascii")
        definition = self._artifact_bytes(
            collection_root, bundle, "imgui-renderer-definition"
        ).decode("ascii")
        cmake = self._artifact_bytes(
            collection_root, bundle, "imgui-renderer-cmake"
        ).decode("ascii")
        binding = self._artifact_bytes(
            collection_root, bundle, "imgui-renderer-build-binding"
        ).decode("ascii")
        metadata = json.loads(
            self._artifact_bytes(
                collection_root, bundle, "imgui-renderer-metadata"
            )
        )

        dll_main = re.search(
            r"BOOL WINAPI DllMain\(.*?\n\}", source, flags=re.DOTALL
        )
        self.assertIsNotNone(dll_main)
        self.assertIn("DisableThreadLibraryCalls(instance)", dll_main.group(0))
        for forbidden in (
            "CreateThread",
            "ImGui::",
            "RAImGuiRenderer_Initialize",
            "SetWindowLongPtrW",
            "VirtualProtect",
            "WriteProcessMemory",
        ):
            self.assertNotIn(forbidden, dll_main.group(0))

        for export in EXPECTED_PLUGIN_EXPORTS:
            self.assertIn(export, header)
            self.assertIn(export, definition)
        self.assertIn('extern "C" BOOL RAImGuiRenderer_Initialize', source)
        self.assertIn("ID3D11Device* device", header)
        self.assertIn("ID3D11DeviceContext* context", header)
        self.assertIn("IMGUI_CHECKVERSION()", source)
        self.assertIn("ImGui::CreateContext()", source)
        self.assertIn("ImGui_ImplWin32_Init(hwnd)", source)
        self.assertIn("ImGui_ImplDX11_Init(device, context)", source)
        self.assertIn("g_renderer.device->AddRef()", source)
        self.assertIn("g_renderer.context->AddRef()", source)
        self.assertIn("value->Release()", source)
        self.assertIn("std::recursive_mutex mutex", source)
        self.assertIn("thread_local char error_snapshot[512]", source)
        self.assertIn("void SetErrorLocked(const char* message) noexcept", source)
        self.assertIn("new (std::nothrow) D3D11RendererBackend()", source)
        self.assertNotIn("std::make_unique", source)
        self.assertIn("ImGui_ImplDX11_InvalidateDeviceObjects()", source)
        self.assertIn("ImGui_ImplDX11_CreateDeviceObjects()", source)
        self.assertIn("CancelFrameLocked()", source)
        self.assertIn("RA_IMGUI_STATE_DEVICE_LOST", source)
        self.assertIn("RA_IMGUI_STATE_SHUTDOWN_PENDING", source)
        self.assertIn("SetWindowLongPtrW", source)
        self.assertIn("CallWindowProcW", source)
        self.assertIn("hwnd != g_renderer.hwnd", source)
        self.assertIn(
            "WNDPROC original = nullptr;\n    {\n"
            "        std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);",
            source,
        )
        self.assertIn("    }\n    return original != nullptr", source)
        self.assertIn("GetWindowThreadProcessId", source)
        self.assertIn("DeviceAndContextMatchLocked", source)
        self.assertIn("ImGui WndProc is followed by another subclass", source)
        self.assertIn("ImGui_ImplWin32_Shutdown()", source)
        self.assertIn("ImGui::DestroyContext", source)

        new_frame = re.search(
            r'extern "C" BOOL RAImGuiRenderer_NewFrame.*?^\}',
            source,
            flags=re.DOTALL | re.MULTILINE,
        )
        render = re.search(
            r'extern "C" BOOL RAImGuiRenderer_RenderDrawData.*?^\}',
            source,
            flags=re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(new_frame)
        self.assertIsNotNone(render)
        self.assertLess(
            new_frame.group(0).index("g_renderer.backend->NewFrame()"),
            new_frame.group(0).index("ImGui_ImplWin32_NewFrame()"),
        )
        self.assertLess(
            new_frame.group(0).index("ImGui_ImplWin32_NewFrame()"),
            new_frame.group(0).index("ImGui::NewFrame()"),
        )
        self.assertLess(
            render.group(0).index("ImGui::Render()"),
            render.group(0).index("g_renderer.backend->Render(ImGui::GetDrawData())"),
        )
        for forbidden in (
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "VirtualProtectEx",
            "MinHook",
            "DetourAttach",
        ):
            self.assertNotIn(forbidden, source)

        self.assertIn("class RendererBackend", source)
        self.assertIn("class D3D11RendererBackend", source)
        self.assertIn("struct RendererBackendInitialization", source)
        self.assertIn("virtual RAImGuiGraphicsApi GraphicsApi() const", source)
        self.assertIn("RA_IMGUI_API_D3D12", header)
        self.assertIn("RA_IMGUI_API_OPENGL3", header)
        self.assertIn("RA_IMGUI_API_VULKAN", header)
        self.assertIn("The production renderer build requires MinGW", cmake)
        self.assertIn("CMAKE_SIZEOF_VOID_P", cmake)
        self.assertIn("IMGUI_ROOT", cmake)
        self.assertIn("d3dcompiler", cmake)
        self.assertIn("-static-libstdc++", cmake)
        for required_source in REQUIRED_IMGUI_FILES:
            self.assertIn(required_source, cmake)
        self.assertIn(plan.parameters["target_identity_hash"], binding)
        self.assertIn(resolution_hash, binding)
        self.assertIn(plan.precondition_hash, binding)

        self.assertEqual(metadata["status"], "ok")
        self.assertEqual(metadata["hook_target_resolution_hash"], resolution_hash)
        self.assertEqual(metadata["precondition_hash"], plan.precondition_hash)
        self.assertFalse(metadata["host_responsibilities"]["plugin_writes_hooks"])
        self.assertFalse(metadata["host_responsibilities"]["provider_injects"])
        self.assertTrue(
            metadata["host_responsibilities"]["quiesce_renderer_calls_before_unload"]
        )
        self.assertEqual(metadata["extension_backends"], ["d3d12", "opengl3", "vulkan"])
        self.assertIsNone(result.provenance["plugin_sha256"])
        checks = self._checks(validation)
        self.assertEqual(checks["official_imgui_sources"]["status"], "ok")
        self.assertNotIn(
            "official",
            checks["official_imgui_sources"]["message"].casefold(),
        )
        self.assertEqual(checks["official_imgui_origin"]["status"], "warning")
        self.assertFalse(plan.parameters["imgui_checkout"]["official_origin_attested"])

        for artifact in bundle.artifacts:
            destination = collection_root / artifact.path
            self.assertTrue(destination.is_file())
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            self.assertEqual(artifact.metadata["sha256"], digest)
            self.assertTrue(artifact.metadata["materialized"])
        manifest = json.loads(
            self._artifact_bytes(
                collection_root, bundle, "imgui-renderer-manifest"
            )
        )
        self.assertEqual(manifest["hook_target_resolution_hash"], resolution_hash)
        self.assertEqual(manifest["precondition_hash"], plan.precondition_hash)
        self.assertIsNone(manifest["plugin_sha256"])
        self.assertTrue(all(item["materialized"] for item in manifest["artifacts"]))

        audit = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(audit)
        self.assertTrue(contract.ok, contract.errors)

    def test_missing_or_incomplete_imgui_checkout_is_dependency_gated(self) -> None:
        runner = _SuccessfulTestDouble()
        provider = self._provider(runner)
        missing_root = self.root / "not-provided"
        plan = provider.plan(
            self._request(action="build", imgui_root=missing_root)
        )
        validation = provider.validate(plan)
        result = provider.execute(plan)

        checks = self._checks(validation)
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(checks["official_imgui_sources"]["status"], "unavailable")
        self.assertEqual(result.status, "unavailable")
        self.assertTrue(result.after_snapshot["project_generated"])
        self.assertTrue(result.report_section["build"]["dependency_gated"])
        self.assertEqual(runner.calls, [])
        self.assertFalse(
            any(item.kind == "imgui-renderer-plugin" for item in result.artifacts)
        )

        incomplete = _create_imgui_checkout(
            self.root / "incomplete-imgui",
            missing={"imgui_widgets.cpp"},
        )
        second = self._provider().plan(self._request(imgui_root=incomplete))
        second_validation = self._provider().validate(second)
        self.assertTrue(second_validation.ok, second_validation.errors)
        self.assertEqual(
            self._checks(second_validation)["official_imgui_sources"]["status"],
            "unavailable",
        )
        self.assertIn(
            "imgui_widgets.cpp",
            self._checks(second_validation)["official_imgui_sources"]["message"],
        )

    def test_internal_build_requires_attested_upstream_git_origin(self) -> None:
        provider = self._provider()
        plan = provider.plan(self._request(action="build"))
        validation = provider.validate(plan)
        result = provider.execute(plan)

        origin = self._checks(validation)["official_imgui_origin"]
        self.assertEqual(origin["status"], "unavailable")
        self.assertTrue(origin["required_for_production_build"])
        self.assertEqual(result.status, "unavailable")
        self.assertTrue(result.report_section["build"]["dependency_gated"])
        self.assertFalse(result.report_section["build"]["production"])

    def test_non_official_markers_and_changed_source_hash_fail_closed(self) -> None:
        corrupt = _create_imgui_checkout(self.root / "corrupt-imgui")
        (corrupt / "imgui.h").write_text("// no version marker\n", encoding="ascii")
        provider = self._provider()
        corrupt_plan = provider.plan(self._request(imgui_root=corrupt))
        corrupt_validation = provider.validate(corrupt_plan)
        self.assertFalse(corrupt_validation.ok)
        self.assertEqual(
            self._checks(corrupt_validation)["official_imgui_sources"]["status"],
            "failed",
        )
        self.assertEqual(provider.execute(corrupt_plan).status, "failed")

        clean_plan = provider.plan(self._request())
        with (self.checkout / "imgui.cpp").open("ab") as handle:
            handle.write(b"// changed after planning\n")
        changed_validation = provider.validate(clean_plan)
        self.assertFalse(changed_validation.ok)
        self.assertIn(
            "changed after planning",
            self._checks(changed_validation)["official_imgui_sources"]["message"],
        )

    def test_standard_present_resolution_is_strict_and_revalidated(self) -> None:
        provider = self._provider()
        valid_plan = provider.plan(self._request())
        self.assertTrue(provider.validate(valid_plan).ok)

        cases: list[tuple[str, dict[str, Any], str]] = []
        wrong_module = _present_resolution(module_path=self.dxgi)
        wrong_module["module"] = "d3d11.dll"
        cases.append(("module", wrong_module, "dxgi.dll"))
        wrong_slot = _present_resolution(module_path=self.dxgi)
        wrong_slot["source"]["vtable_index"] = 9
        cases.append(("slot", wrong_slot, "slot 8"))
        ambiguous = _present_resolution(module_path=self.dxgi)
        ambiguous["ambiguity"] = {"candidate_count": 2, "ambiguous": True}
        cases.append(("ambiguity", ambiguous, "ambiguous"))
        wrong_schema = _present_resolution(module_path=self.dxgi)
        wrong_schema["schema_version"] = 2
        cases.append(("schema", wrong_schema, "schema_version"))
        missing_target = _present_resolution(module_path=self.dxgi)
        missing_target.pop("target")
        cases.append(("target", missing_target, "dxgi_present"))
        missing_interface = _present_resolution(module_path=self.dxgi)
        missing_interface["source"].pop("interface")
        cases.append(("interface", missing_interface, "IDXGISwapChain"))
        invalid_range = _present_resolution(module_path=self.dxgi)
        invalid_range["executable_range"]["size"] = 0
        cases.append(("range-size", invalid_range, "executable_range.size"))
        invalid_confidence = _present_resolution(module_path=self.dxgi)
        invalid_confidence["confidence"] = float("nan")
        cases.append(("confidence", invalid_confidence, "confidence"))
        for label, resolution, expected in cases:
            with self.subTest(label=label):
                plan = provider.plan(self._request(resolution=resolution))
                validation = provider.validate(plan)
                self.assertFalse(validation.ok)
                self.assertIn(expected, "; ".join(validation.errors))
                self.assertEqual(provider.execute(plan).status, "failed")

        module_bound_plan = provider.plan(self._request())
        self.dxgi.write_bytes(b"changed module after resolution")
        changed = provider.validate(module_bound_plan)
        self.assertFalse(changed.ok)
        self.assertIn("SHA-256 no longer matches", "; ".join(changed.errors))

    def test_path_resolution_artifact_binds_raw_and_canonical_hashes(self) -> None:
        resolution = _present_resolution(module_path=self.dxgi)
        canonical_hash = _canonical_sha256(resolution)
        artifact_path = self.root / "present-resolution.json"
        artifact_path.write_text(
            json.dumps(
                {"resolution": resolution, "resolution_hash": canonical_hash},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        provider = self._provider()
        request = self._request(
            resolution=None,
            extra={
                "hook_target_resolution_path": str(artifact_path),
                "hook_target_resolution_sha256": artifact_hash,
                "resolution_hash": canonical_hash,
            },
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)

        self.assertTrue(validation.ok, validation.to_dict())
        self.assertEqual(plan.parameters["hook_target_resolution_hash"], canonical_hash)
        self.assertEqual(
            plan.parameters["hook_target_resolution_artifact_sha256"],
            artifact_hash,
        )
        self.assertEqual(
            plan.parameters["hook_target_resolution_source"],
            str(artifact_path.resolve()),
        )
        self.assertEqual(
            self._checks(validation)["present_target_artifact"]["status"],
            "ok",
        )
        result = provider.execute(plan)
        self.assertEqual(result.status, "ok", result.report_section)
        self.assertEqual(
            result.provenance["hook_target_resolution_artifact_sha256"],
            artifact_hash,
        )

        artifact_path.write_text(
            json.dumps(
                {"resolution": resolution, "resolution_hash": canonical_hash},
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        changed = provider.validate(plan)
        self.assertFalse(changed.ok)
        self.assertIn("changed after planning", "; ".join(changed.errors))
        self.assertEqual(provider.execute(plan).status, "failed")
        with self.assertRaisesRegex(ValueError, "evidence changed before collection"):
            provider.collect_artifacts(result, str(self.root / "changed-evidence"))

    def test_path_resolution_rejects_bad_hash_relative_path_and_duplicate_keys(self) -> None:
        resolution = _present_resolution(module_path=self.dxgi)
        artifact_path = self.root / "resolution.json"
        artifact_path.write_text(json.dumps(resolution), encoding="utf-8")
        provider = self._provider()

        bad_hash_plan = provider.plan(
            self._request(
                resolution=None,
                extra={
                    "hook_target_resolution_path": str(artifact_path),
                    "hook_target_resolution_sha256": "0" * 64,
                },
            )
        )
        self.assertFalse(provider.validate(bad_hash_plan).ok)
        self.assertIn(
            "artifact SHA-256 does not match",
            "; ".join(bad_hash_plan.parameters["parameter_errors"]),
        )

        relative_plan = provider.plan(
            self._request(
                resolution=None,
                extra={"hook_target_resolution_path": "relative/resolution.json"},
            )
        )
        self.assertFalse(provider.validate(relative_plan).ok)
        self.assertIn(
            "must be absolute",
            "; ".join(relative_plan.parameters["parameter_errors"]),
        )

        duplicate_path = self.root / "duplicate-resolution.json"
        duplicate_path.write_text(
            '{"status":"ok","status":"failed"}',
            encoding="utf-8",
        )
        duplicate_plan = provider.plan(
            self._request(
                resolution=None,
                extra={"hook_target_resolution_path": str(duplicate_path)},
            )
        )
        self.assertFalse(provider.validate(duplicate_plan).ok)
        self.assertIn(
            "duplicate JSON key",
            "; ".join(duplicate_plan.parameters["parameter_errors"]),
        )

    def test_wrong_architectures_and_malformed_pe_are_rejected(self) -> None:
        provider = self._provider()
        wrong_resolution = _present_resolution(architecture="x86")
        plan = provider.plan(
            self._request(architecture="x64", resolution=wrong_resolution)
        )
        self.assertFalse(provider.validate(plan).ok)
        self.assertEqual(provider.execute(plan).status, "failed")

        target = TargetIdentity(
            kind="process",
            pid=4242,
            metadata={"architecture": "x86"},
        )
        target_plan = provider.plan(self._request(target=target))
        self.assertFalse(provider.validate(target_plan).ok)
        self.assertIn("conflicts", "; ".join(target_plan.parameters["parameter_errors"]))

        x86_target = self.root / "target-x86.exe"
        x86_target.write_bytes(_minimal_dll_pe("x86"))
        pe_target = TargetIdentity(
            kind="process",
            path=str(x86_target),
            pid=4242,
            metadata={"architecture": "x64"},
        )
        pe_plan = provider.plan(self._request(target=pe_target))
        self.assertFalse(provider.validate(pe_plan).ok)
        self.assertIn("architecture is x86", "; ".join(pe_plan.parameters["parameter_errors"]))

        with self.assertRaisesRegex(
            RendererPluginValidationError,
            "architecture is x86; expected x64",
        ):
            inspect_renderer_plugin_bytes(
                _minimal_dll_pe("x86"),
                expected_architecture="x64",
            )
        with self.assertRaisesRegex(RendererPluginValidationError, "DOS/PE"):
            inspect_renderer_plugin_bytes(b"not-a-pe", expected_architecture="x64")

    def test_relative_inputs_and_artifact_escape_are_rejected_without_writes(self) -> None:
        provider = self._provider()
        relative_plan = provider.plan(self._request(imgui_root="relative/imgui"))
        relative_validation = provider.validate(relative_plan)
        self.assertFalse(relative_validation.ok)
        self.assertIn(
            "must be absolute",
            self._checks(relative_validation)["official_imgui_sources"]["message"],
        )

        result = provider.execute(provider.plan(self._request()))
        with self.assertRaisesRegex(ImGuiPathBoundaryError, "must be absolute"):
            provider.collect_artifacts(result, "relative-collection")
        escaped = self.root / "outside.cpp"
        source_artifact = next(
            item for item in result.artifacts if item.kind == "imgui-renderer-source"
        )
        source_artifact.path = "../outside.cpp"
        with self.assertRaises(ImGuiPathBoundaryError):
            provider.collect_artifacts(result, str(self.root / "escape-collection"))
        self.assertFalse(escaped.exists())
        self.assertEqual(
            list((self.root / "escape-collection").rglob("*")),
            [],
        )

    def test_generation_and_collected_artifacts_are_deterministic(self) -> None:
        first_provider = self._provider()
        second_provider = self._provider()
        request = self._request(session_id="deterministic/session")
        first_plan = first_provider.plan(request)
        second_plan = second_provider.plan(request)
        self.assertEqual(first_plan.precondition_hash, second_plan.precondition_hash)
        self.assertEqual(first_plan.to_dict(), second_plan.to_dict())

        first_result = first_provider.execute(first_plan)
        second_result = second_provider.execute(second_plan)
        self.assertEqual(first_result.status, "ok")
        self.assertEqual(second_result.status, "ok")
        self.assertEqual(
            first_result.provenance["project_hash"],
            second_result.provenance["project_hash"],
        )
        first_root = self.root / "deterministic-one"
        second_root = self.root / "deterministic-two"
        first_bundle = first_provider.collect_artifacts(first_result, str(first_root))
        second_bundle = second_provider.collect_artifacts(second_result, str(second_root))
        first_bytes = {
            artifact.path: (first_root / artifact.path).read_bytes()
            for artifact in first_bundle.artifacts
        }
        second_bytes = {
            artifact.path: (second_root / artifact.path).read_bytes()
            for artifact in second_bundle.artifacts
        }
        self.assertEqual(first_bytes, second_bytes)

        repeated_root = self.root / "deterministic-repeat"
        repeated_bundle = first_provider.collect_artifacts(first_result, str(repeated_root))
        repeated_bytes = {
            artifact.path: (repeated_root / artifact.path).read_bytes()
            for artifact in repeated_bundle.artifacts
        }
        self.assertEqual(first_bytes, repeated_bytes)

    def test_collection_rejects_execution_and_artifact_hash_tampering(self) -> None:
        artifact_provider = self._provider()
        artifact_result = artifact_provider.execute(
            artifact_provider.plan(self._request(session_id="artifact-tamper"))
        )
        source_artifact = next(
            item
            for item in artifact_result.artifacts
            if item.kind == "imgui-renderer-source"
        )
        source_artifact.metadata["sha256"] = "0" * 64
        artifact_root = self.root / "artifact-tamper-output"
        with self.assertRaisesRegex(ValueError, "artifact hash changed"):
            artifact_provider.collect_artifacts(artifact_result, str(artifact_root))
        self.assertEqual(list(artifact_root.rglob("*")), [])

        project_provider = self._provider()
        project_result = project_provider.execute(
            project_provider.plan(self._request(session_id="project-tamper"))
        )
        project_result.provenance["project_hash"] = "0" * 64
        project_root = self.root / "project-tamper-output"
        with self.assertRaisesRegex(ValueError, "execution bindings changed"):
            project_provider.collect_artifacts(project_result, str(project_root))
        self.assertEqual(list(project_root.rglob("*")), [])

    def test_ephemeral_build_paths_are_normalized_in_command_evidence(self) -> None:
        workspace = self.root / "ra-imgui-production-random-token"
        project = workspace / "project"
        build = workspace / "build"
        record = {
            "command": [
                "cmake.exe",
                "-S",
                str(project),
                "-B",
                str(build),
            ],
            "stdout": f"configured {project.as_posix()}",
            "stderr": f"workspace={workspace}",
            "returncode": 0,
        }
        normalized = imgui_renderer_module._normalize_ephemeral_build_record(
            record,
            workspace=workspace,
            project=project,
            build=build,
        )
        encoded = json.dumps(normalized, sort_keys=True)
        self.assertNotIn(str(workspace), encoded)
        self.assertNotIn(workspace.as_posix(), encoded)
        self.assertIn("<ephemeral-project>", encoded)
        self.assertIn("<ephemeral-build>", encoded)
        self.assertIn("<ephemeral-workspace>", encoded)

    def test_test_double_cannot_establish_production_success(self) -> None:
        runner = _SuccessfulTestDouble()
        provider = self._provider(runner)
        plan = provider.plan(self._request(action="build"))
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("src/ra_imgui_renderer.cpp", runner.calls[0]["project_files"])
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.report_section["build"]["production"])
        self.assertTrue(result.report_section["build"]["dependency_gated"])
        self.assertEqual(
            result.report_section["build"]["reported_outcome"]["status"],
            "ok",
        )
        self.assertIn(
            "cannot establish production success",
            "; ".join(result.report_section["errors"]),
        )
        self.assertIsNone(result.provenance["plugin_sha256"])
        self.assertFalse(
            any(item.kind == "imgui-renderer-plugin" for item in result.artifacts)
        )

        failing_provider = self._provider(_FailingTestDouble())
        failing_result = failing_provider.execute(
            failing_provider.plan(self._request(action="build"))
        )
        self.assertEqual(failing_result.status, "failed")
        self.assertFalse(failing_result.report_section["build"]["production"])

    def test_only_explicit_test_doubles_can_cross_the_runner_boundary(self) -> None:
        runner = _UnmarkedRunner()
        with self.assertRaisesRegex(ValueError, "test_double=True"):
            self._provider(runner)

        provider = self._provider()
        plan = provider.plan(self._request(action="build"))
        context_runner = _UnmarkedRunner()
        context = {"imgui_renderer_build_runner": context_runner}
        validation = provider.validate(plan, context=context)
        result = provider.execute(plan, context=context)
        self.assertFalse(validation.ok)
        self.assertEqual(
            self._checks(validation)["build_runner_policy"]["status"],
            "failed",
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(context_runner.calls, 0)

    def test_rollback_is_idempotent_and_never_claims_hook_restoration(self) -> None:
        provider = self._provider()
        result = provider.execute(provider.plan(self._request()))
        first = provider.rollback(result)
        second = provider.rollback(result)

        for rollback in (first, second):
            self.assertTrue(rollback.ok, rollback.details)
            self.assertFalse(rollback.restored)
            self.assertFalse(rollback.details["target_state_modified"])
            self.assertFalse(rollback.details["hook_write_performed"])
            self.assertFalse(rollback.details["injection_performed"])
            self.assertEqual(
                rollback.details["hook_rollback_owner"],
                "host_hook_provider",
            )
        self.assertEqual(first.details["status"], "already_completed")
        self.assertEqual(second.details["status"], "already_completed")
        self.assertEqual(
            first.details["host_must_call"],
            "RAImGuiRenderer_Shutdown before unloading the DLL",
        )

        collection_root = self.root / "rollback-audit"
        bundle = provider.collect_artifacts(result, str(collection_root))
        audit = json.loads(
            self._artifact_bytes(collection_root, bundle, "imgui-renderer-audit")
        )
        self.assertTrue(audit["rollback_plan"]["completed"])
        self.assertEqual(
            audit["report_section"]["rollback"]["status"],
            "already_completed",
        )
        self.assertEqual(
            audit["report_section"]["rollback"]["hook_rollback_owner"],
            "host_hook_provider",
        )

    def test_real_build_when_official_checkout_is_explicitly_available(self) -> None:
        configured = os.environ.get("DEAR_IMGUI_ROOT") or os.environ.get("IMGUI_ROOT")
        if not configured:
            self.skipTest("DEAR_IMGUI_ROOT/IMGUI_ROOT is not configured")
        checkout = Path(configured).expanduser().resolve()
        acceptance = acceptance_context("p4-imgui-d3d11-live")
        bridge_path = ""
        resolution_path: Path | None = None
        target: TargetIdentity | None = None
        resolution: dict[str, Any] | None = None
        if acceptance is not None:
            bridge_path = str(
                os.environ.get("REVERSE_ANALYZER_IMGUI_BRIDGE") or ""
            ).strip()
            if not bridge_path:
                self.skipTest("REVERSE_ANALYZER_IMGUI_BRIDGE is not configured")
            configured_resolution = str(
                os.environ.get("REVERSE_ANALYZER_IMGUI_PRESENT_RESOLUTION") or ""
            ).strip()
            if not configured_resolution:
                self.skipTest(
                    "REVERSE_ANALYZER_IMGUI_PRESENT_RESOLUTION is not configured"
                )
            resolution_path = Path(configured_resolution).expanduser().resolve()
            resolution_payload = load_json(resolution_path)
            nested_resolution = resolution_payload.get("resolution")
            resolution = dict(
                nested_resolution
                if isinstance(nested_resolution, Mapping)
                else resolution_payload
            )
            assert_non_synthetic(resolution)
            self.assertEqual(resolution.get("status"), "ok")
            self.assertIs(resolution.get("production_ready"), True)
            self.assertEqual(resolution.get("evidence_tier"), "live-production")
            self.assertEqual(resolution.get("target"), "dxgi_present")
            self.assertEqual(
                str(resolution.get("method") or "").casefold().replace("-", "_"),
                "vtable_slot",
            )
            resolution_source = dict(resolution.get("source") or {})
            self.assertEqual(
                str(resolution_source.get("interface") or "").casefold(),
                "idxgiswapchain",
            )
            self.assertEqual(resolution_source.get("vtable_index"), 8)
            identity = acceptance_target_identity(required_pid())
            architecture = str(resolution_source.get("architecture") or "x64")
            target = TargetIdentity(
                kind=str(identity["kind"]),
                pid=int(identity["pid"]),
                display_name=str(identity["display_name"]),
                metadata={"architecture": architecture},
            )

        provider = ImGuiRendererProvider(platform_name="win32")
        if acceptance is None:
            request = self._request(
                action="build",
                imgui_root=checkout,
                session_id="imgui-real-build",
            )
        else:
            assert resolution_path is not None
            assert target is not None
            request = self._request(
                action="build",
                architecture=str(target.metadata.get("architecture") or "x64"),
                imgui_root=checkout,
                resolution=None,
                target=target,
                session_id=acceptance.session_id,
                extra={"hook_target_resolution_path": str(resolution_path)},
            )
        plan = provider.plan(request)
        checkout_state = plan.parameters["imgui_checkout"]
        if checkout_state.get("status") != "ok":
            self.skipTest(str(checkout_state.get("reason") or "checkout is incomplete"))
        validation = provider.validate(plan)
        checks = self._checks(validation)
        unavailable = [
            checks[name]["message"]
            for name in (
                "official_imgui_origin",
                "cmake_dependency",
                "mingw_dependency",
                "mingw_make_dependency",
            )
            if checks[name]["status"] == "unavailable"
        ]
        result = provider.execute(plan)
        if unavailable:
            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(result.status, "unavailable")
            self.assertTrue(result.report_section["build"]["dependency_gated"])
            self.skipTest("; ".join(unavailable))

        self.assertTrue(validation.ok, validation.to_dict())
        self.assertEqual(result.status, "ok", result.report_section)
        self.assertTrue(result.report_section["build"]["production"])
        self.assertEqual(checks["official_imgui_origin"]["status"], "ok")
        plugin_sha256 = result.provenance["plugin_sha256"]
        self.assertRegex(plugin_sha256, r"^[0-9a-f]{64}$")
        collection_root = self.root / "real-build"
        bundle = provider.collect_artifacts(result, str(collection_root))
        plugin = next(
            item for item in bundle.artifacts if item.kind == "imgui-renderer-plugin"
        )
        plugin_bytes = (collection_root / plugin.path).read_bytes()
        self.assertEqual(hashlib.sha256(plugin_bytes).hexdigest(), plugin_sha256)
        self.assertEqual(plugin.metadata["sha256"], plugin_sha256)
        manifest = json.loads(
            self._artifact_bytes(
                collection_root, bundle, "imgui-renderer-manifest"
            )
        )
        self.assertEqual(manifest["plugin_sha256"], plugin_sha256)
        self.assertEqual(
            result.report_section["plugin"]["exports"],
            sorted(EXPECTED_PLUGIN_EXPORTS),
        )

        if acceptance is None:
            return

        assert target is not None
        plugin_path = (collection_root / plugin.path).resolve()
        bridge = LocalJsonBridgeAdapter(
            "imgui_renderer_runtime",
            executable=bridge_path,
            timeout_ms=60_000,
        )
        self.assertTrue(bridge.available, bridge.unavailable_reason)
        host = ImGuiHostOrchestrator(
            bridge,
            target=target,
            session_id=acceptance.session_id,
            precondition_hash=plan.precondition_hash,
            backend="d3d11",
            timeout_ms=60_000,
        )
        host_plan = host.plan()
        with mock.patch.dict(
            os.environ,
            {"REVERSE_ANALYZER_IMGUI_PLUGIN": str(plugin_path)},
        ):
            host_execution = host.execute(host_plan)
        self.assertEqual(host_execution["status"], "ok", host_execution)
        self.assertIs(host_execution["live_verified"], True, host_execution)
        self.assertEqual(host_execution["evidence_class"], "live_host_proof")
        lifecycle = list(host_execution.get("lifecycle") or [])
        self.assertEqual(
            [item.get("operation") for item in lifecycle],
            list(IMGUI_HOST_LIFECYCLE),
        )
        for item in lifecycle:
            self.assertEqual(item.get("evidence_class"), "live_host_proof", item)
            self.assertIs(item.get("live_verified"), True, item)
            proof = dict(item.get("proof") or {})
            self.assertEqual(proof.get("source"), "native_host_bridge", proof)
            self.assertIs(proof.get("observed"), True, proof)
            self.assertTrue(proof.get("observed_at"), proof)
            bridge_cleanup = dict(
                dict(item.get("bridge_call") or {}).get("process_cleanup") or {}
            )
            self.assertIs(bridge_cleanup.get("process_exited"), True, bridge_cleanup)

        host_artifacts = host.collect_artifacts(host_execution)
        self.assertIs(host_artifacts["provenance"]["live_verified"], True)
        assert_non_synthetic(host_artifacts)
        shutdown = next(
            item for item in lifecycle if item.get("operation") == "shutdown"
        )
        unload = next(item for item in lifecycle if item.get("operation") == "unload")
        hook_restoration = {
            "status": "completed",
            "verified": True,
            "rollback_verified": True,
            "cleanup_verified": True,
            "renderer_shutdown": bool(shutdown.get("renderer_shutdown")),
            "module_unloaded": bool(unload.get("module_unloaded")),
            "hook_restored": True,
            "shutdown": shutdown,
            "unload": unload,
        }
        self.assertTrue(hook_restoration["renderer_shutdown"])
        self.assertTrue(hook_restoration["module_unloaded"])
        renderer_plugin = {
            "status": "ok",
            "provider": result.provider,
            "production_build": True,
            "official_imgui_origin_verified": True,
            "sha256": plugin_sha256,
            "size": len(plugin_bytes),
            "architecture": result.report_section["plugin"]["architecture"],
            "exports": result.report_section["plugin"]["exports"],
            "retained_binary": "imgui/reverse_analyzer_imgui_renderer.dll",
            "hook_target_resolution_hash": plan.parameters[
                "hook_target_resolution_hash"
            ],
        }
        frame_lifecycle = {
            "status": "ok",
            "fixture_id": acceptance.fixture_id,
            "session_id": acceptance.session_id,
            "plan": host_plan,
            "execution": host_execution,
            "artifacts": host_artifacts,
        }
        execution_proof = {
            "status": "ok",
            "provider": result.provider,
            "evidence_class": "live_host_proof",
            "executed_tests": 1,
            "skipped_tests": 0,
            "live_operations": len(lifecycle),
            "actions": list(IMGUI_HOST_LIFECYCLE),
            "plugin_sha256": plugin_sha256,
        }
        for payload in (
            renderer_plugin,
            frame_lifecycle,
            hook_restoration,
            execution_proof,
        ):
            assert_non_synthetic(payload)
        write_bundle(
            acceptance,
            {
                "imgui/target-identity.json": target.to_dict(),
                "imgui/renderer-plugin.json": renderer_plugin,
                "imgui/reverse_analyzer_imgui_renderer.dll": plugin_bytes,
                "imgui/frame-lifecycle.json": frame_lifecycle,
                "imgui/hook-restoration.json": hook_restoration,
                "imgui/execution-proof.json": execution_proof,
            },
        )


if __name__ == "__main__":
    unittest.main()
