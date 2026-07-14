from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from reverse_analyzer.cli import (
    _BUILTIN_TOOLS,
    _CAPABILITY_REPORT_SECTIONS,
    build_parser,
    main,
)
from reverse_analyzer.providers import (
    AntiTamperLabProvider,
    HardwareIdentityProvider,
    ImGuiRendererProvider,
    KernelDriverMemoryProvider,
    NativeDebuggerProvider,
    TargetControlProvider,
    build_default_registry,
)
from tests.test_android_elf_patch import ARM_CODE_OFFSET, _minimal_arm_elf32


class GapWiringTests(unittest.TestCase):
    def test_registry_and_builtin_tools_expose_extended_capabilities(self) -> None:
        registry = build_default_registry()
        capabilities = set(registry.list_capabilities())
        expected_capabilities = {
            "android_instrumentation",
            "android_rebuild",
            "anti_tamper_lab",
            "dma_memory",
            "engine_runtime",
            "graphics_present_runtime",
            "hardware_identity_virtualization",
            "hook_runtime",
            "imgui_renderer_runtime",
            "injector",
            "ios_instrumentation",
            "ios_rebuild",
            "kernel_driver_memory_runtime",
            "memory_runtime",
            "native_debugger",
            "native_hook",
            "patch_executor",
            "protocol_runtime",
            "render_overlay_runtime",
            "target_control_simulation",
        }
        self.assertTrue(
            expected_capabilities.issubset(capabilities),
            expected_capabilities - capabilities,
        )

        expected_gap_providers = {
            "anti_tamper_lab": AntiTamperLabProvider,
            "hardware_identity_virtualization": HardwareIdentityProvider,
            "imgui_renderer_runtime": ImGuiRendererProvider,
            "kernel_driver_memory_runtime": KernelDriverMemoryProvider,
            "native_debugger": NativeDebuggerProvider,
            "target_control_simulation": TargetControlProvider,
        }
        for capability, provider_type in expected_gap_providers.items():
            with self.subTest(capability=capability):
                provider = registry.resolve(
                    capability,
                    preferred=provider_type.provider_name,
                )
                self.assertIsInstance(provider, provider_type)

        self.assertEqual(
            _CAPABILITY_REPORT_SECTIONS["anti_tamper_lab"],
            "evidence_integrity",
        )
        self.assertEqual(
            _CAPABILITY_REPORT_SECTIONS["target_control_simulation"],
            "gui_analysis",
        )

        tools = {str(item.get("name")) for item in _BUILTIN_TOOLS}
        self.assertTrue(
            {
                "android_elf_patch_plan",
                "android_elf_patch_verify",
                "dll_proxy_generate",
                "gui_world_projection",
            }.issubset(tools)
        )

    def test_registered_provider_contracts_are_complete_and_unambiguous(self) -> None:
        registry = build_default_registry()
        lifecycle_methods = (
            "plan",
            "validate",
            "execute",
            "rollback",
            "collect_artifacts",
        )

        for capability in registry.list_capabilities():
            provider_names = registry.list_providers(capability)
            self.assertEqual(
                len(provider_names),
                len(set(provider_names)),
                f"duplicate provider names registered for {capability}",
            )
            for provider_name in provider_names:
                provider = registry.resolve(capability, preferred=provider_name)
                with self.subTest(
                    capability=capability,
                    provider=provider_name,
                ):
                    self.assertEqual(provider.capability_name, capability)
                    self.assertEqual(provider.provider_name, provider_name)
                    for method in lifecycle_methods:
                        self.assertTrue(
                            callable(getattr(provider, method, None)),
                            f"{capability}/{provider_name} is missing {method}",
                        )

    def test_new_cli_routes_are_registered(self) -> None:
        parser = build_parser()
        cases = (
            (
                [
                    "patch",
                    "android-elf-plan",
                    "sample.so",
                    "--out",
                    "out",
                    "--file-offset",
                    "0x100",
                    "--replacement",
                    "00",
                ],
                "android_elf_patch_plan_command",
            ),
            (
                ["patch", "android-elf-verify", "sample.so", "--plan", "plan.json"],
                "android_elf_patch_verify_command",
            ),
            (
                [
                    "patch",
                    "android-elf-apply",
                    "sample.so",
                    "--plan",
                    "plan.json",
                    "--out",
                    "patched.so",
                ],
                "android_elf_patch_apply_command",
            ),
            (
                [
                    "patch",
                    "android-elf-rollback",
                    "patched.so",
                    "--rollback",
                    "rollback.json",
                    "--out",
                    "restored.so",
                ],
                "android_elf_patch_rollback_command",
            ),
            (
                ["patch", "dll-proxy", "sample.dll", "--copy-dir", "copy"],
                "dll_proxy_command",
            ),
            (
                [
                    "gui",
                    "project-world",
                    "--matrix",
                    "[1,0,0,0,0,1,0,0,0,1,0,0,0,0,0,1]",
                    "--viewport",
                    '{"width":800,"height":600}',
                    "--out",
                    "out",
                ],
                "gui_world_projection_command",
            ),
        )
        for argv, expected in cases:
            with self.subTest(command=argv[:2]):
                self.assertEqual(parser.parse_args(argv).func.__name__, expected)

    def test_world_projection_cli_writes_hash_backed_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            matrix = [
                1,
                0,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                1,
            ]
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "gui",
                        "project-world",
                        "--matrix",
                        json.dumps(matrix),
                        "--viewport",
                        json.dumps({"width": 200, "height": 100}),
                        "--points",
                        json.dumps([[0, 0, 0]]),
                        "--matrix-source",
                        "runtime-read",
                        "--coordinate-system",
                        "world",
                        "--out",
                        str(out_dir),
                    ]
                )

            self.assertEqual(code, 0, stdout.getvalue())
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "ok")
            artifact = out_dir / "gui" / "world_projection.json"
            digest = out_dir / "gui" / "world_projection.json.sha256"
            self.assertTrue(artifact.is_file())
            self.assertTrue(digest.is_file())
            projection = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(projection["summary"]["point_count"], 1)
            self.assertEqual(projection["provenance"]["matrix"]["source"], "runtime-read")

    def test_android_elf_cli_plan_apply_and_rollback_closes_the_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "libfixture.so"
            sample.write_bytes(_minimal_arm_elf32())
            session = root / "session"
            plan = session / "patch" / "plan.json"
            patched = root / "patched.so"
            restored = root / "restored.so"

            commands = (
                [
                    "patch",
                    "android-elf-plan",
                    str(sample),
                    "--out",
                    str(session),
                    "--file-offset",
                    hex(ARM_CODE_OFFSET),
                    "--replacement",
                    "01 f0 20 e3",
                    "--instruction-mode",
                    "arm",
                ],
                [
                    "patch",
                    "android-elf-apply",
                    str(sample),
                    "--plan",
                    str(plan),
                    "--out",
                    str(patched),
                    "--artifact-dir",
                    str(session / "apply"),
                ],
            )
            for argv in commands:
                stdout = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    code = main(argv)
                self.assertEqual(code, 0, stdout.getvalue())

            rollback_manifest = session / "apply" / "rollback.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "patch",
                        "android-elf-rollback",
                        str(patched),
                        "--rollback",
                        str(rollback_manifest),
                        "--out",
                        str(restored),
                        "--artifact-dir",
                        str(session / "rollback"),
                    ]
                )

            self.assertEqual(code, 0, stdout.getvalue())
            self.assertNotEqual(patched.read_bytes(), sample.read_bytes())
            self.assertEqual(restored.read_bytes(), sample.read_bytes())
            report = json.loads((session / "apply" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["patch_analysis"]["target_format"], "elf")


if __name__ == "__main__":
    unittest.main()
