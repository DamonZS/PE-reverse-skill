"""Host dependency and end-to-end readiness validation.

The platform has many optional native adapters.  This module deliberately
separates dependency discovery from an executed probe so reports cannot treat
an installed binary as a completed end-to-end validation.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


Runner = Callable[..., subprocess.CompletedProcess[str]]


_EXECUTABLES: dict[str, tuple[tuple[str, ...], str | None, tuple[str, ...]]] = {
    "frida_cli": (("frida",), "FRIDA_CLI", ("--version",)),
    "apktool": (("apktool",), "APKTOOL_PATH", ("--version",)),
    "jadx": (("jadx", "jadx-gui"), "JADX_PATH", ("--version",)),
    "apksigner": (("apksigner",), "APKSIGNER_PATH", ("version",)),
    "adb": (("adb",), "ADB_PATH", ("version",)),
    "xcodebuild": (("xcodebuild",), "XCODEBUILD_PATH", ("-version",)),
    "xcrun": (("xcrun",), "XCRUN_PATH", ("--version",)),
    "presentmon": (("PresentMon", "PresentMon.exe"), "PRESENTMON_PATH", ("--version",)),
    "graphics_bridge": ((), "REVERSE_ANALYZER_GRAPHICS_BRIDGE", ("--capabilities",)),
    "imgui_bridge": ((), "REVERSE_ANALYZER_IMGUI_BRIDGE", ("--capabilities",)),
    "kernel_bridge": ((), "REVERSE_ANALYZER_KERNEL_BRIDGE", ("--capabilities",)),
    "memprocfs": (("MemProcFS", "MemProcFS.exe"), "MEMPROCFS_PATH", ("-version",)),
    "leechcore": (("leechcore", "leechcore.exe"), "LEECHCORE_PATH", ("--version",)),
    "tesseract": (("tesseract",), "TESSERACT_PATH", ("--version",)),
}

_MODULES: dict[str, str] = {
    "frida_python": "frida",
    "comtypes": "comtypes",
    "opencv": "cv2",
}

_FILES: dict[str, str] = {
    "kernel_driver": "REVERSE_ANALYZER_KERNEL_DRIVER",
}


# These definitions deliberately separate a checked-in deterministic fixture from
# a live-target acceptance run.  A discovered tool or a passing unit test never
# upgrades a live fixture to verified evidence.
_P0_P4_ACCEPTANCE_FIXTURES: tuple[dict[str, Any], ...] = (
    {
        "id": "p0-environment-contract",
        "phase": "P0",
        "capability": "environment_validation",
        "evidence_level": "repository",
        "host": "any",
        "command": "python -m unittest tests.test_environment_validation",
        "argv": ["{python}", "-m", "unittest", "tests.test_environment_validation"],
        "expected_artifacts": ["environment-validation.json"],
    },
    {
        "id": "p1-memory-runtime-live",
        "phase": "P1",
        "capability": "memory_runtime",
        "evidence_level": "live-target",
        "host": "windows",
        "gate_env": ["RUN_MEMORY_RUNTIME_INTEGRATION"],
        "command": "$env:RUN_MEMORY_RUNTIME_INTEGRATION='1'; python -m unittest tests.test_memory_structured",
        "argv": ["{python}", "-m", "unittest", "tests.test_memory_structured"],
        "run_env": {"RUN_MEMORY_RUNTIME_INTEGRATION": "1"},
        "mutating": True,
        "expected_artifacts": ["memory/session.json", "memory/target-identity.json", "memory/rollback_plan.json", "memory/cleanup.json"],
        "execution_proof_artifact": "memory/execution-proof.json",
        "required_executed_tests": 2,
        "target_identity_artifact": "memory/target-identity.json",
        "rollback_artifacts": ["memory/rollback_plan.json"],
        "cleanup_artifacts": ["memory/cleanup.json"],
    },
    {
        "id": "p1-loadlibrary-injector",
        "phase": "P1",
        "capability": "injector",
        "evidence_level": "live-child-process",
        "host": "windows",
        "command": "python -m unittest tests.test_injector_provider.InjectorProviderTests.test_acceptance_runner_retains_real_loadlibrary_artifacts",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_injector_provider.InjectorProviderTests.test_acceptance_runner_retains_real_loadlibrary_artifacts",
        ],
        "mutating": True,
        "expected_artifacts": [
            "injector/*/injection.json",
            "injector/audit.json",
            "injector/target-identity.json",
            "injector/rollback.json",
            "injector/cleanup.json",
        ],
        "execution_proof_artifact": "injector/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "injector/target-identity.json",
        "rollback_artifacts": ["injector/rollback.json"],
        "cleanup_artifacts": ["injector/cleanup.json"],
    },
    {
        "id": "p1-manual-map-live",
        "phase": "P1",
        "capability": "injector_manual_map",
        "evidence_level": "live-target",
        "host": "windows",
        "gate_env": ["RUN_INJECTOR_MANUAL_MAP_WINDOWS_LIVE"],
        "command": "$env:RUN_INJECTOR_MANUAL_MAP_WINDOWS_LIVE='1'; python -m unittest tests.test_injector_manual_map_live",
        "argv": ["{python}", "-m", "unittest", "tests.test_injector_manual_map_live"],
        "run_env": {"RUN_INJECTOR_MANUAL_MAP_WINDOWS_LIVE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "injector/*/injection.json",
            "injector/target-identity.json",
            "injector/manual-map-rollback.json",
        ],
        "execution_proof_artifact": "injector/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "injector/target-identity.json",
        "rollback_artifacts": ["injector/manual-map-rollback.json"],
        "cleanup_artifacts": ["injector/manual-map-rollback.json"],
    },
    {
        "id": "p1-native-hook-live",
        "phase": "P1",
        "capability": "native_hook",
        "evidence_level": "live-target",
        "host": "windows",
        "gate_env": ["RUN_NATIVE_HOOK_SMOKE"],
        "command": "$env:RUN_NATIVE_HOOK_SMOKE='1'; python -m unittest tests.test_native_hook_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_native_hook_provider"],
        "run_env": {"RUN_NATIVE_HOOK_SMOKE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "native_hook/*/audit.json",
            "native_hook/*/events.json",
            "native_hook/*/manifest.json",
            "native-hook/target-identity.json",
            "native-hook/rollback.json",
        ],
        "execution_proof_artifact": "native-hook/execution-proof.json",
        "required_executed_tests": 2,
        "target_identity_artifact": "native-hook/target-identity.json",
        "rollback_artifacts": ["native-hook/rollback.json"],
        "cleanup_artifacts": ["native-hook/rollback.json"],
    },
    {
        "id": "p1-hook-target-resolution",
        "phase": "P1",
        "capability": "hook_target_resolver",
        "evidence_level": "live-target",
        "host": "windows",
        "command": "python -m unittest tests.test_hook_target_live.WindowsLiveHookTargetTests.test_acceptance_runner_retains_live_production_artifacts",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_hook_target_live.WindowsLiveHookTargetTests.test_acceptance_runner_retains_live_production_artifacts",
        ],
        "expected_artifacts": [
            "hook-targets/*/resolution.json",
            "hook-targets/*/audit.json",
            "hook-targets/*/manifest.json",
            "hook-targets/target-identity.json",
            "hook-targets/rollback.json",
        ],
        "execution_proof_artifact": "hook-targets/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "hook-targets/target-identity.json",
        "rollback_artifacts": ["hook-targets/rollback.json"],
    },
    {
        "id": "p1-native-debugger-child",
        "phase": "P1",
        "capability": "native_debugger",
        "evidence_level": "live-child-process",
        "host": "windows",
        "command": "python -m unittest tests.test_native_debugger_provider.NativeDebuggerWindowsE2ETests",
        "argv": ["{python}", "-m", "unittest", "tests.test_native_debugger_provider.NativeDebuggerWindowsE2ETests"],
        "expected_artifacts": [
            "native_debugger/*/audit.json",
            "native_debugger/*/events.json",
            "native_debugger/*/diagnostics.json",
            "native_debugger/*/manifest.json",
            "native-debugger/target-identity.json",
            "native-debugger/rollback.json",
        ],
        "execution_proof_artifact": "native-debugger/execution-proof.json",
        "required_executed_tests": 2,
        "target_identity_artifact": "native-debugger/target-identity.json",
        "cleanup_artifacts": ["native-debugger/rollback.json"],
    },
    {
        "id": "p1-native-hardware-breakpoint",
        "phase": "P1",
        "capability": "native_hook",
        "evidence_level": "live-child-process",
        "host": "windows",
        "gate_env": ["RUN_NATIVE_HOOK_HARDWARE_SMOKE"],
        "command": "$env:RUN_NATIVE_HOOK_HARDWARE_SMOKE='1'; python -m unittest tests.test_native_hook_provider.NativeHookWindowsHardwareSmokeTests",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_native_hook_provider.NativeHookWindowsHardwareSmokeTests",
        ],
        "run_env": {"RUN_NATIVE_HOOK_HARDWARE_SMOKE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "native_hook/*/audit.json",
            "native_hook/*/events.json",
            "native_hook/*/manifest.json",
            "native-hook-hardware/target-identity.json",
            "native-hook-hardware/rollback.json",
        ],
        "execution_proof_artifact": "native-hook-hardware/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "native-hook-hardware/target-identity.json",
        "rollback_artifacts": ["native-hook-hardware/rollback.json"],
        "cleanup_artifacts": ["native-hook-hardware/rollback.json"],
    },
    {
        "id": "p2-pe-seven-strategies",
        "phase": "P2",
        "capability": "patch_planner",
        "evidence_level": "repository-production-backend",
        "host": "any",
        "command": "python -m unittest tests.test_patch_planner tests.test_patch_capability_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_patch_planner", "tests.test_patch_capability_provider"],
        "expected_artifacts": [
            "patch/plan.json",
            "patch/verify.json",
            "patch/rollback_plan.json",
            "patch/acceptance-summary.json",
            "patch/strategies/*/artifacts/plan.json",
            "patch/strategies/*/artifacts/verify.json",
            "patch/strategies/*/artifacts/risk_report.json",
            "patch/strategies/*/artifacts/rollback_plan.json",
            "patch/provider/patch_manifest.json",
            "patch/provider/rollback.json",
            "patch/provider/audit.json",
            "patch/provider/provider-proof.json",
        ],
    },
    {
        "id": "p2-dll-proxy-build",
        "phase": "P2",
        "capability": "dll_proxy_generation",
        "evidence_level": "toolchain",
        "host": "any",
        "gate_env": ["RUN_DLL_PROXY_BUILD"],
        "command": "$env:RUN_DLL_PROXY_BUILD='1'; python -m unittest tests.test_dll_proxy_generator",
        "argv": ["{python}", "-m", "unittest", "tests.test_dll_proxy_generator"],
        "run_env": {"RUN_DLL_PROXY_BUILD": "1"},
        "expected_artifacts": [
            "proxy/CMakeLists.txt",
            "proxy/proxy.def",
            "proxy/validation_report.json",
            "proxy/toolchain-proof.json",
            "proxy/build/fixture.dll",
            "proxy/build/fixture_original.dll",
            "proxy/build_manifest.json",
            "proxy/rollback.json",
            "proxy/risk_report.json",
        ],
    },
    {
        "id": "p2-dll-proxy-load-live",
        "phase": "P2",
        "capability": "dll_proxy_generation",
        "evidence_level": "live-child-process",
        "host": "windows",
        "gate_env": ["RUN_DLL_PROXY_LIVE"],
        "command": "$env:RUN_DLL_PROXY_LIVE='1'; python -m unittest tests.test_dll_proxy_generator.DllProxyProjectGeneratorTests.test_generated_x64_proxy_loads_resolves_and_unloads",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_dll_proxy_generator.DllProxyProjectGeneratorTests.test_generated_x64_proxy_loads_resolves_and_unloads",
        ],
        "run_env": {"RUN_DLL_PROXY_LIVE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "proxy/build/fixture.dll",
            "proxy/build/fixture_original.dll",
            "proxy/validation_report.json",
            "proxy/toolchain-proof.json",
            "proxy/load-proof.json",
            "proxy/unload-proof.json",
            "proxy/target-identity.json",
        ],
        "execution_proof_artifact": "proxy/execution-proof.json",
        "target_identity_artifact": "proxy/target-identity.json",
        "rollback_artifacts": ["proxy/unload-proof.json"],
        "cleanup_artifacts": ["proxy/unload-proof.json"],
    },
    {
        "id": "p3-unity-mono-live",
        "phase": "P3",
        "capability": "engine_runtime_mono",
        "evidence_level": "live-target",
        "host": "windows",
        "gate_env": ["RUN_ENGINE_RUNTIME_WINDOWS_SMOKE", "REVERSE_ANALYZER_UNITY_MONO_FIXTURE"],
        "command": "$env:RUN_ENGINE_RUNTIME_WINDOWS_SMOKE='1'; python -m unittest tests.test_engine_runtime_mono tests.test_engine_runtime_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_engine_runtime_mono", "tests.test_engine_runtime_provider"],
        "run_env": {"RUN_ENGINE_RUNTIME_WINDOWS_SMOKE": "1"},
        "expected_artifacts": ["engine/runtime-metadata.json", "engine/target-identity.json", "engine/semantic_ir_fragment.json"],
        "execution_proof_artifact": "engine/execution-proof.json",
        "target_identity_artifact": "engine/target-identity.json",
    },
    {
        "id": "p3-unity-il2cpp-live",
        "phase": "P3",
        "capability": "engine_runtime_il2cpp",
        "evidence_level": "live-target",
        "host": "windows",
        "gate_env": ["RUN_ENGINE_RUNTIME_WINDOWS_SMOKE", "REVERSE_ANALYZER_UNITY_IL2CPP_FIXTURE"],
        "command": "$env:RUN_ENGINE_RUNTIME_WINDOWS_SMOKE='1'; python -m unittest tests.test_engine_runtime_il2cpp tests.test_engine_runtime_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_engine_runtime_il2cpp", "tests.test_engine_runtime_provider"],
        "run_env": {"RUN_ENGINE_RUNTIME_WINDOWS_SMOKE": "1"},
        "expected_artifacts": ["engine/registration.json", "engine/target-identity.json", "engine/token-native-map.json"],
        "execution_proof_artifact": "engine/execution-proof.json",
        "target_identity_artifact": "engine/target-identity.json",
    },
    {
        "id": "p3-unreal-live",
        "phase": "P3",
        "capability": "engine_runtime_unreal",
        "evidence_level": "live-target",
        "host": "windows",
        "gate_env": ["RUN_ENGINE_RUNTIME_WINDOWS_SMOKE", "REVERSE_ANALYZER_UNREAL_FIXTURE"],
        "command": "$env:RUN_ENGINE_RUNTIME_WINDOWS_SMOKE='1'; python -m unittest tests.test_engine_runtime_unreal tests.test_engine_runtime_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_engine_runtime_unreal", "tests.test_engine_runtime_provider"],
        "run_env": {"RUN_ENGINE_RUNTIME_WINDOWS_SMOKE": "1"},
        "expected_artifacts": ["engine/target-identity.json", "engine/gnames.json", "engine/gobjects.json", "engine/gworld.json"],
        "execution_proof_artifact": "engine/execution-proof.json",
        "target_identity_artifact": "engine/target-identity.json",
    },
    {
        "id": "p4-presentmon-live",
        "phase": "P4",
        "capability": "graphics_present_runtime",
        "evidence_level": "live-target",
        "host": "windows",
        "workflows": ["graphics_present_observation"],
        "gate_env": ["REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID"],
        "command": "python -m unittest tests.test_graphics_runtime_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_graphics_runtime_provider"],
        "expected_artifacts": ["graphics/target-identity.json", "graphics/present-events.jsonl", "graphics/audit.json", "graphics/evidence-manifest.json"],
        "execution_proof_artifact": "graphics/execution-proof.json",
        "target_identity_artifact": "graphics/target-identity.json",
    },
    {
        "id": "p4-native-graphics-bridge",
        "phase": "P4",
        "capability": "graphics_present_bridge",
        "evidence_level": "live-target",
        "host": "windows",
        "workflows": ["graphics_present_hook"],
        "gate_env": [
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID",
            "REVERSE_ANALYZER_GRAPHICS_BRIDGE",
        ],
        "command": "python -m unittest tests.test_graphics_runtime_provider.GraphicsRuntimeAcceptanceTests.test_native_bridge_live_acceptance_artifacts",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_graphics_runtime_provider.GraphicsRuntimeAcceptanceTests.test_native_bridge_live_acceptance_artifacts",
        ],
        "mutating": True,
        "expected_artifacts": ["graphics/target-identity.json", "graphics/bridge-request.json", "graphics/bridge-response.json", "graphics/stop-proof.json"],
        "execution_proof_artifact": "graphics/execution-proof.json",
        "target_identity_artifact": "graphics/target-identity.json",
        "rollback_artifacts": ["graphics/stop-proof.json"],
        "cleanup_artifacts": ["graphics/stop-proof.json"],
    },
    {
        "id": "p4-imgui-d3d11-live",
        "phase": "P4",
        "capability": "imgui_in_process_rendering",
        "evidence_level": "live-target",
        "host": "windows",
        "workflows": ["imgui_in_process"],
        "gate_env": [
            "DEAR_IMGUI_ROOT",
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID",
            "REVERSE_ANALYZER_IMGUI_BRIDGE",
            "REVERSE_ANALYZER_IMGUI_PRESENT_RESOLUTION",
        ],
        "command": "python -m unittest tests.test_imgui_renderer_provider.ImGuiRendererProviderTests.test_real_build_when_official_checkout_is_explicitly_available",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_imgui_renderer_provider.ImGuiRendererProviderTests.test_real_build_when_official_checkout_is_explicitly_available",
        ],
        "mutating": True,
        "expected_artifacts": ["imgui/target-identity.json", "imgui/renderer-plugin.json", "imgui/frame-lifecycle.json", "imgui/hook-restoration.json"],
        "execution_proof_artifact": "imgui/execution-proof.json",
        "target_identity_artifact": "imgui/target-identity.json",
        "rollback_artifacts": ["imgui/hook-restoration.json"],
        "cleanup_artifacts": ["imgui/hook-restoration.json"],
    },
    {
        "id": "p4-external-overlay-live",
        "phase": "P4",
        "capability": "render_overlay_runtime",
        "evidence_level": "interactive-live-target",
        "host": "windows",
        "gate_env": ["RUN_RENDER_OVERLAY_SMOKE"],
        "command": "$env:RUN_RENDER_OVERLAY_SMOKE='1'; python -m unittest tests.test_render_overlay_provider",
        "argv": ["{python}", "-m", "unittest", "tests.test_render_overlay_provider"],
        "run_env": {"RUN_RENDER_OVERLAY_SMOKE": "1"},
        "mutating": True,
        "expected_artifacts": ["render-overlay/target-identity.json", "render-overlay/audit.json", "render-overlay/screenshot.png", "render-overlay/window-teardown.json"],
        "execution_proof_artifact": "render-overlay/execution-proof.json",
        "target_identity_artifact": "render-overlay/target-identity.json",
        "rollback_artifacts": ["render-overlay/window-teardown.json"],
        "cleanup_artifacts": ["render-overlay/window-teardown.json"],
    },
    {
        "id": "p5-android-jadx-live",
        "phase": "P5",
        "capability": "android_java_decompilation",
        "evidence_level": "live-target",
        "host": "any",
        "workflows": ["android_java_decompilation"],
        "gate_env": ["RUN_ANDROID_JADX_LIVE", "ANDROID_JADX_LIVE_APK"],
        "command": "$env:RUN_ANDROID_JADX_LIVE='1'; python -m unittest tests.e2e.test_android_p5_live.AndroidP5JadxLiveTests.test_real_jadx_e2e",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.e2e.test_android_p5_live.AndroidP5JadxLiveTests.test_real_jadx_e2e",
        ],
        "run_env": {"RUN_ANDROID_JADX_LIVE": "1"},
        "expected_artifacts": [
            "android/java_decompilation.json",
            "android/jadx/**/*",
            "android-jadx/target-identity.json",
            "android-jadx/input-integrity.json",
            "android-jadx/toolchain.json",
        ],
        "execution_proof_artifact": "android-jadx/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "android-jadx/target-identity.json",
    },
    {
        "id": "p5-android-rebuild-sign-live",
        "phase": "P5",
        "capability": "android_rebuild_orchestration",
        "evidence_level": "live-target",
        "host": "any",
        "workflows": ["android_rebuild_sign"],
        "gate_env": [
            "RUN_ANDROID_REBUILD_LIVE",
            "ANDROID_REBUILD_LIVE_APK",
            "ANDROID_REBUILD_LIVE_KEYSTORE",
            "ANDROID_REBUILD_LIVE_KS_PASS",
        ],
        "command": "$env:RUN_ANDROID_REBUILD_LIVE='1'; python -m unittest tests.e2e.test_android_rebuild_live.AndroidRebuildLiveTests.test_rebuild_sign_verify_and_rollback",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.e2e.test_android_rebuild_live.AndroidRebuildLiveTests.test_rebuild_sign_verify_and_rollback",
        ],
        "run_env": {"RUN_ANDROID_REBUILD_LIVE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "android-rebuild/provider/rebuild_verify.json",
            "android-rebuild/provider/rebuild_audit.json",
            "android-rebuild/retained/fixture-signed.apk",
            "android-rebuild/retained-artifact.json",
            "android-rebuild/target-identity.json",
            "android-rebuild/rollback.json",
        ],
        "execution_proof_artifact": "android-rebuild/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "android-rebuild/target-identity.json",
        "rollback_artifacts": ["android-rebuild/rollback.json"],
        "cleanup_artifacts": ["android-rebuild/rollback.json"],
    },
    {
        "id": "p5-android-frida-live",
        "phase": "P5",
        "capability": "android_dynamic_instrumentation",
        "evidence_level": "live-target",
        "host": "any",
        "workflows": ["android_dynamic_instrumentation"],
        "gate_env": ["RUN_ANDROID_FRIDA_LIVE", "ANDROID_FRIDA_LIVE_PACKAGE"],
        "command": "$env:RUN_ANDROID_FRIDA_LIVE='1'; python -m unittest tests.e2e.test_android_p5_live.AndroidP5InstrumentationLiveTests.test_real_frida_device_e2e_and_cleanup",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.e2e.test_android_p5_live.AndroidP5InstrumentationLiveTests.test_real_frida_device_e2e_and_cleanup",
        ],
        "run_env": {"RUN_ANDROID_FRIDA_LIVE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "android_instrumentation/*/audit.json",
            "android_instrumentation/*/events.json",
            "android_instrumentation/*/rollback.json",
            "android-frida/target-identity.json",
            "android-frida/cleanup.json",
        ],
        "execution_proof_artifact": "android-frida/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "android-frida/target-identity.json",
        "rollback_artifacts": ["android-frida/cleanup.json"],
        "cleanup_artifacts": ["android-frida/cleanup.json"],
    },
    {
        "id": "p5-android-native-patch-live",
        "phase": "P5",
        "capability": "android_native_patch_pipeline",
        "evidence_level": "live-target",
        "host": "any",
        "workflows": ["android_native_patch_pipeline"],
        "gate_env": [
            "RUN_ANDROID_NATIVE_PATCH_LIVE",
            "ANDROID_NATIVE_PATCH_LIVE_APK",
            "ANDROID_NATIVE_PATCH_LIVE_SPEC",
            "ANDROID_NATIVE_PATCH_LIVE_PACKAGE",
            "ANDROID_NATIVE_PATCH_LIVE_KEYSTORE",
            "ANDROID_NATIVE_PATCH_LIVE_KS_PASS",
        ],
        "command": "$env:RUN_ANDROID_NATIVE_PATCH_LIVE='1'; python -m unittest tests.e2e.test_android_native_patch_live.AndroidNativePatchLiveTests.test_patch_sign_deploy_launch_and_rollback",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.e2e.test_android_native_patch_live.AndroidNativePatchLiveTests.test_patch_sign_deploy_launch_and_rollback",
        ],
        "run_env": {"RUN_ANDROID_NATIVE_PATCH_LIVE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "android-native-patch/provider/native-patch-plan.json",
            "android-native-patch/provider/native-patch-verify.json",
            "android-native-patch/provider/rollback.json",
            "android-native-patch/retained/patched-signed.apk",
            "android-native-patch/target-identity.json",
            "android-native-patch/deployment.json",
            "android-native-patch/rollback.json",
        ],
        "execution_proof_artifact": "android-native-patch/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "android-native-patch/target-identity.json",
        "rollback_artifacts": ["android-native-patch/rollback.json"],
        "cleanup_artifacts": ["android-native-patch/rollback.json"],
    },
    {
        "id": "p6-protocol-runtime-loopback",
        "phase": "P6",
        "capability": "network_capture_mutation_replay",
        "evidence_level": "live-target",
        "host": "any",
        "gate_env": ["RUN_PROTOCOL_RUNTIME_LIVE"],
        "command": "$env:RUN_PROTOCOL_RUNTIME_LIVE='1'; python -m unittest tests.test_protocol_runtime_tls.ProtocolRuntimeTlsTests.test_acceptance_runner_retains_live_protocol_artifacts",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_protocol_runtime_tls.ProtocolRuntimeTlsTests.test_acceptance_runner_retains_live_protocol_artifacts",
        ],
        "run_env": {"RUN_PROTOCOL_RUNTIME_LIVE": "1"},
        "expected_artifacts": [
            "protocol_runtime/*/*.json",
            "protocol-runtime/target-identity.json",
            "protocol-runtime/rollback.json",
        ],
        "execution_proof_artifact": "protocol-runtime/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "protocol-runtime/target-identity.json",
        "rollback_artifacts": ["protocol-runtime/rollback.json"],
        # The loopback session is non-mutating, but socket closure and
        # provider rollback are still required evidence for promotion.
        "cleanup_artifacts": ["protocol-runtime/rollback.json"],
    },
    {
        "id": "p7-vlm-openai-live",
        "phase": "P7",
        "capability": "vlm_visual_provider",
        "evidence_level": "live-target",
        "host": "any",
        "gate_env": [
            "REVERSE_ANALYZER_RUN_VLM_LIVE",
            "REVERSE_ANALYZER_VLM_BASE_URL",
            "REVERSE_ANALYZER_VLM_MODEL",
            "REVERSE_ANALYZER_VLM_API_KEY",
            "REVERSE_ANALYZER_VLM_IMAGE",
            "REVERSE_ANALYZER_VLM_CANARY",
        ],
        "command": "$env:REVERSE_ANALYZER_RUN_VLM_LIVE='1'; python -m unittest tests.e2e.test_gui_vlm_live.LiveOpenAIVLMTests.test_live_image_analysis_retains_sanitized_acceptance_artifacts",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.e2e.test_gui_vlm_live.LiveOpenAIVLMTests.test_live_image_analysis_retains_sanitized_acceptance_artifacts",
        ],
        "run_env": {"REVERSE_ANALYZER_RUN_VLM_LIVE": "1"},
        "expected_artifacts": [
            "gui-vlm/target-identity.json",
            "gui-vlm/invocation.json",
            "gui-vlm/output.json",
            "gui-vlm/transport-audit.json",
            "gui-vlm/canary-verification.json",
        ],
        "execution_proof_artifact": "gui-vlm/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "gui-vlm/target-identity.json",
    },
    {
        "id": "p7-windows-uia-live",
        "phase": "P7",
        "capability": "windows_uia_runtime",
        "evidence_level": "live-child-process",
        "host": "windows",
        "workflows": ["windows_uia"],
        "gate_env": ["REVERSE_ANALYZER_RUN_WINDOWS_UIA_LIVE"],
        "command": "$env:REVERSE_ANALYZER_RUN_WINDOWS_UIA_LIVE='1'; python -m unittest tests.test_gui_windows_uia.WindowsUIAAdapterTests.test_optional_live_windows_uia_smoke",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.test_gui_windows_uia.WindowsUIAAdapterTests.test_optional_live_windows_uia_smoke",
        ],
        "run_env": {"REVERSE_ANALYZER_RUN_WINDOWS_UIA_LIVE": "1"},
        "expected_artifacts": [
            "gui-uia/target-identity.json",
            "gui-uia/runtime-tree-audit.json",
            "gui-uia/fixture-cleanup.json",
        ],
        "execution_proof_artifact": "gui-uia/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "gui-uia/target-identity.json",
        "cleanup_artifacts": ["gui-uia/fixture-cleanup.json"],
    },
    {
        "id": "p7-graphics-combined-live",
        "phase": "P7",
        "capability": "world_projection_and_diagnostic_overlay",
        "evidence_level": "interactive-live-target",
        "host": "windows",
        "workflows": ["graphics_present_hook"],
        "gate_env": [
            "RUN_GRAPHICS_COMBINED_LIVE",
            "REVERSE_ANALYZER_GRAPHICS_BRIDGE",
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_PID",
            "REVERSE_ANALYZER_GRAPHICS_FIXTURE_HWND",
        ],
        "command": "$env:RUN_GRAPHICS_COMBINED_LIVE='1'; python -m unittest tests.e2e.test_graphics_combined_live.GraphicsCombinedLiveTests.test_present_matrix_projection_overlay_retains_artifacts",
        "argv": [
            "{python}",
            "-m",
            "unittest",
            "tests.e2e.test_graphics_combined_live.GraphicsCombinedLiveTests.test_present_matrix_projection_overlay_retains_artifacts",
        ],
        "run_env": {"RUN_GRAPHICS_COMBINED_LIVE": "1"},
        "mutating": True,
        "expected_artifacts": [
            "graphics-combined/target-identity.json",
            "graphics-combined/present-observation.json",
            "graphics-combined/matrix-capture.json",
            "graphics-combined/projection.json",
            "graphics-combined/overlay-audit.json",
            "graphics-combined/cleanup.json",
        ],
        "execution_proof_artifact": "graphics-combined/execution-proof.json",
        "required_executed_tests": 1,
        "target_identity_artifact": "graphics-combined/target-identity.json",
        "rollback_artifacts": ["graphics-combined/cleanup.json"],
        "cleanup_artifacts": ["graphics-combined/cleanup.json"],
    },
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _string_override(
    key: str,
    env_name: str | None,
    overrides: Mapping[str, Any],
    environ: Mapping[str, str],
) -> str | None:
    value = overrides.get(key)
    if value is None and env_name:
        value = environ.get(env_name)
    text = str(value).strip() if value is not None else ""
    return text or None


def _resolve_executable(
    key: str,
    names: Sequence[str],
    env_name: str | None,
    overrides: Mapping[str, Any],
    environ: Mapping[str, str],
) -> str | None:
    explicit = _string_override(key, env_name, overrides, environ)
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.is_file():
            return str(candidate.resolve())
        resolved = shutil.which(explicit)
        return str(Path(resolved).resolve()) if resolved else None
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return str(Path(resolved).resolve())
    return None


def _module_discovered(module_name: str, override: Any = None) -> bool:
    if override is not None:
        return bool(override)
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _probe_executable(
    path: str,
    arguments: Sequence[str],
    *,
    timeout: float,
    runner: Runner,
    expect_json: bool = False,
) -> dict[str, Any]:
    command = [path, *arguments]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "failed",
            "command": command,
            "error": f"{type(exc).__name__}: {exc}",
        }
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    payload: dict[str, Any] = {
        "status": "ok" if completed.returncode == 0 else "failed",
        "command": command,
        "returncode": completed.returncode,
        "stdout": stdout[:4096],
        "stderr": stderr[:4096],
    }
    if expect_json and completed.returncode == 0:
        try:
            parsed = json.loads(stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            payload["status"] = "failed"
            payload["error"] = f"invalid bridge JSON: {exc}"
        else:
            if not isinstance(parsed, Mapping):
                payload["status"] = "failed"
                payload["error"] = "bridge response must be a JSON object"
            else:
                payload["response"] = dict(parsed)
    return payload


def _probe_module(module_name: str) -> dict[str, Any]:
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - optional native imports fail in many valid ways
        return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    return {
        "status": "ok",
        "version": str(getattr(module, "__version__", "unknown")),
    }


def _check_status(discovered: bool, probe: Mapping[str, Any] | None) -> str:
    if not discovered:
        return "unavailable"
    if probe is None:
        return "discovered"
    return "verified" if probe.get("status") == "ok" else "failed"


def _workflow(
    name: str,
    checks: Mapping[str, Mapping[str, Any]],
    *,
    required: Sequence[str] = (),
    any_of: Sequence[str] = (),
    supported: bool = True,
    note: str = "",
) -> dict[str, Any]:
    if not supported:
        return {
            "name": name,
            "status": "unsupported_host",
            "ready": False,
            "verified": False,
            "required": list(required),
            "any_of": list(any_of),
            "note": note,
        }
    required_checks = [checks[item] for item in required]
    any_checks = [checks[item] for item in any_of]
    required_discovered = all(item.get("discovered") for item in required_checks)
    any_discovered = not any_checks or any(item.get("discovered") for item in any_checks)
    discovered = required_discovered and any_discovered
    partial = any(item.get("discovered") for item in [*required_checks, *any_checks])
    required_verified = all(item.get("status") == "verified" for item in required_checks)
    any_verified = not any_checks or any(item.get("status") == "verified" for item in any_checks)
    verified = bool(discovered and required_verified and any_verified)
    failed = any(item.get("status") == "failed" for item in [*required_checks, *any_checks])
    if verified:
        status = "verified"
    elif failed:
        status = "failed"
    elif discovered:
        status = "dependency_gated"
    elif partial:
        status = "partial"
    else:
        status = "unavailable"
    return {
        "name": name,
        "status": status,
        "ready": bool(discovered),
        "verified": verified,
        "required": list(required),
        "any_of": list(any_of),
        "note": note,
    }


def _acceptance_fixtures(
    workflows: Mapping[str, Mapping[str, Any]],
    *,
    environ: Mapping[str, str],
    host_system: str,
) -> list[dict[str, Any]]:
    normalized_host = host_system.strip().lower()
    fixtures: list[dict[str, Any]] = []
    for definition in _P0_P4_ACCEPTANCE_FIXTURES:
        item = dict(definition)
        required_host = str(item.get("host") or "any").lower()
        host_supported = required_host == "any" or required_host == normalized_host
        workflow_names = [str(value) for value in item.get("workflows") or []]
        workflow_states = {
            name: str((workflows.get(name) or {}).get("status") or "missing")
            for name in workflow_names
        }
        workflow_ready = all(
            (workflows.get(name) or {}).get("verified") is True
            for name in workflow_names
        )
        gate_names = [str(value) for value in item.get("gate_env") or []]
        configured_gates = [
            name for name in gate_names if str(environ.get(name) or "").strip()
        ]
        gates_ready = len(configured_gates) == len(gate_names)
        repository_evidence = str(item.get("evidence_level") or "").startswith(
            "repository"
        )
        if not host_supported:
            status = "unsupported_host"
        elif repository_evidence and not workflow_names and not gate_names:
            status = "repository_ready"
        elif workflow_ready and gates_ready:
            status = "ready_to_run"
        else:
            status = "dependency_gated"
        item.update(
            {
                "status": status,
                "host_supported": host_supported,
                "workflow_states": workflow_states,
                "configured_gates": configured_gates,
                "missing_gates": [name for name in gate_names if name not in configured_gates],
                "live_verified": False,
                "acceptance_boundary": (
                    "This readiness record does not become live_verified until the command "
                    "runs against the named production fixture and its artifacts are retained."
                ),
            }
        )
        fixtures.append(item)
    return fixtures


def acceptance_fixture_definitions() -> tuple[dict[str, Any], ...]:
    """Return defensive copies of the registered, executable fixture contracts."""

    return tuple(dict(item) for item in _P0_P4_ACCEPTANCE_FIXTURES)


def validate_external_environment(
    *,
    overrides: Mapping[str, Any] | None = None,
    execute_probes: bool = False,
    timeout: float = 5.0,
    runner: Runner = subprocess.run,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
) -> dict[str, Any]:
    """Return dependency and bounded E2E probe results for optional adapters."""

    override_values = dict(overrides or {})
    environment = dict(os.environ if environ is None else environ)
    host_system = system or platform.system()
    checks: dict[str, dict[str, Any]] = {}

    for key, module_name in _MODULES.items():
        discovered = _module_discovered(module_name, override_values.get(key))
        probe = _probe_module(module_name) if execute_probes and discovered else None
        checks[key] = {
            "kind": "python_module",
            "module": module_name,
            "discovered": discovered,
            "status": _check_status(discovered, probe),
            "probe": probe,
        }

    for key, (names, env_name, arguments) in _EXECUTABLES.items():
        path = _resolve_executable(key, names, env_name, override_values, environment)
        probe = None
        if execute_probes and path:
            probe = _probe_executable(
                path,
                arguments,
                timeout=max(0.1, float(timeout)),
                runner=runner,
                expect_json=key.endswith("_bridge"),
            )
        checks[key] = {
            "kind": "bridge" if key.endswith("_bridge") else "executable",
            "path": path,
            "env": env_name,
            "discovered": bool(path),
            "status": _check_status(bool(path), probe),
            "probe": probe,
        }

    for key, env_name in _FILES.items():
        value = _string_override(key, env_name, override_values, environment)
        path = Path(value).expanduser().resolve() if value else None
        discovered = bool(path and path.is_file())
        probe = {"status": "ok", "size": path.stat().st_size} if execute_probes and discovered and path else None
        checks[key] = {
            "kind": "file",
            "path": str(path) if path else None,
            "env": env_name,
            "discovered": discovered,
            "status": _check_status(discovered, probe),
            "probe": probe,
        }

    vlm_value = _string_override(
        "vlm_provider",
        "REVERSE_ANALYZER_VLM_PROVIDER",
        override_values,
        environment,
    )
    checks["vlm_provider"] = {
        "kind": "configuration",
        "value": vlm_value,
        "env": "REVERSE_ANALYZER_VLM_PROVIDER",
        "discovered": bool(vlm_value),
        "status": "discovered" if vlm_value else "unavailable",
        "probe": None,
    }

    is_windows = host_system.lower() == "windows"
    is_macos = host_system.lower() == "darwin"
    workflows = {
        "frida_desktop": _workflow(
            "frida_desktop",
            checks,
            required=("frida_python",),
            any_of=("frida_cli",),
            note="A live target session is still required for full adapter E2E.",
        ),
        "android_static": _workflow(
            "android_static",
            checks,
            required=("apktool", "jadx"),
        ),
        "android_java_decompilation": _workflow(
            "android_java_decompilation",
            checks,
            required=("jadx",),
        ),
        "android_rebuild_sign": _workflow(
            "android_rebuild_sign",
            checks,
            required=("apktool", "apksigner"),
        ),
        "android_device": _workflow(
            "android_device",
            checks,
            required=("adb",),
            note="The version probe does not prove that an authorized device is attached.",
        ),
        "ios_toolchain": _workflow(
            "ios_toolchain",
            checks,
            required=("xcodebuild", "xcrun"),
            supported=is_macos,
            note="Signing identity and physical-device validation remain session-specific.",
        ),
        "graphics_present_observation": _workflow(
            "graphics_present_observation",
            checks,
            required=("presentmon",),
            supported=is_windows,
            note="PresentMon observes presentation; it is not an in-process Present hook.",
        ),
        "graphics_present_hook": _workflow(
            "graphics_present_hook",
            checks,
            required=("graphics_bridge",),
            supported=is_windows,
        ),
        "imgui_in_process": _workflow(
            "imgui_in_process",
            checks,
            required=("imgui_bridge",),
            supported=is_windows,
        ),
        "kernel_memory": _workflow(
            "kernel_memory",
            checks,
            required=("kernel_bridge", "kernel_driver"),
            supported=is_windows,
            note="A successful bridge probe is not a signed-driver IOCTL test against a live target.",
        ),
        "dma_memory": _workflow(
            "dma_memory",
            checks,
            any_of=("memprocfs", "leechcore"),
            note="Hardware presence and acquisition permissions remain session-specific.",
        ),
        "windows_uia": _workflow(
            "windows_uia",
            checks,
            required=("comtypes",),
            supported=is_windows,
        ),
        "local_ocr": _workflow(
            "local_ocr",
            checks,
            required=("tesseract",),
        ),
        "vlm_visual_parse": _workflow(
            "vlm_visual_parse",
            checks,
            required=("vlm_provider",),
            note="Provider configuration must still be validated by a screenshot request.",
        ),
    }
    status_counts: dict[str, int] = {}
    for workflow in workflows.values():
        status = str(workflow["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    acceptance_fixtures = _acceptance_fixtures(
        workflows,
        environ=environment,
        host_system=host_system,
    )
    fixture_status_counts: dict[str, int] = {}
    for fixture in acceptance_fixtures:
        status = str(fixture["status"])
        fixture_status_counts[status] = fixture_status_counts.get(status, 0) + 1
    return {
        "schema_version": 2,
        "generated_at": _utc_now(),
        "host": {
            "system": host_system,
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "execute_probes": bool(execute_probes),
        "checks": checks,
        "workflows": workflows,
        "acceptance_fixtures": acceptance_fixtures,
        "summary": {
            "total": len(workflows),
            "verified": status_counts.get("verified", 0),
            "dependency_gated": status_counts.get("dependency_gated", 0),
            "partial": status_counts.get("partial", 0),
            "failed": status_counts.get("failed", 0),
            "unavailable": status_counts.get("unavailable", 0),
            "unsupported_host": status_counts.get("unsupported_host", 0),
            "acceptance_fixture_total": len(acceptance_fixtures),
            "acceptance_fixture_repository_ready": fixture_status_counts.get(
                "repository_ready", 0
            ),
            "acceptance_fixture_ready_to_run": fixture_status_counts.get(
                "ready_to_run", 0
            ),
            "acceptance_fixture_dependency_gated": fixture_status_counts.get(
                "dependency_gated", 0
            ),
            "acceptance_fixture_unsupported_host": fixture_status_counts.get(
                "unsupported_host", 0
            ),
        },
    }


def write_environment_report(report: Mapping[str, Any], output: str | Path) -> Path:
    destination = Path(output).expanduser().resolve()
    if destination.suffix.lower() != ".json":
        destination = destination / "environment-validation.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(dict(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return destination


__all__ = [
    "acceptance_fixture_definitions",
    "validate_external_environment",
    "write_environment_report",
]
