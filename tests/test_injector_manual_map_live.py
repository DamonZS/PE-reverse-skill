import ctypes
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    validate_capability_audit_record,
)
from reverse_analyzer.providers.injector import InjectorProvider, WindowsInjectorBackend
from reverse_analyzer.providers.injector_manual_map import inspect_manual_map_image


LIVE_SMOKE_ENV = "RUN_INJECTOR_MANUAL_MAP_WINDOWS_LIVE"
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "injector_manual_map"
EVENT_NAME_PREFIX = "Local\\ReverseAnalyzerManualMapSmoke-"
DLL_PREFERRED_IMAGE_BASE = 0x0000000180000000


def _find_x64_mingw_gcc() -> str | None:
    override = os.environ.get("INJECTOR_MANUAL_MAP_LIVE_CC")
    candidates = [override] if override else []
    candidates.extend(("x86_64-w64-mingw32-gcc", "gcc"))
    for candidate in candidates:
        if not candidate:
            continue
        compiler = shutil.which(candidate)
        if compiler is None and override and Path(candidate).is_file():
            compiler = str(Path(candidate).resolve())
        if compiler is None:
            continue
        try:
            probe = subprocess.run(
                [compiler, "-dumpmachine"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        target = probe.stdout.strip().lower()
        if probe.returncode == 0 and target.startswith("x86_64") and "mingw" in target:
            return compiler
    return None


def _run_build(command: list[str]) -> None:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "fixture compilation failed\n"
            f"command: {subprocess.list2cmdline(command)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def _build_fixtures(compiler: str, output_dir: Path) -> tuple[Path, Path]:
    target = output_dir / "manual_map_target.exe"
    dll = output_dir / "manual_map_smoke.dll"
    common = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
    _run_build([*common, str(FIXTURE_ROOT / "target.c"), "-o", str(target)])
    _run_build(
        [
            *common,
            "-shared",
            "-nostdlib",
            "-fno-stack-protector",
            "-Wl,--entry,DllMain",
            f"-Wl,--image-base,0x{DLL_PREFERRED_IMAGE_BASE:x}",
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
            "-Wl,--no-insert-timestamp",
            str(FIXTURE_ROOT / "smoke_dll.c"),
            "-lkernel32",
            "-o",
            str(dll),
        ]
    )
    return target, dll


class _Win32Event:
    SYNCHRONIZE = 0x00100000
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102

    def __init__(self, name: str) -> None:
        from ctypes import wintypes

        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateEventW.argtypes = [
            ctypes.c_void_p,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        self._kernel32.CreateEventW.restype = wintypes.HANDLE
        self._kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = self._kernel32.CreateEventW(None, True, False, name)
        if not self._handle:
            code = ctypes.get_last_error()
            raise OSError(code, ctypes.FormatError(code))

    def wait(self, timeout_ms: int) -> bool:
        status = int(self._kernel32.WaitForSingleObject(self._handle, timeout_ms))
        if status == self.WAIT_OBJECT_0:
            return True
        if status == self.WAIT_TIMEOUT:
            return False
        code = ctypes.get_last_error()
        raise OSError(code, ctypes.FormatError(code))

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> "_Win32Event":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get(LIVE_SMOKE_ENV) == "1",
    f"requires Windows and {LIVE_SMOKE_ENV}=1",
)
class InjectorManualMapWindowsLiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise unittest.SkipTest("requires a 64-bit Python process")
        cls.compiler = _find_x64_mingw_gcc()
        if cls.compiler is None:
            raise unittest.SkipTest(
                "requires an x64 MinGW GCC compiler; set INJECTOR_MANUAL_MAP_LIVE_CC"
            )

    def test_real_win32_manual_map_attach_audit_and_rollback(self) -> None:
        token = secrets.token_hex(16)
        attach_name = f"{EVENT_NAME_PREFIX}{token}-attach"
        detach_name = f"{EVENT_NAME_PREFIX}{token}-detach"

        with tempfile.TemporaryDirectory() as temp_dir, _Win32Event(
            attach_name
        ) as attach_event, _Win32Event(detach_name) as detach_event:
            root = Path(temp_dir)
            target_path, dll_path = _build_fixtures(self.compiler, root)
            dll_sha256 = hashlib.sha256(dll_path.read_bytes()).hexdigest()
            assessment = inspect_manual_map_image(str(dll_path))
            self.assertTrue(assessment["ok"], assessment)
            self.assertEqual(assessment["architecture"], "x64")
            self.assertEqual(assessment["image_base"], DLL_PREFERRED_IMAGE_BASE)
            self.assertGreater(assessment["import_symbol_count"], 0)
            self.assertGreater(assessment["relocation_count"], 0)
            self.assertGreater(assessment["runtime_function_count"], 0)

            environment = os.environ.copy()
            environment["RA_MANUAL_MAP_SMOKE_TOKEN"] = token
            child = subprocess.Popen(
                [str(target_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
                creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
            )
            result = None
            rollback = None
            try:
                assert child.stdout is not None
                ready_line = child.stdout.readline()
                if not ready_line:
                    assert child.stderr is not None
                    self.fail(f"target fixture exited before ready: {child.stderr.read()}")
                ready = json.loads(ready_line)
                self.assertTrue(ready["ready"])
                self.assertEqual(ready["pid"], child.pid)
                self.assertEqual(
                    ready["relocation_guard"],
                    DLL_PREFERRED_IMAGE_BASE,
                )
                self.assertIsNone(child.poll())
                self.assertFalse(attach_event.wait(0))
                self.assertFalse(detach_event.wait(0))

                backend = WindowsInjectorBackend()
                self.assertIs(type(backend), WindowsInjectorBackend)
                self.assertTrue(backend.available, backend.unavailable_reason)
                provider = InjectorProvider(
                    backend,
                    platform_name="win32",
                    timeout_ms=10_000,
                )
                request = CapabilityRequest(
                    capability="injector",
                    action="manual_map",
                    target=TargetIdentity(
                        kind="process",
                        pid=child.pid,
                        display_name=target_path.name,
                    ),
                    params={
                        "method": "manual_map",
                        "dll_path": str(dll_path.resolve()),
                        "dll_sha256": dll_sha256,
                        "timeout_ms": 10_000,
                    },
                    session_id=f"injector-manual-map-live-{token}",
                    provenance={
                        "source": "tests.test_injector_manual_map_live",
                        "fixture_compiler": self.compiler,
                    },
                )

                plan = provider.plan(request)
                self.assertEqual(plan.precondition_hash, dll_sha256)
                self.assertEqual(plan.provenance["backend"]["name"], "windows_ctypes")
                validation = provider.validate(plan)
                self.assertTrue(validation.ok, validation.errors)
                checks = {item["name"]: item for item in validation.checks}
                self.assertEqual(checks["manual_map_executor"]["status"], "ok")
                self.assertEqual(checks["manual_map_target_identity"]["status"], "ok")
                self.assertEqual(checks["manual_map_architecture_match"]["status"], "ok")

                result = provider.execute(plan)
                self.assertEqual(
                    result.status,
                    "ok",
                    json.dumps(result.report_section, indent=2, sort_keys=True),
                )
                self.assertTrue(attach_event.wait(5_000), "DllMain attach event was not signaled")
                self.assertFalse(detach_event.wait(0))
                self.assertIsNone(child.poll())

                before = result.before_snapshot
                after = result.after_snapshot
                operation = result.after_snapshot["operation"]
                self.assertEqual(result.provenance["backend"]["name"], "windows_ctypes")
                self.assertEqual(before["capture_phase"], "before")
                self.assertEqual(before["process"]["pid"], child.pid)
                self.assertEqual(before["dll"]["sha256"], dll_sha256)
                self.assertFalse(before["module_evidence"]["present"])
                self.assertEqual(after["capture_phase"], "after")
                self.assertEqual(after["dll"]["sha256"], dll_sha256)
                self.assertFalse(after["loader_visibility"]["present"])
                self.assertTrue(operation["target_identity_verified"])
                self.assertEqual(operation["target_identity"]["pid"], child.pid)
                self.assertEqual(operation["dll_sha256"], dll_sha256)
                self.assertTrue(
                    os.path.samefile(
                        operation["target_identity"]["image_path"],
                        target_path,
                    )
                )
                self.assertEqual(
                    before["process"]["creation_time_100ns"],
                    operation["target_identity"]["creation_time_100ns"],
                )
                self.assertEqual(
                    after["process"]["creation_time_100ns"],
                    operation["target_identity"]["creation_time_100ns"],
                )
                self.assertTrue(operation["headers_sections"]["complete"])
                self.assertTrue(operation["relocations"]["complete"])
                self.assertTrue(operation["relocations"]["required"])
                self.assertNotEqual(operation["image_base"], DLL_PREFERRED_IMAGE_BASE)
                self.assertGreater(operation["relocations"]["applied_count"], 0)
                self.assertEqual(
                    operation["relocations"]["applied_count"],
                    operation["relocations"]["available_count"],
                )
                self.assertTrue(operation["imports"]["complete"])
                self.assertTrue(operation["delay_imports"]["complete"])
                self.assertTrue(operation["tls_callbacks"]["complete"])
                self.assertTrue(operation["exception_table"]["complete"])
                self.assertTrue(operation["exception_table"]["registered"])
                self.assertTrue(operation["protections"]["complete"])
                self.assertFalse(operation["protections"]["writable_executable"])
                self.assertTrue(operation["readback"]["complete"])
                self.assertEqual(
                    operation["readback"]["mapped_sha256"],
                    operation["readback"]["readback_sha256"],
                )
                self.assertTrue(result.rollback_plan["supported"])
                self.assertEqual(result.rollback_plan["mode"], "manual_unmap")

                api_names = {item["api"] for item in operation["api_calls"]}
                self.assertIn("VirtualAllocEx", api_names)
                self.assertIn("WriteProcessMemory", api_names)
                self.assertIn("RtlAddFunctionTable", api_names)
                self.assertIn("FlushInstructionCache", api_names)

                record = CapabilityAuditBuilder().build_record(
                    plan=plan,
                    validation=validation,
                    result=result,
                )
                contract = validate_capability_audit_record(record)
                self.assertTrue(contract.ok, contract.errors)

                rollback = provider.rollback(result)
                self.assertTrue(rollback.ok, rollback.details)
                self.assertTrue(rollback.restored)
                self.assertTrue(rollback.details["target_identity_verified"])
                self.assertTrue(rollback.details["mapping_released"])
                self.assertTrue(rollback.details["release_verified"])
                rollback_operation = rollback.details["operation"]
                self.assertEqual(rollback_operation["after_region"]["state"], 0x10000)
                self.assertTrue(rollback_operation["function_table"]["deleted"])
                self.assertTrue(rollback_operation["dependencies_released"])
                self.assertTrue(detach_event.wait(5_000), "DllMain detach event was not signaled")
                self.assertIsNone(child.poll())

                artifact_root = root / "artifacts"
                bundle = provider.collect_artifacts(result, str(artifact_root))
                self.assertEqual(len(bundle.artifacts), 1)
                artifact = bundle.artifacts[0]
                artifact_path = artifact_root / artifact.path
                artifact_payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                self.assertEqual(artifact.metadata["sha256"], artifact_sha256)
                self.assertEqual(bundle.manifest_entries[0]["sha256"], artifact_sha256)
                self.assertEqual(bundle.manifest_entries[0]["precondition_hash"], dll_sha256)
                self.assertEqual(artifact_payload["precondition_hash"], dll_sha256)
                self.assertEqual(
                    artifact_payload["before_snapshot"]["process"]["pid"],
                    child.pid,
                )
                self.assertEqual(
                    artifact_payload["after_snapshot"]["operation"]["dll_sha256"],
                    dll_sha256,
                )
                self.assertTrue(artifact_payload["rollback_plan"]["release_verified"])
                self.assertEqual(
                    artifact_payload["provenance"]["backend"]["name"],
                    "windows_ctypes",
                )
                acceptance_root_value = str(
                    os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or ""
                ).strip()
                if acceptance_root_value:
                    acceptance_root = Path(acceptance_root_value).expanduser().resolve()
                    provider.collect_artifacts(result, str(acceptance_root))
                    acceptance_injector = acceptance_root / "injector"
                    acceptance_injector.mkdir(parents=True, exist_ok=True)
                    target_sha256 = hashlib.sha256(target_path.read_bytes()).hexdigest()
                    (acceptance_injector / "target-identity.json").write_text(
                        json.dumps(
                            {
                                "kind": "controlled_child_process",
                                "pid": child.pid,
                                "path": str(target_path.resolve()),
                                "sha256": target_sha256,
                                "injected_image_sha256": dll_sha256,
                            },
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    (acceptance_injector / "manual-map-rollback.json").write_text(
                        json.dumps(
                            {
                                "status": "ok",
                                "verified": True,
                                "restored": bool(rollback.restored),
                                "mapping_released": bool(
                                    rollback.details.get("mapping_released")
                                ),
                                "release_verified": bool(
                                    rollback.details.get("release_verified")
                                ),
                                "dependencies_released": bool(
                                    rollback.details.get("dependencies_released")
                                ),
                            },
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    (acceptance_injector / "execution-proof.json").write_text(
                        json.dumps(
                            {
                                "status": "ok",
                                "provider": result.provider,
                                "evidence_class": "live_host_proof",
                                "executed_tests": 1,
                                "skipped_tests": 0,
                                "live_operations": len(operation.get("api_calls") or []),
                                "actions": ["manual_map", "manual_unmap"],
                            },
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
            finally:
                if (
                    result is not None
                    and rollback is None
                    and result.rollback_plan.get("supported")
                    and result.rollback_plan.get("mapping_release_required")
                ):
                    provider.rollback(result)
                if child.poll() is None:
                    if child.stdin is not None:
                        try:
                            child.stdin.write("\n")
                            child.stdin.flush()
                        except (BrokenPipeError, OSError):
                            pass
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    unittest.main()
