import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping, Optional

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    validate_capability_audit_record,
)
from reverse_analyzer.providers.injector import (
    InjectorMockProvider,
    InjectorProvider,
    WindowsInjectorBackend,
)
from reverse_analyzer.providers.injector_manual_map import inspect_manual_map_image


class FakeInjectorBackend:
    name = "fake_windows"

    def __init__(
        self,
        *,
        available: bool = True,
        process_accessible: bool = True,
        load_ok: bool = True,
        publish_module: bool = True,
        free_library_ok: bool = True,
        memory_release_ok: bool = True,
        machine: int = 0x8664,
        manual_map_ok: bool = True,
        manual_evidence_complete: bool = True,
        manual_evidence_failure: Optional[str] = None,
        manual_rollback_ok: bool = True,
    ) -> None:
        self.available = available
        self.unavailable_reason = None if available else "fake backend disabled"
        self.process_accessible = process_accessible
        self.load_ok = load_ok
        self.publish_module = publish_module
        self.free_library_ok = free_library_ok
        self.memory_release_ok = memory_release_ok
        self.machine = machine
        self.manual_map_ok = manual_map_ok
        self.manual_evidence_complete = manual_evidence_complete
        self.manual_evidence_failure = manual_evidence_failure
        self.manual_rollback_ok = manual_rollback_ok
        self.modules: list[dict[str, Any]] = [
            {
                "name": "target.exe",
                "path": "C:/targets/target.exe",
                "base_address": 0x400000,
                "size": 0x10000,
            }
        ]
        self.calls: list[tuple[Any, ...]] = []
        self.remote_allocation = 0x71000000
        self.module_handle = 0x72000000
        self.manual_image_base = 0x73000000

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        return {
            "pid": pid,
            "exists": self.process_accessible,
            "accessible": self.process_accessible,
            "status": "ok" if self.process_accessible else "failed",
            "identity_status": "ok" if self.process_accessible else "failed",
            "creation_time_100ns": 133713371337,
            "image_path": "C:/targets/target.exe",
            "machine": self.machine,
            "machine_hex": f"0x{self.machine:04x}",
            "architecture": "x86" if self.machine == 0x014C else "x64",
        }

    def list_modules(self, pid: int) -> list[Mapping[str, Any]]:
        self.calls.append(("list_modules", pid))
        return [dict(item) for item in self.modules]

    def load_library(self, pid: int, dll_path: str, timeout_ms: int) -> Mapping[str, Any]:
        self.calls.append(("load_library", pid, dll_path, timeout_ms))
        if self.load_ok and self.publish_module:
            self.modules.append(
                {
                    "name": Path(dll_path).name,
                    "path": dll_path,
                    "base_address": self.module_handle,
                    "size": 0x9000,
                }
            )
        return {
            "ok": self.load_ok,
            "status": "ok" if self.load_ok else "failed",
            "method": "load_library",
            "pid": pid,
            "dll_path": dll_path,
            "thread_id": 73,
            "thread_exit_code": self.module_handle if self.load_ok else 0,
            "remote_allocation": self.remote_allocation,
            "temporary_memory_retained": self.load_ok,
            "temporary_memory_released": False,
            "safe_to_release": True,
            "api_calls": [
                {"api": "OpenProcess", "status": "ok"},
                {"api": "VirtualAllocEx", "status": "ok"},
                {"api": "WriteProcessMemory", "status": "ok"},
                {"api": "CreateRemoteThread", "status": "ok"},
            ],
            "error": None if self.load_ok else "fake LoadLibraryW failure",
        }

    def rollback_load_library(
        self,
        pid: int,
        module_handle: Optional[int],
        remote_allocation: Optional[int],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "rollback_load_library",
                pid,
                module_handle,
                remote_allocation,
                timeout_ms,
            )
        )
        if self.free_library_ok:
            self.modules = [
                item for item in self.modules if item.get("base_address") != module_handle
            ]
        return {
            "ok": self.free_library_ok and self.memory_release_ok,
            "status": "ok" if self.free_library_ok and self.memory_release_ok else "failed",
            "free_library_attempted": module_handle is not None,
            "free_library_ok": self.free_library_ok,
            "memory_release_attempted": remote_allocation is not None,
            "memory_released": self.memory_release_ok,
            "api_calls": [
                {"api": "FreeLibrary", "status": "ok" if self.free_library_ok else "failed"},
                {
                    "api": "VirtualFreeEx",
                    "status": "ok" if self.memory_release_ok else "failed",
                },
            ],
        }

    def release_remote_memory(self, pid: int, remote_allocation: int) -> Mapping[str, Any]:
        self.calls.append(("release_remote_memory", pid, remote_allocation))
        return {
            "ok": self.memory_release_ok,
            "status": "ok" if self.memory_release_ok else "failed",
            "memory_release_attempted": True,
            "memory_released": self.memory_release_ok,
        }

    def manual_map(
        self,
        pid: int,
        dll_path: str,
        expected_sha256: str,
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "manual_map",
                pid,
                dll_path,
                expected_sha256,
                dict(expected_identity),
                timeout_ms,
            )
        )
        assessment = inspect_manual_map_image(dll_path)
        mapped_sha256 = "a" * 64
        operation: dict[str, Any] = {
            "ok": self.manual_map_ok,
            "status": "ok" if self.manual_map_ok else "failed",
            "method": "manual_map",
            "pid": pid,
            "dll_path": dll_path,
            "dll_sha256": expected_sha256,
            "target_identity": dict(expected_identity),
            "target_identity_verified": True,
            "image": assessment,
            "image_base": self.manual_image_base,
            "image_size": assessment.get("size_of_image"),
            "entry_point_address": self.manual_image_base
            + int(assessment.get("entry_point_rva") or 0),
            "headers_sections": {
                "complete": True,
                "header_bytes": assessment.get("size_of_headers"),
                "section_count": assessment.get("section_count"),
                "mapped_size": assessment.get("size_of_image"),
            },
            "relocations": {
                "required": False,
                "delta": 0,
                "available_count": assessment.get("relocation_count"),
                "applied_count": 0,
                "complete": True,
            },
            "imports": {
                "module_count": assessment.get("import_module_count"),
                "expected_count": assessment.get("import_symbol_count"),
                "resolved_count": assessment.get("import_symbol_count"),
                "complete": True,
            },
            "readback": {
                "complete": True,
                "mapped_sha256": mapped_sha256,
                "readback_sha256": mapped_sha256,
            },
            "protections": {
                "complete": True,
                "range_count": assessment.get("protection_range_count"),
                "applied_count": assessment.get("protection_range_count"),
                "writable_executable": False,
                "instruction_cache_flushed": True,
            },
            "entrypoint": {
                "required": bool(assessment.get("entry_point_rva")),
                "called": bool(assessment.get("entry_point_rva")),
                "completed": True,
                "attach_returned": True,
            },
            "dependencies": [],
            "rollback": {
                "safe_to_unmap": True,
                "image_base": self.manual_image_base,
                "image_size": assessment.get("size_of_image"),
                "entry_point_address": self.manual_image_base
                + int(assessment.get("entry_point_rva") or 0),
                "architecture": assessment.get("architecture"),
                "attach_succeeded": True,
                "dependencies": [],
                "target_identity": dict(expected_identity),
            },
            "side_effects": self.manual_map_ok,
            "image_retained": self.manual_map_ok,
            "error": None if self.manual_map_ok else "fake manual-map failure",
        }
        evidence_failure = self.manual_evidence_failure
        if not self.manual_evidence_complete and evidence_failure is None:
            evidence_failure = "readback"
        if evidence_failure == "readback":
            operation["readback"] = {"complete": False}
        elif evidence_failure == "relocations":
            operation["relocations"] = {"complete": False}
        elif evidence_failure == "imports":
            operation["imports"] = {"complete": False}
        elif evidence_failure == "protections":
            operation["protections"] = {"complete": False}
        elif evidence_failure == "entrypoint":
            operation["entrypoint"] = {
                "required": True,
                "called": True,
                "completed": False,
                "attach_returned": False,
            }
        return operation

    def rollback_manual_map(
        self,
        pid: int,
        mapping: Mapping[str, Any],
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "rollback_manual_map",
                pid,
                dict(mapping),
                dict(expected_identity),
                timeout_ms,
            )
        )
        return {
            "ok": self.manual_rollback_ok,
            "status": "ok" if self.manual_rollback_ok else "failed",
            "target_identity": dict(expected_identity),
            "target_identity_verified": True,
            "detach": {"required": True, "completed": self.manual_rollback_ok},
            "mapping_release_attempted": True,
            "mapping_released": self.manual_rollback_ok,
            "release_verified": self.manual_rollback_ok,
            "before_region": {"state": 0x1000, "state_name": "MEM_COMMIT"},
            "after_region": {
                "state": 0x10000 if self.manual_rollback_ok else 0x1000,
                "state_name": "MEM_FREE" if self.manual_rollback_ok else "MEM_COMMIT",
            },
            "dependencies": [],
            "dependencies_released": self.manual_rollback_ok,
        }


class InjectorProviderTests(unittest.TestCase):
    pid = 4242
    _REPORT_AUDIT_FIELDS = {
        "session_id",
        "target_identity",
        "precondition_hash",
        "before_snapshot",
        "after_snapshot",
        "rollback_plan",
        "provenance",
        "artifacts",
        "evidence_manifest_entries",
    }

    @staticmethod
    def _write_dll(path: Path, payload: bytes = b"MZ\x90\x00fake-dll") -> str:
        path.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _write_manual_map_dll(
        path: Path,
        *,
        machine: int = 0x8664,
        unsupported_directory: Optional[int] = None,
    ) -> str:
        pe32_plus = machine == 0x8664
        optional_size = 0xF0 if pe32_plus else 0xE0
        directory_offset = 112 if pe32_plus else 96
        pe_offset = 0x80
        optional_offset = pe_offset + 24
        payload = bytearray(0x400)
        payload[:2] = b"MZ"
        struct.pack_into("<I", payload, 0x3C, pe_offset)
        payload[pe_offset : pe_offset + 4] = b"PE\0\0"
        characteristics = 0x2002 | (0 if pe32_plus else 0x0100)
        struct.pack_into(
            "<HHIIIHH",
            payload,
            pe_offset + 4,
            machine,
            1,
            0,
            0,
            0,
            optional_size,
            characteristics,
        )
        struct.pack_into("<H", payload, optional_offset, 0x20B if pe32_plus else 0x10B)
        struct.pack_into("<I", payload, optional_offset + 16, 0x1000)
        struct.pack_into("<I", payload, optional_offset + 20, 0x1000)
        if pe32_plus:
            struct.pack_into("<Q", payload, optional_offset + 24, 0x180000000)
            directory_count_offset = 108
        else:
            struct.pack_into("<I", payload, optional_offset + 24, 0x2000)
            struct.pack_into("<I", payload, optional_offset + 28, 0x10000000)
            directory_count_offset = 92
        struct.pack_into("<I", payload, optional_offset + 32, 0x1000)
        struct.pack_into("<I", payload, optional_offset + 36, 0x200)
        struct.pack_into("<I", payload, optional_offset + 56, 0x2000)
        struct.pack_into("<I", payload, optional_offset + 60, 0x200)
        struct.pack_into("<H", payload, optional_offset + 68, 3)
        struct.pack_into("<H", payload, optional_offset + 70, 0x0100)
        struct.pack_into("<I", payload, optional_offset + directory_count_offset, 16)
        if unsupported_directory is not None:
            entry = optional_offset + directory_offset + unsupported_directory * 8
            struct.pack_into("<II", payload, entry, 0x1000, 4)

        section = optional_offset + optional_size
        payload[section : section + 8] = b".text\0\0\0"
        struct.pack_into("<I", payload, section + 8, 0x20)
        struct.pack_into("<I", payload, section + 12, 0x1000)
        struct.pack_into("<I", payload, section + 16, 0x200)
        struct.pack_into("<I", payload, section + 20, 0x200)
        struct.pack_into("<I", payload, section + 36, 0x60000020)
        if pe32_plus:
            payload[0x200 : 0x206] = b"\xB8\x01\x00\x00\x00\xC3"
        else:
            payload[0x200 : 0x208] = b"\xB8\x01\x00\x00\x00\xC2\x0C\x00"
        path.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    def _request(
        self,
        dll_path: Path,
        dll_sha256: str,
        *,
        method: str = "load_library",
        pid: Any = None,
        session_id: str = "injector-test",
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="injector",
            action=method,
            target=TargetIdentity(
                kind="process",
                pid=self.pid if pid is None else pid,
                display_name="target.exe",
            ),
            params={
                "method": method,
                "dll_path": str(dll_path),
                "dll_sha256": dll_sha256,
                "timeout_ms": 2500,
            },
            session_id=session_id,
            provenance={"source": "test_injector_provider"},
        )

    @staticmethod
    def _checks(validation: Any) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in validation.checks}

    @staticmethod
    def _calls(backend: FakeInjectorBackend, name: str) -> list[tuple[Any, ...]]:
        return [item for item in backend.calls if item[0] == name]

    def _assert_audit_contract(self, plan: Any, validation: Any, result: Any) -> None:
        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_acceptance_runner_retains_real_loadlibrary_artifacts(self) -> None:
        configured = str(
            os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or ""
        ).strip()
        if not configured:
            return
        self.assertEqual(sys.platform, "win32")

        acceptance_root = Path(configured).expanduser().resolve()
        session_id = str(
            os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID")
            or "p1-loadlibrary-injector"
        )
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os,sys; print(os.getpid(), flush=True); sys.stdin.readline()",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
        )
        result = None
        rollback = None
        try:
            assert child.stdout is not None
            self.assertEqual(int(child.stdout.readline().strip()), child.pid)
            self.assertIsNone(child.poll())

            backend = WindowsInjectorBackend()
            self.assertIs(type(backend), WindowsInjectorBackend)
            self.assertTrue(backend.available, backend.unavailable_reason)
            loaded = {
                str(item.get("name") or "").casefold()
                for item in backend.list_modules(child.pid)
            }
            system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
            candidates = (
                "winhttp.dll",
                "wininet.dll",
                "winmm.dll",
                "dbghelp.dll",
                "urlmon.dll",
            )
            dll_path = next(
                (
                    (system32 / name).resolve()
                    for name in candidates
                    if name.casefold() not in loaded and (system32 / name).is_file()
                ),
                None,
            )
            self.assertIsNotNone(dll_path, "no unloaded system DLL is available")
            assert dll_path is not None
            dll_sha256 = hashlib.sha256(dll_path.read_bytes()).hexdigest()
            target_path = Path(sys.executable).resolve()
            target_sha256 = hashlib.sha256(target_path.read_bytes()).hexdigest()
            provider = InjectorProvider(
                backend=backend,
                platform_name="win32",
                timeout_ms=10_000,
            )
            request = CapabilityRequest(
                capability="injector",
                action="load_library",
                target=TargetIdentity(
                    kind="controlled_child_process",
                    pid=child.pid,
                    path=str(target_path),
                    sha256=target_sha256,
                    display_name=target_path.name,
                ),
                params={
                    "method": "load_library",
                    "dll_path": str(dll_path),
                    "dll_sha256": dll_sha256,
                    "timeout_ms": 10_000,
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
            self.assertEqual(result.provenance["backend"]["name"], "windows_ctypes")
            self.assertTrue(
                result.after_snapshot["module_evidence"]["observed_transition"]
            )

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok, rollback.details)
            self.assertTrue(rollback.restored, rollback.details)
            self.assertTrue(rollback.details["module_absent_after"])
            bundle = provider.collect_artifacts(result, str(acceptance_root))
            provider_audit = acceptance_root / bundle.artifacts[0].path
            self.assertTrue(provider_audit.is_file())

            evidence = acceptance_root / "injector"
            evidence.mkdir(parents=True, exist_ok=True)
            (evidence / "audit.json").write_bytes(provider_audit.read_bytes())
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
                        "module_absent_after": bool(
                            rollback.details.get("module_absent_after")
                        ),
                        "temporary_memory_released": bool(
                            rollback.details.get("temporary_memory_released")
                        ),
                        "details": rollback.details,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            operation = result.after_snapshot.get("operation") or {}
            rollback_operation = rollback.details.get("operation") or {}
            (evidence / "execution-proof.json").write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "provider": result.provider,
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": len(operation.get("api_calls") or [])
                        + len(rollback_operation.get("api_calls") or []),
                        "actions": ["load_library", "free_library"],
                        "synthetic": False,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        finally:
            if result is not None and rollback is None and result.rollback_plan.get(
                "supported"
            ):
                provider.rollback(result)
            if child.poll() is None and child.stdin is not None:
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

        self.assertIsNotNone(child.returncode)
        cleanup = acceptance_root / "injector" / "cleanup.json"
        cleanup.write_text(
            json.dumps(
                {
                    "status": "ok",
                    "verified": True,
                    "child_process_exited": child.returncode is not None,
                    "returncode": child.returncode,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_load_library_plan_and_validate_pin_identity_and_control_steps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            request = self._request(dll_path.resolve(), dll_sha256)

            self.assertTrue(provider.supports(request))
            plan = provider.plan(request)
            validation = provider.validate(plan)

            self.assertEqual(plan.provider, "windows_controlled_injector")
            self.assertEqual(plan.action, "load_library")
            self.assertEqual(plan.precondition_hash, dll_sha256)
            self.assertEqual(plan.parameters["dll_path"], str(dll_path.resolve()))
            self.assertTrue(plan.parameters["dll_path_is_absolute"])
            self.assertEqual(plan.parameters["pid"], self.pid)
            self.assertEqual(plan.rollback_plan["mode"], "remote_free_library")
            step_names = {item["step"] for item in plan.steps}
            self.assertTrue(
                {
                    "OpenProcess",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "capture_modules_before",
                    "capture_modules_after",
                }
                <= step_names
            )
            self.assertTrue(validation.ok, validation.errors)
            checks = self._checks(validation)
            for name in (
                "target_pid",
                "dll_absolute_path",
                "dll_file",
                "dll_mz_signature",
                "dll_precondition_sha256",
                "dll_declared_sha256",
                "target_process_access",
                "module_snapshot_before",
                "risk_assessment_schema",
            ):
                self.assertEqual(checks[name]["status"], "ok", name)

    def test_validation_rejects_invalid_pid_path_mz_and_declared_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dll_path = root / "not-a-dll.bin"
            actual_hash = self._write_dll(dll_path, b"NO-not-a-pe")
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            request = self._request(dll_path.resolve(), "f" * 64, pid=0)
            plan = provider.plan(request)
            plan.parameters["declared_dll_path"] = dll_path.name

            validation = provider.validate(plan)

            self.assertFalse(validation.ok)
            self.assertEqual(plan.precondition_hash, actual_hash)
            checks = self._checks(validation)
            self.assertEqual(checks["target_pid"]["status"], "failed")
            self.assertEqual(checks["dll_absolute_path"]["status"], "failed")
            self.assertEqual(checks["dll_mz_signature"]["status"], "failed")
            self.assertEqual(checks["dll_declared_sha256"]["status"], "failed")
            self.assertFalse(self._calls(backend, "load_library"))

    def test_validation_and_execute_block_tampered_planned_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            plan = provider.plan(self._request(dll_path.resolve(), dll_sha256))
            plan.parameters["pid"] = self.pid + 1

            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertFalse(validation.ok)
            pid_check = self._checks(validation)["target_pid"]
            self.assertEqual(pid_check["status"], "failed")
            self.assertFalse(pid_check["matches_planned_identity"])
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.report_section["operation"]["side_effects"])
            self.assertFalse(result.rollback_plan["supported"])
            self.assertEqual(result.rollback_plan["mode"], "not_required")
            self.assertFalse(self._calls(backend, "load_library"))

    def test_validation_and_execute_block_tampered_planned_dll_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dll_path = root / "payload.dll"
            replacement_path = root / "replacement.dll"
            dll_sha256 = self._write_dll(dll_path)
            self._write_dll(replacement_path)
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            plan = provider.plan(self._request(dll_path.resolve(), dll_sha256))
            plan.parameters["dll_path"] = str(replacement_path.resolve())

            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertFalse(validation.ok)
            path_check = self._checks(validation)["dll_planned_path_identity"]
            self.assertEqual(path_check["status"], "failed")
            self.assertEqual(path_check["expected"], str(dll_path.resolve()))
            self.assertEqual(path_check["actual"], str(replacement_path.resolve()))
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.report_section["operation"]["side_effects"])
            self.assertFalse(result.rollback_plan["supported"])
            self.assertEqual(result.rollback_plan["mode"], "not_required")
            self.assertFalse(self._calls(backend, "load_library"))

    def test_execute_requires_backend_result_and_exact_module_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            plan = provider.plan(self._request(dll_path.resolve(), dll_sha256))
            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertEqual(result.status, "ok")
            self.assertEqual(len(self._calls(backend, "load_library")), 1)
            evidence = result.after_snapshot["module_evidence"]
            self.assertTrue(evidence["observed_transition"])
            self.assertFalse(evidence["present_before"])
            self.assertTrue(evidence["present_after"])
            self.assertEqual(
                evidence["loaded_module"]["base_address"],
                backend.module_handle,
            )
            self.assertEqual(result.rollback_plan["module_handle"], backend.module_handle)
            self.assertEqual(
                result.rollback_plan["remote_allocation"],
                backend.remote_allocation,
            )
            self.assertEqual(result.report_section["status"], "ok")
            self.assertEqual(result.report_section["dll_sha256"], dll_sha256)
            self.assertEqual(result.dashboard_trace[0]["kind"], "injector_execution")
            self.assertTrue(result.dashboard_trace[0]["module_transition_observed"])
            self.assertEqual(result.artifacts[0].kind, "injector-audit")
            self.assertEqual(
                result.evidence_manifest_entries[0]["role"],
                "injection-audit",
            )
            self.assertTrue(
                self._REPORT_AUDIT_FIELDS <= set(result.report_section)
            )
            self._assert_audit_contract(plan, validation, result)
            serialized_result = json.dumps(result.to_dict(), sort_keys=True)
            self.assertEqual(json.loads(serialized_result)["status"], "ok")

            collection_root = Path(tmp) / "artifacts"
            bundle = provider.collect_artifacts(result, str(collection_root))
            self.assertEqual(bundle.provider, provider.provider_name)
            self.assertEqual(len(bundle.artifacts), 1)
            self.assertEqual(len(bundle.manifest_entries), 1)
            self.assertEqual(bundle.manifest_entries[0]["status"], "ok")
            artifact_path = collection_root / bundle.artifacts[0].path
            encoded = artifact_path.read_bytes()
            payload = json.loads(encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            self.assertEqual(payload["session_id"], result.session_id)
            self.assertEqual(payload["target_identity"]["pid"], self.pid)
            self.assertEqual(payload["precondition_hash"], dll_sha256)
            self.assertTrue(bundle.artifacts[0].metadata["materialized"])
            self.assertEqual(bundle.artifacts[0].metadata["sha256"], digest)
            self.assertEqual(bundle.artifacts[0].metadata["size"], len(encoded))
            self.assertEqual(bundle.manifest_entries[0]["sha256"], digest)
            self.assertEqual(bundle.manifest_entries[0]["size"], len(encoded))
            self.assertEqual(
                bundle.manifest_entries[0]["target_identity"]["pid"], self.pid
            )
            self.assertEqual(
                bundle.manifest_entries[0]["precondition_hash"], dll_sha256
            )
            self.assertEqual(result.evidence_manifest_entries, bundle.manifest_entries)

    def test_execute_fails_closed_when_backend_claims_success_without_module_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend(publish_module=False)
            provider = InjectorProvider(backend=backend, platform_name="win32")
            plan = provider.plan(self._request(dll_path.resolve(), dll_sha256))
            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertEqual(result.status, "failed")
            self.assertFalse(result.after_snapshot["module_evidence"]["observed_transition"])
            self.assertFalse(result.rollback_plan["supported"])
            self.assertEqual(len(self._calls(backend, "release_remote_memory")), 1)
            self.assertIn(
                "not observed",
                " ".join(str(item) for item in result.report_section["errors"]),
            )
            self._assert_audit_contract(plan, validation, result)

    def test_collect_artifacts_rejects_paths_outside_collection_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            provider = InjectorProvider(
                backend=FakeInjectorBackend(),
                platform_name="win32",
            )
            result = provider.execute(
                provider.plan(self._request(dll_path.resolve(), dll_sha256))
            )
            result.artifacts[0].path = "../escaped-injector-audit.json"
            collection_root = Path(tmp) / "artifacts"

            with self.assertRaisesRegex(ValueError, "collection directory"):
                provider.collect_artifacts(result, str(collection_root))
            self.assertFalse((Path(tmp) / "escaped-injector-audit.json").exists())

    def test_execute_rehashes_dll_and_blocks_mutated_precondition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            plan = provider.plan(self._request(dll_path.resolve(), dll_sha256))
            dll_path.write_bytes(b"MZ-mutated-after-plan")

            result = provider.execute(plan)

            self.assertEqual(result.status, "failed")
            self.assertFalse(self._calls(backend, "load_library"))
            self.assertIn("SHA-256", " ".join(result.report_section["validation"]["errors"]))

    def test_rollback_attempts_free_library_and_releases_temporary_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend()
            provider = InjectorProvider(backend=backend, platform_name="win32")
            result = provider.execute(provider.plan(self._request(dll_path.resolve(), dll_sha256)))

            rollback = provider.rollback(result)

            self.assertTrue(rollback.ok, rollback.details)
            self.assertTrue(rollback.restored)
            self.assertTrue(rollback.details["free_library_attempted"])
            self.assertTrue(rollback.details["free_library_ok"])
            self.assertTrue(rollback.details["memory_release_attempted"])
            self.assertTrue(rollback.details["memory_released"])
            self.assertTrue(rollback.details["module_absent_after"])
            rollback_calls = self._calls(backend, "rollback_load_library")
            self.assertEqual(len(rollback_calls), 1)
            self.assertEqual(rollback_calls[0][2], backend.module_handle)
            self.assertEqual(rollback_calls[0][3], backend.remote_allocation)
            self.assertTrue(result.rollback_plan["completed"])
            self.assertEqual(
                result.report_section["after_snapshot"], result.after_snapshot
            )
            self.assertEqual(
                result.report_section["rollback_plan"], result.rollback_plan
            )
            self.assertEqual(result.dashboard_trace[-1]["kind"], "injector_rollback")

    def test_rollback_reports_free_library_failure_but_still_releases_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend(free_library_ok=False, memory_release_ok=True)
            provider = InjectorProvider(backend=backend, platform_name="win32")
            result = provider.execute(provider.plan(self._request(dll_path.resolve(), dll_sha256)))

            rollback = provider.rollback(result)

            self.assertFalse(rollback.ok)
            self.assertFalse(rollback.restored)
            self.assertFalse(rollback.details["free_library_ok"])
            self.assertTrue(rollback.details["memory_released"])
            self.assertFalse(rollback.details["module_absent_after"])

    def test_manual_map_validates_executes_and_rolls_back_pe32_and_pe32_plus(self) -> None:
        for machine, expected_format, expected_architecture in (
            (0x014C, "PE32", "x86"),
            (0x8664, "PE32+", "x64"),
        ):
            with self.subTest(architecture=expected_architecture), tempfile.TemporaryDirectory() as tmp:
                dll_path = Path(tmp) / "payload.dll"
                dll_sha256 = self._write_manual_map_dll(dll_path, machine=machine)
                backend = FakeInjectorBackend(machine=machine)
                provider = InjectorProvider(backend=backend, platform_name="win32")
                request = self._request(
                    dll_path.resolve(),
                    dll_sha256,
                    method="manual_map",
                    session_id=f"manual-map-{expected_architecture}",
                )

                plan = provider.plan(request)
                validation = provider.validate(plan)
                result = provider.execute(plan)

                assessment = plan.provenance["manual_map_image"]
                self.assertTrue(assessment["ok"], assessment)
                self.assertEqual(assessment["format"], expected_format)
                self.assertEqual(assessment["architecture"], expected_architecture)
                risk = plan.parameters["risk_assessment"]
                self.assertEqual(risk["schema_version"], "1.0")
                self.assertEqual(risk["method"], "manual_map")
                self.assertEqual(risk["overall_severity"], "critical")
                self.assertTrue(risk["execution"]["implemented"])
                self.assertTrue(risk["execution"]["available"])
                self.assertGreaterEqual(len(risk["risks"]), 9)
                self.assertTrue(plan.rollback_plan["supported"])

                self.assertTrue(validation.ok, validation.errors)
                checks = self._checks(validation)
                self.assertEqual(checks["manual_map_pe_loader_subset"]["status"], "ok")
                self.assertEqual(checks["manual_map_executor"]["status"], "ok")
                self.assertEqual(checks["manual_map_architecture_match"]["status"], "ok")

                self.assertEqual(result.status, "ok")
                self.assertEqual(len(self._calls(backend, "manual_map")), 1)
                self.assertFalse(self._calls(backend, "load_library"))
                operation = result.after_snapshot["operation"]
                self.assertTrue(operation["headers_sections"]["complete"])
                self.assertTrue(operation["relocations"]["complete"])
                self.assertTrue(operation["imports"]["complete"])
                self.assertTrue(operation["readback"]["complete"])
                self.assertTrue(operation["protections"]["complete"])
                self.assertTrue(operation["entrypoint"]["completed"])
                self.assertTrue(result.rollback_plan["supported"])
                self.assertEqual(result.rollback_plan["mode"], "manual_unmap")
                self.assertEqual(result.artifacts[0].kind, "injector-audit")
                self._assert_audit_contract(plan, validation, result)

                rollback = provider.rollback(result)
                self.assertTrue(rollback.ok, rollback.details)
                self.assertTrue(rollback.restored)
                self.assertTrue(rollback.details["mapping_release_attempted"])
                self.assertTrue(rollback.details["mapping_released"])
                self.assertTrue(rollback.details["release_verified"])
                self.assertEqual(
                    rollback.details["operation"]["after_region"]["state_name"],
                    "MEM_FREE",
                )
                self.assertEqual(len(self._calls(backend, "rollback_manual_map")), 1)

    def test_manual_map_rejects_architecture_mismatch_before_backend_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload-x86.dll"
            dll_sha256 = self._write_manual_map_dll(dll_path, machine=0x014C)
            backend = FakeInjectorBackend(machine=0x8664)
            provider = InjectorProvider(backend=backend, platform_name="win32")
            plan = provider.plan(
                self._request(dll_path.resolve(), dll_sha256, method="manual_map")
            )

            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertFalse(validation.ok)
            self.assertEqual(
                self._checks(validation)["manual_map_architecture_match"]["status"],
                "failed",
            )
            self.assertIn("architecture", " ".join(validation.errors).lower())
            self.assertEqual(result.status, "failed")
            self.assertFalse(result.after_snapshot["side_effects"])
            self.assertFalse(self._calls(backend, "manual_map"))

    def test_manual_map_rejects_unsupported_loader_features_during_validation(self) -> None:
        unsupported = (
            (3, "exception/unwind"),
            (9, "tls"),
            (10, "load-config"),
            (13, "delay imports"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for directory, expected_error in unsupported:
                with self.subTest(directory=directory):
                    dll_path = Path(tmp) / f"unsupported-{directory}.dll"
                    dll_sha256 = self._write_manual_map_dll(
                        dll_path,
                        unsupported_directory=directory,
                    )
                    backend = FakeInjectorBackend()
                    provider = InjectorProvider(backend=backend, platform_name="win32")
                    plan = provider.plan(
                        self._request(dll_path.resolve(), dll_sha256, method="manual_map")
                    )

                    validation = provider.validate(plan)
                    result = provider.execute(plan)

                    self.assertFalse(validation.ok)
                    check = self._checks(validation)["manual_map_pe_loader_subset"]
                    self.assertEqual(check["status"], "failed")
                    self.assertIn(
                        expected_error,
                        " ".join(validation.errors).lower(),
                    )
                    self.assertEqual(result.status, "failed")
                    self.assertFalse(result.after_snapshot["side_effects"])
                    self.assertFalse(self._calls(backend, "manual_map"))

    def test_manual_map_fails_closed_on_incomplete_backend_evidence(self) -> None:
        for evidence_failure, expected_error in (
            ("readback", "readback"),
            ("protections", "page-protection"),
            ("entrypoint", "dll_process_attach"),
        ):
            with self.subTest(evidence=evidence_failure), tempfile.TemporaryDirectory() as tmp:
                dll_path = Path(tmp) / "payload.dll"
                dll_sha256 = self._write_manual_map_dll(dll_path)
                backend = FakeInjectorBackend(manual_evidence_failure=evidence_failure)
                provider = InjectorProvider(backend=backend, platform_name="win32")
                plan = provider.plan(
                    self._request(dll_path.resolve(), dll_sha256, method="manual_map")
                )

                validation = provider.validate(plan)
                result = provider.execute(plan)

                self.assertTrue(validation.ok, validation.errors)
                self.assertEqual(result.status, "failed")
                self.assertEqual(len(self._calls(backend, "manual_map")), 1)
                self.assertTrue(result.rollback_plan["supported"])
                self.assertIn(
                    expected_error,
                    " ".join(str(item) for item in result.report_section["errors"]).lower(),
                )

                rollback = provider.rollback(result)
                self.assertTrue(rollback.ok, rollback.details)
                self.assertTrue(rollback.details["mapping_released"])
                self.assertTrue(rollback.details["release_verified"])

    def test_manual_map_rollback_fails_without_release_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_manual_map_dll(dll_path)
            backend = FakeInjectorBackend(manual_rollback_ok=False)
            provider = InjectorProvider(backend=backend, platform_name="win32")
            result = provider.execute(
                provider.plan(
                    self._request(dll_path.resolve(), dll_sha256, method="manual_map")
                )
            )

            rollback = provider.rollback(result)

            self.assertEqual(result.status, "ok")
            self.assertFalse(rollback.ok)
            self.assertFalse(rollback.restored)
            self.assertFalse(rollback.details["mapping_released"])
            self.assertFalse(rollback.details["release_verified"])
            self.assertEqual(
                rollback.details["operation"]["after_region"]["state_name"],
                "MEM_COMMIT",
            )

    def test_unavailable_backend_is_graceful_and_has_no_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dll_path = Path(tmp) / "payload.dll"
            dll_sha256 = self._write_dll(dll_path)
            backend = FakeInjectorBackend(available=False)
            provider = InjectorProvider(backend=backend, platform_name="linux")
            plan = provider.plan(self._request(dll_path.resolve(), dll_sha256))

            validation = provider.validate(plan)
            result = provider.execute(plan)

            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(self._checks(validation)["windows_backend"]["status"], "unavailable")
            self.assertEqual(result.status, "unavailable")
            self.assertFalse(result.report_section["operation"]["side_effects"])
            self.assertEqual(result.report_section["platform"], "linux")
            self.assertFalse(result.rollback_plan["supported"])
            self.assertEqual(result.rollback_plan["mode"], "not_required")
            self.assertFalse(self._calls(backend, "load_library"))
            self._assert_audit_contract(plan, validation, result)

    def test_mock_provider_is_retained(self) -> None:
        provider = InjectorMockProvider()
        request = CapabilityRequest(
            capability="injector",
            action="plan",
            target=TargetIdentity(kind="process", pid=self.pid),
            session_id="mock-injector",
        )

        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertEqual(provider.provider_name, "mock")
        self.assertTrue(validation.ok)
        self.assertEqual(result.status, "mocked")


if __name__ == "__main__":
    unittest.main()
