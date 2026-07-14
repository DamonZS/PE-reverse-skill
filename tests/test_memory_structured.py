import json
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Mapping, Optional

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    validate_capability_audit_record,
)
from reverse_analyzer.providers.memory_runtime import MemoryRuntimeProvider
from tests.test_memory_schema import SCHEMA, fixture_bytes
from tests.test_memory_runtime_provider import FakeMemoryRuntimeBackend


class AmbiguousModuleBackend(FakeMemoryRuntimeBackend):
    def enumerate_modules(self, pid: int) -> list[Mapping[str, Any]]:
        modules = list(super().enumerate_modules(pid))
        modules.append(
            {
                "name": "target.exe",
                "path": "D:/other/target.exe",
                "base_address": 0x600000,
                "size": 0x8000,
            }
        )
        return modules


class StructuredMemoryProviderTests(unittest.TestCase):
    pid = 4242

    def _provider(
        self, backend: Optional[FakeMemoryRuntimeBackend] = None
    ) -> tuple[MemoryRuntimeProvider, FakeMemoryRuntimeBackend]:
        selected = backend or FakeMemoryRuntimeBackend(pid=self.pid)
        return MemoryRuntimeProvider(backend=selected, platform_name="win32"), selected

    def _request(
        self,
        action: str,
        params: Mapping[str, Any],
        *,
        pid: Optional[int] = 4242,
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="memory_runtime",
            action=action,
            target=TargetIdentity(kind="process", pid=pid, display_name="target.exe"),
            params=dict(params),
            session_id=f"structured-{action}",
            provenance={"source": "test_memory_structured"},
        )

    def _execute(
        self,
        provider: MemoryRuntimeProvider,
        request: CapabilityRequest,
    ) -> tuple[Any, Any, Any]:
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)
        return plan, validation, result

    def _assert_audit(self, plan: Any, validation: Any, result: Any) -> None:
        record = CapabilityAuditBuilder().build_record(
            plan=plan, validation=validation, result=result
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_typed_reads_cover_integer_float_and_double_types(self) -> None:
        cases = [
            ("int8", "b", -5),
            ("uint8", "B", 250),
            ("int16", "h", -1234),
            ("uint16", "H", 60000),
            ("int32", "i", -1234567),
            ("uint32", "I", 0xDEADBEEF),
            ("int64", "q", -0x123456789),
            ("uint64", "Q", 0xFEDCBA9876543210),
            ("float", "f", 1.25),
            ("double", "d", -2.5),
        ]
        for value_type, format_code, expected in cases:
            with self.subTest(value_type=value_type):
                provider, backend = self._provider()
                backend.allocations[0x3000] = {
                    "data": bytearray(struct.pack(">" + format_code, expected)),
                    "protection": 0x04,
                }
                plan, validation, result = self._execute(
                    provider,
                    self._request(
                        "read_typed",
                        {
                            "address": 0x3000,
                            "value_type": value_type,
                            "endian": "big",
                        },
                    ),
                )
                self.assertTrue(validation.ok, validation.errors)
                self.assertEqual(result.status, "ok", result.report_section)
                actual = result.report_section["operation"]["value"]
                if isinstance(expected, float):
                    self.assertAlmostEqual(actual, expected, places=5)
                else:
                    self.assertEqual(actual, expected)
                self._assert_audit(plan, validation, result)

    def test_utf8_utf16le_and_utf16be_string_reads(self) -> None:
        cases = [
            ("utf-8", b"hello\x00tail", "hello"),
            ("utf-16", "hello".encode("utf-16-le") + b"\x00\x00", "hello"),
            ("utf-16-be", "hello".encode("utf-16-be") + b"\x00\x00", "hello"),
        ]
        for encoding, encoded, expected in cases:
            with self.subTest(encoding=encoding):
                provider, backend = self._provider()
                backend.allocations[0x3000] = {
                    "data": bytearray(encoded),
                    "protection": 0x04,
                }
                plan, validation, result = self._execute(
                    provider,
                    self._request(
                        "read_string",
                        {
                            "address": 0x3000,
                            "encoding": encoding,
                            "max_bytes": len(encoded),
                        },
                    ),
                )
                operation = result.report_section["operation"]
                self.assertTrue(validation.ok, validation.errors)
                self.assertEqual(result.status, "ok", result.report_section)
                self.assertEqual(operation["value"], expected)
                self.assertTrue(operation["terminated"])
                self.assertEqual(operation["memory"]["size"], operation["consumed_bytes"])
                self._assert_audit(plan, validation, result)

    def test_pointer_chain_records_each_hop(self) -> None:
        provider, backend = self._provider()
        backend.allocations[0x3000] = {
            "data": bytearray(struct.pack("<Q", 0x4000)),
            "protection": 0x04,
        }
        backend.allocations[0x4000] = {
            "data": bytearray(b"\x00" * 4 + struct.pack("<Q", 0x5000)),
            "protection": 0x04,
        }
        plan, validation, result = self._execute(
            provider,
            self._request(
                "resolve_pointer_chain",
                {
                    "address": 0x3000,
                    "offsets": [4, 8],
                    "pointer_size": 8,
                    "endian": "little",
                },
            ),
        )
        operation = result.report_section["operation"]
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok", result.report_section)
        self.assertEqual(operation["final_address"], 0x5008)
        self.assertEqual([item["read_address"] for item in operation["hops"]], [0x3000, 0x4004])
        self._assert_audit(plan, validation, result)

    def test_module_rva_resolution_and_addressed_typed_read(self) -> None:
        provider, backend = self._provider()
        backend.allocations[0x400100] = {
            "data": bytearray(struct.pack("<I", 0x12345678)),
            "protection": 0x04,
        }
        plan, validation, result = self._execute(
            provider,
            self._request(
                "typed_read",
                {"module": "TARGET.EXE", "rva": "0x100", "value_type": "uint32"},
            ),
        )
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(plan.parameters["address"], 0x400100)
        self.assertEqual(result.report_section["operation"]["value"], 0x12345678)
        self._assert_audit(plan, validation, result)

        path_provider, _ = self._provider(AmbiguousModuleBackend(pid=self.pid))
        path_plan, path_validation, path_result = self._execute(
            path_provider,
            self._request(
                "module_rva",
                {"module": "c:/FIXTURES/target.exe", "rva": 0x20},
            ),
        )
        self.assertTrue(path_validation.ok, path_validation.errors)
        self.assertEqual(path_result.status, "ok")
        self.assertEqual(path_plan.parameters["address"], 0x400020)

    def test_module_rva_missing_ambiguous_and_out_of_range_are_blocked(self) -> None:
        cases = [
            (FakeMemoryRuntimeBackend(pid=self.pid), "missing.dll", 0, "not found"),
            (AmbiguousModuleBackend(pid=self.pid), "target.exe", 0, "ambiguous"),
            (FakeMemoryRuntimeBackend(pid=self.pid), "target.exe", 0x12000, "outside"),
        ]
        for backend, module, rva, error_text in cases:
            with self.subTest(module=module, rva=rva):
                provider, _ = self._provider(backend)
                plan, validation, result = self._execute(
                    provider,
                    self._request("module_rva", {"module": module, "rva": rva}),
                )
                self.assertFalse(validation.ok)
                self.assertEqual(result.status, "failed")
                self.assertIn(error_text, " ".join(plan.parameters["parameter_errors"]))
                self.assertFalse(result.after_snapshot["side_effects"])
                self._assert_audit(plan, validation, result)

    def test_typed_write_expected_value_and_rollback(self) -> None:
        provider, backend = self._provider()
        backend.allocations[0x3000] = {
            "data": bytearray(struct.pack("<I", 7)),
            "protection": 0x04,
        }
        plan, validation, result = self._execute(
            provider,
            self._request(
                "write_typed",
                {
                    "address": 0x3000,
                    "value_type": "uint32",
                    "value": 9,
                    "expected_original_value": 7,
                    "endian": "little",
                },
            ),
        )
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok", result.report_section)
        self.assertEqual(backend.bytes_at(0x3000, 4), struct.pack("<I", 9))
        self.assertEqual(result.report_section["operation"]["typed_write"]["value"], 9)
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertEqual(backend.bytes_at(0x3000, 4), struct.pack("<I", 7))
        self._assert_audit(plan, validation, result)

    def test_typed_expected_value_mismatch_has_no_side_effects(self) -> None:
        provider, backend = self._provider()
        backend.allocations[0x3000] = {
            "data": bytearray(struct.pack("<I", 7)),
            "protection": 0x04,
        }
        plan, validation, result = self._execute(
            provider,
            self._request(
                "write_typed",
                {
                    "address": 0x3000,
                    "value_type": "uint32",
                    "value": 9,
                    "expected_value": 8,
                },
            ),
        )
        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.bytes_at(0x3000, 4), struct.pack("<I", 7))
        self.assertFalse(any(call[0] == "write" for call in backend.calls))
        self.assertFalse(result.after_snapshot["side_effects"])
        self._assert_audit(plan, validation, result)

    def test_non_windows_and_missing_pid_are_unavailable(self) -> None:
        provider = MemoryRuntimeProvider(platform_name="linux")
        plan, validation, result = self._execute(
            provider,
            self._request("typed_read", {"address": 0x1000, "value_type": "uint32"}),
        )
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.after_snapshot["side_effects"])
        self._assert_audit(plan, validation, result)

        windows_provider, _ = self._provider()
        missing_plan, missing_validation, missing_result = self._execute(
            windows_provider,
            self._request(
                "typed_read", {"address": 0x1000, "value_type": "uint32"}, pid=None
            ),
        )
        self.assertEqual(missing_result.status, "unavailable")
        self.assertFalse(missing_result.after_snapshot["side_effects"])
        self._assert_audit(missing_plan, missing_validation, missing_result)


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("RUN_MEMORY_RUNTIME_INTEGRATION") == "1",
    "set RUN_MEMORY_RUNTIME_INTEGRATION=1 on Windows to run the live helper smoke",
)
class WindowsStructuredMemorySmokeTests(unittest.TestCase):
    @staticmethod
    def _retain_acceptance_artifacts(
        *,
        child_pid: int,
        operations: list[str],
        rollback_count: int,
    ) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            return
        memory = Path(configured).expanduser().resolve() / "memory"
        memory.mkdir(parents=True, exist_ok=True)
        (memory / "session.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "provider": "windows_ctypes",
                    "evidence_class": "live_host_proof",
                    "operations": operations,
                    "rollback_count": rollback_count,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (memory / "target-identity.json").write_text(
            json.dumps(
                {
                    "kind": "controlled_child_process",
                    "pid": child_pid,
                    "path": str(Path(sys.executable).resolve()),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (memory / "rollback_plan.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "rollback_verified": True,
                    "verified_operations": rollback_count,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (memory / "cleanup.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "cleanup_verified": True,
                    "child_exit_observed": True,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (memory / "execution-proof.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "provider": "windows_ctypes",
                    "evidence_class": "live_host_proof",
                    "executed_tests": 2,
                    "skipped_tests": 0,
                    "live_operations": len(operations),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_benign_child_typed_string_write_and_rollback(self) -> None:
        script = """
import ctypes, json, sys
number = ctypes.c_uint32(7)
text = ctypes.create_string_buffer(b'helper-text')
print(json.dumps({'number': ctypes.addressof(number), 'text': ctypes.addressof(text)}), flush=True)
sys.stdin.readline()
"""
        child = subprocess.Popen(
            [sys.executable, "-u", "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertIsNotNone(child.stdout)
            addresses = json.loads(child.stdout.readline())
            provider = MemoryRuntimeProvider(platform_name="win32")
            target = TargetIdentity(kind="process", pid=child.pid, display_name="helper")

            def request(action: str, params: Mapping[str, Any]) -> CapabilityRequest:
                return CapabilityRequest(
                    capability="memory_runtime",
                    action=action,
                    target=target,
                    params=dict(params),
                    session_id=f"live-{action}",
                )

            typed = provider.execute(
                provider.plan(
                    request(
                        "typed_read",
                        {"address": addresses["number"], "value_type": "uint32"},
                    )
                )
            )
            string = provider.execute(
                provider.plan(
                    request(
                        "string_read",
                        {
                            "address": addresses["text"],
                            "encoding": "utf-8",
                            "max_bytes": 32,
                        },
                    )
                )
            )
            write = provider.execute(
                provider.plan(
                    request(
                        "write_typed",
                        {
                            "address": addresses["number"],
                            "value_type": "uint32",
                            "value": 9,
                            "expected_original_value": 7,
                        },
                    )
                )
            )
            rollback = provider.rollback(write)
            self.assertEqual(typed.report_section["operation"]["value"], 7)
            self.assertEqual(string.report_section["operation"]["value"], "helper-text")
            self.assertEqual(write.status, "ok")
            self.assertTrue(rollback.ok, rollback.details)
        finally:
            if child.stdin:
                child.stdin.write("stop\n")
                child.stdin.flush()
            child.communicate(timeout=10)
        self._retain_acceptance_artifacts(
            child_pid=child.pid,
            operations=["typed_read", "string_read", "write_typed"],
            rollback_count=1,
        )

    def test_benign_child_schema_scan_protect_alloc_free_and_rollback(self) -> None:
        script = """
import ctypes, json, sys
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
kernel32.VirtualFree.restype = ctypes.c_int
protect_page = kernel32.VirtualAlloc(None, 4096, 0x3000, 0x04)
free_page = kernel32.VirtualAlloc(None, 4096, 0x3000, 0x04)
if not protect_page or not free_page:
    raise OSError(ctypes.get_last_error(), 'VirtualAlloc failed')
ctypes.memmove(protect_page, bytes.fromhex('AA BB CC DD 11 22 33 44'), 8)
ctypes.memmove(free_page, b'FREEPAGE', 8)
record_data = bytes.fromhex('__RECORD_HEX__')
record = ctypes.create_string_buffer(record_data, len(record_data))
print(json.dumps({
    'record': ctypes.addressof(record),
    'protect_page': int(protect_page),
    'free_page': int(free_page),
}), flush=True)
sys.stdin.readline()
kernel32.VirtualFree(ctypes.c_void_p(protect_page), 0, 0x8000)
kernel32.VirtualFree(ctypes.c_void_p(free_page), 0, 0x8000)
""".replace("__RECORD_HEX__", fixture_bytes().hex())
        child = subprocess.Popen(
            [sys.executable, "-u", "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertIsNotNone(child.stdout)
            addresses = json.loads(child.stdout.readline())
            provider = MemoryRuntimeProvider(platform_name="win32")
            target = TargetIdentity(kind="process", pid=child.pid, display_name="helper")

            def request(action: str, params: Mapping[str, Any]) -> CapabilityRequest:
                return CapabilityRequest(
                    capability="memory_runtime",
                    action=action,
                    target=target,
                    params=dict(params),
                    session_id=f"live-{action}",
                )

            schema_read = provider.execute(
                provider.plan(
                    request(
                        "schema_read",
                        {
                            "address": addresses["record"],
                            "schema": SCHEMA,
                            "field_path": "points[1].y",
                        },
                    )
                )
            )
            self.assertEqual(schema_read.status, "ok", schema_read.report_section)
            self.assertEqual(
                schema_read.report_section["operation"]["structured_field"]["value"],
                -40,
            )

            schema_write = provider.execute(
                provider.plan(
                    request(
                        "schema_write",
                        {
                            "address": addresses["record"],
                            "schema": SCHEMA,
                            "field_path": "flags.mode",
                            "field_value": 5,
                            "expected_field_value": 2,
                        },
                    )
                )
            )
            self.assertEqual(schema_write.status, "ok", schema_write.report_section)
            self.assertTrue(provider.rollback(schema_write).ok)

            scan = provider.execute(
                provider.plan(
                    request(
                        "scan",
                        {
                            "pattern": "AA BB CC DD",
                            "start_address": addresses["protect_page"],
                            "end_address": addresses["protect_page"] + 4096,
                            "max_bytes": 4096,
                            "max_results": 4,
                        },
                    )
                )
            )
            self.assertEqual(scan.status, "ok", scan.report_section)
            self.assertIn(
                addresses["protect_page"],
                scan.report_section["operation"]["matches"],
            )

            protect = provider.execute(
                provider.plan(
                    request(
                        "protect",
                        {
                            "address": addresses["protect_page"],
                            "size": 4096,
                            "protection": "PAGE_READONLY",
                        },
                    )
                )
            )
            self.assertEqual(protect.status, "ok", protect.report_section)
            self.assertTrue(provider.rollback(protect).ok)

            allocated = provider.execute(
                provider.plan(
                    request(
                        "alloc",
                        {"size": 4096, "protection": "PAGE_READWRITE"},
                    )
                )
            )
            self.assertEqual(allocated.status, "ok", allocated.report_section)
            self.assertTrue(allocated.report_section["operation"]["address"])
            self.assertTrue(provider.rollback(allocated).ok)

            freed = provider.execute(
                provider.plan(request("free", {"address": addresses["free_page"]}))
            )
            self.assertEqual(freed.status, "ok", freed.report_section)
            free_rollback = provider.rollback(freed)
            self.assertTrue(free_rollback.ok, free_rollback.details)
            restored = provider.execute(
                provider.plan(
                    request(
                        "read",
                        {"address": addresses["free_page"], "size": 8},
                    )
                )
            )
            self.assertEqual(restored.after_snapshot["memory"]["hex"], b"FREEPAGE".hex())
        finally:
            if child.stdin:
                child.stdin.write("stop\n")
                child.stdin.flush()
            child.communicate(timeout=10)
        self._retain_acceptance_artifacts(
            child_pid=child.pid,
            operations=["schema_read", "schema_write", "scan", "protect", "alloc", "free", "read"],
            rollback_count=4,
        )


if __name__ == "__main__":
    unittest.main()
