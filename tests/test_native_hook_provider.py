from __future__ import annotations

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

from reverse_analyzer.core.capabilities.audit_contract import (
    validate_capability_audit_record,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import build_default_registry
from reverse_analyzer.providers.native_hook import (
    NativeHookProvider,
    WindowsNativeHookBackend,
)


class FakeWin32Backend:
    name = "fake_win32_native_hook"
    available = True
    unavailable_reason = None

    def __init__(self, *, architecture: str = "x64") -> None:
        self.architecture = architecture
        self.memory: dict[int, int] = {}
        self.protections: dict[int, int] = {}
        self.allocations: dict[int, int] = {}
        self.freed: list[int] = []
        self.calls: list[tuple[Any, ...]] = []
        self.process_identity = {
            "status": "ok",
            "accessible": True,
            "exists": True,
            "pid": 4242,
            "image_path": r"C:\fixtures\authorized-target.exe",
            "creation_time": 123456789,
            "architecture": architecture,
        }
        self.thread_probe: dict[str, Any] = {
            "status": "ok",
            "accessible": True,
            "pid": 4242,
            "thread_id": 77,
            "architecture": architecture,
            "hardware_breakpoint_supported": architecture == "x64",
        }
        self.trace_response: dict[str, Any] = {
            "status": "ok",
            "installed": True,
            "restored": True,
            "debug_detached": True,
            "bounded": True,
            "slot": 1,
            "duration_ms": 8,
            "events": [],
            "errors": [],
        }
        self.fail_flush_once: set[int] = set()
        self.corrupt_write_once: set[int] = set()
        self.next_allocation: Optional[int] = None

    def map(self, address: int, data: bytes, protection: int = 0x20) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value
        self.protections[address] = protection

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        return {**self.process_identity, "pid": pid}

    def probe_thread(self, pid: int, thread_id: int) -> Mapping[str, Any]:
        self.calls.append(("probe_thread", pid, thread_id))
        return {**self.thread_probe, "pid": pid, "thread_id": thread_id}

    def read(self, pid: int, address: int, size: int) -> bytes:
        self.calls.append(("read", pid, address, size))
        try:
            return bytes(self.memory[address + offset] for offset in range(size))
        except KeyError as exc:
            raise RuntimeError(f"unmapped fake memory at 0x{address:x}") from exc

    def write(self, pid: int, address: int, data: bytes) -> Mapping[str, Any]:
        payload = bytes(data)
        self.calls.append(("write", pid, address, payload))
        for offset, value in enumerate(payload):
            self.memory[address + offset] = value
        if address in self.corrupt_write_once:
            self.corrupt_write_once.remove(address)
            self.memory[address] ^= 0xFF
        return {
            "ok": True,
            "status": "ok",
            "address": address,
            "bytes_written": len(payload),
        }

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]:
        self.calls.append(("protect", pid, address, size, protection))
        old = self.protections.get(address, 0x20)
        self.protections[address] = protection
        return {
            "ok": True,
            "status": "ok",
            "address": address,
            "size": size,
            "old_protection": old,
            "new_protection": protection,
        }

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        near: Optional[int] = None,
    ) -> Mapping[str, Any]:
        address = self.next_allocation
        if address is None:
            address = (near + 0x100000) if near is not None else 0x70000000
        while address in self.allocations:
            address += 0x10000
        self.next_allocation = address + 0x10000
        self.allocations[address] = size
        self.map(address, b"\x00" * size, protection)
        self.calls.append(("alloc", pid, address, size, protection, near))
        return {
            "ok": True,
            "status": "ok",
            "address": address,
            "size": size,
            "protection": protection,
        }

    def free(self, pid: int, address: int) -> Mapping[str, Any]:
        self.calls.append(("free", pid, address))
        size = self.allocations.pop(address)
        for offset in range(size):
            self.memory.pop(address + offset, None)
        self.freed.append(address)
        return {"ok": True, "status": "ok", "address": address, "released": True}

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]:
        self.calls.append(("flush", pid, address, size))
        if address in self.fail_flush_once:
            self.fail_flush_once.remove(address)
            return {"ok": False, "status": "failed", "reason": "injected flush failure"}
        return {"ok": True, "status": "ok", "address": address, "size": size}

    def trace_hardware_breakpoint(
        self,
        pid: int,
        thread_id: int,
        address: int,
        access: str,
        size: int,
        duration_ms: int,
        max_events: int,
        *,
        slot: Optional[int] = None,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "trace_hardware_breakpoint",
                pid,
                thread_id,
                address,
                access,
                size,
                duration_ms,
                max_events,
                slot,
            )
        )
        return dict(self.trace_response)


def _request(
    action: str,
    params: Mapping[str, Any],
    *,
    session_id: str = "native-hook-test",
) -> CapabilityRequest:
    return CapabilityRequest(
        capability="native_hook",
        action=action,
        target=TargetIdentity(
            kind="process",
            pid=4242,
            display_name="authorized-target.exe",
        ),
        params=dict(params),
        session_id=session_id,
        provenance={"request_source": "unit-test"},
    )


def _vtable_params(**overrides: Any) -> dict[str, Any]:
    params = {
        "authorized": True,
        "architecture": "x64",
        "slot_address": 0x100000,
        "expected_original_pointer": 0x1122334455667788,
        "replacement_pointer": 0x8877665544332211,
        "authorization_scope": "authorized repair test",
    }
    params.update(overrides)
    return params


class NativeHookProviderTests(unittest.TestCase):
    def test_default_registry_registers_real_native_provider(self) -> None:
        registry = build_default_registry()
        self.assertIn("native_hook", registry.list_capabilities())
        self.assertEqual(
            registry.list_providers("native_hook"), ["windows_native_hook"]
        )

    def test_vtable_requires_authorization_without_mutating_process(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        backend.map(0x100000, original)
        provider = NativeHookProvider(backend, platform_name="win32")
        plan = provider.plan(
            _request("vtable_pointer", _vtable_params(authorized=False))
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.read(4242, 0x100000, 8), original)
        self.assertFalse(any(call[0] in {"write", "protect", "alloc"} for call in backend.calls))

    def test_vtable_write_verification_protection_and_rollback(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        replacement = (0x8877665544332211).to_bytes(8, "little")
        backend.map(0x100000, original, protection=0x20)
        provider = NativeHookProvider(backend, platform_name="win32")
        plan = provider.plan(_request("vtable_pointer", _vtable_params()))

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(backend.read(4242, 0x100000, 8), replacement)
        self.assertEqual(backend.protections[0x100000], 0x20)
        self.assertEqual(result.before_snapshot["current"]["memory"]["bytes_hex"], original.hex())
        self.assertEqual(result.after_snapshot["action"]["after_hex"], replacement.hex())
        self.assertEqual(result.rollback_plan["status"], "ready")

        rollback = provider.rollback(result)

        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)
        self.assertEqual(backend.read(4242, 0x100000, 8), original)
        self.assertEqual(backend.protections[0x100000], 0x20)
        self.assertEqual(result.rollback_plan["status"], "completed")
        self.assertEqual(provider.rollback(result).details["status"], "already_completed")

    def test_vtable_preimage_change_blocks_execution(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        backend.map(0x100000, original)
        provider = NativeHookProvider(backend, platform_name="win32")
        plan = provider.plan(_request("vtable_pointer", _vtable_params()))
        backend.map(0x100000, b"\xAA" * 8)
        mutation_calls = len(backend.calls)

        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.read(4242, 0x100000, 8), b"\xAA" * 8)
        self.assertFalse(
            any(
                call[0] in {"write", "protect", "alloc"}
                for call in backend.calls[mutation_calls:]
            )
        )

    def test_vtable_failed_write_verification_is_compensated(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        backend.map(0x100000, original, protection=0x20)
        backend.corrupt_write_once.add(0x100000)
        provider = NativeHookProvider(backend, platform_name="win32")

        result = provider.execute(
            provider.plan(_request("vtable_pointer", _vtable_params()))
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.read(4242, 0x100000, 8), original)
        self.assertEqual(backend.protections[0x100000], 0x20)
        self.assertEqual(result.rollback_plan["status"], "compensated")
        self.assertFalse(result.rollback_plan["active"])
        self.assertEqual(provider.rollback(result).details["status"], "already_completed")

    def test_vtable_rollback_refuses_to_overwrite_third_party_bytes(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        third_party = b"\xAA" * 8
        backend.map(0x100000, original)
        provider = NativeHookProvider(backend, platform_name="win32")
        result = provider.execute(
            provider.plan(_request("vtable_pointer", _vtable_params()))
        )
        self.assertEqual(result.status, "ok")
        backend.map(0x100000, third_party)
        rollback_call_start = len(backend.calls)

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(backend.read(4242, 0x100000, 8), third_party)
        self.assertTrue(result.rollback_plan["active"])
        self.assertFalse(
            any(
                call[0] in {"write", "protect", "free"}
                for call in backend.calls[rollback_call_start:]
            )
        )

    def test_x64_inline_trampoline_bytes_and_full_rollback(self) -> None:
        backend = FakeWin32Backend(architecture="x64")
        target = 0x140001000
        replacement = 0x180002000
        original = b"\x55\x48\x89\xE5" + b"\x90" * 10
        backend.map(target, original, protection=0x20)
        backend.next_allocation = 0x140101000
        provider = NativeHookProvider(backend, platform_name="win32")
        plan = provider.plan(
            _request(
                "inline_trampoline",
                {
                    "authorized": True,
                    "architecture": "x64",
                    "target_address": target,
                    "replacement_pointer": replacement,
                    "expected_original_bytes": original.hex(),
                },
            )
        )

        result = provider.execute(plan)

        expected_patch = b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", replacement)
        trampoline_address = result.rollback_plan["trampoline_address"]
        expected_jump_back = b"\xFF\x25\x00\x00\x00\x00" + struct.pack(
            "<Q", target + len(original)
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(backend.read(4242, target, len(original)), expected_patch)
        self.assertEqual(
            backend.read(4242, trampoline_address, len(original) + 14),
            original + expected_jump_back,
        )
        self.assertTrue(result.after_snapshot["action"]["trampoline"]["verified"])

        rollback = provider.rollback(result)

        self.assertTrue(rollback.ok)
        self.assertEqual(backend.read(4242, target, len(original)), original)
        self.assertIn(trampoline_address, backend.freed)
        self.assertFalse(result.rollback_plan["allocation_active"])

    def test_x86_inline_uses_rel32_for_patch_and_jump_back(self) -> None:
        backend = FakeWin32Backend(architecture="x86")
        target = 0x00401000
        replacement = 0x00502000
        trampoline_address = 0x00600000
        original = b"\x55\x8B\xEC\x90\x90"
        backend.map(target, original, protection=0x20)
        backend.next_allocation = trampoline_address
        provider = NativeHookProvider(backend, platform_name="win32")
        result = provider.execute(
            provider.plan(
                _request(
                    "inline_trampoline",
                    {
                        "authorized": True,
                        "architecture": "x86",
                        "target_address": target,
                        "replacement_pointer": replacement,
                        "expected_original_bytes": original.hex(),
                    },
                )
            )
        )

        expected_patch = b"\xE9" + struct.pack("<i", replacement - (target + 5))
        back_source = trampoline_address + len(original)
        expected_back = b"\xE9" + struct.pack(
            "<i", (target + len(original)) - (back_source + 5)
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(backend.read(4242, target, 5), expected_patch)
        self.assertEqual(
            backend.read(4242, trampoline_address, 10), original + expected_back
        )

    def test_inline_fails_closed_for_unrelocated_or_incomplete_instructions(self) -> None:
        cases = (
            ("x64", b"\x48\x8B\x05\x00\x00\x00\x00" + b"\x90" * 7, "RIP"),
            ("x86", b"\xE9\x00\x00\x00\x00", "control-flow"),
            ("x64", b"\x90" * 13, "complete instructions"),
        )
        for architecture, original, expected_error in cases:
            with self.subTest(architecture=architecture, original=original.hex()):
                backend = FakeWin32Backend(architecture=architecture)
                target = 0x401000
                backend.map(target, original)
                provider = NativeHookProvider(backend, platform_name="win32")
                plan = provider.plan(
                    _request(
                        "inline_trampoline",
                        {
                            "authorized": True,
                            "architecture": architecture,
                            "target_address": target,
                            "replacement_pointer": 0x501000,
                            "expected_original_bytes": original.hex(),
                        },
                    )
                )
                result = provider.execute(plan)

                self.assertEqual(result.status, "failed")
                self.assertIn(
                    expected_error.lower(),
                    json.dumps(plan.parameters["instruction_analysis"]).lower(),
                )
                self.assertEqual(backend.read(4242, target, len(original)), original)
                self.assertFalse(
                    any(call[0] in {"write", "protect", "alloc"} for call in backend.calls)
                )

    def test_inline_without_capstone_is_unavailable_without_mutation(self) -> None:
        backend = FakeWin32Backend(architecture="x64")
        target = 0x140002000
        original = b"\x55\x48\x89\xE5" + b"\x90" * 10
        backend.map(target, original)
        provider = NativeHookProvider(
            backend,
            platform_name="win32",
            capstone_module=None,
        )
        plan = provider.plan(
            _request(
                "inline_trampoline",
                {
                    "authorized": True,
                    "architecture": "x64",
                    "target_address": target,
                    "replacement_pointer": 0x180003000,
                    "expected_original_bytes": original.hex(),
                },
            )
        )

        result = provider.execute(plan)

        self.assertEqual(plan.parameters["instruction_analysis"]["status"], "unavailable")
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(backend.read(4242, target, len(original)), original)
        self.assertFalse(
            any(call[0] in {"write", "protect", "alloc"} for call in backend.calls)
        )

    def test_inline_failure_after_target_write_compensates_and_frees(self) -> None:
        backend = FakeWin32Backend(architecture="x64")
        target = 0x140003000
        original = b"\x55\x48\x89\xE5" + b"\x90" * 10
        backend.map(target, original, protection=0x20)
        backend.next_allocation = 0x140103000
        backend.fail_flush_once.add(target)
        provider = NativeHookProvider(backend, platform_name="win32")
        result = provider.execute(
            provider.plan(
                _request(
                    "inline_trampoline",
                    {
                        "authorized": True,
                        "architecture": "x64",
                        "target_address": target,
                        "replacement_pointer": 0x180004000,
                        "expected_original_bytes": original.hex(),
                    },
                )
            )
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.read(4242, target, len(original)), original)
        self.assertEqual(len(backend.freed), 1)
        self.assertFalse(result.rollback_plan["active"])
        self.assertEqual(result.rollback_plan["status"], "compensated")

    def test_inline_rollback_refuses_to_free_changed_trampoline(self) -> None:
        backend = FakeWin32Backend(architecture="x64")
        target = 0x140004000
        original = b"\x55\x48\x89\xE5" + b"\x90" * 10
        backend.map(target, original, protection=0x20)
        backend.next_allocation = 0x140104000
        provider = NativeHookProvider(backend, platform_name="win32")
        result = provider.execute(
            provider.plan(
                _request(
                    "inline_trampoline",
                    {
                        "authorized": True,
                        "architecture": "x64",
                        "target_address": target,
                        "replacement_pointer": 0x180005000,
                        "expected_original_bytes": original.hex(),
                    },
                )
            )
        )
        self.assertEqual(result.status, "ok")
        trampoline_address = result.rollback_plan["trampoline_address"]
        backend.map(trampoline_address, b"\xCC")

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(backend.read(4242, target, len(original)), original)
        self.assertNotIn(trampoline_address, backend.freed)
        self.assertIn(trampoline_address, backend.allocations)
        self.assertTrue(result.rollback_plan["allocation_active"])

    def test_hardware_breakpoint_requires_cleanup_proof(self) -> None:
        event = {
            "event": "hardware_breakpoint",
            "thread_id": 77,
            "instruction_pointer": 0x140001234,
            "slot": 1,
            "elapsed_ms": 2,
        }
        backend = FakeWin32Backend()
        backend.trace_response["events"] = [event]
        provider = NativeHookProvider(backend, platform_name="win32")
        params = {
            "authorized": True,
            "thread_id": 77,
            "address": 0x140005000,
            "access": "execute",
            "size": 1,
            "duration_ms": 20,
            "max_events": 4,
            "slot": 1,
        }

        result = provider.execute(provider.plan(_request("hardware_breakpoint", params)))

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.after_snapshot["trace_event_count"], 1)
        self.assertTrue(result.rollback_plan["restored"])
        self.assertTrue(result.rollback_plan["debug_detached"])
        self.assertEqual(provider.rollback(result).details["status"], "already_completed")

        failing_backend = FakeWin32Backend()
        failing_backend.trace_response.update(
            {"status": "ok", "installed": True, "restored": False, "debug_detached": True}
        )
        failing_provider = NativeHookProvider(failing_backend, platform_name="win32")
        failed = failing_provider.execute(
            failing_provider.plan(_request("hardware_breakpoint", params))
        )
        cleanup = failing_provider.rollback(failed)
        self.assertEqual(failed.status, "failed")
        self.assertFalse(cleanup.ok)
        self.assertFalse(cleanup.restored)

    def test_hardware_breakpoint_unavailable_is_not_reported_as_success(self) -> None:
        backend = FakeWin32Backend(architecture="x86")
        backend.thread_probe.update(
            {
                "hardware_breakpoint_supported": False,
                "reason": "same-bitness x64 context required",
            }
        )
        provider = NativeHookProvider(backend, platform_name="win32")
        plan = provider.plan(
            _request(
                "hardware_breakpoint",
                {
                    "authorized": True,
                    "thread_id": 77,
                    "address": 0x401000,
                    "access": "execute",
                    "size": 1,
                    "duration_ms": 10,
                    "max_events": 2,
                },
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "unavailable")
        self.assertFalse(
            any(call[0] == "trace_hardware_breakpoint" for call in backend.calls)
        )

    def test_session_artifacts_are_confined_hashed_and_contract_valid(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        backend.map(0x100000, original)
        provider = NativeHookProvider(backend, platform_name="win32")
        result = provider.execute(
            provider.plan(
                _request(
                    "vtable_pointer",
                    _vtable_params(),
                    session_id=r"..\..\outside/session",
                )
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = provider.collect_artifacts(result, str(root))
            self.assertEqual(len(bundle.artifacts), 3)
            for artifact in bundle.artifacts:
                path = (root / Path(artifact.path)).resolve()
                path.relative_to(root)
                self.assertTrue(path.is_file())
                data = path.read_bytes()
                self.assertEqual(artifact.metadata["size"], len(data))
                self.assertEqual(
                    artifact.metadata["sha256"], hashlib.sha256(data).hexdigest()
                )

            audit_artifact = next(
                item for item in bundle.artifacts if item.kind == "native-hook-audit"
            )
            audit = json.loads((root / audit_artifact.path).read_text(encoding="utf-8"))
            contract = validate_capability_audit_record(audit)
            self.assertTrue(contract.ok, contract.errors)
            self.assertEqual(audit["target_identity"]["pid"], 4242)
            self.assertEqual(audit["precondition_hash"], result.provenance["precondition_hash"])
            self.assertFalse(audit["provenance"]["frida"])

    def test_tampered_plan_result_and_cross_instance_result_fail_closed(self) -> None:
        backend = FakeWin32Backend()
        original = (0x1122334455667788).to_bytes(8, "little")
        backend.map(0x100000, original)
        provider = NativeHookProvider(backend, platform_name="win32")
        tampered_plan = provider.plan(_request("vtable_pointer", _vtable_params()))
        tampered_plan.parameters["replacement_pointer"] = 1
        self.assertFalse(provider.validate(tampered_plan).ok)
        self.assertEqual(provider.execute(tampered_plan).status, "failed")
        self.assertFalse(any(call[0] == "write" for call in backend.calls))

        clean_plan = provider.plan(_request("vtable_pointer", _vtable_params()))
        result = provider.execute(clean_plan)
        result.report_section["status"] = "tampered"
        with self.assertRaisesRegex(ValueError, "identity"):
            provider.rollback(result)

        second_backend = FakeWin32Backend()
        second_provider = NativeHookProvider(second_backend, platform_name="win32")
        with self.assertRaisesRegex(ValueError, "provider instance"):
            second_provider.rollback(result)


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("RUN_NATIVE_HOOK_SMOKE") == "1",
    "set RUN_NATIVE_HOOK_SMOKE=1 on Windows to exercise real process memory APIs",
)
class NativeHookWindowsSmokeTests(unittest.TestCase):
    @staticmethod
    def _retain_acceptance_artifacts(
        provider: NativeHookProvider,
        result: Any,
        rollback: Any,
        *,
        pid: int,
    ) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            return
        root = Path(configured).expanduser().resolve()
        provider.collect_artifacts(result, str(root))
        evidence = root / "native-hook"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "target-identity.json").write_text(
            json.dumps(
                {
                    "kind": "controlled_child_process",
                    "pid": pid,
                    "path": str(Path(sys.executable).resolve()),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (evidence / "rollback.json").write_text(
            json.dumps(
                {
                    "status": "ok" if rollback.ok and rollback.restored else "failed",
                    "verified": bool(rollback.ok and rollback.restored),
                    "restored": bool(rollback.restored),
                    "details": rollback.details,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        proof_path = evidence / "execution-proof.json"
        proof = {
            "status": "ok",
            "provider": result.provider,
            "evidence_class": "live_host_proof",
            "executed_tests": 0,
            "skipped_tests": 0,
            "live_operations": 0,
            "actions": [],
        }
        if proof_path.is_file():
            previous = json.loads(proof_path.read_text(encoding="utf-8"))
            if isinstance(previous, Mapping):
                proof.update(previous)
        proof["executed_tests"] = int(proof.get("executed_tests") or 0) + 1
        proof["live_operations"] = int(proof.get("live_operations") or 0) + max(
            1, len(result.after_snapshot.get("memory_observations") or [])
        )
        proof["actions"] = [*list(proof.get("actions") or []), result.action]
        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")

    def test_real_child_process_vtable_pointer_round_trip(self) -> None:
        child_script = (
            "import ctypes, os, time\n"
            "value = ctypes.c_void_p(0x12345678)\n"
            "print(os.getpid(), ctypes.addressof(value), flush=True)\n"
            "time.sleep(30)\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", child_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result = None
        rollback = None
        try:
            assert child.stdout is not None
            pid_text, address_text = child.stdout.readline().split()
            pid = int(pid_text)
            address = int(address_text)
            provider = NativeHookProvider(
                WindowsNativeHookBackend(), platform_name="win32"
            )
            request = CapabilityRequest(
                capability="native_hook",
                action="vtable_pointer",
                target=TargetIdentity(kind="process", pid=pid, display_name="smoke-child"),
                params={
                    "authorized": True,
                    "architecture": "x64" if struct.calcsize("P") == 8 else "x86",
                    "slot_address": address,
                    "expected_original_pointer": 0x12345678,
                    "replacement_pointer": 0x87654321,
                },
                session_id="windows-native-hook-smoke",
            )
            result = provider.execute(provider.plan(request))
            self.assertEqual(result.status, "ok")
            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok)
            self.assertTrue(rollback.restored)
        finally:
            child.terminate()
            child.communicate(timeout=5)
        if result is not None and rollback is not None:
            self._retain_acceptance_artifacts(
                provider, result, rollback, pid=pid
            )

    def test_real_child_process_inline_trampoline_round_trip(self) -> None:
        child_script = (
            "import ctypes, os, time\n"
            "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
            "kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, "
            "ctypes.c_ulong, ctypes.c_ulong]\n"
            "kernel32.VirtualAlloc.restype = ctypes.c_void_p\n"
            "address = kernel32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)\n"
            "assert address\n"
            "overwrite_size = 14 if ctypes.sizeof(ctypes.c_void_p) == 8 else 5\n"
            "original = b'\\x90' * overwrite_size\n"
            "ctypes.memmove(address, original, len(original))\n"
            "replacement = address + 0x100\n"
            "ctypes.memset(replacement, 0xC3, 1)\n"
            "print(os.getpid(), address, replacement, original.hex(), flush=True)\n"
            "time.sleep(30)\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", child_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result = None
        rollback = None
        try:
            assert child.stdout is not None
            pid_text, address_text, replacement_text, original_hex = (
                child.stdout.readline().split()
            )
            pid = int(pid_text)
            address = int(address_text)
            replacement = int(replacement_text)
            architecture = "x64" if struct.calcsize("P") == 8 else "x86"
            backend = WindowsNativeHookBackend()
            provider = NativeHookProvider(backend, platform_name="win32")
            request = CapabilityRequest(
                capability="native_hook",
                action="inline_trampoline",
                target=TargetIdentity(kind="process", pid=pid, display_name="smoke-child"),
                params={
                    "authorized": True,
                    "architecture": architecture,
                    "target_address": address,
                    "replacement_pointer": replacement,
                    "expected_original_bytes": original_hex,
                },
                session_id="windows-native-inline-smoke",
            )

            result = provider.execute(provider.plan(request))

            self.assertEqual(result.status, "ok")
            self.assertTrue(result.after_snapshot["action"]["write_verified"])
            self.assertTrue(result.after_snapshot["action"]["trampoline"]["verified"])
            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok)
            self.assertTrue(rollback.restored)
            original = bytes.fromhex(original_hex)
            self.assertEqual(backend.read(pid, address, len(original)), original)
        finally:
            child.terminate()
            child.communicate(timeout=5)
        if result is not None and rollback is not None:
            self._retain_acceptance_artifacts(
                provider, result, rollback, pid=pid
            )


@unittest.skipUnless(
    sys.platform == "win32"
    and struct.calcsize("P") == 8
    and os.environ.get("RUN_NATIVE_HOOK_HARDWARE_SMOKE") == "1",
    "set RUN_NATIVE_HOOK_HARDWARE_SMOKE=1 in 64-bit Python on Windows",
)
class NativeHookWindowsHardwareSmokeTests(unittest.TestCase):
    @staticmethod
    def _retain_acceptance_artifacts(
        provider: NativeHookProvider,
        result: Any,
        *,
        pid: int,
        thread_id: int,
    ) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            return
        root = Path(configured).expanduser().resolve()
        provider.collect_artifacts(result, str(root))
        evidence = root / "native-hook-hardware"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "target-identity.json").write_text(
            json.dumps(
                {
                    "kind": "controlled_child_process_thread",
                    "pid": pid,
                    "thread_id": thread_id,
                    "path": str(Path(sys.executable).resolve()),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        restored = bool(result.rollback_plan.get("restored"))
        detached = bool(result.rollback_plan.get("debug_detached"))
        (evidence / "rollback.json").write_text(
            json.dumps(
                {
                    "status": "ok" if restored and detached else "failed",
                    "verified": restored and detached,
                    "debug_registers_restored": restored,
                    "debug_detached": detached,
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
                    "live_operations": max(
                        1, int(result.after_snapshot.get("trace_event_count") or 0)
                    ),
                    "actions": [result.action],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_real_child_thread_hardware_breakpoint_trace_and_cleanup(self) -> None:
        child_script = (
            "import ctypes, os, time\n"
            "kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
            "kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, "
            "ctypes.c_ulong, ctypes.c_ulong]\n"
            "kernel32.VirtualAlloc.restype = ctypes.c_void_p\n"
            "kernel32.GetCurrentThreadId.restype = ctypes.c_ulong\n"
            "address = kernel32.VirtualAlloc(None, 0x1000, 0x3000, 0x40)\n"
            "assert address\n"
            "ctypes.memmove(address, b'\\xB8\\x2A\\x00\\x00\\x00\\xC3', 6)\n"
            "function = ctypes.CFUNCTYPE(ctypes.c_int)(address)\n"
            "print(os.getpid(), kernel32.GetCurrentThreadId(), address, flush=True)\n"
            "while True:\n"
            "    assert function() == 42\n"
            "    time.sleep(0.001)\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", child_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result = None
        try:
            assert child.stdout is not None
            pid_text, thread_text, address_text = child.stdout.readline().split()
            pid = int(pid_text)
            thread_id = int(thread_text)
            address = int(address_text)
            provider = NativeHookProvider(
                WindowsNativeHookBackend(), platform_name="win32"
            )
            request = CapabilityRequest(
                capability="native_hook",
                action="hardware_breakpoint",
                target=TargetIdentity(kind="process", pid=pid, display_name="smoke-child"),
                params={
                    "authorized": True,
                    "thread_id": thread_id,
                    "address": address,
                    "access": "execute",
                    "size": 1,
                    "duration_ms": 1_000,
                    "max_events": 1,
                },
                session_id="windows-native-hardware-smoke",
            )

            result = provider.execute(provider.plan(request))

            self.assertEqual(result.status, "ok", result.report_section)
            self.assertEqual(result.after_snapshot["trace_event_count"], 1)
            event = result.after_snapshot["trace_events"][0]
            self.assertEqual(event["thread_id"], thread_id)
            self.assertEqual(event["watch_address"], address)
            self.assertTrue(result.rollback_plan["restored"])
            self.assertTrue(result.rollback_plan["debug_detached"])
            self.assertEqual(provider.rollback(result).details["status"], "already_completed")
            self.assertIsNone(child.poll())
        finally:
            child.terminate()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
        if result is not None:
            self._retain_acceptance_artifacts(
                provider,
                result,
                pid=pid,
                thread_id=thread_id,
            )


if __name__ == "__main__":
    unittest.main()
