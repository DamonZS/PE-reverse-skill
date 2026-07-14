import hashlib
import json
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
from reverse_analyzer.providers.memory_runtime import (
    MemoryRuntimeBackendError,
    MemoryRuntimeMockProvider,
    MemoryRuntimeProvider,
)


class FakeMemoryRuntimeBackend:
    name = "fake_memory_runtime"
    available = True
    unavailable_reason = None

    def __init__(self, *, pid: int = 4242) -> None:
        self.pid = pid
        self.calls: list[tuple[Any, ...]] = []
        self.fail_writes = False
        self.partial_writes = False
        self.next_address = 0x5000
        self.allocations: dict[int, dict[str, Any]] = {
            0x1000: {
                "data": bytearray.fromhex("AA BB CC DD AA 99 CC 00"),
                "protection": 0x04,
            },
            0x2000: {
                "data": bytearray(b"FREEBACK"),
                "protection": 0x20,
            },
        }

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe_process", pid))
        accessible = pid == self.pid
        return {
            "pid": pid,
            "exists": accessible,
            "accessible": accessible,
            "status": "ok" if accessible else "failed",
            "image_path": "C:/fixtures/target.exe" if accessible else None,
        }

    def enumerate_regions(self, pid: int) -> list[Mapping[str, Any]]:
        self._require_pid(pid)
        self.calls.append(("enumerate_regions", pid))
        return [
            {
                "base_address": base,
                "allocation_base": base,
                "size": len(allocation["data"]),
                "state": 0x1000,
                "protection": allocation["protection"],
                "committed": True,
                "readable": True,
                "writable": allocation["protection"] in {0x04, 0x40},
                "executable": allocation["protection"] in {0x10, 0x20, 0x40},
            }
            for base, allocation in sorted(self.allocations.items())
        ]

    def enumerate_modules(self, pid: int) -> list[Mapping[str, Any]]:
        self._require_pid(pid)
        self.calls.append(("enumerate_modules", pid))
        return [
            {
                "name": "target.exe",
                "path": "C:/fixtures/target.exe",
                "base_address": 0x400000,
                "size": 0x12000,
            }
        ]

    def read(self, pid: int, address: int, size: int) -> bytes:
        self._require_pid(pid)
        self.calls.append(("read", pid, address, size))
        base, allocation = self._find(address, size)
        offset = address - base
        return bytes(allocation["data"][offset : offset + size])

    def write(
        self,
        pid: int,
        address: int,
        data: bytes,
        expected: bytes,
    ) -> Mapping[str, Any]:
        self._require_pid(pid)
        self.calls.append(("write", pid, address, bytes(data), bytes(expected)))
        base, allocation = self._find(address, len(expected))
        offset = address - base
        before = bytes(allocation["data"][offset : offset + len(expected)])
        if before != expected:
            return {
                "ok": False,
                "status": "precondition_failed",
                "expected_hex": expected.hex(),
                "actual_hex": before.hex(),
                "bytes_written": 0,
                "side_effects": False,
            }
        if self.fail_writes:
            return {
                "ok": False,
                "status": "failed",
                "error": "injected write failure",
                "bytes_written": 0,
                "side_effects": False,
            }
        if self.partial_writes:
            written = max(1, len(data) // 2)
            allocation["data"][offset : offset + written] = data[:written]
            return {
                "ok": False,
                "status": "failed",
                "error": "injected partial write",
                "bytes_written": written,
                "side_effects": True,
            }
        allocation["data"][offset : offset + len(data)] = data
        return {
            "ok": True,
            "status": "ok",
            "address": address,
            "before_hex": before.hex(),
            "after_hex": bytes(data).hex(),
            "bytes_written": len(data),
            "verified": True,
            "side_effects": before != data,
        }

    def protect(
        self,
        pid: int,
        address: int,
        size: int,
        protection: int,
    ) -> Mapping[str, Any]:
        self._require_pid(pid)
        self.calls.append(("protect", pid, address, size, protection))
        _, allocation = self._find(address, size)
        old = int(allocation["protection"])
        allocation["protection"] = protection
        return {
            "ok": True,
            "status": "ok",
            "address": address,
            "size": size,
            "old_protection": old,
            "new_protection": protection,
            "side_effects": old != protection,
        }

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        address: Optional[int] = None,
        allocation_type: int = 0x3000,
    ) -> Mapping[str, Any]:
        self._require_pid(pid)
        selected = self.next_address if address is None else address
        self.calls.append(
            ("alloc", pid, size, protection, selected, allocation_type)
        )
        if selected in self.allocations:
            return {
                "ok": False,
                "status": "failed",
                "error": "address already allocated",
                "side_effects": False,
            }
        self.allocations[selected] = {
            "data": bytearray(size),
            "protection": protection,
        }
        self.next_address = max(self.next_address, selected + 0x1000)
        return {
            "ok": True,
            "status": "ok",
            "address": selected,
            "size": size,
            "protection": protection,
            "allocation_type": allocation_type,
            "side_effects": True,
        }

    def free(
        self,
        pid: int,
        address: int,
        *,
        size: int = 0,
        free_type: int = 0x8000,
    ) -> Mapping[str, Any]:
        self._require_pid(pid)
        self.calls.append(("free", pid, address, size, free_type))
        if address not in self.allocations:
            return {
                "ok": False,
                "status": "failed",
                "error": "allocation not found",
                "side_effects": False,
            }
        del self.allocations[address]
        return {
            "ok": True,
            "status": "ok",
            "address": address,
            "size": size,
            "free_type": free_type,
            "side_effects": True,
        }

    def scan(
        self,
        pid: int,
        pattern: bytes,
        *,
        mask: str,
        start_address: Optional[int] = None,
        end_address: Optional[int] = None,
        max_results: int = 256,
        max_bytes: int = 256 * 1024 * 1024,
        chunk_size: int = 1024 * 1024,
    ) -> Mapping[str, Any]:
        self._require_pid(pid)
        self.calls.append(
            (
                "scan",
                pid,
                bytes(pattern),
                mask,
                start_address,
                end_address,
                max_results,
                max_bytes,
                chunk_size,
            )
        )
        matches: list[int] = []
        scanned = 0
        for base, allocation in sorted(self.allocations.items()):
            data = bytes(allocation["data"])
            lower = max(base, start_address if start_address is not None else base)
            upper = min(
                base + len(data),
                end_address if end_address is not None else base + len(data),
            )
            if lower >= upper:
                continue
            segment = data[lower - base : upper - base]
            budget = max(0, max_bytes - scanned)
            segment = segment[:budget]
            for offset in range(max(0, len(segment) - len(pattern) + 1)):
                if all(
                    mask[index] == "?" or segment[offset + index] == byte
                    for index, byte in enumerate(pattern)
                ):
                    matches.append(lower + offset)
                    if len(matches) >= max_results:
                        break
            scanned += len(segment)
            if len(matches) >= max_results or scanned >= max_bytes:
                break
        return {
            "ok": True,
            "status": "ok",
            "pattern_hex": pattern.hex(),
            "mask": mask,
            "matches": matches,
            "match_count": len(matches),
            "scanned_bytes": scanned,
            "truncated": len(matches) >= max_results or scanned >= max_bytes,
            "side_effects": False,
        }

    def bytes_at(self, address: int, size: int) -> bytes:
        base, allocation = self._find(address, size)
        offset = address - base
        return bytes(allocation["data"][offset : offset + size])

    def protection_at(self, address: int) -> int:
        _, allocation = self._find(address, 1)
        return int(allocation["protection"])

    def _require_pid(self, pid: int) -> None:
        if pid != self.pid:
            raise MemoryRuntimeBackendError(
                "probe_process", "fixture process is unavailable", details={"pid": pid}
            )

    def _find(self, address: int, size: int) -> tuple[int, dict[str, Any]]:
        for base, allocation in self.allocations.items():
            if base <= address and address + size <= base + len(allocation["data"]):
                return base, allocation
        raise MemoryRuntimeBackendError(
            "read",
            "fixture address range is unmapped",
            details={"address": address, "size": size},
        )


class MissingScanBackend(FakeMemoryRuntimeBackend):
    scan = None


class MemoryRuntimeProviderTests(unittest.TestCase):
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

    pid = 4242

    def _provider(
        self, backend: Optional[FakeMemoryRuntimeBackend] = None
    ) -> tuple[MemoryRuntimeProvider, FakeMemoryRuntimeBackend]:
        selected = backend or FakeMemoryRuntimeBackend(pid=self.pid)
        return (
            MemoryRuntimeProvider(backend=selected, platform_name="win32"),
            selected,
        )

    def _request(
        self,
        action: str,
        params: Optional[dict[str, Any]] = None,
        *,
        session_id: Optional[str] = None,
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="memory_runtime",
            action=action,
            target=TargetIdentity(
                kind="process",
                pid=self.pid,
                display_name="target.exe",
            ),
            params=dict(params or {}),
            session_id=session_id or f"memory-{action}",
            provenance={"source": "test_memory_runtime_provider"},
        )

    @staticmethod
    def _checks(validation: Any) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in validation.checks}

    def _assert_audit_contract(self, plan: Any, validation: Any, result: Any) -> None:
        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_required_actions_plan_validate_and_execute(self) -> None:
        cases = {
            "scan": {
                "pattern": "AA ?? CC",
                "start_address": 0x1000,
                "end_address": 0x1008,
                "max_results": 8,
            },
            "read": {"address": 0x1000, "size": 4},
            "write": {
                "address": 0x1000,
                "data": "DE AD BE EF",
                "expected": "AA BB CC DD",
            },
            "protect": {
                "address": 0x1000,
                "size": 4,
                "protection": "PAGE_EXECUTE_READWRITE",
            },
            "alloc": {
                "address": 0x3000,
                "size": 16,
                "protection": "PAGE_READWRITE",
            },
            "free": {"address": 0x2000},
        }

        for action, params in cases.items():
            with self.subTest(action=action):
                provider, _ = self._provider()
                request = self._request(action, params)

                self.assertTrue(provider.supports(request))
                plan = provider.plan(request)
                validation = provider.validate(plan)
                result = provider.execute(plan)

                self.assertEqual(plan.action, action)
                self.assertEqual(plan.parameters["pid"], self.pid)
                self.assertIsNotNone(plan.precondition_hash)
                self.assertEqual(
                    plan.before_snapshot["precondition_hash"], plan.precondition_hash
                )
                self.assertIn("before", plan.rollback_plan)
                self.assertIn("after", plan.rollback_plan)
                self.assertEqual(
                    plan.provenance["precondition_hash"], plan.precondition_hash
                )
                self.assertTrue(validation.ok, validation.errors)
                self.assertEqual(result.status, "ok", result.report_section)
                self.assertTrue(result.before_snapshot)
                self.assertTrue(result.after_snapshot)
                self.assertIn("before", result.rollback_plan)
                self.assertIn("after", result.rollback_plan)
                self.assertEqual(
                    result.provenance["precondition_hash"], plan.precondition_hash
                )
                self.assertEqual(result.artifacts[0].kind, "memory-runtime-audit")
                self.assertEqual(
                    result.evidence_manifest_entries[0]["role"],
                    "memory-runtime-audit",
                )
                self.assertTrue(
                    self._REPORT_AUDIT_FIELDS <= set(result.report_section)
                )
                self.assertEqual(
                    result.report_section["target_identity"]["pid"], self.pid
                )
                self._assert_audit_contract(plan, validation, result)
                json.dumps(result.to_dict(), sort_keys=True)

    def test_scan_supports_aob_wildcards_and_read_returns_exact_bytes(self) -> None:
        provider, _ = self._provider()
        scan = provider.execute(
            provider.plan(
                self._request(
                    "scan",
                    {
                        "pattern": "AA ?? CC",
                        "start_address": 0x1000,
                        "end_address": 0x1008,
                    },
                )
            )
        )
        read = provider.execute(
            provider.plan(self._request("read", {"address": 0x1000, "size": 4}))
        )

        self.assertEqual(scan.report_section["operation"]["matches"], [0x1000, 0x1004])
        self.assertEqual(scan.report_section["operation"]["mask"], "x?x")
        self.assertEqual(read.after_snapshot["memory"]["hex"], "aabbccdd")
        rollback = provider.rollback(read)
        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "not_required")

    def test_probe_region_and_module_enumeration_actions(self) -> None:
        expectations = {
            "probe": ("pid", self.pid),
            "regions": ("region_count", 2),
            "modules": ("module_count", 1),
        }
        for action, (key, expected) in expectations.items():
            with self.subTest(action=action):
                provider, _ = self._provider()
                result = provider.execute(provider.plan(self._request(action)))
                self.assertEqual(result.status, "ok")
                self.assertEqual(result.report_section["operation"][key], expected)

    def test_write_records_audit_metadata_and_rolls_back(self) -> None:
        provider, backend = self._provider()
        plan = provider.plan(
            self._request(
                "write",
                {
                    "address": 0x1000,
                    "data": "DE AD BE EF",
                    "expected": "AA BB CC DD",
                },
            )
        )
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(backend.bytes_at(0x1000, 4), bytes.fromhex("DE AD BE EF"))
        self.assertEqual(result.before_snapshot["memory"]["hex"], "aabbccdd")
        self.assertEqual(result.after_snapshot["memory"]["hex"], "deadbeef")
        self.assertEqual(
            result.rollback_plan["before_sha256"],
            hashlib.sha256(bytes.fromhex("AA BB CC DD")).hexdigest(),
        )
        self.assertEqual(result.rollback_plan["after_hex"], "deadbeef")
        self.assertTrue(result.after_snapshot["side_effects"])
        self.assertEqual(result.provenance["source"], "test_memory_runtime_provider")

        rollback = provider.rollback(result)

        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(rollback.restored)
        self.assertEqual(backend.bytes_at(0x1000, 4), bytes.fromhex("AA BB CC DD"))
        self.assertEqual(result.rollback_plan["rollback_status"], "ok")
        self.assertEqual(result.report_section["rollback"]["status"], "ok")
        self.assertEqual(
            result.report_section["after_snapshot"], result.after_snapshot
        )
        self.assertEqual(
            result.report_section["rollback_plan"], result.rollback_plan
        )
        self.assertEqual(
            result.dashboard_trace[-1]["kind"], "memory_runtime_rollback"
        )
        with tempfile.TemporaryDirectory() as out_dir:
            bundle = provider.collect_artifacts(result, out_dir)
            artifact_path = Path(out_dir) / bundle.artifacts[0].path
            encoded = artifact_path.read_bytes()
            payload = json.loads(encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            self.assertEqual(payload["session_id"], result.session_id)
            self.assertEqual(payload["target_identity"]["pid"], self.pid)
            self.assertEqual(payload["before_snapshot"], result.before_snapshot)
            self.assertTrue(bundle.artifacts[0].metadata["materialized"])
            self.assertEqual(bundle.artifacts[0].metadata["sha256"], digest)
            self.assertEqual(bundle.artifacts[0].metadata["size"], len(encoded))
            self.assertEqual(bundle.manifest_entries[0]["sha256"], digest)
            self.assertEqual(bundle.manifest_entries[0]["size"], len(encoded))
        self.assertEqual(bundle.artifacts, result.artifacts)
        self.assertEqual(bundle.manifest_entries, result.evidence_manifest_entries)

    def test_collect_artifacts_rejects_paths_outside_collection_root(self) -> None:
        provider, _ = self._provider()
        result = provider.execute(
            provider.plan(self._request("read", {"address": 0x1000, "size": 4}))
        )
        result.artifacts[0].path = "../escaped-memory-audit.json"

        with tempfile.TemporaryDirectory() as tmp:
            collection_root = Path(tmp) / "artifacts"
            escaped = Path(tmp) / "escaped-memory-audit.json"
            with self.assertRaisesRegex(ValueError, "collection directory"):
                provider.collect_artifacts(result, str(collection_root))
            self.assertFalse(escaped.exists())

    def test_protect_alloc_and_free_roll_back(self) -> None:
        cases = [
            (
                "protect",
                {
                    "address": 0x1000,
                    "size": 4,
                    "protection": "PAGE_EXECUTE_READWRITE",
                },
            ),
            (
                "alloc",
                {
                    "address": 0x3000,
                    "size": 16,
                    "protection": "PAGE_READWRITE",
                },
            ),
            ("free", {"address": 0x2000}),
        ]

        for action, params in cases:
            with self.subTest(action=action):
                provider, backend = self._provider()
                original_free_bytes = backend.bytes_at(0x2000, 8)
                result = provider.execute(provider.plan(self._request(action, params)))

                self.assertEqual(result.status, "ok", result.report_section)
                self.assertTrue(result.rollback_plan["supported"])
                self.assertTrue(result.after_snapshot["side_effects"])
                rollback = provider.rollback(result)
                self.assertTrue(rollback.ok, rollback.details)
                self.assertTrue(rollback.restored)

                if action == "protect":
                    self.assertEqual(backend.protection_at(0x1000), 0x04)
                elif action == "alloc":
                    self.assertNotIn(0x3000, backend.allocations)
                else:
                    self.assertEqual(backend.bytes_at(0x2000, 8), original_free_bytes)
                    self.assertEqual(backend.protection_at(0x2000), 0x20)

    def test_expected_protection_mismatch_blocks_protect_without_side_effects(self) -> None:
        provider, backend = self._provider()
        plan = provider.plan(
            self._request(
                "protect",
                {
                    "address": 0x1000,
                    "size": 4,
                    "protection": "PAGE_EXECUTE_READWRITE",
                    "expected_protection": "PAGE_EXECUTE_READ",
                },
            )
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(
            self._checks(validation)["protect_expected_protection"]["status"],
            "failed",
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.protection_at(0x1000), 0x04)
        self.assertFalse(any(call[0] == "protect" for call in backend.calls))

    def test_expected_protection_match_is_recorded_and_allows_protect(self) -> None:
        provider, backend = self._provider()
        plan = provider.plan(
            self._request(
                "protect",
                {
                    "address": 0x1000,
                    "size": 4,
                    "protection": "PAGE_EXECUTE_READ",
                    "expected_protection": "PAGE_READWRITE",
                },
            )
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertEqual(plan.parameters["expected_protection"], 0x04)
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok", result.report_section)
        self.assertEqual(backend.protection_at(0x1000), 0x20)

    def test_expected_byte_mismatch_blocks_write_without_side_effects(self) -> None:
        provider, backend = self._provider()
        plan = provider.plan(
            self._request(
                "write",
                {
                    "address": 0x1000,
                    "data": "DE AD BE EF",
                    "expected": "00 00 00 00",
                },
            )
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(self._checks(validation)["write_preimage"]["status"], "failed")
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.bytes_at(0x1000, 4), bytes.fromhex("AA BB CC DD"))
        self.assertFalse(any(call[0] == "write" for call in backend.calls))
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(result.rollback_plan["mode"], "not_required")
        self._assert_audit_contract(plan, validation, result)

    def test_backend_write_failure_latches_and_blocks_later_writes(self) -> None:
        provider, backend = self._provider()
        backend.fail_writes = True
        request = self._request(
            "write",
            {
                "address": 0x1000,
                "data": "DE AD BE EF",
                "expected": "AA BB CC DD",
            },
        )

        first = provider.execute(provider.plan(request))
        writes_after_first = len([call for call in backend.calls if call[0] == "write"])
        second_plan = provider.plan(request)
        second_validation = provider.validate(second_plan)
        second = provider.execute(second_plan)

        self.assertEqual(first.status, "failed")
        self.assertTrue(provider.write_locked)
        self.assertTrue(first.report_section["write_fail_closed"]["locked"])
        self.assertEqual(
            self._checks(second_validation)["write_fail_closed_latch"]["status"],
            "failed",
        )
        self.assertEqual(second.status, "failed")
        self.assertEqual(
            len([call for call in backend.calls if call[0] == "write"]),
            writes_after_first,
        )

    def test_partial_write_failure_stays_rollback_capable(self) -> None:
        provider, backend = self._provider()
        backend.partial_writes = True
        result = provider.execute(
            provider.plan(
                self._request(
                    "write",
                    {
                        "address": 0x1000,
                        "data": "DE AD BE EF",
                        "expected": "AA BB CC DD",
                    },
                )
            )
        )

        self.assertEqual(result.status, "failed")
        self.assertTrue(provider.write_locked)
        self.assertTrue(result.after_snapshot["side_effects"])
        self.assertTrue(result.rollback_plan["supported"])
        self.assertEqual(result.rollback_plan["mode"], "write_restore")

        backend.partial_writes = False
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertEqual(backend.bytes_at(0x1000, 4), bytes.fromhex("AA BB CC DD"))

    def test_non_windows_and_missing_backend_api_are_structured(self) -> None:
        unavailable = MemoryRuntimeProvider(platform_name="linux")
        unavailable_plan = unavailable.plan(
            self._request("read", {"address": 0x1000, "size": 4})
        )
        unavailable_validation = unavailable.validate(unavailable_plan)
        result = unavailable.execute(unavailable_plan)

        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.after_snapshot["status"], "unavailable")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertIn("linux", result.after_snapshot["reason"])
        self.assertEqual(result.rollback_plan["mode"], "not_required")
        self.assertEqual(
            result.report_section["validation"]["checks"][-1]["status"],
            "unavailable",
        )
        self._assert_audit_contract(
            unavailable_plan,
            unavailable_validation,
            result,
        )

        missing = MemoryRuntimeProvider(
            backend=MissingScanBackend(pid=self.pid), platform_name="win32"
        )
        missing_result = missing.execute(
            missing.plan(self._request("scan", {"pattern": "AA BB"}))
        )
        self.assertEqual(missing_result.status, "unavailable")
        self.assertFalse(missing_result.after_snapshot["side_effects"])
        self.assertEqual(
            missing_result.report_section["operation"]["status"], "unavailable"
        )

    def test_mock_provider_is_preserved(self) -> None:
        provider = MemoryRuntimeMockProvider()
        request = self._request("read", {"address": 0x1000, "size": 4})
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)
        rollback = provider.rollback(result)

        self.assertEqual(provider.capability_name, "memory_runtime")
        self.assertTrue(validation.ok)
        self.assertEqual(result.status, "mocked")
        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)


if __name__ == "__main__":
    unittest.main()
