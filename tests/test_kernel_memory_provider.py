from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from reverse_analyzer.core.capabilities.audit_contract import (
    validate_capability_audit_record,
)
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import kernel_memory as kernel_memory_module
from reverse_analyzer.providers.kernel_memory import (
    DEFAULT_DEVICE_PATH,
    HARD_MAX_READ_BYTES,
    IOCTL_KM_READ,
    KernelDriverMemoryProvider,
    KernelMemoryBackendError,
    KernelMemoryProtocolError,
    KernelMemoryRequest,
    KernelMemoryResponse,
    KernelMemoryVersionInfo,
    UnavailableKernelMemoryBackend,
    WindowsKernelMemoryBackend,
)


PID = 4242
CREATION_TIME = 0x01DC123456789ABC
ADDRESS = 0x00100000
ORIGINAL = bytes.fromhex("10 20 30 40")
REPLACEMENT = bytes.fromhex("AA BB CC DD")


class FakeKernelMemoryBackend:
    name = "fake_kernel_memory_protocol_backend"
    available = True
    availability_status = "available"
    unavailable_reason = None
    test_double = True

    def __init__(self) -> None:
        self.pid = PID
        self.creation_time = CREATION_TIME
        self.base = ADDRESS
        self.memory = bytearray(b"\x00" * 0x100)
        self.memory[: len(ORIGINAL)] = ORIGINAL
        self.calls: list[tuple[Any, ...]] = []
        self.fail_after_mutation = 0
        self.conflicting_failure: bytes | None = None
        self.protocol_version = 1

    def describe(self) -> Mapping[str, Any]:
        return {
            "name": self.name,
            "available": True,
            "status": "available",
            "test_double": True,
            "protocol_serialization_exercised": True,
        }

    def get_version(self) -> Mapping[str, Any]:
        self.calls.append(("version",))
        return {
            "status": "ok",
            "protocol_version": self.protocol_version,
            "struct_version": 1,
            "protocol_min": 1,
            "protocol_max": 1,
            "max_read_bytes": 64 * 1024,
            "max_write_bytes": 4 * 1024,
            "operation_mask": 0x0F,
            "driver_backed": False,
        }

    def query_process(self, pid: int, process_creation_time: int) -> Mapping[str, Any]:
        self.calls.append(("query", pid, process_creation_time))
        if pid != self.pid or process_creation_time != self.creation_time:
            raise KernelMemoryBackendError(
                "query_process", "PID/create-time identity mismatch"
            )
        return {
            "status": "ok",
            "pid": pid,
            "process_creation_time": self.creation_time,
            "identity_verified": True,
            "driver_backed": False,
        }

    def read(
        self, pid: int, process_creation_time: int, address: int, size: int
    ) -> bytes:
        self.query_process(pid, process_creation_time)
        self.calls.append(("read", pid, address, size))
        offset = address - self.base
        if offset < 0 or offset + size > len(self.memory):
            return b""
        return bytes(self.memory[offset : offset + size])

    def write(
        self,
        pid: int,
        process_creation_time: int,
        address: int,
        expected: bytes,
        data: bytes,
    ) -> Mapping[str, Any]:
        self.query_process(pid, process_creation_time)
        self.calls.append(("write", pid, address, bytes(expected), bytes(data)))
        offset = address - self.base
        current = bytes(self.memory[offset : offset + len(data)])
        if current != bytes(expected):
            raise KernelMemoryBackendError("write", "expected original bytes mismatch")
        if self.conflicting_failure is not None:
            self.memory[offset : offset + len(data)] = self.conflicting_failure
            self.conflicting_failure = None
            raise KernelMemoryBackendError("write", "injected conflicting target state")
        self.memory[offset : offset + len(data)] = data
        if self.fail_after_mutation:
            self.fail_after_mutation -= 1
            raise KernelMemoryBackendError("write", "injected post-copy transport failure")
        return {
            "status": "ok",
            "bytes_transferred": len(data),
            "after_hex": bytes(data).hex(),
            "driver_backed": False,
        }

    def bytes_at(self, address: int, size: int) -> bytes:
        offset = address - self.base
        return bytes(self.memory[offset : offset + size])


def _target(*, creation_time: int = CREATION_TIME) -> TargetIdentity:
    return TargetIdentity(
        kind="process",
        pid=PID,
        display_name="fixture.exe",
        metadata={
            "pid": PID,
            "process_creation_time": creation_time,
        },
    )


def _request(action: str, params: Mapping[str, Any]) -> CapabilityRequest:
    return CapabilityRequest(
        capability="kernel_driver_memory_runtime",
        action=action,
        target=_target(),
        params=dict(params),
        session_id=f"kernel-memory-{action}-fixture",
        provenance={"fixture": "signed-lab-driver-contract-test-double"},
    )


def _read_params(size: int = len(ORIGINAL)) -> dict[str, Any]:
    return {
        "address": ADDRESS,
        "size": size,
        "allowed_ranges": [[ADDRESS, ADDRESS + max(size, len(ORIGINAL))]],
    }


def _write_params() -> dict[str, Any]:
    return {
        "authorized": True,
        "address": ADDRESS,
        "expected_original_bytes": ORIGINAL.hex(),
        "data": REPLACEMENT.hex(),
        "allowed_ranges": [[ADDRESS, ADDRESS + len(ORIGINAL)]],
    }


class KernelMemoryProtocolTests(unittest.TestCase):
    def test_fixed_layout_write_request_round_trip(self) -> None:
        request_id = bytes(range(16))
        request = KernelMemoryRequest(
            operation=4,
            pid=PID,
            process_creation_time=CREATION_TIME,
            address=ADDRESS,
            length=len(ORIGINAL),
            expected=ORIGINAL,
            data=REPLACEMENT,
            session_nonce=0x1122334455667788,
            request_id=request_id,
        )

        encoded = request.pack()
        decoded = KernelMemoryRequest.unpack(encoded)

        self.assertEqual(decoded, request)
        self.assertEqual(encoded[:4], b"KMRQ")
        self.assertEqual(struct.unpack_from("<H", encoded, 4)[0], 1)
        self.assertEqual(struct.unpack_from("<I", encoded, 8)[0], len(encoded))
        self.assertEqual(encoded[-8:], ORIGINAL + REPLACEMENT)

    def test_response_requires_exact_size_version_and_request_correlation(self) -> None:
        request = KernelMemoryRequest(
            operation=3,
            pid=PID,
            process_creation_time=CREATION_TIME,
            address=ADDRESS,
            length=4,
            session_nonce=7,
            request_id=b"A" * 16,
        )
        response = KernelMemoryResponse(
            operation=3,
            status=0,
            pid=PID,
            process_creation_time=CREATION_TIME,
            address=ADDRESS,
            requested_length=4,
            bytes_transferred=4,
            data=ORIGINAL,
            session_nonce=7,
            request_id=b"A" * 16,
        )
        encoded = response.pack()

        self.assertEqual(
            KernelMemoryResponse.unpack(encoded, expected_request=request), response
        )
        with self.assertRaisesRegex(KernelMemoryProtocolError, "total size"):
            KernelMemoryResponse.unpack(encoded + b"\x00", expected_request=request)
        wrong_id = bytearray(encoded)
        wrong_id[64:80] = b"B" * 16
        with self.assertRaisesRegex(KernelMemoryProtocolError, "request_id"):
            KernelMemoryResponse.unpack(bytes(wrong_id), expected_request=request)

    def test_version_payload_and_transport_allowlists_fail_closed(self) -> None:
        info = KernelMemoryVersionInfo.unpack(KernelMemoryVersionInfo().pack())
        self.assertEqual(info.protocol_min, 1)
        self.assertEqual(info.max_write_bytes, 4096)
        with self.assertRaisesRegex(KernelMemoryProtocolError, "allowlisted"):
            KernelMemoryRequest(operation=99).pack()
        with self.assertRaisesRegex(ValueError, "device path"):
            WindowsKernelMemoryBackend(
                device_path=r"\\.\UnlistedKernelDevice", platform_name="linux"
            )
        with self.assertRaisesRegex(ValueError, "allowlist cannot be expanded"):
            WindowsKernelMemoryBackend(
                device_path=r"\\.\UnlistedKernelDevice",
                allowed_device_paths=(r"\\.\UnlistedKernelDevice",),
                platform_name="linux",
            )
        self.assertEqual(IOCTL_KM_READ, 0x22E408)

    def test_native_source_mechanically_matches_python_ioctl_abi(self) -> None:
        root = Path(__file__).resolve().parents[1]
        header = (root / "native" / "kernel_memory_driver" / "protocol.h").read_text(
            encoding="utf-8"
        )
        driver = (root / "native" / "kernel_memory_driver" / "driver.c").read_text(
            encoding="utf-8"
        )
        flattened = header.replace("\\\n", " ")

        macro_values = {
            "KMD_PROTOCOL_VERSION": kernel_memory_module.PROTOCOL_VERSION,
            "KMD_REQUEST_MAGIC": kernel_memory_module.REQUEST_MAGIC,
            "KMD_RESPONSE_MAGIC": kernel_memory_module.RESPONSE_MAGIC,
            "KMD_VERSION_MAGIC": kernel_memory_module.VERSION_MAGIC,
            "KMD_OPERATION_VERSION": kernel_memory_module.OP_VERSION,
            "KMD_OPERATION_QUERY_PROCESS": kernel_memory_module.OP_QUERY_PROCESS,
            "KMD_OPERATION_READ": kernel_memory_module.OP_READ,
            "KMD_OPERATION_WRITE": kernel_memory_module.OP_WRITE,
        }
        for name, expected in macro_values.items():
            match = re.search(rf"#define\s+{name}\s+(0x[0-9A-Fa-f]+|\d+)u?", header)
            self.assertIsNotNone(match, name)
            self.assertEqual(int(match.group(1), 0), expected, name)

        ioctls = {
            "IOCTL_KMD_VERSION": kernel_memory_module.IOCTL_KM_VERSION,
            "IOCTL_KMD_QUERY_PROCESS": kernel_memory_module.IOCTL_KM_QUERY_PROCESS,
            "IOCTL_KMD_READ": kernel_memory_module.IOCTL_KM_READ,
            "IOCTL_KMD_WRITE": kernel_memory_module.IOCTL_KM_WRITE,
        }
        expected_functions = {
            "IOCTL_KMD_VERSION": 0x900,
            "IOCTL_KMD_QUERY_PROCESS": 0x901,
            "IOCTL_KMD_READ": 0x902,
            "IOCTL_KMD_WRITE": 0x903,
        }
        for name, ioctl in ioctls.items():
            match = re.search(
                rf"#define\s+{name}\s+CTL_CODE\(FILE_DEVICE_UNKNOWN,\s*"
                rf"(0x[0-9A-Fa-f]+),\s*METHOD_BUFFERED,\s*"
                rf"FILE_READ_DATA\s*\|\s*FILE_WRITE_DATA\)",
                flattened,
            )
            self.assertIsNotNone(match, name)
            self.assertEqual(int(match.group(1), 16), expected_functions[name])
            self.assertEqual((ioctl >> 2) & 0xFFF, expected_functions[name])
            self.assertEqual(ioctl & 0x3, kernel_memory_module.METHOD_BUFFERED)
            self.assertEqual((ioctl >> 14) & 0x3, 0x3)
            self.assertEqual((ioctl >> 16) & 0xFFFF, kernel_memory_module.FILE_DEVICE_UNKNOWN)

        c_types = {"ULONG": "I", "USHORT": "H", "LONG": "i", "ULONGLONG": "Q"}

        def parse_struct(name: str) -> tuple[list[str], struct.Struct]:
            match = re.search(
                rf"typedef\s+struct\s+_{name}\s*\{{(.*?)\}}\s*{name}",
                header,
                re.DOTALL,
            )
            self.assertIsNotNone(match, name)
            fields: list[str] = []
            formats: list[str] = []
            for field in re.finditer(
                r"^\s*(ULONG|USHORT|LONG|ULONGLONG|UCHAR)\s+"
                r"(\w+)(?:\[(\d+)\])?;",
                match.group(1),
                re.MULTILINE,
            ):
                c_type, field_name, count = field.groups()
                fields.append(field_name)
                if c_type == "UCHAR":
                    self.assertIsNotNone(count, field_name)
                    formats.append(f"{count}s")
                else:
                    self.assertIsNone(count, field_name)
                    formats.append(c_types[c_type])
            return fields, struct.Struct("<" + "".join(formats))

        request_fields, request_struct = parse_struct("KMD_REQUEST")
        response_fields, response_struct = parse_struct("KMD_RESPONSE")
        version_fields, version_struct = parse_struct("KMD_VERSION_INFO")
        self.assertEqual(request_fields, [
            "Magic", "Version", "HeaderSize", "TotalSize", "Operation", "Flags",
            "Pid", "ProcessCreationTime", "Address", "SessionNonce", "Length",
            "ExpectedLength", "DataLength", "Reserved", "RequestId",
        ])
        self.assertEqual(response_fields, [
            "Magic", "Version", "HeaderSize", "TotalSize", "Operation", "Status",
            "Pid", "ProcessCreationTime", "Address", "SessionNonce", "RequestedLength",
            "BytesTransferred", "DataLength", "Flags", "RequestId",
        ])
        self.assertEqual(version_fields, [
            "Magic", "StructVersion", "Size", "ProtocolMin", "ProtocolMax",
            "MaxReadBytes", "MaxWriteBytes", "OperationMask",
        ])
        self.assertEqual(request_struct.format, kernel_memory_module._REQUEST_STRUCT.format)
        self.assertEqual(response_struct.format, kernel_memory_module._RESPONSE_STRUCT.format)
        self.assertEqual(version_struct.format, kernel_memory_module._VERSION_STRUCT.format)
        self.assertEqual((request_struct.size, response_struct.size, version_struct.size), (80, 80, 24))
        self.assertEqual(
            {name: int(size) for name, size in re.findall(r"C_ASSERT\(sizeof\((KMD_\w+)\)\s*==\s*(\d+)\)", header)},
            {"KMD_REQUEST": 80, "KMD_RESPONSE": 80, "KMD_VERSION_INFO": 24},
        )

        dispatch = dict(
            re.findall(
                r"case\s+(IOCTL_KMD_\w+)\s*:\s*"
                r"expectedOperation\s*=\s*(KMD_OPERATION_\w+)\s*;",
                driver,
                re.DOTALL,
            )
        )
        self.assertEqual(dispatch, {
            "IOCTL_KMD_VERSION": "KMD_OPERATION_VERSION",
            "IOCTL_KMD_QUERY_PROCESS": "KMD_OPERATION_QUERY_PROCESS",
            "IOCTL_KMD_READ": "KMD_OPERATION_READ",
            "IOCTL_KMD_WRITE": "KMD_OPERATION_WRITE",
        })

    def test_operation_specific_protocol_fields_fail_closed(self) -> None:
        invalid_requests = [
            KernelMemoryRequest(operation=1, pid=PID),
            KernelMemoryRequest(
                operation=2,
                pid=PID,
                process_creation_time=0,
            ),
            KernelMemoryRequest(
                operation=3,
                pid=PID,
                process_creation_time=CREATION_TIME,
                address=ADDRESS,
                length=HARD_MAX_READ_BYTES + 1,
            ),
            KernelMemoryRequest(
                operation=4,
                pid=PID,
                process_creation_time=CREATION_TIME,
                address=ADDRESS,
                length=1,
                expected=b"A",
                data=b"",
            ),
        ]
        for request in invalid_requests:
            with self.subTest(operation=request.operation):
                with self.assertRaises(KernelMemoryProtocolError):
                    request.pack()

        with self.assertRaisesRegex(KernelMemoryProtocolError, "session_nonce"):
            KernelMemoryRequest(operation=1, session_nonce=0).pack()
        with self.assertRaisesRegex(KernelMemoryProtocolError, "request_id"):
            KernelMemoryRequest(
                operation=1,
                session_nonce=1,
                request_id=b"\x00" * 16,
            ).pack()

    def test_response_creation_identity_is_correlated(self) -> None:
        request = KernelMemoryRequest(
            operation=3,
            pid=PID,
            process_creation_time=CREATION_TIME,
            address=ADDRESS,
            length=len(ORIGINAL),
            session_nonce=8,
            request_id=b"C" * 16,
        )
        response = KernelMemoryResponse(
            operation=3,
            status=0,
            pid=PID,
            process_creation_time=CREATION_TIME + 1,
            address=ADDRESS,
            requested_length=len(ORIGINAL),
            bytes_transferred=len(ORIGINAL),
            data=ORIGINAL,
            session_nonce=8,
            request_id=b"C" * 16,
        )
        with self.assertRaisesRegex(KernelMemoryProtocolError, "creation identity"):
            KernelMemoryResponse.unpack(
                response.pack(), expected_request=request
            )

    def test_successful_query_response_rejects_unexpected_data(self) -> None:
        response = KernelMemoryResponse(
            operation=2,
            status=0,
            pid=PID,
            process_creation_time=CREATION_TIME,
            bytes_transferred=1,
            data=b"X",
            session_nonce=1,
            request_id=b"Q" * 16,
        )
        with self.assertRaisesRegex(KernelMemoryProtocolError, "query response"):
            response.pack()

    def test_response_requires_nonzero_correlation_fields(self) -> None:
        response = KernelMemoryResponse(
            operation=2,
            status=0,
            pid=PID,
            process_creation_time=CREATION_TIME,
        )
        with self.assertRaisesRegex(KernelMemoryProtocolError, "session nonce"):
            response.pack()

        response = KernelMemoryResponse(
            operation=2,
            status=0,
            pid=PID,
            process_creation_time=CREATION_TIME,
            session_nonce=1,
        )
        with self.assertRaisesRegex(KernelMemoryProtocolError, "request_id"):
            response.pack()

    def test_production_backend_rejects_invalid_direct_calls_before_transport(self) -> None:
        backend = WindowsKernelMemoryBackend(platform_name="linux")
        invalid_calls = [
            lambda: backend.query_process(0, CREATION_TIME),
            lambda: backend.read(
                PID, CREATION_TIME, ADDRESS, HARD_MAX_READ_BYTES + 1
            ),
            lambda: backend.read(PID, CREATION_TIME, 0xFFFF800000001000, 4),
            lambda: backend.read(PID, CREATION_TIME, "0x100000", 4),
            lambda: backend.write(PID, CREATION_TIME, ADDRESS, b"A", b"BB"),
            lambda: backend.write(PID, CREATION_TIME, ADDRESS, "A", b"B"),
        ]
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(KernelMemoryBackendError) as caught:
                    call()
                self.assertEqual(caught.exception.status, "failed")


class KernelDriverMemoryProviderTests(unittest.TestCase):
    def _provider(
        self, backend: FakeKernelMemoryBackend | None = None
    ) -> tuple[KernelDriverMemoryProvider, FakeKernelMemoryBackend]:
        fake = backend or FakeKernelMemoryBackend()
        return KernelDriverMemoryProvider(backend=fake, platform_name="win32"), fake

    def test_read_captures_exact_before_after_and_audited_artifacts(self) -> None:
        provider, backend = self._provider()
        plan = provider.plan(_request("read", _read_params()))
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "test-double")
        self.assertFalse(result.provenance["execution"]["real_driver_completed"])
        self.assertTrue(result.provenance["execution"]["test_double"])
        self.assertEqual(result.before_snapshot["memory"]["hex"], ORIGINAL.hex())
        self.assertEqual(result.after_snapshot["memory"]["hex"], ORIGINAL.hex())
        self.assertEqual(backend.bytes_at(ADDRESS, 4), ORIGINAL)
        self.assertEqual(result.rollback_plan["mode"], "not_required")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = provider.collect_artifacts(result, str(root))
            audit = next(item for item in bundle.artifacts if item.kind == "kernel-memory-audit")
            manifest = next(item for item in bundle.artifacts if item.kind == "evidence-manifest")
            rollback_metadata = next(
                item
                for item in bundle.artifacts
                if item.kind == "kernel-memory-rollback-metadata"
            )
            provenance = next(
                item
                for item in bundle.artifacts
                if item.kind == "kernel-memory-provenance"
            )
            dashboard_trace = next(
                item
                for item in bundle.artifacts
                if item.kind == "kernel-memory-dashboard-trace"
            )
            before = next(
                item for item in bundle.artifacts if item.kind == "kernel-memory-before-snapshot"
            )
            after = next(
                item for item in bundle.artifacts if item.kind == "kernel-memory-after-snapshot"
            )
            self.assertEqual((root / before.path).read_bytes(), ORIGINAL)
            self.assertEqual((root / after.path).read_bytes(), ORIGINAL)
            audit_payload = json.loads((root / audit.path).read_text(encoding="utf-8"))
            contract = validate_capability_audit_record(audit_payload)
            self.assertTrue(contract.ok, contract.errors)
            rollback_payload = json.loads(
                (root / rollback_metadata.path).read_text(encoding="utf-8")
            )
            self.assertEqual(rollback_payload["rollback_plan"]["mode"], "not_required")
            provenance_payload = json.loads(
                (root / provenance.path).read_text(encoding="utf-8")
            )
            self.assertIn("plan", provenance_payload)
            trace_payload = json.loads(
                (root / dashboard_trace.path).read_text(encoding="utf-8")
            )
            self.assertEqual(trace_payload["trace"][0]["status"], "test-double")
            manifest_payload = json.loads(
                (root / manifest.path).read_text(encoding="utf-8")
            )
            self.assertTrue(manifest_payload["entries"])
            for entry in manifest_payload["entries"]:
                data = (root / entry["path"]).read_bytes()
                self.assertEqual(entry["size"], len(data))
                self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertFalse(
                any(entry["path"] == manifest.path for entry in manifest_payload["entries"]),
                "manifest must not hash itself",
            )

    def test_write_records_before_after_and_compare_restore_rollback(self) -> None:
        provider, backend = self._provider()
        result = provider.execute(provider.plan(_request("write", _write_params())))

        self.assertEqual(result.status, "test-double")
        self.assertEqual(result.before_snapshot["memory"]["hex"], ORIGINAL.hex())
        self.assertEqual(result.after_snapshot["memory"]["hex"], REPLACEMENT.hex())
        self.assertTrue(result.rollback_plan["active"])
        self.assertEqual(backend.bytes_at(ADDRESS, 4), REPLACEMENT)

        rollback = provider.rollback(result)

        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(rollback.restored)
        self.assertEqual(rollback.details["status"], "test-double-restored")
        self.assertEqual(backend.bytes_at(ADDRESS, 4), ORIGINAL)
        self.assertFalse(result.rollback_plan["active"])
        self.assertTrue(
            any(item["kind"] == "kernel_memory_rollback" for item in result.dashboard_trace)
        )

    def test_post_copy_failure_is_compensated_with_exact_current_precondition(self) -> None:
        backend = FakeKernelMemoryBackend()
        backend.fail_after_mutation = 1
        provider, backend = self._provider(backend)

        result = provider.execute(provider.plan(_request("write", _write_params())))

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.bytes_at(ADDRESS, 4), ORIGINAL)
        self.assertTrue(result.after_snapshot["compensation"]["restored"])
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(result.rollback_plan["status"], "compensated")
        write_calls = [call for call in backend.calls if call[0] == "write"]
        self.assertEqual(len(write_calls), 2)
        self.assertEqual(write_calls[1][3], REPLACEMENT)
        self.assertEqual(write_calls[1][4], ORIGINAL)
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)

    def test_failed_write_does_not_overwrite_unattributed_conflicting_bytes(self) -> None:
        conflict = bytes.fromhex("99 88 77 66")
        backend = FakeKernelMemoryBackend()
        backend.conflicting_failure = conflict
        provider, backend = self._provider(backend)

        result = provider.execute(provider.plan(_request("write", _write_params())))

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.bytes_at(ADDRESS, 4), conflict)
        self.assertEqual(result.after_snapshot["compensation"]["status"], "state_conflict")
        self.assertFalse(result.after_snapshot["compensation"]["attempted"])
        self.assertEqual(result.rollback_plan["mode"], "manual_review")
        self.assertFalse(result.rollback_plan["active"])
        write_calls = [call for call in backend.calls if call[0] == "write"]
        self.assertEqual(len(write_calls), 1)

    def test_rollback_rejects_identity_drift(self) -> None:
        provider, backend = self._provider()
        result = provider.execute(provider.plan(_request("write", _write_params())))
        backend.creation_time += 1

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(backend.bytes_at(ADDRESS, 4), REPLACEMENT)
        self.assertTrue(result.rollback_plan["active"])

    def test_rollback_rejects_tampered_address_allowlist(self) -> None:
        provider, backend = self._provider()
        result = provider.execute(provider.plan(_request("write", _write_params())))
        result.rollback_plan["allowed_ranges"] = []

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(backend.bytes_at(ADDRESS, 4), REPLACEMENT)
        self.assertFalse(
            any(
                call[0] == "write" and call[4] == ORIGINAL
                for call in backend.calls
            )
        )

    def test_rollback_rejects_tampered_snapshot_metadata(self) -> None:
        provider, backend = self._provider()
        result = provider.execute(provider.plan(_request("write", _write_params())))
        tampered = bytes.fromhex("01 02 03 04")
        result.rollback_plan["before_hex"] = tampered.hex()

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(backend.bytes_at(ADDRESS, 4), REPLACEMENT)
        self.assertFalse(
            any(
                call[0] == "write" and call[4] == tampered
                for call in backend.calls
            )
        )

    def test_identity_drift_blocks_execution_before_write(self) -> None:
        provider, backend = self._provider()
        plan = provider.plan(_request("write", _write_params()))
        backend.creation_time += 1

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.bytes_at(ADDRESS, 4), ORIGINAL)
        self.assertFalse(any(call[0] == "write" for call in backend.calls))
        self.assertTrue(
            any(
                "identity" in error.lower() or "precondition" in error.lower()
                for error in validation.errors
            )
        )

    def test_bounds_allowlist_expected_bytes_and_authorization_fail_closed(self) -> None:
        provider, backend = self._provider()
        cases = [
            _request(
                "read",
                {
                    "address": ADDRESS,
                    "size": HARD_MAX_READ_BYTES + 1,
                    "allowed_ranges": [[ADDRESS, ADDRESS + HARD_MAX_READ_BYTES + 1]],
                },
            ),
            _request(
                "read",
                {
                    "address": ADDRESS,
                    "size": 4,
                    "allowed_ranges": [[ADDRESS + 1, ADDRESS + 5]],
                },
            ),
            _request(
                "write",
                {
                    **_write_params(),
                    "authorized": False,
                },
            ),
            _request(
                "write",
                {
                    **_write_params(),
                    "expected_original_bytes": "00 00 00 00",
                },
            ),
            _request(
                "read",
                {
                    "address": 0xFFFF800000001000,
                    "size": 4,
                    "allowed_ranges": [[0xFFFF800000001000, 0xFFFF800000001004]],
                },
            ),
        ]
        for request in cases:
            with self.subTest(params=request.params):
                plan = provider.plan(request)
                self.assertFalse(provider.validate(plan).ok)
                result = provider.execute(plan)
                self.assertEqual(result.status, "failed")
        self.assertEqual(backend.bytes_at(ADDRESS, 4), ORIGINAL)
        self.assertFalse(any(call[0] == "write" for call in backend.calls))

    def test_dependency_gated_and_platform_unavailable_are_not_success(self) -> None:
        gated = KernelDriverMemoryProvider(
            backend=UnavailableKernelMemoryBackend(
                "signed lab driver service/device is missing",
                status="dependency-gated",
            ),
            platform_name="win32",
        )
        gated_plan = gated.plan(_request("query", {}))
        gated_validation = gated.validate(gated_plan)
        gated_result = gated.execute(gated_plan)
        self.assertFalse(gated_validation.ok)
        self.assertEqual(gated_result.status, "dependency-gated")
        self.assertFalse(gated_result.provenance["execution"]["real_driver_completed"])

        unavailable = KernelDriverMemoryProvider(platform_name="linux")
        unavailable_plan = unavailable.plan(_request("query", {}))
        unavailable_result = unavailable.execute(unavailable_plan)
        self.assertEqual(unavailable_result.status, "unavailable")
        self.assertFalse(unavailable_result.after_snapshot["side_effects"])

        incompatible_backend = FakeKernelMemoryBackend()
        incompatible_backend.protocol_version = 2
        incompatible = KernelDriverMemoryProvider(
            backend=incompatible_backend,
            platform_name="win32",
        )
        incompatible_result = incompatible.execute(
            incompatible.plan(_request("version", {}))
        )
        self.assertEqual(incompatible_result.status, "dependency-gated")

    def test_injected_backend_cannot_self_attest_as_production(self) -> None:
        backend = FakeKernelMemoryBackend()
        backend.test_double = False
        provider = KernelDriverMemoryProvider(backend=backend, platform_name="win32")

        result = provider.execute(provider.plan(_request("read", _read_params())))

        self.assertEqual(result.status, "test-double")
        self.assertTrue(result.provenance["execution"]["test_double"])
        self.assertFalse(result.provenance["execution"]["real_driver_completed"])
        production_check = next(
            item
            for item in result.provenance["validation"]["checks"]
            if item["name"] == "production_backend"
        )
        self.assertEqual(production_check["status"], "test-double")
        self.assertEqual(
            result.provenance["execution"]["backend"]["backend_class"],
            "test-double",
        )


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("RUN_KERNEL_MEMORY_SMOKE") == "1",
    "set RUN_KERNEL_MEMORY_SMOKE=1 on a signed-driver lab host",
)
class KernelMemoryDriverSmokeTests(unittest.TestCase):
    def test_real_driver_version_and_optional_allowlisted_read(self) -> None:
        backend = WindowsKernelMemoryBackend(DEFAULT_DEVICE_PATH)
        provider = KernelDriverMemoryProvider(backend=backend, platform_name="win32")
        version_request = CapabilityRequest(
            capability="kernel_driver_memory_runtime",
            action="version",
            target=TargetIdentity(kind="driver", display_name="ReverseAnalyzerKernelMemory"),
            session_id="kernel-memory-real-version-smoke",
        )
        result = provider.execute(provider.plan(version_request))
        self.assertEqual(result.status, "ok", result.report_section)
        self.assertTrue(result.provenance["execution"]["real_driver_completed"])

        required = {
            "KERNEL_MEMORY_SMOKE_PID",
            "KERNEL_MEMORY_SMOKE_CREATION_TIME",
            "KERNEL_MEMORY_SMOKE_ADDRESS",
            "KERNEL_MEMORY_SMOKE_SIZE",
        }
        if not required.issubset(os.environ):
            self.skipTest("target read variables are not configured")
        pid = int(os.environ["KERNEL_MEMORY_SMOKE_PID"], 0)
        creation = int(os.environ["KERNEL_MEMORY_SMOKE_CREATION_TIME"], 0)
        address = int(os.environ["KERNEL_MEMORY_SMOKE_ADDRESS"], 0)
        size = int(os.environ["KERNEL_MEMORY_SMOKE_SIZE"], 0)
        read_request = CapabilityRequest(
            capability="kernel_driver_memory_runtime",
            action="read",
            target=TargetIdentity(
                kind="process",
                pid=pid,
                display_name="allowlisted-smoke-target",
                metadata={"process_creation_time": creation},
            ),
            params={
                "address": address,
                "size": size,
                "allowed_ranges": [[address, address + size]],
            },
            session_id="kernel-memory-real-read-smoke",
        )
        read_result = provider.execute(provider.plan(read_request))
        self.assertEqual(read_result.status, "ok", read_result.report_section)
        self.assertEqual(read_result.after_snapshot["memory"]["size"], size)


if __name__ == "__main__":
    unittest.main()
