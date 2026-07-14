import struct
import unittest
from typing import Any, Mapping

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    validate_capability_audit_record,
)
from reverse_analyzer.providers.memory_runtime import MemoryRuntimeProvider
from reverse_analyzer.providers.memory_schema import (
    compile_memory_schema,
    decode_structure,
    read_structure_field,
    write_structure_field,
)
from tests.test_memory_runtime_provider import FakeMemoryRuntimeBackend


SCHEMA = {
    "type": "struct",
    "endian": "little",
    "size": 24,
    "fields": [
        {"name": "version", "offset": 0, "type": "uint16"},
        {
            "name": "flags",
            "offset": 2,
            "type": "bitfield",
            "storage": "uint16",
            "bits": [
                {"name": "active", "offset": 0, "width": 1},
                {"name": "mode", "offset": 1, "width": 3},
                {"name": "team", "offset": 4, "width": 4},
            ],
        },
        {
            "name": "points",
            "offset": 4,
            "type": "array",
            "count": 2,
            "element": {
                "type": "struct",
                "size": 8,
                "fields": [
                    {"name": "x", "offset": 0, "type": "int16"},
                    {"name": "y", "offset": 2, "type": "int16"},
                    {"name": "tag", "offset": 4, "type": "bytes", "size": 4},
                ],
            },
        },
        {"name": "checksum", "offset": 20, "type": "uint32"},
    ],
}


def fixture_bytes() -> bytes:
    return b"".join(
        [
            struct.pack("<H", 3),
            struct.pack("<H", 0x00B5),
            struct.pack("<hh", 10, -20),
            b"ABCD",
            struct.pack("<hh", 30, -40),
            b"EFGH",
            struct.pack("<I", 0x12345678),
        ]
    )


class MemorySchemaUnitTests(unittest.TestCase):
    def test_decodes_nested_struct_array_bytes_and_bitfields(self) -> None:
        layout = compile_memory_schema(SCHEMA)
        decoded = decode_structure(fixture_bytes(), layout)

        self.assertEqual(layout.size, 24)
        self.assertEqual(decoded["value"]["version"], 3)
        self.assertEqual(decoded["value"]["flags"], {"active": 1, "mode": 2, "team": 11})
        self.assertEqual(decoded["value"]["points"][0]["tag"], "41424344")
        self.assertEqual(read_structure_field(fixture_bytes(), layout, "points[1].y"), -40)
        self.assertEqual(read_structure_field(fixture_bytes(), layout, "flags.mode"), 2)

    def test_field_patch_preserves_unrelated_bytes_and_bits(self) -> None:
        original = fixture_bytes()
        patched = write_structure_field(
            original,
            SCHEMA,
            "flags.mode",
            5,
            expected=2,
        )
        output = patched["data"]

        self.assertEqual(read_structure_field(output, SCHEMA, "flags.mode"), 5)
        self.assertEqual(read_structure_field(output, SCHEMA, "flags.active"), 1)
        self.assertEqual(read_structure_field(output, SCHEMA, "flags.team"), 11)
        self.assertEqual(output[:2], original[:2])
        self.assertEqual(output[4:], original[4:])

        nested = write_structure_field(
            original,
            SCHEMA,
            "points[0].x",
            77,
            expected=10,
        )
        self.assertEqual(read_structure_field(nested["data"], SCHEMA, "points[0].x"), 77)
        self.assertEqual(read_structure_field(nested["data"], SCHEMA, "points[0].y"), -20)

    def test_schema_and_field_preconditions_fail_closed(self) -> None:
        invalid_schemas = [
            {
                "type": "struct",
                "fields": [
                    {"name": "a", "offset": 0, "type": "uint32"},
                    {"name": "b", "offset": 2, "type": "uint32"},
                ],
            },
            {
                "type": "struct",
                "fields": [
                    {
                        "name": "items",
                        "type": "array",
                        "count": 100,
                        "element": "uint8",
                    }
                ],
            },
            {
                "type": "struct",
                "fields": [
                    {
                        "name": "flags",
                        "type": "bitfield",
                        "storage": "uint8",
                        "bits": [
                            {"name": "a", "offset": 0, "width": 4},
                            {"name": "b", "offset": 3, "width": 2},
                        ],
                    }
                ],
            },
        ]
        with self.assertRaisesRegex(ValueError, "overlaps"):
            compile_memory_schema(invalid_schemas[0])
        with self.assertRaisesRegex(ValueError, "array count"):
            compile_memory_schema(invalid_schemas[1], max_array_length=8)
        with self.assertRaisesRegex(ValueError, "overlaps"):
            compile_memory_schema(invalid_schemas[2])
        with self.assertRaisesRegex(ValueError, "precondition mismatch"):
            write_structure_field(
                fixture_bytes(), SCHEMA, "points[0].x", 77, expected=11
            )
        with self.assertRaisesRegex(ValueError, "outside length"):
            read_structure_field(fixture_bytes(), SCHEMA, "points[2].x")


class MemorySchemaProviderTests(unittest.TestCase):
    pid = 4242
    address = 0x3000

    def setUp(self) -> None:
        self.backend = FakeMemoryRuntimeBackend(pid=self.pid)
        self.backend.allocations[self.address] = {
            "data": bytearray(fixture_bytes()),
            "protection": 0x04,
        }
        self.provider = MemoryRuntimeProvider(
            backend=self.backend,
            platform_name="win32",
        )

    def request(self, action: str, params: Mapping[str, Any]) -> CapabilityRequest:
        return CapabilityRequest(
            capability="memory_runtime",
            action=action,
            target=TargetIdentity(
                kind="process", pid=self.pid, display_name="schema-fixture"
            ),
            params=dict(params),
            session_id=f"memory-schema-{action}",
            provenance={"source": "test_memory_schema"},
        )

    def execute(self, action: str, params: Mapping[str, Any]) -> tuple[Any, Any, Any]:
        plan = self.provider.plan(self.request(action, params))
        validation = self.provider.validate(plan)
        result = self.provider.execute(plan)
        return plan, validation, result

    def assert_audit(self, plan: Any, validation: Any, result: Any) -> None:
        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_schema_read_returns_full_value_and_selected_field(self) -> None:
        plan, validation, result = self.execute(
            "schema_read",
            {"address": self.address, "schema": SCHEMA, "field_path": "points[1].tag"},
        )

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok", result.report_section)
        operation = result.report_section["operation"]
        self.assertEqual(operation["structured_field"]["value"], "45464748")
        self.assertEqual(operation["structured_value"]["value"]["checksum"], 0x12345678)
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assert_audit(plan, validation, result)

    def test_schema_write_round_trip_and_rollback(self) -> None:
        original = fixture_bytes()
        plan, validation, result = self.execute(
            "schema_write",
            {
                "address": self.address,
                "schema": SCHEMA,
                "field_path": "flags.mode",
                "field_value": 5,
                "expected_field_value": 2,
            },
        )

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok", result.report_section)
        current = self.backend.bytes_at(self.address, len(original))
        self.assertEqual(read_structure_field(current, SCHEMA, "flags.mode"), 5)
        self.assertEqual(current[:2], original[:2])
        self.assertEqual(current[4:], original[4:])
        self.assertTrue(result.rollback_plan["supported"])
        rollback = self.provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertEqual(self.backend.bytes_at(self.address, len(original)), original)
        self.assert_audit(plan, validation, result)

    def test_schema_write_expected_mismatch_never_calls_backend_write(self) -> None:
        plan, validation, result = self.execute(
            "schema_write",
            {
                "address": self.address,
                "schema": SCHEMA,
                "field_path": "points[0].x",
                "field_value": 99,
                "expected_field_value": 11,
            },
        )

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertFalse(any(call[0] == "write" for call in self.backend.calls))
        self.assertEqual(self.backend.bytes_at(self.address, 24), fixture_bytes())
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assert_audit(plan, validation, result)

    def test_invalid_schema_is_rejected_before_execution(self) -> None:
        plan, validation, result = self.execute(
            "schema_write",
            {
                "address": self.address,
                "schema": {
                    "type": "struct",
                    "fields": [{"name": "bad", "type": "uint32", "offset": -1}],
                },
                "field_path": "bad",
                "field_value": 1,
                "expected_field_value": 0,
            },
        )

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertFalse(any(call[0] == "write" for call in self.backend.calls))
        self.assertIn("offset for bad", " ".join(plan.parameters["parameter_errors"]))


if __name__ == "__main__":
    unittest.main()
