from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Optional

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.hardware_identity import (
    HardwareIdentityProvider,
    WindowsHardwareIdentityTransport,
)


class FakeHardwareIdentityTransport:
    name = "deterministic-test-transport"
    available = True
    unavailable_reason: Optional[str] = None
    supports_mutation = True

    def __init__(self, *, partial: bool = False) -> None:
        self.state: dict[str, Any] = {
            "machine_guid": "machine-guid-before",
            "smbios": {
                "system": {
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "serial_number": "SYSTEM-001",
                },
                "baseboard": {"serial_number": "BOARD-001"},
            },
            "volumes": [
                {
                    "root": "C:\\",
                    "serial_number": "A1B2C3D4",
                    "label": "System",
                    "file_system": "NTFS",
                }
            ],
            "network_adapters": [
                {
                    "adapter_name": "adapter-1",
                    "physical_address": "00-11-22-33-44-55",
                    "if_index": 7,
                    "if_type": 6,
                    "oper_status": 1,
                }
            ],
        }
        self.partial = partial
        self.calls: list[tuple[Any, ...]] = []
        self._receipts: dict[str, dict[str, Any]] = {}

    def describe(self) -> Mapping[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "supports_snapshot": True,
            "supports_mutation": self.supports_mutation,
            "production_transport": False,
        }

    def snapshot(
        self,
        target: TargetIdentity,
        surfaces: Sequence[str],
    ) -> Mapping[str, Any]:
        self.calls.append(("snapshot", target.display_name, tuple(surfaces)))
        identity = {
            key: copy.deepcopy(self.state[key])
            for key in surfaces
            if key in self.state
        }
        statuses = {key: {"status": "ok"} for key in identity}
        if self.partial and "smbios" in surfaces:
            identity.pop("smbios", None)
            statuses["smbios"] = {
                "status": "unavailable",
                "reason": "synthetic firmware access denial",
            }
        return {
            "identity": identity,
            "surface_status": statuses,
            "source": "deterministic transport fixture",
        }

    def apply(
        self,
        target: TargetIdentity,
        changes: Mapping[str, Any],
        *,
        session_id: str,
        precondition_hash: str,
        change_id: str,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "apply",
                target.display_name,
                copy.deepcopy(dict(changes)),
                session_id,
                precondition_hash,
                change_id,
            )
        )
        receipt = {
            "receipt_id": f"receipt-{session_id}",
            "rollback_token": f"token-{session_id}",
        }
        self._receipts[receipt["receipt_id"]] = copy.deepcopy(self.state)
        for key, value in changes.items():
            self.state[key] = copy.deepcopy(value)
        return receipt

    def rollback(
        self,
        target: TargetIdentity,
        receipt: Mapping[str, Any],
        *,
        session_id: str,
    ) -> Mapping[str, Any]:
        self.calls.append(
            ("rollback", target.display_name, copy.deepcopy(dict(receipt)), session_id)
        )
        receipt_id = str(receipt.get("receipt_id") or "")
        self.state = copy.deepcopy(self._receipts[receipt_id])
        return {"status": "ok", "receipt_id": receipt_id}


class SnapshotOnlyTransport(FakeHardwareIdentityTransport):
    supports_mutation = False

    def apply(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
        raise AssertionError("snapshot-only transport must not execute a mutation")


class HardwareIdentityProviderTests(unittest.TestCase):
    @staticmethod
    def _request(
        *,
        action: str = "virtualize",
        params: Optional[Mapping[str, Any]] = None,
        session_id: str = "hardware-identity-test",
    ) -> CapabilityRequest:
        values: dict[str, Any] = {}
        if action == "virtualize":
            values = {
                "changes": {"machine_guid": "machine-guid-virtualized"},
                "change_id": "CHANGE-42",
                "reason": "deterministic repair fixture",
            }
        values.update(params or {})
        return CapabilityRequest(
            capability="hardware_identity_virtualization",
            action=action,
            target=TargetIdentity(
                kind="machine",
                display_name="local-test-host",
                metadata={"scope": "local"},
            ),
            params=values,
            session_id=session_id,
            provenance={"source": "test_hardware_identity_provider"},
        )

    def test_virtualization_lifecycle_audit_artifacts_and_rollback(self) -> None:
        transport = FakeHardwareIdentityTransport()
        provider = HardwareIdentityProvider(transport=transport)
        request = self._request()

        self.assertTrue(provider.supports(request))
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "mocked")
        self.assertEqual(
            result.before_snapshot["identity"]["machine_guid"],
            "machine-guid-before",
        )
        self.assertEqual(
            result.after_snapshot["identity"]["machine_guid"],
            "machine-guid-virtualized",
        )
        self.assertTrue(result.rollback_plan["supported"])
        self.assertEqual(result.rollback_plan["status"], "pending")
        self.assertIn("rollback_token", result.rollback_plan["receipt"])
        self.assertTrue(result.provenance["mocked"])
        self.assertFalse(result.provenance["production_transport"])

        audit = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(audit)
        self.assertTrue(contract.ok, contract.errors)
        json.dumps(audit.to_dict(), sort_keys=True)

        rollback = provider.rollback(result)
        repeated = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(rollback.restored)
        self.assertTrue(repeated.ok, repeated.details)
        self.assertFalse(repeated.restored)
        self.assertEqual(repeated.details["status"], "already_restored")
        self.assertEqual(transport.state["machine_guid"], "machine-guid-before")
        self.assertEqual(
            [item[0] for item in transport.calls].count("rollback"),
            1,
        )

        with tempfile.TemporaryDirectory() as out_dir:
            bundle = provider.collect_artifacts(result, out_dir)
            self.assertEqual(len(bundle.artifacts), 6)
            self.assertEqual(len(bundle.manifest_entries), 6)
            for artifact, entry in zip(bundle.artifacts, bundle.manifest_entries):
                path = Path(out_dir) / artifact.path
                self.assertTrue(path.is_file(), artifact.path)
                encoded = path.read_bytes()
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), entry["sha256"])
                self.assertEqual(len(encoded), entry["size"])
            session_artifact = next(
                item for item in bundle.artifacts if item.kind == "hardware-identity-audit"
            )
            payload = json.loads((Path(out_dir) / session_artifact.path).read_text())
            self.assertEqual(payload["session_id"], "hardware-identity-test")
            self.assertEqual(payload["rollback_plan"]["status"], "already_restored")
            persisted_contract = validate_capability_audit_record(payload)
            self.assertTrue(persisted_contract.ok, persisted_contract.errors)

    def test_precondition_drift_blocks_change_before_transport_apply(self) -> None:
        transport = FakeHardwareIdentityTransport()
        provider = HardwareIdentityProvider(transport=transport)
        plan = provider.plan(self._request())
        transport.state["machine_guid"] = "out-of-band-drift"

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertIn("hardware identity changed after planning", validation.errors)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertNotIn("apply", [item[0] for item in transport.calls])

    def test_rollback_refuses_to_overwrite_out_of_band_drift(self) -> None:
        transport = FakeHardwareIdentityTransport()
        provider = HardwareIdentityProvider(transport=transport)
        plan = provider.plan(self._request())
        result = provider.execute(plan)
        self.assertEqual(result.status, "mocked")
        transport.state["machine_guid"] = "third-party-change"

        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "precondition_drift")
        self.assertNotIn("rollback", [item[0] for item in transport.calls])
        self.assertEqual(transport.state["machine_guid"], "third-party-change")

    def test_snapshot_partial_status_preserves_real_available_surfaces(self) -> None:
        transport = FakeHardwareIdentityTransport(partial=True)
        provider = HardwareIdentityProvider(transport=transport)
        plan = provider.plan(self._request(action="snapshot"))
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "partial")
        self.assertIn("machine_guid", result.after_snapshot["identity"])
        self.assertNotIn("smbios", result.after_snapshot["identity"])
        self.assertEqual(
            result.after_snapshot["surface_status"]["smbios"]["status"],
            "unavailable",
        )
        self.assertFalse(result.rollback_plan["supported"])

    def test_snapshot_only_transport_dependency_gates_virtualization(self) -> None:
        transport = SnapshotOnlyTransport()
        provider = HardwareIdentityProvider(transport=transport)
        plan = provider.plan(self._request())

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        mutation_check = next(
            item for item in validation.checks if item["name"] == "mutation_transport"
        )
        self.assertEqual(mutation_check["status"], "unavailable")
        self.assertEqual(result.status, "unavailable")
        self.assertNotIn("apply", [item[0] for item in transport.calls])

    def test_non_windows_dependency_is_unavailable_not_fake_success(self) -> None:
        transport = WindowsHardwareIdentityTransport(platform_name="linux")
        provider = HardwareIdentityProvider(transport=transport)
        plan = provider.plan(self._request(action="snapshot"))

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        dependency = next(
            item for item in validation.checks if item["name"] == "transport_dependency"
        )
        self.assertEqual(dependency["status"], "unavailable")
        self.assertEqual(plan.before_snapshot["status"], "unavailable")
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.after_snapshot["side_effects"])

    @unittest.skipUnless(sys.platform.startswith("win"), "requires Windows public APIs")
    def test_windows_transport_collects_real_public_identity_surface(self) -> None:
        transport = WindowsHardwareIdentityTransport()
        request = self._request(
            action="snapshot",
            params={
                "surfaces": [
                    "machine_guid",
                    "smbios",
                    "volumes",
                    "network_adapters",
                ]
            },
            session_id="real-windows-public-identity",
        )
        provider = HardwareIdentityProvider(transport=transport)
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok")
        self.assertTrue(result.provenance["production_transport"])
        self.assertFalse(result.provenance["mocked"])
        identity = result.after_snapshot["identity"]
        self.assertTrue(identity["machine_guid"])
        self.assertEqual(len(identity["smbios"]["table_sha256"]), 64)
        self.assertTrue(identity["volumes"])
        self.assertIsInstance(identity["network_adapters"], list)
        self.assertEqual(
            result.after_snapshot["surface_status"]["machine_guid"]["status"],
            "ok",
        )
        self.assertEqual(
            result.after_snapshot["surface_status"]["smbios"]["status"],
            "ok",
        )
        self.assertEqual(
            result.after_snapshot["surface_status"]["volumes"]["status"],
            "ok",
        )


if __name__ == "__main__":
    unittest.main()
