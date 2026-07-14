from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence
import unittest

from reverse_analyzer.core.capabilities.models import TargetIdentity
from reverse_analyzer.providers.imgui_renderer import (
    IMGUI_HOST_BRIDGE_PROTOCOL,
    IMGUI_HOST_BRIDGE_PROTOCOL_VERSION,
    IMGUI_HOST_LIFECYCLE,
    ImGuiHostContractError,
    ImGuiHostOrchestrator,
)


@dataclass
class _Call:
    operation: str
    status: str = "ok"
    response: Mapping[str, Any] | None = None
    error: Optional[str] = None
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.status in {"ok", "stopped"}

    def to_dict(self, *, include_payloads: bool = True) -> dict[str, Any]:
        del include_payloads
        return {
            "operation": self.operation,
            "status": self.status,
            "timed_out": self.timed_out,
            "error": self.error,
            "response": dict(self.response or {}),
        }


class _MockHostBridge:
    test_double = True

    def __init__(
        self,
        *,
        fail_operation: str | None = None,
        timeout_operation: str | None = None,
        invalid_operation: str | None = None,
        probe_ok: bool = True,
    ) -> None:
        self.fail_operation = fail_operation
        self.timeout_operation = timeout_operation
        self.invalid_operation = invalid_operation
        self.probe_ok = probe_ok
        self.operations: list[str] = []
        self.successful = 0

    def probe(
        self,
        *,
        required_operations: Sequence[str] = (),
        required_backends: Sequence[str] = (),
    ) -> _Call:
        self.probe_requirements = (tuple(required_operations), tuple(required_backends))
        return _Call(
            "probe",
            status="ok" if self.probe_ok else "unavailable",
            error=None if self.probe_ok else "backend dependency missing",
        )

    def invoke(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        session_id: str,
        timeout_ms: int | None = None,
    ) -> _Call:
        del timeout_ms
        self.operations.append(operation)
        if operation == self.timeout_operation:
            return _Call(operation, status="failed", timed_out=True, error="timeout")
        if operation == self.fail_operation:
            return _Call(operation, status="failed", error="host failure")
        sequence = int(payload.get("sequence") or self.successful + 1)
        result = {
            "schema_version": 1,
            "lifecycle_version": 1,
            "sequence": sequence,
            "operation": operation,
            "session_id": session_id,
            "target_identity_hash": payload["target_identity_hash"],
            "precondition_hash": payload["precondition_hash"],
            "backend": payload["backend"],
            "evidence_class": "synthetic_fixture",
            "proof": {"fixture": True, "live_verified": False},
            {
                "resolve_target": "target_resolved",
                "install_hook": "hook_installed",
                "renderer_init": "renderer_initialized",
                "frame_evidence": "frame_observed",
                "resize": "resize_observed",
                "device_lost": "device_lost",
                "device_restore": "device_restored",
                "shutdown": "renderer_shutdown",
                "unload": "module_unloaded",
            }[operation]: True,
        }
        if operation == self.invalid_operation:
            result["schema_version"] = 99
        response = {
            "protocol": IMGUI_HOST_BRIDGE_PROTOCOL,
            "protocol_version": IMGUI_HOST_BRIDGE_PROTOCOL_VERSION,
            "capability": "imgui_renderer_runtime",
            "operation": operation,
            "request_id": f"mock-{len(self.operations)}",
            "session_id": session_id,
            "status": "stopped" if operation in {"shutdown", "unload"} else "ok",
            "native_bridge": True,
            "result": result,
            "errors": [],
        }
        self.successful += 1
        return _Call(operation, status=response["status"], response=response)


class ImGuiHostOrchestrationTests(unittest.TestCase):
    def _orchestrator(self, bridge: _MockHostBridge, backend: str = "d3d11") -> ImGuiHostOrchestrator:
        return ImGuiHostOrchestrator(
            bridge,
            target=TargetIdentity(kind="process", pid=4242, display_name="fixture.exe"),
            session_id="imgui/host-fixture",
            precondition_hash="a" * 64,
            backend=backend,
            timeout_ms=1_000,
        )

    def test_success_covers_complete_lifecycle_but_remains_synthetic(self) -> None:
        bridge = _MockHostBridge()
        host = self._orchestrator(bridge)
        result = host.execute(host.plan())
        artifacts = host.collect_artifacts(result)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(bridge.operations, list(IMGUI_HOST_LIFECYCLE))
        self.assertEqual(result["evidence_class"], "synthetic_fixture")
        self.assertFalse(result["live_verified"])
        self.assertEqual(len(artifacts["frame"]["events"]), 1)
        self.assertEqual(len(artifacts["hook"]["events"]), 1)
        self.assertFalse(artifacts["provenance"]["live_verified"])

    def test_invalid_response_schema_fails_closed_and_rolls_back(self) -> None:
        bridge = _MockHostBridge(invalid_operation="frame_evidence")
        host = self._orchestrator(bridge)

        result = host.execute(host.plan())

        self.assertEqual(result["status"], "failed")
        self.assertIn("schema_version", result["error"])
        self.assertEqual(bridge.operations[-2:], ["shutdown", "unload"])
        self.assertTrue(result["rollback"]["ok"])
        self.assertFalse(result["live_verified"])

    def test_timeout_and_failure_trigger_rollback_without_live_claim(self) -> None:
        for bridge in (
            _MockHostBridge(timeout_operation="resize"),
            _MockHostBridge(fail_operation="device_lost"),
        ):
            with self.subTest(bridge=bridge.__dict__):
                host = self._orchestrator(bridge)
                result = host.execute(host.plan())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(bridge.operations[-2:], ["shutdown", "unload"])
                self.assertFalse(result["live_verified"])

    def test_plan_binding_and_backend_probe_are_strict(self) -> None:
        bridge = _MockHostBridge(probe_ok=False)
        host = self._orchestrator(bridge, backend="vulkan")
        plan = host.plan()
        gated = host.execute(plan)
        self.assertEqual(gated["status"], "unavailable")
        self.assertTrue(gated["validation"]["dependency_gated"])
        self.assertEqual(bridge.probe_requirements[1], ("vulkan",))

        tampered = dict(plan)
        tampered["timeout_ms"] = 2_000
        with self.assertRaises(ImGuiHostContractError):
            host.validate(tampered)


if __name__ == "__main__":
    unittest.main()
