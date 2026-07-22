from __future__ import annotations

import importlib.metadata
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.protocol_runtime import ProtocolRuntimeProvider


class ProtocolRuntimeHttp2AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = ProtocolRuntimeProvider()

    @staticmethod
    def _request(*, adapter: str = "auto") -> CapabilityRequest:
        return CapabilityRequest(
            capability="protocol_runtime",
            action="protocol_adapter_preflight",
            target=TargetIdentity(display_name="local-http2-adapter"),
            params={
                "application_protocol": "http/2",
                "protocol_adapter": adapter,
            },
            session_id="http2-adapter-preflight",
            provenance={"test_case": "http2-adapter-preflight"},
        )

    def test_available_adapter_records_strict_non_live_contract(self) -> None:
        with (
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.util.find_spec",
                return_value=object(),
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.metadata.version",
                return_value="4.2.0",
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.import_module",
                return_value=SimpleNamespace(
                    H2Connection=object,
                    H2Configuration=object,
                    ResponseReceived=object,
                    Encoder=object,
                    Frame=object,
                ),
            ),
        ):
            plan = self.provider.plan(self._request())
            validation = self.provider.validate(plan)
            result = self.provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok")
        self.assertFalse(result.provenance["network_transmit"])
        after = result.to_dict()["after_snapshot"]
        self.assertEqual(after["application_protocol"], "http/2")
        self.assertEqual(after["protocol_adapter"], "hyper-h2")
        self.assertEqual(after["dependency_state"], "available")
        self.assertTrue(after["dependency_probe"]["version_supported"])
        self.assertTrue(all(after["dependency_probe"]["capability_probe"].values()))
        self.assertFalse(after["capture_supported"])
        self.assertFalse(after["replay_supported"])
        self.assertFalse(after["live_verified"])
        self.assertEqual(after["network_boundary"], "local_dependency_probe_only")
        self.assertNotIn("executable", after["dependency_probe"])

        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            bundle = self.provider.collect_artifacts(result, str(root))
            artifact = root / bundle.artifacts[0].path
            payload = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertFalse(payload["after_snapshot"]["live_verified"])
        self.assertEqual(
            payload["after_snapshot"]["adapter_contract"]["live_acceptance"],
            "not_verified",
        )

    def test_missing_adapter_is_dependency_gated_without_network_activity(self) -> None:
        with (
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.util.find_spec",
                return_value=None,
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.metadata.version",
                side_effect=importlib.metadata.PackageNotFoundError("h2"),
            ),
        ):
            plan = self.provider.plan(self._request())
            self.assertTrue(self.provider.validate(plan).ok)
            result = self.provider.execute(plan)

        self.assertEqual(result.status, "dependency-gated")
        after = result.to_dict()["after_snapshot"]
        self.assertFalse(after["network_transmit"])
        self.assertEqual(after["dependency_state"], "dependency-gated")
        self.assertFalse(after["dependency_probe"]["module_found"])
        self.assertFalse(after["capture_supported"])
        self.assertFalse(after["live_verified"])

    def test_contract_tamper_and_unknown_adapter_fail_validation(self) -> None:
        plan = self.provider.plan(self._request())
        plan.parameters["adapter_contract"]["live_acceptance"] = "verified"
        validation = self.provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertIn("contract is invalid", " ".join(validation.errors))

        unknown = self.provider.plan(self._request(adapter="unknown"))
        unknown_validation = self.provider.validate(unknown)
        self.assertFalse(unknown_validation.ok)
        self.assertIn("unsupported HTTP/2", " ".join(unknown_validation.errors))

    def test_incomplete_runtime_interface_is_dependency_gated(self) -> None:
        with (
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.util.find_spec",
                return_value=object(),
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.metadata.version",
                return_value="4.2.0",
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime.importlib.import_module",
                return_value=SimpleNamespace(),
            ),
        ):
            result = self.provider.execute(self.provider.plan(self._request()))

        self.assertEqual(result.status, "dependency-gated")
        probe = result.after_snapshot["dependency_probe"]
        self.assertFalse(any(probe["capability_probe"].values()))
        self.assertIn("runtime interface", probe["reason"])


if __name__ == "__main__":
    unittest.main()
