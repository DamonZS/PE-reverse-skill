import unittest
from unittest.mock import patch

from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import EngineRuntimeProvider, build_default_registry


class EngineRuntimeRegistryTests(unittest.TestCase):
    def test_default_registry_selects_production_engine_runtime_provider(self) -> None:
        registry = build_default_registry()

        self.assertIn("engine_runtime", registry.list_capabilities())
        self.assertEqual(
            registry.list_providers("engine_runtime"),
            ["windows_engine_runtime"],
        )
        provider = registry.resolve("engine_runtime")
        self.assertIsInstance(provider, EngineRuntimeProvider)
        self.assertEqual(provider.capability_name, "engine_runtime")
        self.assertEqual(provider.provider_name, "windows_engine_runtime")

    def test_default_provider_reports_unavailable_without_windows_platform(self) -> None:
        with patch("reverse_analyzer.providers.engine_runtime.sys.platform", "linux"):
            provider = build_default_registry().resolve("engine_runtime")

        self.assertIsInstance(provider, EngineRuntimeProvider)
        self.assertFalse(provider.backend.available)
        self.assertIn("linux", provider.backend.unavailable_reason)

        request = CapabilityRequest(
            capability="engine_runtime",
            action="analyze",
            target=TargetIdentity(kind="process", pid=4242),
            session_id="engine-runtime-registry-unavailable",
        )
        result = provider.execute(provider.plan(request))

        self.assertEqual(result.status, "unavailable")
        operation = result.report_section["operation"]
        self.assertEqual(operation["status"], "unavailable")
        self.assertIn("linux", operation["reason"])
        self.assertFalse(operation["side_effects"])


if __name__ == "__main__":
    unittest.main()
