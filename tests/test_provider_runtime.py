import unittest

from reverse_analyzer.provider_runtime import ProviderRuntime


class ProviderRuntimeTests(unittest.TestCase):
    def test_profiles_are_discoverable_without_network(self):
        runtime = ProviderRuntime()
        names = {item["name"] for item in runtime.profiles()}
        self.assertIn("rule_based", names)
        self.assertIn("openai_compatible", names)

    def test_disabled_external_provider_falls_back_locally(self):
        runtime = ProviderRuntime()
        provider = runtime.create("openai_compatible")
        self.assertEqual(provider.name, "rule_based")

    def test_provider_test_never_calls_network(self):
        result = ProviderRuntime().test("rule_based")
        self.assertEqual(result["status"], "ready")
        self.assertFalse(result["network_call"])


if __name__ == "__main__":
    unittest.main()
