import unittest

from reverse_analyzer.providers import RuleBasedProvider


class RuleBasedProviderTests(unittest.TestCase):
    def test_rule_based_provider_picks_first_unseen_tool(self):
        provider = RuleBasedProvider(plan=["identify", "strings"])

        message = provider.analyze({"target": "sample.exe", "tool_results": []})

        self.assertEqual(message.tool_name, "identify")
        self.assertEqual(message.tool_args, {"target": "sample.exe"})
        self.assertIsNone(message.final_answer)

    def test_rule_based_provider_defaults_to_registered_static_tool_names(self):
        provider = RuleBasedProvider()

        message = provider.analyze({"target": "sample.exe", "tool_results": []})

        self.assertEqual(message.tool_name, "file_info")
        self.assertEqual(message.tool_args, {"path": "sample.exe"})

    def test_rule_based_provider_reaches_deep_pe_and_yara_steps(self):
        provider = RuleBasedProvider()
        tool_results = [
            {"tool_name": "file_info"},
            {"tool_name": "hash"},
            {"tool_name": "strings_extract"},
        ]

        message = provider.analyze({"target": "sample.exe", "tool_results": tool_results})

        self.assertEqual(message.tool_name, "pe_deep_scan")
        self.assertEqual(message.tool_args, {"path": "sample.exe"})

    def test_rule_based_provider_summarizes_after_observations(self):
        provider = RuleBasedProvider(plan=["identify"], finish_after_results=1)

        message = provider.analyze(
            {
                "tool_results": [
                    {
                        "tool_name": "identify",
                        "result": {"findings": [{"title": "Packed PE", "severity": "medium"}]},
                    }
                ]
            }
        )

        self.assertIsNotNone(message.final_answer)
        self.assertIn("Packed PE", message.final_answer)
        self.assertEqual(message.findings[0]["title"], "Packed PE")


if __name__ == "__main__":
    unittest.main()
