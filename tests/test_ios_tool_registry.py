import json
import tempfile
import unittest
from pathlib import Path

import reverse_analyzer.tools as tools_package
from reverse_analyzer.tools.ios import ios_analyze, ipa_analyze
from reverse_analyzer.tools.static_tools import register_builtin_tools


IOS_TOOLS = {
    "ios_analyze": ios_analyze,
    "ipa_analyze": ipa_analyze,
}


class IosToolRegistryTests(unittest.TestCase):
    def test_ios_tools_are_exported_and_discoverable(self) -> None:
        executor = register_builtin_tools()

        for name, implementation in IOS_TOOLS.items():
            with self.subTest(name=name):
                self.assertIn(name, tools_package.__all__)
                self.assertIs(getattr(tools_package, name), implementation)
                self.assertIn(name, executor.tools)
                self.assertIs(executor.tools[name], implementation)

    def test_registry_calls_preserve_failed_status_and_empty_artifacts(self) -> None:
        executor = register_builtin_tools()

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.ipa"

            for name in IOS_TOOLS:
                with self.subTest(name=name):
                    result = executor.execute(name, path=missing)
                    direct = IOS_TOOLS[name](missing)

                    self.assertEqual(result.tool, name)
                    self.assertEqual(result.status, "ok")
                    self.assertIsNone(result.error)
                    self.assertEqual(result.data, direct)
                    self.assertEqual(result.data["status"], "failed")
                    self.assertEqual(result.data["artifacts"], [])
                    json.dumps(result.to_dict())

            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
