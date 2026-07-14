import unittest

import reverse_analyzer.tools as tools_package
from reverse_analyzer.tools.protocol import (
    protocol_analyze,
    protocol_capture,
    protocol_infer,
    protocol_summarize,
)
from reverse_analyzer.tools.static_tools import register_builtin_tools


PROTOCOL_TOOLS = {
    "protocol_capture": protocol_capture,
    "protocol_infer": protocol_infer,
    "protocol_summarize": protocol_summarize,
    "protocol_analyze": protocol_analyze,
}


class ProtocolToolRegistryTests(unittest.TestCase):
    def test_protocol_tools_are_exported_from_tools_package(self) -> None:
        for name, implementation in PROTOCOL_TOOLS.items():
            with self.subTest(name=name):
                self.assertIn(name, tools_package.__all__)
                self.assertIs(getattr(tools_package, name), implementation)

    def test_protocol_tools_are_registered_with_exact_implementations(self) -> None:
        executor = register_builtin_tools()

        for name, implementation in PROTOCOL_TOOLS.items():
            with self.subTest(name=name):
                self.assertIn(name, executor.tools)
                self.assertIs(executor.tools[name], implementation)


if __name__ == "__main__":
    unittest.main()
