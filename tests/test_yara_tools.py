import sys
import tempfile
import types
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import Mock, patch

from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.yara_tools import DEFAULT_RULES_DIR, _collect_rule_files, yara_scan


class YaraToolsTests(TestCase):
    def test_yara_scan_graceful_when_yara_python_missing(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.bin"
            sample.write_bytes(b"MZ\x00\x00hello")

            with patch.dict(sys.modules, {"yara": None}):
                result = yara_scan(sample)

        self.assertIsInstance(result, ToolResult)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.tool, "yara_scan")
        self.assertEqual(result.data["path"], str(sample.resolve()))
        self.assertEqual(result.data["matches"], [])
        self.assertEqual(result.data["match_count"], 0)
        self.assertEqual(result.data["rules_path"], str(DEFAULT_RULES_DIR))
        self.assertIn("yara-python", result.error)

    def test_collect_rule_files_recurses_for_yar_and_yara(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "top.yar").write_text("rule Top { condition: true }", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            (nested / "deep.yara").write_text("rule Deep { condition: true }", encoding="utf-8")
            (nested / "ignore.txt").write_text("nope", encoding="utf-8")

            collected = _collect_rule_files(root)

        self.assertEqual(
            collected,
            [(root / "nested" / "deep.yara").resolve(), (root / "top.yar").resolve()],
        )

    def test_yara_scan_normalizes_compile_and_match_results(self):
        class FakeStringInstance:
            def __init__(self, offset, data):
                self.offset = offset
                self.matched_data = data

        class FakeStringMatch:
            def __init__(self, identifier, instances):
                self.identifier = identifier
                self.instances = instances

        class FakeMatch:
            rule = "SuspiciousWindowsApiCombo"
            namespace = "default.suspicious_apis"
            tags = ["suspicious", "api", "pe"]
            meta = {"severity": "medium", "family": "generic"}
            strings = [
                FakeStringMatch("$a1", [FakeStringInstance(32, b"CreateRemoteThread")]),
                (64, "$http", b"http://example.test/ping"),
            ]

        fake_rules = types.SimpleNamespace(match=Mock(return_value=[FakeMatch()]))
        compile_mock = Mock(return_value=fake_rules)
        fake_yara = types.SimpleNamespace(compile=compile_mock)

        with tempfile.TemporaryDirectory() as td, patch.dict(sys.modules, {"yara": fake_yara}):
            sample = Path(td) / "sample.bin"
            sample.write_bytes(b"MZ\x00\x00payload")
            rules_dir = Path(td) / "rules"
            rules_dir.mkdir()
            (rules_dir / "alpha.yar").write_text("rule Alpha { condition: true }", encoding="utf-8")
            subdir = rules_dir / "nested"
            subdir.mkdir()
            (subdir / "beta.yara").write_text("rule Beta { condition: true }", encoding="utf-8")

            result = yara_scan(sample, rules_path=rules_dir)

        compile_mock.assert_called_once()
        compile_kwargs = compile_mock.call_args.kwargs
        self.assertIn("filepaths", compile_kwargs)
        self.assertEqual(
            compile_kwargs["filepaths"],
            {
                "alpha": str((rules_dir / "alpha.yar").resolve()),
                "nested.beta": str((subdir / "beta.yara").resolve()),
            },
        )
        fake_rules.match.assert_called_once_with(str(sample.resolve()))

        self.assertEqual(result["path"], str(sample.resolve()))
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(len(result["rule_files"]), 2)
        match = result["matches"][0]
        self.assertEqual(match["rule"], "SuspiciousWindowsApiCombo")
        self.assertEqual(match["namespace"], "default.suspicious_apis")
        self.assertEqual(match["tags"], ["suspicious", "api", "pe"])
        self.assertEqual(match["meta"]["severity"], "medium")
        self.assertEqual(match["strings"]["count"], 2)
        self.assertIs(match["strings"]["truncated"], False)
        self.assertEqual(match["strings"]["items"][0]["identifier"], "$a1")
        self.assertEqual(match["strings"]["items"][0]["offset"], 32)
        self.assertEqual(match["strings"]["items"][0]["preview"], "CreateRemoteThread")
        self.assertEqual(match["strings"]["items"][1]["identifier"], "$http")
        self.assertEqual(match["strings"]["items"][1]["offset"], 64)
        self.assertEqual(match["strings"]["items"][1]["preview"], "http://example.test/ping")


if __name__ == "__main__":
    main()