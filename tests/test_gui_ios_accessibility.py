import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

from reverse_analyzer.gui.ios_accessibility import (
    IOS_ACCESSIBILITY_BACKEND,
    IOSAccessibilityAdapter,
    IOSAccessibilityParseError,
    IOSCommandOutput,
    IOSCommandOutputLimitError,
    IOSCommandTimeoutError,
    SubprocessIOSAccessibilityRunner,
    parse_ios_accessibility_output,
    parse_ios_target_identity,
    probe_ios_accessibility,
)


TARGET_UDID = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"


def target_description(
    *,
    udid: str = TARGET_UDID,
    kind: str = "simulator",
    state: str = "Booted",
) -> str:
    return json.dumps(
        {
            "udid": udid,
            "target_type": kind,
            "state": state,
            "name": "Fixture Phone",
            "os_version": "18.0",
            "architecture": "arm64",
        }
    )


def nested_hierarchy() -> str:
    return json.dumps(
        [
            {
                "type": "Application",
                "label": "Fixture App",
                "frame": {"x": 0, "y": 0, "width": 390, "height": 844},
                "enabled": True,
                "children": [
                    {
                        "type": "Window",
                        "label": "Main",
                        "children": [
                            {
                                "type": "Button",
                                "identifier": "save",
                                "label": "Save",
                                "frame": "{{10, 20}, {80, 40}}",
                                "enabled": True,
                                "visible": True,
                                "children": [],
                            }
                        ],
                    }
                ],
            }
        ]
    )


class QueueRunner:
    """Deterministic injected runner; never qualifies as production evidence."""

    def __init__(self, *outputs: object) -> None:
        self.outputs = list(outputs)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object) -> IOSCommandOutput:
        self.calls.append((list(command), dict(kwargs)))
        output = self.outputs.pop(0)
        if isinstance(output, Exception):
            raise output
        assert isinstance(output, IOSCommandOutput)
        return output


class TemporaryIDB:
    def __enter__(self) -> tuple[Path, Path]:
        self._temporary = tempfile.TemporaryDirectory()
        root = Path(self._temporary.name).resolve()
        executable = root / ("idb.exe" if os.name == "nt" else "idb")
        shutil.copy2(sys.executable, executable)
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
        return root, executable

    def __exit__(self, *args: object) -> None:
        self._temporary.cleanup()


class IOSAccessibilityParserTests(unittest.TestCase):
    def test_nested_idb_json_normalizes_accessibility_tree(self) -> None:
        result = parse_ios_accessibility_output(nested_hierarchy())

        self.assertEqual(result["schema"]["name"], "reverse_analyzer.ios_accessibility_tree")
        self.assertEqual(result["schema"]["version"], "1.0")
        self.assertEqual(result["format"], "idb-json")
        self.assertEqual(result["window_count"], 1)
        self.assertEqual(result["node_count"], 3)
        self.assertEqual(result["control_count"], 2)
        application = result["windows"][0]
        self.assertEqual(application["name"], "Fixture App")
        self.assertEqual(
            application["bounds"],
            {"left": 0, "top": 0, "width": 390, "height": 844},
        )
        button = application["children"][0]["children"][0]
        self.assertEqual(button["automation_id"], "save")
        self.assertEqual(button["control_type"], "Button")
        self.assertEqual(
            button["bounds"],
            {"left": 10, "top": 20, "width": 80, "height": 40},
        )
        self.assertTrue(button["enabled"])
        self.assertFalse(button["offscreen"])
        self.assertFalse(result["truncated"])
        required = {
            "automation_id",
            "name",
            "control_type",
            "bounds",
            "enabled",
            "offscreen",
            "depth",
            "children",
        }
        stack = list(result["windows"])
        while stack:
            node = stack.pop()
            self.assertTrue(required.issubset(node))
            self.assertIsInstance(node["children"], list)
            stack.extend(node["children"])

    def test_flat_idb_json_is_grouped_under_its_application(self) -> None:
        payload = json.dumps(
            [
                {"type": "Application", "label": "Fixture"},
                {
                    "AXRole": "Button",
                    "AXUniqueId": "save",
                    "AXLabel": "Save",
                    "AXFrame": "{{2, 4}, {20, 10}}",
                    "AXEnabled": True,
                },
            ]
        )

        result = parse_ios_accessibility_output(payload)

        self.assertEqual(result["window_count"], 1)
        self.assertEqual(result["node_count"], 2)
        control = result["windows"][0]["children"][0]
        self.assertEqual(control["automation_id"], "save")
        self.assertEqual(control["name"], "Save")
        self.assertEqual(control["bounds"]["width"], 20)

    def test_xcuitest_xml_and_appium_json_wrapper_normalize(self) -> None:
        xml = (
            '<AppiumAUT><XCUIElementTypeApplication type="XCUIElementTypeApplication" '
            'name="Fixture App"><XCUIElementTypeWindow type="XCUIElementTypeWindow" '
            'name="Main" x="0" y="0" width="390" height="844">'
            '<XCUIElementTypeButton type="XCUIElementTypeButton" identifier="save" '
            'label="Save" x="10" y="20" width="80" height="40" '
            'enabled="true" visible="false" />'
            "</XCUIElementTypeWindow></XCUIElementTypeApplication></AppiumAUT>"
        )

        direct = parse_ios_accessibility_output(xml)
        wrapped = parse_ios_accessibility_output(json.dumps({"value": xml}))

        for result in (direct, wrapped):
            self.assertEqual(result["format"], "xcuitest-xml")
            self.assertEqual(result["window_count"], 1)
            self.assertEqual(result["node_count"], 2)
            window = result["windows"][0]
            self.assertEqual(window["name"], "Main")
            control = window["children"][0]
            self.assertEqual(control["automation_id"], "save")
            self.assertTrue(control["enabled"])
            self.assertTrue(control["offscreen"])

    def test_target_identity_requires_udid_kind_and_simulator_state(self) -> None:
        identity = parse_ios_target_identity(target_description())

        self.assertEqual(identity["udid"], TARGET_UDID)
        self.assertEqual(identity["kind"], "simulator")
        self.assertEqual(identity["state"], "Booted")
        self.assertEqual(identity["name"], "Fixture Phone")

        with self.assertRaises(IOSAccessibilityParseError):
            parse_ios_target_identity(json.dumps({"type": "simulator", "state": "Booted"}))
        with self.assertRaises(IOSAccessibilityParseError):
            parse_ios_target_identity(json.dumps({"udid": TARGET_UDID, "type": "simulator"}))

    def test_malformed_empty_and_entity_inputs_fail_closed(self) -> None:
        fixtures = (
            "",
            "not-json-or-xml",
            "[]",
            "{not-json}",
            "<XCUIElementTypeWindow>",
            '<!DOCTYPE root [<!ENTITY x "expanded">]><Window name="&x;" />',
            '<!ENTITY x "expanded"><Window />',
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture[:30]):
                with self.assertRaises(IOSAccessibilityParseError):
                    parse_ios_accessibility_output(fixture)

    def test_payload_node_depth_and_text_limits_are_enforced(self) -> None:
        with self.assertRaises(IOSAccessibilityParseError):
            parse_ios_accessibility_output("[]", max_output_bytes=1)

        node_limited = parse_ios_accessibility_output(nested_hierarchy(), max_nodes=2)
        self.assertEqual(node_limited["node_count"], 2)
        self.assertTrue(node_limited["truncated"])
        self.assertIn("max_nodes", node_limited["truncation_reasons"])

        depth_limited = parse_ios_accessibility_output(nested_hierarchy(), max_depth=1)
        self.assertEqual(depth_limited["node_count"], 2)
        self.assertTrue(depth_limited["truncated"])
        self.assertIn("max_depth", depth_limited["truncation_reasons"])

        text_limited = parse_ios_accessibility_output(nested_hierarchy(), max_text_chars=4)
        self.assertEqual(text_limited["windows"][0]["name"], "Fixt")
        self.assertIn("max_text_chars", text_limited["truncation_reasons"])


class IOSAccessibilityAdapterTests(unittest.TestCase):
    def test_non_macos_gate_does_not_touch_dependency_or_runner(self) -> None:
        finder_called = False
        runner_called = False

        def finder(_name: str) -> str | None:
            nonlocal finder_called
            finder_called = True
            raise AssertionError("dependency finder must not run")

        def runner(*_args: object, **_kwargs: object) -> object:
            nonlocal runner_called
            runner_called = True
            raise AssertionError("runner must not run")

        result = probe_ios_accessibility(
            TARGET_UDID,
            platform_name="linux",
            executable_finder=finder,
            runner=runner,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["backend"], IOS_ACCESSIBILITY_BACKEND)
        self.assertEqual(result["error"]["code"], "platform_unavailable")
        self.assertEqual(result["dependency"]["status"], "not_checked")
        self.assertFalse(finder_called)
        self.assertFalse(runner_called)
        self.assertFalse(result["provenance"]["production_evidence"])

    def test_missing_idb_is_gracefully_unavailable(self) -> None:
        result = probe_ios_accessibility(
            TARGET_UDID,
            platform_name="darwin",
            executable_finder=lambda _name: None,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["dependency"]["status"], "missing")
        self.assertEqual(result["error"]["code"], "dependency_missing")
        self.assertEqual(result["windows"], [])

    def test_target_udid_rejects_option_and_path_injection(self) -> None:
        for target in ("--udid", "../fixture", "A/B", "A\\B", " spaced ", ""):
            with self.subTest(target=target):
                result = probe_ios_accessibility(target, platform_name="darwin")
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["error"]["code"], "target_invalid")
                self.assertEqual(result["dependency"]["status"], "not_checked")

    def test_relative_and_out_of_root_executables_are_rejected(self) -> None:
        relative = probe_ios_accessibility(
            TARGET_UDID,
            platform_name="darwin",
            idb_path="idb",
        )
        self.assertEqual(relative["status"], "unavailable")
        self.assertEqual(relative["error"]["code"], "dependency_path_invalid")

        with TemporaryIDB() as (_root, executable), tempfile.TemporaryDirectory() as other:
            outside = probe_ios_accessibility(
                TARGET_UDID,
                platform_name="darwin",
                idb_path=executable,
                allowed_executable_roots=[Path(other).resolve()],
            )
        self.assertEqual(outside["status"], "unavailable")
        self.assertEqual(
            outside["error"]["code"],
            "dependency_path_outside_allowed_roots",
        )

    def test_target_identity_mismatch_stops_before_hierarchy_dump(self) -> None:
        runner = QueueRunner(
            IOSCommandOutput(
                0,
                target_description(udid="BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF"),
                "",
            )
        )
        with TemporaryIDB() as (root, executable):
            result = probe_ios_accessibility(
                TARGET_UDID,
                platform_name="darwin",
                idb_path=executable,
                allowed_executable_roots=[root],
                runner=runner,
            )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "target_identity_mismatch")
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(result["windows"], [])
        self.assertFalse(result["provenance"]["production_evidence"])

    def test_device_and_non_booted_simulator_degrade_without_dump(self) -> None:
        fixtures = (
            (
                "device",
                target_description(kind="device", state="Connected"),
                "device_hierarchy_unsupported",
            ),
            (
                "simulator",
                target_description(state="Shutdown"),
                "target_not_booted",
            ),
        )
        for requested_kind, description, expected_code in fixtures:
            with self.subTest(kind=requested_kind, code=expected_code):
                runner = QueueRunner(IOSCommandOutput(0, description, ""))
                with TemporaryIDB() as (root, executable):
                    result = probe_ios_accessibility(
                        TARGET_UDID,
                        target_kind=requested_kind,
                        platform_name="darwin",
                        idb_path=executable,
                        allowed_executable_roots=[root],
                        runner=runner,
                    )
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["error"]["code"], expected_code)
                self.assertEqual(len(runner.calls), 1)
                self.assertFalse(result["target"]["identity_verified"])
                self.assertIsNone(result["provenance"]["target_identity"])

    def test_fake_runner_parseable_success_cannot_be_production_success(self) -> None:
        runner = QueueRunner(
            IOSCommandOutput(0, target_description(), ""),
            IOSCommandOutput(0, nested_hierarchy(), ""),
        )
        with TemporaryIDB() as (root, executable):
            result = probe_ios_accessibility(
                TARGET_UDID,
                platform_name="darwin",
                idb_path=executable,
                allowed_executable_roots=[root],
                runner=runner,
            )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"]["code"], "non_production_runner")
        self.assertEqual(result["window_count"], 0)
        self.assertEqual(result["node_count"], 0)
        self.assertEqual(result["windows"], [])
        self.assertFalse(result["target"]["identity_verified"])
        self.assertFalse(result["provenance"]["production_evidence"])
        self.assertFalse(result["provenance"]["provider_process_executed"])
        self.assertTrue(result["provenance"]["read_only"])
        self.assertFalse(result["provenance"]["target_executed"])
        self.assertFalse(result["provenance"]["target_mutated"])
        self.assertFalse(result["provenance"]["shell"])
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(
            runner.calls[0][0][1:],
            ["describe", "--udid", TARGET_UDID, "--json"],
        )
        self.assertEqual(
            runner.calls[1][0][1:],
            ["ui", "describe-all", "--udid", TARGET_UDID, "--nested"],
        )

    def test_shared_output_budget_is_enforced_against_injected_runner(self) -> None:
        description = target_description()
        hierarchy = nested_hierarchy()
        runner = QueueRunner(
            IOSCommandOutput(0, description, ""),
            IOSCommandOutput(0, hierarchy, ""),
        )
        with TemporaryIDB() as (root, executable):
            result = IOSAccessibilityAdapter(
                idb_path=executable,
                allowed_executable_roots=[root],
                max_output_bytes=len(description.encode("utf-8")) + len(hierarchy.encode("utf-8")) - 1,
                runner=runner,
            ).probe(TARGET_UDID, platform_name="darwin")

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "output_limit")
        self.assertEqual(result["windows"], [])
        self.assertIn("max_output_bytes", result["truncation_reasons"])


class IOSSubprocessRunnerTests(unittest.TestCase):
    def test_real_local_subprocess_preserves_shell_metacharacters_as_argv(self) -> None:
        runner = SubprocessIOSAccessibilityRunner()
        literal = "fixture;echo-not-a-shell && still-one-argument"

        output = runner.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write(sys.argv[1]); sys.stderr.write('fixture-stderr')",
                literal,
            ],
            timeout_seconds=5.0,
            max_output_bytes=1_024,
        )

        self.assertEqual(output.returncode, 0)
        self.assertEqual(output.stdout, literal)
        self.assertEqual(output.stderr, "fixture-stderr")
        self.assertEqual(output.stdout_bytes, len(literal.encode("utf-8")))

    def test_real_local_subprocess_timeout_is_strict(self) -> None:
        runner = SubprocessIOSAccessibilityRunner()

        with self.assertRaises(IOSCommandTimeoutError):
            runner.run(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                timeout_seconds=0.05,
                max_output_bytes=1_024,
            )

    def test_real_local_subprocess_combined_output_limit_is_strict(self) -> None:
        runner = SubprocessIOSAccessibilityRunner()

        with self.assertRaises(IOSCommandOutputLimitError):
            runner.run(
                [
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * 4096); os.write(2, b'y' * 4096)",
                ],
                timeout_seconds=5.0,
                max_output_bytes=128,
            )


if __name__ == "__main__":
    unittest.main()
