import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.tools.gui import gui_runtime_probe
from reverse_analyzer.tools.gui_runtime_adapters import (
    ANDROID_UIAUTOMATOR_BACKEND,
    IOS_ACCESSIBILITY_BACKEND,
    WINDOWS_UIA_BACKEND,
    CommandOutput,
    CommandTimeoutError,
    RuntimeProviderExecutionError,
    RuntimeProviderParseError,
    RuntimeProviderUnavailable,
    parse_android_uiautomator_xml,
    parse_windows_uia_json,
    probe_android_uiautomator,
    probe_ios_accessibility,
    probe_windows_uia,
)


class QueueRunner:
    """Return fixture outputs without invoking a host command."""

    def __init__(self, *outputs: object) -> None:
        self.outputs = list(outputs)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object) -> CommandOutput:
        self.calls.append((list(command), dict(kwargs)))
        output = self.outputs.pop(0)
        if isinstance(output, Exception):
            raise output
        assert isinstance(output, CommandOutput)
        return output


class GuiRuntimeAdapterTests(unittest.TestCase):
    def test_windows_parser_normalizes_fixture_accessibility_fields(self) -> None:
        payload = json.dumps(
            {
                "windows": [
                    {
                        "automation_id": "mainWindow",
                        "control_type": "ControlType.Window",
                        "name": "Editor",
                        "bounds": {"left": 10, "top": 20, "width": 800, "height": 600},
                        "enabled": True,
                        "offscreen": False,
                        "controls": [
                            {
                                "automation_id": "saveButton",
                                "control_type": "ControlType.Button",
                                "name": "Save",
                                "bounds": {"left": 30, "top": 40, "width": 90, "height": 28},
                                "enabled": True,
                                "offscreen": False,
                            }
                        ],
                    }
                ]
            }
        )

        result = parse_windows_uia_json(payload)

        self.assertEqual(result["window_count"], 1)
        self.assertEqual(result["control_count"], 1)
        control = result["windows"][0]["controls"][0]
        self.assertEqual(control["automation_id"], "saveButton")
        self.assertEqual(control["control_type"], "Button")
        self.assertEqual(control["bounds"]["width"], 90)
        self.assertTrue(control["enabled"])
        self.assertFalse(control["offscreen"])

    def test_windows_provider_uses_injected_runner_and_enforces_boundaries(self) -> None:
        fixture = json.dumps({"windows": []})
        runner = QueueRunner(CommandOutput(0, fixture, ""))
        result = probe_windows_uia(
            321,
            runner=runner,
            platform_name="nt",
            executable_finder=lambda name: "powershell.exe" if name.startswith("powershell") else None,
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["backend"], WINDOWS_UIA_BACKEND)
        self.assertFalse(result["provenance"]["target_executed"])
        self.assertIn("-EncodedCommand", runner.calls[0][0])

        with self.assertRaises(RuntimeProviderExecutionError):
            probe_windows_uia(
                321,
                runner=QueueRunner(CommandOutput(0, "x" * 129, "")),
                max_output_bytes=128,
                platform_name="nt",
                executable_finder=lambda _name: "powershell.exe",
            )
        with self.assertRaises(RuntimeProviderExecutionError):
            probe_windows_uia(
                321,
                runner=QueueRunner(CommandTimeoutError("fixture timeout")),
                platform_name="nt",
                executable_finder=lambda _name: "powershell.exe",
            )

    def test_android_provider_parses_injected_uiautomator_fixture(self) -> None:
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<hierarchy rotation="0">'
            '<node class="android.widget.Button" resource-id="com.example:id/save" text="Save" '
            'content-desc="Save changes" clickable="true" enabled="true" visible-to-user="false" '
            'bounds="[10,20][110,70]" />'
            "</hierarchy>"
        )
        runner = QueueRunner(
            CommandOutput(0, "UI hierarchy dumped", ""),
            CommandOutput(0, xml, ""),
        )

        result = probe_android_uiautomator(
            android_serial="fixture-serial",
            runner=runner,
            executable_finder=lambda _name: "adb",
        )

        self.assertEqual(result["backend"], ANDROID_UIAUTOMATOR_BACKEND)
        self.assertEqual(result["control_count"], 1)
        control = result["windows"][0]["controls"][0]
        self.assertEqual(control["automation_id"], "com.example:id/save")
        self.assertEqual(control["control_type"], "android.widget.Button")
        self.assertEqual(control["bounds"], {"left": 10, "top": 20, "width": 100, "height": 50})
        self.assertTrue(control["offscreen"])
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("fixture-serial", runner.calls[0][0])

    def test_fixture_parse_failures_are_closed(self) -> None:
        with self.assertRaises(RuntimeProviderParseError):
            parse_windows_uia_json("not-json")
        with self.assertRaises(RuntimeProviderParseError):
            parse_android_uiautomator_xml('<!DOCTYPE hierarchy [<!ENTITY x "value">]><hierarchy />')

    def test_ios_provider_requires_macos_and_parseable_injected_output(self) -> None:
        runner = QueueRunner(CommandOutput(0, "unused", ""))
        with self.assertRaises(RuntimeProviderUnavailable):
            probe_ios_accessibility(
                provider_command=["xcrun", "fixture-provider"],
                runner=runner,
                platform_name="linux",
                executable_finder=lambda _name: "/usr/bin/xcrun",
            )
        self.assertFalse(runner.calls)

        xml = (
            '<AppiumAUT><XCUIElementTypeApplication type="XCUIElementTypeApplication" name="FixtureApp">'
            '<XCUIElementTypeWindow type="XCUIElementTypeWindow" name="Main" x="0" y="0" width="390" height="844">'
            '<XCUIElementTypeButton type="XCUIElementTypeButton" identifier="save" label="Save" '
            'x="10" y="20" width="80" height="40" enabled="true" visible="true" />'
            "</XCUIElementTypeWindow></XCUIElementTypeApplication></AppiumAUT>"
        )
        injected = QueueRunner(CommandOutput(0, xml, ""))
        result = probe_ios_accessibility(
            provider_command=["xcrun", "fixture-provider"],
            runner=injected,
            platform_name="darwin",
            executable_finder=lambda name: "/usr/bin/xcrun" if name == "xcrun" else None,
        )

        self.assertEqual(result["backend"], IOS_ACCESSIBILITY_BACKEND)
        self.assertEqual(result["control_count"], 1)
        self.assertEqual(result["windows"][0]["controls"][0]["automation_id"], "save")
        self.assertFalse(result["windows"][0]["controls"][0]["offscreen"])

        with self.assertRaises(RuntimeProviderParseError):
            probe_ios_accessibility(
                provider_command=["xcrun", "fixture-provider"],
                runner=QueueRunner(CommandOutput(0, "provider said success", "")),
                platform_name="darwin",
                executable_finder=lambda _name: "/usr/bin/xcrun",
            )

    def test_gui_probe_labels_injected_win32_fallback(self) -> None:
        fallback = {
            "window_count": 1,
            "control_count": 0,
            "windows": [{"title": "Fixture", "controls": [], "control_count": 0}],
        }
        unavailable = RuntimeProviderUnavailable(
            "fixture UIA unavailable",
            backend=WINDOWS_UIA_BACKEND,
            provenance={"target_executed": False},
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            with (
                patch("reverse_analyzer.tools.gui._is_windows_runtime", return_value=True),
                patch("reverse_analyzer.tools.gui.probe_windows_uia", side_effect=unavailable),
                patch("reverse_analyzer.tools.gui._win32_runtime_tree", return_value=fallback),
            ):
                result = gui_runtime_probe(sample, root / "out", attach_pid=4321)

            self.assertEqual(result.status, "ok")
            self.assertEqual(result.data["status"], "ok")
            self.assertEqual(result.data["backend"], "win32-enumwindows")
            self.assertEqual(result.data["coverage"]["hierarchy"], "top-level and child HWNDs")
            self.assertFalse(result.data["provenance"]["target_executed"])
            self.assertEqual([item["status"] for item in result.data["provenance"]["attempts"]], ["unavailable", "ok"])
            artifact = json.loads((root / "out" / "gui" / "runtime_tree.json").read_text(encoding="utf-8"))
            self.assertEqual(artifact["backend"], "win32-enumwindows")
            self.assertEqual(artifact["status"], "ok")


if __name__ == "__main__":
    unittest.main()
