from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

try:
    from reverse_analyzer.tools.gui_wpf import generate_wpf_project
except ModuleNotFoundError:
    generate_wpf_project = None


class GenerateWpfProjectTests(unittest.TestCase):
    def _render(self, evidence: dict[str, object]) -> tuple[dict[str, object], Path]:
        self.assertIsNotNone(
            generate_wpf_project,
            "generate_wpf_project must be available from reverse_analyzer.tools.gui_wpf",
        )
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        project_dir = Path(temporary_directory.name) / "reconstructed"
        result = generate_wpf_project(project_dir, evidence)  # type: ignore[misc]
        return result, project_dir

    def test_save_button_emits_xaml_and_click_handler(self) -> None:
        result, project_dir = self._render(
            {
                "title": "Document editor",
                "nodes": [
                    {
                        "id": "Save Button",
                        "type": "Button",
                        "text": "Save",
                        "bbox": {"x": 20, "y": 30, "width": 80, "height": 24},
                        "event_handlers": {"Click": "Save_Click"},
                    }
                ],
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")
        code_behind = (project_dir / "src" / "MainWindow.xaml.cs").read_text(encoding="utf-8")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["control_count"], 1)
        self.assertEqual(result["event_handler_count"], 1)
        self.assertIn("generated_files", result)
        self.assertIn("artifacts", result)
        self.assertIn('<Button x:Name="Save_Button"', xaml)
        self.assertIn('Content="Save"', xaml)
        self.assertIn('Click="Save_Click"', xaml)
        self.assertIn("void Save_Click(", code_behind)

    def test_complete_bbox_places_control_on_canvas(self) -> None:
        _, project_dir = self._render(
            {
                "nodes": [
                    {
                        "id": "Caption",
                        "type": "Label",
                        "text": "Name",
                        "bbox": {"x": 12, "y": 34, "width": 120, "height": 22},
                    }
                ]
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")

        self.assertIn("<Canvas", xaml)
        self.assertIn('Canvas.Left="12"', xaml)
        self.assertIn('Canvas.Top="34"', xaml)
        self.assertIn('Width="120"', xaml)
        self.assertIn('Height="22"', xaml)

    def test_missing_bbox_uses_stack_panel_fallback(self) -> None:
        _, project_dir = self._render(
            {
                "nodes": [
                    {
                        "id": "UserName",
                        "type": "TextBox",
                        "properties": {"Text": "Ada"},
                    }
                ]
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")

        self.assertIn("<StackPanel", xaml)
        self.assertIn('<TextBox x:Name="UserName"', xaml)
        self.assertIn('Text="Ada"', xaml)
        self.assertNotIn("Canvas.Left=", xaml)

    def test_non_routed_events_receive_matching_wpf_event_argument_types(self) -> None:
        _, project_dir = self._render(
            {
                "nodes": [
                    {
                        "id": "Name",
                        "type": "TextBox",
                        "event_handlers": {"TextChanged": "NameChanged"},
                    },
                    {
                        "id": "Choices",
                        "type": "ComboBox",
                        "event_handlers": {"SelectionChanged": "ChoiceChanged"},
                    },
                ]
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")
        code_behind = (project_dir / "src" / "MainWindow.xaml.cs").read_text(encoding="utf-8")

        self.assertIn('TextChanged="NameChanged"', xaml)
        self.assertIn('SelectionChanged="ChoiceChanged"', xaml)
        self.assertIn("void NameChanged(object sender, TextChangedEventArgs e)", code_behind)
        self.assertIn("void ChoiceChanged(object sender, SelectionChangedEventArgs e)", code_behind)

    def test_structural_evidence_nodes_do_not_become_placeholder_text_controls(self) -> None:
        result, project_dir = self._render(
            {
                "title": "Editor",
                "nodes": [
                    {"id": "mainWindow", "type": "Window"},
                    {"id": "rootGrid", "type": "Grid", "parent_id": "mainWindow"},
                    {"id": "save", "type": "Button", "text": "Save", "parent_id": "rootGrid"},
                ],
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")

        self.assertEqual(result["control_count"], 1)
        self.assertIn('Content="Save"', xaml)
        self.assertNotIn('Text="Window"', xaml)
        self.assertNotIn('Text="Grid"', xaml)

    def test_compatible_events_reuse_one_handler_stub(self) -> None:
        result, project_dir = self._render(
            {
                "nodes": [
                    {
                        "id": "enabled",
                        "type": "CheckBox",
                        "text": "Enabled",
                        "event_handlers": {
                            "Checked": "EnabledChanged",
                            "Unchecked": "EnabledChanged",
                        },
                    }
                ]
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")
        code_behind = (project_dir / "src" / "MainWindow.xaml.cs").read_text(encoding="utf-8")

        self.assertEqual(result["event_handler_count"], 1)
        self.assertIn('Checked="EnabledChanged"', xaml)
        self.assertIn('Unchecked="EnabledChanged"', xaml)
        self.assertEqual(code_behind.count("void EnabledChanged("), 1)

    def test_escapes_xaml_and_sanitizes_duplicate_illegal_identifiers(self) -> None:
        _, project_dir = self._render(
            {
                "title": 'A & "B" <C>',
                "nodes": [
                    {
                        "id": "9 invalid-id",
                        "type": "Button",
                        "text": 'Save & <Close> "now"',
                        "event_handlers": {"Click": "9 invalid handler!"},
                    },
                    {
                        "id": "9 invalid-id",
                        "type": "Button",
                        "text": "Again",
                        "event_handlers": {"Click": "9 invalid handler!"},
                    },
                    {"id": "unsupported", "type": "UnknownControl", "text": "Fallback"},
                ],
            }
        )

        xaml = (project_dir / "src" / "MainWindow.xaml").read_text(encoding="utf-8")
        code_behind = (project_dir / "src" / "MainWindow.xaml.cs").read_text(encoding="utf-8")
        names = re.findall(r'x:Name="([^"]+)"', xaml)
        click_handlers = re.findall(r'Click="([^"]+)"', xaml)

        self.assertIn('Title="A &amp; &quot;B&quot; &lt;C&gt;"', xaml)
        self.assertIn('Content="Save &amp; &lt;Close&gt; &quot;now&quot;"', xaml)
        self.assertIn("<TextBlock", xaml)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names))
        self.assertEqual(len(click_handlers), 2)
        self.assertEqual(len(set(click_handlers)), 1)
        self.assertTrue(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", click_handlers[0]))
        self.assertEqual(code_behind.count(f"void {click_handlers[0]}("), 1)


if __name__ == "__main__":
    unittest.main()
